//! Container expansion: correctness and the hostile-input surface.
//!
//! The limit tests build custom rules with tiny ceilings so a bomb is
//! a few hundred bytes, not gigabytes. The lying-zip helper crafts an
//! archive whose central directory under-declares a member's size, so
//! the stage-two capped reader is tested against a real lie rather
//! than a truthful archive the zip writer cannot forge.

use std::io::{Cursor, Write};
use std::path::PathBuf;

use text_mirror::convert::Registry;
use text_mirror::detect::FormatTable;
use text_mirror::manifest::{self, Record, Status};
use text_mirror::pipeline::{self, Rules, RunOptions};
use text_mirror::walk::WalkOptions;
use zip::CompressionMethod;
use zip::write::SimpleFileOptions;

const PNG_MAGIC: &[u8] = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR";

struct Setup {
    _dir: tempfile::TempDir,
    root: PathBuf,
    mirror: PathBuf,
    manifest_dir: PathBuf,
}

fn setup() -> Setup {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("source");
    std::fs::create_dir_all(&root).unwrap();
    Setup {
        root,
        mirror: dir.path().join("mirror"),
        manifest_dir: dir.path().join("manifest"),
        _dir: dir,
    }
}

fn run_with(setup: &Setup, rules: &Rules) -> text_mirror::report::RunReport {
    pipeline::run(
        rules,
        &RunOptions {
            root: &setup.root,
            mirror_root: &setup.mirror,
            manifest_dir: &setup.manifest_dir,
            division: "alpha",
            walk: WalkOptions::default(),
        },
    )
    .unwrap()
}

fn terminal(setup: &Setup, source_path: &str) -> Option<Record> {
    manifest::read_shard(&setup.manifest_dir.join("alpha.jsonl"))
        .unwrap()
        .records
        .into_iter()
        .rev()
        .find(|r| r.source_path == source_path)
}

fn stored_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
    for (name, bytes) in entries {
        writer.start_file(*name, options).unwrap();
        writer.write_all(bytes).unwrap();
    }
    writer.finish().unwrap().into_inner()
}

fn symlink_zip(link_name: &str, target: &str) -> Vec<u8> {
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    writer
        .add_symlink(link_name, target, SimpleFileOptions::default())
        .unwrap();
    writer.finish().unwrap().into_inner()
}

/// A single-entry stored zip whose central directory and local header
/// under-declare the member's uncompressed size, so `size()` returns
/// the lie while the real bytes still inflate.
fn lying_zip(name: &str, data: &[u8], declared: u32) -> Vec<u8> {
    let mut bytes = stored_zip(&[(name, data)]);
    let declared = declared.to_le_bytes();
    // Local file header: uncompressed size is 4 bytes at offset 22.
    let local = find(&bytes, b"PK\x03\x04").expect("local header");
    bytes[local + 22..local + 26].copy_from_slice(&declared);
    // Central directory header: uncompressed size is 4 bytes at
    // offset 24. Compressed size is left truthful, so a stored member
    // still reads its real bytes.
    let central = find(&bytes, b"PK\x01\x02").expect("central header");
    bytes[central + 24..central + 28].copy_from_slice(&declared);
    bytes
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn custom_rules(
    max_depth: usize,
    max_children: usize,
    max_expanded_bytes: u64,
    max_member_size: u64,
) -> Rules {
    let formats = r#"version = "9"
[[formats]]
id = "text"
name = "Text"
extensions = ["txt"]
[[formats]]
id = "zip"
name = "Zip archive"
extensions = ["zip"]
[[formats]]
id = "png"
name = "PNG"
extensions = ["png"]
"#;
    let converters = format!(
        r#"version = "9"
[[converters]]
id = "text-passthrough"
version = "1.2.0"
formats = ["text"]
[[unsupported]]
reason = "engine-unpinned"
formats = ["png"]
[containers]
max_depth = {max_depth}
max_children = {max_children}
max_expanded_bytes = {max_expanded_bytes}
max_member_size = {max_member_size}
"#
    );
    Rules::from_parts(
        FormatTable::parse(formats, "formats.toml").unwrap(),
        Registry::parse(&converters, "converters.toml").unwrap(),
    )
    .unwrap()
}

fn docx_bytes() -> Vec<u8> {
    let content_types = br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>"#;
    let rels = br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>"#;
    let document = br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:body><w:p><w:r><w:t>Member document text</w:t></w:r></w:p></w:body>
</w:document>"#;
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for (name, data) in [
        ("[Content_Types].xml", content_types.as_slice()),
        ("_rels/.rels", rels.as_slice()),
        ("word/document.xml", document.as_slice()),
    ] {
        writer
            .start_file(name, SimpleFileOptions::default())
            .unwrap();
        writer.write_all(data).unwrap();
    }
    writer.finish().unwrap().into_inner()
}

// A normal zip expands to a member listing plus one child per member,
// each routed by its own detected format and linked to the parent.
#[test]
fn a_normal_zip_expands_to_a_listing_and_children() {
    let setup = setup();
    let bytes = stored_zip(&[
        ("doc.docx", &docx_bytes()),
        ("note.txt", b"member note body\n"),
        ("pic.png", PNG_MAGIC),
    ]);
    std::fs::write(setup.root.join("update.zip"), bytes).unwrap();
    let rules = Rules::builtin().unwrap();

    let report = run_with(&setup, &rules);
    // Parent listing, the docx, and the txt convert. The png is claimed
    // by the image converter now, so its truncated bytes fail closed in
    // the jailed decoder, and its metadata leg fails closed too on the
    // same malformed carrier, so the png member touches two failed
    // records. Three converted, two failed.
    assert_eq!(report.counts.converted, 3);
    assert_eq!(report.counts.unsupported, 0);
    assert_eq!(report.counts.failed, 2);

    let parent = terminal(&setup, "update.zip").unwrap();
    assert_eq!(parent.status, Status::Converted);
    assert_eq!(parent.detected_format, "zip");
    assert_eq!(parent.converter_id.as_deref(), Some("container-zip"));
    let listing = std::fs::read_to_string(setup.mirror.join("alpha/update.zip.txt")).unwrap();
    assert!(listing.contains("doc.docx\t"), "{listing:?}");
    assert!(listing.contains("note.txt\t"), "{listing:?}");
    assert!(listing.contains("pic.png\t"), "{listing:?}");

    let doc = terminal(&setup, "update.zip.d/doc.docx").unwrap();
    assert_eq!(doc.status, Status::Converted);
    assert_eq!(doc.parent_source.as_deref(), Some("update.zip"));
    assert_eq!(doc.converter_id.as_deref(), Some("anydoc-document"));

    let note = terminal(&setup, "update.zip.d/note.txt").unwrap();
    assert_eq!(note.status, Status::Converted);
    assert_eq!(note.parent_source.as_deref(), Some("update.zip"));
    assert_eq!(
        std::fs::read_to_string(setup.mirror.join("alpha/update.zip.d/note.txt.txt")).unwrap(),
        "member note body\n"
    );

    let png = terminal(&setup, "update.zip.d/pic.png").unwrap();
    assert_eq!(png.status, Status::Failed);
    assert_eq!(png.parent_source.as_deref(), Some("update.zip"));
    assert!(
        png.error
            .as_deref()
            .is_some_and(|e| e.starts_with("image-ocr-decode-failed")),
        "{:?}",
        png.error
    );

    // The member image's metadata leg is a separate derived child that
    // fails closed on the same malformed carrier, linked to the member.
    let png_meta = terminal(&setup, "update.zip.d/pic.png.d/#image-metadata").unwrap();
    assert_eq!(png_meta.status, Status::Failed);
    assert_eq!(
        png_meta.parent_source.as_deref(),
        Some("update.zip.d/pic.png")
    );
    assert_eq!(png_meta.converter_id.as_deref(), Some("image-metadata"));
}

// Nested zips expand recursively down to the depth cap.
#[test]
fn nested_zips_expand_through_the_dispatch_layer() {
    let setup = setup();
    let inner = stored_zip(&[("leaf.txt", b"deep leaf\n")]);
    let outer = stored_zip(&[("inner.zip", &inner)]);
    std::fs::write(setup.root.join("outer.zip"), outer).unwrap();
    let rules = Rules::builtin().unwrap();

    run_with(&setup, &rules);
    let leaf = terminal(&setup, "outer.zip.d/inner.zip.d/leaf.txt").unwrap();
    assert_eq!(leaf.status, Status::Converted);
    assert_eq!(leaf.parent_source.as_deref(), Some("outer.zip.d/inner.zip"));
    assert_eq!(
        std::fs::read_to_string(
            setup
                .mirror
                .join("alpha/outer.zip.d/inner.zip.d/leaf.txt.txt")
        )
        .unwrap(),
        "deep leaf\n"
    );
}

// More members than the ceiling fails the whole container, unexpanded.
#[test]
fn too_many_children_fail_the_whole_container() {
    let setup = setup();
    let members: Vec<(String, Vec<u8>)> = (0..4)
        .map(|i| (format!("m{i}.txt"), b"x".to_vec()))
        .collect();
    let refs: Vec<(&str, &[u8])> = members
        .iter()
        .map(|(n, b)| (n.as_str(), b.as_slice()))
        .collect();
    std::fs::write(setup.root.join("many.zip"), stored_zip(&refs)).unwrap();
    let rules = custom_rules(4, 3, 1_000_000, 1_000_000);

    run_with(&setup, &rules);
    let parent = terminal(&setup, "many.zip").unwrap();
    assert_eq!(parent.status, Status::Failed);
    assert_eq!(parent.error.as_deref(), Some("container-children-exceeded"));
    // Nothing expanded.
    assert!(terminal(&setup, "many.zip.d/m0.txt").is_none());
}

// Declared sizes summing over the cap fail before any inflation.
#[test]
fn declared_bytes_over_the_cap_fail_at_stage_one() {
    let setup = setup();
    let big = vec![b'x'; 80];
    std::fs::write(
        setup.root.join("heavy.zip"),
        stored_zip(&[("a.txt", &big), ("b.txt", &big)]),
    )
    .unwrap();
    // Sum of declared sizes is 160, over the 150 cap.
    let rules = custom_rules(4, 10, 150, 100);

    run_with(&setup, &rules);
    let parent = terminal(&setup, "heavy.zip").unwrap();
    assert_eq!(parent.status, Status::Failed);
    assert_eq!(parent.error.as_deref(), Some("container-expansion-cap"));
    assert!(terminal(&setup, "heavy.zip.d/a.txt").is_none());
}

// A member whose declared size is over the per-member cap fails as a
// child, before inflation, while the container still converts.
#[test]
fn an_oversize_member_fails_as_a_child() {
    let setup = setup();
    let big = vec![b'x'; 200];
    std::fs::write(
        setup.root.join("box.zip"),
        stored_zip(&[("ok.txt", b"small"), ("huge.txt", &big)]),
    )
    .unwrap();
    let rules = custom_rules(4, 10, 1_000_000, 100);

    run_with(&setup, &rules);
    assert_eq!(
        terminal(&setup, "box.zip").unwrap().status,
        Status::Converted
    );
    let huge = terminal(&setup, "box.zip.d/huge.txt").unwrap();
    assert_eq!(huge.status, Status::Failed);
    assert_eq!(huge.error.as_deref(), Some("container-member-too-large"));
    assert_eq!(
        terminal(&setup, "box.zip.d/ok.txt").unwrap().status,
        Status::Converted
    );
}

// A member that under-declares its size is caught by the capped reader
// at stage two, not trusted on its declaration.
#[test]
fn a_lying_member_is_caught_by_the_capped_reader() {
    let setup = setup();
    // Declares 10 bytes, actually holds 200.
    let bytes = lying_zip("liar.txt", &[b'x'; 200], 10);
    std::fs::write(setup.root.join("lie.zip"), bytes).unwrap();
    let rules = custom_rules(4, 10, 1_000_000, 100);

    run_with(&setup, &rules);
    assert_eq!(
        terminal(&setup, "lie.zip").unwrap().status,
        Status::Converted
    );
    let liar = terminal(&setup, "lie.zip.d/liar.txt").unwrap();
    assert_eq!(liar.status, Status::Failed);
    assert_eq!(liar.error.as_deref(), Some("container-member-too-large"));
}

// Cumulative inflated bytes over the cap mid-expansion fail the parent,
// even when each member under-declares to slip past stage one.
#[test]
fn cumulative_overrun_mid_expansion_fails_the_parent() {
    let setup = setup();
    // Two members each declaring 10 bytes, each actually 100. The
    // declared sum (20) clears stage one, but the real inflation
    // (200) overruns the 150 cumulative cap during extraction.
    let combined = {
        let mut bytes = stored_zip(&[("a.txt", &[b'a'; 100]), ("b.txt", &[b'b'; 100])]);
        // Patch both members' uncompressed size fields to 10.
        let ten = 10u32.to_le_bytes();
        let mut cursor = 0;
        while let Some(rel) = find(&bytes[cursor..], b"PK\x03\x04") {
            let at = cursor + rel;
            bytes[at + 22..at + 26].copy_from_slice(&ten);
            cursor = at + 4;
        }
        let mut cursor = 0;
        while let Some(rel) = find(&bytes[cursor..], b"PK\x01\x02") {
            let at = cursor + rel;
            bytes[at + 24..at + 28].copy_from_slice(&ten);
            cursor = at + 4;
        }
        bytes
    };
    std::fs::write(setup.root.join("creep.zip"), combined).unwrap();
    let rules = custom_rules(4, 10, 150, 100);

    run_with(&setup, &rules);
    let parent = terminal(&setup, "creep.zip").unwrap();
    assert_eq!(parent.status, Status::Failed);
    assert_eq!(parent.error.as_deref(), Some("container-expansion-cap"));
}

// A nested container past the depth cap fails as a child, unexpanded.
#[test]
fn nesting_past_the_depth_cap_is_refused() {
    let setup = setup();
    let inner = stored_zip(&[("leaf.txt", b"leaf")]);
    let mid = stored_zip(&[("inner.zip", &inner)]);
    let outer = stored_zip(&[("mid.zip", &mid)]);
    std::fs::write(setup.root.join("deep.zip"), outer).unwrap();
    // depth 0 deep.zip, depth 1 mid.zip, depth 2 inner.zip is refused.
    let rules = custom_rules(1, 10, 1_000_000, 1_000_000);

    run_with(&setup, &rules);
    let refused = terminal(&setup, "deep.zip.d/mid.zip.d/inner.zip").unwrap();
    assert_eq!(refused.status, Status::Failed);
    assert_eq!(refused.error.as_deref(), Some("container-depth-exceeded"));
    // The refused container did not expand.
    assert!(terminal(&setup, "deep.zip.d/mid.zip.d/inner.zip.d/leaf.txt").is_none());
}

// A member whose path escapes with `..` is refused, closing zip-slip.
#[test]
fn a_zip_slip_member_is_refused() {
    let setup = setup();
    std::fs::write(
        setup.root.join("slip.zip"),
        stored_zip(&[("../escape.txt", b"owned")]),
    )
    .unwrap();
    let rules = Rules::builtin().unwrap();

    run_with(&setup, &rules);
    let child = terminal(&setup, "slip.zip.d/#unsafe-member-0").unwrap();
    assert_eq!(child.status, Status::Failed);
    assert_eq!(child.error.as_deref(), Some("unsafe-member-path"));
    // No artifact escaped the mirror tree.
    assert!(!setup.mirror.join("escape.txt.txt").exists());
    assert!(!setup.mirror.join("alpha/escape.txt.txt").exists());
}

// A symlink member is refused like an unsafe path.
#[test]
fn a_symlink_member_is_refused() {
    let setup = setup();
    std::fs::write(
        setup.root.join("link.zip"),
        symlink_zip("link", "/etc/passwd"),
    )
    .unwrap();
    let rules = Rules::builtin().unwrap();

    run_with(&setup, &rules);
    let child = terminal(&setup, "link.zip.d/link").unwrap();
    assert_eq!(child.status, Status::Failed);
    assert_eq!(child.error.as_deref(), Some("unsafe-member-path"));
}

// A real source occupying the expansion namespace fails the container
// rather than colliding two artifacts on one mirror path.
#[test]
fn an_expansion_dir_collision_fails_the_container() {
    let setup = setup();
    std::fs::write(
        setup.root.join("clash.zip"),
        stored_zip(&[("note.txt", b"member")]),
    )
    .unwrap();
    std::fs::create_dir_all(setup.root.join("clash.zip.d")).unwrap();
    std::fs::write(setup.root.join("clash.zip.d/real.txt"), "real source\n").unwrap();
    let rules = Rules::builtin().unwrap();

    run_with(&setup, &rules);
    let parent = terminal(&setup, "clash.zip").unwrap();
    assert_eq!(parent.status, Status::Failed);
    assert_eq!(parent.error.as_deref(), Some("container-mirror-collision"));
}

// An identical member across two containers converts once and the
// second records a dedup pointing at the first.
#[test]
fn an_identical_member_across_containers_dedups() {
    let setup = setup();
    let shared = b"shared member payload\n";
    std::fs::write(setup.root.join("one.zip"), stored_zip(&[("m.txt", shared)])).unwrap();
    std::fs::write(setup.root.join("two.zip"), stored_zip(&[("m.txt", shared)])).unwrap();
    let rules = Rules::builtin().unwrap();

    run_with(&setup, &rules);
    // one.zip sorts before two.zip, so its member is canonical.
    let first = terminal(&setup, "one.zip.d/m.txt").unwrap();
    assert_eq!(first.status, Status::Converted);
    let second = terminal(&setup, "two.zip.d/m.txt").unwrap();
    assert_eq!(second.status, Status::Dedup);
    assert_eq!(second.dedup_of.as_deref(), Some("one.zip.d/m.txt"));
}

// --- fix-pass coverage ---

fn patch_eocd_count(mut bytes: Vec<u8>, count: u16) -> Vec<u8> {
    let eocd = bytes
        .windows(4)
        .rposition(|w| w == [0x50, 0x4b, 0x05, 0x06])
        .expect("eocd");
    // total entries on this disk (offset 8) and total entries (offset 10).
    bytes[eocd + 8..eocd + 10].copy_from_slice(&count.to_le_bytes());
    bytes[eocd + 10..eocd + 12].copy_from_slice(&count.to_le_bytes());
    bytes
}

// Cluster A: a re-expansion that drops a member retires the removed
// child with a terminal record and removes its orphan artifact.
#[test]
fn a_shrunk_container_retires_the_removed_child() {
    let setup = setup();
    let rules = Rules::builtin().unwrap();
    std::fs::write(
        setup.root.join("pack.zip"),
        stored_zip(&[("x.txt", b"keep\n"), ("y.txt", b"drop\n")]),
    )
    .unwrap();
    run_with(&setup, &rules);
    assert!(setup.mirror.join("alpha/pack.zip.d/y.txt.txt").exists());

    // Re-pack with y.txt gone. The parent hash changes, so it
    // re-expands.
    std::fs::write(
        setup.root.join("pack.zip"),
        stored_zip(&[("x.txt", b"keep\n")]),
    )
    .unwrap();
    run_with(&setup, &rules);

    let removed = terminal(&setup, "pack.zip.d/y.txt").unwrap();
    assert_eq!(removed.status, Status::Failed);
    assert_eq!(removed.error.as_deref(), Some("container-member-removed"));
    assert!(removed.text_path.is_none());
    // The orphan artifact is gone, and the surviving member stands.
    assert!(!setup.mirror.join("alpha/pack.zip.d/y.txt.txt").exists());
    // x.txt is unchanged, so it checkpoint-skips with its artifact
    // intact, and it stays text-bearing.
    let survivor = terminal(&setup, "pack.zip.d/x.txt").unwrap();
    assert_eq!(survivor.status, Status::SkippedUnchanged);
    assert!(setup.mirror.join("alpha/pack.zip.d/x.txt.txt").exists());

    // A third run with no change reaches a fixpoint: the removed
    // child is not re-retired.
    let report = run_with(&setup, &rules);
    assert_eq!(report.counts.failed, 0);
}

// Cluster A: the eml parent record is written after its children, so
// an intact parent proves the expansion finished.
#[test]
fn the_eml_parent_record_is_written_after_its_children() {
    let setup = setup();
    let rules = Rules::builtin().unwrap();
    let message = "From: a@example.com\r\n\
Content-Type: multipart/mixed; boundary=\"b\"\r\n\
\r\n\
--b\r\n\
Content-Type: text/plain\r\n\
\r\n\
body text\r\n\
--b\r\n\
Content-Type: text/plain\r\n\
Content-Disposition: attachment; filename=\"note.txt\"\r\n\
\r\n\
attached\r\n\
--b--\r\n";
    std::fs::write(setup.root.join("m.eml"), message).unwrap();
    run_with(&setup, &rules);

    let records = manifest::read_shard(&setup.manifest_dir.join("alpha.jsonl"))
        .unwrap()
        .records;
    let parent = records
        .iter()
        .position(|r| r.source_path == "m.eml")
        .unwrap();
    let child = records
        .iter()
        .position(|r| r.source_path == "m.eml.d/1-note.txt")
        .unwrap();
    assert!(child < parent, "child record must precede the parent");
}

// Cluster A: an eml whose attachments overrun the cumulative cap fails
// the parent, never presenting a partial expansion as complete.
#[test]
fn an_eml_over_the_cumulative_cap_fails_the_parent() {
    let setup = setup();
    // Tiny cumulative cap, and the eml needs the eml converter, so
    // build custom rules that keep the eml route and shrink the cap.
    let formats = r#"version = "9"
[[formats]]
id = "eml"
name = "Email"
extensions = ["eml"]
[[formats]]
id = "text"
name = "Text"
extensions = ["txt"]
"#;
    let converters = r#"version = "9"
[[converters]]
id = "eml-mime"
version = "1.0.0"
formats = ["eml"]
[[converters]]
id = "text-passthrough"
version = "1.2.0"
formats = ["text"]
[containers]
max_depth = 4
max_children = 1000
max_expanded_bytes = 8
max_member_size = 1000
"#;
    let rules = Rules::from_parts(
        FormatTable::parse(formats, "formats.toml").unwrap(),
        Registry::parse(converters, "converters.toml").unwrap(),
    )
    .unwrap();
    let message = "From: a@example.com\r\n\
Content-Type: text/plain\r\n\
Content-Disposition: attachment; filename=\"big.txt\"\r\n\
\r\n\
this attachment body is well over eight bytes\r\n";
    std::fs::write(setup.root.join("big.eml"), message).unwrap();

    run_with(&setup, &rules);
    let parent = terminal(&setup, "big.eml").unwrap();
    assert_eq!(parent.status, Status::Failed);
    assert_eq!(parent.error.as_deref(), Some("container-expansion-cap"));
    assert!(!setup.mirror.join("alpha/big.eml.txt").exists());
}

// Cluster B: a top-level source over the size ceiling is refused
// before detection runs, so its detected format is never resolved.
#[test]
fn a_large_top_level_source_is_refused_before_detection() {
    use std::io::Write as _;
    let setup = setup();
    let rules = Rules::builtin().unwrap();
    let path = setup.root.join("huge.zip");
    let mut file = std::fs::File::create(&path).unwrap();
    file.write_all(b"PK\x03\x04").unwrap();
    // A sparse length one byte over the ceiling. Nothing reads it.
    file.set_len(text_mirror::convert::MAX_SOURCE_BYTES + 1)
        .unwrap();
    drop(file);

    run_with(&setup, &rules);
    let record = terminal(&setup, "huge.zip").unwrap();
    assert_eq!(record.status, Status::Failed);
    assert!(
        record
            .error
            .as_deref()
            .unwrap()
            .starts_with("resource_limit"),
        "{:?}",
        record.error
    );
    // Detection was skipped, so the format is unknown, not zip.
    assert_eq!(record.detected_format, "unknown");
    assert!(!setup.mirror.join("alpha/huge.zip.txt").exists());
}

// Cluster B: the preflight refuses on the raw central-directory entry
// count, which the zip crate's name-keyed map would undercount.
#[test]
fn the_preflight_refuses_on_the_raw_entry_count() {
    let setup = setup();
    // A real 3-entry archive whose EOCD is forged to declare 1500
    // entries. The parsed len is 3, the raw count is 1500.
    let bytes = patch_eocd_count(
        stored_zip(&[("a.txt", b"1"), ("b.txt", b"2"), ("c.txt", b"3")]),
        1500,
    );
    std::fs::write(setup.root.join("forged.zip"), bytes).unwrap();
    let rules = Rules::builtin().unwrap();

    run_with(&setup, &rules);
    let parent = terminal(&setup, "forged.zip").unwrap();
    assert_eq!(parent.status, Status::Failed);
    assert_eq!(parent.error.as_deref(), Some("container-children-exceeded"));
    assert!(terminal(&setup, "forged.zip.d/a.txt").is_none());
}

// Cluster C: two members that map to the same child path do not alias
// one artifact. The later one is refused and the survivor's hash
// matches its file.
#[test]
fn an_intra_container_path_collision_is_refused() {
    let setup = setup();
    let rules = Rules::builtin().unwrap();
    let inner = stored_zip(&[("leaf.txt", b"two\n")]);
    let outer = stored_zip(&[("b.zip.d/leaf.txt", b"one\n".as_slice()), ("b.zip", &inner)]);
    std::fs::write(setup.root.join("a.zip"), outer).unwrap();

    run_with(&setup, &rules);
    // The first member won the path. Its record hash matches the file.
    let winner = terminal(&setup, "a.zip.d/b.zip.d/leaf.txt").unwrap();
    assert_eq!(winner.status, Status::Converted);
    let artifact = std::fs::read(setup.mirror.join("alpha/a.zip.d/b.zip.d/leaf.txt.txt")).unwrap();
    assert_eq!(artifact, b"one\n");
    assert_eq!(
        winner.text_hash.as_deref(),
        Some(text_mirror::hash::hash_bytes(&artifact).as_str())
    );
    // Exactly one converted record claims that path, and a collision
    // was recorded.
    let records = manifest::read_shard(&setup.manifest_dir.join("alpha.jsonl"))
        .unwrap()
        .records;
    let converted_at_path = records
        .iter()
        .filter(|r| r.source_path == "a.zip.d/b.zip.d/leaf.txt" && r.status == Status::Converted)
        .count();
    assert_eq!(converted_at_path, 1);
    assert!(
        records
            .iter()
            .any(|r| r.error.as_deref() == Some("member-path-collision")),
        "a collision must be recorded"
    );
}

// Cluster D: an absolute member path is refused, not rebased.
#[test]
fn an_absolute_member_path_is_refused() {
    let setup = setup();
    let rules = Rules::builtin().unwrap();
    std::fs::write(
        setup.root.join("abs.zip"),
        stored_zip(&[("/tmp/abs_escape.txt", b"owned")]),
    )
    .unwrap();

    run_with(&setup, &rules);
    let records = manifest::read_shard(&setup.manifest_dir.join("alpha.jsonl"))
        .unwrap()
        .records;
    assert!(
        records
            .iter()
            .any(|r| r.error.as_deref() == Some("unsafe-member-path")),
        "the absolute member must be refused"
    );
    assert!(!std::path::Path::new("/tmp/abs_escape.txt").exists());
    // No rebased artifact under the expansion dir.
    assert!(
        !setup
            .mirror
            .join("alpha/abs.zip.d/tmp/abs_escape.txt.txt")
            .exists()
    );
}

// Cluster D: a control character in a member name is refused and the
// parent listing escapes it, keeping one line per member.
#[test]
fn a_control_char_member_name_is_refused_and_the_listing_escapes_it() {
    let setup = setup();
    let rules = Rules::builtin().unwrap();
    std::fs::write(
        setup.root.join("ctrl.zip"),
        stored_zip(&[("line1\nline2.txt", b"body"), ("ok.txt", b"fine")]),
    )
    .unwrap();

    run_with(&setup, &rules);
    let records = manifest::read_shard(&setup.manifest_dir.join("alpha.jsonl"))
        .unwrap()
        .records;
    assert!(
        records
            .iter()
            .any(|r| r.error.as_deref() == Some("unsafe-member-path")),
        "the newline member must be refused"
    );
    // The listing escaped the newline: it stays one line per entry,
    // and no record key carries a raw newline.
    let listing = std::fs::read_to_string(setup.mirror.join("alpha/ctrl.zip.txt")).unwrap();
    assert!(listing.contains("line1\\nline2.txt\t"), "{listing:?}");
    assert!(records.iter().all(|r| !r.source_path.contains('\n')));
    assert_eq!(
        terminal(&setup, "ctrl.zip.d/ok.txt").unwrap().status,
        Status::Converted
    );
}

// A nested container that checkpoint-skips inside a re-expanding
// parent keeps its whole subtree: reconciliation retires only
// genuinely removed members, never a skipped container's live
// descendants.
#[test]
fn a_skipped_nested_container_keeps_its_descendants() {
    let setup = setup();
    let rules = Rules::builtin().unwrap();
    let inner = stored_zip(&[("leaf.txt", b"nested leaf\n")]);
    std::fs::write(
        setup.root.join("outer.zip"),
        stored_zip(&[("inner.zip", &inner), ("other.txt", b"v1\n")]),
    )
    .unwrap();
    run_with(&setup, &rules);
    assert_eq!(
        terminal(&setup, "outer.zip.d/inner.zip.d/leaf.txt")
            .unwrap()
            .status,
        Status::Converted
    );

    // Repack with a byte-identical inner.zip and a changed sibling.
    // The outer re-expands, inner.zip checkpoint-skips, and the leaf
    // must survive with its record and artifact.
    std::fs::write(
        setup.root.join("outer.zip"),
        stored_zip(&[("inner.zip", &inner), ("other.txt", b"v2\n")]),
    )
    .unwrap();
    run_with(&setup, &rules);

    let inner_record = terminal(&setup, "outer.zip.d/inner.zip").unwrap();
    assert_eq!(inner_record.status, Status::SkippedUnchanged);
    let leaf = terminal(&setup, "outer.zip.d/inner.zip.d/leaf.txt").unwrap();
    assert!(
        matches!(leaf.status, Status::Converted | Status::SkippedUnchanged),
        "leaf must stay text-bearing, got {:?} error {:?}",
        leaf.status,
        leaf.error
    );
    assert!(leaf.text_path.is_some());
    assert_eq!(
        std::fs::read_to_string(
            setup
                .mirror
                .join("alpha/outer.zip.d/inner.zip.d/leaf.txt.txt")
        )
        .unwrap(),
        "nested leaf\n"
    );
    assert_eq!(
        std::fs::read_to_string(setup.mirror.join("alpha/outer.zip.d/other.txt.txt")).unwrap(),
        "v2\n"
    );

    // A third run is stable: nothing fails, nothing is retired, the
    // leaf artifact stands.
    let third = run_with(&setup, &rules);
    assert_eq!(third.counts.failed, 0);
    let records = manifest::read_shard(&setup.manifest_dir.join("alpha.jsonl"))
        .unwrap()
        .records;
    assert!(
        records
            .iter()
            .all(|r| r.error.as_deref() != Some("container-member-removed")),
        "no member was genuinely removed, so none may be retired"
    );
    assert!(
        setup
            .mirror
            .join("alpha/outer.zip.d/inner.zip.d/leaf.txt.txt")
            .exists()
    );
}

// The same keep rule covers a nested eml skipping inside a zip.
#[test]
fn a_skipped_nested_eml_keeps_its_attachment_child() {
    let setup = setup();
    let rules = Rules::builtin().unwrap();
    let message = b"From: a@example.com\r\n\
Content-Type: multipart/mixed; boundary=\"b\"\r\n\
\r\n\
--b\r\n\
Content-Type: text/plain\r\n\
\r\n\
covering note\r\n\
--b\r\n\
Content-Type: text/plain\r\n\
Content-Disposition: attachment; filename=\"memo.txt\"\r\n\
\r\n\
attached memo\r\n\
--b--\r\n";
    std::fs::write(
        setup.root.join("box.zip"),
        stored_zip(&[("mail.eml", message), ("readme.txt", b"r1\n")]),
    )
    .unwrap();
    run_with(&setup, &rules);

    std::fs::write(
        setup.root.join("box.zip"),
        stored_zip(&[("mail.eml", message), ("readme.txt", b"r2\n")]),
    )
    .unwrap();
    run_with(&setup, &rules);

    assert_eq!(
        terminal(&setup, "box.zip.d/mail.eml").unwrap().status,
        Status::SkippedUnchanged
    );
    let child = terminal(&setup, "box.zip.d/mail.eml.d/1-memo.txt").unwrap();
    assert!(
        matches!(child.status, Status::Converted | Status::SkippedUnchanged),
        "attachment child must survive, got {:?} error {:?}",
        child.status,
        child.error
    );
    assert!(
        setup
            .mirror
            .join("alpha/box.zip.d/mail.eml.d/1-memo.txt.txt")
            .exists()
    );
}
