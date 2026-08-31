//! Coverage tests for rules version 4: text-native routing through
//! the passthrough, the unsupported reason vocabulary, and detection
//! warnings carried on manifest records.

use std::fs;
use std::io::Write;
use std::path::PathBuf;

use text_mirror::hash;
use text_mirror::manifest::{self, ManifestSchema, ManifestWriter, Record, Status};
use text_mirror::pipeline::{self, Rules, RunOptions};
use text_mirror::walk::WalkOptions;

struct Setup {
    _dir: tempfile::TempDir,
    root: PathBuf,
    mirror: PathBuf,
    manifest_dir: PathBuf,
}

fn setup() -> Setup {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("source");
    fs::create_dir_all(&root).unwrap();
    Setup {
        root,
        mirror: dir.path().join("mirror"),
        manifest_dir: dir.path().join("manifest"),
        _dir: dir,
    }
}

fn run(setup: &Setup) -> text_mirror::report::RunReport {
    pipeline::run(
        &Rules::builtin().unwrap(),
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

fn terminal(setup: &Setup, source_path: &str) -> Record {
    manifest::read_shard(&setup.manifest_dir.join("alpha.jsonl"))
        .unwrap()
        .records
        .into_iter()
        .rev()
        .find(|r| r.source_path == source_path)
        .unwrap()
}

const SVG_SOURCE: &str =
    "<svg xmlns=\"http://www.w3.org/2000/svg\"><text>quarterly totals</text></svg>\n";
const IPYNB_SOURCE: &str =
    "{\"cells\": [{\"cell_type\": \"markdown\", \"source\": [\"projection notes\"]}]}\n";

// Text-native sources route through the passthrough end to end, each
// under its own format id.
#[test]
fn text_native_formats_convert_through_the_passthrough() {
    let setup = setup();
    fs::write(setup.root.join("data.json"), "{\"answer\": 42}\n").unwrap();
    fs::write(setup.root.join("config.yaml"), "answer: 42\n").unwrap();
    fs::write(setup.root.join("chart.svg"), SVG_SOURCE).unwrap();
    fs::write(setup.root.join("notebook.ipynb"), IPYNB_SOURCE).unwrap();

    let report = run(&setup);
    assert_eq!(report.counts.converted, 4);
    assert_eq!(report.counts.unsupported, 0);
    assert_eq!(report.counts.failed, 0);

    for (path, format) in [
        ("data.json", "json"),
        ("config.yaml", "yaml"),
        ("chart.svg", "svg"),
        ("notebook.ipynb", "ipynb"),
    ] {
        let record = terminal(&setup, path);
        assert_eq!(record.status, Status::Converted, "{path}");
        assert_eq!(record.detected_format, format, "{path}");
        assert_eq!(record.converter_id.as_deref(), Some("text-passthrough"));
        assert_eq!(record.rules_version, "10");
    }

    // svg passes through as raw markup and ipynb as the raw notebook
    // json. Nothing is stripped or extracted.
    assert_eq!(
        fs::read_to_string(setup.mirror.join("alpha/chart.svg.txt")).unwrap(),
        SVG_SOURCE
    );
    assert_eq!(
        fs::read_to_string(setup.mirror.join("alpha/notebook.ipynb.txt")).unwrap(),
        IPYNB_SOURCE
    );
}

// A binary wearing a text-native extension fails closed instead of
// leaking bytes into the mirror.
#[test]
fn a_binary_wearing_a_text_extension_fails_closed() {
    let setup = setup();
    fs::write(setup.root.join("payload.json"), b"\x00\x01\xff\xfe binary").unwrap();

    let report = run(&setup);
    assert_eq!(report.counts.failed, 1);
    let record = terminal(&setup, "payload.json");
    assert_eq!(record.status, Status::Failed);
    assert!(record.error.as_deref().unwrap().starts_with("invalid_utf8"));
    assert!(!setup.mirror.join("alpha/payload.json.txt").exists());
}

// Every unsupported record carries exactly one machine-readable
// reason: a declared entry from the registry or the no-converter
// floor. Pickle bytes are never parsed, so nothing records a
// converter id for them.
#[test]
fn unsupported_reasons_name_every_deliberate_exclusion() {
    let setup = setup();
    fs::write(
        setup.root.join("model.pkl"),
        b"\x80\x04\x95\x1a\x00\x00\x00\x00\x00\x00\x00hostile pickle stream",
    )
    .unwrap();
    // arrow stays converter-deferred; parquet, avro, and sqlite are
    // claimed by the records worker and exercised in its own suite.
    fs::write(
        setup.root.join("table.arrow"),
        b"ARROW1\x00\x00not a real arrow file",
    )
    .unwrap();
    fs::write(
        setup.root.join("backup.tar"),
        b"\x00\x01\x02 not a tar block",
    )
    .unwrap();
    fs::write(setup.root.join("mock.psd"), b"8BPS\x00\x01\x00\x00\x00\x00").unwrap();
    // tiff stays engine-unpinned: the in-jail decoder excludes it. png,
    // jpeg, and webp moved to the image-pixel-ocr converter and are
    // exercised in the image-OCR suite.
    fs::write(setup.root.join("scan.tiff"), b"II*\x00\x08\x00\x00\x00").unwrap();
    fs::write(setup.root.join("opaque.blob"), b"\x00\xfe\xedopaque bytes").unwrap();

    let report = run(&setup);
    assert_eq!(report.counts.unsupported, 6);
    assert_eq!(report.counts.converted, 0);

    for (path, format, reason) in [
        ("model.pkl", "pickle", "pickle-deserialization-unsafe"),
        ("table.arrow", "arrow", "converter-deferred"),
        ("backup.tar", "tar", "container-deferred"),
        ("mock.psd", "psd", "proprietary-binary"),
        ("scan.tiff", "tiff", "engine-unpinned"),
        ("opaque.blob", "unknown", "no-converter"),
    ] {
        let record = terminal(&setup, path);
        assert_eq!(record.status, Status::Unsupported, "{path}");
        assert_eq!(record.detected_format, format, "{path}");
        assert_eq!(record.error.as_deref(), Some(reason), "{path}");
        assert!(record.converter_id.is_none(), "{path}");
        assert!(record.text_path.is_none(), "{path}");
        assert!(!setup.mirror.join(format!("alpha/{path}.txt")).exists());
    }
}

// Out-of-table magic under a matching declared id is not a mismatch.
// The record keeps the flag down and explains what the bytes showed.
#[test]
fn cfb_magic_under_a_docx_name_warns_instead_of_flagging() {
    let setup = setup();
    let mut bytes = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1".to_vec();
    bytes.extend_from_slice(&[0u8; 24]);
    fs::write(setup.root.join("locked.docx"), &bytes).unwrap();
    // A genuine disagreement keeps the flag up: png bytes, txt name.
    fs::write(
        setup.root.join("trick.txt"),
        b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR",
    )
    .unwrap();

    run(&setup);

    let locked = terminal(&setup, "locked.docx");
    assert_eq!(locked.declared_format.as_deref(), Some("docx"));
    assert_eq!(locked.detected_format, "docx");
    assert!(!locked.format_mismatch);
    assert!(
        locked
            .warnings
            .iter()
            .any(|w| w == "magic-format-outside-table: cfb"),
        "warnings: {:?}",
        locked.warnings
    );
    // These bytes are no readable docx, so the conversion itself
    // fails with a reason.
    assert_eq!(locked.status, Status::Failed);
    assert!(locked.error.is_some());

    let trick = terminal(&setup, "trick.txt");
    assert_eq!(trick.detected_format, "png");
    assert!(trick.format_mismatch);
}

// A rules 3 era unsupported record reconverts under rules 4 now that
// a converter claims its format. No manual sweep is needed.
#[test]
fn a_prior_unsupported_record_reconverts_under_the_new_rules() {
    let setup = setup();
    let bytes = b"{\"quarter\": \"Q3\"}\n";
    fs::write(setup.root.join("data.json"), bytes).unwrap();

    // The terminal record a rules 3 run would have left: unsupported,
    // unplaced, and reason-less.
    let prior = Record {
        schema: ManifestSchema,
        source_path: "data.json".to_string(),
        source_hash: hash::hash_bytes(bytes),
        source_size: bytes.len() as u64,
        declared_format: None,
        detected_format: "unknown".to_string(),
        format_mismatch: false,
        status: Status::Unsupported,
        text_path: None,
        text_hash: None,
        artifact_kind: None,
        converter_id: None,
        converter_version: None,
        tool_version: None,
        rules_version: "3".to_string(),
        media: None,
        parent_source: None,
        dedup_of: None,
        warnings: Vec::new(),
        error: None,
        duration_ms: Some(1),
    };
    let mut writer = ManifestWriter::open(&setup.manifest_dir.join("alpha.jsonl")).unwrap();
    writer.append(&prior).unwrap();
    drop(writer);

    let report = run(&setup);
    assert_eq!(report.counts.converted, 1);
    assert_eq!(report.counts.unsupported, 0);
    assert_eq!(report.counts.skipped_unchanged, 0);

    let record = terminal(&setup, "data.json");
    assert_eq!(record.status, Status::Converted);
    assert_eq!(record.detected_format, "json");
    assert_eq!(record.rules_version, "10");
    assert_eq!(
        fs::read_to_string(setup.mirror.join("alpha/data.json.txt")).unwrap(),
        String::from_utf8_lossy(bytes)
    );
}

fn utf16le_with_bom(text: &str) -> Vec<u8> {
    let mut bytes = vec![0xFF, 0xFE];
    for unit in text.encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    bytes
}

// A UTF-16 source behind a byte order mark transcodes through the
// passthrough, records the transcoding warning, and a UTF-32 mark
// fails closed with its own reason.
#[test]
fn utf16_sources_transcode_and_utf32_fails_closed() {
    let setup = setup();
    fs::write(
        setup.root.join("report.csv"),
        utf16le_with_bom("name,total\r\nQ3,42\r\n"),
    )
    .unwrap();
    let mut big_endian = vec![0xFE, 0xFF];
    for unit in "quarterly notes\n".encode_utf16() {
        big_endian.extend_from_slice(&unit.to_be_bytes());
    }
    fs::write(setup.root.join("notes.txt"), &big_endian).unwrap();
    fs::write(
        setup.root.join("wide.csv"),
        b"\xFF\xFE\x00\x00A\x00\x00\x00",
    )
    .unwrap();

    let report = run(&setup);
    assert_eq!(report.counts.converted, 2);
    assert_eq!(report.counts.failed, 1);

    let csv = terminal(&setup, "report.csv");
    assert_eq!(csv.status, Status::Converted);
    assert_eq!(csv.converter_version.as_deref(), Some("1.2.0"));
    assert!(
        csv.warnings.iter().any(|w| w == "transcoded from utf-16le"),
        "warnings: {:?}",
        csv.warnings
    );
    assert_eq!(
        fs::read_to_string(setup.mirror.join("alpha/report.csv.txt")).unwrap(),
        "name,total\nQ3,42\n"
    );

    let txt = terminal(&setup, "notes.txt");
    assert_eq!(txt.status, Status::Converted);
    assert!(
        txt.warnings.iter().any(|w| w == "transcoded from utf-16be"),
        "warnings: {:?}",
        txt.warnings
    );
    assert_eq!(
        fs::read_to_string(setup.mirror.join("alpha/notes.txt.txt")).unwrap(),
        "quarterly notes\n"
    );

    let wide = terminal(&setup, "wide.csv");
    assert_eq!(wide.status, Status::Failed);
    assert!(
        wide.error
            .as_deref()
            .unwrap()
            .starts_with("unsupported-encoding: utf-32"),
        "error: {:?}",
        wide.error
    );
    assert!(!setup.mirror.join("alpha/wide.csv.txt").exists());
}

// A rules 3 era invalid_utf8 failure for a marked UTF-16 file
// reconverts under rules 4, because failed records re-run every pass.
#[test]
fn a_prior_invalid_utf8_failure_reconverts_under_the_new_rules() {
    let setup = setup();
    let bytes = utf16le_with_bom("dept,headcount\r\nsales,12\r\n");
    fs::write(setup.root.join("legacy.csv"), &bytes).unwrap();

    let prior = Record {
        schema: ManifestSchema,
        source_path: "legacy.csv".to_string(),
        source_hash: hash::hash_bytes(&bytes),
        source_size: bytes.len() as u64,
        declared_format: Some("csv".to_string()),
        detected_format: "csv".to_string(),
        format_mismatch: false,
        status: Status::Failed,
        text_path: None,
        text_hash: None,
        artifact_kind: None,
        converter_id: Some("text-passthrough".to_string()),
        converter_version: Some("1.0.0".to_string()),
        tool_version: None,
        rules_version: "3".to_string(),
        media: None,
        parent_source: None,
        dedup_of: None,
        warnings: Vec::new(),
        error: Some("invalid_utf8: invalid UTF-8 at byte 0".to_string()),
        duration_ms: Some(1),
    };
    let mut writer = ManifestWriter::open(&setup.manifest_dir.join("alpha.jsonl")).unwrap();
    writer.append(&prior).unwrap();
    drop(writer);

    let report = run(&setup);
    assert_eq!(report.counts.converted, 1);
    assert_eq!(report.counts.failed, 0);

    let record = terminal(&setup, "legacy.csv");
    assert_eq!(record.status, Status::Converted);
    assert_eq!(record.rules_version, "10");
    assert_eq!(record.converter_version.as_deref(), Some("1.2.0"));
    assert!(record.error.is_none());
    assert_eq!(
        fs::read_to_string(setup.mirror.join("alpha/legacy.csv.txt")).unwrap(),
        "dept,headcount\nsales,12\n"
    );
}

fn build_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    for (name, bytes) in entries {
        writer
            .start_file(*name, zip::write::SimpleFileOptions::default())
            .unwrap();
        writer.write_all(bytes).unwrap();
    }
    writer.finish().unwrap().into_inner()
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
<w:body><w:p><w:r><w:t>Offsite agenda draft</w:t></w:r></w:p></w:body>
</w:document>"#;
    build_zip(&[
        ("[Content_Types].xml", content_types.as_slice()),
        ("_rels/.rels", rels.as_slice()),
        ("word/document.xml", document.as_slice()),
    ])
}

// The pickle boundary: bytes that resolve to the pickle format are
// refused untouched, and a pickle name over bytes of another format
// routes as that format under magic-first with the flag raised.
#[test]
fn the_pickle_exclusion_holds_at_its_exact_boundary() {
    let setup = setup();
    fs::write(
        setup.root.join("real.pkl"),
        b"\x80\x04\x95\x08\x00\x00\x00\x00\x00\x00\x00\x8c\x04spam\x94.",
    )
    .unwrap();
    fs::write(setup.root.join("junk.pkl"), b"\x00\xfe\xed no magic here").unwrap();
    fs::write(
        setup.root.join("archive.pkl"),
        build_zip(&[("payload.txt", b"member text".as_slice())]),
    )
    .unwrap();
    fs::write(setup.root.join("poly.pkl"), docx_bytes()).unwrap();

    let report = run(&setup);
    assert_eq!(report.counts.unsupported, 2);

    // Pickle opcode bytes and unplaceable bytes under the pickle
    // name both record the exclusion with no converter run.
    for path in ["real.pkl", "junk.pkl"] {
        let record = terminal(&setup, path);
        assert_eq!(record.status, Status::Unsupported, "{path}");
        assert_eq!(record.detected_format, "pickle", "{path}");
        assert_eq!(
            record.error.as_deref(),
            Some("pickle-deserialization-unsafe"),
            "{path}"
        );
        assert!(record.converter_id.is_none(), "{path}");
    }

    // A plain zip under the pickle name is the container it is: it
    // expands to a member listing, with the extension disagreement
    // flagged. The pickle name never made it a pickle.
    let archive = terminal(&setup, "archive.pkl");
    assert_eq!(archive.status, Status::Converted);
    assert_eq!(archive.declared_format.as_deref(), Some("pickle"));
    assert_eq!(archive.detected_format, "zip");
    assert!(archive.format_mismatch);
    assert_eq!(archive.converter_id.as_deref(), Some("container-zip"));
    let member = terminal(&setup, "archive.pkl.d/payload.txt");
    assert_eq!(member.status, Status::Converted);
    assert_eq!(member.parent_source.as_deref(), Some("archive.pkl"));

    // A docx-shaped zip under the pickle name converts as the docx
    // it is, with the disagreement flagged. No pickle byte was ever
    // interpreted, because nothing in the tree can interpret one.
    let poly = terminal(&setup, "poly.pkl");
    assert_eq!(poly.status, Status::Converted);
    assert_eq!(poly.declared_format.as_deref(), Some("pickle"));
    assert_eq!(poly.detected_format, "docx");
    assert!(poly.format_mismatch);
    assert_eq!(poly.converter_id.as_deref(), Some("anydoc-document"));
}

// An xml-prologed svg records the ruled svg id with no mismatch,
// because the declared id refines what magic saw.
#[test]
fn a_prologed_svg_keeps_its_own_format_id() {
    let setup = setup();
    fs::write(
        setup.root.join("logo.svg"),
        "<?xml version=\"1.0\"?>\n<svg xmlns=\"http://www.w3.org/2000/svg\"><text>fy26</text></svg>\n",
    )
    .unwrap();

    let report = run(&setup);
    assert_eq!(report.counts.converted, 1);
    let record = terminal(&setup, "logo.svg");
    assert_eq!(record.detected_format, "svg");
    assert!(!record.format_mismatch);
    assert!(record.warnings.is_empty());
    assert_eq!(record.converter_id.as_deref(), Some("text-passthrough"));
}
