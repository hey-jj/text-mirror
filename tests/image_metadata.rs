//! End-to-end tests for the image-metadata derived-child leg: one image
//! source yields the pixel-OCR text as its primary artifact and the
//! textual metadata as a hidden child at `<source>.d/#image-metadata`,
//! all behind the subprocess jail.
//!
//! The pixel-purity tripwire is the load-bearing test: metadata values
//! appear only in the metadata child and never in the OCR output, and
//! the OCR recognition never appears in the metadata child. Through the
//! builtin registry the production image-OCR mode fails closed with
//! `image-ocr-runtime-missing`, so a metadata-bearing image records a
//! failed primary and a converted metadata child, proving the two legs
//! are independent. The composition against a working OCR engine is
//! exercised at the converter level through the fake engine, the same
//! fake the OCR adapter tests use, so the tripwire is testable now and
//! stays testable once a real engine is pinned. Fixtures are built
//! in-test with the same parser crates the worker reads with, so no
//! committed binary fixture is needed.

#![cfg(all(unix, feature = "image-metadata"))]

use std::fs;
use std::io::{Cursor, Write};
use std::path::PathBuf;

use text_mirror::manifest::{self, ArtifactKind, ManifestWriter, Record, Status};
use text_mirror::pipeline::{self, Rules, RunOptions};
use text_mirror::walk::WalkOptions;
use zip::CompressionMethod;
use zip::write::SimpleFileOptions;

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
    run_with(setup, &Rules::builtin().unwrap())
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

/// The builtin rules with the image formats driven through the fake
/// OCR engine, so the primary leg succeeds with a real artifact and the
/// composition with the metadata leg can be observed end to end.
fn fake_ocr_rules() -> Rules {
    let mut rules = Rules::builtin().unwrap();
    rules.registry.use_fake_image_ocr();
    rules
}

/// Rewrites the manifest shard through a transform, so a test can stand
/// in a prior run's records without the run that produced them.
fn rewrite_shard(setup: &Setup, transform: impl FnOnce(Vec<Record>) -> Vec<Record>) {
    let path = setup.manifest_dir.join("alpha.jsonl");
    let records = transform(manifest::read_shard(&path).unwrap().records);
    fs::remove_file(&path).unwrap();
    let mut writer = ManifestWriter::open(&path).unwrap();
    for record in &records {
        writer.append(record).unwrap();
    }
}

/// Removes a child's artifact and segments sidecar from the mirror.
fn remove_child_artifact(setup: &Setup, source_path: &str) {
    fs::remove_file(setup.mirror.join(format!("alpha/{source_path}.txt"))).unwrap();
    fs::remove_file(
        setup
            .mirror
            .join(format!("alpha/{source_path}.segments.jsonl")),
    )
    .unwrap();
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

fn records(setup: &Setup) -> Vec<Record> {
    manifest::read_shard(&setup.manifest_dir.join("alpha.jsonl"))
        .unwrap()
        .records
}

fn terminal(setup: &Setup, source_path: &str) -> Option<Record> {
    records(setup)
        .into_iter()
        .rev()
        .find(|r| r.source_path == source_path)
}

fn artifact(setup: &Setup, source_path: &str) -> String {
    fs::read_to_string(setup.mirror.join(format!("alpha/{source_path}.txt"))).unwrap()
}

// --- fixture builders -----------------------------------------------

/// A tiny valid png whose only ancillary content is one iTXt chunk
/// keyed `XML:com.adobe.xmp` carrying the given RDF packet.
fn png_with_xmp(xmp: &str) -> Vec<u8> {
    png_with(|encoder| {
        encoder
            .add_itxt_chunk("XML:com.adobe.xmp".to_string(), xmp.to_string())
            .unwrap();
    })
}

/// A tiny valid png with no textual metadata at all.
fn png_plain() -> Vec<u8> {
    png_with(|_| {})
}

fn png_with<F: FnOnce(&mut png::Encoder<'_, &mut Vec<u8>>)>(build: F) -> Vec<u8> {
    let mut out = Vec::new();
    {
        let mut encoder = png::Encoder::new(&mut out, 2, 2);
        encoder.set_color(png::ColorType::Grayscale);
        encoder.set_depth(png::BitDepth::Eight);
        build(&mut encoder);
        let mut writer = encoder.write_header().unwrap();
        writer.write_image_data(&[10, 20, 30, 40]).unwrap();
    }
    out
}

/// An xmp packet whose `dc:description` carries the sentinel.
fn xmp_description(sentinel: &str) -> String {
    format!(
        r#"<?xpacket begin="?"?><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" xmlns:dc="http://purl.org/dc/elements/1.1/"><rdf:Description><dc:description><rdf:Alt><rdf:li xml:lang="x-default">{sentinel}</rdf:li></rdf:Alt></dc:description></rdf:Description></rdf:RDF>"#
    )
}

// --- tests ----------------------------------------------------------

#[test]
fn a_metadata_bearing_image_yields_a_hidden_converted_child() {
    let setup = setup();
    fs::write(
        setup.root.join("shot.png"),
        png_with_xmp(&xmp_description("a caption sentinel")),
    )
    .unwrap();

    run(&setup);

    // The metadata child is converted, attributed to image-metadata,
    // with the value present.
    let child = terminal(&setup, "shot.png.d/#image-metadata").expect("metadata child record");
    assert_eq!(child.status, Status::Converted);
    assert_eq!(child.converter_id.as_deref(), Some("image-metadata"));
    assert_eq!(child.converter_version.as_deref(), Some("1.0.0"));
    assert_eq!(child.artifact_kind, Some(ArtifactKind::Text));
    assert_eq!(child.parent_source.as_deref(), Some("shot.png"));
    assert_eq!(child.detected_format, "png");

    let text = artifact(&setup, "shot.png.d/#image-metadata");
    assert!(text.contains("a caption sentinel"), "{text}");
    assert!(text.contains("xmp-dc-description"), "{text}");

    // Every segment over the child artifact is a hidden metadata span.
    let sidecar = fs::read_to_string(
        setup
            .mirror
            .join("alpha/shot.png.d/#image-metadata.segments.jsonl"),
    )
    .unwrap();
    assert!(!sidecar.trim().is_empty());
    for line in sidecar.lines() {
        assert!(line.contains("\"hidden\":true"), "{line}");
        assert!(line.contains("\"source\":\"metadata\""), "{line}");
    }
}

#[test]
fn the_pixel_purity_tripwire_holds_through_the_pipeline() {
    // The composition through the pipeline against a working OCR
    // engine: the primary succeeds with a real artifact, and the
    // metadata sentinel appears only in the child while the OCR
    // recognition appears only in the primary. Neither leg carries the
    // other's content once the pipeline has assembled both records.
    let setup = setup();
    let sentinel = "METADATA ONLY SENTINEL";
    fs::write(
        setup.root.join("photo.png"),
        png_with_xmp(&xmp_description(sentinel)),
    )
    .unwrap();

    run_with(&setup, &fake_ocr_rules());

    let primary = terminal(&setup, "photo.png").expect("primary image record");
    assert_eq!(primary.status, Status::Converted);
    assert_eq!(primary.converter_id.as_deref(), Some("image-pixel-ocr"));
    assert_eq!(primary.artifact_kind, Some(ArtifactKind::Ocr));
    let ocr_text = artifact(&setup, "photo.png");
    assert!(
        !ocr_text.contains(sentinel),
        "metadata leaked into the primary artifact: {ocr_text}"
    );

    let child = terminal(&setup, "photo.png.d/#image-metadata").expect("metadata child");
    assert_eq!(child.status, Status::Converted);
    let child_text = artifact(&setup, "photo.png.d/#image-metadata");
    assert!(child_text.contains(sentinel), "{child_text}");
    let recognition = ocr_text.lines().next().unwrap_or_default();
    assert!(
        !recognition.is_empty() && !child_text.contains(recognition),
        "ocr recognition leaked into the metadata child: {child_text}"
    );
}

#[test]
fn a_failed_primary_never_touches_the_child() {
    // Through the builtin registry the production OCR mode fails closed
    // for want of a wired runtime. The metadata child still converts,
    // so the two legs are independent in the failure direction too.
    let setup = setup();
    fs::write(
        setup.root.join("photo.png"),
        png_with_xmp(&xmp_description("METADATA ONLY SENTINEL")),
    )
    .unwrap();

    run(&setup);

    let primary = terminal(&setup, "photo.png").expect("primary image record");
    assert_eq!(primary.status, Status::Failed);
    assert_eq!(primary.converter_id.as_deref(), Some("image-pixel-ocr"));
    assert!(
        primary
            .error
            .as_deref()
            .is_some_and(|e| e.starts_with("image-ocr-runtime-missing")),
        "{:?}",
        primary.error
    );
    assert!(!setup.mirror.join("alpha/photo.png.txt").exists());

    let child = terminal(&setup, "photo.png.d/#image-metadata").expect("metadata child");
    assert_eq!(child.status, Status::Converted);
    let child_text = artifact(&setup, "photo.png.d/#image-metadata");
    assert!(
        child_text.contains("METADATA ONLY SENTINEL"),
        "{child_text}"
    );
}

#[test]
fn the_composition_keeps_the_two_legs_disjoint_under_a_working_engine() {
    use text_mirror::convert::Converter;
    use text_mirror::convert::subprocess::{ImageMetadata, ImagePixelOcr};

    // The tripwire against a working OCR engine: the fake engine stands
    // in for the unpinned runtime, exactly as it does for the OCR adapter
    // tests. The metadata sentinel appears only in the metadata child,
    // and the OCR recognition appears only in the OCR text. Neither leg
    // carries the other's content.
    let sentinel = "METADATA ONLY SENTINEL";
    let bytes = png_with_xmp(&xmp_description(sentinel));

    let ocr = ImagePixelOcr::new_fake(Default::default());
    let ocr_text = ocr.convert(&bytes, "png").unwrap().text;
    assert!(
        !ocr_text.contains(sentinel),
        "metadata leaked into ocr: {ocr_text}"
    );

    let metadata = ImageMetadata::new(Default::default());
    let child_text = metadata.convert(&bytes, "png").unwrap().text;
    assert!(
        child_text.contains(sentinel),
        "metadata missing: {child_text}"
    );
    // The OCR recognition text never appears in the metadata child.
    let recognition = ocr_text.lines().next().unwrap_or_default();
    assert!(
        !recognition.is_empty() && !child_text.contains(recognition),
        "ocr recognition leaked into metadata: {child_text}"
    );
}

#[test]
fn an_image_with_no_metadata_writes_no_child() {
    let setup = setup();
    fs::write(setup.root.join("bare.png"), png_plain()).unwrap();

    run(&setup);

    // The primary leg records as usual; the metadata leg produces
    // nothing: no child record, no artifact, no segments file.
    assert!(terminal(&setup, "bare.png").is_some());
    assert!(terminal(&setup, "bare.png.d/#image-metadata").is_none());
    assert!(
        !setup
            .mirror
            .join("alpha/bare.png.d/#image-metadata.txt")
            .exists()
    );
    assert!(
        !setup
            .mirror
            .join("alpha/bare.png.d/#image-metadata.segments.jsonl")
            .exists()
    );
}

#[test]
fn a_malformed_metadata_surface_fails_the_child_and_spares_the_primary() {
    // A png whose xmp packet is malformed xml. The metadata child fails
    // closed with a machine-readable reason and no artifact, while the
    // primary OCR leg is untouched.
    let setup = setup();
    fs::write(
        setup.root.join("bad.png"),
        png_with_xmp("<a></b>"), // mismatched end tag
    )
    .unwrap();

    run(&setup);

    let child = terminal(&setup, "bad.png.d/#image-metadata").expect("metadata child record");
    assert_eq!(child.status, Status::Failed);
    assert_eq!(child.converter_id.as_deref(), Some("image-metadata"));
    assert!(
        child
            .error
            .as_deref()
            .is_some_and(|e| e.starts_with("image-metadata-malformed")),
        "{:?}",
        child.error
    );
    assert!(child.text_path.is_none());
    assert!(
        !setup
            .mirror
            .join("alpha/bad.png.d/#image-metadata.txt")
            .exists()
    );

    // The primary leg is unaffected: it fails only for the unwired
    // runtime, the metadata failure never touched it.
    let primary = terminal(&setup, "bad.png").expect("primary record");
    assert!(
        primary
            .error
            .as_deref()
            .is_some_and(|e| e.starts_with("image-ocr-runtime-missing")),
        "{:?}",
        primary.error
    );
}

#[test]
fn a_like_named_source_in_the_namespace_skips_the_leg_with_a_warning() {
    // A real walked file already occupies the image `.d/` namespace, so
    // the metadata leg must not run and must not overwrite it. The image
    // parent record carries the namespace-occupied warning, and the real
    // source converts normally.
    let setup = setup();
    fs::write(
        setup.root.join("clash.png"),
        png_with_xmp(&xmp_description("should not be written")),
    )
    .unwrap();
    // A real source sitting exactly where the synthetic child would go.
    fs::create_dir_all(setup.root.join("clash.png.d")).unwrap();
    fs::write(
        setup.root.join("clash.png.d/#image-metadata"),
        b"a real walked file",
    )
    .unwrap();

    run(&setup);

    // No synthetic child record was emitted for the image; the record at
    // that path is the real walked source, converted as text.
    let occupant = terminal(&setup, "clash.png.d/#image-metadata").expect("the real source record");
    assert_ne!(occupant.converter_id.as_deref(), Some("image-metadata"));

    // The image parent carries the warning.
    let parent = terminal(&setup, "clash.png").expect("image parent record");
    assert!(
        parent
            .warnings
            .iter()
            .any(|w| w == "image-metadata-namespace-occupied"),
        "{:?}",
        parent.warnings
    );
}

#[test]
fn a_re_run_retires_a_prior_metadata_child_that_no_longer_applies() {
    // A first run produces a metadata child; a second run over the same
    // path with no metadata retires it, matching the container-member
    // reconciliation.
    let setup = setup();
    let path = setup.root.join("changing.png");
    fs::write(&path, png_with_xmp(&xmp_description("first pass"))).unwrap();
    run(&setup);
    let first = terminal(&setup, "changing.png.d/#image-metadata").expect("first child");
    assert_eq!(first.status, Status::Converted);

    // Replace the source with a metadata-free image and re-run.
    fs::write(&path, png_plain()).unwrap();
    run(&setup);
    let retired = terminal(&setup, "changing.png.d/#image-metadata").expect("retired child");
    assert_eq!(retired.status, Status::Failed);
    assert!(
        !setup
            .mirror
            .join("alpha/changing.png.d/#image-metadata.txt")
            .exists()
    );
}

#[test]
fn an_over_ceiling_image_source_fails_the_primary_and_mints_no_child() {
    // A sparse file over the source ceiling, wearing png magic. It is
    // refused on size before anything reads its body: one failed
    // primary with the resource-limit reason, and no metadata child.
    let setup = setup();
    let path = setup.root.join("huge.png");
    let mut file = fs::File::create(&path).unwrap();
    file.write_all(b"\x89PNG\r\n\x1a\n").unwrap();
    file.set_len(text_mirror::convert::MAX_SOURCE_BYTES + 1)
        .unwrap();
    drop(file);

    let report = run(&setup);

    let primary = terminal(&setup, "huge.png").expect("primary record");
    assert_eq!(primary.status, Status::Failed);
    assert!(
        primary
            .error
            .as_deref()
            .is_some_and(|e| e.starts_with("resource_limit")),
        "{:?}",
        primary.error
    );
    assert_eq!(report.counts.failed, 1);
    assert!(terminal(&setup, "huge.png.d/#image-metadata").is_none());
    assert!(
        !setup
            .mirror
            .join("alpha/huge.png.d/#image-metadata.txt")
            .exists()
    );
}

#[test]
fn a_literal_member_before_the_image_occupies_the_child_path() {
    // The archive names a real member exactly where the image's
    // metadata child would go, and that member comes first. The image
    // records the namespace-occupied warning and no synthetic child is
    // written, so the real member is neither overwritten nor relabeled.
    let setup = setup();
    let bytes = stored_zip(&[
        ("photo.png.d/#image-metadata", b"a literal member"),
        (
            "photo.png",
            &png_with_xmp(&xmp_description("must not be written")),
        ),
    ]);
    fs::write(setup.root.join("bundle.zip"), bytes).unwrap();

    run(&setup);

    // The record at the child path is the literal member's own, routed
    // by its own detection (extensionless, so unsupported), never the
    // metadata converter's.
    let occupant = terminal(&setup, "bundle.zip.d/photo.png.d/#image-metadata")
        .expect("the literal member record");
    assert_eq!(occupant.status, Status::Unsupported);
    assert_ne!(occupant.converter_id.as_deref(), Some("image-metadata"));
    assert_eq!(occupant.parent_source.as_deref(), Some("bundle.zip"));
    assert!(
        !setup
            .mirror
            .join("alpha/bundle.zip.d/photo.png.d/#image-metadata.txt")
            .exists()
    );

    let image = terminal(&setup, "bundle.zip.d/photo.png").expect("image member record");
    assert!(
        image
            .warnings
            .iter()
            .any(|w| w == "image-metadata-namespace-occupied"),
        "{:?}",
        image.warnings
    );
    assert!(terminal(&setup, "bundle.zip.d/#collision-1").is_none());
}

#[test]
fn a_literal_member_after_the_image_is_the_collision() {
    // The image comes first and mints its child; the later real member
    // at the child path is refused as a member-path collision, so the
    // metadata child is neither overwritten nor silently dropped.
    let setup = setup();
    let bytes = stored_zip(&[
        (
            "photo.png",
            &png_with_xmp(&xmp_description("kept sentinel")),
        ),
        ("photo.png.d/#image-metadata", b"a literal member"),
    ]);
    fs::write(setup.root.join("bundle.zip"), bytes).unwrap();

    run(&setup);

    let child = terminal(&setup, "bundle.zip.d/photo.png.d/#image-metadata")
        .expect("the metadata child record");
    assert_eq!(child.status, Status::Converted);
    assert_eq!(child.converter_id.as_deref(), Some("image-metadata"));
    let text = artifact(&setup, "bundle.zip.d/photo.png.d/#image-metadata");
    assert!(text.contains("kept sentinel"), "{text}");

    let refused = terminal(&setup, "bundle.zip.d/#collision-1").expect("collision record");
    assert_eq!(refused.status, Status::Failed);
    assert_eq!(refused.error.as_deref(), Some("member-path-collision"));
}

#[test]
fn a_prior_record_from_the_previous_rules_generation_is_not_skipped() {
    // A primary record written under the previous rules generation,
    // before the metadata leg existed: same bytes, same converter
    // version, an intact artifact, and no child. The rules bump makes it
    // a checkpoint miss, so the image re-runs and the child is minted.
    let setup = setup();
    fs::write(
        setup.root.join("old.png"),
        png_with_xmp(&xmp_description("minted on upgrade")),
    )
    .unwrap();
    let rules = fake_ocr_rules();
    run_with(&setup, &rules);
    assert!(terminal(&setup, "old.png.d/#image-metadata").is_some());

    remove_child_artifact(&setup, "old.png.d/#image-metadata");
    rewrite_shard(&setup, |records| {
        records
            .into_iter()
            .filter(|r| r.source_path == "old.png")
            .map(|mut r| {
                r.rules_version = "8".to_string();
                r
            })
            .collect()
    });

    let report = run_with(&setup, &rules);
    assert_eq!(report.counts.skipped_unchanged, 0);
    let primary = terminal(&setup, "old.png").unwrap();
    assert_eq!(primary.status, Status::Converted);
    assert_eq!(primary.rules_version, "10");
    let child = terminal(&setup, "old.png.d/#image-metadata").expect("minted child");
    assert_eq!(child.status, Status::Converted);
    assert!(artifact(&setup, "old.png.d/#image-metadata").contains("minted on upgrade"));
}

#[test]
fn an_identical_image_borrows_its_primary_and_still_gets_a_child() {
    // Two byte-identical images: the second borrows the first's OCR
    // artifact as a dedup record, and its own metadata child is still
    // written under its own path.
    let setup = setup();
    let bytes = png_with_xmp(&xmp_description("shared sentinel"));
    fs::write(setup.root.join("a.png"), &bytes).unwrap();
    fs::write(setup.root.join("b.png"), &bytes).unwrap();

    let report = run_with(&setup, &fake_ocr_rules());

    assert_eq!(report.counts.dedup, 1);
    let second = terminal(&setup, "b.png").unwrap();
    assert_eq!(second.status, Status::Dedup);
    assert_eq!(second.dedup_of.as_deref(), Some("a.png"));
    for image in ["a.png", "b.png"] {
        let path = format!("{image}.d/#image-metadata");
        let child = terminal(&setup, &path).unwrap_or_else(|| panic!("{path}"));
        assert_eq!(child.status, Status::Converted);
        assert_eq!(child.parent_source.as_deref(), Some(image));
        assert!(artifact(&setup, &path).contains("shared sentinel"));
    }
}

#[test]
fn a_missing_child_artifact_re_runs_the_image() {
    // The primary artifact is intact but the metadata child's artifact
    // is gone. The checkpoint validates the image's descendants the way
    // it validates a container's, so the image is not skipped and the
    // child is written again rather than left pointing at nothing.
    let setup = setup();
    fs::write(
        setup.root.join("shot.png"),
        png_with_xmp(&xmp_description("restored sentinel")),
    )
    .unwrap();
    let rules = fake_ocr_rules();
    run_with(&setup, &rules);
    remove_child_artifact(&setup, "shot.png.d/#image-metadata");

    let report = run_with(&setup, &rules);

    assert_eq!(report.counts.skipped_unchanged, 0);
    assert_eq!(
        terminal(&setup, "shot.png").unwrap().status,
        Status::Converted
    );
    let child = terminal(&setup, "shot.png.d/#image-metadata").unwrap();
    assert_eq!(child.status, Status::Converted);
    assert!(artifact(&setup, "shot.png.d/#image-metadata").contains("restored sentinel"));
}

#[test]
fn a_skipped_member_image_keeps_its_child_when_the_container_re_expands() {
    // The container changes, so it re-expands, but the image member is
    // unchanged with an intact primary and child, so it skips. The
    // skip must carry the prior child forward as emitted, or the
    // owner's reconciliation would retire it as a removed member.
    let setup = setup();
    let image = png_with_xmp(&xmp_description("carried forward"));
    let first = stored_zip(&[("photo.png", &image), ("note.txt", b"one\n")]);
    fs::write(setup.root.join("bundle.zip"), first).unwrap();
    let rules = fake_ocr_rules();
    run_with(&setup, &rules);
    let child_path = "bundle.zip.d/photo.png.d/#image-metadata";
    assert_eq!(
        terminal(&setup, child_path).unwrap().status,
        Status::Converted
    );

    let second = stored_zip(&[
        ("photo.png", &image),
        ("note.txt", b"one\n"),
        ("extra.txt", b"two\n"),
    ]);
    fs::write(setup.root.join("bundle.zip"), second).unwrap();
    run_with(&setup, &rules);

    let member = terminal(&setup, "bundle.zip.d/photo.png").unwrap();
    assert_eq!(member.status, Status::SkippedUnchanged);
    let child = terminal(&setup, child_path).unwrap();
    assert_eq!(child.status, Status::Converted, "{:?}", child.error);
    assert!(artifact(&setup, child_path).contains("carried forward"));
}

#[test]
fn a_prior_record_from_a_build_without_the_converter_is_not_skipped() {
    // A primary record whose warnings say the metadata leg never ran,
    // as a build without the converter writes it. Once the converter is
    // present that record is not skippable even with an intact artifact
    // and a matching key, so the child is minted.
    let setup = setup();
    fs::write(
        setup.root.join("later.png"),
        png_with_xmp(&xmp_description("minted once built")),
    )
    .unwrap();
    let rules = fake_ocr_rules();
    run_with(&setup, &rules);

    remove_child_artifact(&setup, "later.png.d/#image-metadata");
    rewrite_shard(&setup, |records| {
        records
            .into_iter()
            .filter(|r| r.source_path == "later.png")
            .map(|mut r| {
                r.warnings.push("image-metadata-not-built".to_string());
                r
            })
            .collect()
    });

    let report = run_with(&setup, &rules);
    assert_eq!(report.counts.skipped_unchanged, 0);
    let primary = terminal(&setup, "later.png").unwrap();
    assert_eq!(primary.status, Status::Converted);
    assert!(
        !primary
            .warnings
            .iter()
            .any(|w| w == "image-metadata-not-built"),
        "{:?}",
        primary.warnings
    );
    let child = terminal(&setup, "later.png.d/#image-metadata").expect("minted child");
    assert_eq!(child.status, Status::Converted);
}

#[test]
fn a_dedup_seeded_over_ceiling_image_is_refused_before_any_load() {
    // Run-level control for the dedup shape: a prior current-rules
    // converted record whose source hash equals a sparse over-ceiling
    // png-magic file. At the run level the walker refuses the file
    // before a unit exists; the in-process guard on the dedup borrow is
    // proven by the pipeline unit test that drives the expander
    // directly.
    let setup = setup();
    let rules = fake_ocr_rules();
    fs::write(
        setup.root.join("canon.png"),
        png_with_xmp(&xmp_description("canonical")),
    )
    .unwrap();
    run_with(&setup, &rules);
    assert_eq!(
        terminal(&setup, "canon.png").unwrap().status,
        Status::Converted
    );

    let huge = setup.root.join("huge.png");
    let mut file = fs::File::create(&huge).unwrap();
    file.write_all(b"\x89PNG\r\n\x1a\n").unwrap();
    file.set_len(text_mirror::convert::MAX_SOURCE_BYTES + 1)
        .unwrap();
    drop(file);
    let huge_hash = text_mirror::hash::hash_bytes(&fs::read(&huge).unwrap());
    rewrite_shard(&setup, |records| {
        records
            .into_iter()
            .map(|mut r| {
                if r.source_path == "canon.png" {
                    r.source_hash = huge_hash.clone();
                }
                r
            })
            .collect()
    });

    let report = run_with(&setup, &rules);

    assert_eq!(report.counts.dedup, 0);
    let primary = terminal(&setup, "huge.png").expect("primary record");
    assert_eq!(primary.status, Status::Failed);
    assert!(
        primary
            .error
            .as_deref()
            .is_some_and(|e| e.starts_with("resource_limit")),
        "{:?}",
        primary.error
    );
    assert!(primary.dedup_of.is_none());
    assert!(terminal(&setup, "huge.png.d/#image-metadata").is_none());
    assert!(
        !setup
            .mirror
            .join("alpha/huge.png.d/#image-metadata.txt")
            .exists()
    );
}
