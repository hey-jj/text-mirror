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
use std::path::PathBuf;

use text_mirror::manifest::{self, ArtifactKind, Record, Status};
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
    // A metadata-bearing image: the metadata sentinel lands in the child
    // and the OCR primary leg produces no artifact for it to leak into.
    // The two legs are independent: the primary fails closed for want of
    // a wired runtime while the child converts.
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
    // No OCR artifact exists, so the sentinel cannot appear in one.
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
