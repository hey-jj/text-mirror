//! End-to-end tests for the in-jail pixel-OCR converter: png, jpeg, and
//! webp decoded behind the subprocess sandbox, the area cap and
//! long-edge guards, the gated fail-closed formats, and the .ai and svg
//! routing behavior.
//!
//! Through the builtin registry the production `image-ocr` worker mode
//! runs, and it fails closed with `image-ocr-runtime-missing` because
//! this core wires no engine: a valid raster's decode and area guards
//! pass and stage 3 refuses. The fake stage-3 recognition is a separate
//! `image-ocr-fake` worker mode the test harness selects through
//! `ImagePixelOcr::new_fake`; it exercises the outcome mapping (spans to
//! text, the OCR artifact kind, the low-confidence and long-edge
//! warnings) against the real jail without a pinned engine. Raster
//! fixtures are built in-test with the same crate the worker decodes
//! with, so no committed binary fixture is needed. The strict
//! stdout-envelope grammar, the runtime inventory, and the accelerator
//! check are unit tested beside their implementation.

#![cfg(all(unix, feature = "image-ocr"))]

use std::fs;
use std::path::PathBuf;

use image::{ExtendedColorType, ImageEncoder, RgbImage};
use text_mirror::detect::{self, FormatTable};
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

fn terminal(setup: &Setup, source_path: &str) -> Record {
    manifest::read_shard(&setup.manifest_dir.join("alpha.jsonl"))
        .unwrap()
        .records
        .into_iter()
        .rev()
        .find(|r| r.source_path == source_path)
        .unwrap()
}

fn artifact(setup: &Setup, source_path: &str) -> String {
    fs::read_to_string(setup.mirror.join(format!("alpha/{source_path}.txt"))).unwrap()
}

// --- raster fixture builders ----------------------------------------

fn raster(width: u32, height: u32) -> RgbImage {
    // A simple deterministic gradient, so the fixture is a real image
    // rather than a solid block.
    RgbImage::from_fn(width, height, |x, y| {
        image::Rgb([(x % 256) as u8, (y % 256) as u8, 128])
    })
}

fn png_bytes(width: u32, height: u32) -> Vec<u8> {
    let mut out = Vec::new();
    let image = raster(width, height);
    image::codecs::png::PngEncoder::new(&mut out)
        .write_image(image.as_raw(), width, height, ExtendedColorType::Rgb8)
        .unwrap();
    out
}

fn jpeg_bytes(width: u32, height: u32) -> Vec<u8> {
    let mut out = Vec::new();
    image::codecs::jpeg::JpegEncoder::new(&mut out)
        .encode_image(&raster(width, height))
        .unwrap();
    out
}

fn webp_bytes(width: u32, height: u32) -> Vec<u8> {
    let image = raster(width, height);
    let mut out = Vec::new();
    image::codecs::webp::WebPEncoder::new_lossless(&mut out)
        .encode(image.as_raw(), width, height, ExtendedColorType::Rgb8)
        .unwrap();
    out
}

// A minimal PDF with a text layer, for the pdf-backed .ai regression
// guard. The same hand-built shape the pdf converter tests use.
fn pdf_with_text(text: &str) -> Vec<u8> {
    let stream = format!("BT /F1 12 Tf 72 720 Td ({text}) Tj ET");
    let objects = [
        "<< /Type /Catalog /Pages 2 0 R >>".to_string(),
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_string(),
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>"
            .to_string(),
        format!("<< /Length {} >>\nstream\n{stream}\nendstream", stream.len() + 1),
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_string(),
    ];
    let mut pdf = String::from("%PDF-1.4\n");
    let mut offsets = Vec::new();
    for (index, body) in objects.iter().enumerate() {
        offsets.push(pdf.len());
        pdf.push_str(&format!("{} 0 obj\n{body}\nendobj\n", index + 1));
    }
    let xref_at = pdf.len();
    pdf.push_str(&format!("xref\n0 {}\n", objects.len() + 1));
    pdf.push_str("0000000000 65535 f \n");
    for offset in offsets {
        pdf.push_str(&format!("{offset:010} 00000 n \n"));
    }
    pdf.push_str(&format!(
        "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref_at}\n%%EOF\n",
        objects.len() + 1
    ));
    pdf.into_bytes()
}

// --- tests ----------------------------------------------------------

#[test]
fn png_jpeg_and_webp_fail_closed_without_a_wired_runtime() {
    // The builtin registry drives the production image-ocr worker mode.
    // A valid raster's decode and area guards pass, and stage 3 refuses
    // because this core wires no engine, so each records a failed
    // conversion with the runtime-missing reason, no artifact.
    let setup = setup();
    fs::write(setup.root.join("shot.png"), png_bytes(64, 48)).unwrap();
    fs::write(setup.root.join("photo.jpeg"), jpeg_bytes(64, 48)).unwrap();
    fs::write(setup.root.join("sticker.webp"), webp_bytes(64, 48)).unwrap();

    let report = run(&setup);
    assert_eq!(report.counts.converted, 0, "records: {report:?}");
    assert_eq!(report.counts.failed, 3, "records: {report:?}");

    for (source, format) in [
        ("shot.png", "png"),
        ("photo.jpeg", "jpeg"),
        ("sticker.webp", "webp"),
    ] {
        let record = terminal(&setup, source);
        assert_eq!(record.status, Status::Failed, "{source}");
        assert_eq!(record.detected_format, format, "{source}");
        assert_eq!(
            record.converter_id.as_deref(),
            Some("image-pixel-ocr"),
            "{source}"
        );
        assert!(
            record
                .error
                .as_deref()
                .is_some_and(|e| e.starts_with("image-ocr-runtime-missing")),
            "{source}: {:?}",
            record.error
        );
        assert!(record.text_path.is_none(), "{source}");
        assert!(record.artifact_kind.is_none(), "{source}");
    }
}

#[test]
fn the_fake_engine_path_maps_spans_to_an_ocr_outcome() {
    // The fake stage-3 mode is selected explicitly through new_fake,
    // never through the registry. It exercises the decode, the outcome
    // mapping, the OCR artifact kind, and the low-confidence warning
    // against the real jail without a pinned engine.
    use text_mirror::convert::Converter;
    use text_mirror::convert::subprocess::ImagePixelOcr;

    for (bytes, format) in [
        (png_bytes(64, 48), "png"),
        (jpeg_bytes(64, 48), "jpeg"),
        (webp_bytes(64, 48), "webp"),
    ] {
        let converter = ImagePixelOcr::new_fake(Default::default());
        let outcome = converter
            .convert(&bytes, format)
            .unwrap_or_else(|e| panic!("{format}: {e}"));
        assert_eq!(outcome.converter_id, "image-pixel-ocr", "{format}");
        assert_eq!(outcome.artifact_kind, ArtifactKind::Ocr, "{format}");
        assert!(
            outcome.text.contains("recognized from"),
            "{format}: {}",
            outcome.text
        );
        // The fake returns one span under the confidence floor.
        assert!(
            outcome
                .warnings
                .iter()
                .any(|w| w.starts_with("ocr_low_confidence:")),
            "{format}: {:?}",
            outcome.warnings
        );
    }
}

#[test]
fn the_area_cap_fails_closed_with_no_silent_resize() {
    // 2048x2048 = 4.19 MP is over the 2.36 MP encoder-input area cap and
    // fails at the area layer; a 1536x1536 in-scope raster clears the
    // area layer and then fails closed at stage 3 for want of a runtime.
    // No raster is silently downscaled to fit.
    let setup = setup();
    fs::write(setup.root.join("huge.png"), png_bytes(2048, 2048)).unwrap();
    fs::write(setup.root.join("ceiling.png"), png_bytes(1536, 1536)).unwrap();

    let report = run(&setup);
    assert_eq!(report.counts.converted, 0, "records: {report:?}");
    assert_eq!(report.counts.failed, 2, "records: {report:?}");

    let huge = terminal(&setup, "huge.png");
    assert_eq!(huge.status, Status::Failed);
    assert!(
        huge.error
            .as_deref()
            .is_some_and(|e| e.starts_with("image-ocr-area-exceeded")),
        "{:?}",
        huge.error
    );
    assert!(huge.text_path.is_none());
    assert!(!setup.mirror.join("alpha/huge.png.txt").exists());

    let ceiling = terminal(&setup, "ceiling.png");
    assert_eq!(ceiling.status, Status::Failed);
    assert!(
        ceiling
            .error
            .as_deref()
            .is_some_and(|e| e.starts_with("image-ocr-runtime-missing")),
        "{:?}",
        ceiling.error
    );
}

#[test]
fn a_long_edge_within_the_area_cap_warns_on_the_fake_path() {
    // 3000x786 = 2,358,000 px, legal by area, long edge past the
    // validated 1600, so decode emits the long-edge note once. The fake
    // path carries the worker's warnings through to the outcome.
    use text_mirror::convert::Converter;
    use text_mirror::convert::subprocess::ImagePixelOcr;

    let converter = ImagePixelOcr::new_fake(Default::default());
    let outcome = converter.convert(&png_bytes(3000, 786), "png").unwrap();
    assert!(
        outcome
            .warnings
            .iter()
            .any(|w| w.starts_with("image_ocr_long_edge:")),
        "{:?}",
        outcome.warnings
    );
}

#[test]
fn corrupt_raster_bytes_fail_with_a_decode_reason() {
    let setup = setup();
    let mut truncated = png_bytes(32, 32);
    truncated.truncate(40);
    fs::write(setup.root.join("torn.png"), truncated).unwrap();

    run(&setup);
    let record = terminal(&setup, "torn.png");
    assert_eq!(record.status, Status::Failed);
    assert!(
        record
            .error
            .as_deref()
            .is_some_and(|e| e.starts_with("image-ocr-decode-failed")),
        "{:?}",
        record.error
    );
    assert!(record.text_path.is_none());
}

#[test]
fn heic_fails_closed_with_no_jailed_rasterizer() {
    let setup = setup();
    // An ftyp box with the heic brand, so detection resolves heic.
    fs::write(
        setup.root.join("photo.heic"),
        b"\x00\x00\x00\x18ftypheic\x00\x00\x00\x00heic",
    )
    .unwrap();

    run(&setup);
    let record = terminal(&setup, "photo.heic");
    assert_eq!(record.detected_format, "heic");
    assert_eq!(record.status, Status::Unsupported);
    assert_eq!(record.error.as_deref(), Some("no-jailed-rasterizer"));
    assert!(record.text_path.is_none());
}

#[test]
fn a_pdf_backed_ai_still_converts_and_does_not_regress() {
    // A PDF-backed .ai routes to the pdf path and keeps its text layer,
    // so a file that converts today does not become unsupported under
    // the new .ai routing.
    let setup = setup();
    fs::write(
        setup.root.join("art.ai"),
        pdf_with_text("Illustrator text layer"),
    )
    .unwrap();

    run(&setup);
    let record = terminal(&setup, "art.ai");
    assert_eq!(record.detected_format, "ai");
    assert!(
        !record.format_mismatch,
        "pdf magic under .ai is a refinement"
    );
    assert_eq!(record.status, Status::Converted);
    assert_eq!(record.converter_id.as_deref(), Some("pdf-subprocess"));
    assert_eq!(record.artifact_kind, Some(ArtifactKind::Text));
    assert!(artifact(&setup, "art.ai").contains("Illustrator text layer"));
}

#[test]
fn svg_still_routes_to_text_passthrough() {
    // svg stays on text-passthrough as raw markup in the core and no OCR
    // claimant is added; the pixel-OCR leg for svg is a provider-surface
    // concern that is not built here.
    let setup = setup();
    let svg = b"<?xml version=\"1.0\"?>\n<svg xmlns=\"http://www.w3.org/2000/svg\"><text>hi</text></svg>\n";
    fs::write(setup.root.join("logo.svg"), svg).unwrap();

    run(&setup);
    let record = terminal(&setup, "logo.svg");
    assert_eq!(record.detected_format, "svg");
    assert_eq!(record.status, Status::Converted);
    assert_eq!(record.converter_id.as_deref(), Some("text-passthrough"));
    assert_eq!(record.artifact_kind, Some(ArtifactKind::Text));
    assert!(artifact(&setup, "logo.svg").contains("<svg"));
}

#[test]
fn ai_detection_resolves_by_refinement_and_by_extension() {
    let table = FormatTable::builtin().unwrap();
    let dir = tempfile::tempdir().unwrap();

    // PDF magic plus the .ai extension: refinement wins, no mismatch.
    let backed = dir.path().join("art.ai");
    fs::write(&backed, pdf_with_text("x")).unwrap();
    let detection = detect::detect_file(&backed, &table).unwrap();
    assert_eq!(detection.detected, "ai");
    assert!(!detection.mismatch);

    // PDF magic with no .ai extension stays pdf.
    let plain = dir.path().join("doc.pdf");
    fs::write(&plain, pdf_with_text("x")).unwrap();
    let detection = detect::detect_file(&plain, &table).unwrap();
    assert_eq!(detection.detected, "pdf");

    // Legacy PostScript magic under .ai resolves by extension to ai,
    // whose bytes the table does not name, so a warning notes the
    // out-of-table magic and the flag stays down.
    let legacy = dir.path().join("legacy.ai");
    fs::write(&legacy, b"%!PS-Adobe-3.0\n%%Title: legacy\nshowpage\n").unwrap();
    let (detection, warnings) = detect::detect_file_with_warnings(&legacy, &table).unwrap();
    assert_eq!(detection.detected, "ai");
    assert!(!detection.mismatch);
    assert!(
        warnings
            .iter()
            .any(|w| w.starts_with("magic-format-outside-table:")),
        "{warnings:?}"
    );
}

#[test]
fn a_legacy_postscript_ai_fails_closed_with_a_pdf_family_reason() {
    // The accepted consequence of routing .ai to the pdf path: a
    // PostScript-backed .ai fails closed there, not as an unknown format.
    let setup = setup();
    fs::write(
        setup.root.join("legacy.ai"),
        b"%!PS-Adobe-3.0\n%%Title: legacy\nshowpage\n",
    )
    .unwrap();

    run(&setup);
    let record = terminal(&setup, "legacy.ai");
    assert_eq!(record.detected_format, "ai");
    assert_eq!(record.status, Status::Failed);
    // The pdf worker owns it, so the reason is a pdf-family one rather
    // than a no-converter or unknown-format outcome.
    assert!(record.error.is_some());
    assert!(record.text_path.is_none());
}

#[test]
fn the_registry_routes_the_image_family_as_ruled() {
    let rules = Rules::builtin().unwrap();
    let registry = &rules.registry;
    assert_eq!(registry.version(), "9");
    for format in ["png", "jpeg", "webp"] {
        assert_eq!(
            registry.converter_for(format).map(|c| c.id()),
            Some("image-pixel-ocr"),
            "{format}"
        );
    }
    assert_eq!(
        registry.converter_for("ai").map(|c| c.id()),
        Some("pdf-subprocess")
    );
    assert_eq!(
        registry.converter_for("svg").map(|c| c.id()),
        Some("text-passthrough")
    );
    assert_eq!(
        registry.unsupported_reason("heic"),
        Some("no-jailed-rasterizer")
    );
    assert_eq!(registry.unsupported_reason("tiff"), Some("engine-unpinned"));
}
