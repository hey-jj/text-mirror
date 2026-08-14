//! End-to-end tests for the subprocess runner in the pipeline.
//!
//! PDF conversion runs behind the sandbox runner, and the media
//! formats route to unpinned adapters that fail closed. These tests
//! run the whole pipeline: a PDF converts through the worker and its
//! record reconverts idempotently under the current rules version, and
//! image, audio, and video fixtures record `unsupported` with the
//! `engine-unpinned` reason and no artifact.

#![cfg(unix)]

use std::fs;
use std::path::PathBuf;

use text_mirror::manifest::{self, Record, Status};
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
    let mirror = dir.path().join("mirror");
    let manifest_dir = dir.path().join("manifest");
    fs::create_dir_all(&root).unwrap();
    Setup {
        _dir: dir,
        root,
        mirror,
        manifest_dir,
    }
}

fn run(setup: &Setup, rules: &Rules) -> text_mirror::report::RunReport {
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

fn terminal(setup: &Setup, source_path: &str) -> Record {
    manifest::read_shard(&setup.manifest_dir.join("alpha.jsonl"))
        .unwrap()
        .records
        .into_iter()
        .rev()
        .find(|r| r.source_path == source_path)
        .unwrap()
}

/// A minimal one-page PDF with a text layer.
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

#[test]
fn pdf_converts_behind_the_runner_and_records_the_subprocess_converter() {
    let setup = setup();
    fs::write(
        setup.root.join("brief.pdf"),
        pdf_with_text("Runner carried text"),
    )
    .unwrap();

    let rules = Rules::builtin().unwrap();
    let report = run(&setup, &rules);
    assert_eq!(report.counts.converted, 1, "records: {report:?}");

    let record = terminal(&setup, "brief.pdf");
    assert_eq!(
        record.status,
        Status::Converted,
        "error: {:?}",
        record.error
    );
    assert_eq!(record.converter_id.as_deref(), Some("pdf-subprocess"));
    assert_eq!(record.converter_version.as_deref(), Some("1.0.0"));
    assert_eq!(record.rules_version, "3");
    let text = fs::read_to_string(setup.mirror.join("brief.pdf.txt")).unwrap();
    assert!(text.contains("Runner carried text"), "text: {text:?}");
}

#[test]
fn a_converted_pdf_reconverts_idempotently_under_rules_three() {
    let setup = setup();
    fs::write(
        setup.root.join("brief.pdf"),
        pdf_with_text("stable across runs"),
    )
    .unwrap();

    let rules = Rules::builtin().unwrap();
    let first = run(&setup, &rules);
    assert_eq!(first.counts.converted, 1);

    // The checkpoint key includes converter version and rules version.
    // A second pass matches it and skips with no work, and the record
    // still carries the rules_version 3 provenance.
    let second = run(&setup, &rules);
    assert_eq!(second.counts.converted, 0);
    assert_eq!(second.counts.skipped_unchanged, 1);
    let record = terminal(&setup, "brief.pdf");
    assert_eq!(record.status, Status::SkippedUnchanged);
    assert_eq!(record.rules_version, "3");
    assert_eq!(record.converter_id.as_deref(), Some("pdf-subprocess"));
}

/// A one-page PDF with an empty content stream, the no-text-layer
/// shape that fails with `pdf_no_text_layer`.
fn scanned_pdf() -> Vec<u8> {
    let objects = [
        "<< /Type /Catalog /Pages 2 0 R >>".to_string(),
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_string(),
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>".to_string(),
        "<< /Length 1 >>\nstream\n\nendstream".to_string(),
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

#[test]
fn a_scanned_pdf_fails_closed_behind_the_runner() {
    let setup = setup();
    fs::write(setup.root.join("scan.pdf"), scanned_pdf()).unwrap();

    let rules = Rules::builtin().unwrap();
    let report = run(&setup, &rules);
    assert_eq!(report.counts.failed, 1, "records: {report:?}");

    let record = terminal(&setup, "scan.pdf");
    assert_eq!(record.status, Status::Failed);
    assert!(
        record
            .error
            .as_deref()
            .unwrap()
            .starts_with("pdf_no_text_layer"),
        "error: {:?}",
        record.error
    );
    assert!(!setup.mirror.join("scan.pdf.txt").exists());
}

#[test]
fn media_formats_record_unsupported_with_engine_unpinned() {
    let setup = setup();
    // One representative per adapter class: image, audio, and video.
    fs::write(
        setup.root.join("scan.png"),
        [0x89, b'P', b'N', b'G', 0, 1, 2, 3],
    )
    .unwrap();
    fs::write(setup.root.join("call.mp3"), b"ID3fake audio bytes").unwrap();
    fs::write(setup.root.join("clip.mp4"), b"\0\0\0\x18ftypmp42fake").unwrap();

    let rules = Rules::builtin().unwrap();
    let report = run(&setup, &rules);
    assert_eq!(report.counts.unsupported, 3, "records: {report:?}");

    for (source, format) in [
        ("scan.png", "png"),
        ("call.mp3", "mp3"),
        ("clip.mp4", "mp4"),
    ] {
        let record = terminal(&setup, source);
        assert_eq!(record.status, Status::Unsupported, "{source}");
        assert_eq!(record.detected_format, format, "{source}");
        assert_eq!(
            record.error.as_deref(),
            Some("engine-unpinned"),
            "{source} should carry the engine-unpinned reason"
        );
        assert!(record.text_path.is_none(), "{source} has no artifact");
        assert!(
            !setup.mirror.join(format!("{source}.txt")).exists(),
            "{source} wrote no text file"
        );
    }
}

#[test]
fn an_engine_unpinned_record_reruns_every_pass() {
    let setup = setup();
    fs::write(
        setup.root.join("scan.png"),
        [0x89, b'P', b'N', b'G', 0, 1, 2, 3],
    )
    .unwrap();
    let rules = Rules::builtin().unwrap();

    run(&setup, &rules);
    // Unsupported records are re-evaluated every run, so a rules bump
    // that pins an engine converts them automatically with no sweep.
    let second = run(&setup, &rules);
    assert_eq!(second.counts.unsupported, 1);
    assert_eq!(second.counts.skipped_unchanged, 0);
    let record = terminal(&setup, "scan.png");
    assert_eq!(record.error.as_deref(), Some("engine-unpinned"));
}
