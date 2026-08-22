//! End-to-end coverage for rules version 5: the markup and mail
//! converters, the NUL refusal, dedup warning inheritance, and
//! basename routing, all through the full pipeline.

use std::fs;
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

fn utf16le_with_bom(text: &str) -> Vec<u8> {
    let mut bytes = vec![0xFF, 0xFE];
    for unit in text.encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    bytes
}

const PAGE: &str = "<html><head><title>Board Update</title>\
<script>tracker('secret');</script><style>.x{color:red}</style></head>\
<body><p>Revenue &amp; costs</p><ul><li>one<li>two</ul>\
<table><tr><td>cell a</td><td>cell b</td></tr></table></body></html>";

#[test]
fn an_html_page_converts_to_clean_text() {
    let setup = setup();
    fs::write(setup.root.join("page.html"), PAGE).unwrap();

    let report = run(&setup);
    assert_eq!(report.counts.converted, 1);

    let record = terminal(&setup, "page.html");
    assert_eq!(record.status, Status::Converted);
    assert_eq!(record.detected_format, "html");
    assert_eq!(record.converter_id.as_deref(), Some("html-strip"));
    assert_eq!(record.rules_version, "5");

    let text = fs::read_to_string(setup.mirror.join("alpha/page.html.txt")).unwrap();
    assert_eq!(
        text,
        "Board Update\nRevenue & costs\n\none\ntwo\n\ncell a\tcell b\n"
    );
    assert!(
        setup
            .mirror
            .join("alpha/page.html.segments.jsonl")
            .is_file()
    );
}

const MESSAGE: &str = "From: =?UTF-8?B?WsO8cmljaCBPZmZpY2U=?= <office@example.com>\r\n\
To: team@example.com\r\n\
Subject: Offsite plan\r\n\
Date: Fri, 21 Aug 2026 09:00:00 +0000\r\n\
MIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; boundary=\"outer\"\r\n\
\r\n\
--outer\r\n\
Content-Type: multipart/alternative; boundary=\"inner\"\r\n\
\r\n\
--inner\r\n\
Content-Type: text/plain; charset=utf-8\r\n\
\r\n\
See the attached budget.\r\n\
--inner\r\n\
Content-Type: text/html; charset=utf-8\r\n\
\r\n\
<p>See the <b>attached</b> budget.</p>\r\n\
--inner--\r\n\
--outer\r\n\
Content-Type: application/pdf\r\n\
Content-Disposition: attachment; filename=\"budget.pdf\"\r\n\
Content-Transfer-Encoding: base64\r\n\
\r\n\
JVBERi0xLjQK\r\n\
--outer--\r\n";

#[test]
fn an_eml_message_converts_and_enumerates_its_attachment() {
    let setup = setup();
    fs::write(setup.root.join("update.eml"), MESSAGE).unwrap();

    let report = run(&setup);
    assert_eq!(report.counts.converted, 1);

    let record = terminal(&setup, "update.eml");
    assert_eq!(record.status, Status::Converted);
    assert_eq!(record.detected_format, "eml");
    assert_eq!(record.converter_id.as_deref(), Some("eml-mime"));
    assert!(
        record
            .warnings
            .iter()
            .any(|w| w == "attachment-not-expanded: budget.pdf (application/pdf)"),
        "warnings: {:?}",
        record.warnings
    );

    let text = fs::read_to_string(setup.mirror.join("alpha/update.eml.txt")).unwrap();
    assert_eq!(
        text,
        "From: Z\u{fc}rich Office <office@example.com>\n\
         To: team@example.com\n\
         Date: Fri, 21 Aug 2026 09:00:00 +0000\n\
         Subject: Offsite plan\n\n\
         See the attached budget.\n"
    );
}

#[test]
fn malformed_mime_fails_closed_with_a_machine_reason() {
    let setup = setup();
    fs::write(
        setup.root.join("broken.eml"),
        "From: a@example.com\r\n\
Content-Type: text/plain\r\n\
Content-Transfer-Encoding: base64\r\n\
\r\n\
this is not base64 at all!!!\r\n",
    )
    .unwrap();

    let report = run(&setup);
    assert_eq!(report.counts.failed, 1);
    let record = terminal(&setup, "broken.eml");
    assert_eq!(record.status, Status::Failed);
    let error = record.error.as_deref().unwrap();
    assert!(
        error.starts_with("mime_decode_error") || error.starts_with("mime_parse_error"),
        "{error}"
    );
    assert!(!setup.mirror.join("alpha/broken.eml.txt").exists());
}

// The markless-ASCII UTF-16 twin: valid UTF-8 with interleaved NULs,
// refused now instead of converting into NUL-split tokens.
#[test]
fn nul_bytes_refuse_with_the_offset_and_the_triage_hint() {
    let setup = setup();
    let mut markless = Vec::new();
    for unit in "{\"quarter\": \"Q3\"}\n".encode_utf16() {
        markless.extend_from_slice(&unit.to_le_bytes());
    }
    fs::write(setup.root.join("twin.json"), &markless).unwrap();

    let report = run(&setup);
    assert_eq!(report.counts.failed, 1);
    assert_eq!(report.counts.converted, 0);

    let record = terminal(&setup, "twin.json");
    assert_eq!(record.status, Status::Failed);
    let error = record.error.as_deref().unwrap();
    assert!(error.starts_with("nul_bytes: NUL at byte 1"), "{error}");
    assert!(error.contains("BOM-less UTF-16"), "{error}");
    assert!(!setup.mirror.join("alpha/twin.json.txt").exists());
}

// The NUL refusal is a pipeline output gate, so html and eml output
// carrying a NUL fails the record exactly like passthrough text.
#[test]
fn nul_output_from_any_converter_fails_at_the_pipeline_gate() {
    let setup = setup();
    fs::write(setup.root.join("nul.html"), b"<p>bad\x00text</p>").unwrap();
    fs::write(
        setup.root.join("nul.eml"),
        b"From: a@example.com\r\nContent-Type: text/plain\r\n\r\nbad\x00body\r\n",
    )
    .unwrap();

    let report = run(&setup);
    assert_eq!(report.counts.failed, 2);
    assert_eq!(report.counts.converted, 0);

    for path in ["nul.html", "nul.eml"] {
        let record = terminal(&setup, path);
        assert_eq!(record.status, Status::Failed, "{path}");
        let error = record.error.as_deref().unwrap();
        assert!(
            error.starts_with("nul_bytes: NUL at byte"),
            "{path}: {error}"
        );
        assert!(!setup.mirror.join(format!("alpha/{path}.txt")).exists());
    }
}

// A duplicate of the canonical bytes inherits the canonical's
// conversion warnings, the transcoding warning here.
#[test]
fn a_dedup_record_inherits_the_canonical_conversion_warnings() {
    let setup = setup();
    let bytes = utf16le_with_bom("dept,headcount\r\nsales,12\r\n");
    fs::write(setup.root.join("a.csv"), &bytes).unwrap();
    fs::write(setup.root.join("b.csv"), &bytes).unwrap();

    let report = run(&setup);
    assert_eq!(report.counts.converted, 1);
    assert_eq!(report.counts.dedup, 1);

    let duplicate = terminal(&setup, "b.csv");
    assert_eq!(duplicate.status, Status::Dedup);
    assert_eq!(duplicate.dedup_of.as_deref(), Some("a.csv"));
    assert!(
        duplicate
            .warnings
            .iter()
            .any(|w| w == "transcoded from utf-16le"),
        "warnings: {:?}",
        duplicate.warnings
    );

    // The inheritance also rides a seeded canonical on a second run:
    // the duplicate changes, reconverts as a dedup of the seeded
    // canonical, and still carries the warning.
    fs::write(setup.root.join("b.csv"), utf16le_with_bom("changed\r\n")).unwrap();
    run(&setup);
    fs::write(setup.root.join("b.csv"), &bytes).unwrap();
    let third = run(&setup);
    assert_eq!(third.counts.dedup, 1);
    let duplicate = terminal(&setup, "b.csv");
    assert_eq!(duplicate.status, Status::Dedup);
    assert!(
        duplicate
            .warnings
            .iter()
            .any(|w| w == "transcoded from utf-16le"),
        "warnings: {:?}",
        duplicate.warnings
    );
}

#[test]
fn a_bare_dotenv_routes_by_basename() {
    let setup = setup();
    fs::write(setup.root.join(".env"), "API_URL=http://localhost\n").unwrap();

    let report = run(&setup);
    assert_eq!(report.counts.converted, 1);
    let record = terminal(&setup, ".env");
    assert_eq!(record.status, Status::Converted);
    assert_eq!(record.detected_format, "env");
    assert_eq!(record.converter_id.as_deref(), Some("text-passthrough"));
    assert_eq!(
        fs::read_to_string(setup.mirror.join("alpha/.env.txt")).unwrap(),
        "API_URL=http://localhost\n"
    );
}

// A rules 4 era unsupported html record reconverts under rules 5 now
// that the strip converter claims its format.
#[test]
fn a_v4_era_unsupported_html_record_reconverts_under_v5() {
    let setup = setup();
    let bytes = b"<html><body><p>quarterly numbers</p></body></html>";
    fs::write(setup.root.join("report.html"), bytes).unwrap();

    let prior = Record {
        schema: ManifestSchema,
        source_path: "report.html".to_string(),
        source_hash: hash::hash_bytes(bytes),
        source_size: bytes.len() as u64,
        declared_format: Some("html".to_string()),
        detected_format: "html".to_string(),
        format_mismatch: false,
        status: Status::Unsupported,
        text_path: None,
        text_hash: None,
        artifact_kind: None,
        converter_id: None,
        converter_version: None,
        tool_version: None,
        rules_version: "4".to_string(),
        media: None,
        parent_source: None,
        dedup_of: None,
        warnings: Vec::new(),
        error: Some("no-converter".to_string()),
        duration_ms: Some(1),
    };
    let mut writer = ManifestWriter::open(&setup.manifest_dir.join("alpha.jsonl")).unwrap();
    writer.append(&prior).unwrap();
    drop(writer);

    let report = run(&setup);
    assert_eq!(report.counts.converted, 1);
    assert_eq!(report.counts.unsupported, 0);

    let record = terminal(&setup, "report.html");
    assert_eq!(record.status, Status::Converted);
    assert_eq!(record.converter_id.as_deref(), Some("html-strip"));
    assert_eq!(record.rules_version, "5");
    assert_eq!(
        fs::read_to_string(setup.mirror.join("alpha/report.html.txt")).unwrap(),
        "quarterly numbers\n"
    );
}
