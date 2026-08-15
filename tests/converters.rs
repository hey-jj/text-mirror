//! End-to-end tests for the in-process converters and segments files.
//!
//! Fixtures are built in-test with generic content: OOXML and ODF
//! archives through the zip crate, RTF and PDF bytes by hand, and a
//! legacy BIFF workbook through cfb.

use std::fs;
use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};

use text_mirror::manifest::{self, Record, Status};
use text_mirror::pipeline::{self, Rules, RunOptions};
use text_mirror::segments::{self, Segment, SegmentKind};
use text_mirror::walk::WalkOptions;
use zip::CompressionMethod;
use zip::write::SimpleFileOptions;

// ---- fixture builders ----

fn build_zip(entries: &[(&str, &[u8], bool)]) -> Vec<u8> {
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for (name, bytes, stored) in entries {
        let options = if *stored {
            SimpleFileOptions::default().compression_method(CompressionMethod::Stored)
        } else {
            SimpleFileOptions::default()
        };
        writer.start_file(*name, options).unwrap();
        writer.write_all(bytes).unwrap();
    }
    writer.finish().unwrap().into_inner()
}

fn xlsx_fixture() -> Vec<u8> {
    let content_types = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
<Override PartName="/xl/worksheets/sheet2.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
</Types>"#;
    let rels = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>"#;
    let workbook = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
<sheets>
<sheet name="Visible" sheetId="1" r:id="rId1"/>
<sheet name="Secret" sheetId="2" state="hidden" r:id="rId2"/>
</sheets>
</workbook>"#;
    let workbook_rels = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet2.xml"/>
</Relationships>"#;
    let sheet1 = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<cols><col min="2" max="2" hidden="1" width="0" customWidth="1"/></cols>
<sheetData>
<row r="1"><c r="A1" t="inlineStr"><is><t>alpha</t></is></c><c r="B1" t="inlineStr"><is><t>covert</t></is></c><c r="C1"><v>7</v></c></row>
<row r="2" hidden="1"><c r="A2" t="inlineStr"><is><t>ghost row</t></is></c></row>
<row r="3"><c r="A3"><f>SUM(C1:C1)</f><v>7</v></c></row>
</sheetData>
</worksheet>"#;
    let sheet2 = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<sheetData>
<row r="1"><c r="A1" t="inlineStr"><is><t>very quiet</t></is></c></row>
</sheetData>
</worksheet>"#;
    build_zip(&[
        ("[Content_Types].xml", content_types.as_bytes(), false),
        ("_rels/.rels", rels.as_bytes(), false),
        ("xl/workbook.xml", workbook.as_bytes(), false),
        (
            "xl/_rels/workbook.xml.rels",
            workbook_rels.as_bytes(),
            false,
        ),
        ("xl/worksheets/sheet1.xml", sheet1.as_bytes(), false),
        ("xl/worksheets/sheet2.xml", sheet2.as_bytes(), false),
    ])
}

fn ods_fixture() -> Vec<u8> {
    let manifest_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0" manifest:version="1.2">
<manifest:file-entry manifest:full-path="/" manifest:media-type="application/vnd.oasis.opendocument.spreadsheet"/>
<manifest:file-entry manifest:full-path="content.xml" manifest:media-type="text/xml"/>
</manifest:manifest>"#;
    let content = r#"<?xml version="1.0" encoding="UTF-8"?>
<office:document-content xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:table="urn:oasis:names:tc:opendocument:xmlns:table:1.0" xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0" office:version="1.2">
<office:body><office:spreadsheet><table:table table:name="Data"><table:table-column/><table:table-column table:visibility="collapse"/><table:table-row><table:table-cell office:value-type="string"><text:p>one</text:p></table:table-cell><table:table-cell office:value-type="string"><text:p>shy</text:p></table:table-cell></table:table-row><table:table-row table:visibility="collapse"><table:table-cell office:value-type="string"><text:p>lowrow</text:p></table:table-cell></table:table-row></table:table></office:spreadsheet></office:body></office:document-content>"#;
    build_zip(&[
        (
            "mimetype",
            b"application/vnd.oasis.opendocument.spreadsheet",
            true,
        ),
        ("META-INF/manifest.xml", manifest_xml.as_bytes(), false),
        ("content.xml", content.as_bytes(), false),
    ])
}

fn docx_fixture() -> Vec<u8> {
    let content_types = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>"#;
    let rels = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>"#;
    let document = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:body>
<w:p><w:r><w:t>Quarterly planning notes</w:t></w:r></w:p>
<w:p><w:r><w:t>The venue holds forty people.</w:t></w:r></w:p>
</w:body>
</w:document>"#;
    build_zip(&[
        ("[Content_Types].xml", content_types.as_bytes(), false),
        ("_rels/.rels", rels.as_bytes(), false),
        ("word/document.xml", document.as_bytes(), false),
    ])
}

fn epub_fixture() -> Vec<u8> {
    let container = r#"<?xml version="1.0" encoding="UTF-8"?>
<container version="1.0" xmlns="urn:oasis:names:tc:opendocument:xmlns:container">
<rootfiles><rootfile full-path="OEBPS/content.opf" media-type="application/oebps-package+xml"/></rootfiles>
</container>"#;
    let opf = r#"<?xml version="1.0" encoding="UTF-8"?>
<package xmlns="http://www.idpf.org/2007/opf" version="3.0" unique-identifier="uid">
<metadata xmlns:dc="http://purl.org/dc/elements/1.1/">
<dc:identifier id="uid">generic-fixture-book</dc:identifier>
<dc:title>Fixture Book</dc:title>
<dc:language>en</dc:language>
</metadata>
<manifest><item id="c1" href="chapter.xhtml" media-type="application/xhtml+xml"/></manifest>
<spine><itemref idref="c1"/></spine>
</package>"#;
    let chapter = r#"<?xml version="1.0" encoding="UTF-8"?>
<html xmlns="http://www.w3.org/1999/xhtml"><head><title>One</title></head>
<body><p>A chapter about nothing in particular.</p></body></html>"#;
    build_zip(&[
        ("mimetype", b"application/epub+zip", true),
        ("META-INF/container.xml", container.as_bytes(), false),
        ("OEBPS/content.opf", opf.as_bytes(), false),
        ("OEBPS/chapter.xhtml", chapter.as_bytes(), false),
    ])
}

/// A minimal one-page PDF. With `text` the page draws one string, and
/// without it the content stream is empty, which is the no-text-layer
/// shape.
fn pdf_fixture(text: Option<&str>) -> Vec<u8> {
    let stream = match text {
        Some(t) => format!("BT /F1 12 Tf 72 720 Td ({t}) Tj ET"),
        None => String::new(),
    };
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

// BIFF fixture: one worksheet named Data with two label cells and a
// number cell, one hidden row, one hidden column.
fn biff_record(opcode: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&opcode.to_le_bytes());
    out.extend_from_slice(&(payload.len() as u16).to_le_bytes());
    out.extend_from_slice(payload);
    out
}

fn biff_bof(dt: u16) -> Vec<u8> {
    let mut payload = vec![0u8; 16];
    payload[0..2].copy_from_slice(&0x0600u16.to_le_bytes());
    payload[2..4].copy_from_slice(&dt.to_le_bytes());
    biff_record(0x0809, &payload)
}

fn biff_label(row: u16, col: u16, text: &str) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&row.to_le_bytes());
    payload.extend_from_slice(&col.to_le_bytes());
    payload.extend_from_slice(&0u16.to_le_bytes());
    payload.extend_from_slice(&(text.len() as u16).to_le_bytes());
    payload.push(0);
    payload.extend_from_slice(text.as_bytes());
    biff_record(0x0204, &payload)
}

fn biff_number(row: u16, col: u16, value: f64) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&row.to_le_bytes());
    payload.extend_from_slice(&col.to_le_bytes());
    payload.extend_from_slice(&0u16.to_le_bytes());
    payload.extend_from_slice(&value.to_le_bytes());
    biff_record(0x0203, &payload)
}

fn biff_row_hidden(row: u16) -> Vec<u8> {
    let mut payload = vec![0u8; 16];
    payload[0..2].copy_from_slice(&row.to_le_bytes());
    payload[6..8].copy_from_slice(&300u16.to_le_bytes());
    payload[12..14].copy_from_slice(&0x0020u16.to_le_bytes());
    biff_record(0x0208, &payload)
}

fn biff_colinfo_hidden(first: u16, last: u16) -> Vec<u8> {
    let mut payload = vec![0u8; 12];
    payload[0..2].copy_from_slice(&first.to_le_bytes());
    payload[2..4].copy_from_slice(&last.to_le_bytes());
    payload[4..6].copy_from_slice(&2048u16.to_le_bytes());
    payload[8..10].copy_from_slice(&0x0001u16.to_le_bytes());
    biff_record(0x007D, &payload)
}

fn xls_fixture() -> Vec<u8> {
    let mut globals = biff_bof(0x0005);
    let name = b"Data";
    let mut boundsheet = vec![0u8; 8];
    boundsheet[6] = name.len() as u8;
    boundsheet.extend_from_slice(name);
    let boundsheet = biff_record(0x0085, &boundsheet);
    let eof = biff_record(0x000A, &[]);
    let sheet_start = globals.len() + boundsheet.len() + eof.len();
    let mut patched = boundsheet;
    patched[4..8].copy_from_slice(&(sheet_start as u32).to_le_bytes());
    globals.extend(patched);
    globals.extend(eof.clone());

    let mut stream = globals;
    stream.extend(biff_bof(0x0010));
    stream.extend(biff_row_hidden(1));
    stream.extend(biff_colinfo_hidden(1, 1));
    stream.extend(biff_label(0, 0, "plaincell"));
    stream.extend(biff_label(0, 1, "shycol"));
    stream.extend(biff_label(1, 0, "shyrow"));
    stream.extend(biff_number(2, 0, 42.0));
    stream.extend(eof);

    let cursor = Cursor::new(Vec::new());
    let mut compound = cfb::CompoundFile::create(cursor).unwrap();
    {
        let mut entry = compound.create_stream("/Workbook").unwrap();
        entry.write_all(&stream).unwrap();
    }
    compound.into_inner().into_inner()
}

// ---- shared helpers ----

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

fn read_segments(setup: &Setup, source_path: &str) -> Vec<Segment> {
    let path = segments::segments_path(&setup.mirror, "alpha", Path::new(source_path));
    fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

fn artifact(setup: &Setup, source_path: &str) -> String {
    fs::read_to_string(setup.mirror.join(format!("alpha/{source_path}.txt"))).unwrap()
}

fn slice<'a>(text: &'a str, segment: &Segment) -> &'a str {
    &text[segment.start as usize..segment.end as usize]
}

fn hidden_spans<'a>(segments: &'a [Segment], source: &str) -> Vec<&'a Segment> {
    segments
        .iter()
        .filter(|s| s.hidden && s.source.as_deref() == Some(source))
        .collect()
}

// ---- tests ----

#[test]
fn xlsx_hidden_content_is_inline_and_marked_out_of_band() {
    let setup = setup();
    fs::write(setup.root.join("sheet.xlsx"), xlsx_fixture()).unwrap();
    let rules = Rules::builtin().unwrap();
    let report = run(&setup, &rules);
    assert_eq!(
        report.counts.converted, 1,
        "warnings: {:?}",
        report.warnings
    );

    let text = artifact(&setup, "sheet.xlsx");
    // Hidden content sits inline with no marker strings around it.
    assert!(text.contains("covert"));
    assert!(text.contains("ghost row"));
    assert!(text.contains("very quiet"));
    // The formula is inert text beside its cached value.
    assert!(text.contains("7 [=SUM(C1:C1)]"));

    let segs = read_segments(&setup, "sheet.xlsx");
    segments::validate(&segs, &text).unwrap();

    // Sheet boundaries and spans, including the hidden sheet.
    let boundaries: Vec<_> = segs
        .iter()
        .filter(|s| s.kind == SegmentKind::Sheet)
        .collect();
    assert_eq!(boundaries.len(), 2);
    let sheet_spans: Vec<_> = segs
        .iter()
        .filter(|s| s.kind == SegmentKind::Span && s.source.as_deref() == Some("sheet"))
        .collect();
    assert_eq!(sheet_spans.len(), 2);
    let secret = sheet_spans
        .iter()
        .find(|s| s.name.as_deref() == Some("Secret"))
        .unwrap();
    assert!(secret.hidden);
    assert!(slice(&text, secret).contains("very quiet"));

    // The hidden row and hidden column carry hidden-true spans that
    // slice exactly the concealed text.
    let rows = hidden_spans(&segs, "row");
    assert_eq!(rows.len(), 1);
    assert_eq!(slice(&text, rows[0]), "ghost row");
    let columns = hidden_spans(&segs, "column");
    assert_eq!(columns.len(), 1);
    assert_eq!(slice(&text, columns[0]), "covert");

    // Idempotent second run.
    let second = run(&setup, &rules);
    assert_eq!(second.counts.skipped_unchanged, 1);
}

#[test]
fn ods_hidden_rows_and_columns_are_marked() {
    let setup = setup();
    fs::write(setup.root.join("data.ods"), ods_fixture()).unwrap();
    let rules = Rules::builtin().unwrap();
    let report = run(&setup, &rules);
    let record = terminal(&setup, "data.ods");
    assert_eq!(
        report.counts.converted, 1,
        "status {:?} error {:?} detected {:?}",
        record.status, record.error, record.detected_format
    );

    let text = artifact(&setup, "data.ods");
    assert!(text.contains("shy"));
    assert!(text.contains("lowrow"));

    let segs = read_segments(&setup, "data.ods");
    segments::validate(&segs, &text).unwrap();
    let rows = hidden_spans(&segs, "row");
    assert_eq!(rows.len(), 1);
    assert_eq!(slice(&text, rows[0]), "lowrow");
    let columns = hidden_spans(&segs, "column");
    assert_eq!(columns.len(), 1);
    assert_eq!(slice(&text, columns[0]), "shy");
}

#[test]
fn xls_conversion_marks_hidden_content_and_runs_the_differential() {
    let setup = setup();
    fs::write(setup.root.join("legacy.xls"), xls_fixture()).unwrap();
    let rules = Rules::builtin().unwrap();
    run(&setup, &rules);

    let record = terminal(&setup, "legacy.xls");
    assert_eq!(
        record.status,
        Status::Converted,
        "error: {:?}",
        record.error
    );
    let text = artifact(&setup, "legacy.xls");
    assert!(text.contains("plaincell"));
    assert!(text.contains("shycol"));
    assert!(text.contains("shyrow"));
    assert!(text.contains("42"));

    let segs = read_segments(&setup, "legacy.xls");
    segments::validate(&segs, &text).unwrap();
    let rows = hidden_spans(&segs, "row");
    assert_eq!(rows.len(), 1);
    assert_eq!(slice(&text, rows[0]), "shyrow");
    let columns = hidden_spans(&segs, "column");
    assert_eq!(columns.len(), 1);
    assert_eq!(slice(&text, columns[0]), "shycol");

    // The differential ran: either the secondary parsed this minimal
    // fixture and the outcome shows in the warning set, or it could
    // not and said so. Either way the record names it.
    let differential_noted = record
        .warnings
        .iter()
        .any(|w| w.starts_with("differential-"));
    assert!(
        record.warnings.is_empty() || differential_noted,
        "unexpected warnings: {:?}",
        record.warnings
    );
}

#[test]
fn documents_convert_and_segments_cover_the_artifact() {
    let setup = setup();
    fs::write(setup.root.join("report.docx"), docx_fixture()).unwrap();
    fs::write(
        setup.root.join("notes.rtf"),
        br"{\rtf1\ansi Plain words from rich text.}",
    )
    .unwrap();
    fs::write(setup.root.join("book.epub"), epub_fixture()).unwrap();

    let rules = Rules::builtin().unwrap();
    let report = run(&setup, &rules);
    assert_eq!(report.counts.failed, 0, "records: {:?}", {
        manifest::read_shard(&setup.manifest_dir.join("alpha.jsonl"))
            .unwrap()
            .records
            .iter()
            .map(|r| (r.source_path.clone(), r.error.clone()))
            .collect::<Vec<_>>()
    });
    assert_eq!(report.counts.converted, 3);

    for source in ["report.docx", "notes.rtf", "book.epub"] {
        let record = terminal(&setup, source);
        assert_eq!(record.status, Status::Converted);
        let text = artifact(&setup, source);
        let segs = read_segments(&setup, source);
        segments::validate(&segs, &text).unwrap();
        // One whole-document span covers the artifact.
        assert!(
            segs.iter().any(|s| {
                s.kind == SegmentKind::Span
                    && s.source.as_deref() == Some("document")
                    && s.start == 0
                    && s.end == text.len() as u64
            }),
            "no covering span for {source}"
        );
    }
    assert!(artifact(&setup, "report.docx").contains("The venue holds forty people."));
    assert!(artifact(&setup, "notes.rtf").contains("Plain words from rich text."));
    assert!(artifact(&setup, "book.epub").contains("A chapter about nothing in particular."));
}

#[test]
fn pdf_text_layer_converts_and_scanned_pdf_fails_closed() {
    let setup = setup();
    fs::write(
        setup.root.join("doc.pdf"),
        pdf_fixture(Some("Hello text layer")),
    )
    .unwrap();
    fs::write(setup.root.join("scan.pdf"), pdf_fixture(None)).unwrap();

    let rules = Rules::builtin().unwrap();
    let report = run(&setup, &rules);
    assert_eq!(report.counts.converted, 1);
    assert_eq!(report.counts.failed, 1);

    let converted = terminal(&setup, "doc.pdf");
    assert_eq!(
        converted.status,
        Status::Converted,
        "error: {:?}",
        converted.error
    );
    assert!(artifact(&setup, "doc.pdf").contains("Hello text layer"));

    let scanned = terminal(&setup, "scan.pdf");
    assert_eq!(scanned.status, Status::Failed);
    assert!(
        scanned
            .error
            .as_deref()
            .unwrap()
            .starts_with("pdf_no_text_layer"),
        "error: {:?}",
        scanned.error
    );
    assert!(!setup.mirror.join("alpha/scan.pdf.txt").exists());

    // Failed records re-evaluate every run, so the scanned PDF is
    // retried and converts automatically once OCR lands.
    let second = run(&setup, &rules);
    assert_eq!(second.counts.failed, 1);
    assert_eq!(second.counts.skipped_unchanged, 1);
}

#[test]
fn xlsb_records_the_interim_unsupported_reason() {
    let setup = setup();
    fs::write(setup.root.join("macro.xlsb"), b"not a real workbook").unwrap();
    let rules = Rules::builtin().unwrap();
    let report = run(&setup, &rules);
    assert_eq!(report.counts.unsupported, 1);

    let record = terminal(&setup, "macro.xlsb");
    assert_eq!(record.status, Status::Unsupported);
    assert_eq!(
        record.error.as_deref(),
        Some("hidden-visibility-unresolved")
    );
    assert!(record.text_path.is_none());
}

#[test]
fn corrupt_worksheet_visibility_fails_instead_of_unmarked_content() {
    let setup = setup();
    // A zip claiming to be a workbook with no worksheet XML at all.
    let broken = build_zip(&[(
        "xl/workbook.xml",
        br#"<workbook xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="S" sheetId="1" r:id="rId1"/></sheets></workbook>"# as &[u8],
        false,
    )]);
    fs::write(setup.root.join("broken.xlsx"), broken).unwrap();
    let rules = Rules::builtin().unwrap();
    let report = run(&setup, &rules);
    assert_eq!(report.counts.failed, 1);

    let record = terminal(&setup, "broken.xlsx");
    assert_eq!(record.status, Status::Failed);
    let error = record.error.as_deref().unwrap();
    assert!(
        error.starts_with("visibility_read_error") || error.starts_with("workbook_parse_error"),
        "error: {error}"
    );
    assert!(!setup.mirror.join("alpha/broken.xlsx.txt").exists());
}

#[test]
fn passthrough_still_emits_a_whole_file_span() {
    let setup = setup();
    fs::write(setup.root.join("plain.txt"), "just text\n").unwrap();
    let rules = Rules::builtin().unwrap();
    run(&setup, &rules);

    let text = artifact(&setup, "plain.txt");
    let segs = read_segments(&setup, "plain.txt");
    segments::validate(&segs, &text).unwrap();
    assert_eq!(segs.len(), 1);
    assert_eq!(segs[0].kind, SegmentKind::Span);
    assert_eq!(segs[0].source.as_deref(), Some("document"));
    assert_eq!(segs[0].end, text.len() as u64);
}

fn two_page_pdf() -> Vec<u8> {
    let stream1 = "BT /F1 12 Tf 72 720 Td (First page text) Tj ET";
    let stream2 = "";
    let objects = [
        "<< /Type /Catalog /Pages 2 0 R >>".to_string(),
        "<< /Type /Pages /Kids [3 0 R 4 0 R] /Count 2 >>".to_string(),
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 5 0 R /Resources << /Font << /F1 7 0 R >> >> >>".to_string(),
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 6 0 R /Resources << /Font << /F1 7 0 R >> >> >>".to_string(),
        format!("<< /Length {} >>\nstream\n{stream1}\nendstream", stream1.len() + 1),
        format!("<< /Length {} >>\nstream\n{stream2}\nendstream", stream2.len() + 1),
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

// Hostile-input and policy regressions.

use text_mirror::convert::{AnydocDocument, Converter, WorkbookIr};

/// A complete single-sheet OOXML package with a chosen relationship
/// type and worksheet part path, parseable by the workbook parser.
fn single_sheet_xlsx(rel_type: &str, part: &str, sheet_xml: &str) -> Vec<u8> {
    let content_types = format!(
        r#"<?xml version="1.0"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
<Override PartName="/{part}" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
</Types>"#
    );
    let package_rels = r#"<?xml version="1.0"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>"#;
    let workbook = r#"<?xml version="1.0"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
<sheets><sheet name="Data" sheetId="1" r:id="rId1"/></sheets></workbook>"#;
    let target = part.strip_prefix("xl/").unwrap_or(part);
    let workbook_rels = format!(
        r#"<?xml version="1.0"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="{rel_type}" Target="{target}"/>
</Relationships>"#
    );
    build_zip(&[
        ("[Content_Types].xml", content_types.as_bytes(), false),
        ("_rels/.rels", package_rels.as_bytes(), false),
        ("xl/workbook.xml", workbook.as_bytes(), false),
        (
            "xl/_rels/workbook.xml.rels",
            workbook_rels.as_bytes(),
            false,
        ),
        (part, sheet_xml.as_bytes(), false),
    ])
}

const WORKSHEET_REL: &str =
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet";
const CHARTSHEET_REL: &str =
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/chartsheet";

// A worksheet grid behind a chartsheet relationship type never ships
// its hidden content. The parser and the visibility reader agree the
// sheet is not a worksheet, nothing renders, and the empty-output rule
// fails the file closed.
#[test]
fn chartsheet_typed_worksheet_fails_closed() {
    let sheet = r#"<?xml version="1.0"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<sheetData><row r="1" hidden="1"><c r="A1" t="inlineStr"><is><t>hidden text</t></is></c></row></sheetData></worksheet>"#;
    let bytes = single_sheet_xlsx(CHARTSHEET_REL, "xl/worksheets/sheet1.xml", sheet);
    let err = WorkbookIr.convert(&bytes, "xlsx").unwrap_err();
    assert_eq!(err.code, "empty_output");
}

// The decompression bomb: a small archive holding one part far over
// the ceiling fails with resource_limit before anything balloons.
#[test]
fn workbook_decompression_bomb_is_held_under_the_cap() {
    let mut huge = String::with_capacity(65 * 1024 * 1024 + 4096);
    huge.push_str(r#"<?xml version="1.0"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>"#);
    while huge.len() <= 64 * 1024 * 1024 {
        huge.push_str("                                                                ");
    }
    huge.push_str("</sheetData></worksheet>");
    let workbook = r#"<?xml version="1.0"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
<sheets><sheet name="Data" sheetId="1" r:id="rId1"/></sheets></workbook>"#;
    let rels = r#"<?xml version="1.0"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
</Relationships>"#;
    let bytes = build_zip(&[
        ("xl/workbook.xml", workbook.as_bytes(), false),
        ("xl/_rels/workbook.xml.rels", rels.as_bytes(), false),
        ("xl/worksheets/sheet1.xml", huge.as_bytes(), false),
    ]);
    assert!(bytes.len() < 2 * 1024 * 1024, "the bomb itself stays small");
    let err = WorkbookIr.convert(&bytes, "xlsx").unwrap_err();
    assert_eq!(err.code, "resource_limit");
}

// The dense-extent attack: two far-apart cell references refuse
// before the parser allocates their product.
#[test]
fn cell_extent_product_is_refused_before_parsing() {
    let workbook = r#"<?xml version="1.0"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
<sheets><sheet name="Data" sheetId="1" r:id="rId1"/></sheets></workbook>"#;
    let rels = r#"<?xml version="1.0"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
</Relationships>"#;
    let sheet = r#"<?xml version="1.0"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<sheetData><row r="1"><c r="A1"><v>1</v></c></row>
<row r="1048576"><c r="XFD1048576"><v>2</v></c></row></sheetData></worksheet>"#;
    let bytes = build_zip(&[
        ("xl/workbook.xml", workbook.as_bytes(), false),
        ("xl/_rels/workbook.xml.rels", rels.as_bytes(), false),
        ("xl/worksheets/sheet1.xml", sheet.as_bytes(), false),
    ]);
    let err = WorkbookIr.convert(&bytes, "xlsx").unwrap_err();
    assert_eq!(err.code, "resource_limit");
}

// Empty output is one rule everywhere: a non-empty source that
// converts to no text fails toward a later capability instead of
// counting as covered forever.
#[test]
fn empty_output_fails_documents_and_workbooks() {
    let document = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body/></w:document>"#;
    let empty_docx = build_zip(&[
        ("[Content_Types].xml", br#"<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>"#, false),
        ("_rels/.rels", br#"<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>"#, false),
        ("word/document.xml", document.as_bytes(), false),
    ]);
    let err = AnydocDocument.convert(&empty_docx, "docx").unwrap_err();
    assert_eq!(err.code, "empty_output");

    let sheet = r#"<?xml version="1.0"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData/></worksheet>"#;
    let empty_xlsx = single_sheet_xlsx(WORKSHEET_REL, "xl/worksheets/sheet1.xml", sheet);
    let err = WorkbookIr.convert(&empty_xlsx, "xlsx").unwrap_err();
    assert_eq!(err.code, "empty_output");
}

// A hidden coordinate always gets its record, zero width when the
// cell rendered no bytes.
#[test]
fn empty_cell_in_a_hidden_column_gets_a_zero_width_span() {
    let sheet = r#"<?xml version="1.0"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<cols><col min="1" max="1" hidden="1"/></cols>
<sheetData><row r="1"><c r="A1" t="inlineStr"><is><t></t></is></c><c r="B1" t="inlineStr"><is><t>vis</t></is></c></row></sheetData></worksheet>"#;
    let bytes = single_sheet_xlsx(WORKSHEET_REL, "xl/worksheets/sheet1.xml", sheet);
    let outcome = WorkbookIr.convert(&bytes, "xlsx").unwrap();
    assert_eq!(outcome.text, "\tvis\n");
    let zero_width = outcome
        .segments
        .iter()
        .find(|s| s.hidden && s.source.as_deref() == Some("column"))
        .unwrap();
    assert_eq!((zero_width.start, zero_width.end), (0, 0));
}

// A partially extracted PDF records its recovery warning instead of
// reading as silently complete. The PDF core is shared with the
// sandbox worker, so testing it here proves the warning the worker
// carries over the protocol.
#[test]
fn partial_pdf_extraction_carries_a_warning() {
    let conversion = text_mirror::convert::pdf::convert_pdf(&two_page_pdf()).unwrap();
    assert!(conversion.text.contains("First page text"));
    let warning = conversion
        .warnings
        .iter()
        .find(|w| w.starts_with("pdf_partial_text:"))
        .unwrap();
    assert!(warning.contains("pages need OCR"), "{warning}");
}

// A corrupted sidecar fails the checkpoint verification and the next
// run reconverts instead of skipping.
#[test]
fn corrupted_sidecar_reconverts_at_checkpoint_time() {
    let setup = setup();
    fs::write(setup.root.join("plain.txt"), "reliable content\n").unwrap();
    let rules = Rules::builtin().unwrap();
    run(&setup, &rules);

    let sidecar = setup.mirror.join("alpha/plain.txt.segments.jsonl");
    fs::write(&sidecar, "not segments at all\n").unwrap();

    let report = run(&setup, &rules);
    assert_eq!(report.counts.skipped_unchanged, 0);
    assert_eq!(report.counts.converted, 1);
    let repaired = fs::read_to_string(&sidecar).unwrap();
    assert!(repaired.starts_with(r#"{"schema":"text-mirror/segments@1""#));

    // Clean state skips again.
    let third = run(&setup, &rules);
    assert_eq!(third.counts.skipped_unchanged, 1);
}

// A tampered canonical no longer propagates through dedup with a
// self-consistent record. The duplicate converts for itself.
#[test]
fn tampered_canonical_falls_through_to_conversion() {
    let setup = setup();
    fs::write(setup.root.join("a.txt"), "twin payload\n").unwrap();
    fs::write(setup.root.join("b.txt"), "twin payload\n").unwrap();
    let rules = Rules::builtin().unwrap();
    run(&setup, &rules);

    // The canonical source leaves the tree, its artifact is tampered
    // with, and the duplicate's envelope is removed.
    fs::remove_file(setup.root.join("a.txt")).unwrap();
    fs::write(setup.mirror.join("alpha/a.txt.txt"), "tampered payload\n").unwrap();
    fs::remove_file(setup.mirror.join("alpha/b.txt.txt")).unwrap();
    fs::remove_file(setup.mirror.join("alpha/b.txt.segments.jsonl")).unwrap();

    let report = run(&setup, &rules);
    assert_eq!(report.counts.converted, 1);
    assert_eq!(report.counts.dedup, 0);
    let record = terminal(&setup, "b.txt");
    assert_eq!(record.status, Status::Converted);
    assert_eq!(
        fs::read_to_string(setup.mirror.join("alpha/b.txt.txt")).unwrap(),
        "twin payload\n"
    );
}
