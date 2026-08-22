//! End-to-end tests for the jailed records worker: parquet, avro, and
//! sqlite rendered to inert tab-separated text behind the subprocess
//! sandbox.
//!
//! Fixtures are built with the pinned reader crates, which the self
//! dev-dependency turns on with the `records-worker` feature, exactly
//! as the fake-engine tests use `test-adapters`. The pipeline routes
//! each format to the worker, so these tests exercise the real jail,
//! the framed protocol, the rendering, the rules-driven ceilings, and
//! container dispatch.

#![cfg(all(unix, feature = "records-worker"))]

use std::fs;
use std::io::{Cursor, Write};
use std::path::PathBuf;

use text_mirror::convert::{Converter, RecordsLimits, RecordsSubprocess};
use text_mirror::manifest::{self, Record, Status};
use text_mirror::pipeline::{self, Rules, RunOptions};
use text_mirror::segments::{self, SegmentKind};
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

// --- fixture builders ------------------------------------------------

fn parquet_fixture(rows: usize) -> Vec<u8> {
    use parquet::data_type::{ByteArray, ByteArrayType, Int64Type};
    use parquet::file::properties::WriterProperties;
    use parquet::file::writer::SerializedFileWriter;
    use parquet::schema::parser::parse_message_type;
    use std::sync::Arc;

    let schema = Arc::new(
        parse_message_type("message row { REQUIRED INT64 id; REQUIRED BYTE_ARRAY name (UTF8); }")
            .unwrap(),
    );
    let props = Arc::new(WriterProperties::builder().build());
    let mut buf = Vec::new();
    {
        let mut writer = SerializedFileWriter::new(&mut buf, schema, props).unwrap();
        let mut group = writer.next_row_group().unwrap();

        let ids: Vec<i64> = (0..rows as i64).collect();
        let mut column = group.next_column().unwrap().unwrap();
        column
            .typed::<Int64Type>()
            .write_batch(&ids, None, None)
            .unwrap();
        column.close().unwrap();

        let names: Vec<ByteArray> = (0..rows)
            .map(|i| ByteArray::from(format!("name{i}").into_bytes()))
            .collect();
        let mut column = group.next_column().unwrap().unwrap();
        column
            .typed::<ByteArrayType>()
            .write_batch(&names, None, None)
            .unwrap();
        column.close().unwrap();

        group.close().unwrap();
        writer.close().unwrap();
    }
    buf
}

fn avro_fixture(rows: usize) -> Vec<u8> {
    use apache_avro::types::Value;
    use apache_avro::{Schema, Writer};

    let schema = Schema::parse_str(
        r#"{"type":"record","name":"row","fields":[
            {"name":"id","type":"long"},
            {"name":"name","type":"string"}]}"#,
    )
    .unwrap();
    let mut writer = Writer::new(&schema, Vec::new()).unwrap();
    for i in 0..rows {
        let record = Value::Record(vec![
            ("id".to_string(), Value::Long(i as i64)),
            ("name".to_string(), Value::String(format!("name{i}"))),
        ]);
        writer.append_value(record).unwrap();
    }
    writer.into_inner().unwrap()
}

/// Builds a sqlite database in a scratch directory and returns just the
/// database file bytes, so no journal or wal sidecar reaches the tree.
fn sqlite_fixture(tables: usize, rows: usize) -> Vec<u8> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("fixture.db");
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        for table in 0..tables {
            conn.execute_batch(&format!("CREATE TABLE t{table}(id INTEGER, label TEXT);"))
                .unwrap();
            for row in 0..rows {
                conn.execute(
                    &format!("INSERT INTO t{table}(id, label) VALUES (?1, ?2)"),
                    rusqlite::params![row as i64, format!("cell{row}")],
                )
                .unwrap();
            }
        }
    }
    fs::read(&path).unwrap()
}

/// Builds a sqlite database of `(table, [text values])` and returns
/// just the database bytes.
fn sqlite_text_fixture(tables: &[(&str, &[&str])]) -> Vec<u8> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("fixture.db");
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        for (name, values) in tables {
            conn.execute_batch(&format!("CREATE TABLE {name}(label TEXT);"))
                .unwrap();
            for value in *values {
                conn.execute(
                    &format!("INSERT INTO {name}(label) VALUES (?1)"),
                    rusqlite::params![value],
                )
                .unwrap();
            }
        }
    }
    fs::read(&path).unwrap()
}

fn stored_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    use zip::CompressionMethod;
    use zip::write::SimpleFileOptions;
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
    for (name, bytes) in entries {
        writer.start_file(*name, options).unwrap();
        writer.write_all(bytes).unwrap();
    }
    writer.finish().unwrap().into_inner()
}

// --- rendering -------------------------------------------------------

// Each format converts a real fixture to the tab-separated rendering
// with a header line first and the records that follow.
#[test]
fn each_format_renders_tab_separated_records_with_a_header() {
    let setup = setup();
    fs::write(setup.root.join("data.parquet"), parquet_fixture(3)).unwrap();
    fs::write(setup.root.join("events.avro"), avro_fixture(3)).unwrap();
    fs::write(setup.root.join("store.sqlite"), sqlite_fixture(1, 2)).unwrap();

    let report = run(&setup);
    assert_eq!(report.counts.converted, 3, "{:?}", report.counts);
    assert_eq!(report.counts.failed, 0);
    assert_eq!(report.counts.unsupported, 0);

    for (name, format) in [
        ("data.parquet", "parquet"),
        ("events.avro", "avro"),
        ("store.sqlite", "sqlite"),
    ] {
        let record = terminal(&setup, name);
        assert_eq!(record.status, Status::Converted, "{name}");
        assert_eq!(record.detected_format, format, "{name}");
        assert_eq!(
            record.converter_id.as_deref(),
            Some("records-worker"),
            "{name}"
        );
    }

    // Parquet: header then three rows, tab-separated.
    let parquet = artifact(&setup, "data.parquet");
    let mut lines = parquet.lines();
    assert_eq!(lines.next(), Some("id\tname"));
    assert_eq!(lines.next(), Some("0\tname0"));
    assert_eq!(parquet.lines().count(), 4);

    // Avro: same header and shape.
    let avro = artifact(&setup, "events.avro");
    assert_eq!(avro.lines().next(), Some("id\tname"));
    assert!(avro.contains("2\tname2"), "{avro}");

    // Sqlite: header for the one table and its two rows.
    let sqlite = artifact(&setup, "store.sqlite");
    assert_eq!(sqlite.lines().next(), Some("id\tlabel"));
    assert!(sqlite.contains("1\tcell1"), "{sqlite}");
}

// A sqlite database renders one dump per table, each opening with a
// sheet boundary carrying the table name, reusing the workbook
// vocabulary with no segments schema change.
#[test]
fn sqlite_tables_carry_a_sheet_boundary_each() {
    let setup = setup();
    fs::write(setup.root.join("multi.sqlite"), sqlite_fixture(3, 1)).unwrap();
    run(&setup);

    let record = terminal(&setup, "multi.sqlite");
    assert_eq!(record.status, Status::Converted);

    let sidecar =
        fs::read_to_string(setup.mirror.join("alpha/multi.sqlite.segments.jsonl")).unwrap();
    let parsed = segments::parse_jsonl(&sidecar).unwrap();
    let boundaries: Vec<&str> = parsed
        .iter()
        .filter(|s| s.kind == SegmentKind::Sheet)
        .filter_map(|s| s.name.as_deref())
        .collect();
    assert_eq!(boundaries, vec!["t0", "t1", "t2"]);
    // The sheet spans and boundaries validate against the text.
    let text = artifact(&setup, "multi.sqlite");
    segments::validate(&parsed, &text).unwrap();
}

// A decomposed-Unicode TEXT cell converts, and its segment offsets
// address the final normalized bytes, so a single-table dump validates.
#[test]
fn a_decomposed_cell_leaves_segments_addressing_the_normalized_text() {
    let setup = setup();
    // "cafe" plus a combining acute accent. NFC composes it to "café",
    // one byte shorter, which used to leave the sheet span past the end.
    let decomposed = "cafe\u{0301}";
    fs::write(
        setup.root.join("one.sqlite"),
        sqlite_text_fixture(&[("t0", &[decomposed])]),
    )
    .unwrap();

    let report = run(&setup);
    assert_eq!(report.counts.converted, 1, "{:?}", report.counts);
    assert_eq!(report.counts.failed, 0);

    let record = terminal(&setup, "one.sqlite");
    assert_eq!(record.status, Status::Converted, "{:?}", record.error);
    let text = artifact(&setup, "one.sqlite");
    assert!(
        text.contains("caf\u{e9}"),
        "expected composed form: {text:?}"
    );
    let parsed = segments::parse_jsonl(
        &fs::read_to_string(setup.mirror.join("alpha/one.sqlite.segments.jsonl")).unwrap(),
    )
    .unwrap();
    segments::validate(&parsed, &text).unwrap();
}

// A decomposed cell in the first of several tables shifts no later
// boundary: every table's sheet span still validates.
#[test]
fn a_decomposed_cell_does_not_shift_later_table_boundaries() {
    let setup = setup();
    let decomposed = "cafe\u{0301}";
    fs::write(
        setup.root.join("multi.sqlite"),
        sqlite_text_fixture(&[("t0", &[decomposed]), ("t1", &["plain"])]),
    )
    .unwrap();

    let report = run(&setup);
    assert_eq!(report.counts.converted, 1, "{:?}", report.counts);

    let record = terminal(&setup, "multi.sqlite");
    assert_eq!(record.status, Status::Converted, "{:?}", record.error);
    let text = artifact(&setup, "multi.sqlite");
    let parsed = segments::parse_jsonl(
        &fs::read_to_string(setup.mirror.join("alpha/multi.sqlite.segments.jsonl")).unwrap(),
    )
    .unwrap();
    segments::validate(&parsed, &text).unwrap();
    // Both table boundaries survive with their names.
    let boundaries: Vec<&str> = parsed
        .iter()
        .filter(|s| s.kind == SegmentKind::Sheet)
        .filter_map(|s| s.name.as_deref())
        .collect();
    assert_eq!(boundaries, vec!["t0", "t1"]);
}

// A sqlite TEXT value holding invalid UTF-8 still converts, and the
// record carries a warning naming the table where replacement occurred.
#[test]
fn invalid_utf8_text_converts_with_a_recorded_warning() {
    let setup = setup();
    // Build a database with a raw invalid-UTF-8 byte in a TEXT cell.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("fixture.db");
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch("CREATE TABLE t0(label TEXT);").unwrap();
        // 0xFF is never valid UTF-8. Insert it as a TEXT value.
        conn.execute(
            "INSERT INTO t0(label) VALUES (CAST(? AS TEXT))",
            rusqlite::params![[0x61u8, 0xFF, 0x62u8].as_slice()],
        )
        .unwrap();
    }
    fs::write(setup.root.join("lossy.sqlite"), fs::read(&path).unwrap()).unwrap();

    run(&setup);
    let record = terminal(&setup, "lossy.sqlite");
    assert_eq!(record.status, Status::Converted, "{:?}", record.error);
    assert!(
        record
            .warnings
            .iter()
            .any(|w| w == "invalid-utf8-replaced: t0"),
        "warnings: {:?}",
        record.warnings
    );
}

// --- ceilings --------------------------------------------------------

fn adapter(limits: RecordsLimits) -> RecordsSubprocess {
    RecordsSubprocess::new(limits)
}

// Each ceiling fails closed with the precise record-limit-exceeded
// reason and no artifact, never a truncated dump.
#[test]
fn the_record_ceiling_fails_closed() {
    let over = adapter(RecordsLimits {
        max_records: 2,
        ..RecordsLimits::default()
    })
    .convert(&parquet_fixture(5), "parquet")
    .unwrap_err();
    assert_eq!(over.code, "record-limit-exceeded", "{over}");
}

#[test]
fn the_table_ceiling_fails_closed() {
    let over = adapter(RecordsLimits {
        max_tables: 2,
        ..RecordsLimits::default()
    })
    .convert(&sqlite_fixture(4, 1), "sqlite")
    .unwrap_err();
    assert_eq!(over.code, "record-limit-exceeded", "{over}");
}

#[test]
fn the_output_ceiling_fails_closed() {
    // A tiny output ceiling overflows on the first rendered row. Parquet
    // exercises the shared Sink ceiling without the avro decoder's own
    // allocation cap, which is set from the same ceiling, intervening.
    let over = adapter(RecordsLimits {
        max_output_bytes: 4,
        ..RecordsLimits::default()
    })
    .convert(&parquet_fixture(100), "parquet")
    .unwrap_err();
    assert_eq!(over.code, "record-limit-exceeded", "{over}");
}

// --- hostile input ---------------------------------------------------

// A hostile file per format fails closed as one record and the run
// continues: a sibling good file in the same division still converts,
// proving the jailed child never takes the pipeline down.
#[test]
fn hostile_files_fail_closed_without_aborting_the_run() {
    let setup = setup();
    // Real header bytes, garbage bodies, so detection still routes each
    // to the worker where the reader refuses them.
    fs::write(
        setup.root.join("bad.parquet"),
        b"PAR1\xff\xffbroken\x00PAR1",
    )
    .unwrap();
    fs::write(
        setup.root.join("bad.avro"),
        b"Obj\x01\x00\x00hostile avro body",
    )
    .unwrap();
    let mut hostile_sqlite = b"SQLite format 3\x00".to_vec();
    hostile_sqlite.extend_from_slice(&[0xffu8; 200]);
    fs::write(setup.root.join("bad.sqlite"), &hostile_sqlite).unwrap();
    // A sound sibling that must still convert.
    fs::write(setup.root.join("good.parquet"), parquet_fixture(2)).unwrap();

    let report = run(&setup);
    assert_eq!(report.counts.converted, 1, "{:?}", report.counts);
    assert_eq!(report.counts.failed, 3, "{:?}", report.counts);

    for name in ["bad.parquet", "bad.avro", "bad.sqlite"] {
        let record = terminal(&setup, name);
        assert_eq!(record.status, Status::Failed, "{name}");
        assert!(record.error.is_some(), "{name}");
        assert!(record.text_path.is_none(), "{name}");
        assert!(
            !setup.mirror.join(format!("alpha/{name}.txt")).exists(),
            "{name}"
        );
    }
    assert_eq!(terminal(&setup, "good.parquet").status, Status::Converted);
}

// --- container dispatch ----------------------------------------------

// A parquet member inside a zip routes through container expansion to
// the records worker, confirming the container dispatch reaches it.
#[test]
fn a_parquet_member_of_a_zip_routes_to_the_worker() {
    let setup = setup();
    let zip = stored_zip(&[("inner/table.parquet", &parquet_fixture(2))]);
    fs::write(setup.root.join("bundle.zip"), zip).unwrap();

    run(&setup);

    let member = terminal(&setup, "bundle.zip.d/inner/table.parquet");
    assert_eq!(member.status, Status::Converted, "{:?}", member.error);
    assert_eq!(member.detected_format, "parquet");
    assert_eq!(member.converter_id.as_deref(), Some("records-worker"));
    assert_eq!(member.parent_source.as_deref(), Some("bundle.zip"));
    let text = fs::read_to_string(
        setup
            .mirror
            .join("alpha/bundle.zip.d/inner/table.parquet.txt"),
    )
    .unwrap();
    assert_eq!(text.lines().next(), Some("id\tname"));
}

// --- detection -------------------------------------------------------

// A real sqlite routes on its magic even under a bare .db name, while a
// non-sqlite .db is not a database and never reaches the worker.
#[test]
fn sqlite_routes_by_magic_not_by_extension() {
    let setup = setup();
    fs::write(setup.root.join("real.db"), sqlite_fixture(1, 1)).unwrap();
    fs::write(
        setup.root.join("fake.db"),
        b"just some bytes, not a database\n",
    )
    .unwrap();

    run(&setup);

    let real = terminal(&setup, "real.db");
    assert_eq!(real.detected_format, "sqlite");
    assert_eq!(real.status, Status::Converted);
    assert_eq!(real.converter_id.as_deref(), Some("records-worker"));

    // The .db extension alone is not in the table, so a file without
    // the magic stays unknown and lands on the no-converter floor,
    // never routed to the records worker.
    let fake = terminal(&setup, "fake.db");
    assert_eq!(fake.detected_format, "unknown");
    assert_eq!(fake.status, Status::Unsupported);
    assert_eq!(fake.error.as_deref(), Some("no-converter"));
}
