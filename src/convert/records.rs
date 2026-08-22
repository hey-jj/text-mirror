//! The parquet, avro, and sqlite readers, run only inside the jail.
//!
//! Structured data formats parse through large native trees with real
//! CVE history, so this module never links into the default build. It
//! compiles only under the `records-worker` feature, and the
//! subprocess worker is the only caller. A panic on hostile bytes
//! crashes the jailed child, which the runner reports as a failed
//! record without touching the pipeline.
//!
//! One rendering serves all three, the workbook posture: inert text,
//! one record per line, tab-separated, a header line of field names
//! first. Tabs, line feeds, and carriage returns inside a value escape
//! to the literal sequences `\t`, `\n`, and `\r`, so a value can never
//! forge a row or column boundary. Nothing is ever evaluated.
//!
//! Ceilings are rules data the parent passes in: at most
//! [`Ceilings::max_records`] records per parquet or avro file and per
//! sqlite table, at most [`Ceilings::max_tables`] tables per database,
//! and at most [`Ceilings::max_output_bytes`] rendered bytes. A source
//! over any ceiling fails closed with reason `record-limit-exceeded`
//! and no artifact, never a truncated dump.

use std::fs::File;
use std::path::Path;

use unicode_normalization::UnicodeNormalization;

use crate::convert::normalize_text;
use crate::segments::{Segment, SegmentKind};

/// The ceilings the worker enforces, supplied by the parent from the
/// rules.
pub struct Ceilings {
    /// Records per parquet or avro file, and per sqlite table.
    pub max_records: u64,
    /// Tables per sqlite database.
    pub max_tables: u64,
    /// Rendered output bytes.
    pub max_output_bytes: u64,
}

/// A successful records conversion.
pub struct RecordsConversion {
    /// The rendered text, UTF-8, NFC, LF line endings.
    pub text: String,
    /// Non-fatal notes about the conversion.
    pub warnings: Vec<String>,
    /// Structure spans over the text.
    pub segments: Vec<Segment>,
}

/// A records conversion failure with a stable reason code.
pub struct RecordsError {
    /// Stable reason, such as `record-limit-exceeded` or `malformed`.
    pub code: &'static str,
    /// Detail for a human reading the manifest.
    pub message: String,
}

impl RecordsError {
    fn new(code: &'static str, message: impl Into<String>) -> RecordsError {
        RecordsError {
            code,
            message: message.into(),
        }
    }
}

/// The magic that opens every sqlite 3 database file.
const SQLITE_MAGIC: &[u8] = b"SQLite format 3\0";

/// Converts one staged records file to text. `input` is a bare name in
/// the worker's jail directory.
pub fn convert_records(
    input: &Path,
    format: &str,
    ceilings: &Ceilings,
) -> Result<RecordsConversion, RecordsError> {
    let conversion = match format {
        "parquet" => convert_parquet(input, ceilings)?,
        "avro" => convert_avro(input, ceilings)?,
        "sqlite" => convert_sqlite(input, ceilings)?,
        other => {
            return Err(RecordsError::new(
                "unclaimed_format",
                format!("the records worker does not handle {other}"),
            ));
        }
    };
    if conversion.text.is_empty() {
        return Err(RecordsError::new(
            "empty_output",
            "the source rendered no records",
        ));
    }
    Ok(conversion)
}

/// A tab-separated line builder that charges the output ceiling as it
/// grows, so a run-away render fails closed instead of buying memory.
struct Sink {
    text: String,
    max_output_bytes: u64,
}

impl Sink {
    fn new(max_output_bytes: u64) -> Sink {
        Sink {
            text: String::new(),
            max_output_bytes,
        }
    }

    /// Appends one row of already-escaped cells and its line feed.
    ///
    /// The projected size of the row, the cell bytes plus the separator
    /// tabs plus the line feed, is charged against the output ceiling
    /// before anything is appended, so a run-away render fails closed
    /// without first growing the buffer.
    fn push_row(&mut self, cells: &[String]) -> Result<(), RecordsError> {
        let separators = cells.len().saturating_sub(1);
        let addition: u64 =
            cells.iter().map(|cell| cell.len() as u64).sum::<u64>() + separators as u64 + 1;
        if self.text.len() as u64 + addition > self.max_output_bytes {
            return Err(RecordsError::new(
                "record-limit-exceeded",
                format!(
                    "rendered output over the {} byte ceiling",
                    self.max_output_bytes
                ),
            ));
        }
        for (index, cell) in cells.iter().enumerate() {
            if index > 0 {
                self.text.push('\t');
            }
            self.text.push_str(cell);
        }
        self.text.push('\n');
        Ok(())
    }
}

/// Normalizes a cell to NFC, then escapes the three structure
/// characters so the value stays on its own line and column.
///
/// NFC runs here, before escaping, so the bytes this returns are final.
/// A sqlite dump takes segment offsets straight from the rendered text,
/// and running NFC afterward would shrink a decomposed value and push
/// every later boundary past the end of the text. NFC never introduces
/// a tab, line feed, or carriage return, so escaping after it stays
/// exact, and the ASCII tabs and line feeds that join cells never
/// compose with neighboring content, so per-cell NFC matches
/// whole-string NFC.
fn escape_cell(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for c in raw.nfc() {
        match c {
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            other => out.push(other),
        }
    }
    out
}

fn records_over(ceiling: u64, unit: &str) -> RecordsError {
    RecordsError::new(
        "record-limit-exceeded",
        format!("more than {ceiling} {unit}"),
    )
}

/// Finishes a single-table conversion: normalize, one document span.
fn finish_document(sink: Sink, warnings: Vec<String>) -> RecordsConversion {
    let text = normalize_text(&sink.text);
    let segments = vec![Segment::span(0, text.len(), "document")];
    RecordsConversion {
        text,
        warnings,
        segments,
    }
}

// --- parquet ---------------------------------------------------------

fn convert_parquet(input: &Path, ceilings: &Ceilings) -> Result<RecordsConversion, RecordsError> {
    use parquet::file::reader::{FileReader, SerializedFileReader};
    use parquet::record::Field;

    let file = File::open(input)
        .map_err(|e| RecordsError::new("io", format!("cannot open the staged input: {e}")))?;
    let reader = SerializedFileReader::new(file)
        .map_err(|e| RecordsError::new("malformed", format!("not a readable parquet file: {e}")))?;

    let header: Vec<String> = reader
        .metadata()
        .file_metadata()
        .schema_descr()
        .root_schema()
        .get_fields()
        .iter()
        .map(|field| escape_cell(field.name()))
        .collect();

    let mut sink = Sink::new(ceilings.max_output_bytes);
    sink.push_row(&header)?;

    let rows = reader
        .get_row_iter(None)
        .map_err(|e| RecordsError::new("malformed", format!("cannot read parquet rows: {e}")))?;
    let mut count: u64 = 0;
    for row in rows {
        let row =
            row.map_err(|e| RecordsError::new("malformed", format!("cannot decode a row: {e}")))?;
        count += 1;
        if count > ceilings.max_records {
            return Err(records_over(ceilings.max_records, "records"));
        }
        let cells: Vec<String> = row
            .get_column_iter()
            .map(|(_, field)| {
                let raw = match field {
                    Field::Null => String::new(),
                    Field::Str(value) => value.clone(),
                    other => other.to_string(),
                };
                escape_cell(&raw)
            })
            .collect();
        sink.push_row(&cells)?;
    }

    Ok(finish_document(sink, Vec::new()))
}

// --- avro ------------------------------------------------------------

fn convert_avro(input: &Path, ceilings: &Ceilings) -> Result<RecordsConversion, RecordsError> {
    use apache_avro::Schema;
    use apache_avro::types::Value;

    let file = File::open(input)
        .map_err(|e| RecordsError::new("io", format!("cannot open the staged input: {e}")))?;
    // Bound the decoder's per-allocation appetite before it reads the
    // header, so one hostile length field cannot direct the default
    // 512 MiB allocation. The worker is one process per file, so this
    // process-global setter is fresh on each spawn.
    let allocation = usize::try_from(ceilings.max_output_bytes).unwrap_or(usize::MAX);
    apache_avro::util::max_allocation_bytes(allocation);
    let reader = apache_avro::Reader::new(file)
        .map_err(|e| RecordsError::new("malformed", format!("not a readable avro file: {e}")))?;

    let header: Vec<String> = match reader.writer_schema() {
        Schema::Record(record) => record
            .fields
            .iter()
            .map(|field| escape_cell(&field.name))
            .collect(),
        _ => vec![escape_cell("value")],
    };

    let mut sink = Sink::new(ceilings.max_output_bytes);
    sink.push_row(&header)?;

    let mut count: u64 = 0;
    for value in reader {
        let value = value
            .map_err(|e| RecordsError::new("malformed", format!("cannot decode a record: {e}")))?;
        count += 1;
        if count > ceilings.max_records {
            return Err(records_over(ceilings.max_records, "records"));
        }
        let cells: Vec<String> = match value {
            Value::Record(fields) => fields
                .iter()
                .map(|(_, value)| escape_cell(&avro_cell(value)))
                .collect(),
            other => vec![escape_cell(&avro_cell(&other))],
        };
        sink.push_row(&cells)?;
    }

    Ok(finish_document(sink, Vec::new()))
}

/// Renders one avro value to inert text. Nested values render in a
/// compact, deterministic form.
fn avro_cell(value: &apache_avro::types::Value) -> String {
    use apache_avro::types::Value;
    match value {
        Value::Null => String::new(),
        Value::Boolean(v) => v.to_string(),
        Value::Int(v) | Value::Date(v) | Value::TimeMillis(v) => v.to_string(),
        Value::Long(v)
        | Value::TimeMicros(v)
        | Value::TimestampMillis(v)
        | Value::TimestampMicros(v)
        | Value::TimestampNanos(v)
        | Value::LocalTimestampMillis(v)
        | Value::LocalTimestampMicros(v)
        | Value::LocalTimestampNanos(v) => v.to_string(),
        Value::Float(v) => v.to_string(),
        Value::Double(v) => v.to_string(),
        Value::String(v) => v.clone(),
        Value::Enum(_, symbol) => symbol.clone(),
        Value::Uuid(v) => v.to_string(),
        Value::Bytes(bytes) | Value::Fixed(_, bytes) => hex(bytes),
        Value::Union(_, inner) => avro_cell(inner),
        Value::Array(items) => {
            let parts: Vec<String> = items.iter().map(avro_cell).collect();
            format!("[{}]", parts.join(", "))
        }
        Value::Map(entries) => {
            let mut parts: Vec<String> = entries
                .iter()
                .map(|(key, value)| format!("{key}: {}", avro_cell(value)))
                .collect();
            parts.sort();
            format!("{{{}}}", parts.join(", "))
        }
        Value::Record(fields) => {
            let parts: Vec<String> = fields
                .iter()
                .map(|(name, value)| format!("{name}: {}", avro_cell(value)))
                .collect();
            format!("{{{}}}", parts.join(", "))
        }
        other => format!("{other:?}"),
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

// --- sqlite ----------------------------------------------------------

fn convert_sqlite(input: &Path, ceilings: &Ceilings) -> Result<RecordsConversion, RecordsError> {
    use rusqlite::config::DbConfig;
    use rusqlite::limits::Limit;
    use rusqlite::{Connection, OpenFlags};

    // The routing detects sqlite by magic, and the reader confirms it
    // before opening, so a file that reached here on a sqlite-shaped
    // extension alone fails plainly instead of on an opaque open error.
    let head = read_head(input)?;
    if !head.starts_with(SQLITE_MAGIC) {
        return Err(RecordsError::new(
            "not_sqlite",
            "the file has no SQLite format 3 header",
        ));
    }

    let name = input
        .to_str()
        .ok_or_else(|| RecordsError::new("io", "the staged input name is not valid UTF-8"))?;
    // Read-only, immutable, single connection, and URI parsing for the
    // immutable flag. Immutable means sqlite never touches a journal or
    // WAL, which is the safe posture for a hostile file.
    let uri = format!("file:{name}?immutable=1&mode=ro");
    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY
        | OpenFlags::SQLITE_OPEN_URI
        | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let conn = Connection::open_with_flags(uri, flags)
        .map_err(|e| RecordsError::new("malformed", format!("cannot open the database: {e}")))?;

    // Defense in depth on the untrusted C parser, immediately after
    // open: the defensive flag, no triggers, no views, and no memory
    // mapping of the file. These sit on top of the read-only immutable
    // query-only posture below.
    let db_config = |config: DbConfig, on: bool| -> Result<(), RecordsError> {
        conn.set_db_config(config, on)
            .map(|_| ())
            .map_err(|e| RecordsError::new("records_read_error", format!("db config: {e}")))
    };
    db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)?;
    db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER, false)?;
    db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_VIEW, false)?;

    // Defensive configuration: refuse writes, do not trust the schema
    // to run functions, check cell sizes, keep temporaries in memory,
    // and never memory-map the file.
    let pragma = |name: &str, value: &dyn rusqlite::ToSql| -> Result<(), RecordsError> {
        conn.pragma_update(None, name, value)
            .map_err(|e| RecordsError::new("records_read_error", format!("pragma {name}: {e}")))
    };
    pragma("query_only", &true)?;
    pragma("trusted_schema", &false)?;
    pragma("cell_size_check", &true)?;
    pragma("temp_store", &"MEMORY")?;
    pragma("mmap_size", &0i64)?;
    let set_limit = |limit: Limit, value: i32| -> Result<(), RecordsError> {
        conn.set_limit(limit, value)
            .map(|_| ())
            .map_err(|e| RecordsError::new("records_read_error", format!("set limit: {e}")))
    };
    set_limit(Limit::SQLITE_LIMIT_ATTACHED, 0)?;
    // Cap the largest value the engine will materialize at the output
    // ceiling, so an oversized cell fails at the reader with a clean
    // error rather than allocating first.
    let length_limit = i32::try_from(ceilings.max_output_bytes).unwrap_or(i32::MAX);
    set_limit(Limit::SQLITE_LIMIT_LENGTH, length_limit)?;

    let tables = table_names(&conn)?;
    if tables.len() as u64 > ceilings.max_tables {
        return Err(records_over(ceilings.max_tables, "tables"));
    }

    let mut sink = Sink::new(ceilings.max_output_bytes);
    let mut segments = Vec::new();
    let mut warnings = Vec::new();
    for table in &tables {
        if !sink.text.is_empty() {
            sink.text.push('\n');
        }
        let table_start = sink.text.len();
        render_table(&conn, table, ceilings, &mut sink, &mut warnings)?;
        segments.push(Segment::boundary(SegmentKind::Sheet, table_start).named(table));
        segments.push(Segment::span(table_start, sink.text.len(), "sheet").named(table));
    }

    // The offsets above index sink.text directly. escape_cell already
    // applied NFC per cell and every separator is an ASCII byte, so
    // sink.text is the final UTF-8 NFC LF artifact and no later
    // normalization can shift a boundary.
    let text = sink.text;
    segments.sort_by_key(|segment| (segment.start, segment.end));
    Ok(RecordsConversion {
        text,
        warnings,
        segments,
    })
}

fn read_head(input: &Path) -> Result<Vec<u8>, RecordsError> {
    use std::io::Read;
    let mut file = File::open(input)
        .map_err(|e| RecordsError::new("io", format!("cannot open the staged input: {e}")))?;
    let mut head = vec![0u8; SQLITE_MAGIC.len()];
    let mut filled = 0;
    while filled < head.len() {
        match file.read(&mut head[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) => {
                return Err(RecordsError::new(
                    "io",
                    format!("cannot read the header: {e}"),
                ));
            }
        }
    }
    head.truncate(filled);
    Ok(head)
}

fn table_names(conn: &rusqlite::Connection) -> Result<Vec<String>, RecordsError> {
    let mut stmt = conn
        .prepare(
            "SELECT name FROM sqlite_master \
             WHERE type = 'table' AND name NOT LIKE 'sqlite\\_%' ESCAPE '\\' \
             ORDER BY name",
        )
        .map_err(|e| RecordsError::new("records_read_error", format!("list tables: {e}")))?;
    let rows = stmt
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|e| RecordsError::new("records_read_error", format!("list tables: {e}")))?;
    let mut names = Vec::new();
    for name in rows {
        names.push(name.map_err(|e| {
            RecordsError::new("records_read_error", format!("read a table name: {e}"))
        })?);
    }
    Ok(names)
}

fn render_table(
    conn: &rusqlite::Connection,
    table: &str,
    ceilings: &Ceilings,
    sink: &mut Sink,
    warnings: &mut Vec<String>,
) -> Result<(), RecordsError> {
    let quoted = quote_ident(table);
    // Order by rowid for a deterministic dump. A WITHOUT ROWID table
    // has no rowid, so fall back to the natural primary-key order of a
    // plain scan, which is deterministic for that table shape.
    let ordered = format!("SELECT * FROM {quoted} ORDER BY _rowid_");
    let plain = format!("SELECT * FROM {quoted}");
    let mut stmt = match conn.prepare(&ordered) {
        Ok(stmt) => stmt,
        Err(_) => conn
            .prepare(&plain)
            .map_err(|e| RecordsError::new("records_read_error", format!("query {table}: {e}")))?,
    };
    let column_count = stmt.column_count();
    let header: Vec<String> = stmt
        .column_names()
        .iter()
        .map(|name| escape_cell(name))
        .collect();
    sink.push_row(&header)?;

    let mut rows = stmt
        .query([])
        .map_err(|e| RecordsError::new("records_read_error", format!("query {table}: {e}")))?;
    let mut count: u64 = 0;
    let mut lossy = false;
    while let Some(row) = rows
        .next()
        .map_err(|e| RecordsError::new("records_read_error", format!("read {table}: {e}")))?
    {
        count += 1;
        if count > ceilings.max_records {
            return Err(records_over(ceilings.max_records, "records"));
        }
        let mut cells = Vec::with_capacity(column_count);
        for index in 0..column_count {
            let value = row.get_ref(index).map_err(|e| {
                RecordsError::new("records_read_error", format!("read a cell: {e}"))
            })?;
            cells.push(escape_cell(&sqlite_cell(value, &mut lossy)));
        }
        sink.push_row(&cells)?;
    }
    // A converted record must not hide a content mutation, so a table
    // whose TEXT held invalid UTF-8 records one warning naming it.
    if lossy {
        warnings.push(format!("invalid-utf8-replaced: {table}"));
    }
    Ok(())
}

/// Renders one sqlite value to inert text. A TEXT value that is not
/// valid UTF-8 renders through lossy replacement and sets `lossy`, so
/// the caller can record the mutation.
fn sqlite_cell(value: rusqlite::types::ValueRef<'_>, lossy: &mut bool) -> String {
    use rusqlite::types::ValueRef;
    match value {
        ValueRef::Null => String::new(),
        ValueRef::Integer(v) => v.to_string(),
        ValueRef::Real(v) => v.to_string(),
        ValueRef::Text(bytes) => match std::str::from_utf8(bytes) {
            Ok(text) => text.to_string(),
            Err(_) => {
                *lossy = true;
                String::from_utf8_lossy(bytes).into_owned()
            }
        },
        ValueRef::Blob(bytes) => hex(bytes),
    }
}

/// Quotes a sqlite identifier, doubling any embedded quote, so a table
/// name can never break out of its `SELECT`.
fn quote_ident(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escaping_keeps_structure_characters_inert() {
        assert_eq!(escape_cell("a\tb\nc\rd"), "a\\tb\\nc\\rd");
        assert_eq!(escape_cell("plain"), "plain");
    }

    #[test]
    fn quoting_doubles_embedded_quotes() {
        assert_eq!(quote_ident("t"), "\"t\"");
        assert_eq!(quote_ident("a\"b"), "\"a\"\"b\"");
    }

    #[test]
    fn the_output_ceiling_fails_closed() {
        let mut sink = Sink::new(8);
        assert!(sink.push_row(&["short".to_string()]).is_ok());
        let over = sink.push_row(&["this pushes well past eight bytes".to_string()]);
        let err = over.unwrap_err();
        assert_eq!(err.code, "record-limit-exceeded");
    }
}
