//! Row and column visibility, read beside calamine.
//!
//! calamine exposes sheet visibility but discards row and column
//! visibility while parsing, so this layer reads it from the source
//! itself: worksheet XML inside the OOXML archive, `content.xml`
//! inside the ODF archive, and `ROW` and `COLINFO` records in the
//! BIFF stream of a legacy workbook. Hidden means the hidden flag is
//! set or the explicit custom height or width is zero.
//!
//! The readers fail closed. Element and attribute matching is
//! namespace aware, so a foreign-namespace attribute can neither hide
//! nor reveal anything. Worksheet parts are selected by relationship
//! type, archive parts and streams read under the module ceilings,
//! repeats and indexes use checked arithmetic against the sheet
//! extent ceilings, and the reader reports exactly which sheets it
//! resolved. The workbook converter refuses to render a sheet this
//! layer did not resolve.

use std::collections::HashMap;
use std::io::{Cursor, Read};

use quick_xml::NsReader;
use quick_xml::XmlVersion;
use quick_xml::encoding::Decoder;
use quick_xml::events::{BytesStart, Event};
use quick_xml::name::ResolveResult;

use super::{MAX_PART_BYTES, MAX_SHEET_CELLS, MAX_SHEET_COLUMNS, MAX_SHEET_ROWS};

const SPREADSHEET_NAMESPACES: [&[u8]; 2] = [
    b"http://schemas.openxmlformats.org/spreadsheetml/2006/main",
    b"http://purl.oclc.org/ooxml/spreadsheetml/main",
];

const PACKAGE_RELS_NAMESPACE: &[u8] =
    b"http://schemas.openxmlformats.org/package/2006/relationships";

const DOC_RELS_NAMESPACES: [&[u8]; 2] = [
    b"http://schemas.openxmlformats.org/officeDocument/2006/relationships",
    b"http://purl.oclc.org/ooxml/officeDocument/relationships",
];

const WORKSHEET_REL_TYPES: [&str; 2] = [
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet",
    "http://purl.oclc.org/ooxml/officeDocument/relationships/worksheet",
];

const TABLE_NAMESPACE: &[u8] = b"urn:oasis:names:tc:opendocument:xmlns:table:1.0";

const OFFICE_NAMESPACE: &[u8] = b"urn:oasis:names:tc:opendocument:xmlns:office:1.0";

/// Why visibility could not be resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VisibilityError {
    /// A module ceiling was exceeded. Maps to reason `resource_limit`.
    Limit(String),
    /// The file's visibility data is missing, damaged, or beyond this
    /// reader. Maps to reason `visibility_read_error`.
    Unresolved(String),
}

impl std::fmt::Display for VisibilityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VisibilityError::Limit(detail) => write!(f, "{detail}"),
            VisibilityError::Unresolved(detail) => write!(f, "{detail}"),
        }
    }
}

type VisResult<T> = std::result::Result<T, VisibilityError>;

fn unresolved(detail: impl Into<String>) -> VisibilityError {
    VisibilityError::Unresolved(detail.into())
}

fn limit(detail: impl Into<String>) -> VisibilityError {
    VisibilityError::Limit(detail.into())
}

/// An inclusive range of 0-based row or column indexes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IndexRange {
    /// First index covered.
    pub first: u32,
    /// Last index covered, inclusive.
    pub last: u32,
}

/// Hidden rows and columns of one sheet, as index ranges.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SheetVisibility {
    hidden_rows: Vec<IndexRange>,
    hidden_columns: Vec<IndexRange>,
}

impl SheetVisibility {
    /// True when the 0-based row is hidden.
    pub fn row_hidden(&self, row: u32) -> bool {
        self.hidden_rows
            .iter()
            .any(|r| r.first <= row && row <= r.last)
    }

    /// True when the 0-based column is hidden.
    pub fn column_hidden(&self, column: u32) -> bool {
        self.hidden_columns
            .iter()
            .any(|r| r.first <= column && column <= r.last)
    }
}

/// Hidden rows and columns per resolved sheet name.
#[derive(Debug, Clone, Default)]
pub struct WorkbookVisibility {
    by_sheet: HashMap<String, SheetVisibility>,
}

impl WorkbookVisibility {
    /// The visibility data for a sheet this reader resolved. `None`
    /// for any sheet the reader did not resolve as a worksheet, and
    /// the caller must refuse to render such a sheet.
    pub fn sheet(&self, name: &str) -> Option<SheetVisibility> {
        self.by_sheet.get(name).cloned()
    }
}

/// Reads row and column visibility for a workbook format.
///
/// `xlsx` and `xlsm` read worksheet XML, `ods` reads `content.xml`,
/// and `xls` walks the BIFF stream. Any other format id is a caller
/// error, because the registry routes formats without a reader to the
/// interim unsupported rule before conversion starts.
pub fn read_visibility(bytes: &[u8], format_id: &str) -> VisResult<WorkbookVisibility> {
    match format_id {
        "xlsx" | "xlsm" => read_ooxml(bytes),
        "ods" => read_ods(bytes),
        "xls" => read_biff(bytes),
        other => Err(unresolved(format!(
            "no visibility reader for format {other}"
        ))),
    }
}

fn zip_entry(archive: &mut zip::ZipArchive<Cursor<&[u8]>>, name: &str) -> VisResult<String> {
    let entry = archive
        .by_name(name)
        .map_err(|e| unresolved(format!("archive part {name} unreadable: {e}")))?;
    let mut text = String::new();
    entry
        .take(MAX_PART_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(|e| unresolved(format!("archive part {name} unreadable: {e}")))?;
    if text.len() as u64 > MAX_PART_BYTES {
        return Err(limit(format!(
            "archive part {name} exceeds the {MAX_PART_BYTES} byte ceiling"
        )));
    }
    Ok(text)
}

/// How an attribute must be namespaced to count.
enum AttrSpace<'a> {
    /// No prefix. Unprefixed attributes belong to no namespace.
    None,
    /// Bound to one of these namespaces.
    OneOf(&'a [&'a [u8]]),
}

fn attribute(
    reader: &NsReader<&[u8]>,
    start: &BytesStart,
    space: AttrSpace,
    local: &[u8],
    decoder: Decoder,
) -> VisResult<Option<String>> {
    for attr in start.attributes() {
        let attr = attr.map_err(|e| unresolved(format!("bad attribute: {e}")))?;
        let (resolution, name) = reader.resolver().resolve_attribute(attr.key);
        if name.as_ref() != local {
            continue;
        }
        let matches = match &space {
            AttrSpace::None => matches!(resolution, ResolveResult::Unbound),
            AttrSpace::OneOf(namespaces) => match resolution {
                ResolveResult::Bound(bound) => namespaces.iter().any(|ns| *ns == bound.as_ref()),
                _ => false,
            },
        };
        if !matches {
            continue;
        }
        let value = attr
            .decoded_and_normalized_value(XmlVersion::Implicit1_0, decoder)
            .map_err(|e| unresolved(format!("bad attribute value: {e}")))?;
        return Ok(Some(value.into_owned()));
    }
    Ok(None)
}

fn element_in(
    reader: &NsReader<&[u8]>,
    start: &BytesStart,
    namespaces: &[&[u8]],
    local: &[u8],
) -> bool {
    let (resolution, name) = reader.resolver().resolve_element(start.name());
    if name.as_ref() != local {
        return false;
    }
    match resolution {
        ResolveResult::Bound(bound) => namespaces.iter().any(|ns| *ns == bound.as_ref()),
        _ => false,
    }
}

fn is_truthy(value: &str) -> bool {
    value == "1" || value.eq_ignore_ascii_case("true")
}

fn parse_index(value: &str, what: &str) -> VisResult<u32> {
    value
        .parse::<u32>()
        .map_err(|_| unresolved(format!("bad {what} value {value:?}")))
}

/// A size attribute is zero only when it parses to a finite zero.
/// Anything unparseable or non-finite is a resolution error.
fn parse_zero_size(value: &str, what: &str) -> VisResult<bool> {
    let parsed = value
        .parse::<f64>()
        .map_err(|_| unresolved(format!("bad {what} value {value:?}")))?;
    if !parsed.is_finite() {
        return Err(unresolved(format!("bad {what} value {value:?}")));
    }
    Ok(parsed == 0.0)
}

/// Splits an A1-style reference into 0-based (row, column).
fn parse_cell_reference(reference: &str) -> VisResult<(u32, u32)> {
    let letters: String = reference
        .chars()
        .take_while(char::is_ascii_alphabetic)
        .collect();
    let digits = &reference[letters.len()..];
    if letters.is_empty() || digits.is_empty() || !digits.chars().all(|c| c.is_ascii_digit()) {
        return Err(unresolved(format!("bad cell reference {reference:?}")));
    }
    let mut column = 0u64;
    for c in letters.chars() {
        column = column * 26 + (c.to_ascii_uppercase() as u64 - 'A' as u64 + 1);
        if column > u64::from(MAX_SHEET_COLUMNS) {
            return Err(limit(format!(
                "cell reference {reference:?} past the column ceiling"
            )));
        }
    }
    let row = digits
        .parse::<u32>()
        .map_err(|_| unresolved(format!("bad cell reference {reference:?}")))?;
    if row == 0 || row > MAX_SHEET_ROWS {
        return Err(limit(format!(
            "cell reference {reference:?} past the row ceiling"
        )));
    }
    Ok((row - 1, column as u32 - 1))
}

fn check_extent(rows: u32, columns: u32, sheet: &str) -> VisResult<()> {
    if u64::from(rows) * u64::from(columns) > MAX_SHEET_CELLS {
        return Err(limit(format!(
            "sheet {sheet:?} extent {rows} rows by {columns} columns exceeds the {MAX_SHEET_CELLS} cell ceiling"
        )));
    }
    Ok(())
}

/// Resolves an OPC part target against the `xl/` base, handling
/// absolute targets and parent or current segments.
fn normalize_part_target(target: &str) -> VisResult<String> {
    let (mut stack, path): (Vec<&str>, &str) = match target.strip_prefix('/') {
        Some(absolute) => (Vec::new(), absolute),
        None => (vec!["xl"], target),
    };
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                if stack.pop().is_none() {
                    return Err(unresolved(format!(
                        "part target {target:?} escapes the package"
                    )));
                }
            }
            other => stack.push(other),
        }
    }
    if stack.is_empty() {
        return Err(unresolved(format!("empty part target {target:?}")));
    }
    Ok(stack.join("/"))
}

// OOXML: xl/workbook.xml names the sheets, the workbook rels map each
// sheet to its part by relationship type, and worksheet parts carry
// row and col visibility attributes.
fn read_ooxml(bytes: &[u8]) -> VisResult<WorkbookVisibility> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes))
        .map_err(|e| unresolved(format!("not a zip archive: {e}")))?;

    let workbook = zip_entry(&mut archive, "xl/workbook.xml")?;
    let mut sheets: Vec<(String, String)> = Vec::new();
    let mut reader = NsReader::from_str(&workbook);
    let decoder = reader.decoder();
    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                if element_in(&reader, &e, &SPREADSHEET_NAMESPACES, b"sheet") {
                    let name = attribute(&reader, &e, AttrSpace::None, b"name", decoder)?
                        .ok_or_else(|| unresolved("sheet element without a name"))?;
                    let rid = attribute(
                        &reader,
                        &e,
                        AttrSpace::OneOf(&DOC_RELS_NAMESPACES),
                        b"id",
                        decoder,
                    )?
                    .ok_or_else(|| {
                        unresolved(format!("sheet {name:?} without a relationship id"))
                    })?;
                    sheets.push((name, rid));
                }
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(e) => return Err(unresolved(format!("malformed xl/workbook.xml: {e}"))),
        }
    }

    let rels = zip_entry(&mut archive, "xl/_rels/workbook.xml.rels")?;
    let mut targets: HashMap<String, (String, String)> = HashMap::new();
    let mut reader = NsReader::from_str(&rels);
    let decoder = reader.decoder();
    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                if element_in(&reader, &e, &[PACKAGE_RELS_NAMESPACE], b"Relationship") {
                    let id = attribute(&reader, &e, AttrSpace::None, b"Id", decoder)?;
                    let target = attribute(&reader, &e, AttrSpace::None, b"Target", decoder)?;
                    let rel_type = attribute(&reader, &e, AttrSpace::None, b"Type", decoder)?;
                    if let (Some(id), Some(target), Some(rel_type)) = (id, target, rel_type) {
                        targets.insert(id, (target, rel_type));
                    }
                }
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(e) => return Err(unresolved(format!("malformed workbook rels: {e}"))),
        }
    }

    let mut by_sheet = HashMap::new();
    for (name, rid) in sheets {
        let (target, rel_type) = targets
            .get(&rid)
            .ok_or_else(|| unresolved(format!("sheet {name:?} has no relationship target")))?;
        if !WORKSHEET_REL_TYPES.contains(&rel_type.as_str()) {
            // Chart, dialog, and macro sheet parts carry no cell grid
            // this reader can resolve. They stay unresolved, and the
            // converter refuses to render them if the parser disagrees.
            continue;
        }
        let part = normalize_part_target(target)?;
        let xml = zip_entry(&mut archive, &part)?;
        by_sheet.insert(name.clone(), read_ooxml_worksheet(&xml, &part, &name)?);
    }
    Ok(WorkbookVisibility { by_sheet })
}

fn read_ooxml_worksheet(xml: &str, part: &str, sheet: &str) -> VisResult<SheetVisibility> {
    let mut visibility = SheetVisibility::default();
    let mut max_row = 0u32;
    let mut max_column = 0u32;
    let mut reader = NsReader::from_str(xml);
    let decoder = reader.decoder();
    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                if element_in(&reader, &e, &SPREADSHEET_NAMESPACES, b"col") {
                    let first = attribute(&reader, &e, AttrSpace::None, b"min", decoder)?
                        .ok_or_else(|| unresolved(format!("{part}: col without min")))?;
                    let last = attribute(&reader, &e, AttrSpace::None, b"max", decoder)?
                        .ok_or_else(|| unresolved(format!("{part}: col without max")))?;
                    let hidden = attribute(&reader, &e, AttrSpace::None, b"hidden", decoder)?
                        .is_some_and(|v| is_truthy(&v));
                    let zero_width = attribute(&reader, &e, AttrSpace::None, b"width", decoder)?
                        .map(|w| parse_zero_size(&w, "col width"))
                        .transpose()?
                        .unwrap_or(false);
                    let first = parse_index(&first, "col min")?;
                    let last = parse_index(&last, "col max")?;
                    if first == 0 || last < first || last > MAX_SHEET_COLUMNS {
                        return Err(unresolved(format!("{part}: bad col range {first}..{last}")));
                    }
                    if hidden || zero_width {
                        visibility.hidden_columns.push(IndexRange {
                            first: first - 1,
                            last: last - 1,
                        });
                    }
                } else if element_in(&reader, &e, &SPREADSHEET_NAMESPACES, b"row") {
                    let index = attribute(&reader, &e, AttrSpace::None, b"r", decoder)?;
                    let hidden = attribute(&reader, &e, AttrSpace::None, b"hidden", decoder)?
                        .is_some_and(|v| is_truthy(&v));
                    let zero_height = attribute(&reader, &e, AttrSpace::None, b"ht", decoder)?
                        .map(|h| parse_zero_size(&h, "row height"))
                        .transpose()?
                        .unwrap_or(false);
                    if let Some(index) = index {
                        let index = parse_index(&index, "row index")?;
                        if index == 0 {
                            return Err(unresolved(format!("{part}: row index 0")));
                        }
                        if index > MAX_SHEET_ROWS {
                            return Err(limit(format!("{part}: row {index} past the row ceiling")));
                        }
                        max_row = max_row.max(index);
                        if hidden || zero_height {
                            visibility.hidden_rows.push(IndexRange {
                                first: index - 1,
                                last: index - 1,
                            });
                        }
                    } else if hidden || zero_height {
                        return Err(unresolved(format!("{part}: hidden row without an index")));
                    }
                } else if element_in(&reader, &e, &SPREADSHEET_NAMESPACES, b"c")
                    && let Some(reference) = attribute(&reader, &e, AttrSpace::None, b"r", decoder)?
                {
                    let (row, column) = parse_cell_reference(&reference)?;
                    max_row = max_row.max(row + 1);
                    max_column = max_column.max(column + 1);
                }
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(e) => return Err(unresolved(format!("malformed {part}: {e}"))),
        }
    }
    check_extent(max_row, max_column, sheet)?;
    Ok(visibility)
}

// ODF: content.xml lists every table with its columns and rows in
// order. Visibility is the table:visibility attribute with values
// collapse and filter, repeats widen the covered range with checked
// arithmetic, and only top-level tables count as sheets.
fn read_ods(bytes: &[u8]) -> VisResult<WorkbookVisibility> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes))
        .map_err(|e| unresolved(format!("not a zip archive: {e}")))?;
    let content = zip_entry(&mut archive, "content.xml")?;

    struct OpenTable {
        name: String,
        visibility: SheetVisibility,
        next_row: u32,
        next_column: u32,
        // Extent of cells that carry content, the bounding box the
        // workbook parser densifies. Declared empty fillers to the
        // sheet maximum are normal and stay outside this box.
        max_content_row: u32,
        max_content_column: u32,
        row_cell_cursor: u32,
    }

    let mut by_sheet = HashMap::new();
    let mut table_depth = 0u32;
    let mut current: Option<OpenTable> = None;

    let mut reader = NsReader::from_str(&content);
    let decoder = reader.decoder();

    fn repeat_of(
        reader: &NsReader<&[u8]>,
        e: &BytesStart,
        local: &[u8],
        decoder: Decoder,
    ) -> VisResult<u32> {
        let repeat = attribute(
            reader,
            e,
            AttrSpace::OneOf(&[TABLE_NAMESPACE]),
            local,
            decoder,
        )?
        .map(|v| parse_index(&v, "repeat"))
        .transpose()?
        .unwrap_or(1);
        if repeat == 0 {
            return Err(unresolved("zero repeat count"));
        }
        Ok(repeat)
    }

    fn advance(cursor: u32, repeat: u32, ceiling: u32, what: &str) -> VisResult<u32> {
        let next = cursor
            .checked_add(repeat)
            .ok_or_else(|| limit(format!("{what} repeat overflows")))?;
        if next > ceiling {
            return Err(limit(format!(
                "{what} extent {next} exceeds the {ceiling} ceiling"
            )));
        }
        Ok(next)
    }

    loop {
        let event = reader
            .read_event()
            .map_err(|e| unresolved(format!("malformed content.xml: {e}")))?;
        let (e, empty) = match &event {
            Event::Start(e) => (e, false),
            Event::Empty(e) => (e, true),
            Event::End(e) => {
                let (resolution, name) = reader.resolver().resolve_element(e.name());
                let is_table = name.as_ref() == b"table"
                    && matches!(&resolution, ResolveResult::Bound(b) if b.as_ref() == TABLE_NAMESPACE);
                if is_table && table_depth > 0 {
                    table_depth -= 1;
                    if table_depth == 0
                        && let Some(open) = current.take()
                    {
                        check_extent(open.max_content_row, open.max_content_column, &open.name)?;
                        by_sheet.insert(open.name, open.visibility);
                    }
                }
                continue;
            }
            Event::Eof => break,
            _ => continue,
        };

        if element_in(&reader, e, &[TABLE_NAMESPACE], b"table") {
            if table_depth == 0 {
                let name = attribute(
                    &reader,
                    e,
                    AttrSpace::OneOf(&[TABLE_NAMESPACE]),
                    b"name",
                    decoder,
                )?
                .ok_or_else(|| unresolved("table without a name"))?;
                let open = OpenTable {
                    name,
                    visibility: SheetVisibility::default(),
                    next_row: 0,
                    next_column: 0,
                    max_content_row: 0,
                    max_content_column: 0,
                    row_cell_cursor: 0,
                };
                if empty {
                    by_sheet.insert(open.name, open.visibility);
                } else {
                    current = Some(open);
                    table_depth = 1;
                }
            } else if !empty {
                table_depth += 1;
            }
            continue;
        }
        if table_depth != 1 {
            continue;
        }
        let Some(open) = current.as_mut() else {
            continue;
        };

        if element_in(&reader, e, &[TABLE_NAMESPACE], b"table-column") {
            let repeat = repeat_of(&reader, e, b"number-columns-repeated", decoder)?;
            let hidden = attribute(
                &reader,
                e,
                AttrSpace::OneOf(&[TABLE_NAMESPACE]),
                b"visibility",
                decoder,
            )?
            .is_some_and(|v| v == "collapse" || v == "filter");
            let next = advance(open.next_column, repeat, MAX_SHEET_COLUMNS, "column")?;
            if hidden {
                open.visibility.hidden_columns.push(IndexRange {
                    first: open.next_column,
                    last: next - 1,
                });
            }
            open.next_column = next;
        } else if element_in(&reader, e, &[TABLE_NAMESPACE], b"table-row") {
            let repeat = repeat_of(&reader, e, b"number-rows-repeated", decoder)?;
            let hidden = attribute(
                &reader,
                e,
                AttrSpace::OneOf(&[TABLE_NAMESPACE]),
                b"visibility",
                decoder,
            )?
            .is_some_and(|v| v == "collapse" || v == "filter");
            let next = advance(open.next_row, repeat, MAX_SHEET_ROWS, "row")?;
            if hidden {
                open.visibility.hidden_rows.push(IndexRange {
                    first: open.next_row,
                    last: next - 1,
                });
            }
            open.next_row = next;
            open.row_cell_cursor = 0;
        } else if element_in(&reader, e, &[TABLE_NAMESPACE], b"table-cell")
            || element_in(&reader, e, &[TABLE_NAMESPACE], b"covered-table-cell")
        {
            let repeat = repeat_of(&reader, e, b"number-columns-repeated", decoder)?;
            let next = advance(open.row_cell_cursor, repeat, MAX_SHEET_COLUMNS, "cell")?;
            let has_content = attribute(
                &reader,
                e,
                AttrSpace::OneOf(&[OFFICE_NAMESPACE]),
                b"value-type",
                decoder,
            )?
            .is_some();
            open.row_cell_cursor = next;
            if has_content {
                open.max_content_column = open.max_content_column.max(next);
                open.max_content_row = open.max_content_row.max(open.next_row);
            }
        }
    }
    if table_depth != 0 {
        return Err(unresolved("content.xml ends inside a table"));
    }
    Ok(WorkbookVisibility { by_sheet })
}

// BIFF record opcodes the walk cares about.
const BIFF_BOF: u16 = 0x0809;
const BIFF_EOF: u16 = 0x000A;
const BIFF_BOUNDSHEET: u16 = 0x0085;
const BIFF_FILEPASS: u16 = 0x002F;
const BIFF_CODEPAGE: u16 = 0x0042;
const BIFF_ROW: u16 = 0x0208;
const BIFF_COLINFO: u16 = 0x007D;

const BOF_WORKSHEET: u16 = 0x0010;

struct BiffRecord<'a> {
    opcode: u16,
    payload: &'a [u8],
}

/// Walks records from `from` until the substream's own EOF record.
/// Truncated records, a missing EOF, and trailing garbage after a
/// header fragment are errors, never a silent stop.
struct BiffWalk<'a> {
    stream: &'a [u8],
    offset: usize,
    done: bool,
}

impl<'a> BiffWalk<'a> {
    fn new(stream: &'a [u8], from: usize) -> Self {
        BiffWalk {
            stream,
            offset: from,
            done: false,
        }
    }
}

impl<'a> Iterator for BiffWalk<'a> {
    type Item = VisResult<BiffRecord<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        if self.offset + 4 > self.stream.len() {
            self.done = true;
            return Some(Err(unresolved(format!(
                "BIFF stream ends without EOF at offset {}",
                self.offset
            ))));
        }
        let opcode = u16::from_le_bytes([self.stream[self.offset], self.stream[self.offset + 1]]);
        let len = u16::from_le_bytes([self.stream[self.offset + 2], self.stream[self.offset + 3]])
            as usize;
        let start = self.offset + 4;
        if start + len > self.stream.len() {
            self.done = true;
            return Some(Err(unresolved(format!(
                "truncated BIFF record 0x{opcode:04X} at {}",
                self.offset
            ))));
        }
        self.offset = start + len;
        if opcode == BIFF_EOF {
            self.done = true;
        }
        Some(Ok(BiffRecord {
            opcode,
            payload: &self.stream[start..start + len],
        }))
    }
}

fn field_u16(payload: &[u8], at: usize, what: &str) -> VisResult<u16> {
    if at + 2 > payload.len() {
        return Err(unresolved(format!("short BIFF {what} record")));
    }
    Ok(u16::from_le_bytes([payload[at], payload[at + 1]]))
}

#[derive(Clone, Copy, PartialEq)]
enum BiffVersion {
    Biff8,
    Biff5,
}

/// Decodes a narrow byte with the workbook codepage the way calamine
/// does: ASCII directly, cp1252 through its table, and anything else
/// is beyond this reader and fails closed.
fn decode_narrow(bytes: &[u8], codepage: u16) -> VisResult<String> {
    let mut out = String::with_capacity(bytes.len());
    for byte in bytes {
        if byte.is_ascii() {
            out.push(*byte as char);
        } else if codepage == 1252 {
            out.push(cp1252_char(*byte));
        } else {
            return Err(unresolved(format!(
                "sheet name in unsupported codepage {codepage}"
            )));
        }
    }
    Ok(out)
}

fn cp1252_char(byte: u8) -> char {
    // The 0x80..0xA0 block is where cp1252 differs from Latin-1.
    const HIGH: [char; 32] = [
        '\u{20AC}', '\u{81}', '\u{201A}', '\u{192}', '\u{201E}', '\u{2026}', '\u{2020}',
        '\u{2021}', '\u{2C6}', '\u{2030}', '\u{160}', '\u{2039}', '\u{152}', '\u{8D}', '\u{17D}',
        '\u{8F}', '\u{90}', '\u{2018}', '\u{2019}', '\u{201C}', '\u{201D}', '\u{2022}', '\u{2013}',
        '\u{2014}', '\u{2DC}', '\u{2122}', '\u{161}', '\u{203A}', '\u{153}', '\u{9D}', '\u{17E}',
        '\u{178}',
    ];
    if (0x80..0xA0).contains(&byte) {
        HIGH[(byte - 0x80) as usize]
    } else {
        byte as char
    }
}

fn boundsheet_name(payload: &[u8], version: BiffVersion, codepage: u16) -> VisResult<String> {
    match version {
        BiffVersion::Biff8 => {
            if payload.len() < 8 {
                return Err(unresolved("short BOUNDSHEET record"));
            }
            let len = payload[6] as usize;
            let wide = payload[7] & 0x01 != 0;
            let name_bytes = &payload[8..];
            if wide {
                if name_bytes.len() < len * 2 {
                    return Err(unresolved("short BOUNDSHEET name"));
                }
                let units: Vec<u16> = name_bytes[..len * 2]
                    .chunks_exact(2)
                    .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                    .collect();
                String::from_utf16(&units).map_err(|_| unresolved("bad BOUNDSHEET name"))
            } else {
                if name_bytes.len() < len {
                    return Err(unresolved("short BOUNDSHEET name"));
                }
                // BIFF8 compressed strings are UTF-16 low bytes.
                Ok(name_bytes[..len].iter().map(|b| *b as char).collect())
            }
        }
        BiffVersion::Biff5 => {
            if payload.len() < 7 {
                return Err(unresolved("short BOUNDSHEET record"));
            }
            let len = payload[6] as usize;
            let name_bytes = &payload[7..];
            if name_bytes.len() < len {
                return Err(unresolved("short BOUNDSHEET name"));
            }
            decode_narrow(&name_bytes[..len], codepage)
        }
    }
}

// Legacy BIFF: the workbook globals name every sheet and the offset of
// its substream, and each substream carries ROW and COLINFO records
// with hidden flags and explicit sizes.
fn read_biff(bytes: &[u8]) -> VisResult<WorkbookVisibility> {
    let mut compound = cfb::CompoundFile::open(Cursor::new(bytes))
        .map_err(|e| unresolved(format!("not a compound file: {e}")))?;
    let stream_name = ["/Workbook", "/Book"]
        .into_iter()
        .find(|name| compound.exists(name))
        .ok_or_else(|| unresolved("no Workbook stream"))?;
    let mut stream = Vec::new();
    compound
        .open_stream(stream_name)
        .map_err(|e| unresolved(format!("cannot open {stream_name}: {e}")))?
        .take(MAX_PART_BYTES + 1)
        .read_to_end(&mut stream)
        .map_err(|e| unresolved(format!("cannot read {stream_name}: {e}")))?;
    if stream.len() as u64 > MAX_PART_BYTES {
        return Err(limit(format!(
            "workbook stream exceeds the {MAX_PART_BYTES} byte ceiling"
        )));
    }

    // Globals: version from the leading BOF, then sheet names and
    // substream offsets, ending at the globals EOF.
    let mut walker = BiffWalk::new(&stream, 0);
    let first = walker
        .next()
        .ok_or_else(|| unresolved("empty workbook stream"))??;
    if first.opcode != BIFF_BOF {
        return Err(unresolved("workbook stream does not start with BOF"));
    }
    let version = match field_u16(first.payload, 0, "BOF")? {
        0x0600 => BiffVersion::Biff8,
        0x0500 => BiffVersion::Biff5,
        other => {
            return Err(unresolved(format!(
                "unsupported BIFF version 0x{other:04X}"
            )));
        }
    };
    let mut codepage = 1252u16;
    let mut sheets: Vec<(String, usize)> = Vec::new();
    let mut saw_globals_eof = false;
    for record in walker.by_ref() {
        let record = record?;
        match record.opcode {
            BIFF_FILEPASS => return Err(unresolved("encrypted workbook")),
            BIFF_CODEPAGE => codepage = field_u16(record.payload, 0, "CODEPAGE")?,
            BIFF_BOUNDSHEET => {
                if record.payload.len() < 6 {
                    return Err(unresolved("short BOUNDSHEET record"));
                }
                let position = u32::from_le_bytes([
                    record.payload[0],
                    record.payload[1],
                    record.payload[2],
                    record.payload[3],
                ]) as usize;
                let sheet_type = record.payload[5];
                if sheet_type == 0 {
                    sheets.push((
                        boundsheet_name(record.payload, version, codepage)?,
                        position,
                    ));
                }
            }
            BIFF_EOF => saw_globals_eof = true,
            _ => {}
        }
    }
    if !saw_globals_eof {
        return Err(unresolved("globals end without EOF"));
    }
    let globals_end = walker.offset;

    // Substreams must tile the rest of the stream: no worksheet may
    // start inside the globals, and after every substream ends at its
    // own EOF, no bytes may remain past the last one.
    let mut furthest_end = globals_end;
    let mut by_sheet = HashMap::new();
    for (name, position) in sheets {
        if position < globals_end || position >= stream.len() {
            return Err(unresolved(format!(
                "sheet {name:?} substream offset {position} is outside the sheet area"
            )));
        }
        let mut visibility = SheetVisibility::default();
        let mut walker = BiffWalk::new(&stream, position);
        let first = walker
            .next()
            .ok_or_else(|| unresolved(format!("sheet {name:?} substream is empty")))??;
        if first.opcode != BIFF_BOF {
            return Err(unresolved(format!(
                "sheet {name:?} substream does not start with BOF"
            )));
        }
        if field_u16(first.payload, 2, "BOF")? != BOF_WORKSHEET {
            return Err(unresolved(format!(
                "sheet {name:?} substream BOF is not a worksheet"
            )));
        }
        let mut saw_eof = false;
        for record in walker.by_ref() {
            let record = record?;
            match record.opcode {
                BIFF_ROW => {
                    let row = field_u16(record.payload, 0, "ROW")?;
                    let height = field_u16(record.payload, 6, "ROW")?;
                    let flags = field_u16(record.payload, 12, "ROW")?;
                    let zero_height = height & 0x8000 == 0 && height & 0x7FFF == 0;
                    if flags & 0x0020 != 0 || zero_height {
                        visibility.hidden_rows.push(IndexRange {
                            first: row as u32,
                            last: row as u32,
                        });
                    }
                }
                BIFF_COLINFO => {
                    let first = field_u16(record.payload, 0, "COLINFO")?;
                    let last = field_u16(record.payload, 2, "COLINFO")?;
                    let width = field_u16(record.payload, 4, "COLINFO")?;
                    let flags = field_u16(record.payload, 8, "COLINFO")?;
                    if first > last || last > 255 {
                        return Err(unresolved(format!(
                            "COLINFO range {first}..{last} outside the column limit"
                        )));
                    }
                    if flags & 0x0001 != 0 || width == 0 {
                        visibility.hidden_columns.push(IndexRange {
                            first: first as u32,
                            last: last as u32,
                        });
                    }
                }
                BIFF_EOF => saw_eof = true,
                _ => {}
            }
        }
        if !saw_eof {
            return Err(unresolved(format!("sheet {name:?} substream has no EOF")));
        }
        furthest_end = furthest_end.max(walker.offset);
        by_sheet.insert(name, visibility);
    }
    if furthest_end != stream.len() {
        return Err(unresolved(format!(
            "{} trailing bytes after the last substream",
            stream.len() - furthest_end
        )));
    }
    Ok(WorkbookVisibility { by_sheet })
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) fn record(opcode: u16, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&opcode.to_le_bytes());
        out.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        out.extend_from_slice(payload);
        out
    }

    fn bof(version: u16, dt: u16) -> Vec<u8> {
        let mut payload = vec![0u8; 16];
        payload[0..2].copy_from_slice(&version.to_le_bytes());
        payload[2..4].copy_from_slice(&dt.to_le_bytes());
        record(BIFF_BOF, &payload)
    }

    fn row_record(row: u16, height: u16, flags: u16) -> Vec<u8> {
        let mut payload = vec![0u8; 16];
        payload[0..2].copy_from_slice(&row.to_le_bytes());
        payload[6..8].copy_from_slice(&height.to_le_bytes());
        payload[12..14].copy_from_slice(&flags.to_le_bytes());
        record(BIFF_ROW, &payload)
    }

    fn colinfo_record(first: u16, last: u16, width: u16, flags: u16) -> Vec<u8> {
        let mut payload = vec![0u8; 12];
        payload[0..2].copy_from_slice(&first.to_le_bytes());
        payload[2..4].copy_from_slice(&last.to_le_bytes());
        payload[4..6].copy_from_slice(&width.to_le_bytes());
        payload[8..10].copy_from_slice(&flags.to_le_bytes());
        record(BIFF_COLINFO, &payload)
    }

    fn boundsheet_biff8(name: &str, position: u32) -> Vec<u8> {
        let mut payload = vec![0u8; 8];
        payload[0..4].copy_from_slice(&position.to_le_bytes());
        payload[6] = name.len() as u8;
        payload.extend_from_slice(name.as_bytes());
        record(BIFF_BOUNDSHEET, &payload)
    }

    /// A BIFF8 workbook stream with one sheet named Data.
    fn biff_stream(sheet_records: &[Vec<u8>]) -> Vec<u8> {
        let globals = [
            bof(0x0600, 0x0005),
            boundsheet_biff8("Data", 0),
            record(BIFF_EOF, &[]),
        ];
        let globals_len: usize = globals.iter().map(Vec::len).sum();
        let mut stream = Vec::new();
        stream.extend(bof(0x0600, 0x0005));
        stream.extend(boundsheet_biff8("Data", globals_len as u32));
        stream.extend(record(BIFF_EOF, &[]));
        stream.extend(bof(0x0600, BOF_WORKSHEET));
        for sheet_record in sheet_records {
            stream.extend(sheet_record.clone());
        }
        stream.extend(record(BIFF_EOF, &[]));
        stream
    }

    fn biff_file(stream: &[u8]) -> Vec<u8> {
        let cursor = Cursor::new(Vec::new());
        let mut compound = cfb::CompoundFile::create(cursor).unwrap();
        {
            use std::io::Write;
            let mut entry = compound.create_stream("/Workbook").unwrap();
            entry.write_all(stream).unwrap();
        }
        compound.into_inner().into_inner()
    }

    #[test]
    fn biff_walk_finds_hidden_rows_and_columns() {
        let stream = biff_stream(&[
            row_record(0, 300, 0x0000),
            row_record(3, 300, 0x0020),
            row_record(5, 0x0000, 0x0000),
            colinfo_record(1, 2, 2048, 0x0001),
            colinfo_record(4, 4, 0, 0x0000),
        ]);
        let visibility = read_biff(&biff_file(&stream)).unwrap();
        let sheet = visibility.sheet("Data").unwrap();
        assert!(!sheet.row_hidden(0));
        assert!(sheet.row_hidden(3));
        assert!(sheet.row_hidden(5));
        assert!(sheet.column_hidden(1));
        assert!(sheet.column_hidden(2));
        assert!(!sheet.column_hidden(3));
        assert!(sheet.column_hidden(4));
    }

    #[test]
    fn truncated_biff_stream_names_the_defect() {
        let mut stream = biff_stream(&[row_record(3, 300, 0x0020)]);
        stream.truncate(stream.len() - 7);
        let err = read_biff(&biff_file(&stream)).unwrap_err();
        assert!(err.to_string().contains("truncated"));
    }

    #[test]
    fn trailing_bytes_after_the_last_substream_are_an_error() {
        let mut stream = biff_stream(&[row_record(3, 300, 0x0020)]);
        stream.extend_from_slice(&[0x00, 0x01, 0x02]);
        let err = read_biff(&biff_file(&stream)).unwrap_err();
        assert!(err.to_string().contains("trailing bytes"), "{err}");
    }

    #[test]
    fn misdirected_substream_offset_is_refused() {
        // Point the BOUNDSHEET at a ROW record instead of a BOF.
        let globals = [
            bof(0x0600, 0x0005),
            boundsheet_biff8("Data", 0),
            record(BIFF_EOF, &[]),
        ];
        let globals_len: usize = globals.iter().map(Vec::len).sum();
        let row = row_record(3, 300, 0x0020);
        let target = globals_len + bof(0x0600, BOF_WORKSHEET).len();

        let mut stream = Vec::new();
        stream.extend(bof(0x0600, 0x0005));
        stream.extend(boundsheet_biff8("Data", target as u32));
        stream.extend(record(BIFF_EOF, &[]));
        stream.extend(bof(0x0600, BOF_WORKSHEET));
        stream.extend(row);
        stream.extend(record(BIFF_EOF, &[]));

        let err = read_biff(&biff_file(&stream)).unwrap_err();
        assert!(err.to_string().contains("does not start with BOF"), "{err}");
    }

    #[test]
    fn substream_inside_the_globals_is_refused() {
        let mut stream = Vec::new();
        stream.extend(bof(0x0600, 0x0005));
        stream.extend(boundsheet_biff8("Data", 0));
        stream.extend(record(BIFF_EOF, &[]));
        stream.extend(bof(0x0600, BOF_WORKSHEET));
        stream.extend(record(BIFF_EOF, &[]));
        let err = read_biff(&biff_file(&stream)).unwrap_err();
        assert!(err.to_string().contains("outside the sheet area"), "{err}");
    }

    #[test]
    fn biff5_names_parse_with_their_own_layout() {
        // BIFF5 BOUNDSHEET: position, visibility, type, length, bytes.
        let mut boundsheet = vec![0u8; 7];
        boundsheet[6] = 4;
        boundsheet.extend_from_slice(b"Data");
        let globals = [
            bof(0x0500, 0x0005),
            record(BIFF_BOUNDSHEET, &boundsheet),
            record(BIFF_EOF, &[]),
        ];
        let globals_len: usize = globals.iter().map(Vec::len).sum();
        let mut patched = vec![0u8; 7];
        patched[0..4].copy_from_slice(&(globals_len as u32).to_le_bytes());
        patched[6] = 4;
        patched.extend_from_slice(b"Data");

        let mut stream = Vec::new();
        stream.extend(bof(0x0500, 0x0005));
        stream.extend(record(BIFF_BOUNDSHEET, &patched));
        stream.extend(record(BIFF_EOF, &[]));
        stream.extend(bof(0x0500, BOF_WORKSHEET));
        stream.extend(row_record(2, 300, 0x0020));
        stream.extend(record(BIFF_EOF, &[]));

        let visibility = read_biff(&biff_file(&stream)).unwrap();
        assert!(visibility.sheet("Data").unwrap().row_hidden(2));
    }

    #[test]
    fn encrypted_biff_stream_is_refused() {
        let mut stream = Vec::new();
        stream.extend(bof(0x0600, 0x0005));
        stream.extend(record(BIFF_FILEPASS, &[0u8; 6]));
        stream.extend(record(BIFF_EOF, &[]));
        let err = read_biff(&biff_file(&stream)).unwrap_err();
        assert!(err.to_string().contains("encrypted"));
    }

    #[test]
    fn colinfo_past_the_column_limit_is_refused() {
        let stream = biff_stream(&[colinfo_record(5, 3, 2048, 0x0001)]);
        let err = read_biff(&biff_file(&stream)).unwrap_err();
        assert!(err.to_string().contains("COLINFO"), "{err}");
    }

    fn zip_of(entries: &[(&str, &[u8])]) -> Vec<u8> {
        use std::io::Write;
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        for (name, bytes) in entries {
            writer
                .start_file(*name, zip::write::SimpleFileOptions::default())
                .unwrap();
            writer.write_all(bytes).unwrap();
        }
        writer.finish().unwrap().into_inner()
    }

    fn ods_of(content: &str) -> Vec<u8> {
        zip_of(&[
            (
                "mimetype",
                b"application/vnd.oasis.opendocument.spreadsheet",
            ),
            ("content.xml", content.as_bytes()),
        ])
    }

    const ODS_OPEN: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<office:document-content xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:table="urn:oasis:names:tc:opendocument:xmlns:table:1.0" xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0" xmlns:evil="urn:example:evil">
<office:body><office:spreadsheet>"#;
    const ODS_CLOSE: &str = "</office:spreadsheet></office:body></office:document-content>";

    #[test]
    fn ods_repeat_overflow_is_a_limit_error_not_a_panic() {
        let content = format!(
            "{ODS_OPEN}<table:table table:name=\"D\">\
<table:table-row table:number-rows-repeated=\"4294967290\"/>\
<table:table-row table:number-rows-repeated=\"4294967290\"/>\
</table:table>{ODS_CLOSE}"
        );
        let err = read_ods(&ods_of(&content)).unwrap_err();
        assert!(matches!(err, VisibilityError::Limit(_)), "{err}");
    }

    #[test]
    fn ods_zero_repeat_is_refused() {
        let content = format!(
            "{ODS_OPEN}<table:table table:name=\"D\">\
<table:table-row table:number-rows-repeated=\"0\"/>\
</table:table>{ODS_CLOSE}"
        );
        let err = read_ods(&ods_of(&content)).unwrap_err();
        assert!(err.to_string().contains("zero repeat"), "{err}");
    }

    #[test]
    fn ods_spoofed_foreign_visibility_changes_nothing() {
        // A foreign visibility attribute neither hides nor reveals.
        let content = format!(
            "{ODS_OPEN}<table:table table:name=\"D\">\
<table:table-row evil:visibility=\"collapse\"/>\
<table:table-row evil:visibility=\"visible\" table:visibility=\"collapse\"/>\
</table:table>{ODS_CLOSE}"
        );
        let sheet = read_ods(&ods_of(&content)).unwrap().sheet("D").unwrap();
        assert!(!sheet.row_hidden(0));
        assert!(sheet.row_hidden(1));
    }

    #[test]
    fn ods_nested_tables_neither_open_sheets_nor_shift_rows() {
        // A nested table, foreign or table-namespaced, must not steal
        // the outer sheet's remaining rows.
        let content = format!(
            "{ODS_OPEN}<table:table table:name=\"Outer\">\
<table:table-row/>\
<evil:table><table:table-row table:visibility=\"collapse\"/></evil:table>\
<table:table><table:table-row table:visibility=\"collapse\"/></table:table>\
<table:table-row table:visibility=\"collapse\"/>\
</table:table>{ODS_CLOSE}"
        );
        let visibility = read_ods(&ods_of(&content)).unwrap();
        let outer = visibility.sheet("Outer").unwrap();
        assert!(!outer.row_hidden(0));
        assert!(outer.row_hidden(2), "outer hidden row keeps its index");
        assert!(
            visibility.sheet("").is_none(),
            "nested table is not a sheet"
        );
    }

    fn xlsx_of(sheet_xml: &str) -> Vec<u8> {
        let workbook = r#"<?xml version="1.0"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
<sheets><sheet name="Data" sheetId="1" r:id="rId1"/></sheets></workbook>"#;
        let rels = r#"<?xml version="1.0"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
</Relationships>"#;
        zip_of(&[
            ("xl/workbook.xml", workbook.as_bytes()),
            ("xl/_rels/workbook.xml.rels", rels.as_bytes()),
            ("xl/worksheets/sheet1.xml", sheet_xml.as_bytes()),
        ])
    }

    const SHEET_OPEN: &str = r#"<?xml version="1.0"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:evil="urn:example:evil"><sheetData>"#;
    const SHEET_CLOSE: &str = "</sheetData></worksheet>";

    #[test]
    fn xlsx_spoofed_foreign_hidden_changes_nothing() {
        let sheet = format!(
            "{SHEET_OPEN}<row r=\"1\" evil:hidden=\"1\"/>\
<row r=\"2\" evil:hidden=\"0\" hidden=\"1\"/>{SHEET_CLOSE}"
        );
        let visibility = read_ooxml(&xlsx_of(&sheet)).unwrap();
        let data = visibility.sheet("Data").unwrap();
        assert!(!data.row_hidden(0));
        assert!(data.row_hidden(1));
    }

    #[test]
    fn xlsx_cell_extent_product_is_refused() {
        let sheet = format!(
            "{SHEET_OPEN}<row r=\"1\"><c r=\"A1\"><v>1</v></c></row>\
<row r=\"1048576\"><c r=\"XFD1048576\"><v>2</v></c></row>{SHEET_CLOSE}"
        );
        let err = read_ooxml(&xlsx_of(&sheet)).unwrap_err();
        assert!(matches!(err, VisibilityError::Limit(_)), "{err}");
    }

    #[test]
    fn xlsx_non_numeric_sizes_are_refused() {
        let sheet = format!("{SHEET_OPEN}<row r=\"1\" ht=\"NaN\"/>{SHEET_CLOSE}");
        let err = read_ooxml(&xlsx_of(&sheet)).unwrap_err();
        assert!(err.to_string().contains("row height"), "{err}");

        let sheet = r#"<?xml version="1.0"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<cols><col min="1" max="1" width="wide"/></cols><sheetData/></worksheet>"#;
        let err = read_ooxml(&xlsx_of(sheet)).unwrap_err();
        assert!(err.to_string().contains("col width"), "{err}");
    }

    #[test]
    fn worksheet_at_an_unusual_part_path_resolves_by_relationship_type() {
        let workbook = r#"<?xml version="1.0"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
<sheets><sheet name="Data" sheetId="1" r:id="rId1"/></sheets></workbook>"#;
        let rels = r#"<?xml version="1.0"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="parts/sheet1.xml"/>
</Relationships>"#;
        let sheet = r#"<?xml version="1.0"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<sheetData><row r="2" hidden="1"/></sheetData></worksheet>"#;
        let archive = zip_of(&[
            ("xl/workbook.xml", workbook.as_bytes()),
            ("xl/_rels/workbook.xml.rels", rels.as_bytes()),
            ("xl/parts/sheet1.xml", sheet.as_bytes()),
        ]);
        let visibility = read_ooxml(&archive).unwrap();
        assert!(visibility.sheet("Data").unwrap().row_hidden(1));
    }

    #[test]
    fn oversized_archive_part_is_a_limit_error() {
        // A tiny compressed archive holding one part far over the
        // ceiling stays under the ceiling in memory and fails closed.
        let mut huge = String::with_capacity(MAX_PART_BYTES as usize + 1024);
        huge.push_str(r#"<?xml version="1.0"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>"#);
        while huge.len() as u64 <= MAX_PART_BYTES {
            huge.push_str("                                                                ");
        }
        huge.push_str("</sheetData></worksheet>");
        let err = read_ooxml(&xlsx_of(&huge)).unwrap_err();
        assert!(matches!(err, VisibilityError::Limit(_)), "{err}");
    }

    #[test]
    fn unknown_format_has_no_reader() {
        let err = read_visibility(b"", "xlsb").unwrap_err();
        assert!(err.to_string().contains("no visibility reader"));
    }

    #[test]
    fn unresolved_sheet_lookup_returns_none() {
        let visibility = WorkbookVisibility::default();
        assert!(visibility.sheet("Ghost").is_none());
    }

    #[test]
    fn cell_references_parse_and_cap() {
        assert_eq!(parse_cell_reference("A1").unwrap(), (0, 0));
        assert_eq!(
            parse_cell_reference("XFD1048576").unwrap(),
            (1048575, 16383)
        );
        assert!(parse_cell_reference("XFE1").is_err());
        assert!(parse_cell_reference("A0").is_err());
        assert!(parse_cell_reference("11").is_err());
    }

    #[test]
    fn part_targets_normalize() {
        assert_eq!(
            normalize_part_target("worksheets/sheet1.xml").unwrap(),
            "xl/worksheets/sheet1.xml"
        );
        assert_eq!(
            normalize_part_target("/xl/parts/sheet1.xml").unwrap(),
            "xl/parts/sheet1.xml"
        );
        assert_eq!(
            normalize_part_target("./sub/../parts/s.xml").unwrap(),
            "xl/parts/s.xml"
        );
        assert!(normalize_part_target("../../evil.xml").is_err());
    }
}
