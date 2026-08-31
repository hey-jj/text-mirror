//! The workbook converter over calamine.
//!
//! Renders every sheet row by row, cells joined with tabs, one row
//! per line, with one blank line between sheets. A cell that carries
//! a formula renders its cached value first and the formula as inert
//! text in the form `value [=formula]`. Formulas are never evaluated.
//!
//! Hidden content renders inline, unmarked. The marks are out of
//! band: the segments records carry a span for every sheet with its
//! hidden flag, and hidden-true spans for hidden rows and for cells
//! in hidden columns. Sheet visibility comes from calamine, row and
//! column visibility from the sibling visibility module, and a file
//! whose visibility cannot be resolved fails instead of emitting
//! unmarked content.
//!
//! Legacy `xls` runs the differential check against a second
//! extraction, comparing cell values only.

use std::collections::HashMap;
use std::io::Cursor;

use calamine::{Data, Reader, SheetType, SheetVisible};

use crate::segments::{Segment, SegmentKind};

use super::differential::{self, DifferentialOutcome};
use super::visibility::{self, SheetVisibility, VisibilityError};
use super::{ConvertError, Converter, Outcome, normalize_text};

/// Registry id of the workbook converter.
pub const WORKBOOK_ID: &str = "workbook-ir";

/// Version of the workbook converter.
pub const WORKBOOK_VERSION: &str = "1.0.0";

/// Normalizes one cell's text: NFC, and structure characters (tabs
/// and line breaks) become spaces so a cell can never fake a row or
/// column boundary.
fn cell_piece(raw: &str) -> String {
    normalize_text(raw).replace(['\n', '\t'], " ")
}

fn value_text(value: &Data) -> String {
    match value {
        Data::Empty => String::new(),
        other => cell_piece(&other.to_string()),
    }
}

fn parse_error(detail: impl std::fmt::Display) -> ConvertError {
    ConvertError {
        code: "workbook_parse_error",
        message: detail.to_string(),
    }
}

/// The workbook converter. See the module documentation.
pub struct WorkbookIr;

impl Converter for WorkbookIr {
    fn id(&self) -> &'static str {
        WORKBOOK_ID
    }

    fn version(&self) -> &'static str {
        WORKBOOK_VERSION
    }

    fn convert(
        &self,
        source: &[u8],
        detected_format: &str,
    ) -> std::result::Result<Outcome, ConvertError> {
        if !matches!(detected_format, "xls" | "xlsx" | "xlsm" | "ods") {
            return Err(ConvertError {
                code: "unclaimed_format",
                message: format!("the workbook converter does not handle {detected_format}"),
            });
        }

        // Visibility resolves first. A workbook never emits unmarked
        // content, so an unresolvable file fails before any rendering.
        let visibility =
            visibility::read_visibility(source, detected_format).map_err(|error| match error {
                VisibilityError::Limit(message) => ConvertError {
                    code: "resource_limit",
                    message,
                },
                VisibilityError::Unresolved(message) => ConvertError {
                    code: "visibility_read_error",
                    message,
                },
            })?;

        let mut workbook = calamine::open_workbook_auto_from_rs(Cursor::new(source.to_vec()))
            .map_err(parse_error)?;
        let sheets = workbook.sheets_metadata().to_vec();

        let mut text = String::new();
        let mut segments = Vec::new();
        let mut value_stream: Vec<String> = Vec::new();

        for sheet in &sheets {
            if sheet.typ != SheetType::WorkSheet {
                continue;
            }
            if !text.is_empty() {
                text.push('\n');
            }
            let sheet_start = text.len();
            let sheet_hidden = !matches!(sheet.visible, SheetVisible::Visible);
            // A sheet the visibility reader did not resolve must not
            // render, whatever the reason for the disagreement.
            let Some(sheet_visibility) = visibility.sheet(&sheet.name) else {
                return Err(ConvertError {
                    code: "visibility_read_error",
                    message: format!("no resolved visibility for sheet {:?}", sheet.name),
                });
            };

            let range = workbook.worksheet_range(&sheet.name).map_err(parse_error)?;
            let formulas = workbook
                .worksheet_formula(&sheet.name)
                .map_err(parse_error)?;
            let mut formula_map: HashMap<(u32, u32), String> = HashMap::new();
            if let Some((formula_row, formula_col)) = formulas.start() {
                for (row, col, formula) in formulas.used_cells() {
                    if !formula.is_empty() {
                        formula_map.insert(
                            (formula_row + row as u32, formula_col + col as u32),
                            cell_piece(formula),
                        );
                    }
                }
            }

            render_sheet(
                &range,
                &formula_map,
                &sheet_visibility,
                &mut text,
                &mut segments,
                &mut value_stream,
            );

            segments.push(Segment::boundary(SegmentKind::Sheet, sheet_start).named(&sheet.name));
            let mut sheet_span = Segment::span(sheet_start, text.len(), "sheet").named(&sheet.name);
            if sheet_hidden {
                sheet_span = sheet_span.hidden();
            }
            segments.push(sheet_span);
        }

        segments.sort_by_key(|s| (s.start, s.end));

        if !source.is_empty() && text.is_empty() {
            return Err(ConvertError {
                code: "empty_output",
                message: format!(
                    "source is {} bytes but conversion produced no text",
                    source.len()
                ),
            });
        }

        let mut warnings = Vec::new();
        if detected_format == "xls" {
            // The secondary sees values only, so the comparison side
            // excludes formulas and rendering structure.
            let values_only = value_stream.join(" ");
            match differential::check(&values_only, source, "xls") {
                DifferentialOutcome::Agreement => {}
                DifferentialOutcome::Warning(warning) => warnings.push(warning),
                DifferentialOutcome::Failure(detail) => {
                    return Err(ConvertError {
                        code: "differential-divergence",
                        message: detail,
                    });
                }
            }
        }

        Ok(Outcome {
            artifact_kind: crate::manifest::ArtifactKind::Text,
            converter_id: WORKBOOK_ID.to_string(),
            converter_version: WORKBOOK_VERSION.to_string(),
            detected_format: detected_format.to_string(),
            text,
            warnings,
            segments,
            media: None,
        })
    }
}

fn render_sheet(
    range: &calamine::Range<Data>,
    formula_map: &HashMap<(u32, u32), String>,
    sheet_visibility: &SheetVisibility,
    text: &mut String,
    segments: &mut Vec<Segment>,
    value_stream: &mut Vec<String>,
) {
    let Some((start_row, start_col)) = range.start() else {
        return;
    };
    for (relative_row, row) in range.rows().enumerate() {
        let absolute_row = start_row + relative_row as u32;
        let line_start = text.len();
        // Trailing empty cells render nothing, so a row never ends in
        // separator tabs.
        let rendered_width = row
            .iter()
            .enumerate()
            .rev()
            .find(|(relative_col, value)| {
                **value != Data::Empty
                    || formula_map.contains_key(&(absolute_row, start_col + *relative_col as u32))
            })
            .map(|(relative_col, _)| relative_col + 1)
            .unwrap_or(0);
        for (relative_col, value) in row.iter().take(rendered_width).enumerate() {
            if relative_col > 0 {
                text.push('\t');
            }
            let absolute_col = start_col + relative_col as u32;
            let cell_start = text.len();
            let value_piece = value_text(value);
            if !value_piece.is_empty() {
                value_stream.push(value_piece.clone());
            }
            match formula_map.get(&(absolute_row, absolute_col)) {
                Some(formula) if value_piece.is_empty() => {
                    text.push_str(&format!("[={formula}]"));
                }
                Some(formula) => {
                    text.push_str(&format!("{value_piece} [={formula}]"));
                }
                None => text.push_str(&value_piece),
            }
            // Hidden coordinates always get their record, zero width
            // when the cell rendered no bytes.
            if sheet_visibility.column_hidden(absolute_col) {
                segments.push(Segment::span(cell_start, text.len(), "column").hidden());
            }
        }
        text.push('\n');
        let line_end = text.len() - 1;
        if sheet_visibility.row_hidden(absolute_row) {
            segments.push(Segment::span(line_start, line_end, "row").hidden());
        }
    }
}
