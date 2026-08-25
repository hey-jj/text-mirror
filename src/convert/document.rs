//! The document adapter over anydoc.
//!
//! One converter covers documents, presentations, rich text, ebooks,
//! and OpenDocument files. anydoc emits Markdown, and one
//! deterministic normalizer flattens that Markdown to plain text
//! before the shared NFC and LF pass. anydoc's stable error class is
//! preserved as the machine-readable reason of a failed record.
//!
//! Text-layer PDF is no longer an in-process format here. It runs
//! behind the sandbox runner in the worker binary, because hostile
//! PDF bytes must crash a jailed child and never the pipeline. See
//! the sibling `pdf` and `subprocess` modules.
//!
//! Legacy `doc` and `ppt` conversions run the differential check
//! against a second extraction. See the sibling differential module
//! for the policy.
//!
//! anydoc reports recovered and skipped content through the log
//! facade. The shared bridge in `anydoc_log` captures those records
//! per conversion and promotes them to manifest warnings, so a
//! partially extracted document never reads as silently complete.

use crate::segments::Segment;

use super::anydoc_log::capture_anydoc;
use super::differential::{self, DifferentialOutcome};
use super::{ConvertError, Converter, Outcome, normalize_text};

/// Turns a captured anydoc message into a manifest warning.
fn promote_warning(message: &str) -> String {
    format!("anydoc_recovery: {message}")
}

/// Registry id of the document adapter.
pub const ANYDOC_ID: &str = "anydoc-document";

/// Version of the document adapter.
pub const ANYDOC_VERSION: &str = "1.0.0";

fn anydoc_format(format_id: &str) -> Option<anydoc::Format> {
    Some(match format_id {
        "doc" => anydoc::Format::Doc,
        "docx" => anydoc::Format::Docx,
        "odt" => anydoc::Format::Odt,
        "ppt" => anydoc::Format::Ppt,
        "pptx" => anydoc::Format::Pptx,
        "rtf" => anydoc::Format::Rtf,
        "epub" => anydoc::Format::Epub,
        "odp" => anydoc::Format::Odp,
        _ => return None,
    })
}

fn error_code(error: &anydoc::ConvertError) -> &'static str {
    match error.code() {
        "unsupported" => "unsupported",
        "malformed" => "malformed",
        "encrypted" => "encrypted",
        "resourceLimit" => "resourceLimit",
        "missingPart" => "missingPart",
        _ => "io",
    }
}

/// Renders Markdown to plain text through a real parser.
///
/// The GFM event stream renders explicitly: text nodes, code span and
/// code block content, and link and image labels come through
/// verbatim, table cells join with tabs and rows with newlines, block
/// ends separate with one blank line, and destinations, heading
/// markers, emphasis delimiters, and rules leave nothing behind.
/// Escapes resolve in the parser, so literal content such as an
/// intraword underscore or an escaped pipe survives byte for byte.
pub fn markdown_to_plain(markdown: &str) -> String {
    use pulldown_cmark::{Event, Options, Parser, Tag, TagEnd};

    let mut options = Options::empty();
    options.insert(Options::ENABLE_TABLES);
    options.insert(Options::ENABLE_STRIKETHROUGH);
    options.insert(Options::ENABLE_TASKLISTS);

    fn close_block(out: &mut String) {
        while out.ends_with('\n') {
            out.pop();
        }
        if !out.is_empty() {
            out.push_str("\n\n");
        }
    }

    fn close_line(out: &mut String) {
        if !out.is_empty() && !out.ends_with('\n') {
            out.push('\n');
        }
    }

    let mut out = String::with_capacity(markdown.len());
    let mut first_cell = true;
    for event in Parser::new_ext(markdown, options) {
        match event {
            Event::Start(tag) => match tag {
                Tag::TableHead | Tag::TableRow => first_cell = true,
                Tag::TableCell => {
                    if !first_cell {
                        out.push('\t');
                    }
                    first_cell = false;
                }
                _ => {}
            },
            Event::End(tag) => match tag {
                TagEnd::Paragraph
                | TagEnd::Heading(_)
                | TagEnd::List(_)
                | TagEnd::Table
                | TagEnd::CodeBlock => close_block(&mut out),
                TagEnd::Item | TagEnd::TableHead | TagEnd::TableRow => close_line(&mut out),
                _ => {}
            },
            Event::Text(text) => out.push_str(&text),
            Event::Code(code) => out.push_str(&code),
            Event::Html(html) | Event::InlineHtml(html) => out.push_str(&html),
            Event::SoftBreak | Event::HardBreak => out.push('\n'),
            Event::Rule => {}
            Event::TaskListMarker(checked) => {
                out.push_str(if checked { "[x] " } else { "[ ] " });
            }
            Event::FootnoteReference(label) => {
                out.push('[');
                out.push_str(&label);
                out.push(']');
            }
            _ => {}
        }
    }
    while out.ends_with('\n') {
        out.pop();
    }
    if !out.is_empty() {
        out.push('\n');
    }
    out
}

/// The document adapter. See the module documentation.
pub struct AnydocDocument;

impl Converter for AnydocDocument {
    fn id(&self) -> &'static str {
        ANYDOC_ID
    }

    fn version(&self) -> &'static str {
        ANYDOC_VERSION
    }

    fn convert(
        &self,
        source: &[u8],
        detected_format: &str,
    ) -> std::result::Result<Outcome, ConvertError> {
        let Some(format) = anydoc_format(detected_format) else {
            return Err(ConvertError {
                code: "unclaimed_format",
                message: format!("the document adapter does not handle {detected_format}"),
            });
        };
        let (converted, captured) = capture_anydoc(|| anydoc::to_markdown_bytes(source, format));
        let markdown = converted.map_err(|error| ConvertError {
            code: error_code(&error),
            message: error.to_string(),
        })?;
        let text = normalize_text(&markdown_to_plain(&markdown));
        if !source.is_empty() && text.is_empty() {
            return Err(ConvertError {
                code: "empty_output",
                message: format!(
                    "source is {} bytes but conversion produced no text",
                    source.len()
                ),
            });
        }
        let mut warnings: Vec<String> = captured
            .iter()
            .map(|message| promote_warning(message))
            .collect();

        // Legacy Office formats get a second, independent extraction.
        if matches!(detected_format, "doc" | "ppt") {
            match differential::check(&text, source, detected_format) {
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

        let segments = vec![Segment::span(0, text.len(), "document")];
        Ok(Outcome {
            artifact_kind: crate::manifest::ArtifactKind::Text,
            converter_id: ANYDOC_ID.to_string(),
            converter_version: ANYDOC_VERSION.to_string(),
            detected_format: detected_format.to_string(),
            text,
            warnings,
            segments,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn markdown_structure_flattens_to_plain_text() {
        let markdown = "\
# Title

Some *emphasis* and **bold** and `code`.

> quoted line

- first item
- second item
1. numbered

| a | b |
| --- | --- |
| 1 | 2 |

[label](https://example.invalid/path) and \\*literal\\*

```
let x = 1;
```
";
        let plain = markdown_to_plain(markdown);
        assert_eq!(
            plain,
            "\
Title

Some emphasis and bold and code.

quoted line

first item
second item

numbered

a\tb
1\t2

label and *literal*

let x = 1;
"
        );
    }

    #[test]
    fn literal_identifiers_and_operators_survive_verbatim() {
        assert_eq!(
            markdown_to_plain("employee_id and 2 * 3 and snake_case_name"),
            "employee_id and 2 * 3 and snake_case_name\n"
        );
        assert_eq!(markdown_to_plain("`2 * 3 _x_ [y]`"), "2 * 3 _x_ [y]\n");
        assert_eq!(
            markdown_to_plain("ends with a backslash \\"),
            "ends with a backslash \\\n"
        );
    }

    #[test]
    fn escaped_pipes_stay_inside_their_table_cell() {
        let table = "| a \\| b | c |\n| --- | --- |\n| 1 | 2 |";
        assert_eq!(markdown_to_plain(table), "a | b\tc\n1\t2\n");
    }

    #[test]
    fn link_labels_survive_and_destinations_never_leak() {
        assert_eq!(
            markdown_to_plain("[label](https://example.invalid/a(b)) tail"),
            "label tail\n"
        );
        assert_eq!(
            markdown_to_plain("[ref label][r] tail\n\n[r]: https://example.invalid/x"),
            "ref label tail\n"
        );
        assert_eq!(
            markdown_to_plain("![alt text](https://example.invalid/i.png) tail"),
            "alt text tail\n"
        );
    }

    #[test]
    fn gfm_extensions_render_their_content() {
        assert_eq!(markdown_to_plain("~~struck~~ kept"), "struck kept\n");
        assert_eq!(
            markdown_to_plain("- [x] done\n- [ ] open"),
            "[x] done\n[ ] open\n"
        );
    }

    #[test]
    fn the_log_bridge_captures_and_promotes_anydoc_warnings() {
        let ((), captured) = capture_anydoc(|| {
            log::warn!(target: "anydoc::formats::pptx", "skipped slide 3: corrupt part");
            log::warn!(target: "unrelated::crate", "never captured");
        });
        assert_eq!(captured.len(), 1);
        assert_eq!(
            promote_warning(&captured[0]),
            "anydoc_recovery: skipped slide 3: corrupt part"
        );
    }

    #[test]
    fn adapter_rejects_formats_it_does_not_map() {
        let err = AnydocDocument.convert(b"anything", "png").unwrap_err();
        assert_eq!(err.code, "unclaimed_format");
    }

    #[test]
    fn malformed_bytes_preserve_the_anydoc_error_class() {
        let err = AnydocDocument
            .convert(b"PK\x03\x04 not a real docx", "docx")
            .unwrap_err();
        assert!(
            ["malformed", "unsupported", "missingPart", "io"].contains(&err.code),
            "unexpected class {}",
            err.code
        );
    }
}
