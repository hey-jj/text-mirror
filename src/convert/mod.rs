//! The converter boundary and the plain text passthrough.
//!
//! Every converter returns the same outcome shape. The registry in
//! `rules/converters.toml` maps format ids to converters. A format no
//! converter claims is unsupported. A converter error or invalid
//! output is a failure with a machine-readable reason and no text
//! artifact. There is no silent skip and no silently empty file. A
//! non-empty source that converts to empty text fails with reason
//! `empty_output` in every converter.
//!
//! In-process conversion runs under a panic boundary and explicit
//! ceilings that apply before allocation in this crate's own code:
//! the source size before read, the decompressed size of every
//! archive part and compound stream, the cell extent of every sheet
//! before the workbook parser runs, and the rendered output size. A
//! caught panic or an exceeded ceiling becomes one failed record and
//! the run continues. The panic boundary requires the default
//! `panic = "unwind"` profile. A downstream `panic = "abort"` build
//! turns any converter panic into process death, so keep unwinding
//! enabled wherever this crate converts untrusted bytes.

/// Ceiling on source bytes read for conversion, checked before read.
pub const MAX_SOURCE_BYTES: u64 = 128 * 1024 * 1024;

/// Ceiling on the decompressed bytes of one archive part or one
/// compound file stream.
pub const MAX_PART_BYTES: u64 = 64 * 1024 * 1024;

/// Ceiling on rendered artifact text bytes.
pub const MAX_OUTPUT_BYTES: usize = 64 * 1024 * 1024;

/// Ceiling on 0-based row indexes in one sheet.
pub const MAX_SHEET_ROWS: u32 = 1_048_576;

/// Ceiling on 0-based column indexes in one sheet.
pub const MAX_SHEET_COLUMNS: u32 = 16_384;

/// Ceiling on the row-column product of one sheet, checked from the
/// source's own references before the workbook parser allocates.
pub const MAX_SHEET_CELLS: u64 = 10_000_000;

use std::collections::HashMap;
use std::fmt;

use serde::Deserialize;
use unicode_normalization::UnicodeNormalization;

use crate::segments::Segment;
use crate::{Error, Result};

mod anydoc_log;
mod differential;
mod document;
pub mod pdf;
pub mod subprocess;
mod visibility;
mod workbook;

pub use differential::{
    DiffMetrics, DiffVerdict, DifferentialOutcome, compare_texts, normalize_for_diff,
};
pub use document::{AnydocDocument, markdown_to_plain};
pub use subprocess::PdfSubprocess;
pub use visibility::{IndexRange, SheetVisibility, WorkbookVisibility, read_visibility};
pub use workbook::WorkbookIr;

/// What every converter returns on success.
#[derive(Debug, Clone)]
pub struct Outcome {
    /// Stable converter id from the registry.
    pub converter_id: String,
    /// Converter version from the registry.
    pub converter_version: String,
    /// Format id the converter was asked to handle.
    pub detected_format: String,
    /// The converted text, UTF-8, NFC, LF line endings.
    pub text: String,
    /// Non-fatal notes about the conversion.
    pub warnings: Vec<String>,
    /// Structure spans over `text` for the segments file.
    pub segments: Vec<Segment>,
}

/// A conversion failure with a machine-readable reason.
#[derive(Debug, Clone)]
pub struct ConvertError {
    /// Stable reason code, such as `invalid_utf8` or `empty_output`.
    pub code: &'static str,
    /// Detail for a human reading the manifest.
    pub message: String,
}

impl fmt::Display for ConvertError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for ConvertError {}

/// A converter takes one source's bytes and returns text or a reason.
///
/// The caller supplies the bytes, so the hash it records and the bytes
/// the converter consumed are one snapshot. Implementations must be
/// deterministic. The same input bytes under the same rules produce
/// byte-identical output.
pub trait Converter {
    /// Stable converter id.
    fn id(&self) -> &'static str;
    /// Converter version, part of the incremental checkpoint key.
    fn version(&self) -> &'static str;
    /// Converts one source from its bytes.
    fn convert(
        &self,
        source: &[u8],
        detected_format: &str,
    ) -> std::result::Result<Outcome, ConvertError>;
}

/// Normalizes text to the output contract.
///
/// CRLF and lone CR become LF, then the text is normalized to NFC.
/// NFC only. NFKC rewrites identifiers, so it is prohibited.
pub fn normalize_text(input: &str) -> String {
    let mut unified = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\r' {
            if chars.peek() == Some(&'\n') {
                chars.next();
            }
            unified.push('\n');
        } else {
            unified.push(c);
        }
    }
    unified.nfc().collect()
}

/// Passthrough for text-native formats.
///
/// Reads the source as plain text, validates UTF-8, strips a leading
/// byte order mark, and applies [`normalize_text`]. It parses nothing
/// and strips no markup.
pub struct PlainTextPassthrough;

/// Registry id of the passthrough converter.
pub const PASSTHROUGH_ID: &str = "text-passthrough";
/// Version of the passthrough converter.
pub const PASSTHROUGH_VERSION: &str = "1.0.0";

impl Converter for PlainTextPassthrough {
    fn id(&self) -> &'static str {
        PASSTHROUGH_ID
    }

    fn version(&self) -> &'static str {
        PASSTHROUGH_VERSION
    }

    fn convert(
        &self,
        source: &[u8],
        detected_format: &str,
    ) -> std::result::Result<Outcome, ConvertError> {
        let source_len = source.len();
        let raw = String::from_utf8(source.to_vec()).map_err(|e| ConvertError {
            code: "invalid_utf8",
            message: format!("invalid UTF-8 at byte {}", e.utf8_error().valid_up_to()),
        })?;
        let mut warnings = Vec::new();
        let raw = match raw.strip_prefix('\u{feff}') {
            Some(stripped) => {
                warnings.push("stripped leading byte order mark".to_string());
                stripped.to_string()
            }
            None => raw,
        };
        let text = normalize_text(&raw);
        if source_len > 0 && text.is_empty() {
            return Err(ConvertError {
                code: "empty_output",
                message: format!("source is {source_len} bytes but conversion produced no text"),
            });
        }
        let segments = vec![Segment::span(0, text.len(), "document")];
        Ok(Outcome {
            converter_id: PASSTHROUGH_ID.to_string(),
            converter_version: PASSTHROUGH_VERSION.to_string(),
            detected_format: detected_format.to_string(),
            text,
            warnings,
            segments,
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRegistry {
    version: String,
    converters: Vec<RawEntry>,
    #[serde(default)]
    unsupported: Vec<RawUnsupported>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEntry {
    id: String,
    version: String,
    formats: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawUnsupported {
    reason: String,
    formats: Vec<String>,
}

/// The converter registry from `rules/converters.toml`.
///
/// The registry is data. A rules bump is a visible versioned event,
/// and the pinned entry version must match the implementation, so a
/// code change cannot ship silently under an old version.
pub struct Registry {
    version: String,
    converters: Vec<Box<dyn Converter>>,
    by_format: HashMap<String, usize>,
    unsupported_reasons: HashMap<String, String>,
}

impl Registry {
    /// The registry compiled into the binary from `rules/converters.toml`.
    pub fn builtin() -> Result<Self> {
        Self::parse(
            include_str!("../../rules/converters.toml"),
            "converters.toml",
        )
    }

    /// Parses a registry and binds entries to implementations.
    pub fn parse(text: &str, name: &str) -> Result<Self> {
        let raw: RawRegistry = toml::from_str(text).map_err(|e| Error::Rules {
            name: name.to_string(),
            message: e.to_string(),
        })?;
        let mut converters: Vec<Box<dyn Converter>> = Vec::new();
        let mut by_format = HashMap::new();
        for entry in &raw.converters {
            let converter: Box<dyn Converter> = match entry.id.as_str() {
                PASSTHROUGH_ID => Box::new(PlainTextPassthrough),
                document::ANYDOC_ID => Box::new(AnydocDocument),
                workbook::WORKBOOK_ID => Box::new(WorkbookIr),
                subprocess::PDF_SUBPROCESS_ID => Box::new(PdfSubprocess),
                other => {
                    return Err(Error::Rules {
                        name: name.to_string(),
                        message: format!("unknown converter id {other:?}"),
                    });
                }
            };
            if entry.version != converter.version() {
                return Err(Error::Rules {
                    name: name.to_string(),
                    message: format!(
                        "converter {:?} pins version {:?} but the implementation is {:?}",
                        entry.id,
                        entry.version,
                        converter.version()
                    ),
                });
            }
            let index = converters.len();
            converters.push(converter);
            for format in &entry.formats {
                if by_format.insert(format.clone(), index).is_some() {
                    return Err(Error::Rules {
                        name: name.to_string(),
                        message: format!("format {format:?} claimed twice"),
                    });
                }
            }
        }
        let mut unsupported_reasons = HashMap::new();
        for entry in &raw.unsupported {
            for format in &entry.formats {
                if by_format.contains_key(format)
                    || unsupported_reasons
                        .insert(format.clone(), entry.reason.clone())
                        .is_some()
                {
                    return Err(Error::Rules {
                        name: name.to_string(),
                        message: format!("format {format:?} claimed twice"),
                    });
                }
            }
        }
        Ok(Registry {
            version: raw.version,
            converters,
            by_format,
            unsupported_reasons,
        })
    }

    /// The registry version, part of the run's rules version.
    pub fn version(&self) -> &str {
        &self.version
    }

    /// The converter that claims a format id, if any.
    pub fn converter_for(&self, format_id: &str) -> Option<&dyn Converter> {
        self.by_format
            .get(format_id)
            .map(|index| self.converters[*index].as_ref())
    }

    /// The declared reason a format is unsupported, when the registry
    /// names one, such as a spreadsheet format with no visibility
    /// reader yet.
    pub fn unsupported_reason(&self, format_id: &str) -> Option<&str> {
        self.unsupported_reasons.get(format_id).map(String::as_str)
    }

    /// A registry built directly from converter instances, for tests
    /// that need behavior no shipped converter exhibits, such as a
    /// panicking converter.
    #[cfg(test)]
    pub(crate) fn for_tests(
        version: &str,
        entries: Vec<(Box<dyn Converter>, Vec<&str>)>,
    ) -> Registry {
        let mut converters = Vec::new();
        let mut by_format = HashMap::new();
        for (converter, formats) in entries {
            let index = converters.len();
            converters.push(converter);
            for format in formats {
                by_format.insert(format.to_string(), index);
            }
        }
        Registry {
            version: version.to_string(),
            converters,
            by_format,
            unsupported_reasons: HashMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_converts_crlf_to_lf() {
        assert_eq!(normalize_text("a\r\nb\r\n"), "a\nb\n");
    }

    #[test]
    fn normalize_converts_lone_cr_to_lf() {
        assert_eq!(normalize_text("a\rb\r"), "a\nb\n");
        assert_eq!(normalize_text("a\r\rb"), "a\n\nb");
    }

    #[test]
    fn normalize_composes_to_nfc() {
        assert_eq!(normalize_text("cafe\u{301}"), "caf\u{e9}");
    }

    #[test]
    fn normalize_never_applies_nfkc() {
        assert_eq!(normalize_text("\u{fb01}le \u{2460}"), "\u{fb01}le \u{2460}");
    }

    #[test]
    fn passthrough_rejects_invalid_utf8() {
        let err = PlainTextPassthrough
            .convert(b"hello \xff world", "text")
            .unwrap_err();
        assert_eq!(err.code, "invalid_utf8");
    }

    #[test]
    fn passthrough_fails_on_suspiciously_empty_output() {
        let err = PlainTextPassthrough
            .convert("\u{feff}".as_bytes(), "text")
            .unwrap_err();
        assert_eq!(err.code, "empty_output");
    }

    #[test]
    fn passthrough_accepts_an_empty_source() {
        let outcome = PlainTextPassthrough.convert(b"", "text").unwrap();
        assert_eq!(outcome.text, "");
    }

    #[test]
    fn builtin_registry_claims_the_text_family() {
        let registry = Registry::builtin().unwrap();
        assert_eq!(registry.version(), "3");
        assert!(registry.converter_for("text").is_some());
        assert!(registry.converter_for("markdown").is_some());
        assert!(registry.converter_for("csv").is_some());
        assert!(registry.converter_for("pdf").is_some());
        assert_eq!(
            registry.converter_for("pdf").map(|c| c.id()),
            Some("pdf-subprocess")
        );
        assert!(registry.converter_for("docx").is_some());
        assert!(registry.converter_for("xlsx").is_some());
        assert!(registry.converter_for("html").is_none());
        assert!(registry.converter_for("xlsb").is_none());
        assert_eq!(
            registry.unsupported_reason("xlsb"),
            Some("hidden-visibility-unresolved")
        );
        assert_eq!(registry.unsupported_reason("png"), Some("engine-unpinned"));
        assert_eq!(registry.unsupported_reason("mp4"), Some("engine-unpinned"));
        assert_eq!(registry.unsupported_reason("html"), None);
    }

    #[test]
    fn registry_rejects_a_version_that_contradicts_the_implementation() {
        let toml = r#"
version = "1"

[[converters]]
id = "text-passthrough"
version = "9.9.9"
formats = ["text"]
"#;
        assert!(Registry::parse(toml, "converters.toml").is_err());
    }
}
