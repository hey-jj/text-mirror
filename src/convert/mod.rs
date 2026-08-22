//! The converter boundary and the plain text passthrough.
//!
//! Every converter returns the same outcome shape. The registry in
//! `rules/converters.toml` maps format ids to converters. A format no
//! converter claims is unsupported, with a declared reason or the
//! `no-converter` floor. A converter error or invalid
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

use crate::detect::RESERVED_FORMAT_IDS;
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
/// Reads the source as plain text and applies [`normalize_text`]. It
/// parses nothing and strips no markup. Input encoding is UTF-8, or
/// UTF-16 behind a required byte order mark: a leading `FF FE`
/// decodes as UTF-16LE and `FE FF` as UTF-16BE, the mark is consumed
/// before decoding, and the outcome carries a transcoding warning. A
/// UTF-32 mark fails closed with reason `unsupported-encoding`, an
/// odd trailing byte or unpaired surrogate fails with `invalid_utf16`
/// naming the byte offset, and a file with no mark must be valid
/// UTF-8. A leading UTF-8 byte order mark is stripped with a warning.
pub struct PlainTextPassthrough;

/// The floor reason for an unsupported record whose detected format
/// has no converter entry and no declared reason, including true
/// unknowns.
pub const NO_CONVERTER_REASON: &str = "no-converter";

/// Registry id of the passthrough converter.
pub const PASSTHROUGH_ID: &str = "text-passthrough";
/// Version of the passthrough converter.
pub const PASSTHROUGH_VERSION: &str = "1.1.0";

/// Decodes UTF-16 byte pairs after a consumed byte order mark.
///
/// `mark_len` is the consumed mark's length, so failure offsets name
/// positions in the original source bytes.
fn decode_utf16_pairs(
    bytes: &[u8],
    big_endian: bool,
    mark_len: usize,
) -> std::result::Result<String, ConvertError> {
    if bytes.len() % 2 != 0 {
        return Err(ConvertError {
            code: "invalid_utf16",
            message: format!("odd trailing byte at byte {}", mark_len + bytes.len() - 1),
        });
    }
    let units = bytes.chunks_exact(2).map(|pair| {
        if big_endian {
            u16::from_be_bytes([pair[0], pair[1]])
        } else {
            u16::from_le_bytes([pair[0], pair[1]])
        }
    });
    let mut decoded = String::with_capacity(bytes.len() / 2);
    let mut consumed_units = 0usize;
    for result in char::decode_utf16(units) {
        match result {
            Ok(c) => {
                decoded.push(c);
                consumed_units += c.len_utf16();
            }
            Err(_) => {
                return Err(ConvertError {
                    code: "invalid_utf16",
                    message: format!(
                        "unpaired surrogate at byte {}",
                        mark_len + consumed_units * 2
                    ),
                });
            }
        }
    }
    Ok(decoded)
}

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
        let mut warnings = Vec::new();
        // The four-byte UTF-32 marks come first, because the UTF-32LE
        // mark begins with the UTF-16LE one and would otherwise decode
        // as UTF-16 with interleaved NULs.
        let raw = if source.starts_with(&[0xFF, 0xFE, 0x00, 0x00])
            || source.starts_with(&[0x00, 0x00, 0xFE, 0xFF])
        {
            return Err(ConvertError {
                code: "unsupported-encoding",
                message: "utf-32 byte order mark".to_string(),
            });
        } else if let Some(rest) = source.strip_prefix(&[0xFF, 0xFE][..]) {
            warnings.push("transcoded from utf-16le".to_string());
            decode_utf16_pairs(rest, false, 2)?
        } else if let Some(rest) = source.strip_prefix(&[0xFE, 0xFF][..]) {
            warnings.push("transcoded from utf-16be".to_string());
            decode_utf16_pairs(rest, true, 2)?
        } else {
            let raw = String::from_utf8(source.to_vec()).map_err(|e| ConvertError {
                code: "invalid_utf8",
                message: format!("invalid UTF-8 at byte {}", e.utf8_error().valid_up_to()),
            })?;
            match raw.strip_prefix('\u{feff}') {
                Some(stripped) => {
                    warnings.push("stripped leading byte order mark".to_string());
                    stripped.to_string()
                }
                None => raw,
            }
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
                if RESERVED_FORMAT_IDS.contains(&format.as_str()) {
                    return Err(Error::Rules {
                        name: name.to_string(),
                        message: format!("format id {format:?} is reserved"),
                    });
                }
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
                if RESERVED_FORMAT_IDS.contains(&format.as_str()) {
                    return Err(Error::Rules {
                        name: name.to_string(),
                        message: format!("format id {format:?} is reserved"),
                    });
                }
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

    /// The reason a format is unsupported.
    ///
    /// A declared entry from the registry wins, such as a spreadsheet
    /// format with no visibility reader yet. Every other format no
    /// converter claims gets the generic floor
    /// [`NO_CONVERTER_REASON`], so an unsupported record is never
    /// reason-less. A format a converter claims returns `None`.
    pub fn unsupported_reason(&self, format_id: &str) -> Option<&str> {
        if self.by_format.contains_key(format_id) {
            return None;
        }
        Some(
            self.unsupported_reasons
                .get(format_id)
                .map(String::as_str)
                .unwrap_or(NO_CONVERTER_REASON),
        )
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

    fn utf16_bytes(text: &str, big_endian: bool) -> Vec<u8> {
        let mut bytes = if big_endian {
            vec![0xFE, 0xFF]
        } else {
            vec![0xFF, 0xFE]
        };
        for unit in text.encode_utf16() {
            bytes.extend_from_slice(&if big_endian {
                unit.to_be_bytes()
            } else {
                unit.to_le_bytes()
            });
        }
        bytes
    }

    #[test]
    fn passthrough_transcodes_utf16le_behind_a_byte_order_mark() {
        let source = utf16_bytes("a,b\r\n1,caf\u{e9}\r\n", false);
        let outcome = PlainTextPassthrough.convert(&source, "csv").unwrap();
        assert_eq!(outcome.text, "a,b\n1,caf\u{e9}\n");
        assert_eq!(
            outcome.warnings,
            vec!["transcoded from utf-16le".to_string()]
        );
    }

    #[test]
    fn passthrough_transcodes_utf16be_behind_a_byte_order_mark() {
        let source = utf16_bytes("total \u{5317}\u{4eac}\n", true);
        let outcome = PlainTextPassthrough.convert(&source, "text").unwrap();
        assert_eq!(outcome.text, "total \u{5317}\u{4eac}\n");
        assert_eq!(
            outcome.warnings,
            vec!["transcoded from utf-16be".to_string()]
        );
    }

    #[test]
    fn passthrough_refuses_utf32_byte_order_marks() {
        for source in [
            b"\xFF\xFE\x00\x00A\x00\x00\x00".as_slice(),
            b"\x00\x00\xFE\xFF\x00\x00\x00A".as_slice(),
        ] {
            let err = PlainTextPassthrough.convert(source, "text").unwrap_err();
            assert_eq!(err.code, "unsupported-encoding");
            assert!(err.to_string().starts_with("unsupported-encoding: utf-32"));
        }
    }

    #[test]
    fn passthrough_fails_an_odd_utf16_tail_at_its_offset() {
        let err = PlainTextPassthrough
            .convert(b"\xFF\xFEA\x00B", "text")
            .unwrap_err();
        assert_eq!(err.code, "invalid_utf16");
        assert_eq!(err.message, "odd trailing byte at byte 4");
    }

    #[test]
    fn passthrough_fails_an_unpaired_surrogate_at_its_offset() {
        let err = PlainTextPassthrough
            .convert(b"\xFF\xFEA\x00\x00\xD8", "text")
            .unwrap_err();
        assert_eq!(err.code, "invalid_utf16");
        assert_eq!(err.message, "unpaired surrogate at byte 4");
    }

    #[test]
    fn passthrough_still_fails_bomless_utf16_as_invalid_utf8() {
        let mut source = utf16_bytes("R\u{e9}sum\u{e9}\n", false);
        source.drain(..2);
        let err = PlainTextPassthrough.convert(&source, "text").unwrap_err();
        assert_eq!(err.code, "invalid_utf8");
    }

    #[test]
    fn builtin_registry_claims_the_text_family() {
        let registry = Registry::builtin().unwrap();
        assert_eq!(registry.version(), "4");
        assert!(registry.converter_for("json").is_some());
        assert!(registry.converter_for("yaml").is_some());
        assert!(registry.converter_for("svg").is_some());
        assert!(registry.converter_for("ipynb").is_some());
        assert!(registry.converter_for("python").is_some());
        assert!(registry.converter_for("pickle").is_none());
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
        assert_eq!(
            registry.unsupported_reason("pickle"),
            Some("pickle-deserialization-unsafe")
        );
        assert_eq!(registry.unsupported_reason("webp"), Some("engine-unpinned"));
        assert_eq!(
            registry.unsupported_reason("parquet"),
            Some("converter-deferred")
        );
        assert_eq!(
            registry.unsupported_reason("tar"),
            Some("container-deferred")
        );
        assert_eq!(
            registry.unsupported_reason("psd"),
            Some("proprietary-binary")
        );
        // The floor: a format nothing claims and nothing declares.
        assert_eq!(
            registry.unsupported_reason("unknown"),
            Some(NO_CONVERTER_REASON)
        );
        // A claimed format has no unsupported reason.
        assert_eq!(registry.unsupported_reason("text"), None);
        assert_eq!(registry.unsupported_reason("png"), Some("engine-unpinned"));
        assert_eq!(registry.unsupported_reason("mp4"), Some("engine-unpinned"));
        // html is detected but unclaimed until a strip converter
        // lands, so it sits on the floor, not outside the vocabulary.
        assert_eq!(
            registry.unsupported_reason("html"),
            Some(NO_CONVERTER_REASON)
        );
    }

    #[test]
    fn registry_rejects_reserved_format_ids() {
        for (section, id) in [
            ("converters", "symlink"),
            ("converters", "unknown"),
            ("unsupported", "symlink"),
            ("unsupported", "unknown"),
        ] {
            let toml = if section == "converters" {
                format!(
                    "version = \"1\"\n[[converters]]\nid = \"text-passthrough\"\nversion = \"1.1.0\"\nformats = [\"{id}\"]\n"
                )
            } else {
                format!(
                    "version = \"1\"\nconverters = []\n[[unsupported]]\nreason = \"r\"\nformats = [\"{id}\"]\n"
                )
            };
            let err = match Registry::parse(&toml, "converters.toml") {
                Ok(_) => panic!("{section} {id}: reserved id was accepted"),
                Err(e) => e,
            };
            assert!(
                err.to_string().contains("reserved"),
                "{section} {id}: {err}"
            );
        }
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
