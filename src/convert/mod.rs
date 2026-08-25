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

/// Ceilings for the records worker, held as rules data beside the
/// container limits so a deployment raises them in a visible versioned
/// bump. The parent reads them from the registry and passes them into
/// the jailed worker, which enforces them and fails a source over any
/// ceiling with reason `record-limit-exceeded`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordsLimits {
    /// Records per parquet or avro file, and per sqlite table.
    pub max_records: u64,
    /// Tables per sqlite database.
    pub max_tables: u64,
    /// Rendered output bytes. Under the runner's response cap.
    pub max_output_bytes: u64,
}

impl Default for RecordsLimits {
    fn default() -> RecordsLimits {
        RecordsLimits {
            max_records: 100_000,
            max_tables: 256,
            max_output_bytes: 64 * 1024 * 1024,
        }
    }
}

/// The image-OCR jail limit profile, held as rules data beside the
/// records ceilings so a deployment raises it in a visible versioned
/// bump. The default runner limits are tuned for the pure-Rust
/// document worker; the pinned vision runtime maps a far larger
/// working set, so the image-OCR converter carries its own envelope.
/// The registry reads this into the converter, which maps it into the
/// runner limits its jailed worker enforces.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageOcrLimits {
    /// Wall-clock ceiling for one image, in seconds.
    pub wall_timeout_secs: u64,
    /// Ceiling on the response frame payload, in bytes.
    pub max_response_bytes: u32,
    /// Ceiling on stderr bytes.
    pub max_stderr_bytes: u64,
    /// RLIMIT_AS for the child, in bytes. Linux only.
    pub address_space_bytes: u64,
    /// RLIMIT_CPU for the child, in seconds.
    pub cpu_seconds: u64,
    /// RLIMIT_FSIZE for the child, in bytes.
    pub file_size_bytes: u64,
    /// RLIMIT_NPROC for the child.
    pub max_processes: u64,
}

impl Default for ImageOcrLimits {
    fn default() -> ImageOcrLimits {
        ImageOcrLimits {
            wall_timeout_secs: 300,
            max_response_bytes: 8 * 1024 * 1024,
            max_stderr_bytes: 4 * 1024 * 1024,
            address_space_bytes: 64 * 1024 * 1024 * 1024,
            cpu_seconds: 600,
            file_size_bytes: 64 * 1024 * 1024,
            max_processes: 64,
        }
    }
}

/// The image-metadata parser ceilings, held as rules data beside the
/// records ceilings so a deployment raises them in a visible versioned
/// bump. The parent reads them from the registry and passes them into
/// the jailed worker, which enforces them and fails a source over any
/// ceiling with a stable `image-metadata-*` reason. The metadata worker
/// runs behind the shared platform-default jail, so these are the
/// parser-surface ceilings only, not the wall-clock and address-space
/// envelope the runner already imposes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageMetadataLimits {
    /// Inflated-size ceiling for any single compressed text block, the
    /// png `zTXt` and compressed `iTXt` streams above all. Checked
    /// incrementally during inflation so a decompression bomb is stopped
    /// before it lands.
    pub max_decompressed_bytes: u64,
    /// Nesting-depth ceiling for an xmp parse.
    pub max_xml_depth: u32,
    /// Event-count ceiling for an xmp parse.
    pub max_xml_events: u64,
    /// Box-count ceiling for an iso base media file format carrier.
    pub max_boxes: u64,
    /// Ceiling on emitted metadata rows across all surfaces.
    pub max_rows: u64,
    /// Ceiling on the rendered value bytes, under the runner response
    /// cap.
    pub max_output_bytes: u64,
}

impl Default for ImageMetadataLimits {
    fn default() -> ImageMetadataLimits {
        ImageMetadataLimits {
            max_decompressed_bytes: 16 * 1024 * 1024,
            max_xml_depth: 100,
            max_xml_events: 1_000_000,
            max_boxes: 10_000,
            max_rows: 4096,
            max_output_bytes: 16 * 1024 * 1024,
        }
    }
}

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization;

use crate::detect::RESERVED_FORMAT_IDS;
use crate::segments::Segment;
use crate::{Error, Result};

mod anydoc_log;
pub mod container;
mod differential;
mod document;
pub mod eml;
pub mod html;
pub mod pdf;
// The parquet, avro, and sqlite readers. Compiled only for the records
// worker, so a default build pulls none of the heavy parser trees.
// Crate-private, so a library consumer cannot run the native parsers in
// process and bypass the jail. The worker dispatch reaches it through a
// crate path.
#[cfg(all(unix, feature = "records-worker"))]
pub(crate) mod records;
// The in-jail raster decode and recognize path. Crate-private for the
// same reason records is: a library consumer must not run the decode
// and engine path in process and bypass the jail. The worker dispatch
// reaches it through a crate path.
#[cfg(all(unix, feature = "image-ocr"))]
pub(crate) mod image_ocr;
// The image-metadata derived-child leg. The id, version, and the
// applies predicate are always compiled so the registry and pipeline can
// name the leg; the parsers and the parent rendering compile only under
// the feature, crate-private for the same reason records is: a library
// consumer must not run the parsers in process and bypass the jail.
pub mod image_metadata;
pub mod subprocess;
mod visibility;
mod workbook;

pub use container::{
    CONTAINER_ZIP_ID, CONTAINER_ZIP_VERSION, ContainerLimits, Inflated, ZipContainer,
    preflight_entry_count,
};
pub use differential::{
    DiffMetrics, DiffVerdict, DifferentialOutcome, compare_texts, normalize_for_diff,
};
pub use document::{AnydocDocument, markdown_to_plain};
pub use eml::{EmlExpansion, EmlMime, expand_eml};
pub use html::HtmlStrip;
pub use subprocess::{PdfSubprocess, RecordsSubprocess};
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
    /// How the text was derived. Every text and structured converter
    /// sets [`ArtifactKind::Text`]; the pixel-OCR converter sets
    /// [`ArtifactKind::Ocr`], so the manifest records recognized text
    /// as OCR rather than extraction.
    pub artifact_kind: crate::manifest::ArtifactKind,
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

/// Invisible format characters: code points that render nothing yet are
/// neither whitespace nor control characters, so a bare emptiness check
/// would let them through. The set is the soft hyphen, the zero-width
/// and bidi marks (`U+200B`–`U+200F`), the bidi overrides and embeddings
/// (`U+202A`–`U+202E`), the word joiner and invisible-operator block
/// (`U+2060`–`U+2064`), and the byte-order mark (`U+FEFF`). Text whose
/// only characters are these carries nothing a reader would see. The set
/// is a documented minimum and is not narrowed; whitespace and control
/// characters are handled separately by [`is_meaningful`], so the two
/// together cover the empty-render cases.
pub(crate) fn is_invisible_format(c: char) -> bool {
    matches!(
        c as u32,
        0x00AD | 0x200B..=0x200F | 0x202A..=0x202E | 0x2060..=0x2064 | 0xFEFF
    )
}

/// Whether a character is meaningful content: something a reader would
/// see on the page. Whitespace, control characters, and invisible format
/// characters are not. This is the shared meaningful-text floor: the PDF
/// recovery path and the image-OCR converter both gate on the presence
/// of at least one such character, so a well-formed but content-free
/// result fails closed rather than passing as a blank success.
pub(crate) fn is_meaningful(c: char) -> bool {
    !c.is_whitespace() && !c.is_control() && !is_invisible_format(c)
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
/// A NUL scalar anywhere in the decoded text fails closed with reason
/// `nul_bytes`, because text-native content never holds one and the
/// usual culprit is a BOM-less UTF-16 export.
pub struct PlainTextPassthrough;

/// The floor reason for an unsupported record whose detected format
/// has no converter entry and no declared reason, including true
/// unknowns.
pub const NO_CONVERTER_REASON: &str = "no-converter";

/// The reason a records format records on a build without the
/// `records-worker` feature. The converter exists and the rules route
/// to it, but this binary's worker has no records mode, so the format
/// is a deliberate capability gap rather than a converter error.
pub const RECORDS_NOT_BUILT_REASON: &str = "records-worker-not-built";

/// The reason raster-image formats record on a build without the
/// `image-ocr` feature, or on a platform with no jail backend. The
/// converter exists and the rules route to it, but this binary has no
/// in-jail decode-plus-recognize path, so the format is a deliberate
/// capability gap rather than a converter error. The checkpoint key
/// includes `rules_version`, so a later feature-carrying build
/// reconverts every such record.
pub const IMAGE_OCR_NOT_BUILT_REASON: &str = "image-ocr-not-built";

/// Registry id of the passthrough converter.
pub const PASSTHROUGH_ID: &str = "text-passthrough";
/// Version of the passthrough converter.
pub const PASSTHROUGH_VERSION: &str = "1.2.0";

/// Decodes UTF-16 byte pairs after a consumed byte order mark.
///
/// `mark_len` is the consumed mark's length, so failure offsets name
/// positions in the original source bytes.
fn decode_utf16_pairs(
    bytes: &[u8],
    big_endian: bool,
    mark_len: usize,
) -> std::result::Result<String, ConvertError> {
    if !bytes.len().is_multiple_of(2) {
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
        // Legitimate text-native content carries no NUL, and the
        // common way one appears is a BOM-less UTF-16 export whose
        // ASCII half happens to be valid UTF-8. Refuse instead of
        // emitting NUL-split tokens.
        if let Some(offset) = raw.find('\0') {
            return Err(ConvertError {
                code: "nul_bytes",
                message: format!(
                    "NUL at byte {offset} of the decoded text, the bytes may be \
                     BOM-less UTF-16, re-export as UTF-8"
                ),
            });
        }
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
            artifact_kind: crate::manifest::ArtifactKind::Text,
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
    #[serde(default)]
    containers: Option<ContainerLimits>,
    #[serde(default)]
    records: Option<RecordsLimits>,
    #[serde(default)]
    image_ocr: Option<ImageOcrLimits>,
    #[serde(default)]
    image_metadata: Option<ImageMetadataLimits>,
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
    container_limits: ContainerLimits,
    records_limits: RecordsLimits,
    image_ocr_limits: ImageOcrLimits,
    image_metadata_limits: ImageMetadataLimits,
    /// Index into `converters` of the auxiliary image-metadata converter,
    /// which never enters `by_format`. The pipeline reaches it by this
    /// index to run the derived-child leg. `None` when the feature is
    /// absent, so the leg simply does not run.
    image_metadata_index: Option<usize>,
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
        let records_limits = raw.records.clone().unwrap_or_default();
        let image_ocr_limits = raw.image_ocr.clone().unwrap_or_default();
        let image_metadata_limits = raw.image_metadata.clone().unwrap_or_default();
        let mut converters: Vec<Box<dyn Converter>> = Vec::new();
        let mut by_format = HashMap::new();
        let mut unsupported_reasons = HashMap::new();
        // Reassigned only under the feature; without it the auxiliary
        // converter is never constructed and the index stays absent.
        #[allow(unused_mut)]
        let mut image_metadata_index: Option<usize> = None;
        for entry in &raw.converters {
            // A build without the records-worker feature has no records
            // mode in its worker, so route the records formats to a
            // deliberate unsupported reason instead of a converter that
            // would spawn a worker unable to serve them. The rules stay
            // one shared file: the routing decision is made here at
            // construction, not by forking the rules.
            #[cfg(not(feature = "records-worker"))]
            if entry.id == subprocess::RECORDS_SUBPROCESS_ID {
                for format in &entry.formats {
                    if RESERVED_FORMAT_IDS.contains(&format.as_str()) {
                        return Err(Error::Rules {
                            name: name.to_string(),
                            message: format!("format id {format:?} is reserved"),
                        });
                    }
                    if by_format.contains_key(format)
                        || unsupported_reasons
                            .insert(format.clone(), RECORDS_NOT_BUILT_REASON.to_string())
                            .is_some()
                    {
                        return Err(Error::Rules {
                            name: name.to_string(),
                            message: format!("format {format:?} claimed twice"),
                        });
                    }
                }
                continue;
            }
            // A build without the in-jail image decode path, or a
            // platform with no jail backend, has no way to decode and
            // recognize a raster, so route the image formats to a
            // deliberate unsupported reason instead of a converter that
            // cannot serve them. The rules stay one shared file: the
            // routing decision is made here at construction.
            #[cfg(not(all(unix, feature = "image-ocr")))]
            if entry.id == subprocess::IMAGE_PIXEL_OCR_ID {
                for format in &entry.formats {
                    if RESERVED_FORMAT_IDS.contains(&format.as_str()) {
                        return Err(Error::Rules {
                            name: name.to_string(),
                            message: format!("format id {format:?} is reserved"),
                        });
                    }
                    if by_format.contains_key(format)
                        || unsupported_reasons
                            .insert(format.clone(), IMAGE_OCR_NOT_BUILT_REASON.to_string())
                            .is_some()
                    {
                        return Err(Error::Rules {
                            name: name.to_string(),
                            message: format!("format {format:?} claimed twice"),
                        });
                    }
                }
                continue;
            }
            // The image-metadata converter is auxiliary and claims no
            // formats. Without the in-jail metadata reader, or on a
            // platform with no jail backend, the derived-child leg cannot
            // run; there are no formats to route to a not-built reason, so
            // the entry is simply skipped. The pipeline reads
            // `image_metadata_converter()` as absent and never runs the
            // leg.
            #[cfg(not(all(unix, feature = "image-metadata")))]
            if entry.id == image_metadata::IMAGE_METADATA_ID {
                continue;
            }
            let converter: Box<dyn Converter> = match entry.id.as_str() {
                PASSTHROUGH_ID => Box::new(PlainTextPassthrough),
                html::HTML_STRIP_ID => Box::new(HtmlStrip),
                eml::EML_ID => Box::new(EmlMime),
                document::ANYDOC_ID => Box::new(AnydocDocument),
                workbook::WORKBOOK_ID => Box::new(WorkbookIr),
                subprocess::PDF_SUBPROCESS_ID => Box::new(PdfSubprocess),
                subprocess::RECORDS_SUBPROCESS_ID => {
                    Box::new(RecordsSubprocess::new(records_limits.clone()))
                }
                #[cfg(all(unix, feature = "image-ocr"))]
                subprocess::IMAGE_PIXEL_OCR_ID => {
                    Box::new(subprocess::ImagePixelOcr::new(image_ocr_limits.clone()))
                }
                #[cfg(all(unix, feature = "image-metadata"))]
                image_metadata::IMAGE_METADATA_ID => Box::new(subprocess::ImageMetadata::new(
                    image_metadata_limits.clone(),
                )),
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
            #[cfg(all(unix, feature = "image-metadata"))]
            if entry.id == image_metadata::IMAGE_METADATA_ID {
                image_metadata_index = Some(index);
            }
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
            container_limits: raw.containers.unwrap_or_default(),
            records_limits,
            image_ocr_limits,
            image_metadata_limits,
            image_metadata_index,
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

    /// The container expansion limits from the rules.
    pub fn container_limits(&self) -> &ContainerLimits {
        &self.container_limits
    }

    /// The records worker ceilings from the rules.
    pub fn records_limits(&self) -> &RecordsLimits {
        &self.records_limits
    }

    /// The image-OCR jail limit profile from the rules.
    pub fn image_ocr_limits(&self) -> &ImageOcrLimits {
        &self.image_ocr_limits
    }

    /// The image-metadata parser ceilings from the rules.
    pub fn image_metadata_limits(&self) -> &ImageMetadataLimits {
        &self.image_metadata_limits
    }

    /// Test-only: drives the image formats through the fake-engine
    /// image-OCR adapter instead of the pinned-runtime one, so a pipeline
    /// test can compose a succeeding primary leg with the metadata leg.
    /// The shared decode, area guards, and outcome mapping are the
    /// production ones; only the recognition stage is the fake. A release
    /// build has no such hook.
    #[cfg(all(unix, feature = "image-ocr", feature = "test-adapters"))]
    pub fn use_fake_image_ocr(&mut self) {
        if let Some(index) = self
            .converters
            .iter()
            .position(|c| c.id() == subprocess::IMAGE_PIXEL_OCR_ID)
        {
            self.converters[index] = Box::new(subprocess::ImagePixelOcr::new_fake(
                self.image_ocr_limits.clone(),
            ));
        }
    }

    /// The auxiliary image-metadata converter, if the feature built one.
    /// It never enters `by_format`, so the pipeline reaches it here to
    /// run the derived-child leg. `None` means the leg does not run.
    pub fn image_metadata_converter(&self) -> Option<&dyn Converter> {
        self.image_metadata_index
            .map(|index| self.converters[index].as_ref())
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
            container_limits: ContainerLimits::default(),
            records_limits: RecordsLimits::default(),
            image_ocr_limits: ImageOcrLimits::default(),
            image_metadata_limits: ImageMetadataLimits::default(),
            image_metadata_index: None,
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
    fn passthrough_refuses_nul_bytes_with_the_first_offset() {
        let err = PlainTextPassthrough
            .convert(b"ab\0cd\0", "text")
            .unwrap_err();
        assert_eq!(err.code, "nul_bytes");
        assert!(err.message.contains("byte 2"), "{}", err.message);
        assert!(err.message.contains("BOM-less UTF-16"), "{}", err.message);
        // The decoded path gets the same check: a UTF-16 file whose
        // decoded text holds a NUL fails too.
        let err = PlainTextPassthrough
            .convert(b"\xFF\xFEA\x00\x00\x00B\x00", "text")
            .unwrap_err();
        assert_eq!(err.code, "nul_bytes");
        assert!(err.message.contains("byte 1"), "{}", err.message);
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
        assert_eq!(registry.version(), "9");
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
        assert_eq!(
            registry.converter_for("html").map(|c| c.id()),
            Some("html-strip")
        );
        assert_eq!(
            registry.converter_for("eml").map(|c| c.id()),
            Some("eml-mime")
        );
        assert!(registry.converter_for("msg").is_none());
        assert!(registry.converter_for("xlsb").is_none());
        assert_eq!(
            registry.unsupported_reason("xlsb"),
            Some("hidden-visibility-unresolved")
        );
        assert_eq!(
            registry.unsupported_reason("pickle"),
            Some("pickle-deserialization-unsafe")
        );
        // png, jpeg, and webp are claimed by the image-pixel-ocr
        // converter now (the image-ocr feature is on under test), so
        // they carry no unsupported reason. tiff stays engine-unpinned:
        // the in-jail decoder deliberately excludes it.
        for format in ["png", "jpeg", "webp"] {
            assert_eq!(
                registry.converter_for(format).map(|c| c.id()),
                Some("image-pixel-ocr"),
                "{format}"
            );
            assert_eq!(registry.unsupported_reason(format), None, "{format}");
        }
        assert_eq!(registry.unsupported_reason("tiff"), Some("engine-unpinned"));
        // heic cannot be decoded by the pure-Rust jail path and fails
        // closed until the opt-in external provider is built.
        assert_eq!(
            registry.unsupported_reason("heic"),
            Some("no-jailed-rasterizer")
        );
        // ai routes to the pdf path: a PDF-backed .ai keeps its text
        // layer, and a legacy PostScript-backed .ai fails closed with a
        // pdf-family reason rather than as an unknown format.
        assert_eq!(
            registry.converter_for("ai").map(|c| c.id()),
            Some("pdf-subprocess")
        );
        // Parquet, avro, and sqlite are claimed by the records worker
        // now, so they carry no unsupported reason. arrow and the rest
        // stay deferred.
        for format in ["parquet", "avro", "sqlite"] {
            assert_eq!(
                registry.converter_for(format).map(|c| c.id()),
                Some("records-worker"),
                "{format}"
            );
            assert_eq!(registry.unsupported_reason(format), None, "{format}");
        }
        assert_eq!(
            registry.unsupported_reason("arrow"),
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
        assert_eq!(registry.unsupported_reason("mp4"), Some("engine-unpinned"));
        // html is claimed now, and msg stays on the floor: it is a
        // compound file, not an RFC 822 message.
        assert_eq!(registry.unsupported_reason("html"), None);
        assert_eq!(
            registry.unsupported_reason("msg"),
            Some(NO_CONVERTER_REASON)
        );
    }

    // The raster family routes to a live converter when the `image-ocr`
    // feature is built with a jail backend, and to a deliberate
    // `image-ocr-not-built` capability gap otherwise. Both arms are
    // asserted here through a runtime branch, so both compile in every
    // configuration and neither rots. The self dev-dependency turns the
    // feature on for the normal suite, so `cargo test` runs the feature-
    // present arm; the feature-absent arm runs whenever the crate is
    // built without the feature, which is a documented CI step:
    //
    //   cargo test --no-default-features -p text-mirror   # crate built
    //   without the self dev-dependency, so the feature is genuinely off
    //
    // The unsupported reason itself is asserted directly regardless of
    // configuration so the not-built plumbing never goes untested.
    #[test]
    fn the_raster_family_routes_by_the_image_ocr_feature() {
        let registry = Registry::builtin().unwrap();
        let feature_present = cfg!(all(unix, feature = "image-ocr"));
        for format in ["png", "jpeg", "webp"] {
            if feature_present {
                // A live converter claims the format, so it carries no
                // unsupported reason.
                assert!(registry.converter_for(format).is_some(), "{format}");
                assert_eq!(registry.unsupported_reason(format), None, "{format}");
            } else {
                // A deliberate capability gap: no converter, and the
                // not-built reason rather than a converter error.
                assert!(registry.converter_for(format).is_none(), "{format}");
                assert_eq!(
                    registry.unsupported_reason(format),
                    Some(IMAGE_OCR_NOT_BUILT_REASON),
                    "{format}"
                );
            }
        }
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
                    "version = \"1\"\n[[converters]]\nid = \"text-passthrough\"\nversion = \"1.2.0\"\nformats = [\"{id}\"]\n"
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
