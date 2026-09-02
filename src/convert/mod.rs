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
    /// Expected BLAKE3 per pinned runtime role, keyed by the generic
    /// role label. The deployment supplies the paths through the
    /// runtime-inventory config; the cold worker re-hashes every file
    /// against these values immediately before use. Empty when no
    /// runtime is pinned in the rules, which leaves recognition on its
    /// fail-closed runtime-missing path.
    #[serde(default)]
    pub inventory: std::collections::BTreeMap<String, String>,
    /// The svg provider pins, keyed by the two provider role labels:
    /// the expected BLAKE3, the exact version, and, for the rasterizer,
    /// the aggregate digest over its executable closure. Rules data,
    /// like every other pinned expectation; the deployment supplies only
    /// paths and jail parameters through the provider configuration.
    /// Empty when the rules pin no provider, which leaves the svg leg
    /// unconfigurable.
    #[serde(default)]
    pub svg_provider: std::collections::BTreeMap<String, provider::ProviderPin>,
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
            inventory: std::collections::BTreeMap::new(),
            svg_provider: std::collections::BTreeMap::new(),
        }
    }
}

/// The ruled encoder-input area cap: 1536 * 1536 = 2.36 MP, the
/// validated-safe ceiling. Applied uniformly to every image fed to the
/// engine, because the hazard is encoder-side and degenerates on
/// oversized area, not on any single dimension.
pub const IMAGE_OCR_MAX_AREA_PX: u64 = 2_359_296;

/// The largest single edge the engine was validated against. An input
/// under the area cap but with a longer edge is legal by area and must
/// not fail; it logs one note for validation and proceeds.
pub const IMAGE_OCR_VALIDATED_LONG_EDGE: u32 = 1600;

/// Decode-time allocation guard: one layer of a layered containment,
/// not a single invariant. Three independent limits bound this path.
/// The parent's source-bytes ceiling bounds the bytes that stage into
/// the jail; this guard bounds the decoder's working pixel buffers; and
/// the area cap bounds the encoder input. This guard's job is only the
/// middle layer: it caps the decoder against a decompression bomb whose
/// declared dimensions the area preflight has not yet seen. The largest
/// in-scope raster is the area cap at 4 bytes per pixel, about 9 MiB, so
/// this value leaves room for the decoded buffer plus codec scratch
/// while refusing a bomb demanding hundreds of megabytes. It is not the
/// jail's address-space limit and not the area cap; each of the three
/// fails closed on its own.
pub const IMAGE_OCR_DECODE_ALLOC: u64 = 64 * 1024 * 1024;

/// The pinned-runtime role labels of the image-OCR path: the engine
/// binary, its weights, the projector, the fixed prompt, and the
/// serialized limit policy. Generic labels only; the identities behind
/// them are deployment data bound by hash.
pub(crate) const IMAGE_OCR_ROLE_LABELS: [&str; 5] = [
    "engine-cli",
    "vision-weights",
    "vision-projector",
    "ocr-prompt",
    "ocr-limit-policy",
];

/// The speech-transcription jail limit profile and pinned runtime
/// hashes, held as rules data beside the image-OCR profile so a
/// deployment changes them only in a visible versioned bump. Every
/// number is a containment ceiling measured for the pinned engine on
/// the pinned machine class. The registry reads this into the audio
/// converter, which maps it into the runner limits its jailed worker
/// enforces and sends the decoded-duration ceiling into the jail.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AsrProfile {
    /// Decoded-duration ceiling in seconds, asserted in-jail from the
    /// decoded frame count with a small priming allowance. Over the
    /// ceiling fails closed with `asr-duration-exceeded`, never
    /// truncation.
    pub max_duration_seconds: u64,
    /// Wall-clock ceiling for one source, in seconds.
    pub wall_timeout_secs: u64,
    /// RLIMIT_CPU for the child, in seconds. The second backstop
    /// behind the accelerator preflight: a run that fell back to CPU
    /// burns through it long before the wall clock.
    pub cpu_seconds: u64,
    /// Parent-side ceiling on the aggregate resident bytes of the
    /// worker's whole process group, engine child included.
    pub max_resident_bytes: u64,
    /// Ceiling on the response frame payload, in bytes.
    pub max_response_bytes: u32,
    /// Ceiling on stderr bytes.
    pub max_stderr_bytes: u64,
    /// RLIMIT_FSIZE for the child, in bytes. Sits above the decoded
    /// size preflight, so the preflight is the arbiter and this only
    /// backstops it.
    pub file_size_bytes: u64,
    /// RLIMIT_NPROC for the child.
    pub max_processes: u64,
    /// The pinned transcription language. The built-in decode policy
    /// pins `en`, and rules parsing refuses any other value.
    pub language: String,
    /// Expected BLAKE3 per pinned runtime role, keyed by the generic
    /// role label. `asr-cli`, `asr-weights`, and `asr-decode-policy`
    /// must be present; `asr-probe` is accepted and pinned in the
    /// built-in rules, and a required role whose pin a rules file
    /// omits fails the engine path closed in the worker as
    /// runtime-missing rather than parsing as an invented identity.
    /// The deployment supplies the file paths through the runtime
    /// inventory config; the cold worker re-hashes every file against
    /// these values immediately before preflight and execution.
    pub inventory: std::collections::BTreeMap<String, String>,
}

/// Whether a string is a lowercase hex BLAKE3.
fn is_lower_hex_256(value: &str) -> bool {
    value.len() == 64
        && value
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
}

/// Validates the `[asr]` rules section: the pinned language, the
/// known roles only with the three pinned ones present, lowercase hex
/// hashes, and an `asr-decode-policy` value that matches the
/// serialization built into the adapter, so the rules cannot silently
/// disagree with the code. The probe role is allowed but not
/// required: the built-in rules pin it, a custom profile may omit
/// it, and a required runtime role with no pinned hash fails closed
/// in the worker as runtime-missing rather than parsing as an
/// invented identity here.
fn validate_asr_profile(profile: &AsrProfile, name: &str) -> Result<()> {
    let rules_error = |message: String| Error::Rules {
        name: name.to_string(),
        message,
    };
    if profile.language != "en" {
        return Err(rules_error(format!(
            "[asr] language {:?} is not supported: the built-in decode policy pins \"en\"",
            profile.language
        )));
    }
    let required_roles = [
        subprocess::ASR_ROLE_CLI,
        subprocess::ASR_ROLE_WEIGHTS,
        subprocess::ASR_ROLE_DECODE_POLICY,
    ];
    let allowed_roles = [
        subprocess::ASR_ROLE_CLI,
        subprocess::ASR_ROLE_WEIGHTS,
        subprocess::ASR_ROLE_DECODE_POLICY,
        subprocess::ASR_ROLE_PROBE,
    ];
    for role in required_roles {
        if !profile.inventory.contains_key(role) {
            return Err(rules_error(format!(
                "[asr.inventory] is missing role {role:?}"
            )));
        }
    }
    for (role, hash) in &profile.inventory {
        if !allowed_roles.contains(&role.as_str()) {
            return Err(rules_error(format!(
                "[asr.inventory] names unknown role {role:?}"
            )));
        }
        if !is_lower_hex_256(hash) {
            return Err(rules_error(format!(
                "[asr.inventory] role {role:?} is not a lowercase hex BLAKE3"
            )));
        }
    }
    let built_in = crate::hash::hash_bytes(subprocess::ASR_DECODE_POLICY.as_bytes());
    if profile.inventory[subprocess::ASR_ROLE_DECODE_POLICY] != built_in {
        return Err(rules_error(
            "[asr.inventory] asr-decode-policy does not match the built-in decode \
             serialization"
                .to_string(),
        ));
    }
    Ok(())
}

/// Validates the `[image_ocr]` inventory keys against the known role
/// labels and requires lowercase hex hashes.
fn validate_image_ocr_limits(limits: &ImageOcrLimits, name: &str) -> Result<()> {
    provider::validate_pins(&limits.svg_provider).map_err(|message| Error::Rules {
        name: name.to_string(),
        message,
    })?;
    for (role, hash) in &limits.inventory {
        if !IMAGE_OCR_ROLE_LABELS.contains(&role.as_str()) {
            return Err(Error::Rules {
                name: name.to_string(),
                message: format!("[image_ocr.inventory] names unknown role {role:?}"),
            });
        }
        if !is_lower_hex_256(hash) {
            return Err(Error::Rules {
                name: name.to_string(),
                message: format!(
                    "[image_ocr.inventory] role {role:?} is not a lowercase hex BLAKE3"
                ),
            });
        }
    }
    Ok(())
}

/// Deployment-side mapping from a pinned runtime role label to the
/// file that fills it. Paths are deployment data and never enter the
/// versioned rules: the expected hashes live in the rules, and the
/// jailed worker re-hashes every supplied file against them
/// immediately before use, so a swap after parent-side validation
/// still fails closed. Roles are validated against the known label
/// set, so a typo fails loudly instead of silently leaving a role
/// unfilled.
#[derive(Debug, Clone, Default)]
pub struct RuntimeInventory {
    paths: std::collections::BTreeMap<String, std::path::PathBuf>,
}

impl RuntimeInventory {
    /// An inventory with no roles filled: every engine path stays on
    /// its fail-closed runtime-missing seam.
    pub fn empty() -> RuntimeInventory {
        RuntimeInventory::default()
    }

    /// Every role label a deployment may fill.
    pub fn known_roles() -> impl Iterator<Item = &'static str> {
        IMAGE_OCR_ROLE_LABELS
            .into_iter()
            .chain(subprocess::ASR_FILE_ROLE_LABELS)
    }

    /// Fills one role with the absolute path of a literal regular
    /// file. A directory or a symlink is refused here, before it can
    /// become a broader jail capability, and the spawn path re-asserts
    /// the same rule right before every run.
    pub fn set(&mut self, role: &str, path: std::path::PathBuf) -> Result<()> {
        let rules_error = |message: String| Error::Rules {
            name: "runtime-inventory".to_string(),
            message,
        };
        if !Self::known_roles().any(|known| known == role) {
            return Err(rules_error(format!("unknown runtime role {role:?}")));
        }
        if !path.is_absolute() {
            return Err(rules_error(format!(
                "runtime role {role:?} needs an absolute path"
            )));
        }
        let metadata = std::fs::symlink_metadata(&path)
            .map_err(|e| rules_error(format!("runtime role {role:?} cannot be inspected: {e}")))?;
        if !metadata.file_type().is_file() {
            return Err(rules_error(format!(
                "runtime role {role:?} is not a literal regular file"
            )));
        }
        self.paths.insert(role.to_string(), path);
        Ok(())
    }

    /// The path filling a role, when the deployment supplied one.
    pub fn path(&self, role: &str) -> Option<&std::path::Path> {
        self.paths.get(role).map(std::path::PathBuf::as_path)
    }

    /// Parses an inventory from TOML text: one flat table mapping each
    /// role label to an absolute path.
    pub fn parse(text: &str, name: &str) -> Result<RuntimeInventory> {
        let raw: std::collections::BTreeMap<String, String> =
            toml::from_str(text).map_err(|e| Error::Rules {
                name: name.to_string(),
                message: e.to_string(),
            })?;
        let mut inventory = RuntimeInventory::empty();
        for (role, path) in raw {
            inventory.set(&role, std::path::PathBuf::from(path))?;
        }
        Ok(inventory)
    }

    /// Loads an inventory from a TOML file.
    pub fn load(path: &std::path::Path) -> Result<RuntimeInventory> {
        let text = std::fs::read_to_string(path).map_err(|e| Error::io("read", path, e))?;
        RuntimeInventory::parse(&text, &path.display().to_string())
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
// The in-jail audio decode and transcribe path. Crate-private for the
// same reason image_ocr is: a library consumer must not run the
// decode and engine path in process and bypass the jail. The worker
// dispatch reaches it through a crate path.
#[cfg(all(unix, feature = "audio-asr"))]
pub(crate) mod audio_asr;
// The image-metadata derived-child leg. The id, version, and the
// applies predicate are always compiled so the registry and pipeline can
// name the leg; the parsers and the parent rendering compile only under
// the feature, crate-private for the same reason records is: a library
// consumer must not run the parsers in process and bypass the jail.
pub mod image_metadata;
// The deployment-owned provider configuration. Always compiled, so a
// build without the provider feature still parses and validates a
// configuration it was handed rather than ignoring it silently.
pub mod provider;
pub mod subprocess;
// The in-jail svg raster path. Crate-private for the same reason
// image_ocr is: a library consumer must not run the external
// components in process and bypass the provider jail. The worker
// dispatch reaches it through a crate path.
#[cfg(all(unix, feature = "svg-provider"))]
pub(crate) mod svg_raster;
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
    /// Media provenance for a transcript artifact: source duration,
    /// language, and the pinned engine identity as a role label and
    /// hashes. Every text and image converter returns `None`; the
    /// audio converter populates it, and the pipeline copies it onto
    /// the manifest record and through dedup.
    pub media: Option<crate::manifest::Media>,
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

/// The warning an svg record carries when a deployment configured the
/// external provider but this binary was built without the
/// `svg-provider` feature. The configuration is valid and the operator
/// asked for the leg, so the record says the leg did not run rather
/// than looking like a provider-free run. A later build that carries
/// the feature is not allowed to skip such a record as unchanged, so
/// the child is minted on the first build that can produce it.
pub const SVG_PROVIDER_NOT_BUILT: &str = "svg-provider-not-built";

/// The reason audio formats record on a build without the `audio-asr`
/// feature. The converter exists and the rules route to it, but this
/// binary has no in-jail decode-plus-transcribe path, so the formats
/// are a deliberate capability gap rather than a converter error. The
/// checkpoint key includes `rules_version`, so a later feature-carrying
/// build reconverts every such record.
pub const AUDIO_ASR_NOT_BUILT_REASON: &str = "audio-asr-not-built";

/// The reason a media format records when its adapter's engine has no
/// pinned identity for the running platform. Declared entries in the
/// rules use the same string; the registry also applies it at
/// construction to the audio formats on any platform outside the
/// pinned machine class, because an engine pin is per machine class
/// and a second class needs its own measured pin before the route
/// opens there.
pub const ENGINE_UNPINNED_REASON: &str = "engine-unpinned";

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
            media: None,
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
    #[serde(default)]
    asr: Option<AsrProfile>,
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
    asr_profile: Option<AsrProfile>,
    /// Index into `converters` of the converter that runs the svg
    /// provider leg. It is the same pixel-OCR converter the raster
    /// formats route to, constructed with the provider wired, and it is
    /// reached by this index alone: svg never enters `by_format`, so
    /// its primary stays the passthrough. `None` whenever no complete
    /// provider is configured, which is every default run.
    svg_ocr_index: Option<usize>,
    /// The configured svg provider, kept so the test-only fake hook can
    /// rebuild the converter with the same provider wired. A release
    /// build has no such hook and carries no such field.
    #[cfg(all(
        unix,
        feature = "image-ocr",
        feature = "svg-provider",
        feature = "test-adapters"
    ))]
    svg_provider: Option<provider::SvgProvider>,
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

    /// The built-in registry with the deployment's runtime-inventory
    /// paths wired into the pinned-engine converters.
    pub fn builtin_with_inventory(inventory: &RuntimeInventory) -> Result<Self> {
        Self::parse_with_inventory(
            include_str!("../../rules/converters.toml"),
            "converters.toml",
            inventory,
        )
    }

    /// The built-in registry with the deployment's runtime-inventory
    /// paths and its external provider configuration wired in.
    pub fn builtin_with_runtime(
        inventory: &RuntimeInventory,
        provider: Option<&provider::ProviderConfig>,
    ) -> Result<Self> {
        Self::parse_with_runtime(
            include_str!("../../rules/converters.toml"),
            "converters.toml",
            inventory,
            provider,
        )
    }

    /// Parses a registry and binds entries to implementations, with no
    /// runtime inventory: every pinned-engine path stays on its
    /// fail-closed runtime-missing seam.
    pub fn parse(text: &str, name: &str) -> Result<Self> {
        Self::parse_with_inventory(text, name, &RuntimeInventory::empty())
    }

    /// Parses a registry and binds entries to implementations, wiring
    /// the deployment's runtime-inventory paths into the pinned-engine
    /// converters. The expected hashes stay in the rules text; the
    /// inventory supplies only paths.
    #[cfg_attr(
        not(all(unix, any(feature = "image-ocr", feature = "audio-asr"))),
        allow(unused_variables)
    )]
    pub fn parse_with_inventory(
        text: &str,
        name: &str,
        inventory: &RuntimeInventory,
    ) -> Result<Self> {
        Self::parse_with_runtime(text, name, inventory, None)
    }

    /// Parses a registry, wiring both the deployment's runtime
    /// inventory and, when one is configured, the external svg
    /// provider. The provider is opt-in twice over: the feature must be
    /// built and a configuration must name both roles.
    #[cfg_attr(
        not(all(unix, any(feature = "image-ocr", feature = "audio-asr"))),
        allow(unused_variables)
    )]
    pub fn parse_with_runtime(
        text: &str,
        name: &str,
        inventory: &RuntimeInventory,
        provider: Option<&provider::ProviderConfig>,
    ) -> Result<Self> {
        let raw: RawRegistry = toml::from_str(text).map_err(|e| Error::Rules {
            name: name.to_string(),
            message: e.to_string(),
        })?;
        let records_limits = raw.records.clone().unwrap_or_default();
        let image_ocr_limits = raw.image_ocr.clone().unwrap_or_default();
        let image_metadata_limits = raw.image_metadata.clone().unwrap_or_default();
        validate_image_ocr_limits(&image_ocr_limits, name)?;
        let asr_profile = raw.asr.clone();
        if let Some(profile) = &asr_profile {
            validate_asr_profile(profile, name)?;
        }
        let mut converters: Vec<Box<dyn Converter>> = Vec::new();
        let mut by_format = HashMap::new();
        let mut unsupported_reasons = HashMap::new();
        // Reassigned only under the feature; without it the auxiliary
        // converter is never constructed and the index stays absent.
        #[allow(unused_mut)]
        let mut image_metadata_index: Option<usize> = None;
        // Reassigned only when the feature is built and a complete
        // provider is configured; otherwise the svg leg does not exist.
        #[allow(unused_mut)]
        let mut svg_ocr_index: Option<usize> = None;
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
            // A build without the audio-asr feature has no in-jail
            // decode-plus-transcribe path, so route the audio formats
            // to a deliberate unsupported reason instead of a
            // converter that cannot serve them. The rules stay one
            // shared file: the routing decision is made here at
            // construction.
            #[cfg(not(all(unix, feature = "audio-asr")))]
            if entry.id == subprocess::ASR_ADAPTER_ID {
                for format in &entry.formats {
                    if RESERVED_FORMAT_IDS.contains(&format.as_str()) {
                        return Err(Error::Rules {
                            name: name.to_string(),
                            message: format!("format id {format:?} is reserved"),
                        });
                    }
                    if by_format.contains_key(format)
                        || unsupported_reasons
                            .insert(format.clone(), AUDIO_ASR_NOT_BUILT_REASON.to_string())
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
            // The pinned speech engine identity exists for one machine
            // class. A feature-carrying build on any other platform
            // routes the audio formats back to engine-unpinned, the
            // same reason they carried before the pin, until that
            // platform gains its own measured engine identity in a
            // rules bump.
            #[cfg(all(
                unix,
                feature = "audio-asr",
                not(all(target_os = "macos", target_arch = "aarch64"))
            ))]
            if entry.id == subprocess::ASR_ADAPTER_ID {
                for format in &entry.formats {
                    if RESERVED_FORMAT_IDS.contains(&format.as_str()) {
                        return Err(Error::Rules {
                            name: name.to_string(),
                            message: format!("format id {format:?} is reserved"),
                        });
                    }
                    if by_format.contains_key(format)
                        || unsupported_reasons
                            .insert(format.clone(), ENGINE_UNPINNED_REASON.to_string())
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
                    // With a provider configured the same converter
                    // additionally carries the svg leg. Without one it
                    // is the direct raster converter it has always
                    // been, and svg never reaches it.
                    #[cfg(feature = "svg-provider")]
                    let converter = match provider.and_then(provider::ProviderConfig::svg) {
                        Some(svg) => {
                            // A configured provider needs pinned
                            // expectations to be verified against. Rules
                            // that pin none cannot run one, and saying
                            // so beats running an unverified executable.
                            if image_ocr_limits.svg_provider.is_empty() {
                                return Err(Error::Rules {
                                    name: name.to_string(),
                                    message: "a provider is configured but [image_ocr.svg_provider] pins no expectations for it".to_string(),
                                });
                            }
                            Box::new(subprocess::ImagePixelOcr::with_svg_provider(
                                image_ocr_limits.clone(),
                                inventory,
                                svg,
                            ))
                        }
                        None => Box::new(subprocess::ImagePixelOcr::new(
                            image_ocr_limits.clone(),
                            inventory,
                        )),
                    };
                    #[cfg(not(feature = "svg-provider"))]
                    let converter = Box::new(subprocess::ImagePixelOcr::new(
                        image_ocr_limits.clone(),
                        inventory,
                    ));
                    converter
                }
                #[cfg(all(
                    unix,
                    feature = "audio-asr",
                    target_os = "macos",
                    target_arch = "aarch64"
                ))]
                subprocess::ASR_ADAPTER_ID => {
                    let profile = asr_profile.clone().ok_or_else(|| Error::Rules {
                        name: name.to_string(),
                        message: "the asr-adapter entry requires an [asr] section".to_string(),
                    })?;
                    Box::new(subprocess::AsrAdapter::new(profile, inventory))
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
            #[cfg(all(unix, feature = "image-ocr", feature = "svg-provider"))]
            if entry.id == subprocess::IMAGE_PIXEL_OCR_ID
                && provider.and_then(provider::ProviderConfig::svg).is_some()
            {
                svg_ocr_index = Some(index);
            }
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
            asr_profile,
            image_metadata_index,
            svg_ocr_index,
            #[cfg(all(
                unix,
                feature = "image-ocr",
                feature = "svg-provider",
                feature = "test-adapters"
            ))]
            svg_provider: provider.and_then(provider::ProviderConfig::svg).cloned(),
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

    /// The speech-transcription jail profile from the rules, when the
    /// rules carry one.
    pub fn asr_profile(&self) -> Option<&AsrProfile> {
        self.asr_profile.as_ref()
    }

    /// Test-only: drives the audio formats through the fake-engine
    /// speech adapter instead of the pinned-runtime one, so a pipeline
    /// test can exercise the decode, preflight, rendering, and media
    /// propagation without a wired engine. The shared decode,
    /// duration, size, and silence layers are the production ones;
    /// only the engine stage is the fake. A release build has no such
    /// hook, and the registry never constructs the fake itself.
    #[cfg(all(
        unix,
        feature = "audio-asr",
        feature = "test-adapters",
        target_os = "macos",
        target_arch = "aarch64"
    ))]
    pub fn use_fake_asr(&mut self) {
        if let Some(index) = self
            .converters
            .iter()
            .position(|c| c.id() == subprocess::ASR_ADAPTER_ID)
            && let Some(profile) = self.asr_profile.clone()
        {
            self.converters[index] = Box::new(subprocess::AsrAdapter::new_fake(profile));
        }
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
            // A configured provider stays wired: only the recognition
            // stage is faked, so the provider half of the svg leg runs
            // for real, jail and all.
            #[cfg(feature = "svg-provider")]
            {
                self.converters[index] = match &self.svg_provider {
                    Some(svg) => Box::new(subprocess::ImagePixelOcr::new_fake_with_svg_provider(
                        self.image_ocr_limits.clone(),
                        svg,
                    )),
                    None => Box::new(subprocess::ImagePixelOcr::new_fake(
                        self.image_ocr_limits.clone(),
                    )),
                };
            }
            #[cfg(not(feature = "svg-provider"))]
            {
                self.converters[index] = Box::new(subprocess::ImagePixelOcr::new_fake(
                    self.image_ocr_limits.clone(),
                ));
            }
        }
    }

    /// The converter that runs the svg provider leg, when a complete
    /// provider is configured and this build carries the feature. It
    /// never enters `by_format`, so the pipeline reaches it here to run
    /// the derived-child leg, exactly as it reaches the metadata
    /// converter. `None` means the leg does not run and svg is a
    /// passthrough primary with no child.
    pub fn svg_ocr_converter(&self) -> Option<&dyn Converter> {
        self.svg_ocr_index
            .map(|index| self.converters[index].as_ref())
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
            asr_profile: None,
            image_metadata_index: None,
            svg_ocr_index: None,
            #[cfg(all(
                unix,
                feature = "image-ocr",
                feature = "svg-provider",
                feature = "test-adapters"
            ))]
            svg_provider: None,
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
        assert_eq!(registry.version(), "10");
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

    // The audio family's route depends on the feature and the pinned
    // machine class. All three arms are asserted through runtime
    // branches, so each compiles in every configuration and none rots:
    // with the feature on the pinned class the live converter claims
    // the formats, with the feature elsewhere they stay engine-unpinned
    // because the engine identity is per machine class, and without
    // the feature they carry the deliberate not-built gap.
    #[test]
    fn the_audio_family_routes_by_the_feature_and_platform() {
        let registry = Registry::builtin().unwrap();
        let pinned_class = cfg!(all(
            unix,
            feature = "audio-asr",
            target_os = "macos",
            target_arch = "aarch64"
        ));
        let feature_present = cfg!(all(unix, feature = "audio-asr"));
        for format in ["wav", "mp3", "flac", "m4a"] {
            if pinned_class {
                assert_eq!(
                    registry.converter_for(format).map(|c| c.id()),
                    Some("asr-adapter"),
                    "{format}"
                );
                assert_eq!(registry.unsupported_reason(format), None, "{format}");
            } else if feature_present {
                assert!(registry.converter_for(format).is_none(), "{format}");
                assert_eq!(
                    registry.unsupported_reason(format),
                    Some(ENGINE_UNPINNED_REASON),
                    "{format}"
                );
            } else {
                assert!(registry.converter_for(format).is_none(), "{format}");
                assert_eq!(
                    registry.unsupported_reason(format),
                    Some(AUDIO_ASR_NOT_BUILT_REASON),
                    "{format}"
                );
            }
        }
        // Video containers stay engine-unpinned everywhere: their
        // audio-track extraction is a later, separately ruled path.
        assert_eq!(registry.unsupported_reason("mp4"), Some("engine-unpinned"));
        assert_eq!(registry.unsupported_reason("mov"), Some("engine-unpinned"));
        // The [asr] profile parses with the ruled ceilings and exactly
        // the four pinned roles, whatever the routing arm.
        let profile = registry
            .asr_profile()
            .expect("the built-in rules carry an [asr] section");
        assert_eq!(profile.max_duration_seconds, 3600);
        assert_eq!(profile.wall_timeout_secs, 900);
        assert_eq!(profile.cpu_seconds, 600);
        assert_eq!(profile.max_resident_bytes, 6_442_450_944);
        assert_eq!(profile.max_response_bytes, 4_194_304);
        assert_eq!(profile.max_stderr_bytes, 4_194_304);
        assert_eq!(profile.file_size_bytes, 1_207_959_552);
        assert_eq!(profile.max_processes, 64);
        assert_eq!(profile.language, "en");
        // All four runtime roles ship pinned, the probe included.
        assert_eq!(profile.inventory.len(), 4);
        assert!(profile.inventory.contains_key("asr-probe"));
    }

    // The [asr] section is validated at parse: a wrong language, a
    // missing or unknown role, a malformed hash, and a decode-policy
    // hash that disagrees with the built-in serialization are all
    // rules errors, not silent divergences.
    #[test]
    fn the_asr_profile_is_validated_at_parse() {
        let policy_hash = crate::hash::hash_bytes(subprocess::ASR_DECODE_POLICY.as_bytes());
        let zeros = "0".repeat(64);
        let base = |language: &str, extra_row: &str, policy: &str| {
            format!(
                r#"version = "1"
converters = []

[asr]
max_duration_seconds = 3600
wall_timeout_secs = 900
cpu_seconds = 600
max_resident_bytes = 6442450944
max_response_bytes = 4194304
max_stderr_bytes = 4194304
file_size_bytes = 1207959552
max_processes = 64
language = "{language}"

[asr.inventory]
asr-cli = "{zeros}"
asr-weights = "{zeros}"
asr-decode-policy = "{policy}"
{extra_row}"#,
                zeros = zeros.as_str(),
            )
        };
        // A custom profile that omits the optional probe row parses.
        let good = base("en", "", &policy_hash);
        assert!(Registry::parse(&good, "converters.toml").is_ok());
        // The probe-bearing shape the built-in rules ship parses the
        // same way.
        let with_probe = base("en", &format!("asr-probe = \"{zeros}\"\n"), &policy_hash);
        assert!(Registry::parse(&with_probe, "converters.toml").is_ok());
        // A non-pinned language is refused.
        let err = Registry::parse(&base("fr", "", &policy_hash), "converters.toml")
            .err()
            .expect("a non-pinned language must be refused");
        assert!(err.to_string().contains("language"), "{err}");
        // An unknown role is refused.
        let unknown = base("en", &format!("asr-extra = \"{zeros}\"\n"), &policy_hash);
        let err = Registry::parse(&unknown, "converters.toml")
            .err()
            .expect("an unknown role must be refused");
        assert!(err.to_string().contains("role"), "{err}");
        // A missing pinned role is refused.
        let missing: String = good
            .lines()
            .filter(|line| !line.starts_with("asr-weights"))
            .collect::<Vec<_>>()
            .join("\n");
        let err = Registry::parse(&missing, "converters.toml")
            .err()
            .expect("a missing pinned role must be refused");
        assert!(err.to_string().contains("missing"), "{err}");
        // A decode-policy hash that disagrees with the built-in
        // serialization is refused.
        let err = Registry::parse(&base("en", "", &"a".repeat(64)), "converters.toml")
            .err()
            .expect("a divergent decode-policy hash must be refused");
        assert!(err.to_string().contains("decode"), "{err}");
        // A malformed hash is refused.
        let err = Registry::parse(&base("en", "", "SHOUTING"), "converters.toml")
            .err()
            .expect("a malformed hash must be refused");
        assert!(err.to_string().contains("hex"), "{err}");
    }

    #[test]
    #[cfg(unix)]
    fn the_runtime_inventory_validates_roles_and_paths() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("engine");
        std::fs::write(&file, b"pinned bytes").unwrap();
        let mut inventory = RuntimeInventory::empty();
        assert!(inventory.set("asr-cli", file.clone()).is_ok());
        assert_eq!(inventory.path("asr-cli"), Some(file.as_path()));
        assert!(inventory.path("asr-weights").is_none());
        // An unknown role and a relative path both fail loudly. The
        // decode-policy role is deliberately unknown here: the crate
        // owns that serialization as a constant, so it is never a
        // deployment inventory key.
        assert!(inventory.set("mystery-role", file.clone()).is_err());
        assert!(inventory.set("asr-decode-policy", file.clone()).is_err());
        let policy_row = format!("asr-decode-policy = \"{}\"\n", file.display());
        assert!(RuntimeInventory::parse(&policy_row, "inventory.toml").is_err());
        assert!(
            inventory
                .set("asr-weights", std::path::PathBuf::from("relative"))
                .is_err()
        );
        // A directory, a symlink, and a missing path are all refused:
        // the jail grants literal regular files only, and the spawn
        // path re-asserts the same rule.
        assert!(
            inventory
                .set("asr-weights", dir.path().to_path_buf())
                .is_err()
        );
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        assert!(inventory.set("asr-weights", link).is_err());
        assert!(
            inventory
                .set("asr-weights", dir.path().join("absent"))
                .is_err()
        );
        // The TOML form parses the same way.
        let toml_text = format!("asr-weights = \"{}\"\n", file.display());
        let parsed = RuntimeInventory::parse(&toml_text, "inventory.toml").unwrap();
        assert_eq!(parsed.path("asr-weights"), Some(file.as_path()));
        assert!(RuntimeInventory::parse("nope = \"/x\"\n", "inventory.toml").is_err());
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
