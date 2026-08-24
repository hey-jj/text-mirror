//! The framed stdin/stdout protocol between the runner and a worker.
//!
//! One frame is a four-byte big-endian length prefix followed by
//! exactly that many bytes of one UTF-8 JSON value. The same frame
//! format runs both directions. The declared length is checked
//! against a limit before any allocation, so an oversized declaration
//! is refused without buying its buffer. EOF inside the header or the
//! payload is a truncated frame, the footprint of a killed writer,
//! and never parses.
//!
//! A response frame alone is not success. The runner also requires a
//! clean child exit and no trailing stdout bytes, so a worker that
//! crashes after writing plausible JSON, or logs past its frame, is
//! refused.

use std::io::{self, Read, Write};

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::segments::Segment;

/// The schema identifier carried by every adapter request.
pub const REQUEST_SCHEMA: &str = "text-mirror/adapter-request@1";

/// The schema identifier carried by every adapter response.
pub const RESPONSE_SCHEMA: &str = "text-mirror/adapter-response@1";

/// Ceiling on request frame payload bytes, enforced by the worker
/// before allocation. Requests carry paths and options, never file
/// content, so they stay small.
pub const MAX_REQUEST_BYTES: u32 = 1024 * 1024;

macro_rules! literal_schema {
    ($name:ident, $value:expr) => {
        /// A schema field pinned to one literal value. Serializes to
        /// that literal and rejects every other value on read.
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
        pub struct $name;

        impl Serialize for $name {
            fn serialize<S: Serializer>(
                &self,
                serializer: S,
            ) -> std::result::Result<S::Ok, S::Error> {
                serializer.serialize_str($value)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(
                deserializer: D,
            ) -> std::result::Result<Self, D::Error> {
                let value = String::deserialize(deserializer)?;
                if value == $value {
                    Ok($name)
                } else {
                    Err(D::Error::custom(format!(
                        "unrecognized schema {value:?}, expected {:?}",
                        $value
                    )))
                }
            }
        }
    };
}

literal_schema!(RequestSchema, REQUEST_SCHEMA);
literal_schema!(ResponseSchema, RESPONSE_SCHEMA);

/// One request frame from the runner to a worker.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    /// The literal string `text-mirror/adapter-request@1`.
    pub schema: RequestSchema,
    /// The adapter mode this request addresses.
    pub adapter: String,
    /// The adapter-specific request body.
    pub payload: serde_json::Value,
}

/// One response frame from a worker to the runner.
///
/// Exactly one of `ok` and `error` is present. [`Response::validate`]
/// enforces that, and the runner refuses any frame that fails it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    /// The literal string `text-mirror/adapter-response@1`.
    pub schema: ResponseSchema,
    /// The adapter-specific success body.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub ok: Option<serde_json::Value>,
    /// The failure body.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub error: Option<WireError>,
}

impl Response {
    /// A success response.
    pub fn ok(value: serde_json::Value) -> Response {
        Response {
            schema: ResponseSchema,
            ok: Some(value),
            error: None,
        }
    }

    /// A failure response.
    pub fn err(code: &str, message: String) -> Response {
        Response {
            schema: ResponseSchema,
            ok: None,
            error: Some(WireError {
                code: code.to_string(),
                message,
            }),
        }
    }

    /// Checks that exactly one of `ok` and `error` is present.
    pub fn validate(&self) -> std::result::Result<(), String> {
        match (&self.ok, &self.error) {
            (Some(_), None) | (None, Some(_)) => Ok(()),
            (Some(_), Some(_)) => Err("response carries both ok and error".to_string()),
            (None, None) => Err("response carries neither ok nor error".to_string()),
        }
    }
}

/// A machine-readable failure carried over the wire.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireError {
    /// Stable reason code, such as `pdf_no_text_layer`.
    pub code: String,
    /// Detail for a human reading the manifest.
    pub message: String,
}

/// How reading one frame ended.
#[derive(Debug)]
pub enum FrameRead {
    /// A complete frame payload.
    Complete(Vec<u8>),
    /// EOF before any header byte. The writer produced nothing.
    Empty,
    /// EOF inside the header or the payload. The writer died mid-frame.
    Truncated,
    /// The header declared more bytes than the limit allows. Nothing
    /// was allocated or read past the header.
    Oversized {
        /// The declared payload length.
        declared: u64,
    },
}

/// Reads one length-prefixed frame, checking the declared length
/// against `max_bytes` before allocating.
pub fn read_frame(reader: &mut impl Read, max_bytes: u32) -> io::Result<FrameRead> {
    let mut header = [0u8; 4];
    match read_exact_or_eof(reader, &mut header)? {
        Fill::Empty => return Ok(FrameRead::Empty),
        Fill::Partial => return Ok(FrameRead::Truncated),
        Fill::Full => {}
    }
    let declared = u32::from_be_bytes(header);
    if declared > max_bytes {
        return Ok(FrameRead::Oversized {
            declared: u64::from(declared),
        });
    }
    let mut payload = vec![0u8; declared as usize];
    match read_exact_or_eof(reader, &mut payload)? {
        Fill::Full => Ok(FrameRead::Complete(payload)),
        Fill::Empty | Fill::Partial => Ok(FrameRead::Truncated),
    }
}

enum Fill {
    Full,
    Partial,
    Empty,
}

fn read_exact_or_eof(reader: &mut impl Read, buffer: &mut [u8]) -> io::Result<Fill> {
    let mut filled = 0;
    while filled < buffer.len() {
        match reader.read(&mut buffer[filled..]) {
            Ok(0) => {
                return Ok(if filled == 0 {
                    Fill::Empty
                } else {
                    Fill::Partial
                });
            }
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(Fill::Full)
}

/// Writes one value as one frame and flushes.
pub fn write_frame<T: Serialize>(writer: &mut impl Write, value: &T) -> io::Result<()> {
    let payload = serde_json::to_vec(value).map_err(io::Error::other)?;
    let length = u32::try_from(payload.len())
        .map_err(|_| io::Error::other("frame payload exceeds the u32 length prefix"))?;
    writer.write_all(&length.to_be_bytes())?;
    writer.write_all(&payload)?;
    writer.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_non_recovered_pdf_response_omits_the_recovered_field() {
        use bodies::PdfOk;
        // A non-recovered outcome serializes byte-identical to the
        // pre-recovery wire: the `recovered` field is skipped entirely,
        // so a mixed-version worker pairing can only trip on an
        // actually-recovered document.
        let plain = PdfOk {
            text: "hi".to_string(),
            warnings: Vec::new(),
            segments: Vec::new(),
            recovered: false,
        };
        let encoded = serde_json::to_string(&plain).unwrap();
        assert!(
            !encoded.contains("recovered"),
            "false recovered is off the wire: {encoded}"
        );
        // The default fills it back in when the field is absent.
        let back: PdfOk = serde_json::from_str(&encoded).unwrap();
        assert!(!back.recovered);

        let recovered = PdfOk {
            recovered: true,
            ..plain
        };
        let encoded = serde_json::to_string(&recovered).unwrap();
        assert!(
            encoded.contains("\"recovered\":true"),
            "a recovered outcome carries the field: {encoded}"
        );
    }

    #[test]
    fn frames_roundtrip() {
        let mut buffer = Vec::new();
        let request = Request {
            schema: RequestSchema,
            adapter: "pdf".to_string(),
            payload: serde_json::json!({"input": "input.pdf"}),
        };
        write_frame(&mut buffer, &request).unwrap();
        let mut cursor = std::io::Cursor::new(buffer);
        let FrameRead::Complete(payload) = read_frame(&mut cursor, MAX_REQUEST_BYTES).unwrap()
        else {
            panic!("expected a complete frame");
        };
        let back: Request = serde_json::from_slice(&payload).unwrap();
        assert_eq!(back.adapter, "pdf");
    }

    #[test]
    fn oversized_declarations_are_refused_before_allocation() {
        let mut bytes = u32::MAX.to_be_bytes().to_vec();
        bytes.extend_from_slice(b"junk");
        let mut cursor = std::io::Cursor::new(bytes);
        let FrameRead::Oversized { declared } = read_frame(&mut cursor, 1024).unwrap() else {
            panic!("expected an oversized refusal");
        };
        assert_eq!(declared, u64::from(u32::MAX));
    }

    #[test]
    fn truncation_is_detected_in_header_and_payload() {
        let mut cursor = std::io::Cursor::new(vec![0u8, 0, 0]);
        assert!(matches!(
            read_frame(&mut cursor, 1024).unwrap(),
            FrameRead::Truncated
        ));

        let mut bytes = 10u32.to_be_bytes().to_vec();
        bytes.extend_from_slice(b"half");
        let mut cursor = std::io::Cursor::new(bytes);
        assert!(matches!(
            read_frame(&mut cursor, 1024).unwrap(),
            FrameRead::Truncated
        ));

        let mut cursor = std::io::Cursor::new(Vec::<u8>::new());
        assert!(matches!(
            read_frame(&mut cursor, 1024).unwrap(),
            FrameRead::Empty
        ));
    }

    #[test]
    fn responses_require_exactly_one_body() {
        assert!(Response::ok(serde_json::json!({})).validate().is_ok());
        assert!(Response::err("io", "detail".to_string()).validate().is_ok());
        let both = Response {
            schema: ResponseSchema,
            ok: Some(serde_json::json!({})),
            error: Some(WireError {
                code: "io".to_string(),
                message: "detail".to_string(),
            }),
        };
        assert!(both.validate().is_err());
        let neither = Response {
            schema: ResponseSchema,
            ok: None,
            error: None,
        };
        assert!(neither.validate().is_err());
    }

    #[test]
    fn wrong_schema_values_are_rejected() {
        let json = serde_json::to_string(&Response::ok(serde_json::json!({}))).unwrap();
        let bumped = json.replace("adapter-response@1", "adapter-response@2");
        assert!(serde_json::from_str::<Response>(&bumped).is_err());
    }
}

/// Typed request and response bodies for the shipped adapters. Each
/// adapter's `payload` and `ok` values are these shapes.
pub mod bodies {
    use super::*;

    /// Request body for the `pdf` adapter.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct PdfRequest {
        /// Input file name inside the jail.
        pub input: String,
    }

    /// Success body for the `pdf` adapter.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct PdfOk {
        /// The converted text, UTF-8, NFC, LF line endings.
        pub text: String,
        /// Non-fatal notes about the conversion.
        pub warnings: Vec<String>,
        /// Structure spans over the text.
        pub segments: Vec<Segment>,
        /// Whether the text came from the direct recovery extractor
        /// rather than the markdown path. The parent adapter maps this
        /// to the manifest converter id, so a recovered document is
        /// never recorded under the markdown path's id.
        ///
        /// Skipped from the wire when false, so every non-recovered
        /// outcome serializes byte-identical to the pre-recovery wire
        /// and a mixed-version worker pairing can only ever trip on an
        /// actually-recovered document. `deny_unknown_fields` above then
        /// fails such a pairing loudly rather than dropping the field.
        #[serde(default, skip_serializing_if = "is_false")]
        pub recovered: bool,
    }

    /// Whether a boolean is false, for `skip_serializing_if`.
    fn is_false(value: &bool) -> bool {
        !*value
    }

    /// Request body for the `records` adapter, which reads parquet,
    /// avro, and sqlite behind the jail.
    ///
    /// The ceilings travel in the request because the worker, not the
    /// parent, enforces them, and they are rules data the parent reads
    /// from the registry. A source over any ceiling fails closed with
    /// reason `record-limit-exceeded`.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct RecordsRequest {
        /// Input file name inside the jail.
        pub input: String,
        /// The detected format: `parquet`, `avro`, or `sqlite`.
        pub format: String,
        /// Ceiling on records per parquet or avro file, or per sqlite
        /// table.
        pub max_records: u64,
        /// Ceiling on tables per sqlite database.
        pub max_tables: u64,
        /// Ceiling on rendered output bytes.
        pub max_output_bytes: u64,
    }

    /// Success body for the `records` adapter.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct RecordsOk {
        /// The rendered text, UTF-8, NFC, LF line endings.
        pub text: String,
        /// Non-fatal notes about the conversion.
        pub warnings: Vec<String>,
        /// Structure spans over the text. Sqlite carries a sheet
        /// boundary per table.
        pub segments: Vec<Segment>,
    }

    /// Request body for the `image-metadata` adapter, which lifts
    /// textual metadata out of a raster behind the jail.
    ///
    /// The ceilings travel in the request because the worker, not the
    /// parent, enforces them, and they are rules data the parent reads
    /// from the registry, matching [`RecordsRequest`]. A source over any
    /// ceiling fails closed with a stable `image-metadata-*` reason.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct ImageMetadataRequest {
        /// Input file name inside the jail.
        pub input: String,
        /// The detected carrier format: `png`, `jpeg`, `webp`, `heic`,
        /// or `svg`.
        pub format: String,
        /// Ceiling on the inflated size of any single compressed text
        /// block, checked incrementally during inflation.
        pub max_decompressed_bytes: u64,
        /// Ceiling on the nesting depth of an xmp or svg parse.
        pub max_xml_depth: u32,
        /// Ceiling on the event count of an xmp or svg parse.
        pub max_xml_events: u64,
        /// Ceiling on the box count walked in an iso base media file
        /// format carrier.
        pub max_boxes: u64,
        /// Ceiling on emitted metadata rows across all surfaces.
        pub max_rows: u64,
        /// Ceiling on the rendered artifact text, under the runner
        /// response cap.
        pub max_output_bytes: u64,
    }

    /// One extracted metadata value, addressed by carrier, surface, and
    /// path. The parent renders these to the tabular artifact and builds
    /// one hidden segment per row, so the output contract and the hidden
    /// marking stay in the crate rather than the worker.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct MetadataRow {
        /// The container the value came from, such as `exif`,
        /// `png-itxt`, `jpeg-app1-xmp`, `webp-xmp`, `iptc-iim`, or
        /// `heic-uuid`.
        pub carrier: String,
        /// The surface family, such as `exif-imagedescription`,
        /// `xmp-dc-description`, or `iptc-2-120-caption`.
        pub surface: String,
        /// The addressing detail, such as the exif tag number, the xmp
        /// property path, the iptc dataset, or the svg element path.
        pub path: String,
        /// The language tag when the surface carries one, such as an
        /// `iTXt` language tag or an xmp `xml:lang`.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub language: Option<String>,
        /// The extracted text.
        pub value: String,
    }

    /// Success body for the `image-metadata` adapter.
    ///
    /// An empty `rows` is the not-applicable outcome: the parent writes
    /// nothing for the metadata leg. One or more rows renders to a
    /// non-empty artifact and records a converted child.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct ImageMetadataOk {
        /// Extracted rows, one per metadata value. Zero rows is the
        /// no-metadata outcome.
        pub rows: Vec<MetadataRow>,
    }

    /// What an OCR request asks the engine to read.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case", deny_unknown_fields)]
    pub enum OcrInput {
        /// A standalone raster image.
        Image,
        /// One page of a paginated source rendered to raster.
        PageRender {
            /// Zero-based page index.
            page: u32,
            /// Render resolution in dots per inch.
            dpi: u32,
        },
    }

    /// Request body for the `ocr` adapter.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct OcrRequest {
        /// Input file name inside the jail.
        pub input: String,
        /// What the engine should read.
        pub kind: OcrInput,
    }

    /// One recognized text span with its confidence.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct OcrSpan {
        /// The recognized text.
        pub text: String,
        /// Engine confidence in the closed range 0 to 1.
        pub confidence: f64,
    }

    /// Success body for the `ocr` adapter.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct OcrOk {
        /// Recognized spans in reading order.
        pub spans: Vec<OcrSpan>,
        /// Non-fatal notes from the worker, such as the long-edge
        /// validation note. Skipped from the wire when empty, so the
        /// pre-existing engine-unpinned scaffold serializes unchanged.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub warnings: Vec<String>,
    }

    /// Request body for the `asr` adapter.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct AsrRequest {
        /// Input file name inside the jail.
        pub input: String,
        /// Language hint, when the caller has one.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub language: Option<String>,
    }

    /// One transcribed speech segment.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct AsrSegment {
        /// Segment start in seconds from the recording start.
        pub start_seconds: f64,
        /// Segment end in seconds.
        pub end_seconds: f64,
        /// One-based speaker index from diarization.
        pub speaker: u32,
        /// The transcribed text.
        pub text: String,
    }

    /// Success body for the `asr` adapter.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct AsrOk {
        /// Speech segments ordered by start time.
        pub segments: Vec<AsrSegment>,
        /// Detected language tag, when the engine reports one.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub language: Option<String>,
        /// Source duration in seconds, when the engine reports it.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub duration_seconds: Option<f64>,
    }

    /// Request body for the `video` adapter.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct VideoRequest {
        /// Input file name inside the jail.
        pub input: String,
        /// Seconds between sampled frames.
        pub sample_interval_seconds: f64,
        /// Ceiling on sampled frames.
        pub max_frames: u32,
    }

    /// One deduplicated on-screen text state.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct ScreenState {
        /// When this state first appeared, in seconds.
        pub first_seen_seconds: f64,
        /// The on-screen text.
        pub text: String,
    }

    /// Success body for the `video` adapter.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct VideoOk {
        /// Screen states deduplicated by content, ordered by first
        /// appearance.
        pub states: Vec<ScreenState>,
        /// Source duration in seconds, when the engine reports it.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub duration_seconds: Option<f64>,
    }

    /// Success body for the `probe-net` mode.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct ProbeReport {
        /// One entry per attempted egress path.
        pub attempts: Vec<ProbeAttempt>,
    }

    /// One egress attempt and how it ended.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct ProbeAttempt {
        /// Which path was attempted, such as `ipv4_tcp`.
        pub name: String,
        /// `denied` for an immediate error, `connected` for success,
        /// `timeout` when the attempt hung. Only `denied` proves the
        /// jail.
        pub outcome: String,
        /// The underlying error or address detail.
        pub detail: String,
    }

    /// Request body for the `probe-net` mode.
    ///
    /// Every target is one the parent controls and holds reachable
    /// while the probe runs, so a connection that fails from inside
    /// the jail is evidence of the jail and not of an unreachable
    /// address. From an unjailed process every leg would succeed.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct ProbeNetRequest {
        /// A Unix socket target the parent listens on outside the
        /// jail. An abstract name on Linux, a filesystem path
        /// elsewhere.
        pub unix_target: String,
        /// An IPv4 TCP address the parent listens on, such as
        /// `127.0.0.1:49152`.
        pub tcp4_target: String,
        /// An IPv6 TCP address the parent listens on, such as
        /// `[::1]:49152`.
        pub tcp6_target: String,
    }
}
