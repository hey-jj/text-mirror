//! Subprocess adapters: converters that run behind the sandboxed
//! runner instead of in this process.
//!
//! Each adapter speaks the framed stdin/stdout protocol to a worker
//! mode and renders the response to the outcome shape every converter
//! emits. The PDF adapter is the production occupant: it carries the
//! same outcome, warnings, and failure reasons as the in-process PDF
//! path did, so its manifest records differ only in converter id. The
//! OCR, ASR, and video adapters are the protocol half of their
//! conversions. Their engines are not pinned yet, so the registry
//! routes their formats to `unsupported` with reason `engine-unpinned`
//! until a rules bump pins an engine, and the adapters are exercised
//! against fake engines under test.

use serde::de::DeserializeOwned;

use crate::segments::Segment;

use super::{ConvertError, Converter, Outcome, normalize_text};

/// Registry id of the subprocess PDF adapter.
pub const PDF_SUBPROCESS_ID: &str = "pdf-subprocess";
/// Version of the subprocess PDF adapter.
pub const PDF_SUBPROCESS_VERSION: &str = "1.0.0";

/// Manifest converter id for the direct-extraction recovery path: a
/// PDF whose text was recovered after the markdown path declined the
/// page as image-based. It names the actual extraction path so a
/// recovered document is never recorded under the markdown path's id.
pub const PDF_RECOVERED_ID: &str = "pdf-text-recovered";
/// Version of the PDF recovery path. It shares the adapter version
/// deliberately: both paths ship in the same adapter, and the checkpoint
/// key compares converter version, so an unchanged recovered PDF skips
/// on a later run only because this equals the adapter version.
///
/// INVARIANT: any future change to the recovery path's behavior MUST
/// bump the shared adapter version [`PDF_SUBPROCESS_VERSION`]. Because
/// this equals that version, a bump moves both paths together and
/// reconverts prior artifacts of both. The equality is asserted in the
/// tests below so a silent divergence cannot compile past review.
pub const PDF_RECOVERED_VERSION: &str = PDF_SUBPROCESS_VERSION;

/// The manifest converter id and version for a PDF outcome, chosen by
/// whether the text came from the direct recovery extractor. The
/// registered converter keeps its single id and version; only the
/// per-outcome manifest record names the recovery path.
#[cfg_attr(not(unix), allow(dead_code))]
pub(crate) fn pdf_converter_identity(recovered: bool) -> (&'static str, &'static str) {
    if recovered {
        (PDF_RECOVERED_ID, PDF_RECOVERED_VERSION)
    } else {
        (PDF_SUBPROCESS_ID, PDF_SUBPROCESS_VERSION)
    }
}

/// Registry id of the jailed records worker adapter.
pub const RECORDS_SUBPROCESS_ID: &str = "records-worker";
/// Version of the jailed records worker adapter.
pub const RECORDS_SUBPROCESS_VERSION: &str = "1.0.0";

/// Registry id of the in-jail pixel-OCR converter for raster images.
pub const IMAGE_PIXEL_OCR_ID: &str = "image-pixel-ocr";
/// Version of the in-jail pixel-OCR converter.
pub const IMAGE_PIXEL_OCR_VERSION: &str = "1.0.0";

/// Registry id of the OCR adapter.
pub const OCR_ADAPTER_ID: &str = "ocr-adapter";
/// Version of the OCR adapter.
pub const OCR_ADAPTER_VERSION: &str = "1.0.0";

/// Registry id of the speech transcription adapter.
pub const ASR_ADAPTER_ID: &str = "asr-adapter";
/// Version of the speech transcription adapter.
pub const ASR_ADAPTER_VERSION: &str = "1.0.0";

/// Registry id of the video adapter.
pub const VIDEO_ADAPTER_ID: &str = "video-adapter";
/// Version of the video adapter.
pub const VIDEO_ADAPTER_VERSION: &str = "1.0.0";

/// OCR spans below this confidence carry a warning.
pub const OCR_CONFIDENCE_WARNING: f64 = 0.5;

/// Renders whole seconds as `HH:MM:SS` for transcript timecodes.
/// The input must be finite and non-negative.
pub fn format_timecode(seconds: f64) -> Result<String, String> {
    if !seconds.is_finite() || seconds < 0.0 {
        return Err(format!("timestamp {seconds} is not a non-negative time"));
    }
    let whole = seconds as u64;
    Ok(format!(
        "{:02}:{:02}:{:02}",
        whole / 3600,
        (whole % 3600) / 60,
        whole % 60
    ))
}

fn single_line(text: &str) -> String {
    text.replace(['\n', '\r'], " ").trim().to_string()
}

#[cfg(unix)]
mod imp {
    use std::sync::OnceLock;

    use super::*;
    use crate::convert::RecordsLimits;
    use crate::manifest::ArtifactKind;
    use crate::runner::protocol::bodies::{
        AsrOk, AsrRequest, OcrInput, OcrOk, OcrRequest, PdfOk, PdfRequest, RecordsOk,
        RecordsRequest, VideoOk, VideoRequest,
    };
    use crate::runner::{Runner, RunnerError};

    /// Maps a wire reason to the static reason vocabulary. Codes the
    /// in-process converters already use pass through unchanged, so a
    /// record's failure reason does not depend on which side of the
    /// process boundary produced it.
    fn static_code(code: &str) -> &'static str {
        const KNOWN: &[&str] = &[
            "pdf_no_text_layer",
            "malformed",
            "encrypted",
            "resourceLimit",
            "missingPart",
            "unsupported",
            "io",
            "empty_output",
            "invalid_utf8",
            "converter_panic",
            "unclaimed_format",
            "resource_limit",
            "record-limit-exceeded",
            "records_read_error",
            "not_sqlite",
            // Image-OCR worker reasons. Each must survive the wire-to-
            // static mapping so the manifest keeps the specific reason
            // rather than collapsing it to adapter_error.
            "image-ocr-decode-failed",
            "image-ocr-area-exceeded",
            "image-ocr-runtime-missing",
            "image-ocr-runtime-mismatch",
            "image-ocr-no-accelerator",
            "ocr-protocol-error",
        ];
        KNOWN
            .iter()
            .find(|known| **known == code)
            .copied()
            .unwrap_or("adapter_error")
    }

    fn runner_failure(error: RunnerError) -> ConvertError {
        ConvertError {
            code: error.code,
            message: error.message,
        }
    }

    /// Runs one adapter mode and returns the parsed success body.
    fn call<Req: serde::Serialize, Ok: DeserializeOwned>(
        runner: &Runner,
        mode: &str,
        request: &Req,
        files: &[(&str, &[u8])],
    ) -> Result<Ok, ConvertError> {
        let payload = serde_json::to_value(request).map_err(|e| ConvertError {
            code: "adapter_error",
            message: format!("cannot encode the adapter request: {e}"),
        })?;
        let response = runner.run(mode, payload, files).map_err(runner_failure)?;
        if let Some(error) = response.error {
            return Err(ConvertError {
                code: static_code(&error.code),
                message: error.message,
            });
        }
        let ok = response.ok.expect("validated response has a body");
        serde_json::from_value(ok).map_err(|e| ConvertError {
            code: "adapter_error",
            message: format!("adapter success body did not parse: {e}"),
        })
    }

    fn shared_runner() -> Result<&'static Runner, ConvertError> {
        static RUNNER: OnceLock<Result<Runner, RunnerError>> = OnceLock::new();
        match RUNNER.get_or_init(Runner::with_platform_defaults) {
            Ok(runner) => Ok(runner),
            Err(error) => Err(runner_failure(error.clone())),
        }
    }

    /// The production PDF conversion behind the sandbox runner.
    ///
    /// The worker links the same anydoc path the in-process document
    /// adapter used, so text, warnings such as `pdf_partial_text`, and
    /// failure reasons such as `pdf_no_text_layer` are unchanged.
    pub struct PdfSubprocess;

    impl Converter for PdfSubprocess {
        fn id(&self) -> &'static str {
            PDF_SUBPROCESS_ID
        }

        fn version(&self) -> &'static str {
            PDF_SUBPROCESS_VERSION
        }

        fn convert(
            &self,
            source: &[u8],
            detected_format: &str,
        ) -> std::result::Result<Outcome, ConvertError> {
            // ai routes here too: a modern .ai is a PDF-compatible
            // container, so the same worker path extracts its text
            // layer with the pdf-family warnings and recovery route. A
            // legacy PostScript-backed .ai has no PDF text layer and
            // fails closed with a pdf-family reason.
            if !matches!(detected_format, "pdf" | "ai") {
                return Err(ConvertError {
                    code: "unclaimed_format",
                    message: format!(
                        "the subprocess PDF adapter does not handle {detected_format}"
                    ),
                });
            }
            let body: PdfOk = call(
                shared_runner()?,
                "pdf",
                &PdfRequest {
                    input: "input.pdf".to_string(),
                },
                &[("input.pdf", source)],
            )?;
            let (converter_id, converter_version) = pdf_converter_identity(body.recovered);
            Ok(Outcome {
                artifact_kind: ArtifactKind::Text,
                converter_id: converter_id.to_string(),
                converter_version: converter_version.to_string(),
                detected_format: detected_format.to_string(),
                text: body.text,
                warnings: body.warnings,
                segments: body.segments,
            })
        }
    }

    /// The records worker adapter: parquet, avro, and sqlite behind
    /// the sandbox runner.
    ///
    /// The three readers pull large native parser trees with CVE
    /// history, so they never run in this process. Each source stages
    /// into the jail and the reader runs in the worker, where a panic
    /// on hostile bytes crashes the child and records a failed outcome
    /// without touching the pipeline. The ceilings come from the rules
    /// and travel in the request, and a source over any ceiling fails
    /// closed with reason `record-limit-exceeded`.
    pub struct RecordsSubprocess {
        limits: RecordsLimits,
    }

    impl RecordsSubprocess {
        /// An adapter over the rules-supplied ceilings.
        pub fn new(limits: RecordsLimits) -> RecordsSubprocess {
            RecordsSubprocess { limits }
        }
    }

    impl Converter for RecordsSubprocess {
        fn id(&self) -> &'static str {
            RECORDS_SUBPROCESS_ID
        }

        fn version(&self) -> &'static str {
            RECORDS_SUBPROCESS_VERSION
        }

        fn convert(
            &self,
            source: &[u8],
            detected_format: &str,
        ) -> std::result::Result<Outcome, ConvertError> {
            if !matches!(detected_format, "parquet" | "avro" | "sqlite") {
                return Err(ConvertError {
                    code: "unclaimed_format",
                    message: format!("the records worker does not handle {detected_format}"),
                });
            }
            let input = format!("input.{detected_format}");
            let body: RecordsOk = call(
                shared_runner()?,
                "records",
                &RecordsRequest {
                    input: input.clone(),
                    format: detected_format.to_string(),
                    max_records: self.limits.max_records,
                    max_tables: self.limits.max_tables,
                    max_output_bytes: self.limits.max_output_bytes,
                },
                &[(&input, source)],
            )?;
            Ok(Outcome {
                artifact_kind: ArtifactKind::Text,
                converter_id: RECORDS_SUBPROCESS_ID.to_string(),
                converter_version: RECORDS_SUBPROCESS_VERSION.to_string(),
                detected_format: detected_format.to_string(),
                text: body.text,
                warnings: body.warnings,
                segments: body.segments,
            })
        }
    }

    /// The in-jail pixel-OCR converter for raster images.
    ///
    /// png, jpeg, and webp stage into the jail by bare name and the
    /// worker decodes them with the pure-Rust image crate, asserts the
    /// encoder-input area cap, re-encodes a canonical raster, and hands
    /// it to the pinned vision engine as a hash-verified jailed child.
    /// The parent does no image parsing: it selects the worker mode,
    /// stages the bytes, and maps the fenced recognition to the outcome
    /// shape with [`ArtifactKind::Ocr`]. The engine is machine-class
    /// scoped, so the recognized text carries no cross-platform
    /// byte-equality claim; only the pure-Rust decode does.
    #[cfg(feature = "image-ocr")]
    pub struct ImagePixelOcr {
        /// The worker mode this converter drives. Production always uses
        /// the pinned-runtime `image-ocr` mode; the test-only fake
        /// constructor selects the harness `image-ocr-fake` mode.
        mode: &'static str,
        /// This instance's own runner, built from its own limits at
        /// construction. Security ceilings are per-registry rules data,
        /// so each converter owns its runner rather than sharing a
        /// process-global cache whose ceilings the first caller would
        /// fix for every later one.
        runner: Result<Runner, RunnerError>,
    }

    #[cfg(feature = "image-ocr")]
    impl ImagePixelOcr {
        /// An adapter over the rules-supplied image-OCR jail profile. It
        /// drives the production `image-ocr` worker mode, which fails
        /// closed with `image-ocr-runtime-missing` until a deployment
        /// wires the pinned runtime.
        pub fn new(limits: crate::convert::ImageOcrLimits) -> ImagePixelOcr {
            ImagePixelOcr {
                mode: "image-ocr",
                runner: build_image_runner(image_runner_limits(&limits)),
            }
        }

        /// A test-only converter that drives the harness `image-ocr-fake`
        /// worker mode instead of the pinned-runtime mode. It shares the
        /// identical decode, area guards, and outcome mapping; only stage
        /// 3 is the deterministic fake. The registry never constructs
        /// this, so a release build's image converter always drives the
        /// production mode and never ships fake recognition.
        #[cfg(feature = "test-adapters")]
        pub fn new_fake(limits: crate::convert::ImageOcrLimits) -> ImagePixelOcr {
            ImagePixelOcr {
                mode: "image-ocr-fake",
                runner: build_image_runner(image_runner_limits(&limits)),
            }
        }
    }

    /// Maps the rules-supplied image-OCR profile onto the runner limits.
    #[cfg(feature = "image-ocr")]
    fn image_runner_limits(limits: &crate::convert::ImageOcrLimits) -> crate::runner::Limits {
        crate::runner::Limits {
            wall_timeout: std::time::Duration::from_secs(limits.wall_timeout_secs),
            max_response_bytes: limits.max_response_bytes,
            max_stderr_bytes: limits.max_stderr_bytes,
            address_space_bytes: limits.address_space_bytes,
            cpu_seconds: limits.cpu_seconds,
            file_size_bytes: limits.file_size_bytes,
            max_processes: limits.max_processes,
        }
    }

    /// Builds one runner for the image-OCR jail profile. Called once per
    /// converter instance, so the ceilings that travel are exactly this
    /// registry's, never a leftover from an earlier caller.
    #[cfg(feature = "image-ocr")]
    fn build_image_runner(limits: crate::runner::Limits) -> Result<Runner, RunnerError> {
        Ok(Runner::new(
            crate::runner::jail::platform_backend()?,
            crate::runner::locate_worker()?,
            limits,
        ))
    }

    #[cfg(feature = "image-ocr")]
    impl Converter for ImagePixelOcr {
        fn id(&self) -> &'static str {
            IMAGE_PIXEL_OCR_ID
        }

        fn version(&self) -> &'static str {
            IMAGE_PIXEL_OCR_VERSION
        }

        fn convert(
            &self,
            source: &[u8],
            detected_format: &str,
        ) -> std::result::Result<Outcome, ConvertError> {
            if !matches!(detected_format, "png" | "jpeg" | "webp") {
                return Err(ConvertError {
                    code: "unclaimed_format",
                    message: format!(
                        "the image-pixel-ocr converter does not handle {detected_format}"
                    ),
                });
            }
            let runner = self
                .runner
                .as_ref()
                .map_err(|e| runner_failure(e.clone()))?;
            let input = format!("input.{detected_format}");
            let body: OcrOk = call(
                runner,
                self.mode,
                &OcrRequest {
                    input: input.clone(),
                    kind: OcrInput::Image,
                },
                &[(&input, source)],
            )?;
            // The worker's own notes (such as the long-edge validation
            // note) propagate; the span mapping appends any low-confidence
            // ones and applies the meaningful-text floor.
            let mut warnings = body.warnings;
            let (text, low_confidence) = render_ocr_spans(&body.spans, source.len())?;
            warnings.extend(low_confidence);
            Ok(Outcome {
                converter_id: IMAGE_PIXEL_OCR_ID.to_string(),
                converter_version: IMAGE_PIXEL_OCR_VERSION.to_string(),
                detected_format: detected_format.to_string(),
                artifact_kind: ArtifactKind::Ocr,
                segments: vec![Segment::span(0, text.len(), "document")],
                text,
                warnings,
            })
        }
    }

    /// The OCR protocol adapter. Engine-unpinned: reachable only
    /// through an explicit runner until a rules bump pins an engine.
    pub struct OcrAdapter {
        runner: Runner,
    }

    impl OcrAdapter {
        /// An adapter over an explicit runner.
        pub fn new(runner: Runner) -> OcrAdapter {
            OcrAdapter { runner }
        }
    }

    impl Converter for OcrAdapter {
        fn id(&self) -> &'static str {
            OCR_ADAPTER_ID
        }

        fn version(&self) -> &'static str {
            OCR_ADAPTER_VERSION
        }

        fn convert(
            &self,
            source: &[u8],
            detected_format: &str,
        ) -> std::result::Result<Outcome, ConvertError> {
            if !matches!(detected_format, "png" | "jpeg" | "tiff") {
                return Err(ConvertError {
                    code: "unclaimed_format",
                    message: format!("the OCR adapter does not handle {detected_format}"),
                });
            }
            let input = format!("input.{detected_format}");
            let body: OcrOk = call(
                &self.runner,
                "ocr",
                &OcrRequest {
                    input: input.clone(),
                    kind: OcrInput::Image,
                },
                &[(&input, source)],
            )?;
            // Propagate the worker's own notes rather than starting a
            // fresh vec, then append the low-confidence ones.
            let mut warnings = body.warnings;
            let mut lines = Vec::new();
            for (index, span) in body.spans.iter().enumerate() {
                if !(0.0..=1.0).contains(&span.confidence) {
                    return Err(ConvertError {
                        code: "adapter_error",
                        message: format!(
                            "span {index} confidence {} is outside 0 to 1",
                            span.confidence
                        ),
                    });
                }
                if span.confidence < OCR_CONFIDENCE_WARNING {
                    warnings.push(format!(
                        "ocr_low_confidence: span {index} at {:.2}",
                        span.confidence
                    ));
                }
                lines.push(single_line(&span.text));
            }
            let text = normalize_text(&finish_lines(lines));
            if !source.is_empty() && text.is_empty() {
                return Err(empty_output(source.len()));
            }
            Ok(Outcome {
                // Recognized text is OCR, not extraction.
                artifact_kind: ArtifactKind::Ocr,
                converter_id: OCR_ADAPTER_ID.to_string(),
                converter_version: OCR_ADAPTER_VERSION.to_string(),
                detected_format: detected_format.to_string(),
                segments: vec![Segment::span(0, text.len(), "document")],
                text,
                warnings,
            })
        }
    }

    /// The speech transcription protocol adapter. Engine-unpinned.
    pub struct AsrAdapter {
        runner: Runner,
    }

    impl AsrAdapter {
        /// An adapter over an explicit runner.
        pub fn new(runner: Runner) -> AsrAdapter {
            AsrAdapter { runner }
        }
    }

    impl Converter for AsrAdapter {
        fn id(&self) -> &'static str {
            ASR_ADAPTER_ID
        }

        fn version(&self) -> &'static str {
            ASR_ADAPTER_VERSION
        }

        fn convert(
            &self,
            source: &[u8],
            detected_format: &str,
        ) -> std::result::Result<Outcome, ConvertError> {
            if !matches!(detected_format, "mp3" | "wav" | "m4a") {
                return Err(ConvertError {
                    code: "unclaimed_format",
                    message: format!("the ASR adapter does not handle {detected_format}"),
                });
            }
            let input = format!("input.{detected_format}");
            let body: AsrOk = call(
                &self.runner,
                "asr",
                &AsrRequest {
                    input: input.clone(),
                    language: None,
                },
                &[(&input, source)],
            )?;
            let text = normalize_text(&render_transcript(&body.segments).map_err(|detail| {
                ConvertError {
                    code: "adapter_error",
                    message: detail,
                }
            })?);
            if !source.is_empty() && text.is_empty() {
                return Err(empty_output(source.len()));
            }
            Ok(Outcome {
                // A speech transcript, not extracted text.
                artifact_kind: ArtifactKind::Transcript,
                converter_id: ASR_ADAPTER_ID.to_string(),
                converter_version: ASR_ADAPTER_VERSION.to_string(),
                detected_format: detected_format.to_string(),
                segments: vec![Segment::span(0, text.len(), "document")],
                text,
                warnings: Vec::new(),
            })
        }
    }

    /// The video protocol adapter. Engine-unpinned.
    pub struct VideoAdapter {
        runner: Runner,
    }

    impl VideoAdapter {
        /// An adapter over an explicit runner.
        pub fn new(runner: Runner) -> VideoAdapter {
            VideoAdapter { runner }
        }
    }

    impl Converter for VideoAdapter {
        fn id(&self) -> &'static str {
            VIDEO_ADAPTER_ID
        }

        fn version(&self) -> &'static str {
            VIDEO_ADAPTER_VERSION
        }

        fn convert(
            &self,
            source: &[u8],
            detected_format: &str,
        ) -> std::result::Result<Outcome, ConvertError> {
            if !matches!(detected_format, "mp4" | "mov") {
                return Err(ConvertError {
                    code: "unclaimed_format",
                    message: format!("the video adapter does not handle {detected_format}"),
                });
            }
            let input = format!("input.{detected_format}");
            let body: VideoOk = call(
                &self.runner,
                "video",
                &VideoRequest {
                    input: input.clone(),
                    sample_interval_seconds: 1.0,
                    max_frames: 10_000,
                },
                &[(&input, source)],
            )?;
            let text = normalize_text(&render_screen_states(&body.states).map_err(|detail| {
                ConvertError {
                    code: "adapter_error",
                    message: detail,
                }
            })?);
            if !source.is_empty() && text.is_empty() {
                return Err(empty_output(source.len()));
            }
            Ok(Outcome {
                artifact_kind: ArtifactKind::Text,
                converter_id: VIDEO_ADAPTER_ID.to_string(),
                converter_version: VIDEO_ADAPTER_VERSION.to_string(),
                detected_format: detected_format.to_string(),
                segments: vec![Segment::span(0, text.len(), "document")],
                text,
                warnings: Vec::new(),
            })
        }
    }

    fn empty_output(source_len: usize) -> ConvertError {
        ConvertError {
            code: "empty_output",
            message: format!("source is {source_len} bytes but conversion produced no text"),
        }
    }
}

#[cfg(all(unix, feature = "image-ocr"))]
pub use imp::ImagePixelOcr;
#[cfg(unix)]
pub use imp::{AsrAdapter, OcrAdapter, PdfSubprocess, RecordsSubprocess, VideoAdapter};

#[cfg(not(unix))]
mod imp {
    use super::*;
    use crate::convert::RecordsLimits;

    fn no_backend() -> ConvertError {
        ConvertError {
            code: "sandbox_unavailable",
            message: "no jail backend exists for this platform, refusing to run adapters"
                .to_string(),
        }
    }

    /// The subprocess PDF adapter on a platform without a jail
    /// backend. It refuses every run.
    pub struct PdfSubprocess;

    impl Converter for PdfSubprocess {
        fn id(&self) -> &'static str {
            PDF_SUBPROCESS_ID
        }

        fn version(&self) -> &'static str {
            PDF_SUBPROCESS_VERSION
        }

        fn convert(
            &self,
            _source: &[u8],
            _detected_format: &str,
        ) -> std::result::Result<Outcome, ConvertError> {
            Err(no_backend())
        }
    }

    /// The records worker adapter on a platform without a jail
    /// backend. It refuses every run.
    pub struct RecordsSubprocess;

    impl RecordsSubprocess {
        /// An adapter that refuses every run, ceilings unused.
        pub fn new(_limits: RecordsLimits) -> RecordsSubprocess {
            RecordsSubprocess
        }
    }

    impl Converter for RecordsSubprocess {
        fn id(&self) -> &'static str {
            RECORDS_SUBPROCESS_ID
        }

        fn version(&self) -> &'static str {
            RECORDS_SUBPROCESS_VERSION
        }

        fn convert(
            &self,
            _source: &[u8],
            _detected_format: &str,
        ) -> std::result::Result<Outcome, ConvertError> {
            Err(no_backend())
        }
    }
}

#[cfg(not(unix))]
pub use imp::{PdfSubprocess, RecordsSubprocess};

/// Renders speech segments to the transcript format:
/// `[HH:MM:SS -> HH:MM:SS] Speaker N: text`, one line per segment,
/// ordered by start time.
pub fn render_transcript(segments: &[crate::runner_bodies::AsrSegment]) -> Result<String, String> {
    let mut ordered: Vec<_> = segments.iter().collect();
    ordered.sort_by(|a, b| {
        a.start_seconds
            .total_cmp(&b.start_seconds)
            .then(a.end_seconds.total_cmp(&b.end_seconds))
            .then(a.speaker.cmp(&b.speaker))
    });
    let mut lines = Vec::new();
    for segment in ordered {
        if segment.end_seconds < segment.start_seconds {
            return Err(format!(
                "segment ends at {} before it starts at {}",
                segment.end_seconds, segment.start_seconds
            ));
        }
        lines.push(format!(
            "[{} -> {}] Speaker {}: {}",
            format_timecode(segment.start_seconds)?,
            format_timecode(segment.end_seconds)?,
            segment.speaker,
            single_line(&segment.text)
        ));
    }
    Ok(finish_lines(lines))
}

/// Renders deduplicated screen states to the transcript format:
/// `[on-screen @ HH:MM:SS] text`, ordered by first appearance, with
/// consecutive identical text collapsed.
pub fn render_screen_states(
    states: &[crate::runner_bodies::ScreenState],
) -> Result<String, String> {
    let mut ordered: Vec<_> = states.iter().collect();
    ordered.sort_by(|a, b| {
        a.first_seen_seconds
            .total_cmp(&b.first_seen_seconds)
            .then(a.text.cmp(&b.text))
    });
    let mut lines = Vec::new();
    let mut previous: Option<String> = None;
    for state in ordered {
        let text = single_line(&state.text);
        if previous.as_deref() == Some(text.as_str()) {
            continue;
        }
        lines.push(format!(
            "[on-screen @ {}] {}",
            format_timecode(state.first_seen_seconds)?,
            text
        ));
        previous = Some(text);
    }
    Ok(finish_lines(lines))
}

fn finish_lines(lines: Vec<String>) -> String {
    if lines.is_empty() {
        String::new()
    } else {
        let mut text = lines.join("\n");
        text.push('\n');
        text
    }
}

/// Renders recognized spans to normalized text plus the low-confidence
/// warnings, applying two floors so a well-formed but content-free
/// recognition cannot pass as a blank success.
///
/// A span confidence outside 0 to 1 is a protocol error. A span under
/// [`OCR_CONFIDENCE_WARNING`] adds one low-confidence warning. After the
/// lines are joined and normalized, the meaningful-text floor applies:
/// on a non-empty source, text with no meaningful character (only
/// whitespace, control, or invisible-format code points, exactly the
/// class the PDF recovery path gates on) fails closed with
/// `empty_output` rather than emitting a blank artifact. This is where a
/// well-formed but empty recognition envelope is caught: the envelope
/// grammar keeps `ocr-protocol-error` for malformed stdout, and an
/// empty-but-well-formed recognition lands here as `empty_output`.
#[cfg(all(unix, feature = "image-ocr"))]
pub(crate) fn render_ocr_spans(
    spans: &[crate::runner::protocol::bodies::OcrSpan],
    source_len: usize,
) -> Result<(String, Vec<String>), ConvertError> {
    let mut warnings = Vec::new();
    let mut lines = Vec::new();
    for (index, span) in spans.iter().enumerate() {
        if !(0.0..=1.0).contains(&span.confidence) {
            return Err(ConvertError {
                code: "ocr-protocol-error",
                message: format!(
                    "span {index} confidence {} is outside 0 to 1",
                    span.confidence
                ),
            });
        }
        if span.confidence < OCR_CONFIDENCE_WARNING {
            warnings.push(format!(
                "ocr_low_confidence: span {index} at {:.2}",
                span.confidence
            ));
        }
        lines.push(single_line(&span.text));
    }
    let text = normalize_text(&finish_lines(lines));
    if source_len > 0 && !text.chars().any(crate::convert::is_meaningful) {
        return Err(ConvertError {
            code: "empty_output",
            message: format!("source is {source_len} bytes but conversion produced no text"),
        });
    }
    Ok((text, warnings))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner_bodies::{AsrSegment, ScreenState};

    #[test]
    fn recovered_pdf_text_is_recorded_under_the_recovery_id() {
        // The markdown path keeps the adapter id; a recovered document
        // names the recovery path, and both share the adapter version
        // so the checkpoint key still skips an unchanged recovered PDF.
        assert_eq!(
            pdf_converter_identity(false),
            (PDF_SUBPROCESS_ID, PDF_SUBPROCESS_VERSION)
        );
        assert_eq!(
            pdf_converter_identity(true),
            (PDF_RECOVERED_ID, PDF_RECOVERED_VERSION)
        );
        assert_ne!(PDF_RECOVERED_ID, PDF_SUBPROCESS_ID);
        assert_eq!(PDF_RECOVERED_VERSION, PDF_SUBPROCESS_VERSION);
    }

    #[test]
    fn timecodes_render_as_hours_minutes_seconds() {
        assert_eq!(format_timecode(0.0).unwrap(), "00:00:00");
        assert_eq!(format_timecode(12.9).unwrap(), "00:00:12");
        assert_eq!(format_timecode(182.0).unwrap(), "00:03:02");
        assert_eq!(format_timecode(3661.0).unwrap(), "01:01:01");
        assert!(format_timecode(-1.0).is_err());
        assert!(format_timecode(f64::NAN).is_err());
    }

    #[test]
    fn transcripts_render_one_ordered_line_per_segment() {
        let segments = vec![
            AsrSegment {
                start_seconds: 19.0,
                end_seconds: 24.0,
                speaker: 2,
                text: "second\nline".to_string(),
            },
            AsrSegment {
                start_seconds: 12.0,
                end_seconds: 19.0,
                speaker: 1,
                text: "first remark".to_string(),
            },
        ];
        assert_eq!(
            render_transcript(&segments).unwrap(),
            "[00:00:12 -> 00:00:19] Speaker 1: first remark\n\
             [00:00:19 -> 00:00:24] Speaker 2: second line\n"
        );
    }

    #[test]
    fn transcripts_reject_a_segment_that_ends_before_it_starts() {
        let segments = vec![AsrSegment {
            start_seconds: 5.0,
            end_seconds: 4.0,
            speaker: 1,
            text: "impossible".to_string(),
        }];
        assert!(render_transcript(&segments).is_err());
    }

    #[test]
    fn screen_states_render_deduplicated_in_order() {
        let states = vec![
            ScreenState {
                first_seen_seconds: 182.0,
                text: "Quarterly revenue".to_string(),
            },
            ScreenState {
                first_seen_seconds: 10.0,
                text: "Agenda".to_string(),
            },
            ScreenState {
                first_seen_seconds: 200.0,
                text: "Quarterly revenue".to_string(),
            },
        ];
        assert_eq!(
            render_screen_states(&states).unwrap(),
            "[on-screen @ 00:00:10] Agenda\n[on-screen @ 00:03:02] Quarterly revenue\n"
        );
    }
}
