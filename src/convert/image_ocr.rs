//! The in-jail raster decode and recognize path, run only inside the
//! subprocess sandbox.
//!
//! Raster images reach the pinned vision engine through three stages,
//! all inside the jailed worker. Each of the three stages is an
//! independent fail-closed layer: the parent's source-bytes ceiling
//! bounds what stages here, the decode allocation guard bounds the
//! decoded pixel buffers, and the area cap bounds the encoder input.
//! No single number carries the whole containment claim.
//!
//! 1. DECODE. png, jpeg, and webp are already rasters and decode with
//!    the pure-Rust `image` crate. The decode is deterministic and
//!    byte-identical across machine classes, so the supported-format
//!    set and the decode carry the only cross-platform equality claim
//!    this converter makes. The recognized text does not: it is
//!    machine-class scoped.
//! 2. AREA PREFLIGHT. The encoder-input area cap is asserted on the
//!    header dimensions before the full decode, and a violation fails
//!    closed with no silent resize. An oversized raster degenerates the
//!    vision output rather than erroring at the encoder, so the guard
//!    lives in the hazard's own unit, area, with a loud reason.
//! 3. RECOGNIZE. The canonical raster is re-encoded once and handed to
//!    the hash-verified engine child. The child's stdout is parsed
//!    against a record-separator-fenced envelope, so any stray engine
//!    diagnostic degrades loudly to a protocol error rather than
//!    silently polluting the recognized text.
//!
//! Only the canonical pixels reach the recognition stage. No metadata,
//! embedded text, or file information is read: structured or metadata
//! extraction, if ever wanted, is a separately named capability, never
//! padding this pixel-only leg.
//!
//! The engine, its weights, the multimodal projector, the fixed
//! prompt, and the serialized limit policy are pinned by hash and
//! named here only by generic role label. This core release wires no
//! runtime into the jail, so recognition fails closed with a
//! runtime-missing reason until a deployment supplies the pinned
//! runtime. The live-engine recognition and its cross-restart
//! determinism proof are pending at that runtime-missing seam and are
//! required before the engine path is enabled.

use std::path::Path;

use image::{ExtendedColorType, ImageEncoder, ImageFormat, ImageReader, Limits, RgbImage};

use crate::runner::protocol::bodies::{OcrInput, OcrOk, OcrRequest, OcrSpan};

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

/// A recognition failure with a stable reason code. The message never
/// embeds a path, host, endpoint, or device identity.
#[derive(Debug)]
pub struct ImageOcrError {
    /// Stable reason, such as `image-ocr-area-exceeded`.
    pub code: &'static str,
    /// Detail for a human reading the manifest.
    pub message: String,
}

impl ImageOcrError {
    fn new(code: &'static str, message: impl Into<String>) -> ImageOcrError {
        ImageOcrError {
            code,
            message: message.into(),
        }
    }
}

/// Stages 1 and 2 for one request: read the staged input and decode it
/// to a canonical raster, with the area preflight applied. Shared by the
/// production [`recognize`] and, under `test-adapters`, by
/// [`recognize_fake`], so both drive the identical decode and area
/// guards and only stage 3 differs.
fn stage_pixels(request: &OcrRequest) -> Result<(RgbImage, Vec<String>), ImageOcrError> {
    if !matches!(request.kind, OcrInput::Image) {
        return Err(ImageOcrError::new(
            "ocr-protocol-error",
            "the image-pixel-ocr worker recognizes standalone rasters only",
        ));
    }
    let input = Path::new(&request.input);
    let format = input
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or_default();
    let bytes = std::fs::read(input).map_err(|e| {
        ImageOcrError::new(
            "io",
            format!("cannot read the staged input {}: {e}", request.input),
        )
    })?;
    decode_to_rgb(&bytes, format)
}

/// Recognizes text from one staged raster.
///
/// `request.input` is a bare name in the worker's jail directory whose
/// extension names the resolved format, exactly as the parent staged
/// it. The kind is always a standalone image for this converter; a page
/// render is a paginated-source concern and never reaches here.
///
/// This is the production recognition symbol and compiles one way in
/// every feature combination: it always drives the pinned-runtime stage
/// 3, which fails closed with `image-ocr-runtime-missing` until a
/// deployment wires the runtime. It is never swapped for a fake, so an
/// all-features build recognizes through this same fail-closed path.
pub fn recognize(request: &OcrRequest) -> Result<OcrOk, ImageOcrError> {
    let (rgb, warnings) = stage_pixels(request)?;
    let spans = recognize_pixels(&rgb)?;
    Ok(OcrOk { spans, warnings })
}

/// The fake-engine recognition path, selected only by the test harness
/// (the `image-ocr-fake` worker mode), never by the production worker
/// mode or the registry. It is a separate symbol from [`recognize`], not
/// a replacement of it: stages 1 and 2 are the same real decode and area
/// guards, and only stage 3 is the deterministic fake below. This
/// mirrors how the existing fake-engine worker modes sit beside the
/// production modes rather than swapping them.
#[cfg(feature = "test-adapters")]
pub fn recognize_fake(request: &OcrRequest) -> Result<OcrOk, ImageOcrError> {
    let (rgb, warnings) = stage_pixels(request)?;
    let spans = recognize_pixels_fake(&rgb)?;
    Ok(OcrOk { spans, warnings })
}

/// The decode allocation guard as an `image` limit set: the per-buffer
/// allocation is bounded, and the per-dimension limits stay unset
/// because the ruled cap is on area and a per-dimension cap would
/// wrongly fail a legal wide raster.
fn decode_limits() -> Limits {
    let mut limits = Limits::no_limits();
    limits.max_alloc = Some(IMAGE_OCR_DECODE_ALLOC);
    limits
}

/// Stages 1 and 2: probe dimensions, assert the area cap, decode, and
/// convert to a canonical 8-bit RGB raster. Alpha is flattened here, so
/// a transparent raster cannot smuggle a channel the engine never sees,
/// and the hand-off is one canonical channel order regardless of the
/// source format.
fn decode_to_rgb(bytes: &[u8], format: &str) -> Result<(RgbImage, Vec<String>), ImageOcrError> {
    let fmt = match format {
        "png" => ImageFormat::Png,
        "jpeg" => ImageFormat::Jpeg,
        "webp" => ImageFormat::WebP,
        other => {
            return Err(ImageOcrError::new(
                "image-ocr-decode-failed",
                format!("the image-pixel-ocr worker does not decode {other}"),
            ));
        }
    };
    let decode_failed = |e: image::ImageError| {
        ImageOcrError::new(
            "image-ocr-decode-failed",
            format!("cannot decode the raster: {e}"),
        )
    };

    // Probe dimensions from the header without decoding pixels.
    let mut reader = ImageReader::with_format(std::io::Cursor::new(bytes), fmt);
    reader.limits(decode_limits());
    let (width, height) = reader.into_dimensions().map_err(decode_failed)?;

    // Area preflight, in the hazard's unit, fail closed with no resize.
    let area = u64::from(width) * u64::from(height);
    if area > IMAGE_OCR_MAX_AREA_PX {
        return Err(ImageOcrError::new(
            "image-ocr-area-exceeded",
            format!(
                "{width}x{height} = {area} px over the {IMAGE_OCR_MAX_AREA_PX} px encoder-input area cap"
            ),
        ));
    }
    let mut warnings = Vec::new();
    if width.max(height) > IMAGE_OCR_VALIDATED_LONG_EDGE {
        warnings.push(format!(
            "image_ocr_long_edge: {width}x{height} within the area cap but outside validated evidence, logged for validation"
        ));
    }

    // Decode under the same allocation guard, then flatten to RGB.
    let mut reader = ImageReader::with_format(std::io::Cursor::new(bytes), fmt);
    reader.limits(decode_limits());
    let image = reader.decode().map_err(decode_failed)?;
    if (image.width(), image.height()) != (width, height) {
        return Err(ImageOcrError::new(
            "image-ocr-decode-failed",
            "the decoded dimensions disagree with the header",
        ));
    }
    Ok((image.to_rgb8(), warnings))
}

/// Re-encodes the canonical raster as PNG with fixed encoder settings,
/// so the engine always reads one deterministic container.
fn encode_png(rgb: &RgbImage) -> Result<Vec<u8>, ImageOcrError> {
    let mut buffer = Vec::new();
    image::codecs::png::PngEncoder::new(&mut buffer)
        .write_image(
            rgb.as_raw(),
            rgb.width(),
            rgb.height(),
            ExtendedColorType::Rgb8,
        )
        .map_err(|e| {
            ImageOcrError::new(
                "image-ocr-decode-failed",
                format!("cannot re-encode the canonical raster: {e}"),
            )
        })?;
    Ok(buffer)
}

/// Stage 3 under the fake engine, reached only through
/// [`recognize_fake`] and the harness-selected `image-ocr-fake` worker
/// mode. Deterministic spans are derived from the canonical pixels. The
/// text is a stable digest of the RGB bytes, so an alpha-flattened
/// raster and its opaque twin recognize identically, which is the
/// flatten proof. The second span sits below the confidence floor so the
/// low-confidence warning path is exercised. This is a separate symbol
/// from the production [`recognize_pixels`]; it never replaces it.
#[cfg(feature = "test-adapters")]
fn recognize_pixels_fake(rgb: &RgbImage) -> Result<Vec<OcrSpan>, ImageOcrError> {
    let _canonical = encode_png(rgb)?;
    let digest = crate::hash::hash_bytes(rgb.as_raw());
    Ok(vec![
        OcrSpan {
            text: format!(
                "recognized from a {}x{} raster {}",
                rgb.width(),
                rgb.height(),
                &digest[..16]
            ),
            confidence: 0.94,
        },
        OcrSpan {
            text: "faint line".to_string(),
            confidence: 0.31,
        },
    ])
}

/// Stage 3 under the pinned runtime: re-encode the canonical raster,
/// verify the runtime inventory fresh (the worker is cold-started per
/// invocation, so a boot-time check would miss a swapped component),
/// assert an accelerator-class device is present and selected, exec the
/// engine child, and parse its fenced stdout. This core release wires
/// no runtime, so `resolve_components` yields nothing and the verify
/// fails closed with runtime-missing.
///
/// This is the production recognition symbol. It carries no feature cfg,
/// so it compiles identically in every feature combination, including an
/// all-features build: the fake stage 3 above is a separate function and
/// never stands in for this one.
fn recognize_pixels(rgb: &RgbImage) -> Result<Vec<OcrSpan>, ImageOcrError> {
    let canonical = encode_png(rgb)?;
    let components = runtime::resolve_components();
    runtime::verify_inventory(&runtime::CORE_ROLES, &components)?;
    let devices = runtime::enumerate_devices(&components);
    runtime::check_accelerator(&devices)?;
    let stdout = runtime::engine_stdout(&components, &canonical)?;
    let text = runtime::parse_fenced_envelope(&stdout)?;
    Ok(vec![OcrSpan {
        text,
        confidence: 1.0,
    }])
}

/// The pinned-runtime layer: inventory verification, the accelerator
/// class check, the engine child, and the fenced-stdout parse.
///
/// These run on the production recognition path, which compiles in every
/// feature combination, and are exercised directly by the unit tests
/// below. The fake-engine path is a separate stage 3 selected only by
/// the harness; it does not remove this layer from the build.
mod runtime {
    use std::path::PathBuf;

    use super::ImageOcrError;

    /// The runtime roles the worker verifies before recognition. Each
    /// is a generic role label only: no filename, path, host, or device
    /// identity is recorded here, in error messages, or in the manifest.
    ///
    /// These are the five roles the core png/jpeg/webp path needs: the
    /// engine binary, its weights, the projector, the prompt, and the
    /// serialized limit policy. Three further raster-provider roles
    /// exist only for the gated external-rasterizer set, which this core
    /// ships nothing of, so verification here is deliberately scoped to
    /// these five. Extending it to all eight is a carried obligation of
    /// the provider build (see the provider-surface note below).
    pub(super) const CORE_ROLES: [&str; 5] = [
        "engine-cli",
        "vision-weights",
        "vision-projector",
        "ocr-prompt",
        "ocr-limit-policy",
    ];

    // Provider-surface TODO (carried obligation): the gated external
    // rasterizer build verifies eight roles, not five. It extends the
    // inventory above with the three raster-provider roles `raster-ql`,
    // `raster-magick`, and `raster-sips`, each a generic role label. The
    // core ships no rasterizer, so it deliberately scopes verification to
    // the five core roles; the provider build owns extending it to all
    // eight.

    /// A short, scrub-clean marker for the one behavior this core does
    /// not yet carry: the live-engine recognition and the proof that it
    /// is deterministic across a worker restart. It is required-nonempty
    /// so the obligation cannot be quietly dropped, and it lives at the
    /// runtime-missing seam because that is exactly where the unwired
    /// runtime leaves the gap.
    pub(super) const DETERMINISM_PROOF_PENDING: &str = "live-engine cross-restart determinism proof pending; required before the engine path is enabled";

    /// The sentinels the worker directs the model to wrap its
    /// recognized text between. Each is fenced by an ASCII record
    /// separator (0x1E), which cannot occur in ordinary document text,
    /// so a sentinel cannot be forged by the recognized content.
    pub(super) const BEGIN_SENTINEL: &[u8] = b"\x1eTM-OCR-BEGIN\x1e";
    pub(super) const END_SENTINEL: &[u8] = b"\x1eTM-OCR-END\x1e";

    /// One runtime component, pinned by BLAKE3 and named by role label
    /// only. No filename, path, host, or device identity is a literal
    /// in this crate: the path is resolved at runtime and the expected
    /// hash is deployment data.
    pub(super) struct Component {
        pub(super) role: &'static str,
        pub(super) path: PathBuf,
        pub(super) expected_blake3: String,
    }

    /// Resolves the pinned runtime components a deployment wired into
    /// the jail. This core release wires none, so every role is
    /// unresolved and recognition fails closed. A deployment implements
    /// this against its hash-pinned engine, weights, projector, prompt,
    /// and serialized limit policy, each named by role label only.
    pub(super) fn resolve_components() -> Vec<Component> {
        Vec::new()
    }

    /// Verifies every required role is present and matches its pinned
    /// BLAKE3. A missing component is a distinct reason from a
    /// mismatched one, so the manifest tells the two apart.
    pub(super) fn verify_inventory(
        required: &[&str],
        resolved: &[Component],
    ) -> Result<(), ImageOcrError> {
        for role in required {
            let Some(component) = resolved.iter().find(|component| component.role == *role) else {
                return Err(ImageOcrError::new(
                    "image-ocr-runtime-missing",
                    format!("runtime component {role} is not present"),
                ));
            };
            let actual = crate::hash::hash_file(&component.path).map_err(|_| {
                ImageOcrError::new(
                    "image-ocr-runtime-missing",
                    format!("runtime component {role} cannot be read"),
                )
            })?;
            if actual != component.expected_blake3 {
                return Err(ImageOcrError::new(
                    "image-ocr-runtime-mismatch",
                    format!("runtime component {role} does not match its pinned hash"),
                ));
            }
        }
        Ok(())
    }

    /// An accelerator device class, kept as a class so the check never
    /// string-compares a device id: the same check generalizes across
    /// machine classes.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(super) enum DeviceClass {
        Accelerator,
        // A resolved runtime enumerates CPU-class devices too; the check
        // fails closed on them. No runtime is wired in this core
        // release, so the variant is constructed only by the tests that
        // prove the fail-closed path.
        #[cfg_attr(not(test), allow(dead_code))]
        Cpu,
    }

    /// One enumerated compute device: its class, and whether the engine
    /// selected it.
    pub(super) struct Device {
        pub(super) class: DeviceClass,
        pub(super) selected: bool,
    }

    /// Enumerates the engine's compute devices. A resolved runtime lists
    /// them from the engine; with no runtime wired the list is empty and
    /// the accelerator check below fails closed.
    pub(super) fn enumerate_devices(_components: &[Component]) -> Vec<Device> {
        Vec::new()
    }

    /// Asserts an accelerator-class device is present and selected. No
    /// silent CPU fallback: an empty enumeration or a CPU resolution
    /// fails closed. The check is on device class, never a literal id.
    pub(super) fn check_accelerator(devices: &[Device]) -> Result<(), ImageOcrError> {
        if devices
            .iter()
            .any(|device| device.class == DeviceClass::Accelerator && device.selected)
        {
            Ok(())
        } else {
            Err(ImageOcrError::new(
                "image-ocr-no-accelerator",
                "no accelerator-class device is present and selected, refusing a cpu fallback",
            ))
        }
    }

    /// Execs the hash-verified engine child and returns its raw stdout.
    /// The invocation is resolved from the runtime components, so no
    /// engine argv, device id, or model identity is a literal here. This
    /// core release wires no runtime, so this is unreached and the
    /// runtime verification above is the fail-closed guard. The live exec
    /// and its cross-restart determinism proof are pending here; see
    /// [`DETERMINISM_PROOF_PENDING`].
    pub(super) fn engine_stdout(
        _components: &[Component],
        _canonical_png: &[u8],
    ) -> Result<Vec<u8>, ImageOcrError> {
        Err(ImageOcrError::new(
            "image-ocr-runtime-missing",
            format!(
                "no pinned vision runtime is wired into this build; {DETERMINISM_PROOF_PENDING}"
            ),
        ))
    }

    /// Parses the record-separator-fenced recognition envelope.
    ///
    /// The child's whole stdout must be exactly one BEGIN sentinel, the
    /// recognized text, and one END sentinel, with nothing before BEGIN
    /// and nothing after END except an optional single trailing newline.
    /// Any deviation, a missing or doubled or out-of-order sentinel, a
    /// byte outside the envelope such as a banner or a leaked log line,
    /// or a degenerate output that emits no sentinels, is a protocol
    /// error. This makes both an engine log leak and the oversized-raster
    /// degeneracy fail loudly rather than pollute the recognized text.
    pub(super) fn parse_fenced_envelope(stdout: &[u8]) -> Result<String, ImageOcrError> {
        let protocol_error = |detail: &str| {
            ImageOcrError::new(
                "ocr-protocol-error",
                format!("engine stdout is not a clean recognition envelope: {detail}"),
            )
        };
        let begins = count_occurrences(stdout, BEGIN_SENTINEL);
        let ends = count_occurrences(stdout, END_SENTINEL);
        if begins != 1 {
            return Err(protocol_error(
                "the BEGIN sentinel does not appear exactly once",
            ));
        }
        if ends != 1 {
            return Err(protocol_error(
                "the END sentinel does not appear exactly once",
            ));
        }
        let begin = find(stdout, BEGIN_SENTINEL).expect("one BEGIN was counted");
        let end = find(stdout, END_SENTINEL).expect("one END was counted");
        let text_start = begin + BEGIN_SENTINEL.len();
        if begin != 0 {
            return Err(protocol_error("bytes appear before the BEGIN sentinel"));
        }
        if text_start > end {
            return Err(protocol_error("the sentinels are out of order or overlap"));
        }
        let after_end = end + END_SENTINEL.len();
        let tail = &stdout[after_end..];
        if !(tail.is_empty() || tail == b"\n") {
            return Err(protocol_error("bytes appear after the END sentinel"));
        }
        let text_bytes = &stdout[text_start..end];
        String::from_utf8(text_bytes.to_vec())
            .map_err(|_| protocol_error("the recognized text is not valid utf-8"))
    }

    /// Counts non-overlapping occurrences of `needle` in `haystack`.
    pub(super) fn count_occurrences(haystack: &[u8], needle: &[u8]) -> usize {
        if needle.is_empty() || haystack.len() < needle.len() {
            return 0;
        }
        let mut count = 0;
        let mut index = 0;
        while index + needle.len() <= haystack.len() {
            if &haystack[index..index + needle.len()] == needle {
                count += 1;
                index += needle.len();
            } else {
                index += 1;
            }
        }
        count
    }

    /// The first index of `needle` in `haystack`.
    pub(super) fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        if needle.is_empty() || haystack.len() < needle.len() {
            return None;
        }
        (0..=haystack.len() - needle.len()).find(|&i| &haystack[i..i + needle.len()] == needle)
    }
}

#[cfg(test)]
mod tests {
    use super::runtime::{
        BEGIN_SENTINEL, CORE_ROLES, Component, DETERMINISM_PROOF_PENDING, Device, DeviceClass,
        END_SENTINEL, check_accelerator, engine_stdout, enumerate_devices, parse_fenced_envelope,
        resolve_components, verify_inventory,
    };
    use super::*;
    use std::io::Write;

    fn png(width: u32, height: u32) -> Vec<u8> {
        let image = RgbImage::from_pixel(width, height, image::Rgb([200, 40, 40]));
        encode_png(&image).unwrap()
    }

    fn fence(text: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(BEGIN_SENTINEL);
        out.extend_from_slice(text);
        out.extend_from_slice(END_SENTINEL);
        out
    }

    #[test]
    fn decodes_a_small_raster_to_rgb() {
        let (rgb, warnings) = decode_to_rgb(&png(8, 8), "png").unwrap();
        assert_eq!((rgb.width(), rgb.height()), (8, 8));
        assert!(warnings.is_empty());
    }

    #[test]
    fn each_supported_format_decodes() {
        // jpeg and webp round-trip through the encoders the crate pulls,
        // so build them from a decoded png and re-read them.
        let (rgb, _) = decode_to_rgb(&png(16, 16), "png").unwrap();
        let mut jpeg = Vec::new();
        image::codecs::jpeg::JpegEncoder::new(&mut jpeg)
            .encode_image(&rgb)
            .unwrap();
        assert!(decode_to_rgb(&jpeg, "jpeg").is_ok());
        let mut webp = Vec::new();
        image::codecs::webp::WebPEncoder::new_lossless(&mut webp)
            .encode(
                rgb.as_raw(),
                rgb.width(),
                rgb.height(),
                ExtendedColorType::Rgb8,
            )
            .unwrap();
        assert!(decode_to_rgb(&webp, "webp").is_ok());
    }

    #[test]
    fn the_area_cap_fails_closed_with_no_resize() {
        // The area cap is the encoder-input layer of a layered
        // containment, distinct from the parent's source-bytes ceiling
        // and from the decode allocation guard; each fails closed on its
        // own. This exercises the area layer.
        // 2048x2048 = 4.19 MP, over the cap.
        let err = decode_to_rgb(&png(2048, 2048), "png").unwrap_err();
        assert_eq!(err.code, "image-ocr-area-exceeded");
        // 1536x1536 = 2.36 MP and 1600x900 = 1.44 MP are in scope.
        assert!(decode_to_rgb(&png(1536, 1536), "png").is_ok());
        let (_, warnings) = decode_to_rgb(&png(1600, 900), "png").unwrap();
        assert!(warnings.is_empty());
    }

    #[test]
    fn a_long_edge_within_the_area_cap_warns_once_and_proceeds() {
        // 3000x786 = 2,358,000 px, legal by area, long edge over 1600.
        let (rgb, warnings) = decode_to_rgb(&png(3000, 786), "png").unwrap();
        assert_eq!((rgb.width(), rgb.height()), (3000, 786));
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].starts_with("image_ocr_long_edge:"));
    }

    #[test]
    fn alpha_is_flattened_so_transparent_and_opaque_twins_match() {
        // Same RGB channels, one fully transparent, one fully opaque.
        let transparent = image::RgbaImage::from_pixel(4, 4, image::Rgba([10, 20, 30, 0]));
        let opaque = image::RgbaImage::from_pixel(4, 4, image::Rgba([10, 20, 30, 255]));
        let mut a = Vec::new();
        image::codecs::png::PngEncoder::new(&mut a)
            .write_image(transparent.as_raw(), 4, 4, ExtendedColorType::Rgba8)
            .unwrap();
        let mut b = Vec::new();
        image::codecs::png::PngEncoder::new(&mut b)
            .write_image(opaque.as_raw(), 4, 4, ExtendedColorType::Rgba8)
            .unwrap();
        let (rgb_a, _) = decode_to_rgb(&a, "png").unwrap();
        let (rgb_b, _) = decode_to_rgb(&b, "png").unwrap();
        assert_eq!(rgb_a.as_raw(), rgb_b.as_raw());
    }

    #[test]
    fn corrupt_and_truncated_bytes_fail_with_decode_failed() {
        for bytes in [
            b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR".as_slice(),
            b"not an image at all".as_slice(),
        ] {
            let err = decode_to_rgb(bytes, "png").unwrap_err();
            assert_eq!(err.code, "image-ocr-decode-failed");
        }
    }

    #[test]
    fn a_clean_envelope_parses_with_and_without_a_trailing_newline() {
        assert_eq!(
            parse_fenced_envelope(&fence(b"hello world")).unwrap(),
            "hello world"
        );
        let mut with_newline = fence(b"line");
        with_newline.push(b'\n');
        assert_eq!(parse_fenced_envelope(&with_newline).unwrap(), "line");
    }

    #[test]
    fn every_envelope_violation_is_a_protocol_error() {
        let mut doubled_begin = Vec::new();
        doubled_begin.extend_from_slice(BEGIN_SENTINEL);
        doubled_begin.extend_from_slice(&fence(b"x"));
        let mut out_of_order = Vec::new();
        out_of_order.extend_from_slice(END_SENTINEL);
        out_of_order.extend_from_slice(b"x");
        out_of_order.extend_from_slice(BEGIN_SENTINEL);
        let mut leading = b"banner\n".to_vec();
        leading.extend_from_slice(&fence(b"x"));
        let mut trailing = fence(b"x");
        trailing.extend_from_slice(b"timing 12ms");
        let mut leaked_log = fence(b"x");
        leaked_log.extend_from_slice(b"\nengine: loaded\n");
        for bytes in [
            BEGIN_SENTINEL.to_vec(), // missing END
            END_SENTINEL.to_vec(),   // missing BEGIN
            doubled_begin,           // doubled sentinel
            out_of_order,            // out of order
            leading,                 // byte before BEGIN
            trailing,                // byte after END
            leaked_log,              // leaked log line
            b"!!!!!!!!".to_vec(),    // degenerate, no sentinels
        ] {
            let err = parse_fenced_envelope(&bytes).unwrap_err();
            assert_eq!(err.code, "ocr-protocol-error", "{bytes:?}");
        }
    }

    #[test]
    fn the_core_build_resolves_no_runtime_so_recognition_fails_closed() {
        // No runtime is wired into this core release, so every role is
        // unresolved and the inventory verification fails closed.
        assert!(resolve_components().is_empty());
        let err = verify_inventory(&CORE_ROLES, &resolve_components()).unwrap_err();
        assert_eq!(err.code, "image-ocr-runtime-missing");
    }

    #[test]
    fn the_inventory_flags_missing_and_mismatch_distinctly() {
        // No components resolved: the first required role is missing.
        let missing = verify_inventory(&CORE_ROLES, &[]).unwrap_err();
        assert_eq!(missing.code, "image-ocr-runtime-missing");

        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(b"weights").unwrap();
        file.flush().unwrap();
        let good = crate::hash::hash_file(file.path()).unwrap();
        let present = [Component {
            role: "engine-cli",
            path: file.path().to_path_buf(),
            expected_blake3: good.clone(),
        }];
        // Present and matching passes for the single role.
        assert!(verify_inventory(&["engine-cli"], &present).is_ok());
        // Present but wrong hash is a mismatch, a distinct reason.
        let wrong = [Component {
            role: "engine-cli",
            path: file.path().to_path_buf(),
            expected_blake3: "0".repeat(64),
        }];
        let mismatch = verify_inventory(&["engine-cli"], &wrong).unwrap_err();
        assert_eq!(mismatch.code, "image-ocr-runtime-mismatch");
    }

    #[test]
    fn the_accelerator_check_fails_closed_without_a_selected_accelerator() {
        // Core enumeration is empty with no runtime wired.
        let empty = check_accelerator(&enumerate_devices(&[])).unwrap_err();
        assert_eq!(empty.code, "image-ocr-no-accelerator");
        // A CPU device, or an unselected accelerator, does not satisfy it.
        let cpu = check_accelerator(&[Device {
            class: DeviceClass::Cpu,
            selected: true,
        }])
        .unwrap_err();
        assert_eq!(cpu.code, "image-ocr-no-accelerator");
        assert!(
            check_accelerator(&[Device {
                class: DeviceClass::Accelerator,
                selected: false,
            }])
            .is_err()
        );
        // A selected accelerator-class device passes.
        assert!(
            check_accelerator(&[Device {
                class: DeviceClass::Accelerator,
                selected: true,
            }])
            .is_ok()
        );
    }

    #[test]
    fn the_engine_exec_fails_closed_and_carries_the_pending_determinism_note() {
        let err = engine_stdout(&[], b"png").unwrap_err();
        assert_eq!(err.code, "image-ocr-runtime-missing");
        // The pending-proof marker is non-empty and travels with the
        // fail-closed reason at the runtime-missing seam.
        assert!(!DETERMINISM_PROOF_PENDING.is_empty());
        assert!(err.message.contains(DETERMINISM_PROOF_PENDING));
    }

    #[test]
    fn the_production_recognize_fails_closed_in_every_feature_combination() {
        // recognize() is the production symbol and is never swapped for a
        // fake, so even an all-features build reaches the pinned-runtime
        // stage 3 and fails closed because no runtime is wired. This is
        // the guard that a fake never ships behind the production path.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("input.png");
        std::fs::write(&path, png(8, 8)).unwrap();
        let request = OcrRequest {
            input: path.to_str().unwrap().to_string(),
            kind: OcrInput::Image,
        };
        let err = recognize(&request).unwrap_err();
        assert_eq!(err.code, "image-ocr-runtime-missing");
    }

    #[test]
    fn a_well_formed_but_content_free_envelope_is_empty_output_not_protocol_error() {
        // Only whitespace and control bytes between the sentinels: the
        // envelope is well-formed, so it is not a protocol error, and it
        // carries no meaningful character, so the converter's meaningful
        // floor fails it closed with empty_output on a non-empty source.
        let text = parse_fenced_envelope(&fence(b" \t\r\n\x07")).unwrap();
        assert!(!text.chars().any(crate::convert::is_meaningful));
        let span = OcrSpan {
            text,
            confidence: 1.0,
        };
        let err = crate::convert::subprocess::render_ocr_spans(&[span], 128).unwrap_err();
        assert_eq!(err.code, "empty_output");
    }

    #[test]
    fn the_inventory_is_scoped_to_the_five_core_roles() {
        // The core ships no rasterizer, so it verifies exactly the five
        // core roles; the three raster-provider roles are the gated
        // provider build's carried obligation.
        assert_eq!(CORE_ROLES.len(), 5);
        assert!(!CORE_ROLES.iter().any(|role| role.starts_with("raster-")));
    }
}
