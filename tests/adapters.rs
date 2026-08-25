//! Protocol tests for the OCR, ASR, and video adapter scaffolds.
//!
//! Each adapter speaks the framed protocol to a fake engine compiled
//! into the worker under the `test-adapters` feature. The engines are
//! stand-ins for the real wrappers, which land once an engine is
//! pinned. These tests prove the adapter renders a well-formed engine
//! response into the outcome shape and the transcript format, so the
//! protocol boundary is exercised end to end without any real engine.

#![cfg(unix)]

use std::time::Duration;

use text_mirror::convert::Converter;
use text_mirror::convert::subprocess::{AsrAdapter, OcrAdapter, VideoAdapter};
use text_mirror::manifest::ArtifactKind;
use text_mirror::runner::jail::platform_backend;
use text_mirror::runner::{Limits, Runner, locate_worker};

fn runner() -> Runner {
    let backend = platform_backend().expect("this platform has a jail backend");
    let worker = locate_worker().expect("the worker binary sits beside the test binary");
    Runner::new(
        backend,
        worker,
        Limits {
            wall_timeout: Duration::from_secs(10),
            ..Limits::default()
        },
    )
}

#[test]
fn the_ocr_adapter_renders_spans_and_flags_low_confidence() {
    let outcome = OcrAdapter::new(runner())
        .convert(b"fake png bytes", "png")
        .expect("the OCR adapter converts");
    assert_eq!(outcome.converter_id, "ocr-adapter");
    // Recognized text is stamped as OCR, not extraction.
    assert_eq!(outcome.artifact_kind, ArtifactKind::Ocr);
    assert!(outcome.text.contains("recognized from image"));
    assert!(outcome.text.contains("faint line"));
    // The fake engine returns one span below the confidence floor.
    assert!(
        outcome
            .warnings
            .iter()
            .any(|w| w.starts_with("ocr_low_confidence:")),
        "warnings: {:?}",
        outcome.warnings
    );
    // A whole-document span covers the artifact.
    assert!(
        outcome
            .segments
            .iter()
            .any(|s| s.source.as_deref() == Some("document") && s.end == outcome.text.len() as u64)
    );
}

#[test]
fn the_asr_adapter_renders_the_transcript_format() {
    let outcome = AsrAdapter::new(runner())
        .convert(b"fake mp3 bytes", "mp3")
        .expect("the ASR adapter converts");
    assert_eq!(outcome.converter_id, "asr-adapter");
    // A speech transcript, not extracted text.
    assert_eq!(outcome.artifact_kind, ArtifactKind::Transcript);
    assert_eq!(
        outcome.text,
        "[00:00:00 -> 00:00:04] Speaker 1: welcome to the recording\n\
         [00:00:04 -> 00:00:09] Speaker 2: glad to be here\n"
    );
}

#[test]
fn the_video_adapter_deduplicates_screen_states() {
    let outcome = VideoAdapter::new(runner())
        .convert(b"fake mp4 bytes", "mp4")
        .expect("the video adapter converts");
    assert_eq!(outcome.converter_id, "video-adapter");
    // The fake engine repeats one screen state, which the transcript
    // renders once.
    assert_eq!(
        outcome.text,
        "[on-screen @ 00:00:02] Title slide\n\
         [on-screen @ 00:00:08] Quarterly revenue\n"
    );
}

#[test]
fn adapters_reject_formats_they_do_not_claim() {
    assert_eq!(
        OcrAdapter::new(runner())
            .convert(b"x", "mp3")
            .unwrap_err()
            .code,
        "unclaimed_format"
    );
    assert_eq!(
        AsrAdapter::new(runner())
            .convert(b"x", "png")
            .unwrap_err()
            .code,
        "unclaimed_format"
    );
    assert_eq!(
        VideoAdapter::new(runner())
            .convert(b"x", "png")
            .unwrap_err()
            .code,
        "unclaimed_format"
    );
}
