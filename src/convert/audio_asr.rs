//! The in-jail audio decode and transcribe path, run only inside the
//! subprocess sandbox.
//!
//! Audio reaches the pinned speech engine through four stages, all
//! inside the jailed worker, each a fail-closed layer of its own:
//!
//! 1. DECODE. wav, mp3, flac, and AAC-LC m4a decode with the
//!    pure-Rust symphonia crate into interleaved signed 16-bit
//!    samples. Nothing is resampled, downmixed, dithered, or
//!    normalized: the jail wav is written at the DECODER-reported
//!    sample rate and channel count, never the container's declared
//!    rate, and the engine owns any resampling or channel mixing.
//! 2. PREFLIGHTS. The decoded frame count is checked against the
//!    ruled duration ceiling with a small priming allowance, and the
//!    decoded byte size against a fixed 1 GiB ceiling, both with
//!    checked arithmetic and both during the decode, so an over-cap
//!    source stops early and is never truncated into a partial
//!    artifact.
//! 3. SILENCE. The sum of squared samples over the whole accepted
//!    waveform decides between two failure reasons: a sub-LSB signal
//!    is `asr-no-speech`, and a louder signal whose engine response
//!    carries no segments is `empty_output`. Neither ever emits an
//!    empty transcript artifact.
//! 4. ENGINE. The pinned runtime files are re-hashed against the
//!    rules-supplied BLAKE3s in this cold worker, the backend probe
//!    must confirm an accelerator-class device, and the engine child
//!    runs with a fixed argument tuple derived from the pinned decode
//!    policy. Only the transcription array of its output reaches the
//!    response; the raw engine output never leaves this module.
//!
//! Every failure carries a generic static reason and names runtime
//! components by role label only.

use std::fs::File;
use std::io::{BufWriter, Seek, SeekFrom, Write};
use std::path::Path;
use std::process::{Command, Stdio};

use symphonia::core::audio::SampleBuffer;
use symphonia::core::codecs::{CODEC_TYPE_AAC, CODEC_TYPE_ALAC, CodecParameters, DecoderOptions};
use symphonia::core::errors::Error as AudioError;
use symphonia::core::formats::FormatOptions;
use symphonia::core::io::MediaSourceStream;
use symphonia::core::meta::MetadataOptions;
use symphonia::core::probe::Hint;

use crate::convert::subprocess::{
    ASR_DECODE_POLICY, ASR_ROLE_CLI, ASR_ROLE_PROBE, ASR_ROLE_WEIGHTS,
};
use crate::runner::protocol::bodies::{AsrOk, AsrRequest, AsrSegment, InventoryEntry};

/// Ceiling on the decoded waveform size in bytes: frames times
/// channels times two. The jail's file-size limit sits above this
/// value, so this preflight is the arbiter and the rlimit only
/// backstops it.
pub(crate) const ASR_MAX_DECODED_BYTES: u64 = 1024 * 1024 * 1024;

/// The decoder priming allowance on the duration ceiling: a decoder
/// may emit a few residue frames past the nominal length, so the cap
/// is `rate * max_duration_seconds + 16` frames.
pub(crate) const ASR_DURATION_PRIMING_FRAMES: u64 = 16;

/// Ceiling on the engine's output envelope, the same value as the
/// `[asr]` profile's response ceiling: the transcription the parent
/// would accept can never exceed it, so a larger output file is
/// refused by its size alone, before a byte of it is read or parsed.
pub(crate) const ASR_MAX_ENGINE_OUTPUT_BYTES: u64 = 4 * 1024 * 1024;

/// The decoded wav the engine reads, by bare name in the jail.
const DECODED_WAV: &str = "decoded.wav";

/// The engine output base name inside the jail; the engine writes
/// `<base>.json` beside it.
const ENGINE_OUTPUT_BASE: &str = "engine-output";

/// The decoded frame count at which the fake engine returns zero
/// segments, so a test can drive the nonsilent-but-empty response
/// through the whole stack deterministically.
#[cfg(feature = "test-adapters")]
const FAKE_EMPTY_SEGMENTS_FRAMES: u64 = 12345;

/// A transcription failure with a stable reason code. The message
/// never embeds a path, host, device identity, or engine output.
#[derive(Debug)]
pub(crate) struct AsrError {
    /// Stable reason, such as `asr-codec-unsupported`.
    pub code: &'static str,
    /// Detail for a human reading the manifest.
    pub message: String,
}

impl AsrError {
    fn new(code: &'static str, message: impl Into<String>) -> AsrError {
        AsrError {
            code,
            message: message.into(),
        }
    }
}

fn codec_unsupported(message: &str) -> AsrError {
    AsrError::new("asr-codec-unsupported", message)
}

fn decode_failed(message: impl Into<String>) -> AsrError {
    AsrError::new("asr-decode-failed", message)
}

/// Transcribes one staged source through the pinned engine.
///
/// This is the production symbol and compiles one way in every
/// feature combination: it always verifies the runtime inventory,
/// runs the backend probe, and execs the engine child, so it fails
/// closed with a runtime reason until a deployment wires the pinned
/// files. It is never swapped for a fake.
pub(crate) fn transcribe(request: &AsrRequest) -> Result<AsrOk, AsrError> {
    check_language(request)?;
    let decoded = decode_request(request)?;
    if decoded.silent {
        return Err(AsrError::new(
            "asr-no-speech",
            "the decoded waveform is below the silence threshold",
        ));
    }
    let runtime = verify_runtime(&request.inventory)?;
    run_probe(Path::new(&runtime.probe))?;
    let json = run_engine(Path::new(&runtime.cli), &runtime.weights)?;
    let segments = parse_transcription(&json)?;
    Ok(AsrOk {
        segments,
        language: Some("en".to_string()),
        duration_seconds: Some(decoded.duration_seconds()),
    })
}

/// The fake-engine transcription path, selected only by the test
/// harness (the `asr-fake` worker mode), never by the production
/// worker mode or the registry. The decode, preflights, and silence
/// stages are the same real layers; only the engine stage is replaced
/// by deterministic segments derived from the decoded waveform.
#[cfg(feature = "test-adapters")]
pub(crate) fn transcribe_fake(request: &AsrRequest) -> Result<AsrOk, AsrError> {
    check_language(request)?;
    let decoded = decode_request(request)?;
    if decoded.silent {
        return Err(AsrError::new(
            "asr-no-speech",
            "the decoded waveform is below the silence threshold",
        ));
    }
    let duration = decoded.duration_seconds();
    let segments = if decoded.frames == FAKE_EMPTY_SEGMENTS_FRAMES {
        // The deterministic zero-segment response: a nonsilent input
        // whose engine heard nothing, which the adapter must fail as
        // empty_output rather than emit an empty artifact.
        Vec::new()
    } else {
        let digest = crate::hash::hash_file(Path::new(DECODED_WAV))
            .map_err(|_| decode_failed("cannot hash the decoded wav"))?;
        let first_end = duration.min(2.0);
        vec![
            AsrSegment {
                start_seconds: 0.0,
                end_seconds: first_end,
                speaker: 1,
                text: format!(
                    "decoded {} frames at {} hz across {} channels {}",
                    decoded.frames,
                    decoded.rate,
                    decoded.channels,
                    &digest[..16]
                ),
            },
            AsrSegment {
                start_seconds: first_end,
                end_seconds: duration.max(first_end),
                speaker: 1,
                text: "fake transcription second line".to_string(),
            },
        ]
    };
    Ok(AsrOk {
        segments,
        language: Some("en".to_string()),
        duration_seconds: Some(duration),
    })
}

/// The pinned language check: the request must ask for exactly the
/// language the decode policy pins.
fn check_language(request: &AsrRequest) -> Result<(), AsrError> {
    if request.language.as_deref() != Some("en") {
        return Err(AsrError::new(
            "unsupported",
            "the pinned engine transcribes language en only",
        ));
    }
    Ok(())
}

/// What one accepted decode produced.
#[derive(Debug)]
struct Decoded {
    frames: u64,
    rate: u32,
    channels: u16,
    silent: bool,
}

impl Decoded {
    fn duration_seconds(&self) -> f64 {
        self.frames as f64 / f64::from(self.rate)
    }
}

/// Decodes the staged input to the jail wav under the ruled ceilings.
fn decode_request(request: &AsrRequest) -> Result<Decoded, AsrError> {
    let input = Path::new(&request.input);
    let extension = input
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if !matches!(extension.as_str(), "wav" | "mp3" | "flac" | "m4a") {
        return Err(AsrError::new(
            "unsupported",
            format!("the audio worker does not decode {extension:?}"),
        ));
    }
    decode_to_wav(
        input,
        &extension,
        request.max_duration_seconds,
        Path::new(DECODED_WAV),
    )
}

/// The duration ceiling in frames for a decoder-reported rate, with
/// the priming allowance, in checked arithmetic.
fn duration_cap_frames(rate: u32, max_duration_seconds: u64) -> Option<u64> {
    u64::from(rate)
        .checked_mul(max_duration_seconds)?
        .checked_add(ASR_DURATION_PRIMING_FRAMES)
}

/// The decoded byte size of a frame count, in checked arithmetic.
fn decoded_byte_size(frames: u64, channels: u16) -> Option<u64> {
    frames.checked_mul(u64::from(channels))?.checked_mul(2)
}

/// The decoded-size preflight comparator: a waveform of exactly the
/// ceiling is accepted, one byte past it is refused, and an overflow
/// in the arithmetic is a decode failure of its own.
fn check_decoded_size(frames: u64, channels: u16) -> Result<(), AsrError> {
    let bytes = decoded_byte_size(frames, channels)
        .ok_or_else(|| decode_failed("the decoded size overflowed"))?;
    if bytes > ASR_MAX_DECODED_BYTES {
        return Err(AsrError::new(
            "asr-decoded-too-large",
            format!("the decoded waveform passed the {ASR_MAX_DECODED_BYTES} byte ceiling"),
        ));
    }
    Ok(())
}

/// Streams one source through the decoder into a canonical PCM wav at
/// the decoder-reported rate and channel count, enforcing the
/// duration and size ceilings during the decode and accumulating the
/// silence sum over the whole waveform.
fn decode_to_wav(
    input: &Path,
    extension: &str,
    max_duration_seconds: u64,
    output: &Path,
) -> Result<Decoded, AsrError> {
    let file = File::open(input)
        .map_err(|e| AsrError::new("io", format!("cannot read the staged input: {e}")))?;
    let stream = MediaSourceStream::new(Box::new(file), Default::default());
    let mut hint = Hint::new();
    hint.with_extension(extension);
    let probed = symphonia::default::get_probe()
        .format(
            &hint,
            stream,
            &FormatOptions::default(),
            &MetadataOptions::default(),
        )
        .map_err(|e| decode_failed(format!("cannot open the audio stream: {e}")))?;
    let mut format = probed.format;
    if extension == "m4a" {
        let params = format
            .default_track()
            .map(|track| track.codec_params.clone());
        check_m4a_track(format.tracks().len(), params.as_ref())?;
    }
    let track = format
        .default_track()
        .ok_or_else(|| decode_failed("the source holds no audio track"))?;
    let track_id = track.id;
    let mut decoder = symphonia::default::get_codecs()
        .make(&track.codec_params, &DecoderOptions::default())
        .map_err(|e| decode_failed(format!("cannot construct the decoder: {e}")))?;

    let mut writer = WavWriter::create(output)?;
    let mut rate: Option<u32> = None;
    let mut channels: u16 = 0;
    let mut frames: u64 = 0;
    let mut sum_squares: u128 = 0;
    let mut sample_buffer: Option<SampleBuffer<i16>> = None;
    let mut byte_scratch: Vec<u8> = Vec::new();
    loop {
        let packet = match format.next_packet() {
            Ok(packet) => packet,
            Err(AudioError::IoError(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                break;
            }
            Err(e) => return Err(decode_failed(format!("cannot read the next packet: {e}"))),
        };
        if packet.track_id() != track_id {
            continue;
        }
        let decoded = decoder
            .decode(&packet)
            .map_err(|e| decode_failed(format!("cannot decode a packet: {e}")))?;
        if decoded.frames() == 0 {
            continue;
        }
        let spec = *decoded.spec();
        let packet_channels = u16::try_from(spec.channels.count())
            .map_err(|_| decode_failed("the channel count does not fit the wav header"))?;
        match rate {
            None => {
                if spec.rate == 0 || packet_channels == 0 {
                    return Err(decode_failed("the decoder reported no rate or channels"));
                }
                rate = Some(spec.rate);
                channels = packet_channels;
            }
            Some(reported) => {
                if spec.rate != reported || packet_channels != channels {
                    return Err(decode_failed("the stream parameters changed mid-file"));
                }
            }
        }
        let reported_rate = rate.expect("set above");
        frames = frames
            .checked_add(decoded.frames() as u64)
            .ok_or_else(|| decode_failed("the frame count overflowed"))?;
        let cap = duration_cap_frames(reported_rate, max_duration_seconds)
            .ok_or_else(|| decode_failed("the duration ceiling overflowed"))?;
        if frames > cap {
            return Err(AsrError::new(
                "asr-duration-exceeded",
                format!("the decoded frame count passed the {max_duration_seconds} second ceiling"),
            ));
        }
        check_decoded_size(frames, channels)?;
        let needed = decoded.frames() * spec.channels.count();
        let recreate = sample_buffer
            .as_ref()
            .is_none_or(|buffer| buffer.capacity() < needed);
        if recreate {
            sample_buffer = Some(SampleBuffer::<i16>::new(decoded.capacity() as u64, spec));
        }
        let buffer = sample_buffer.as_mut().expect("created above");
        buffer.copy_interleaved_ref(decoded);
        let samples = buffer.samples();
        for &sample in samples {
            let square = i64::from(sample) * i64::from(sample);
            sum_squares = sum_squares
                .checked_add(square as u128)
                .ok_or_else(|| decode_failed("the silence accumulator overflowed"))?;
        }
        byte_scratch.clear();
        byte_scratch.reserve(samples.len() * 2);
        for &sample in samples {
            byte_scratch.extend_from_slice(&sample.to_le_bytes());
        }
        writer.write_bytes(&byte_scratch)?;
    }
    let Some(rate) = rate else {
        return Err(decode_failed("the source decoded to no audio frames"));
    };
    debug_assert!(frames > 0, "a reported rate implies decoded frames");
    writer.finish(rate, channels, frames)?;
    // The ruled silence bound: strict sum of squared samples under the
    // decoded frame count, sub-LSB energy over the whole waveform.
    let silent = sum_squares < u128::from(frames);
    Ok(Decoded {
        frames,
        rate,
        channels,
        silent,
    })
}

/// The m4a admission guards, over the container's track list and the
/// selected track's parameters: exactly one track, the AAC codec and
/// never ALAC, a decoder configuration present and parsed by the
/// bounded reader below, and agreement between the container's
/// declared rate and the configuration's rate.
fn check_m4a_track(n_tracks: usize, params: Option<&CodecParameters>) -> Result<(), AsrError> {
    if n_tracks > 1 {
        return Err(codec_unsupported("the container holds more than one track"));
    }
    let Some(params) = params else {
        return Err(decode_failed("the container holds no audio track"));
    };
    if params.codec == CODEC_TYPE_ALAC {
        return Err(codec_unsupported("the track codec is not aac-lc"));
    }
    if params.codec != CODEC_TYPE_AAC {
        return Err(codec_unsupported("the track codec is not aac-lc"));
    }
    let extra = params
        .extra_data
        .as_deref()
        .ok_or_else(|| codec_unsupported("the track carries no decoder configuration"))?;
    let asc_rate = parse_audio_config(extra)?;
    if let Some(container_rate) = params.sample_rate
        && container_rate != asc_rate
    {
        return Err(codec_unsupported(
            "the container and decoder configuration disagree on the sample rate",
        ));
    }
    Ok(())
}

/// The sampling rates the four-bit frequency index names. Indexes 13
/// and 14 are reserved and rejected; index 15 escapes to an explicit
/// 24-bit rate.
const ASC_RATES: [u32; 13] = [
    96000, 88200, 64000, 48000, 44100, 32000, 24000, 22050, 16000, 12000, 11025, 8000, 7350,
];

/// A bounded big-endian bit reader over one byte slice. Every read is
/// checked against the slice length, so no parse can scan past the
/// declared configuration.
struct Bits<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> Bits<'a> {
    fn new(data: &'a [u8]) -> Bits<'a> {
        Bits { data, position: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len() * 8 - self.position
    }

    fn read(&mut self, count: u32) -> Option<u32> {
        debug_assert!(count <= 24);
        if self.remaining() < count as usize {
            return None;
        }
        let mut value: u32 = 0;
        for _ in 0..count {
            let byte = self.data[self.position / 8];
            let bit = (byte >> (7 - (self.position % 8))) & 1;
            value = (value << 1) | u32::from(bit);
            self.position += 1;
        }
        Some(value)
    }

    fn peek(&self, count: u32) -> Option<u32> {
        let mut copy = Bits {
            data: self.data,
            position: self.position,
        };
        copy.read(count)
    }
}

/// The bounded audio-configuration parser: the base object type must
/// be the low-complexity profile, the rate index must be a defined
/// rate or an explicit escape, and the trailing sync extension, when
/// present, must not signal spectral-band replication or parametric
/// coding. Everything else fails closed with a named codec reason,
/// truncation included. Returns the configuration's sample rate.
fn parse_audio_config(extra: &[u8]) -> Result<u32, AsrError> {
    let truncated = || codec_unsupported("the decoder configuration is truncated");
    let mut bits = Bits::new(extra);
    let mut object_type = bits.read(5).ok_or_else(truncated)?;
    if object_type == 31 {
        object_type = 32 + bits.read(6).ok_or_else(truncated)?;
    }
    if object_type != 2 {
        return Err(codec_unsupported(
            "the audio object type is not the low-complexity profile",
        ));
    }
    let rate_index = bits.read(4).ok_or_else(truncated)?;
    let rate = match rate_index {
        15 => bits.read(24).ok_or_else(truncated)?,
        13 | 14 => {
            return Err(codec_unsupported(
                "the sampling-frequency index is reserved",
            ));
        }
        index => ASC_RATES[index as usize],
    };
    let channel_config = bits.read(4).ok_or_else(truncated)?;
    if channel_config == 0 {
        return Err(codec_unsupported(
            "a program-config-element channel layout is not supported",
        ));
    }
    // The low-complexity specific config: frame length, core-coder
    // dependency, and the extension flag, which must be clear.
    let _frame_length_flag = bits.read(1).ok_or_else(truncated)?;
    let depends_on_core = bits.read(1).ok_or_else(truncated)?;
    if depends_on_core == 1 {
        bits.read(14).ok_or_else(truncated)?;
    }
    let extension_flag = bits.read(1).ok_or_else(truncated)?;
    if extension_flag == 1 {
        return Err(codec_unsupported(
            "an extended specific configuration is not supported",
        ));
    }
    // The trailing sync extension. Ordinary low-complexity encoders
    // may write it with the replication flag clear, so the sync word
    // alone never rejects; the flag bit decides.
    if bits.remaining() >= 16 && bits.peek(11) == Some(0x2b7) {
        bits.read(11).ok_or_else(truncated)?;
        let extension_type = bits.read(5).ok_or_else(truncated)?;
        if extension_type == 29 {
            return Err(codec_unsupported(
                "parametric coding is signaled and not supported",
            ));
        }
        if extension_type != 5 {
            return Err(codec_unsupported(
                "an unrecognized configuration extension is signaled",
            ));
        }
        let replication_present = bits.read(1).ok_or_else(truncated)?;
        if replication_present == 1 {
            return Err(codec_unsupported(
                "spectral-band replication is signaled and not supported",
            ));
        }
    }
    Ok(rate)
}

/// A streaming canonical PCM wav writer: a 44-byte header patched
/// after the samples, interleaved little-endian signed 16-bit data,
/// no metadata chunks.
struct WavWriter {
    file: BufWriter<File>,
}

impl WavWriter {
    fn create(path: &Path) -> Result<WavWriter, AsrError> {
        let file = File::create(path)
            .map_err(|e| AsrError::new("io", format!("cannot create the decoded wav: {e}")))?;
        let mut writer = WavWriter {
            file: BufWriter::new(file),
        };
        writer.write_bytes(&[0u8; 44])?;
        Ok(writer)
    }

    fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), AsrError> {
        self.file
            .write_all(bytes)
            .map_err(|e| AsrError::new("io", format!("cannot write the decoded wav: {e}")))
    }

    fn finish(mut self, rate: u32, channels: u16, frames: u64) -> Result<(), AsrError> {
        let io_error =
            |e: std::io::Error| AsrError::new("io", format!("cannot finish the decoded wav: {e}"));
        let data_bytes = decoded_byte_size(frames, channels)
            .filter(|bytes| *bytes <= ASR_MAX_DECODED_BYTES)
            .and_then(|bytes| u32::try_from(bytes).ok())
            .ok_or_else(|| decode_failed("the decoded size overflowed the wav header"))?;
        let riff_bytes = data_bytes
            .checked_add(36)
            .ok_or_else(|| decode_failed("the decoded size overflowed the wav header"))?;
        let byte_rate = rate
            .checked_mul(u32::from(channels))
            .and_then(|v| v.checked_mul(2))
            .ok_or_else(|| decode_failed("the byte rate overflowed the wav header"))?;
        let block_align = channels
            .checked_mul(2)
            .ok_or_else(|| decode_failed("the block alignment overflowed the wav header"))?;
        let mut header = Vec::with_capacity(44);
        header.extend_from_slice(b"RIFF");
        header.extend_from_slice(&riff_bytes.to_le_bytes());
        header.extend_from_slice(b"WAVE");
        header.extend_from_slice(b"fmt ");
        header.extend_from_slice(&16u32.to_le_bytes());
        header.extend_from_slice(&1u16.to_le_bytes());
        header.extend_from_slice(&channels.to_le_bytes());
        header.extend_from_slice(&rate.to_le_bytes());
        header.extend_from_slice(&byte_rate.to_le_bytes());
        header.extend_from_slice(&block_align.to_le_bytes());
        header.extend_from_slice(&16u16.to_le_bytes());
        header.extend_from_slice(b"data");
        header.extend_from_slice(&data_bytes.to_le_bytes());
        self.file.seek(SeekFrom::Start(0)).map_err(io_error)?;
        self.file.write_all(&header).map_err(io_error)?;
        self.file.flush().map_err(io_error)
    }
}

/// The verified runtime file paths, by role.
#[derive(Debug)]
struct Runtime {
    cli: String,
    weights: String,
    probe: String,
}

/// Re-hashes every runtime file against its pinned BLAKE3 in this
/// cold worker, immediately before preflight and execution, so a swap
/// after any parent-side validation still fails closed. A missing
/// role is a distinct reason from a mismatched one, and failures name
/// role labels only.
fn verify_runtime(inventory: &[InventoryEntry]) -> Result<Runtime, AsrError> {
    let resolve = |role: &str| -> Result<String, AsrError> {
        let entry = inventory
            .iter()
            .find(|entry| entry.role == role)
            .ok_or_else(|| {
                AsrError::new(
                    "asr-runtime-missing",
                    format!("runtime component {role} is not present"),
                )
            })?;
        let actual = crate::hash::hash_file(Path::new(&entry.path)).map_err(|_| {
            AsrError::new(
                "asr-runtime-missing",
                format!("runtime component {role} cannot be read"),
            )
        })?;
        if actual != entry.expected_blake3 {
            return Err(AsrError::new(
                "asr-runtime-mismatch",
                format!("runtime component {role} does not match its pinned hash"),
            ));
        }
        Ok(entry.path.clone())
    };
    Ok(Runtime {
        cli: resolve(ASR_ROLE_CLI)?,
        weights: resolve(ASR_ROLE_WEIGHTS)?,
        probe: resolve(ASR_ROLE_PROBE)?,
    })
}

/// Runs the hash-verified backend probe and requires a clean exit,
/// which the pinned probe gives only when an accelerator-class device
/// is enumerable by type. No silent CPU fallback: any other outcome
/// refuses the transcription.
fn run_probe(probe: &Path) -> Result<(), AsrError> {
    let status = Command::new(probe)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(discard_file("probe.out").map_err(|_| {
            AsrError::new("asr-backend-unavailable", "the backend probe cannot run")
        })?)
        .stderr(discard_file("probe.err").map_err(|_| {
            AsrError::new("asr-backend-unavailable", "the backend probe cannot run")
        })?)
        .status()
        .map_err(|_| AsrError::new("asr-backend-unavailable", "the backend probe cannot run"))?;
    if !status.success() {
        return Err(AsrError::new(
            "asr-backend-unavailable",
            "no accelerator-class device is enumerable, refusing a cpu fallback",
        ));
    }
    Ok(())
}

/// A jail-owned sink for a child's output stream. The jail profile
/// grants writes inside the jail only, so `/dev/null` needs no write
/// allowance the deny-first profile would otherwise have to carry:
/// the bytes land in a jail file that is never read and dies with the
/// jail, and the file-size rlimit bounds it like any other jail file.
fn discard_file(name: &str) -> std::io::Result<Stdio> {
    Ok(Stdio::from(File::create(name)?))
}

/// The fixed engine argument tuple: the weights, the decoded wav, the
/// pinned decode policy verbatim, and the output selection. The
/// middle tokens are derived from the policy serialization itself, so
/// the argv cannot drift from the pinned policy, and nothing is ever
/// appended per call.
pub(crate) fn engine_argv(weights: &str, wav: &str, output_base: &str) -> Vec<String> {
    let mut argv = vec![
        "-m".to_string(),
        weights.to_string(),
        "-f".to_string(),
        wav.to_string(),
    ];
    argv.extend(ASR_DECODE_POLICY.split(' ').map(str::to_string));
    argv.push("-oj".to_string());
    argv.push("-of".to_string());
    argv.push(output_base.to_string());
    argv
}

/// Execs the hash-verified engine child over the decoded wav and
/// returns the raw bytes of its output file. Streams to the child are
/// discarded: nothing the engine prints can reach a record.
fn run_engine(cli: &Path, weights: &str) -> Result<Vec<u8>, AsrError> {
    let engine_failed = || {
        AsrError::new(
            "asr-protocol-error",
            "the engine child did not complete cleanly",
        )
    };
    let argv = engine_argv(weights, DECODED_WAV, ENGINE_OUTPUT_BASE);
    let status = Command::new(cli)
        .args(&argv)
        .env_clear()
        // The engine sees only jail paths: a home and temp dir under
        // the jail keep any cache or scratch write inside it, where
        // the profile already allows writes and the cleanup removes
        // them.
        .env("HOME", "engine-home")
        .env("TMPDIR", "engine-home")
        .stdin(Stdio::null())
        .stdout(discard_file("engine.out").map_err(|_| engine_failed())?)
        .stderr(discard_file("engine.err").map_err(|_| engine_failed())?)
        .status()
        .map_err(|_| engine_failed())?;
    if !status.success() {
        return Err(engine_failed());
    }
    read_engine_output(Path::new(&format!("{ENGINE_OUTPUT_BASE}.json")))
}

/// Reads the engine's output file under the response ceiling. The
/// size is refused from the file metadata BEFORE any byte is read, so
/// a runaway envelope under the jail's file-size rlimit still cannot
/// buy an allocation here, and the read itself stays bounded in case
/// the file grows between the two steps.
fn read_engine_output(path: &Path) -> Result<Vec<u8>, AsrError> {
    use std::io::Read as _;
    let missing = || {
        AsrError::new(
            "asr-protocol-error",
            "the engine produced no transcription envelope",
        )
    };
    let oversized = || {
        AsrError::new(
            "asr-protocol-error",
            "the engine output exceeds the response ceiling",
        )
    };
    let metadata = std::fs::symlink_metadata(path).map_err(|_| missing())?;
    if !metadata.is_file() {
        return Err(missing());
    }
    if metadata.len() > ASR_MAX_ENGINE_OUTPUT_BYTES {
        return Err(oversized());
    }
    let file = File::open(path).map_err(|_| missing())?;
    let mut bytes = Vec::new();
    file.take(ASR_MAX_ENGINE_OUTPUT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| missing())?;
    if bytes.len() as u64 > ASR_MAX_ENGINE_OUTPUT_BYTES {
        return Err(oversized());
    }
    Ok(bytes)
}

/// The transcription array only: integer-millisecond offsets and the
/// text. Every other field of the engine output is ignored at the
/// type level and can never be serialized back out, so host paths and
/// machine fingerprints in the raw output never reach a record.
#[derive(serde::Deserialize)]
struct EngineTranscription {
    transcription: Vec<EngineSegment>,
}

#[derive(serde::Deserialize)]
struct EngineSegment {
    offsets: EngineOffsets,
    text: String,
}

#[derive(serde::Deserialize)]
struct EngineOffsets {
    from: i64,
    to: i64,
}

/// Deserializes the engine output into the private transcription
/// shape and converts it to wire segments with the fixed speaker
/// label. The parse-failure message is a fixed string, never the
/// parser's own detail, which could quote the raw output.
fn parse_transcription(json: &[u8]) -> Result<Vec<AsrSegment>, AsrError> {
    let envelope_error = || {
        AsrError::new(
            "asr-protocol-error",
            "the engine output is not a valid transcription envelope",
        )
    };
    let parsed: EngineTranscription = serde_json::from_slice(json).map_err(|_| envelope_error())?;
    let mut segments = Vec::with_capacity(parsed.transcription.len());
    for item in parsed.transcription {
        if item.offsets.from < 0 || item.offsets.to < item.offsets.from {
            return Err(envelope_error());
        }
        segments.push(AsrSegment {
            start_seconds: item.offsets.from as f64 / 1000.0,
            end_seconds: item.offsets.to as f64 / 1000.0,
            speaker: 1,
            text: item.text,
        });
    }
    Ok(segments)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    // --- fixture helpers ---------------------------------------------

    /// A canonical PCM wav from raw interleaved samples.
    fn wav_bytes(rate: u32, channels: u16, samples: &[i16]) -> Vec<u8> {
        let data: u32 = (samples.len() * 2) as u32;
        let mut out = Vec::new();
        out.extend_from_slice(b"RIFF");
        out.extend_from_slice(&(36 + data).to_le_bytes());
        out.extend_from_slice(b"WAVE");
        out.extend_from_slice(b"fmt ");
        out.extend_from_slice(&16u32.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&channels.to_le_bytes());
        out.extend_from_slice(&rate.to_le_bytes());
        out.extend_from_slice(&(rate * u32::from(channels) * 2).to_le_bytes());
        out.extend_from_slice(&(channels * 2).to_le_bytes());
        out.extend_from_slice(&16u16.to_le_bytes());
        out.extend_from_slice(b"data");
        out.extend_from_slice(&data.to_le_bytes());
        for sample in samples {
            out.extend_from_slice(&sample.to_le_bytes());
        }
        out
    }

    fn decode_temp(
        bytes: &[u8],
        extension: &str,
        max_duration_seconds: u64,
    ) -> (tempfile::TempDir, Result<Decoded, AsrError>) {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join(format!("input.{extension}"));
        std::fs::write(&input, bytes).unwrap();
        let output = dir.path().join("decoded.wav");
        let result = decode_to_wav(&input, extension, max_duration_seconds, &output);
        (dir, result)
    }

    fn fixture(name: &str) -> Vec<u8> {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/data")
            .join(name);
        std::fs::read(path).unwrap()
    }

    // --- boundary battery ---------------------------------------------

    #[test]
    fn the_extended_object_type_escape_is_parsed_and_fenced() {
        // A complete extended encoding: 31 escapes to 32 plus the next
        // six bits, never the low-complexity profile, so the named
        // codec rejection fires after a full parse.
        let complete = asc_bytes(&[(31, 5), (6, 6), (8, 4), (1, 4), (0, 3)]);
        let error = parse_audio_config(&complete).unwrap_err();
        assert_eq!(error.code, "asr-codec-unsupported");
        assert!(error.message.contains("object type"), "{}", error.message);
        // The same escape truncated inside its six extension bits is a
        // truncation, proving the read stops at the declared bound.
        let truncated = asc_bytes(&[(31, 5), (1, 2)]);
        let error = parse_audio_config(&truncated).unwrap_err();
        assert_eq!(error.code, "asr-codec-unsupported");
        assert!(error.message.contains("truncated"), "{}", error.message);
    }

    #[test]
    fn every_configuration_read_stops_at_the_declared_length() {
        // A sync extension that would continue past the declared
        // bytes: the sync word and extension type fit exactly, the
        // replication flag does not, and the parse refuses rather
        // than reading on.
        let mut fenced = lc_base();
        fenced.extend([(0x2b7, 11), (5, 5)]);
        let error = parse_audio_config(&asc_bytes(&fenced)).unwrap_err();
        assert_eq!(error.code, "asr-codec-unsupported");
        assert!(error.message.contains("truncated"), "{}", error.message);
        // A core-coder delay cut short mid-field is fenced the same
        // way.
        let cut = asc_bytes(&[(2, 5), (8, 4), (1, 4), (0, 1), (1, 1), (3, 5)]);
        let error = parse_audio_config(&cut).unwrap_err();
        assert_eq!(error.code, "asr-codec-unsupported");
        assert!(error.message.contains("truncated"), "{}", error.message);
        // A tail too short to hold a sync extension is left unread and
        // the configuration is accepted as it stands.
        let mut short_tail = lc_base();
        short_tail.extend([(0x56, 8)]);
        assert_eq!(parse_audio_config(&asc_bytes(&short_tail)).unwrap(), 16000);
    }

    #[test]
    fn ordinary_durations_below_and_exactly_at_the_cap_are_accepted() {
        // Rate 8000 with a one-second ceiling: the cap is 8016 frames
        // including the priming allowance.
        let below = vec![100i16; 4000];
        let (_dir, result) = decode_temp(&wav_bytes(8000, 1, &below), "wav", 1);
        assert_eq!(result.unwrap().frames, 4000);
        let exactly = vec![100i16; 8016];
        let (_dir, result) = decode_temp(&wav_bytes(8000, 1, &exactly), "wav", 1);
        assert_eq!(result.unwrap().frames, 8016);
    }

    #[test]
    fn the_decoded_size_comparator_accepts_the_ceiling_and_refuses_one_past_it() {
        // Exactly the 1 GiB ceiling: accepted.
        assert!(check_decoded_size(ASR_MAX_DECODED_BYTES / 2, 1).is_ok());
        // One frame past it: refused with the named reason.
        let error = check_decoded_size(ASR_MAX_DECODED_BYTES / 2 + 1, 1).unwrap_err();
        assert_eq!(error.code, "asr-decoded-too-large");
        // The overflow arm stays a decode failure.
        assert_eq!(
            check_decoded_size(u64::MAX, 2).unwrap_err().code,
            "asr-decode-failed"
        );
    }

    #[test]
    fn the_stereo_silence_band_locks_the_per_channel_denominator() {
        // 1000 stereo frames are 2000 samples. A squared sum inside
        // [frames, 2*frames) is silent under a total-samples reading
        // and NOT silent under the bound per-channel-frames reading,
        // so this locks the bound one.
        let mut in_band = vec![0i16; 2000];
        for sample in in_band.iter_mut().take(1500) {
            *sample = 1;
        }
        let (_dir, result) = decode_temp(&wav_bytes(8000, 2, &in_band), "wav", 3600);
        assert!(
            !result.unwrap().silent,
            "a sum of 1500 at 1000 frames is not silent"
        );
        // Just under the per-channel frame count stays silent.
        let mut under = vec![0i16; 2000];
        for sample in under.iter_mut().take(999) {
            *sample = 1;
        }
        let (_dir, result) = decode_temp(&wav_bytes(8000, 2, &under), "wav", 3600);
        assert!(result.unwrap().silent);
    }

    #[test]
    fn an_oversized_engine_output_is_refused_before_it_is_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("engine-output.json");
        // One byte over the ceiling, created by length alone: the
        // refusal comes from the metadata, before any read.
        let file = std::fs::File::create(&path).unwrap();
        file.set_len(ASR_MAX_ENGINE_OUTPUT_BYTES + 1).unwrap();
        drop(file);
        let error = read_engine_output(&path).unwrap_err();
        assert_eq!(error.code, "asr-protocol-error");
        assert!(error.message.contains("ceiling"), "{}", error.message);
        // A small file is read and returned whole.
        let ok_path = dir.path().join("ok.json");
        std::fs::write(&ok_path, b"{}").unwrap();
        assert_eq!(read_engine_output(&ok_path).unwrap(), b"{}");
        // A missing file keeps the missing-envelope message.
        let error = read_engine_output(&dir.path().join("absent.json")).unwrap_err();
        assert!(error.message.contains("envelope"), "{}", error.message);
    }

    // --- decode layer -------------------------------------------------

    #[test]
    fn a_wav_decodes_at_its_native_rate_and_channels() {
        let samples: Vec<i16> = (0..1600).map(|i| ((i % 200) as i16 - 100) * 50).collect();
        let (dir, result) = decode_temp(&wav_bytes(8000, 1, &samples), "wav", 3600);
        let decoded = result.unwrap();
        assert_eq!(decoded.rate, 8000);
        assert_eq!(decoded.channels, 1);
        assert_eq!(decoded.frames, 1600);
        assert!(!decoded.silent);
        // The emitted wav is byte-identical to the canonical form of
        // the same samples: no resample, no dither, no metadata.
        let written = std::fs::read(dir.path().join("decoded.wav")).unwrap();
        assert_eq!(written, wav_bytes(8000, 1, &samples));
    }

    #[test]
    fn stereo_stays_stereo_with_interleaving_preserved() {
        let mut samples = Vec::new();
        for i in 0..800 {
            samples.push((i % 100) as i16 * 100); // left
            samples.push(-((i % 50) as i16) * 200); // right
        }
        let (dir, result) = decode_temp(&wav_bytes(16000, 2, &samples), "wav", 3600);
        let decoded = result.unwrap();
        assert_eq!(decoded.rate, 16000);
        assert_eq!(decoded.channels, 2);
        assert_eq!(decoded.frames, 800);
        let written = std::fs::read(dir.path().join("decoded.wav")).unwrap();
        assert_eq!(written, wav_bytes(16000, 2, &samples));
    }

    #[test]
    fn the_silence_bound_is_strict_at_one_least_significant_bit() {
        // All-zero samples: silent.
        let zeros = vec![0i16; 4000];
        let (_dir, result) = decode_temp(&wav_bytes(8000, 1, &zeros), "wav", 3600);
        assert!(result.unwrap().silent);

        // One unit of energy under the frame count: still silent.
        let mut nearly = vec![0i16; 4000];
        nearly[7] = 1;
        let (_dir, result) = decode_temp(&wav_bytes(8000, 1, &nearly), "wav", 3600);
        assert!(result.unwrap().silent);

        // Every sample at one: the sum equals the frame count, and the
        // strict bound tips it over to not-silent.
        let ones = vec![1i16; 4000];
        let (_dir, result) = decode_temp(&wav_bytes(8000, 1, &ones), "wav", 3600);
        assert!(!result.unwrap().silent);
    }

    #[test]
    fn the_duration_ceiling_tolerates_priming_and_no_more() {
        // A zero-second ceiling leaves exactly the 16-frame allowance.
        let sixteen = vec![100i16; 16];
        let (_dir, result) = decode_temp(&wav_bytes(8000, 1, &sixteen), "wav", 0);
        assert!(result.is_ok());

        let seventeen = vec![100i16; 17];
        let (_dir, result) = decode_temp(&wav_bytes(8000, 1, &seventeen), "wav", 0);
        assert_eq!(result.unwrap_err().code, "asr-duration-exceeded");
    }

    #[test]
    fn the_preflight_formulas_use_checked_arithmetic() {
        assert_eq!(duration_cap_frames(8000, 3600), Some(28_800_016));
        assert_eq!(duration_cap_frames(u32::MAX, u64::MAX), None);
        assert_eq!(decoded_byte_size(1000, 2), Some(4000));
        assert_eq!(decoded_byte_size(u64::MAX, 2), None);
        // The wav header refuses a size the preflight would have
        // refused first.
        assert!(
            decoded_byte_size(ASR_MAX_DECODED_BYTES, 1)
                .is_some_and(|bytes| bytes > ASR_MAX_DECODED_BYTES)
        );
    }

    #[test]
    fn garbage_bytes_fail_closed_for_every_routed_extension() {
        for extension in ["wav", "mp3", "flac", "m4a"] {
            let (_dir, result) = decode_temp(b"not audio at all, only bytes", extension, 3600);
            let error = result.unwrap_err();
            assert!(
                matches!(error.code, "asr-decode-failed" | "asr-codec-unsupported"),
                "{extension}: {}",
                error.code
            );
        }
    }

    #[test]
    fn the_mp3_and_flac_fixtures_decode_to_their_native_shape() {
        let (_dir, result) = decode_temp(&fixture("mono.mp3"), "mp3", 3600);
        let decoded = result.unwrap();
        assert_eq!(decoded.rate, 16000);
        assert_eq!(decoded.channels, 1);
        assert!(!decoded.silent);
        assert!(decoded.frames > 5000, "{}", decoded.frames);

        let (_dir, result) = decode_temp(&fixture("mono.flac"), "flac", 3600);
        let decoded = result.unwrap();
        assert_eq!(decoded.rate, 16000);
        assert_eq!(decoded.channels, 1);
        assert!(!decoded.silent);
        assert_eq!(decoded.frames, 6400);
    }

    #[test]
    fn two_decodes_of_one_source_are_byte_identical() {
        let bytes = fixture("mono.mp3");
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("input.mp3");
        std::fs::write(&input, &bytes).unwrap();
        let first = dir.path().join("first.wav");
        let second = dir.path().join("second.wav");
        decode_to_wav(&input, "mp3", 3600, &first).unwrap();
        decode_to_wav(&input, "mp3", 3600, &second).unwrap();
        let first = std::fs::read(first).unwrap();
        assert_eq!(first, std::fs::read(second).unwrap());
        assert!(!first.is_empty());
    }

    // --- m4a admission ------------------------------------------------

    #[test]
    fn an_aac_lc_m4a_is_accepted_mono_and_stereo() {
        let (_dir, result) = decode_temp(&fixture("aac-lc-mono.m4a"), "m4a", 3600);
        let decoded = result.unwrap();
        assert_eq!(decoded.rate, 16000);
        assert_eq!(decoded.channels, 1);
        assert!(!decoded.silent);

        let (_dir, result) = decode_temp(&fixture("aac-lc-stereo.m4a"), "m4a", 3600);
        let decoded = result.unwrap();
        assert_eq!(decoded.channels, 2);
    }

    #[test]
    fn alac_two_track_and_replication_shapes_are_named_codec_rejections() {
        for name in ["alac.m4a", "two-track.m4a", "he-aac.m4a"] {
            let (_dir, result) = decode_temp(&fixture(name), "m4a", 3600);
            let error = result.unwrap_err();
            assert_eq!(
                error.code, "asr-codec-unsupported",
                "{name}: {}",
                error.message
            );
        }
    }

    #[test]
    fn the_track_guards_reject_alac_and_rate_disagreement() {
        // ALAC by codec id, before any decoder construction.
        let alac = CodecParameters::new().for_codec(CODEC_TYPE_ALAC).clone();
        let error = check_m4a_track(1, Some(&alac)).unwrap_err();
        assert_eq!(error.code, "asr-codec-unsupported");

        // An AAC track with no decoder configuration.
        let bare = CodecParameters::new().for_codec(CODEC_TYPE_AAC).clone();
        let error = check_m4a_track(1, Some(&bare)).unwrap_err();
        assert_eq!(error.code, "asr-codec-unsupported");

        // A container rate that disagrees with the configuration rate.
        let asc = asc_bytes(&[(2, 5), (8, 4), (1, 4), (0, 3)]);
        let mismatched = CodecParameters::new()
            .for_codec(CODEC_TYPE_AAC)
            .with_sample_rate(22050)
            .with_extra_data(asc.clone().into_boxed_slice())
            .clone();
        let error = check_m4a_track(1, Some(&mismatched)).unwrap_err();
        assert_eq!(error.code, "asr-codec-unsupported");

        // The same configuration with an agreeing container rate.
        let agreeing = CodecParameters::new()
            .for_codec(CODEC_TYPE_AAC)
            .with_sample_rate(16000)
            .with_extra_data(asc.into_boxed_slice())
            .clone();
        assert!(check_m4a_track(1, Some(&agreeing)).is_ok());

        // More than one track, whatever the codec.
        assert_eq!(
            check_m4a_track(2, Some(&CodecParameters::new()))
                .unwrap_err()
                .code,
            "asr-codec-unsupported"
        );
    }

    // --- the bounded configuration parser ----------------------------

    /// Packs (value, bit-width) pairs big-endian into bytes, zero
    /// padded to a byte boundary.
    fn asc_bytes(fields: &[(u32, u32)]) -> Vec<u8> {
        let mut bits: Vec<bool> = Vec::new();
        for (value, width) in fields {
            for shift in (0..*width).rev() {
                bits.push((value >> shift) & 1 == 1);
            }
        }
        while !bits.len().is_multiple_of(8) {
            bits.push(false);
        }
        bits.chunks(8)
            .map(|chunk| {
                chunk
                    .iter()
                    .fold(0u8, |byte, bit| (byte << 1) | u8::from(*bit))
            })
            .collect()
    }

    /// The low-complexity base: object type 2, rate index 8 (16 kHz),
    /// one channel, and a clean specific config.
    fn lc_base() -> Vec<(u32, u32)> {
        vec![(2, 5), (8, 4), (1, 4), (0, 3)]
    }

    #[test]
    fn a_plain_low_complexity_config_parses_to_its_rate() {
        assert_eq!(parse_audio_config(&asc_bytes(&lc_base())).unwrap(), 16000);
    }

    #[test]
    fn an_explicit_rate_escape_parses() {
        let fields = vec![(2, 5), (15, 4), (12345, 24), (1, 4), (0, 3)];
        assert_eq!(parse_audio_config(&asc_bytes(&fields)).unwrap(), 12345);
    }

    #[test]
    fn the_sync_extension_rejects_on_the_flag_bit_not_the_sync_word() {
        // Extension present with the replication flag clear: the
        // ordinary ffmpeg low-complexity shape, accepted.
        let mut clear = lc_base();
        clear.extend([(0x2b7, 11), (5, 5), (0, 1)]);
        assert_eq!(parse_audio_config(&asc_bytes(&clear)).unwrap(), 16000);

        // The same extension with the flag set: rejected.
        let mut set = lc_base();
        set.extend([(0x2b7, 11), (5, 5), (1, 1)]);
        let error = parse_audio_config(&asc_bytes(&set)).unwrap_err();
        assert_eq!(error.code, "asr-codec-unsupported");
        assert!(error.message.contains("replication"), "{}", error.message);

        // Extension object type 29: parametric coding, rejected.
        let mut parametric = lc_base();
        parametric.extend([(0x2b7, 11), (29, 5)]);
        let error = parse_audio_config(&asc_bytes(&parametric)).unwrap_err();
        assert_eq!(error.code, "asr-codec-unsupported");
        assert!(error.message.contains("parametric"), "{}", error.message);
    }

    #[test]
    fn non_lc_object_types_and_reserved_rates_are_rejected() {
        for object_type in [1u32, 5, 29] {
            let fields = vec![(object_type, 5), (8, 4), (1, 4), (0, 3)];
            let error = parse_audio_config(&asc_bytes(&fields)).unwrap_err();
            assert_eq!(error.code, "asr-codec-unsupported", "aot {object_type}");
        }
        for index in [13u32, 14] {
            let fields = vec![(2, 5), (index, 4), (1, 4), (0, 3)];
            let error = parse_audio_config(&asc_bytes(&fields)).unwrap_err();
            assert_eq!(error.code, "asr-codec-unsupported", "index {index}");
        }
        // Channel config zero needs a program config element.
        let fields = vec![(2, 5), (8, 4), (0, 4), (0, 3)];
        let error = parse_audio_config(&asc_bytes(&fields)).unwrap_err();
        assert_eq!(error.code, "asr-codec-unsupported");
    }

    #[test]
    fn truncated_configurations_are_rejected_without_overrun() {
        // One byte holds the object type and part of the rate index.
        let error = parse_audio_config(&[0x12]).unwrap_err();
        assert_eq!(error.code, "asr-codec-unsupported");
        assert!(error.message.contains("truncated"), "{}", error.message);
        // Empty configuration.
        let error = parse_audio_config(&[]).unwrap_err();
        assert_eq!(error.code, "asr-codec-unsupported");
    }

    // --- the engine boundary ------------------------------------------

    #[test]
    fn the_decode_policy_serialization_is_pinned() {
        let policy = ASR_DECODE_POLICY.as_bytes();
        assert_eq!(policy.len(), 55, "the policy is exactly 55 bytes");
        assert_eq!(policy.last(), Some(&b'0'), "no trailing newline");
        assert!(!policy.contains(&b'\n'));
        assert_eq!(
            crate::hash::hash_bytes(policy),
            "f5f5ff161c4fea33411cfd2e51a52cfe5ed953c209eda24b395d8574c4d32871",
            "the no-newline serialization is the pinned one"
        );
    }

    #[test]
    fn the_engine_argv_is_a_fixed_tuple_with_no_additions() {
        let argv = engine_argv("weights.bin", "decoded.wav", "engine-output");
        let expected: Vec<&str> = [
            "-m",
            "weights.bin",
            "-f",
            "decoded.wav",
            "-l",
            "en",
            "-t",
            "1",
            "-p",
            "1",
            "-bo",
            "1",
            "-bs",
            "1",
            "-nf",
            "-tp",
            "0",
            "-tpi",
            "0",
            "-nfa",
            "-mc",
            "0",
            "-oj",
            "-of",
            "engine-output",
        ]
        .to_vec();
        assert_eq!(argv, expected);
        // The accelerator opt-out flag is never emitted, and the
        // middle of the tuple is exactly the pinned policy tokens.
        assert!(!argv.iter().any(|arg| arg == "-ng"));
        let middle: Vec<&str> = argv[4..argv.len() - 3].iter().map(String::as_str).collect();
        assert_eq!(middle.join(" "), ASR_DECODE_POLICY);
        // The tuple hashes stably, so any drift in the builder is a
        // loud test failure rather than a silent argv change.
        assert_eq!(
            crate::hash::hash_bytes(argv.join(" ").as_bytes()),
            crate::hash::hash_bytes(
                format!("-m weights.bin -f decoded.wav {ASR_DECODE_POLICY} -oj -of engine-output")
                    .as_bytes()
            )
        );
    }

    #[test]
    fn the_runtime_verification_tells_missing_from_mismatched() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("component");
        std::fs::write(&path, b"pinned bytes").unwrap();
        let good = crate::hash::hash_file(&path).unwrap();
        let entry = |role: &str, expected: &str| InventoryEntry {
            role: role.to_string(),
            path: path.to_str().unwrap().to_string(),
            expected_blake3: expected.to_string(),
        };

        // Nothing supplied: the first role is missing.
        let error = verify_runtime(&[]).unwrap_err();
        assert_eq!(error.code, "asr-runtime-missing");

        // All three roles present and matching verifies.
        let all = [
            entry(ASR_ROLE_CLI, &good),
            entry(ASR_ROLE_WEIGHTS, &good),
            entry(ASR_ROLE_PROBE, &good),
        ];
        assert!(verify_runtime(&all).is_ok());

        // The probe role can lack a pinned hash entirely, the shape
        // of a custom profile that omits the optional probe row: no
        // entry travels for it, and the engine path fails closed as
        // missing, never as a mismatch, because nothing pinned can
        // mismatch.
        let unpinned_probe = [entry(ASR_ROLE_CLI, &good), entry(ASR_ROLE_WEIGHTS, &good)];
        let error = verify_runtime(&unpinned_probe).unwrap_err();
        assert_eq!(error.code, "asr-runtime-missing");
        assert!(error.message.contains("asr-probe"), "{}", error.message);

        // A wrong hash is a mismatch, a distinct reason.
        let wrong = [
            entry(ASR_ROLE_CLI, &"0".repeat(64)),
            entry(ASR_ROLE_WEIGHTS, &good),
            entry(ASR_ROLE_PROBE, &good),
        ];
        let error = verify_runtime(&wrong).unwrap_err();
        assert_eq!(error.code, "asr-runtime-mismatch");

        // An unreadable path reads as missing, role label only.
        let gone = [
            entry(ASR_ROLE_CLI, &good),
            InventoryEntry {
                role: ASR_ROLE_WEIGHTS.to_string(),
                path: dir.path().join("absent").to_str().unwrap().to_string(),
                expected_blake3: good.clone(),
            },
            entry(ASR_ROLE_PROBE, &good),
        ];
        let error = verify_runtime(&gone).unwrap_err();
        assert_eq!(error.code, "asr-runtime-missing");
        assert!(!error.message.contains("absent"), "{}", error.message);
    }

    #[test]
    fn the_backend_probe_gates_on_the_exit_status() {
        let dir = tempfile::tempdir().unwrap();
        let write_probe = |name: &str, code: u8| {
            let path = dir.path().join(name);
            let mut file = std::fs::File::create(&path).unwrap();
            file.write_all(format!("#!/bin/sh\nexit {code}\n").as_bytes())
                .unwrap();
            drop(file);
            let mut permissions = std::fs::metadata(&path).unwrap().permissions();
            permissions.set_mode(0o755);
            std::fs::set_permissions(&path, permissions).unwrap();
            path
        };
        // The negative control: a probe that reports no accelerator
        // must refuse the transcription.
        let failing = write_probe("failing", 2);
        let error = run_probe(&failing).unwrap_err();
        assert_eq!(error.code, "asr-backend-unavailable");
        // A clean exit passes the gate.
        let passing = write_probe("passing", 0);
        assert!(run_probe(&passing).is_ok());
    }

    #[test]
    fn the_transcription_parse_keeps_only_the_transcription_array() {
        // Host-like fields beside the transcription are ignored at the
        // type level and cannot reach the segments.
        let json = br#"{
            "systeminfo": "machine fingerprint text",
            "params": {"model": "/home/user/weights.bin"},
            "result": {"language": "en"},
            "transcription": [
                {"timestamps": {"from": "x"}, "offsets": {"from": 0, "to": 1500}, "text": " hello"},
                {"offsets": {"from": 1500, "to": 2000}, "text": "again"}
            ]
        }"#;
        let segments = parse_transcription(json).unwrap();
        assert_eq!(segments.len(), 2);
        assert_eq!(segments[0].speaker, 1);
        assert_eq!(segments[1].speaker, 1);
        assert!((segments[0].end_seconds - 1.5).abs() < f64::EPSILON);
        assert_eq!(segments[0].text, " hello");

        // Malformed output is one fixed message that quotes nothing.
        let error = parse_transcription(b"model path leak /home/user").unwrap_err();
        assert_eq!(error.code, "asr-protocol-error");
        assert!(!error.message.contains("/home"), "{}", error.message);

        // Negative or inverted offsets are protocol errors.
        let error = parse_transcription(
            br#"{"transcription": [{"offsets": {"from": -1, "to": 0}, "text": "x"}]}"#,
        )
        .unwrap_err();
        assert_eq!(error.code, "asr-protocol-error");
    }

    #[test]
    fn a_non_pinned_language_request_is_refused() {
        let request = AsrRequest {
            input: "input.wav".to_string(),
            language: Some("fr".to_string()),
            max_duration_seconds: 3600,
            inventory: Vec::new(),
        };
        assert_eq!(check_language(&request).unwrap_err().code, "unsupported");
        let request = AsrRequest {
            language: None,
            ..request
        };
        assert_eq!(check_language(&request).unwrap_err().code, "unsupported");
    }
}
