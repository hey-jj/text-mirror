//! End-to-end tests for the in-jail audio converter: wav, mp3, flac,
//! and m4a decoded behind the subprocess sandbox, the codec admission
//! guards, the silence and empty-response split, the runtime
//! inventory, and the media provenance through conversion and dedup.
//!
//! Through the builtin registry the production `asr` worker mode runs,
//! and it fails closed with `asr-runtime-missing` because no runtime
//! is wired: a valid source's decode and preflights pass and the
//! engine stage refuses. The fake engine stage is a separate
//! `asr-fake` worker mode the test harness selects through
//! `use_fake_asr`; it exercises the outcome mapping, the transcript
//! format, and the media block against the real jail and the real
//! decode without a pinned engine. The suite runs on the pinned
//! machine class only, because that is the only class the registry
//! routes audio on.

#![cfg(all(
    unix,
    feature = "audio-asr",
    target_os = "macos",
    target_arch = "aarch64"
))]

use std::fs;
use std::path::PathBuf;

use text_mirror::convert::RuntimeInventory;
use text_mirror::manifest::{self, ArtifactKind, Record, Status};
use text_mirror::pipeline::{self, Rules, RunOptions};
use text_mirror::walk::WalkOptions;

struct Setup {
    _dir: tempfile::TempDir,
    root: PathBuf,
    mirror: PathBuf,
    manifest_dir: PathBuf,
}

fn setup() -> Setup {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("source");
    fs::create_dir_all(&root).unwrap();
    Setup {
        root,
        mirror: dir.path().join("mirror"),
        manifest_dir: dir.path().join("manifest"),
        _dir: dir,
    }
}

fn run_with(setup: &Setup, rules: &Rules) -> text_mirror::report::RunReport {
    pipeline::run(
        rules,
        &RunOptions {
            root: &setup.root,
            mirror_root: &setup.mirror,
            manifest_dir: &setup.manifest_dir,
            division: "alpha",
            walk: WalkOptions::default(),
        },
    )
    .unwrap()
}

fn fake_rules() -> Rules {
    let mut rules = Rules::builtin().unwrap();
    rules.registry.use_fake_asr();
    rules
}

fn terminal(setup: &Setup, source_path: &str) -> Record {
    manifest::read_shard(&setup.manifest_dir.join("alpha.jsonl"))
        .unwrap()
        .records
        .into_iter()
        .rev()
        .find(|r| r.source_path == source_path)
        .unwrap()
}

/// A canonical PCM wav over raw interleaved samples.
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

/// A half-second spoken-band tone, loud enough to clear the silence
/// bound by a wide margin.
fn tone_wav() -> Vec<u8> {
    let samples: Vec<i16> = (0..8000)
        .map(|i| (f64::sin(f64::from(i) * 0.2) * 9000.0) as i16)
        .collect();
    wav_bytes(16000, 1, &samples)
}

fn fixture(name: &str) -> Vec<u8> {
    fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/data")
            .join(name),
    )
    .unwrap()
}

// --- the production seam ---------------------------------------------

#[test]
fn audio_fails_closed_without_a_wired_runtime() {
    // The builtin registry drives the production asr worker mode. A
    // valid wav's decode, preflights, and silence layers pass, and the
    // engine stage refuses because no runtime is wired, so the record
    // is a failed conversion with the runtime-missing reason and no
    // artifact.
    let setup = setup();
    fs::write(setup.root.join("call.wav"), tone_wav()).unwrap();

    let rules = Rules::builtin().unwrap();
    let report = run_with(&setup, &rules);
    assert_eq!(report.counts.failed, 1, "records: {report:?}");

    let record = terminal(&setup, "call.wav");
    assert_eq!(record.status, Status::Failed);
    assert_eq!(record.detected_format, "wav");
    assert_eq!(record.converter_id.as_deref(), Some("asr-adapter"));
    assert_eq!(record.converter_version.as_deref(), Some("2.0.0"));
    assert_eq!(record.rules_version, "10");
    assert!(
        record
            .error
            .as_deref()
            .is_some_and(|e| e.starts_with("asr-runtime-missing")),
        "{:?}",
        record.error
    );
    assert!(record.text_path.is_none());
    assert!(record.media.is_none());
}

#[test]
fn a_wired_runtime_that_mismatches_its_pin_is_refused_by_the_worker() {
    // Supply real files for all three file roles whose bytes cannot
    // match the pinned hashes. The paths travel through the runtime
    // inventory, the jail grants them as literal files, and the cold
    // worker re-hashes each one and refuses on the first mismatch,
    // naming the role only.
    let setup = setup();
    fs::write(setup.root.join("call.wav"), tone_wav()).unwrap();
    let runtime_dir = tempfile::tempdir().unwrap();
    let mut inventory = RuntimeInventory::empty();
    for role in ["asr-cli", "asr-weights", "asr-probe"] {
        let path = runtime_dir.path().join(role);
        fs::write(&path, format!("stand-in bytes for {role}")).unwrap();
        // Canonicalize so the literal jail grant names the real path.
        inventory.set(role, path.canonicalize().unwrap()).unwrap();
    }

    let rules = Rules::builtin_with_inventory(&inventory).unwrap();
    run_with(&setup, &rules);
    let record = terminal(&setup, "call.wav");
    assert_eq!(record.status, Status::Failed);
    let error = record.error.as_deref().unwrap();
    assert!(error.starts_with("asr-runtime-mismatch"), "{error}");
    assert!(!error.contains("stand-in"), "{error}");
    assert!(
        !error.contains(runtime_dir.path().to_str().unwrap()),
        "no path leaks: {error}"
    );
}

#[test]
fn a_record_never_carries_a_component_of_a_runtime_path() {
    // The wired engine is swapped for a directory after the rules were
    // built and before the run: the runner's own spawn-time
    // re-assertion refuses, and the record names the grant by its
    // position and kind, never its path.
    let setup = setup();
    fs::write(setup.root.join("call.wav"), tone_wav()).unwrap();
    let runtime_dir = tempfile::tempdir().unwrap();
    let mut inventory = RuntimeInventory::empty();
    for role in ["asr-cli", "asr-weights", "asr-probe"] {
        let path = runtime_dir.path().join(role);
        fs::write(&path, format!("stand-in bytes for {role}")).unwrap();
        inventory.set(role, path.canonicalize().unwrap()).unwrap();
    }
    let rules = Rules::builtin_with_inventory(&inventory).unwrap();
    let engine = runtime_dir.path().join("asr-cli");
    fs::remove_file(&engine).unwrap();
    fs::create_dir_all(&engine).unwrap();
    run_with(&setup, &rules);
    let record = terminal(&setup, "call.wav");
    assert_eq!(record.status, Status::Failed);
    let error = record.error.clone().unwrap_or_default();
    assert!(error.starts_with("adapter_spawn_error"), "{error}");
    assert!(
        error.contains("executable grant 1 of 2 is not a literal regular file"),
        "{error}"
    );
    let mut text = error;
    text.extend(record.warnings.iter().cloned());
    assert!(!text.contains('/'), "{text}");
    for component in runtime_dir
        .path()
        .canonicalize()
        .unwrap()
        .components()
        .filter_map(|c| c.as_os_str().to_str())
        .filter(|c| c.len() > 3)
    {
        assert!(
            !text.contains(component),
            "{component} reached the record: {text}"
        );
    }
}

// --- the fake engine stage -------------------------------------------

#[test]
fn the_fake_engine_path_maps_a_wav_to_a_transcript_with_media() {
    let setup = setup();
    fs::write(setup.root.join("memo.wav"), tone_wav()).unwrap();

    let rules = fake_rules();
    let report = run_with(&setup, &rules);
    assert_eq!(report.counts.converted, 1, "records: {report:?}");

    let record = terminal(&setup, "memo.wav");
    assert_eq!(record.status, Status::Converted);
    assert_eq!(record.converter_id.as_deref(), Some("asr-adapter"));
    assert_eq!(record.artifact_kind, Some(ArtifactKind::Transcript));

    // The transcript format: ordered timecoded lines, every line the
    // fixed speaker label.
    let text = fs::read_to_string(setup.mirror.join("alpha/memo.wav.txt")).unwrap();
    assert!(
        text.starts_with("[00:00:00 -> 00:00:00] Speaker 1: decoded 8000 frames"),
        "{text}"
    );
    for line in text.lines() {
        assert!(line.contains("] Speaker 1: "), "{line}");
    }

    // The media provenance: decoded duration, the pinned language, the
    // weights role label, and the rules-pinned hashes. speaker_count
    // stays absent: no diarizer ran.
    let media = record.media.expect("a transcript record carries media");
    assert!(
        (media.duration_seconds.unwrap() - 0.5).abs() < 0.01,
        "{:?}",
        media.duration_seconds
    );
    assert_eq!(media.language.as_deref(), Some("en"));
    assert_eq!(media.model_id.as_deref(), Some("asr-weights"));
    assert_eq!(
        media.model_hash.as_deref(),
        Some("a25408281ffced74ee45c743d59deb11689c918fe4fa0d22e6f1924e365ac4ab")
    );
    assert_eq!(
        media.decode_options_hash.as_deref(),
        Some("f5f5ff161c4fea33411cfd2e51a52cfe5ed953c209eda24b395d8574c4d32871")
    );
    assert_eq!(media.speaker_count, None);
}

#[test]
fn every_compressed_format_routes_through_the_same_decode_layer() {
    let setup = setup();
    fs::write(setup.root.join("clip.mp3"), fixture("mono.mp3")).unwrap();
    fs::write(setup.root.join("clip.flac"), fixture("mono.flac")).unwrap();
    fs::write(setup.root.join("clip.m4a"), fixture("aac-lc-mono.m4a")).unwrap();
    fs::write(setup.root.join("wide.m4a"), fixture("aac-lc-stereo.m4a")).unwrap();

    let rules = fake_rules();
    let report = run_with(&setup, &rules);
    assert_eq!(report.counts.converted, 4, "records: {report:?}");

    for source in ["clip.mp3", "clip.flac", "clip.m4a", "wide.m4a"] {
        let record = terminal(&setup, source);
        assert_eq!(record.status, Status::Converted, "{source}");
        assert_eq!(
            record.artifact_kind,
            Some(ArtifactKind::Transcript),
            "{source}"
        );
        assert!(record.media.is_some(), "{source}");
    }
    // The flac row landed in detection: the record names the format.
    assert_eq!(terminal(&setup, "clip.flac").detected_format, "flac");
    // Stereo stays stereo through the decode: the fake transcript
    // names the channel count it decoded.
    let wide = fs::read_to_string(setup.mirror.join("alpha/wide.m4a.txt")).unwrap();
    assert!(wide.contains("across 2 channels"), "{wide}");
}

#[test]
fn unsupported_codec_shapes_fail_closed_through_the_pipeline() {
    let setup = setup();
    fs::write(setup.root.join("lossless.m4a"), fixture("alac.m4a")).unwrap();
    fs::write(setup.root.join("double.m4a"), fixture("two-track.m4a")).unwrap();
    fs::write(setup.root.join("torn.mp3"), b"ID3fake audio bytes").unwrap();

    let rules = fake_rules();
    let report = run_with(&setup, &rules);
    assert_eq!(report.counts.failed, 3, "records: {report:?}");

    for source in ["lossless.m4a", "double.m4a"] {
        let record = terminal(&setup, source);
        assert_eq!(record.status, Status::Failed, "{source}");
        assert!(
            record
                .error
                .as_deref()
                .is_some_and(|e| e.starts_with("asr-codec-unsupported")),
            "{source}: {:?}",
            record.error
        );
        assert!(record.text_path.is_none(), "{source}");
    }
    let torn = terminal(&setup, "torn.mp3");
    assert_eq!(torn.status, Status::Failed);
    assert!(
        torn.error
            .as_deref()
            .is_some_and(|e| e.starts_with("asr-decode-failed")),
        "{:?}",
        torn.error
    );
}

#[test]
fn silence_and_an_empty_engine_response_split_into_their_two_reasons() {
    let setup = setup();
    // All-zero samples: the signal-level silence check owns this one.
    fs::write(
        setup.root.join("silent.wav"),
        wav_bytes(16000, 1, &vec![0i16; 8000]),
    )
    .unwrap();
    // Exactly the fake trigger frame count, loud: the engine stage
    // returns zero segments, and the adapter refuses to emit an empty
    // artifact.
    fs::write(
        setup.root.join("hollow.wav"),
        wav_bytes(16000, 1, &vec![5000i16; 12345]),
    )
    .unwrap();

    let rules = fake_rules();
    let report = run_with(&setup, &rules);
    assert_eq!(report.counts.failed, 2, "records: {report:?}");

    let silent = terminal(&setup, "silent.wav");
    assert!(
        silent
            .error
            .as_deref()
            .is_some_and(|e| e.starts_with("asr-no-speech")),
        "{:?}",
        silent.error
    );
    let hollow = terminal(&setup, "hollow.wav");
    assert!(
        hollow
            .error
            .as_deref()
            .is_some_and(|e| e.starts_with("empty_output")),
        "{:?}",
        hollow.error
    );
    for record in [&silent, &hollow] {
        assert_eq!(record.status, Status::Failed);
        assert!(record.text_path.is_none());
    }
    assert!(!setup.mirror.join("alpha/silent.wav.txt").exists());
    assert!(!setup.mirror.join("alpha/hollow.wav.txt").exists());
}

// --- the real pinned engine, when a deployment supplies it ------------

/// Runs only where the environment names a runtime inventory file
/// (`TEXT_MIRROR_ASR_RUNTIME_INVENTORY`). Everywhere else it reports
/// itself skipped and passes, honestly named. With the runtime
/// present it drives one real transcription through the whole jailed
/// path: decode, inventory re-hash, backend probe, engine exec, and
/// the media block, so fake-engine coverage can never again hide a
/// jail that refuses the real runtime.
#[test]
fn the_real_engine_transcribes_in_jail_when_the_runtime_is_supplied() {
    let Ok(inventory_path) = std::env::var("TEXT_MIRROR_ASR_RUNTIME_INVENTORY") else {
        eprintln!(
            "skipped: TEXT_MIRROR_ASR_RUNTIME_INVENTORY is not set, no pinned runtime on this host"
        );
        return;
    };
    let inventory = RuntimeInventory::load(std::path::Path::new(&inventory_path))
        .expect("the runtime inventory file loads");
    let rules = Rules::builtin_with_inventory(&inventory).unwrap();
    let setup = setup();
    fs::write(setup.root.join("spoken.wav"), synthesized_speech_wav()).unwrap();

    let report = run_with(&setup, &rules);
    let record = terminal(&setup, "spoken.wav");
    assert_eq!(
        record.status,
        Status::Converted,
        "error: {:?}, report: {report:?}",
        record.error
    );
    assert_eq!(record.artifact_kind, Some(ArtifactKind::Transcript));
    let text = fs::read_to_string(setup.mirror.join("alpha/spoken.wav.txt")).unwrap();
    assert!(text.contains("] Speaker 1: "), "{text}");
    assert!(
        text.to_ascii_lowercase().contains("quarterly"),
        "the engine transcribes the synthesized sentence: {text}"
    );
    let media = record.media.expect("a real transcript carries media");
    assert_eq!(
        media.model_hash.as_deref(),
        Some("a25408281ffced74ee45c743d59deb11689c918fe4fa0d22e6f1924e365ac4ab")
    );
    assert!(media.duration_seconds.unwrap() > 1.0);
}

/// Synthesized speech through the host speech synthesizer, converted
/// to a plain 16 kHz wav. Only the runtime-gated test above uses it,
/// so the host-tool dependency travels with the same gate.
fn synthesized_speech_wav() -> Vec<u8> {
    let dir = tempfile::tempdir().unwrap();
    let aiff = dir.path().join("speech.aiff");
    let wav = dir.path().join("speech.wav");
    let synth = std::process::Command::new("/usr/bin/say")
        .arg("-o")
        .arg(&aiff)
        .arg("the quarterly numbers are ready for review")
        .status()
        .expect("the host speech synthesizer runs");
    assert!(synth.success());
    let convert = std::process::Command::new("/usr/bin/afconvert")
        .arg("-f")
        .arg("WAVE")
        .arg("-d")
        .arg("LEI16@16000")
        .arg(&aiff)
        .arg(&wav)
        .status()
        .expect("the host audio converter runs");
    assert!(convert.success());
    fs::read(wav).unwrap()
}

// --- media through dedup and the checkpoint ---------------------------

#[test]
fn media_propagates_through_same_run_dedup_the_checkpoint_and_seeding() {
    let setup = setup();
    fs::write(setup.root.join("a.wav"), tone_wav()).unwrap();
    fs::write(setup.root.join("b.wav"), tone_wav()).unwrap();

    let rules = fake_rules();
    run_with(&setup, &rules);

    // Same run: one Converted, one Dedup, both carrying the media
    // block and the transcript kind.
    let a = terminal(&setup, "a.wav");
    let b = terminal(&setup, "b.wav");
    let (converted, deduped) = if a.status == Status::Converted {
        (a, b)
    } else {
        (b, a)
    };
    assert_eq!(converted.status, Status::Converted);
    assert_eq!(deduped.status, Status::Dedup);
    for record in [&converted, &deduped] {
        assert_eq!(record.artifact_kind, Some(ArtifactKind::Transcript));
        let media = record.media.as_ref().expect("media travels with dedup");
        assert_eq!(media.model_id.as_deref(), Some("asr-weights"));
        assert!(media.duration_seconds.is_some());
    }

    // Second run: the unchanged sources skip and keep their media
    // (the checkpoint clones the prior record), and a new identical
    // source dedups off the seeded canonical with the media intact.
    fs::write(setup.root.join("c.wav"), tone_wav()).unwrap();
    let second = run_with(&setup, &rules);
    assert_eq!(second.counts.skipped_unchanged, 2, "{second:?}");
    assert_eq!(second.counts.dedup, 1, "{second:?}");
    let skipped = terminal(&setup, "a.wav");
    assert_eq!(skipped.status, Status::SkippedUnchanged);
    assert!(skipped.media.is_some());
    let seeded = terminal(&setup, "c.wav");
    assert_eq!(seeded.status, Status::Dedup);
    assert_eq!(
        seeded.media.as_ref().and_then(|m| m.model_id.as_deref()),
        Some("asr-weights")
    );
}
