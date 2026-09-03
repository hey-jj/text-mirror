//! The worker binary's mode dispatch.
//!
//! One binary hosts several modes selected by its first argument. The
//! sandbox helper mode is the first stage of every jailed spawn. The
//! `pdf` mode is the production converter behind the runner. The two
//! probe modes prove the jail from the inside. The remaining fake
//! engine and harness modes exist only under the `test-adapters`
//! feature, so a production build ships the helper, the PDF path, and
//! the probes, and nothing else.
//!
//! Every non-helper mode speaks the framed protocol: it reads one
//! request frame from stdin, does its work, and writes exactly one
//! response frame to stdout. It never writes a second frame or logs
//! to stdout, because the parent treats any trailing stdout byte as a
//! protocol violation.

use std::io;
use std::process::ExitCode;

use super::protocol::{self, FrameRead, MAX_REQUEST_BYTES, Request, Response};

/// Runs the worker. `mode` is the first argument, `rest` the ones
/// after it. Returns the process exit code.
pub fn worker_main(mode: &str, rest: &[String]) -> ExitCode {
    if mode == "sandbox-helper" {
        // Never returns.
        super::helper::helper_main(rest);
    }
    match run_mode(mode) {
        Ok(response) => match emit(&response) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("worker_write_failed: {e}");
                ExitCode::from(1)
            }
        },
        Err(exit) => exit.into(),
    }
}

/// A worker-side dispatch failure that must not become a valid
/// response frame. It carries the exit code the parent will read.
struct HardExit(u8);

impl From<HardExit> for ExitCode {
    fn from(exit: HardExit) -> ExitCode {
        ExitCode::from(exit.0)
    }
}

fn read_request() -> Result<Request, HardExit> {
    let mut stdin = io::stdin().lock();
    match protocol::read_frame(&mut stdin, MAX_REQUEST_BYTES) {
        Ok(FrameRead::Complete(payload)) => serde_json::from_slice(&payload).map_err(|e| {
            eprintln!("worker_bad_request: {e}");
            HardExit(2)
        }),
        Ok(other) => {
            eprintln!("worker_bad_request: no complete request frame ({other:?})");
            Err(HardExit(2))
        }
        Err(e) => {
            eprintln!("worker_read_failed: {e}");
            Err(HardExit(2))
        }
    }
}

fn emit(response: &Response) -> io::Result<()> {
    let mut stdout = io::stdout().lock();
    protocol::write_frame(&mut stdout, response)
}

fn run_mode(mode: &str) -> Result<Response, HardExit> {
    match mode {
        "pdf" => production::pdf(read_request()?),
        "probe-net" => production::probe_net(read_request()?),
        "probe-seccomp" => production::probe_seccomp(read_request()?),
        // The records reader trees are heavy and native, so they
        // compile only under the feature and run only in the jail.
        #[cfg(all(unix, feature = "records-worker"))]
        "records" => records::records(read_request()?),
        // The in-jail raster decode plus recognize path. Compiles only
        // under the feature and runs only in the jail: the pure-Rust
        // decode and the engine child both stay behind the sandbox.
        #[cfg(all(unix, feature = "image-ocr"))]
        "image-ocr" => image_ocr::image_ocr(read_request()?),
        // The in-jail svg raster path. Compiles only under the feature
        // and runs only in the provider jail: the pinned external
        // components are verified and executed there, never here in
        // the parent.
        #[cfg(all(unix, feature = "svg-provider"))]
        "svg-raster" => svg_raster::svg_raster(read_request()?),
        // The in-jail image-metadata reader. Compiles only under the
        // feature and runs only in the jail: the exif, png text-chunk,
        // xmp, iptc, and iso base media file format parsers all stay
        // behind the sandbox, where a bomb or a flood crashes or times
        // out the child.
        #[cfg(all(unix, feature = "image-metadata"))]
        "image-metadata" => image_metadata::image_metadata(read_request()?),
        // The fake stage-3 recognition, a separate mode the test harness
        // selects. It runs the real decode and area guards and only the
        // stage-3 recognition is fake, so it never stands in for the
        // production `image-ocr` mode above.
        #[cfg(all(unix, feature = "image-ocr", feature = "test-adapters"))]
        "image-ocr-fake" => image_ocr::image_ocr_fake(read_request()?),
        // The in-jail audio decode plus transcribe path. Compiles only
        // under the feature and runs only in the jail: the pure-Rust
        // decode and the engine child both stay behind the sandbox.
        #[cfg(all(unix, feature = "audio-asr"))]
        "asr" => audio::asr(read_request()?),
        // The fake engine-stage transcription, a separate mode the test
        // harness selects. It runs the real decode, preflight, and
        // silence layers and only the engine stage is fake, so it never
        // stands in for the production `asr` mode above.
        #[cfg(all(unix, feature = "audio-asr", feature = "test-adapters"))]
        "asr-fake" => audio::asr_fake(read_request()?),
        // Held descendants get no stdin, so this mode never reads a
        // request frame.
        #[cfg(feature = "test-adapters")]
        "harness-hold" => harness::hold(),
        // Closes its inherited stdio, then holds. A descendant spawned
        // this way lets the parent drains reach EOF once its leader
        // exits, so the group kill is what must reap it. Reads no
        // request frame.
        #[cfg(feature = "test-adapters")]
        "harness-hold-closed" => harness::hold_closed(),
        // Attempts to leave its process group with setsid and holds
        // stdout without writing. The attempt fails as shipped, since
        // a group leader cannot setsid, so the wall clock bounds the
        // hold. Reads no request frame.
        #[cfg(feature = "test-adapters")]
        "harness-setsid-hold" => harness::setsid_hold(),
        // Closes its stdio, grows a resident balloon, marks readiness
        // in the jail, and holds. The descendant shape for the memory
        // guard's exit-race test. Reads no request frame.
        #[cfg(feature = "test-adapters")]
        "harness-hold-balloon" => harness::hold_balloon(),
        // A descendant that runs the escape controls from inside a
        // spawned child and writes its findings into the jail, so a
        // test can prove a helper inherits the leader's profile. Reads
        // no request frame.
        #[cfg(feature = "test-adapters")]
        "harness-child-probe" => harness::child_probe(),
        #[cfg(feature = "test-adapters")]
        other => harness::run(other, read_request()?),
        #[cfg(not(feature = "test-adapters"))]
        _ => {
            eprintln!("worker_unknown_mode");
            Err(HardExit(2))
        }
    }
}

mod production {
    use super::*;
    use crate::convert::pdf::convert_pdf;
    use crate::runner::protocol::bodies::{PdfOk, PdfRequest, ProbeNetRequest, ProbeReport};

    pub(super) fn pdf(request: Request) -> Result<Response, HardExit> {
        let body: PdfRequest = parse(&request)?;
        let bytes = match std::fs::read(&body.input) {
            Ok(bytes) => bytes,
            Err(e) => {
                return Ok(Response::err(
                    "io",
                    format!("cannot read the staged input {}: {e}", body.input),
                ));
            }
        };
        match convert_pdf(&bytes) {
            Ok(conversion) => Ok(Response::ok(
                serde_json::to_value(PdfOk {
                    text: conversion.text,
                    warnings: conversion.warnings,
                    segments: conversion.segments,
                    recovered: conversion.recovered,
                })
                .expect("PdfOk serializes"),
            )),
            Err(error) => Ok(Response::err(error.code, error.message)),
        }
    }

    pub(super) fn probe_net(request: Request) -> Result<Response, HardExit> {
        let body: ProbeNetRequest = parse(&request)?;
        let report = ProbeReport {
            attempts: super::net::attempt_all(&body),
        };
        Ok(Response::ok(
            serde_json::to_value(report).expect("ProbeReport serializes"),
        ))
    }

    /// Creates a socket. Under the seccomp allow-list the socket
    /// syscall is denied with KillProcess, so the kernel kills this
    /// process before it can respond. If it survives, the filter did
    /// not engage and the parent reads a response the probe treats as
    /// failure.
    pub(super) fn probe_seccomp(_request: Request) -> Result<Response, HardExit> {
        let outcome = std::net::UdpSocket::bind("127.0.0.1:0")
            .map(|_| "socket created, the filter did not engage".to_string())
            .unwrap_or_else(|e| format!("socket refused by errno: {e}"));
        Ok(Response::ok(serde_json::json!({ "outcome": outcome })))
    }

    fn parse<T: serde::de::DeserializeOwned>(request: &Request) -> Result<T, HardExit> {
        serde_json::from_value(request.payload.clone()).map_err(|e| {
            eprintln!("worker_bad_payload: {e}");
            HardExit(2)
        })
    }
}

/// The jailed records mode: parquet, avro, and sqlite to text.
#[cfg(all(unix, feature = "records-worker"))]
mod records {
    use std::path::Path;

    use super::*;
    use crate::convert::records::{Ceilings, convert_records};
    use crate::runner::protocol::bodies::{RecordsOk, RecordsRequest};

    pub(super) fn records(request: Request) -> Result<Response, HardExit> {
        let body: RecordsRequest =
            serde_json::from_value(request.payload.clone()).map_err(|e| {
                eprintln!("worker_bad_payload: {e}");
                HardExit(2)
            })?;
        let ceilings = Ceilings {
            max_records: body.max_records,
            max_tables: body.max_tables,
            max_output_bytes: body.max_output_bytes,
        };
        match convert_records(Path::new(&body.input), &body.format, &ceilings) {
            Ok(conversion) => Ok(Response::ok(
                serde_json::to_value(RecordsOk {
                    text: conversion.text,
                    warnings: conversion.warnings,
                    segments: conversion.segments,
                })
                .expect("RecordsOk serializes"),
            )),
            Err(error) => Ok(Response::err(error.code, error.message)),
        }
    }
}

/// The jailed image-OCR mode: decode a raster, assert the area cap,
/// re-encode a canonical raster, and hand it to the pinned vision
/// engine, all inside the sandbox.
#[cfg(all(unix, feature = "image-ocr"))]
mod image_ocr {
    use super::*;
    use crate::convert::image_ocr::recognize;
    use crate::runner::protocol::bodies::OcrRequest;

    pub(super) fn image_ocr(request: Request) -> Result<Response, HardExit> {
        let body: OcrRequest = serde_json::from_value(request.payload.clone()).map_err(|e| {
            eprintln!("worker_bad_payload: {e}");
            HardExit(2)
        })?;
        match recognize(&body) {
            Ok(ok) => Ok(Response::ok(
                serde_json::to_value(ok).expect("OcrOk serializes"),
            )),
            Err(error) => Ok(Response::err(error.code, error.message)),
        }
    }

    /// The fake-engine recognition mode: the real decode and area guards
    /// with a deterministic fake stage 3. Selected only by the test
    /// harness, never by the production `image-ocr` mode.
    #[cfg(feature = "test-adapters")]
    pub(super) fn image_ocr_fake(request: Request) -> Result<Response, HardExit> {
        use crate::convert::image_ocr::recognize_fake;
        let body: OcrRequest = serde_json::from_value(request.payload.clone()).map_err(|e| {
            eprintln!("worker_bad_payload: {e}");
            HardExit(2)
        })?;
        match recognize_fake(&body) {
            Ok(ok) => Ok(Response::ok(
                serde_json::to_value(ok).expect("OcrOk serializes"),
            )),
            Err(error) => Ok(Response::err(error.code, error.message)),
        }
    }
}

/// The jailed audio mode: decode to a native-rate wav, assert the
/// duration, size, and silence layers, verify the pinned runtime, and
/// transcribe through the engine child, all inside the sandbox.
#[cfg(all(unix, feature = "audio-asr"))]
mod audio {
    use super::*;
    use crate::convert::audio_asr;
    use crate::runner::protocol::bodies::AsrRequest;

    pub(super) fn asr(request: Request) -> Result<Response, HardExit> {
        let body: AsrRequest = serde_json::from_value(request.payload.clone()).map_err(|e| {
            eprintln!("worker_bad_payload: {e}");
            HardExit(2)
        })?;
        match audio_asr::transcribe(&body) {
            Ok(ok) => Ok(Response::ok(
                serde_json::to_value(ok).expect("AsrOk serializes"),
            )),
            Err(error) => Ok(Response::err(error.code, error.message)),
        }
    }

    /// The fake engine-stage transcription mode: the real decode and
    /// preflights with deterministic segments. Selected only by the
    /// test harness, never by the production `asr` mode.
    #[cfg(feature = "test-adapters")]
    pub(super) fn asr_fake(request: Request) -> Result<Response, HardExit> {
        let body: AsrRequest = serde_json::from_value(request.payload.clone()).map_err(|e| {
            eprintln!("worker_bad_payload: {e}");
            HardExit(2)
        })?;
        match audio_asr::transcribe_fake(&body) {
            Ok(ok) => Ok(Response::ok(
                serde_json::to_value(ok).expect("AsrOk serializes"),
            )),
            Err(error) => Ok(Response::err(error.code, error.message)),
        }
    }
}

/// The jailed svg raster mode: parse the declared geometry, verify and
/// run the pinned external components, assert the geometry and the area
/// cap, and return the flattened raster, all inside the provider jail.
#[cfg(all(unix, feature = "svg-provider"))]
mod svg_raster {
    use super::*;
    use crate::convert::svg_raster::rasterize;
    use crate::runner::protocol::bodies::SvgRasterRequest;

    pub(super) fn svg_raster(request: Request) -> Result<Response, HardExit> {
        let body: SvgRasterRequest =
            serde_json::from_value(request.payload.clone()).map_err(|e| {
                eprintln!("worker_bad_payload: {e}");
                HardExit(2)
            })?;
        match rasterize(&body) {
            Ok(ok) => Ok(Response::ok(
                serde_json::to_value(ok).expect("SvgRasterOk serializes"),
            )),
            Err(error) => Ok(Response::err(error.code, error.message)),
        }
    }
}

/// The jailed image-metadata mode: lift textual metadata out of a
/// raster and return structured rows, all inside the sandbox.
#[cfg(all(unix, feature = "image-metadata"))]
mod image_metadata {
    use std::path::Path;

    use super::*;
    use crate::convert::image_metadata::extract::{Ceilings, extract};
    use crate::runner::protocol::bodies::{ImageMetadataOk, ImageMetadataRequest};

    pub(super) fn image_metadata(request: Request) -> Result<Response, HardExit> {
        let body: ImageMetadataRequest =
            serde_json::from_value(request.payload.clone()).map_err(|e| {
                eprintln!("worker_bad_payload: {e}");
                HardExit(2)
            })?;
        let ceilings = Ceilings {
            max_decompressed_bytes: body.max_decompressed_bytes,
            max_xml_depth: body.max_xml_depth,
            max_xml_events: body.max_xml_events,
            max_boxes: body.max_boxes,
            max_rows: body.max_rows,
            max_output_bytes: body.max_output_bytes,
        };
        match extract(Path::new(&body.input), &body.format, &ceilings) {
            Ok(rows) => Ok(Response::ok(
                serde_json::to_value(ImageMetadataOk { rows }).expect("ImageMetadataOk serializes"),
            )),
            Err(error) => Ok(Response::err(error.code, error.message)),
        }
    }
}

/// Network egress attempts used by the probe. Every target is one
/// the parent controls and holds reachable, so each leg discriminates
/// jailed from unjailed: an unjailed process connects, a jailed one
/// gets a prompt error. Only an error before the deadline scores
/// `denied`. A hang
/// scores `timeout`, which fails the probe, because a hang proves
/// nothing about the jail.
mod net {
    use std::io;
    use std::net::{SocketAddr, TcpStream, UdpSocket};
    use std::time::Duration;

    use crate::runner::protocol::bodies::{ProbeAttempt, ProbeName, ProbeNetRequest, ProbeOutcome};

    const TIMEOUT: Duration = Duration::from_millis(600);

    pub(super) fn attempt_all(request: &ProbeNetRequest) -> Vec<ProbeAttempt> {
        vec![
            tcp(ProbeName::Ipv4Tcp, &request.tcp4_target),
            tcp(ProbeName::Ipv6Tcp, &request.tcp6_target),
            unix_socket(&request.unix_target),
            udp_send(&request.tcp4_target),
        ]
    }

    fn classify(name: ProbeName, result: io::Result<()>) -> ProbeAttempt {
        let (outcome, error_kind) = match result {
            Ok(()) => (ProbeOutcome::Connected, io::ErrorKind::Other),
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) =>
            {
                (ProbeOutcome::Timeout, e.kind())
            }
            Err(e) => (ProbeOutcome::Denied, e.kind()),
        };
        ProbeAttempt {
            name,
            outcome,
            error_kind,
        }
    }

    fn tcp(name: ProbeName, target: &str) -> ProbeAttempt {
        // An unparseable target is instrumentation error, not denial.
        let address = match target.parse::<SocketAddr>() {
            Ok(address) => address,
            Err(_) => {
                return ProbeAttempt {
                    name,
                    outcome: ProbeOutcome::InvalidTarget,
                    error_kind: io::ErrorKind::InvalidInput,
                };
            }
        };
        classify(
            name,
            TcpStream::connect_timeout(&address, TIMEOUT).map(drop),
        )
    }

    #[cfg(target_os = "linux")]
    fn unix_socket(target: &str) -> ProbeAttempt {
        use std::os::linux::net::SocketAddrExt;
        let result = std::os::unix::net::SocketAddr::from_abstract_name(target.as_bytes())
            .and_then(|address| std::os::unix::net::UnixStream::connect_addr(&address))
            .map(drop);
        classify(ProbeName::UnixSocket, result)
    }

    #[cfg(not(target_os = "linux"))]
    fn unix_socket(target: &str) -> ProbeAttempt {
        classify(
            ProbeName::UnixSocket,
            std::os::unix::net::UnixStream::connect(target).map(drop),
        )
    }

    /// Sends one datagram toward the parent's IPv4 target. An
    /// unjailed send succeeds whether or not anything reads it, so a
    /// failure here is the jail refusing the socket or the route.
    fn udp_send(target: &str) -> ProbeAttempt {
        let result = (|| {
            let socket = UdpSocket::bind("0.0.0.0:0")?;
            socket.connect(target)?;
            socket.send(b"probe")?;
            Ok(())
        })();
        classify(ProbeName::UdpSend, result)
    }
}

#[cfg(feature = "test-adapters")]
mod harness {
    use std::io::Write;

    use super::*;
    use crate::runner::protocol::bodies::{
        OcrInput, OcrOk, OcrRequest, OcrSpan, ScreenState, VideoOk, VideoRequest,
    };

    pub(super) fn run(mode: &str, request: Request) -> Result<Response, HardExit> {
        match mode {
            "ocr" => ocr(request),
            "video" => video(request),
            "harness-echo" => Ok(Response::ok(request.payload)),
            "harness-env" => harness_env(),
            "harness-escape" => harness_escape(request),
            "harness-crash" => harness_crash(),
            "harness-sleep" => harness_sleep(),
            "harness-balloon" => harness_balloon(),
            "harness-oversized" => harness_oversized(),
            "harness-trailing" => harness_trailing(),
            "harness-truncated" => harness_truncated(),
            "harness-stderr-flood" => harness_stderr_flood(),
            "harness-survivor" => harness_survivor(request),
            "harness-balloon-survivor" => harness_balloon_survivor(request),
            "harness-spawn-storm" => harness_spawn_storm(request),
            "harness-fd-check" => harness_fd_check(request),
            "harness-controls" => harness_controls(request),
            "harness-spawn-probe" => harness_spawn_probe(request),
            _ => {
                eprintln!("worker_unknown_mode");
                Err(HardExit(2))
            }
        }
    }

    /// Sleeps forever without reading stdin. The mode a harness
    /// descendant is spawned into, so the group-kill contract is what
    /// ends it. Dispatched before the request read in `run_mode`.
    pub(super) fn hold() -> ! {
        loop {
            std::thread::sleep(std::time::Duration::from_secs(3600));
        }
    }

    /// Closes its inherited standard descriptors, then sleeps. A
    /// descendant in this mode releases the parent's stdout pipe, so
    /// the parent's drains reach EOF when the leader exits and the
    /// only thing keeping the descendant alive is that it is not yet
    /// killed. Reads no stdin.
    pub(super) fn hold_closed() -> ! {
        for fd in 0..=2 {
            let _ = nix::unistd::close(fd);
        }
        loop {
            std::thread::sleep(std::time::Duration::from_secs(3600));
        }
    }

    /// Closes its stdio, grows a resident set far past any small
    /// memory ceiling, marks readiness through the jail, and holds.
    /// The descendant shape for the memory guard's exit-race test: it
    /// outlives its fast-exiting leader, and only the runner's final
    /// group measurement and unconditional kill account for it.
    pub(super) fn hold_balloon() -> ! {
        for fd in 0..=2 {
            let _ = nix::unistd::close(fd);
        }
        let mut balloon = vec![0u8; 192 * 1024 * 1024];
        for index in (0..balloon.len()).step_by(4096) {
            balloon[index] = (index % 251) as u8;
        }
        let _ = std::fs::write("ballooned", b"up");
        loop {
            std::hint::black_box(&balloon);
            std::thread::sleep(std::time::Duration::from_secs(3600));
        }
    }

    /// Spawns a descendant into the balloon-hold mode, waits for its
    /// readiness marker in the jail, then answers cleanly and exits at
    /// once, so the leader is gone while the group's memory is still
    /// up. The runner's final measurement is what must catch it.
    fn harness_balloon_survivor(request: Request) -> Result<Response, HardExit> {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct SurvivorRequest {
            program: String,
        }
        let body: SurvivorRequest = parse(&request)?;
        if let Err(e) = std::process::Command::new(&body.program)
            .arg("harness-hold-balloon")
            .spawn()
        {
            return Ok(Response::err(
                "spawn_failed",
                format!("cannot spawn the balloon: {e}"),
            ));
        }
        for _ in 0..400 {
            if std::fs::metadata("ballooned").is_ok() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        Ok(Response::ok(serde_json::json!({ "spawned": true })))
    }

    /// Attempts to leave the process group with setsid and holds
    /// stdout open without writing, then self-terminates so a test
    /// leaks nothing. The attempt fails as shipped, because the
    /// adapter leads its own group and a group leader cannot setsid,
    /// so the wall-clock kill reaps it. The bounded drain join stays
    /// as defense in depth for a descendant that does escape, which
    /// requires a profile that permits spawning.
    pub(super) fn setsid_hold() -> ! {
        let _ = nix::unistd::setsid();
        std::thread::sleep(std::time::Duration::from_secs(5));
        std::process::exit(0);
    }

    /// A fake OCR engine. Confirms the input is staged and returns
    /// canned spans, one derived from the requested page when the
    /// request is a page render.
    fn ocr(request: Request) -> Result<Response, HardExit> {
        let body: OcrRequest = parse(&request)?;
        confirm_input(&body.input)?;
        let label = match body.kind {
            OcrInput::Image => "image".to_string(),
            OcrInput::PageRender { page, dpi } => format!("page {page} at {dpi} dpi"),
        };
        let ok = OcrOk {
            spans: vec![
                OcrSpan {
                    text: format!("recognized from {label}"),
                    confidence: 0.94,
                },
                OcrSpan {
                    text: "faint line".to_string(),
                    confidence: 0.31,
                },
            ],
            warnings: Vec::new(),
        };
        Ok(Response::ok(serde_json::to_value(ok).expect("OcrOk")))
    }

    /// A fake video engine. Returns deduplicated screen states, with a
    /// deliberate repeat the adapter must collapse.
    fn video(request: Request) -> Result<Response, HardExit> {
        let body: VideoRequest = parse(&request)?;
        confirm_input(&body.input)?;
        let ok = VideoOk {
            states: vec![
                ScreenState {
                    first_seen_seconds: 2.0,
                    text: "Title slide".to_string(),
                },
                ScreenState {
                    first_seen_seconds: 8.0,
                    text: "Quarterly revenue".to_string(),
                },
                ScreenState {
                    first_seen_seconds: 20.0,
                    text: "Quarterly revenue".to_string(),
                },
            ],
            duration_seconds: Some(30.0),
        };
        Ok(Response::ok(serde_json::to_value(ok).expect("VideoOk")))
    }

    fn harness_env() -> Result<Response, HardExit> {
        let vars: Vec<[String; 2]> = std::env::vars().map(|(k, v)| [k, v]).collect();
        Ok(Response::ok(serde_json::json!({ "env": vars })))
    }

    /// Attempts to read a caller-named host file and to write outside
    /// the jail. Both must fail under the filesystem policy. The read
    /// target comes from the test, which asserts the file exists on
    /// the host, so a denial is the policy and never a missing file.
    fn harness_escape(request: Request) -> Result<Response, HardExit> {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct EscapeRequest {
            read_path: String,
            /// Optional directory whose entries are listed, so a test
            /// can separate a listing-only allowance from a read of
            /// the files it names.
            #[serde(default)]
            list_path: Option<String>,
        }
        let body: EscapeRequest = parse(&request)?;
        let read = std::fs::read(&body.read_path)
            .map(|bytes| format!("read succeeded with {} bytes", bytes.len()))
            .unwrap_or_else(|e| format!("read denied: {e}"));
        let list = body.list_path.as_ref().map(|path| {
            std::fs::read_dir(path)
                .map(|entries| format!("list succeeded with {} entries", entries.count()))
                .unwrap_or_else(|e| format!("list denied: {e}"))
        });
        let target = std::env::temp_dir().join("text-mirror-escape-probe");
        let write = std::fs::write(&target, b"escaped")
            .map(|_| "write succeeded".to_string())
            .unwrap_or_else(|e| format!("write denied: {e}"));
        Ok(Response::ok(serde_json::json!({
            "read": read,
            "write": write,
            "list": list,
        })))
    }

    /// Spawns one descendant into the hold mode with all stdio
    /// detached, reports its pid, and exits cleanly. The descendant
    /// outlives this leader on purpose: the runner's unconditional
    /// group kill is what must end it.
    fn harness_survivor(request: Request) -> Result<Response, HardExit> {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct SurvivorRequest {
            program: String,
        }
        let body: SurvivorRequest = parse(&request)?;
        // Inherited stdio, not a redirect to /dev/null, so the spawn
        // needs no device the jail withholds. The child closes its
        // stdio itself once running.
        match std::process::Command::new(&body.program)
            .arg("harness-hold-closed")
            .spawn()
        {
            Ok(child) => Ok(Response::ok(
                serde_json::json!({ "survivor_pid": child.id() }),
            )),
            Err(e) => Ok(Response::err(
                "spawn_failed",
                format!("cannot spawn the survivor: {e}"),
            )),
        }
    }

    /// Tries to spawn many held descendants and reports how many the
    /// process-count limit let through. Children keep running until
    /// the runner's group kill ends them.
    fn harness_spawn_storm(request: Request) -> Result<Response, HardExit> {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct StormRequest {
            program: String,
            attempts: u32,
        }
        let body: StormRequest = parse(&request)?;
        let mut spawned = 0u32;
        let mut failed = 0u32;
        let mut first_error = String::new();
        let mut children = Vec::new();
        for _ in 0..body.attempts {
            match std::process::Command::new(&body.program)
                .arg("harness-hold-closed")
                .spawn()
            {
                Ok(child) => {
                    spawned += 1;
                    children.push(child);
                }
                Err(e) => {
                    failed += 1;
                    if first_error.is_empty() {
                        first_error = e.to_string();
                    }
                }
            }
        }
        Ok(Response::ok(serde_json::json!({
            "spawned": spawned,
            "failed": failed,
            "first_error": first_error,
        })))
    }

    /// The escape controls, each attempted and reported on its own so a
    /// test can assert every one by name. Targets are absolute host
    /// paths the test names, so a denial is the policy and never a
    /// redirected home or a missing file.
    fn harness_controls(request: Request) -> Result<Response, HardExit> {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct ControlsRequest {
            /// The system temp root to attempt a write under.
            temp_root: String,
            /// The real home directory to attempt a write under.
            home: String,
            /// The per-user cache root to attempt a write under.
            cache_root: String,
            /// An outbound address to connect to.
            outbound: String,
            /// A loopback listener the parent holds outside the jail.
            loopback: String,
            /// A shell profile file in the real home to read.
            shell_profile: String,
            /// A real file inside a resident profile directory to read.
            profile_file: String,
            /// The privileged configuration file to read.
            privileged: String,
            /// An undeclared program to attempt to run.
            program: String,
        }
        let body: ControlsRequest = parse(&request)?;
        Ok(Response::ok(serde_json::json!({
            "write-temp-root": attempt_write(&std::path::Path::new(&body.temp_root).join("text-mirror-control")),
            "write-home": attempt_write(&std::path::Path::new(&body.home).join("text-mirror-control")),
            "write-cache-root": attempt_write(&std::path::Path::new(&body.cache_root).join("text-mirror-control")),
            "tcp-outbound": attempt_connect(&body.outbound),
            "tcp-loopback-connect": attempt_connect(&body.loopback),
            "tcp-listen": outcome(std::net::TcpListener::bind("127.0.0.1:0").map(|_| ())),
            "read-shell-profile": outcome(std::fs::read(&body.shell_profile).map(|_| ())),
            "read-resident-profile": outcome(std::fs::read(&body.profile_file).map(|_| ())),
            "read-privileged": outcome(std::fs::read(&body.privileged).map(|_| ())),
            "exec-undeclared": outcome(
                std::process::Command::new(&body.program)
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status()
                    .map(|_| ())
            ),
            "write-inside-jail": attempt_write(std::path::Path::new("control-inside-jail")),
        })))
    }

    fn attempt_write(path: &std::path::Path) -> String {
        outcome(std::fs::write(path, b"control").map(|_| ()))
    }

    fn attempt_connect(target: &str) -> String {
        let Ok(address) = target.parse::<std::net::SocketAddr>() else {
            return "invalid target".to_string();
        };
        outcome(
            std::net::TcpStream::connect_timeout(&address, std::time::Duration::from_millis(600))
                .map(|_| ()),
        )
    }

    fn outcome(result: std::io::Result<()>) -> String {
        match result {
            Ok(()) => "allowed".to_string(),
            Err(e) => format!("denied: {e}"),
        }
    }

    /// Spawns a descendant into the child-probe mode, waits for it,
    /// and returns what the descendant reported through the jail. The
    /// descendant's own denials prove it inherited the profile.
    fn harness_spawn_probe(request: Request) -> Result<Response, HardExit> {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct SpawnProbeRequest {
            program: String,
            temp_root: String,
            privileged: String,
        }
        let body: SpawnProbeRequest = parse(&request)?;
        let status = std::process::Command::new(&body.program)
            .arg("harness-child-probe")
            .env("PROBE_TEMP_ROOT", &body.temp_root)
            .env("PROBE_PRIVILEGED", &body.privileged)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        let Ok(status) = status else {
            return Ok(Response::err(
                "spawn_failed",
                "the descendant could not be spawned".to_string(),
            ));
        };
        let report = std::fs::read_to_string("child-probe.json").unwrap_or_default();
        Ok(Response::ok(serde_json::json!({
            "descendant_exited_cleanly": status.success(),
            "report": serde_json::from_str::<serde_json::Value>(&report).unwrap_or(serde_json::Value::Null),
        })))
    }

    /// The descendant half of the spawn probe: attempts a write under
    /// the named temp root and a read of the named privileged file,
    /// writes the outcomes into the jail, and exits.
    pub(super) fn child_probe() -> ! {
        let temp_root = std::env::var("PROBE_TEMP_ROOT").unwrap_or_default();
        let privileged = std::env::var("PROBE_PRIVILEGED").unwrap_or_default();
        let report = serde_json::json!({
            "write-temp-root": attempt_write(&std::path::Path::new(&temp_root).join("text-mirror-descendant")),
            "read-privileged": outcome(std::fs::read(&privileged).map(|_| ())),
            "write-inside-jail": attempt_write(std::path::Path::new("descendant-inside-jail")),
        });
        let _ = std::fs::write("child-probe.json", report.to_string());
        std::process::exit(0)
    }

    /// Reports whether a numbered descriptor is open in this process,
    /// through the `/dev/fd` view, for the descriptor-inheritance
    /// test.
    fn harness_fd_check(request: Request) -> Result<Response, HardExit> {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct FdCheckRequest {
            fd: i32,
        }
        let body: FdCheckRequest = parse(&request)?;
        let open = std::fs::metadata(format!("/dev/fd/{}", body.fd)).is_ok();
        Ok(Response::ok(serde_json::json!({ "open": open })))
    }

    /// Writes a complete, well-formed response frame, then exits
    /// nonzero. A response frame plus a clean exit is the only
    /// success, so the parent must refuse this.
    fn harness_crash() -> Result<Response, HardExit> {
        let response = Response::ok(serde_json::json!({ "note": "plausible but doomed" }));
        let mut stdout = io::stdout().lock();
        let _ = protocol::write_frame(&mut stdout, &response);
        std::process::exit(3);
    }

    fn harness_sleep() -> Result<Response, HardExit> {
        loop {
            std::thread::sleep(std::time::Duration::from_secs(3600));
        }
    }

    /// Grows its resident set past any small ceiling and holds without
    /// responding, so the parent-side resident-memory guard is what
    /// must end it. The pages are written, so they are truly resident
    /// rather than reserved.
    fn harness_balloon() -> Result<Response, HardExit> {
        const BALLOON_BYTES: usize = 192 * 1024 * 1024;
        let mut balloon = vec![0u8; BALLOON_BYTES];
        for index in (0..balloon.len()).step_by(4096) {
            balloon[index] = (index % 251) as u8;
        }
        std::thread::sleep(std::time::Duration::from_secs(30));
        drop(balloon);
        Err(HardExit(0))
    }

    /// Writes a four-byte header declaring more than the response cap,
    /// then stops. The parent must refuse before allocating.
    fn harness_oversized() -> Result<Response, HardExit> {
        let mut stdout = io::stdout().lock();
        let _ = stdout.write_all(&u32::MAX.to_be_bytes());
        let _ = stdout.flush();
        std::thread::sleep(std::time::Duration::from_secs(30));
        Err(HardExit(0))
    }

    /// Writes a valid frame, then extra bytes. One frame is the whole
    /// stdout budget, so the trailing bytes are a violation.
    fn harness_trailing() -> Result<Response, HardExit> {
        let response = Response::ok(serde_json::json!({ "note": "then noise" }));
        let mut stdout = io::stdout().lock();
        let _ = protocol::write_frame(&mut stdout, &response);
        let _ = stdout.write_all(b"trailing noise past the frame");
        let _ = stdout.flush();
        std::thread::sleep(std::time::Duration::from_secs(30));
        Err(HardExit(0))
    }

    /// Writes a header and only part of the declared payload, then
    /// exits. The parent sees a truncated frame.
    fn harness_truncated() -> Result<Response, HardExit> {
        let mut stdout = io::stdout().lock();
        let _ = stdout.write_all(&64u32.to_be_bytes());
        let _ = stdout.write_all(b"{\"partial\":");
        let _ = stdout.flush();
        std::process::exit(0);
    }

    /// Floods stderr past its cap while writing no response frame.
    fn harness_stderr_flood() -> Result<Response, HardExit> {
        let chunk = [b'x'; 8192];
        let mut stderr = io::stderr().lock();
        for _ in 0..4096 {
            if stderr.write_all(&chunk).is_err() {
                break;
            }
        }
        let _ = stderr.flush();
        std::thread::sleep(std::time::Duration::from_secs(30));
        Err(HardExit(0))
    }

    fn confirm_input(name: &str) -> Result<(), HardExit> {
        if std::fs::metadata(name).is_ok() {
            Ok(())
        } else {
            eprintln!("worker_missing_input: {name}");
            Err(HardExit(4))
        }
    }

    fn parse<T: serde::de::DeserializeOwned>(request: &Request) -> Result<T, HardExit> {
        serde_json::from_value(request.payload.clone()).map_err(|e| {
            eprintln!("worker_bad_payload: {e}");
            HardExit(2)
        })
    }
}
