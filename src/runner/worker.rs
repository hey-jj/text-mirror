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
        #[cfg(feature = "test-adapters")]
        other => harness::run(other, read_request()?),
        #[cfg(not(feature = "test-adapters"))]
        other => {
            eprintln!("worker_unknown_mode: {other}");
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

    use crate::runner::protocol::bodies::{ProbeAttempt, ProbeNetRequest};

    const TIMEOUT: Duration = Duration::from_millis(600);

    pub(super) fn attempt_all(request: &ProbeNetRequest) -> Vec<ProbeAttempt> {
        vec![
            tcp("ipv4_tcp", &request.tcp4_target),
            tcp("ipv6_tcp", &request.tcp6_target),
            unix_socket(&request.unix_target),
            udp_send(&request.tcp4_target),
        ]
    }

    fn classify(name: &str, result: io::Result<()>) -> ProbeAttempt {
        let (outcome, detail) = match result {
            Ok(()) => (
                "connected",
                "the connection succeeded, the jail is not proven".to_string(),
            ),
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) =>
            {
                ("timeout", e.to_string())
            }
            Err(e) => ("denied", e.to_string()),
        };
        ProbeAttempt {
            name: name.to_string(),
            outcome: outcome.to_string(),
            detail,
        }
    }

    fn tcp(name: &str, target: &str) -> ProbeAttempt {
        // An unparseable target is instrumentation error, not denial.
        let address = match target.parse::<SocketAddr>() {
            Ok(address) => address,
            Err(e) => {
                return ProbeAttempt {
                    name: name.to_string(),
                    outcome: "invalid_target".to_string(),
                    detail: e.to_string(),
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
        classify("unix_socket", result)
    }

    #[cfg(not(target_os = "linux"))]
    fn unix_socket(target: &str) -> ProbeAttempt {
        classify(
            "unix_socket",
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
        classify("udp_send", result)
    }
}

#[cfg(feature = "test-adapters")]
mod harness {
    use std::io::Write;

    use super::*;
    use crate::runner::protocol::bodies::{
        AsrOk, AsrRequest, AsrSegment, OcrInput, OcrOk, OcrRequest, OcrSpan, ScreenState, VideoOk,
        VideoRequest,
    };

    pub(super) fn run(mode: &str, request: Request) -> Result<Response, HardExit> {
        match mode {
            "ocr" => ocr(request),
            "asr" => asr(request),
            "video" => video(request),
            "harness-echo" => Ok(Response::ok(request.payload)),
            "harness-env" => harness_env(),
            "harness-escape" => harness_escape(request),
            "harness-crash" => harness_crash(),
            "harness-sleep" => harness_sleep(),
            "harness-oversized" => harness_oversized(),
            "harness-trailing" => harness_trailing(),
            "harness-truncated" => harness_truncated(),
            "harness-stderr-flood" => harness_stderr_flood(),
            "harness-survivor" => harness_survivor(request),
            "harness-spawn-storm" => harness_spawn_storm(request),
            "harness-fd-check" => harness_fd_check(request),
            other => {
                eprintln!("worker_unknown_mode: {other}");
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
        };
        Ok(Response::ok(serde_json::to_value(ok).expect("OcrOk")))
    }

    /// A fake speech engine. Returns two diarized segments.
    fn asr(request: Request) -> Result<Response, HardExit> {
        let body: AsrRequest = parse(&request)?;
        confirm_input(&body.input)?;
        let ok = AsrOk {
            segments: vec![
                AsrSegment {
                    start_seconds: 0.0,
                    end_seconds: 4.5,
                    speaker: 1,
                    text: "welcome to the recording".to_string(),
                },
                AsrSegment {
                    start_seconds: 4.5,
                    end_seconds: 9.0,
                    speaker: 2,
                    text: "glad to be here".to_string(),
                },
            ],
            language: body.language.or_else(|| Some("en".to_string())),
            duration_seconds: Some(9.0),
        };
        Ok(Response::ok(serde_json::to_value(ok).expect("AsrOk")))
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
        }
        let body: EscapeRequest = parse(&request)?;
        let read = std::fs::read(&body.read_path)
            .map(|bytes| format!("read succeeded with {} bytes", bytes.len()))
            .unwrap_or_else(|e| format!("read denied: {e}"));
        let target = std::env::temp_dir().join("text-mirror-escape-probe");
        let write = std::fs::write(&target, b"escaped")
            .map(|_| "write succeeded".to_string())
            .unwrap_or_else(|e| format!("write denied: {e}"));
        Ok(Response::ok(serde_json::json!({
            "read": read,
            "write": write,
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
