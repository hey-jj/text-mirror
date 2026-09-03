//! The sandboxed subprocess runner behind every subprocess adapter.
//!
//! The runner enforces the whole sandbox contract from the design
//! document: a wall-clock timeout, separate stdout and stderr caps
//! drained concurrently, no network, no inherited environment, and a
//! temp-dir working jail. Every violation fails closed with a
//! machine-readable reason and no partial result.
//!
//! The spawn is two-stage. The parent builds a `std::process::Command`
//! through the platform [`jail::JailBackend`] with a cleared
//! environment, the jail as working directory, piped stdio, and a
//! fresh process group. The child starts in the worker binary's
//! single-threaded sandbox helper mode, which applies namespaces,
//! resource limits, descriptor hygiene, the filesystem jail, and the
//! syscall filter, then execs the requested adapter mode. No sandbox
//! work runs in a `pre_exec` closure.
//!
//! The wall clock is a parent-owned monotonic deadline. When it fires,
//! or when either output cap is crossed, the parent kills the whole
//! process group with SIGKILL. The same group kill also runs after a
//! normal clean exit, so no descendant outlives the invocation, and
//! the post-exit drain join is deadline-bounded, so the parent never
//! blocks on a pipe an escaped descendant holds open. A response
//! frame is accepted only from a child that wrote exactly one
//! complete frame, nothing after it, and exited cleanly.

use std::io::Read;
use std::path::PathBuf;
use std::process::{Child, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

pub mod helper;
pub mod jail;
mod memory;
pub mod protocol;
pub mod worker;

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;

use jail::{JailBackend, ProviderJail, RuntimeProfile, SpawnSpec};
use protocol::{FrameRead, Request, RequestSchema, Response};

/// Resource and output limits for one adapter class.
#[derive(Debug, Clone)]
pub struct Limits {
    /// Wall-clock ceiling enforced by the parent.
    pub wall_timeout: Duration,
    /// Ceiling on the response frame payload, checked against the
    /// declared length before allocation.
    pub max_response_bytes: u32,
    /// Ceiling on stderr bytes, drained and counted concurrently.
    pub max_stderr_bytes: u64,
    /// RLIMIT_AS for the child, in bytes. `None` leaves the limit
    /// unset, the shape a profile takes on a platform where the mapped
    /// accelerator runtime reserves a virtual range no sane cap sits
    /// above; the resident-memory guard below is the bound there.
    pub address_space_bytes: Option<u64>,
    /// RLIMIT_CPU for the child, in seconds.
    pub cpu_seconds: u64,
    /// RLIMIT_FSIZE for the child, in bytes. Caps regular-file growth
    /// inside the jail. Stdout is a pipe, so the response cap above
    /// is enforced by the parent instead.
    pub file_size_bytes: u64,
    /// RLIMIT_NPROC for the child: this invocation's spawn budget, so
    /// a compromised adapter cannot fork-bomb the host. The limit
    /// counts every process of the mapped real user id, not just this
    /// invocation's descendants, so the helper applies the number as
    /// headroom above the count that already exists at spawn, clamped
    /// to the hard limit. The semantic is defined there once and
    /// holds for every profile. A count the host will not answer
    /// refuses the run with `process-count-unavailable`, never a
    /// substituted baseline.
    pub max_processes: u64,
    /// Parent-side ceiling on the aggregate resident bytes of the
    /// child's whole process group, engine descendants included. The
    /// parent polls the group while the child runs, kills the group
    /// when the sum crosses the ceiling, and fails closed with
    /// `worker-memory-exceeded`. A failed measurement is itself a
    /// failure, `memory-monitor-failed`, never a silent pass. `None`
    /// disables the monitor, the shape of every profile whose worker
    /// spawns no engine child.
    pub max_resident_bytes: Option<u64>,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits {
            wall_timeout: Duration::from_secs(120),
            max_response_bytes: 192 * 1024 * 1024,
            max_stderr_bytes: 1024 * 1024,
            address_space_bytes: Some(4 * 1024 * 1024 * 1024),
            cpu_seconds: 300,
            file_size_bytes: 512 * 1024 * 1024,
            max_processes: 16,
            max_resident_bytes: None,
        }
    }
}

/// A runner failure with a machine-readable reason.
///
/// The codes are stable: `sandbox_unavailable`, `sandbox_probe_failed`,
/// `worker_not_found`, `adapter_spawn_error`, `adapter_timeout`,
/// `adapter_frame_oversized`, `adapter_output_overflow`,
/// `adapter_protocol_error`, `adapter_drain_timeout`,
/// `adapter_crash`, `worker-memory-exceeded`,
/// `memory-monitor-failed`, and `process-count-unavailable`.
#[derive(Debug, Clone)]
pub struct RunnerError {
    /// Stable reason code.
    pub code: &'static str,
    /// Detail for a human reading the manifest.
    pub message: String,
}

impl std::fmt::Display for RunnerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for RunnerError {}

/// The BLAKE3 of the provider jail profile template on this platform,
/// or `None` where no provider profile is measured. Part of the
/// effective rules version whenever a provider is configured.
pub fn provider_profile_template_blake3() -> Option<String> {
    #[cfg(target_os = "macos")]
    {
        Some(macos::provider_profile_template_blake3())
    }
    #[cfg(not(target_os = "macos"))]
    {
        None
    }
}

/// File name of the worker binary this crate ships.
pub const WORKER_BINARY: &str = "text-mirror-worker";

/// Exit code the sandbox helper uses when jail setup fails, so the
/// parent can tell a refused jail from an adapter crash.
pub const SANDBOX_SETUP_EXIT: i32 = 71;

/// Exit code the sandbox helper uses when the real user id's process
/// count cannot be measured, so the parent can name that refusal
/// rather than folding it into every other setup failure.
pub const PROCESS_COUNT_EXIT: i32 = 72;

/// Locates the worker binary beside the current executable, or one
/// directory up, which covers an installed layout and a build tree.
pub fn locate_worker() -> Result<PathBuf, RunnerError> {
    let missing = |detail: String| RunnerError {
        code: "worker_not_found",
        message: detail,
    };
    let current = std::env::current_exe().map_err(|e| {
        missing(format!(
            "cannot resolve the current executable: {:?}",
            e.kind()
        ))
    })?;
    let Some(dir) = current.parent() else {
        return Err(missing(
            "the current executable has no directory".to_string(),
        ));
    };
    let mut candidates = vec![dir.join(WORKER_BINARY)];
    if let Some(parent) = dir.parent() {
        candidates.push(parent.join(WORKER_BINARY));
    }
    for candidate in &candidates {
        if candidate.is_file() {
            return candidate
                .canonicalize()
                .map_err(|e| missing(format!("cannot resolve the worker binary: {:?}", e.kind())));
        }
    }
    Err(missing(format!(
        "no {WORKER_BINARY} beside the current executable"
    )))
}

/// Runs worker modes under the platform jail.
pub struct Runner {
    backend: Box<dyn JailBackend>,
    worker: PathBuf,
    limits: Limits,
    exec_grants: Vec<PathBuf>,
    read_grants: Vec<PathBuf>,
    runtime_profile: RuntimeProfile,
    provider: Option<ProviderJail>,
}

impl Runner {
    /// A runner over an explicit backend, worker, and limits, with no
    /// grants beyond the worker and the jail.
    pub fn new(backend: Box<dyn JailBackend>, worker: PathBuf, limits: Limits) -> Runner {
        Runner::with_grants(
            backend,
            worker,
            limits,
            Vec::new(),
            Vec::new(),
            RuntimeProfile::Plain,
        )
    }

    /// A runner whose jail additionally grants literal files: read and
    /// execute for `exec_grants`, read only for `read_grants`. This is
    /// how the pinned engine binaries and weights reach a jailed
    /// worker: literal files only, never a directory, and the worker
    /// still re-hashes each one against its pinned BLAKE3 before use.
    ///
    /// `runtime_profile` is the measured jail class this worker mode
    /// is authorized for. Only the audio worker mode passes
    /// [`RuntimeProfile::Accelerator`]; every other mode passes
    /// [`RuntimeProfile::Plain`] whatever grants it carries, so no
    /// worker inherits allowances measured for a different engine.
    pub fn with_grants(
        backend: Box<dyn JailBackend>,
        worker: PathBuf,
        limits: Limits,
        exec_grants: Vec<PathBuf>,
        read_grants: Vec<PathBuf>,
        runtime_profile: RuntimeProfile,
    ) -> Runner {
        Runner {
            backend,
            worker,
            limits,
            exec_grants,
            read_grants,
            runtime_profile,
            provider: None,
        }
    }

    /// A runner under the provider jail class, whose profile
    /// additionally grants the measured closures and service namespace
    /// the pinned external components need.
    ///
    /// The class alone buys nothing: the backend renders the widened
    /// profile only when this class arrives together with a non-empty
    /// executable grant and these parameters, so a worker that names
    /// the class with nothing wired keeps the base profile.
    pub fn with_provider_jail(
        backend: Box<dyn JailBackend>,
        worker: PathBuf,
        limits: Limits,
        exec_grants: Vec<PathBuf>,
        read_grants: Vec<PathBuf>,
        provider: ProviderJail,
    ) -> Runner {
        Runner {
            backend,
            worker,
            limits,
            exec_grants,
            read_grants,
            runtime_profile: RuntimeProfile::Provider,
            provider: Some(provider),
        }
    }

    /// The platform backend, the co-located worker binary, and
    /// default limits.
    pub fn with_platform_defaults() -> Result<Runner, RunnerError> {
        Ok(Runner::new(
            jail::platform_backend()?,
            locate_worker()?,
            Limits::default(),
        ))
    }

    /// The backend this runner spawns through.
    pub fn backend(&self) -> &dyn JailBackend {
        self.backend.as_ref()
    }

    /// The limits this runner enforces.
    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    /// Test-only view of the literal grant lists, so a converter test
    /// can prove exactly which capabilities its jail would receive.
    #[cfg(test)]
    pub(crate) fn grant_lists(&self) -> (&[PathBuf], &[PathBuf]) {
        (&self.exec_grants, &self.read_grants)
    }

    /// Test-only view of the jail class, so a converter test can
    /// prove which adapter modes ask for the device allowances.
    #[cfg(test)]
    pub(crate) fn runtime_profile(&self) -> RuntimeProfile {
        self.runtime_profile
    }

    /// Test-only view of the provider jail parameters, so a converter
    /// test can prove exactly which closures its jail would grant.
    #[cfg(test)]
    pub(crate) fn provider_jail(&self) -> Option<&ProviderJail> {
        self.provider.as_ref()
    }

    /// The policy digest that keys this runner's probe cache entry.
    pub fn policy_digest(&self) -> Result<String, RunnerError> {
        jail::policy_digest(
            self.backend.as_ref(),
            &self.worker,
            &self.exec_grants,
            &self.read_grants,
            self.runtime_profile,
            self.provider.as_ref(),
        )
    }

    /// Runs one adapter mode inside the jail and returns its response.
    ///
    /// `files` are written into a fresh jail directory before the
    /// spawn, so the child reads inputs by bare name from its working
    /// directory. The capability probe must have passed for the
    /// current policy digest, and runs once per process if not.
    pub fn run(
        &self,
        mode: &str,
        payload: serde_json::Value,
        files: &[(&str, &[u8])],
    ) -> Result<Response, RunnerError> {
        let digest = self.policy_digest()?;
        jail::ensure_probed(self, &digest)?;
        self.run_unprobed(mode, payload, files, true)
    }

    /// Runs one mode without the probe gate. Only the probe itself
    /// uses this, and only through the jail backend.
    pub(crate) fn run_unprobed(
        &self,
        mode: &str,
        payload: serde_json::Value,
        files: &[(&str, &[u8])],
        seccomp: bool,
    ) -> Result<Response, RunnerError> {
        // Literal-file re-assertion at spawn time: every grant must be
        // a regular file right now, whatever an earlier validation
        // saw, so a path swapped for a directory or a symlink between
        // configuration and spawn refuses the run instead of widening
        // the jail.
        // The refusal names the grant by its kind and position and the
        // fault, never the path: this message reaches the record of
        // whatever was being converted, and a deployment path does not
        // belong there.
        let grants = self
            .exec_grants
            .iter()
            .enumerate()
            .map(|(index, grant)| {
                (
                    format!(
                        "executable grant {} of {}",
                        index + 1,
                        self.exec_grants.len()
                    ),
                    grant,
                )
            })
            .chain(self.read_grants.iter().enumerate().map(|(index, grant)| {
                (
                    format!("read grant {} of {}", index + 1, self.read_grants.len()),
                    grant,
                )
            }));
        for (label, grant) in grants {
            let refuse = |detail: &str| RunnerError {
                code: "adapter_spawn_error",
                message: format!("{label} is not a literal regular file: {detail}"),
            };
            match std::fs::symlink_metadata(grant) {
                Ok(metadata) if metadata.file_type().is_file() => {}
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    return Err(refuse("it is a symlink"));
                }
                Ok(_) => return Err(refuse("it is not a regular file")),
                Err(e) => {
                    let detail = format!("{:?}", e.kind());
                    return Err(refuse(&detail));
                }
            }
        }
        let jail_dir = tempfile::tempdir().map_err(|e| RunnerError {
            code: "adapter_spawn_error",
            message: format!("cannot create the jail directory: {:?}", e.kind()),
        })?;
        let jail_path = jail_dir.path().canonicalize().map_err(|e| RunnerError {
            code: "adapter_spawn_error",
            message: format!("cannot canonicalize the jail directory: {:?}", e.kind()),
        })?;
        for (name, bytes) in files {
            if name.contains('/') || name.contains("..") {
                return Err(RunnerError {
                    code: "adapter_spawn_error",
                    message: format!("input name {name:?} is not a bare file name"),
                });
            }
            std::fs::write(jail_path.join(name), bytes).map_err(|e| RunnerError {
                code: "adapter_spawn_error",
                message: format!("cannot stage input {name:?}: {:?}", e.kind()),
            })?;
        }

        let spec = SpawnSpec {
            worker: &self.worker,
            jail: &jail_path,
            mode,
            limits: &self.limits,
            seccomp,
            exec_grants: &self.exec_grants,
            read_grants: &self.read_grants,
            runtime_profile: self.runtime_profile,
            provider: self.provider.as_ref(),
        };
        let mut command = self.backend.command(&spec)?;
        command
            .env_clear()
            .current_dir(&jail_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }
        let mut child = command.spawn().map_err(|e| RunnerError {
            code: "adapter_spawn_error",
            message: format!("cannot spawn the jailed worker: {:?}", e.kind()),
        })?;

        let request = Request {
            schema: RequestSchema,
            adapter: mode.to_string(),
            payload,
        };
        if let Some(mut stdin) = child.stdin.take() {
            // A child that dies before reading breaks the pipe. That
            // is not a verdict, the exit status below is.
            let _ = protocol::write_frame(&mut stdin, &request);
        }

        drive(&mut child, &self.limits)
    }
}

/// What the stdout drain thread observed.
enum StdoutEnd {
    Frame(Vec<u8>),
    Empty,
    Truncated,
    Oversized { declared: u64 },
    Trailing,
    ReadError(std::io::ErrorKind),
}

/// How long the parent waits for the drains to reach EOF after the
/// final group kill. A drain still open past this bound means a
/// descendant escaped the process group and holds a pipe, and the
/// parent detaches the drain and fails closed instead of hanging.
const DRAIN_JOIN_BOUND: Duration = Duration::from_secs(2);

/// Drains both pipes concurrently, enforces the deadline and caps,
/// and interprets the exit.
///
/// The group-lifetime contract: no descendant outlives the
/// invocation. The parent SIGKILLs the whole process group on every
/// exit path, the normal clean exit included, before it returns. The
/// parent itself never blocks without a bound: the post-exit drain
/// join is deadline-bounded, and a drain that does not finish is
/// detached while the call returns a fail-closed reason.
fn drive(child: &mut Child, limits: &Limits) -> Result<Response, RunnerError> {
    let kill_now = Arc::new(AtomicBool::new(false));

    let stdout = child.stdout.take().expect("stdout was piped");
    let stdout_kill = kill_now.clone();
    let max_response = limits.max_response_bytes;
    let (stdout_done, stdout_result) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut reader = stdout;
        let end = match protocol::read_frame(&mut reader, max_response) {
            Ok(FrameRead::Complete(payload)) => {
                // One frame is the whole grammar. Any byte after it is
                // a protocol violation and kills the child.
                let mut probe = [0u8; 1];
                match reader.read(&mut probe) {
                    Ok(0) => StdoutEnd::Frame(payload),
                    Ok(_) => StdoutEnd::Trailing,
                    Err(e) => StdoutEnd::ReadError(e.kind()),
                }
            }
            Ok(FrameRead::Empty) => StdoutEnd::Empty,
            Ok(FrameRead::Truncated) => StdoutEnd::Truncated,
            Ok(FrameRead::Oversized { declared }) => StdoutEnd::Oversized { declared },
            Err(e) => StdoutEnd::ReadError(e.kind()),
        };
        if matches!(
            end,
            StdoutEnd::Oversized { .. } | StdoutEnd::Trailing | StdoutEnd::ReadError(_)
        ) {
            stdout_kill.store(true, Ordering::SeqCst);
        }
        if matches!(end, StdoutEnd::Oversized { .. } | StdoutEnd::Trailing) {
            // Keep the pipe drained so the child cannot stall on a
            // full pipe between the violation and the kill. The bytes
            // are discarded.
            let mut sink = [0u8; 8192];
            while matches!(reader.read(&mut sink), Ok(n) if n > 0) {}
        }
        let _ = stdout_done.send(end);
    });

    let stderr = child.stderr.take().expect("stderr was piped");
    let stderr_kill = kill_now.clone();
    let max_stderr = limits.max_stderr_bytes;
    let (stderr_done, stderr_result) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut reader = stderr;
        let mut kept = Vec::new();
        let mut total: u64 = 0;
        let mut chunk = [0u8; 8192];
        loop {
            match reader.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    total += n as u64;
                    if kept.len() < 4096 {
                        let take = (4096 - kept.len()).min(n);
                        kept.extend_from_slice(&chunk[..take]);
                    }
                    if total > max_stderr {
                        stderr_kill.store(true, Ordering::SeqCst);
                        // Keep draining so the child cannot stall.
                    }
                }
                Err(_) => break,
            }
        }
        let _ = stderr_done.send((kept, total));
    });

    let deadline = Instant::now() + limits.wall_timeout;
    let mut timed_out = false;
    // The resident-memory guard: while the child runs, the parent
    // periodically sums resident bytes over the whole process group,
    // so the engine child and any other descendant are counted, not
    // just the worker. A crossing kills the group; a failed
    // measurement also kills the group and fails closed. The drains
    // above keep running through the termination either way.
    const MEMORY_POLL_INTERVAL: Duration = Duration::from_millis(100);
    let mut next_memory_check = Instant::now() + MEMORY_POLL_INTERVAL;
    let mut memory_failure: Option<RunnerError> = None;
    let status = loop {
        if let Some(status) = child.try_wait().ok().flatten() {
            break status;
        }
        if Instant::now() >= deadline {
            timed_out = true;
            kill_group(child);
            break wait_after_kill(child);
        }
        if kill_now.load(Ordering::SeqCst) {
            kill_group(child);
            break wait_after_kill(child);
        }
        if let Some(ceiling) = limits.max_resident_bytes
            && Instant::now() >= next_memory_check
        {
            next_memory_check = Instant::now() + MEMORY_POLL_INTERVAL;
            memory_failure = memory_verdict(memory::group_resident_bytes(child.id()), ceiling);
            if memory_failure.is_some() {
                kill_group(child);
                break wait_after_kill(child);
            }
        }
        std::thread::sleep(Duration::from_millis(2));
    };

    // One final group measurement after the leader exits and BEFORE
    // the unconditional group kill below, so a descendant that
    // ballooned and outlived a fast-exiting leader is still measured:
    // a clean exit inside the first polling interval must not bypass
    // the guard. Over the ceiling discards the response, and a failed
    // measurement fails closed, exactly as the polled path does. The
    // wall-timeout path keeps its own verdict, and a group the kill
    // paths already emptied simply measures zero.
    if let Some(ceiling) = limits.max_resident_bytes
        && memory_failure.is_none()
        && !timed_out
    {
        memory_failure = memory_verdict(memory::group_resident_bytes(child.id()), ceiling);
    }

    // The final group kill runs on every exit path, the normal clean
    // exit included, so a descendant that closed its stdio and
    // lingered past its leader is still killed. The group id stays
    // reserved while any member lives, and ESRCH on an empty group is
    // fine.
    kill_group(child);

    // Bounded drain join. On Linux the group kill guarantees EOF,
    // because a descendant cannot leave the group. On macOS a
    // descendant that changed its session can survive the group kill
    // holding a pipe, and this bound is what keeps the parent from
    // hanging on it: the drain is detached and the call fails closed.
    let join_deadline = Instant::now() + DRAIN_JOIN_BOUND;
    let stdout_end = stdout_result.recv_timeout(DRAIN_JOIN_BOUND).ok();
    let stderr_end = stderr_result
        .recv_timeout(join_deadline.saturating_duration_since(Instant::now()))
        .ok();
    let (Some(stdout_end), Some((stderr_kept, stderr_total))) = (stdout_end, stderr_end) else {
        return Err(RunnerError {
            code: "adapter_drain_timeout",
            message: format!(
                "a pipe stayed open {DRAIN_JOIN_BOUND:?} after the group kill, so a descendant escaped the process group; the drain is detached and all output is discarded"
            ),
        });
    };

    if let Some(failure) = memory_failure {
        return Err(failure);
    }
    if timed_out {
        return Err(RunnerError {
            code: "adapter_timeout",
            message: format!(
                "killed the process group after the {:?} wall-clock ceiling, partial output discarded",
                limits.wall_timeout
            ),
        });
    }
    if let StdoutEnd::Oversized { declared } = stdout_end {
        return Err(RunnerError {
            code: "adapter_frame_oversized",
            message: format!(
                "response frame declared {declared} bytes over the {} byte ceiling, refused before allocation",
                limits.max_response_bytes
            ),
        });
    }
    if stderr_total > limits.max_stderr_bytes {
        return Err(RunnerError {
            code: "adapter_output_overflow",
            message: format!(
                "stderr wrote {stderr_total} bytes over the {} byte cap",
                limits.max_stderr_bytes
            ),
        });
    }
    if matches!(stdout_end, StdoutEnd::Trailing) {
        return Err(RunnerError {
            code: "adapter_output_overflow",
            message: "bytes after the response frame, one frame is the whole stdout budget"
                .to_string(),
        });
    }
    if !status.success() {
        let detail = exit_detail(&status);
        let stderr_text = String::from_utf8_lossy(&stderr_kept);
        let stderr_text = scrub_stderr(&stderr_text, limits.max_stderr_bytes);
        #[cfg(unix)]
        let refusal = helper_refusal(status.code(), &stderr_text);
        #[cfg(not(unix))]
        let refusal = None;
        if let Some(error) = refusal {
            return Err(error);
        }
        return Err(RunnerError {
            code: "adapter_crash",
            message: if stderr_text.is_empty() {
                format!("worker {detail}, any response frame is discarded")
            } else {
                format!("worker {detail}: {stderr_text}")
            },
        });
    }
    let payload = match stdout_end {
        StdoutEnd::Frame(payload) => payload,
        StdoutEnd::Empty => {
            return Err(RunnerError {
                code: "adapter_protocol_error",
                message: "worker exited without a response frame".to_string(),
            });
        }
        StdoutEnd::Truncated => {
            return Err(RunnerError {
                code: "adapter_protocol_error",
                message: "worker exited with a truncated response frame".to_string(),
            });
        }
        StdoutEnd::ReadError(detail) => {
            return Err(RunnerError {
                code: "adapter_protocol_error",
                message: format!("reading the response failed: {detail:?}"),
            });
        }
        StdoutEnd::Oversized { .. } | StdoutEnd::Trailing => unreachable!("handled above"),
    };
    let response: Response = serde_json::from_slice(&payload).map_err(|_| RunnerError {
        code: "adapter_protocol_error",
        message: "response frame did not parse".to_string(),
    })?;
    response.validate().map_err(|detail| RunnerError {
        code: "adapter_protocol_error",
        message: detail,
    })?;
    Ok(response)
}

/// Replaces each whitespace-delimited stderr token that contains `/`
/// before the text can enter a runner message. Both helper refusals
/// and worker crashes use this function. The returned text stays
/// within the configured stderr byte ceiling.
fn scrub_stderr(stderr_text: &str, max_bytes: u64) -> String {
    const PATH_PLACEHOLDER: &str = "[path]";

    let max_bytes = usize::try_from(max_bytes).unwrap_or(usize::MAX);
    let mut scrubbed = String::new();
    for token in stderr_text.split_whitespace() {
        let token = if token.contains('/') {
            PATH_PLACEHOLDER
        } else {
            token
        };
        let separator = usize::from(!scrubbed.is_empty());
        if scrubbed
            .len()
            .saturating_add(separator)
            .saturating_add(token.len())
            > max_bytes
        {
            break;
        }
        if separator == 1 {
            scrubbed.push(' ');
        }
        scrubbed.push_str(token);
    }
    scrubbed
}

/// Interprets a helper exit code that refused before any adapter ran.
/// A failed jail setup is `sandbox_unavailable`. A process count the
/// host would not answer is `process-count-unavailable`, kept apart
/// because a spawn budget whose baseline is unknown is refused, not
/// guessed at. Any other exit code is the adapter's own.
#[cfg_attr(not(unix), allow(dead_code))]
fn helper_refusal(exit: Option<i32>, stderr_text: &str) -> Option<RunnerError> {
    let (code, refused) = match exit? {
        SANDBOX_SETUP_EXIT => ("sandbox_unavailable", "refused to engage the jail"),
        PROCESS_COUNT_EXIT => (
            "process-count-unavailable",
            "could not measure the user's process count and refused the spawn",
        ),
        _ => return None,
    };
    Some(RunnerError {
        code,
        message: format!("the sandbox helper {refused}: {stderr_text}"),
    })
}

/// Interprets one resident-memory measurement against the ceiling.
/// Over the ceiling is `worker-memory-exceeded`; a failed measurement
/// is `memory-monitor-failed`, because a guard that cannot see is a
/// guard that must fail closed.
fn memory_verdict(measurement: Result<u64, String>, ceiling: u64) -> Option<RunnerError> {
    match measurement {
        Ok(total) if total > ceiling => Some(RunnerError {
            code: "worker-memory-exceeded",
            message: format!(
                "the worker process group holds {total} resident bytes over the {ceiling} byte ceiling, killed"
            ),
        }),
        Ok(_) => None,
        Err(detail) => Some(RunnerError {
            code: "memory-monitor-failed",
            message: format!("the resident-memory measurement failed, failing closed: {detail}"),
        }),
    }
}

/// Kills the child's whole process group with SIGKILL.
fn kill_group(child: &mut Child) {
    #[cfg(unix)]
    {
        if let Ok(pid) = i32::try_from(child.id()) {
            // The child is its own group leader via process_group(0),
            // and ESRCH after the group is gone is fine.
            let _ = nix::sys::signal::killpg(
                nix::unistd::Pid::from_raw(pid),
                nix::sys::signal::Signal::SIGKILL,
            );
        }
    }
    #[cfg(not(unix))]
    {
        let _ = child.kill();
    }
}

fn wait_after_kill(child: &mut Child) -> std::process::ExitStatus {
    child.wait().unwrap_or_else(|_| {
        // The child was already reaped by try_wait.
        child
            .try_wait()
            .ok()
            .flatten()
            .expect("killed child has an exit status")
    })
}

fn exit_detail(status: &std::process::ExitStatus) -> String {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return format!("died on signal {signal}");
        }
    }
    match status.code() {
        Some(code) => format!("exited with code {code}"),
        None => "exited without a status".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_helper_refusal_is_named_and_never_folded_into_a_crash() {
        // A failed jail setup keeps the code it always had.
        let setup =
            helper_refusal(Some(SANDBOX_SETUP_EXIT), "detail").expect("a setup exit is a refusal");
        assert_eq!(setup.code, "sandbox_unavailable");
        // An unmeasurable process count is named on its own, so the
        // manifest says why the spawn never happened.
        let count = helper_refusal(Some(PROCESS_COUNT_EXIT), "the listing is unavailable")
            .expect("a count exit is a refusal");
        assert_eq!(count.code, "process-count-unavailable");
        assert!(
            count.message.contains("the listing is unavailable"),
            "{count}"
        );
        // Everything else is the adapter's own exit, not a refusal.
        assert!(helper_refusal(Some(1), "detail").is_none());
        assert!(helper_refusal(None, "detail").is_none());
    }

    #[test]
    fn stderr_passthrough_replaces_absolute_and_grant_paths() {
        let absolute = "/runtime/worker";
        let grant = "/runtime/grants/engine-cli";
        let detail = format!("sandbox_setup_failed: open {absolute} grant {grant}: NotFound");
        let scrubbed = scrub_stderr(&detail, 1024);
        let refusal =
            helper_refusal(Some(SANDBOX_SETUP_EXIT), &scrubbed).expect("a setup exit is a refusal");
        assert!(!refusal.message.contains(absolute), "{refusal}");
        assert!(!refusal.message.contains(grant), "{refusal}");
        assert_eq!(refusal.message.matches("[path]").count(), 2);
        assert!(refusal.message.len() <= 1024);
    }

    #[test]
    fn a_missing_worker_hash_reports_only_the_error_kind() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing-worker");
        let backend = jail::platform_backend().expect("this host has a jail backend");
        let error = jail::policy_digest(
            backend.as_ref(),
            &missing,
            &[],
            &[],
            RuntimeProfile::Plain,
            None,
        )
        .expect_err("the missing worker cannot be hashed");
        assert_eq!(error.code, "worker_not_found");
        assert_eq!(
            error.message,
            "the worker binary cannot be hashed: NotFound"
        );
        for component in missing.components() {
            let std::path::Component::Normal(component) = component else {
                continue;
            };
            assert!(
                !error
                    .message
                    .as_bytes()
                    .windows(component.as_encoded_bytes().len())
                    .any(|window| window == component.as_encoded_bytes()),
                "a worker path component reached the message"
            );
        }
    }

    #[test]
    fn the_memory_verdict_kills_over_the_ceiling_and_fails_closed_on_a_query_error() {
        // Under the ceiling: no verdict.
        assert!(memory_verdict(Ok(100), 200).is_none());
        // Exactly at the ceiling: still inside it.
        assert!(memory_verdict(Ok(200), 200).is_none());
        // Over the ceiling: the group is killed with the stable code.
        let over = memory_verdict(Ok(201), 200).expect("over the ceiling is a verdict");
        assert_eq!(over.code, "worker-memory-exceeded");
        // A failed measurement is a failure of its own, never a pass:
        // a guard that cannot see must fail closed.
        let failed = memory_verdict(Err("query broke".to_string()), 200)
            .expect("a failed measurement is a verdict");
        assert_eq!(failed.code, "memory-monitor-failed");
        assert!(failed.message.contains("query broke"));
    }
}

/// Every runner error message can reach a record, so none may carry a
/// path. This reads the runner's own sources and refuses any error
/// construction, or any message handed to a refusal closure, that
/// renders a path or names a path-carrying variable. Runtime tests
/// cover the sites a test can trigger; this covers all of them.
#[cfg(test)]
mod message_audit_tests {
    const SOURCES: [(&str, &str); 4] = [
        ("mod.rs", include_str!("mod.rs")),
        ("jail.rs", include_str!("jail.rs")),
        ("macos.rs", include_str!("macos.rs")),
        ("linux.rs", include_str!("linux.rs")),
    ];

    /// The spellings a path takes when it is rendered into a message.
    const RENDERINGS: [&str; 8] = [
        "display()",
        "to_string_lossy(",
        "{text",
        "{path",
        "{e}",
        "{source}",
        "e.to_string()",
        "source.to_string()",
    ];

    /// Variables in the runner that hold a path, which no message may
    /// interpolate.
    const PATH_VARIABLES: [&str; 8] = [
        "{grant",
        "{closure",
        "{worker",
        "{candidate",
        "{current",
        "{target",
        "{jail",
        "{dir",
    ];

    /// Every error construction site and every refusal-closure call in
    /// one source, as the text of the site.
    fn sites(source: &str) -> Vec<String> {
        let mut found = Vec::new();
        for needle in [
            "RunnerError {",
            "refuse(",
            "missing(",
            "probe_bind_error(",
            "drift(",
        ] {
            let mut from = 0;
            while let Some(at) = source[from..].find(needle) {
                let start = from + at;
                // The site runs to the matching close of the brace or
                // parenthesis that opens it.
                let open = source[start..].find(['{', '(']).map(|i| start + i).unwrap();
                let (opener, closer) = if source.as_bytes()[open] == b'{' {
                    ('{', '}')
                } else {
                    ('(', ')')
                };
                let mut depth = 0usize;
                let mut end = open;
                for (offset, ch) in source[open..].char_indices() {
                    if ch == opener {
                        depth += 1;
                    } else if ch == closer {
                        depth -= 1;
                        if depth == 0 {
                            end = open + offset + ch.len_utf8();
                            break;
                        }
                    }
                }
                found.push(source[start..end].to_string());
                from = end.max(start + needle.len());
            }
        }
        found
    }

    #[test]
    fn no_runner_error_message_renders_a_path() {
        let mut audited = 0;
        for (name, source) in SOURCES {
            for site in sites(source) {
                // The audit reads the sites, not itself.
                if site.contains("RENDERINGS") || site.contains("PATH_VARIABLES") {
                    continue;
                }
                audited += 1;
                for rendering in RENDERINGS {
                    assert!(
                        !site.contains(rendering),
                        "{name}: a runner error renders a path with {rendering}: {site}"
                    );
                }
                for variable in PATH_VARIABLES {
                    assert!(
                        !site.contains(variable),
                        "{name}: a runner error interpolates {variable}: {site}"
                    );
                }
            }
        }
        // The audit saw the sites it exists for: the grant re-assertion
        // and the closure refusals among them.
        assert!(audited >= 40, "only {audited} sites audited");
    }

    #[test]
    fn the_construction_site_check_rejects_error_display() {
        let old_worker_hash = concat!(
            "Runner",
            r#"Error {
            code: "worker_not_found",
            message: format!("the worker binary cannot be hashed: "#,
            "{e}",
            r#""),
        }"#
        );
        let sites = sites(old_worker_hash);
        assert_eq!(sites.len(), 1);
        assert!(
            RENDERINGS
                .iter()
                .any(|rendering| sites[0].contains(rendering)),
            "the former worker-hash construction escaped the check"
        );
    }
}
