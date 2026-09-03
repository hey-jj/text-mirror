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
use protocol::bodies::{ProbeName, ProbeOutcome};
use protocol::{FrameRead, Request, RequestSchema, Response, ResponseValidationError};

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
    message: RunnerMessage,
}

impl RunnerError {
    fn new(code: &'static str, message: RunnerMessage) -> RunnerError {
        RunnerError { code, message }
    }

    /// Path-free detail for a human reading the manifest.
    pub fn message(&self) -> String {
        self.message.to_string()
    }
}

impl std::fmt::Display for RunnerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for RunnerError {}

#[derive(Debug, Clone, Copy)]
enum GrantKind {
    Executable,
    Read,
}

#[derive(Debug, Clone, Copy)]
enum GrantFault {
    Symlink,
    NotRegular,
    Io(std::io::ErrorKind),
}

#[derive(Debug, Clone, Copy)]
enum ClosureFault {
    NotAbsolute,
    NotNormal,
    Symlink,
    SharedRoot,
    Unresolved,
    NotFileOrDirectory,
    ResolvedSharedRoot,
}

#[derive(Debug, Clone, Copy)]
enum PathClass {
    Jail,
    Worker,
    ExecutableGrantDirectory,
    ExecutableGrant,
    ReadGrant,
}

#[derive(Debug, Clone, Copy)]
enum TemplateValue {
    Jail,
    Worker,
    Closures,
    Service,
    Grants,
}

#[derive(Debug, Clone, Copy)]
enum ExitDetail {
    SandboxSetup(i32),
    ProcessCount(i32),
    WorkerCode(i32),
    WorkerSignal(i32),
    WorkerNoStatus,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
enum RunnerMessage {
    CurrentExecutable(std::io::ErrorKind),
    CurrentExecutableHasNoDirectory,
    WorkerBinaryResolve(std::io::ErrorKind),
    WorkerBinaryMissing,
    Grant {
        kind: GrantKind,
        position: usize,
        count: usize,
        fault: GrantFault,
    },
    JailDirectoryCreate(std::io::ErrorKind),
    JailDirectoryCanonicalize(std::io::ErrorKind),
    InputNameNotBare,
    StageInput(std::io::ErrorKind),
    SpawnWorker(std::io::ErrorKind),
    DrainTimeout(u64),
    WallTimeout(u64),
    ResponseFrameOversized {
        declared: u64,
        ceiling: u64,
    },
    StderrOverflow {
        written: u64,
        ceiling: u64,
    },
    TrailingStdout,
    Exit(ExitDetail),
    EmptyResponse,
    TruncatedResponse,
    ReadResponse(std::io::ErrorKind),
    ParseResponse,
    ValidateResponse(ResponseValidationError),
    MemoryExceeded {
        total: u64,
        ceiling: u64,
    },
    Memory(memory::MemoryError),
    Closure {
        position: usize,
        count: usize,
        fault: ClosureFault,
    },
    ServiceNamespace,
    TempDirectoryVariable,
    PlatformBackendMissing,
    WorkerHash(std::io::ErrorKind),
    ProbeRequestEncode,
    ProbeReportedFailure,
    ProbeResponseParse,
    ProbeAttemptMissing(ProbeName),
    ProbeAttempt {
        name: ProbeName,
        outcome: ProbeOutcome,
        error_kind: std::io::ErrorKind,
    },
    ProbeListener(std::io::ErrorKind),
    TemplateBrace(TemplateValue),
    ClosureNotUtf8 {
        position: usize,
        count: usize,
    },
    ClosureCannotBeQuoted {
        position: usize,
        count: usize,
    },
    PathNotUtf8(PathClass),
    PathCannotBeQuoted(PathClass),
    ProviderNeedsWiring,
    SandboxHelperMissing,
    ProviderPlatformUnsupported,
    SyscallProbeAllowed,
    SyscallProbeFailed,
}

impl std::fmt::Display for RunnerMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            RunnerMessage::CurrentExecutable(kind) => {
                write!(f, "cannot resolve the current executable: {kind:?}")
            }
            RunnerMessage::CurrentExecutableHasNoDirectory => {
                f.write_str("the current executable has no directory")
            }
            RunnerMessage::WorkerBinaryResolve(kind) => {
                write!(f, "cannot resolve the worker binary: {kind:?}")
            }
            RunnerMessage::WorkerBinaryMissing => {
                write!(f, "no {WORKER_BINARY} beside the current executable")
            }
            RunnerMessage::Grant {
                kind,
                position,
                count,
                fault,
            } => {
                let kind = match kind {
                    GrantKind::Executable => "executable grant",
                    GrantKind::Read => "read grant",
                };
                write!(
                    f,
                    "{kind} {position} of {count} is not a literal regular file: "
                )?;
                match fault {
                    GrantFault::Symlink => f.write_str("it is a symlink"),
                    GrantFault::NotRegular => f.write_str("it is not a regular file"),
                    GrantFault::Io(kind) => write!(f, "{kind:?}"),
                }
            }
            RunnerMessage::JailDirectoryCreate(kind) => {
                write!(f, "cannot create the jail directory: {kind:?}")
            }
            RunnerMessage::JailDirectoryCanonicalize(kind) => {
                write!(f, "cannot canonicalize the jail directory: {kind:?}")
            }
            RunnerMessage::InputNameNotBare => f.write_str("an input name is not a bare file name"),
            RunnerMessage::StageInput(kind) => write!(f, "cannot stage an input: {kind:?}"),
            RunnerMessage::SpawnWorker(kind) => {
                write!(f, "cannot spawn the jailed worker: {kind:?}")
            }
            RunnerMessage::DrainTimeout(milliseconds) => write!(
                f,
                "a pipe stayed open {milliseconds} milliseconds after the group kill, so a descendant escaped the process group. The drain is detached and all output is discarded"
            ),
            RunnerMessage::WallTimeout(milliseconds) => write!(
                f,
                "killed the process group after the {milliseconds} millisecond wall-clock ceiling, partial output discarded"
            ),
            RunnerMessage::ResponseFrameOversized { declared, ceiling } => write!(
                f,
                "response frame declared {declared} bytes over the {ceiling} byte ceiling, refused before allocation"
            ),
            RunnerMessage::StderrOverflow { written, ceiling } => {
                write!(
                    f,
                    "stderr wrote {written} bytes over the {ceiling} byte cap"
                )
            }
            RunnerMessage::TrailingStdout => {
                f.write_str("bytes after the response frame, one frame is the whole stdout budget")
            }
            RunnerMessage::Exit(detail) => match detail {
                ExitDetail::SandboxSetup(code) => write!(
                    f,
                    "the sandbox helper refused to engage the jail (exit {code})"
                ),
                ExitDetail::ProcessCount(code) => write!(
                    f,
                    "the sandbox helper could not measure the user's process count and refused the spawn (exit {code})"
                ),
                ExitDetail::WorkerCode(code) => write!(
                    f,
                    "worker exited with code {code}, any response frame is discarded"
                ),
                ExitDetail::WorkerSignal(signal) => write!(
                    f,
                    "worker died on signal {signal}, any response frame is discarded"
                ),
                ExitDetail::WorkerNoStatus => {
                    f.write_str("worker exited without a status, any response frame is discarded")
                }
            },
            RunnerMessage::EmptyResponse => f.write_str("worker exited without a response frame"),
            RunnerMessage::TruncatedResponse => {
                f.write_str("worker exited with a truncated response frame")
            }
            RunnerMessage::ReadResponse(kind) => {
                write!(f, "reading the response failed: {kind:?}")
            }
            RunnerMessage::ParseResponse => f.write_str("response frame did not parse"),
            RunnerMessage::ValidateResponse(detail) => match detail {
                ResponseValidationError::BothBodies => {
                    f.write_str("response carries both ok and error")
                }
                ResponseValidationError::NoBody => {
                    f.write_str("response carries neither ok nor error")
                }
            },
            RunnerMessage::MemoryExceeded { total, ceiling } => write!(
                f,
                "the worker process group holds {total} resident bytes over the {ceiling} byte ceiling, killed"
            ),
            RunnerMessage::Memory(error) => match error {
                memory::MemoryError::ProcessTable(kind) => {
                    write!(f, "cannot enumerate the process table: {kind:?}")
                }
                memory::MemoryError::ProcessGroup(kind) => {
                    write!(f, "cannot enumerate the process group: {kind:?}")
                }
                memory::MemoryError::ProcessGroupRecheck(kind) => {
                    write!(f, "cannot re-enumerate the process group: {kind:?}")
                }
                memory::MemoryError::GroupLeaderPid(pid) => {
                    write!(f, "group leader pid {pid} does not fit a pid_t")
                }
                memory::MemoryError::GroupMemberPid(pid) => {
                    write!(f, "group member pid {pid} does not fit a pid_t")
                }
                memory::MemoryError::ResidentSizeSum => {
                    f.write_str("the resident-size sum overflowed")
                }
                memory::MemoryError::ResidentSizeRead(pid) => {
                    write!(f, "cannot read the resident size of process {pid}")
                }
                memory::MemoryError::StatRecord(pid) => {
                    write!(f, "cannot parse the stat record of process {pid}")
                }
                memory::MemoryError::ProcessRecords(pid, kind) => {
                    write!(f, "cannot read the records of process {pid}: {kind:?}")
                }
                memory::MemoryError::ProcessRecheck(pid, kind) => write!(
                    f,
                    "cannot re-check process {pid} after a read failure: {kind:?}"
                ),
                memory::MemoryError::ResidentSizeValue => f.write_str("cannot parse a VmRSS value"),
                memory::MemoryError::ResidentSizeUnit => {
                    f.write_str("a VmRSS line is not in kibibytes")
                }
                memory::MemoryError::ResidentSizeScale => f.write_str("a VmRSS value overflowed"),
                memory::MemoryError::MonitorUnavailable => {
                    f.write_str("no resident-memory monitor exists for this platform")
                }
            },
            RunnerMessage::Closure {
                position,
                count,
                fault,
            } => {
                write!(f, "closure entry {position} of {count} ")?;
                match fault {
                    ClosureFault::NotAbsolute => f.write_str("is not absolute"),
                    ClosureFault::NotNormal => f.write_str("is not in normal form"),
                    ClosureFault::Symlink => f.write_str("is a symlink, not the tree it names"),
                    ClosureFault::SharedRoot => {
                        f.write_str("is a shared root, not a measured dependency")
                    }
                    ClosureFault::Unresolved => f.write_str("cannot be resolved"),
                    ClosureFault::NotFileOrDirectory => {
                        f.write_str("is not a directory or a regular file")
                    }
                    ClosureFault::ResolvedSharedRoot => {
                        f.write_str("resolves to a shared root, not a measured dependency")
                    }
                }
            }
            RunnerMessage::ServiceNamespace => {
                f.write_str("the service namespace is not an anchored dotted prefix")
            }
            RunnerMessage::TempDirectoryVariable => {
                f.write_str("the temp-directory variable is not a bounded identifier")
            }
            RunnerMessage::PlatformBackendMissing => {
                f.write_str("no jail backend exists for this platform, refusing to run adapters")
            }
            RunnerMessage::WorkerHash(kind) => {
                write!(f, "the worker binary cannot be hashed: {kind:?}")
            }
            RunnerMessage::ProbeRequestEncode => f.write_str("cannot encode probe request"),
            RunnerMessage::ProbeReportedFailure => f.write_str("network probe reported a failure"),
            RunnerMessage::ProbeResponseParse => {
                f.write_str("network probe response did not parse")
            }
            RunnerMessage::ProbeAttemptMissing(name) => {
                write!(f, "network probe skipped the {} attempt", probe_name(name))
            }
            RunnerMessage::ProbeAttempt {
                name,
                outcome,
                error_kind,
            } => write!(
                f,
                "network probe attempt {} ended {} ({error_kind:?}), the jail is not proven",
                probe_name(name),
                probe_outcome(outcome)
            ),
            RunnerMessage::ProbeListener(kind) => {
                write!(f, "cannot stand up the Unix probe listener: {kind:?}")
            }
            RunnerMessage::TemplateBrace(value) => write!(
                f,
                "the {} value carries a brace and cannot be rendered",
                template_value(value)
            ),
            RunnerMessage::ClosureNotUtf8 { position, count } => {
                write!(f, "closure entry {position} of {count} is not UTF-8")
            }
            RunnerMessage::ClosureCannotBeQuoted { position, count } => write!(
                f,
                "closure entry {position} of {count} cannot be quoted in a jail profile"
            ),
            RunnerMessage::PathNotUtf8(class) => {
                write!(f, "{} is not UTF-8", path_class(class))
            }
            RunnerMessage::PathCannotBeQuoted(class) => write!(
                f,
                "{} cannot be quoted in a Seatbelt profile",
                path_class(class)
            ),
            RunnerMessage::ProviderNeedsWiring => {
                f.write_str("the provider jail class needs a wired provider, refusing the run")
            }
            RunnerMessage::SandboxHelperMissing => {
                f.write_str("the sandbox helper is missing, refusing to run adapters")
            }
            RunnerMessage::ProviderPlatformUnsupported => f.write_str(
                "no provider jail profile is measured for this platform, refusing the run",
            ),
            RunnerMessage::SyscallProbeAllowed => {
                f.write_str("the syscall filter let a socket creation through")
            }
            RunnerMessage::SyscallProbeFailed => {
                f.write_str("the syscall filter probe failed to run")
            }
        }
    }
}

fn probe_name(name: ProbeName) -> &'static str {
    match name {
        ProbeName::Ipv4Tcp => "ipv4_tcp",
        ProbeName::Ipv6Tcp => "ipv6_tcp",
        ProbeName::UnixSocket => "unix_socket",
        ProbeName::UdpSend => "udp_send",
    }
}

fn probe_outcome(outcome: ProbeOutcome) -> &'static str {
    match outcome {
        ProbeOutcome::Connected => "connected",
        ProbeOutcome::Denied => "denied",
        ProbeOutcome::Timeout => "timeout",
        ProbeOutcome::InvalidTarget => "invalid_target",
    }
}

fn path_class(class: PathClass) -> &'static str {
    match class {
        PathClass::Jail => "the jail path",
        PathClass::Worker => "the worker path",
        PathClass::ExecutableGrantDirectory => "an executable grant's directory",
        PathClass::ExecutableGrant => "an executable grant",
        PathClass::ReadGrant => "a read grant",
    }
}

fn template_value(value: TemplateValue) -> &'static str {
    match value {
        TemplateValue::Jail => "jail template",
        TemplateValue::Worker => "worker template",
        TemplateValue::Closures => "closures template",
        TemplateValue::Service => "service template",
        TemplateValue::Grants => "grants template",
    }
}

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
    let current = std::env::current_exe().map_err(|e| {
        RunnerError::new(
            "worker_not_found",
            RunnerMessage::CurrentExecutable(e.kind()),
        )
    })?;
    let Some(dir) = current.parent() else {
        return Err(RunnerError::new(
            "worker_not_found",
            RunnerMessage::CurrentExecutableHasNoDirectory,
        ));
    };
    let mut candidates = vec![dir.join(WORKER_BINARY)];
    if let Some(parent) = dir.parent() {
        candidates.push(parent.join(WORKER_BINARY));
    }
    for candidate in &candidates {
        if candidate.is_file() {
            return candidate.canonicalize().map_err(|e| {
                RunnerError::new(
                    "worker_not_found",
                    RunnerMessage::WorkerBinaryResolve(e.kind()),
                )
            });
        }
    }
    Err(RunnerError::new(
        "worker_not_found",
        RunnerMessage::WorkerBinaryMissing,
    ))
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
        let grants =
            self.exec_grants
                .iter()
                .enumerate()
                .map(|(index, grant)| {
                    (
                        GrantKind::Executable,
                        index + 1,
                        self.exec_grants.len(),
                        grant,
                    )
                })
                .chain(self.read_grants.iter().enumerate().map(|(index, grant)| {
                    (GrantKind::Read, index + 1, self.read_grants.len(), grant)
                }));
        for (kind, position, count, grant) in grants {
            match std::fs::symlink_metadata(grant) {
                Ok(metadata) if metadata.file_type().is_file() => {}
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    return Err(RunnerError::new(
                        "adapter_spawn_error",
                        RunnerMessage::Grant {
                            kind,
                            position,
                            count,
                            fault: GrantFault::Symlink,
                        },
                    ));
                }
                Ok(_) => {
                    return Err(RunnerError::new(
                        "adapter_spawn_error",
                        RunnerMessage::Grant {
                            kind,
                            position,
                            count,
                            fault: GrantFault::NotRegular,
                        },
                    ));
                }
                Err(e) => {
                    return Err(RunnerError::new(
                        "adapter_spawn_error",
                        RunnerMessage::Grant {
                            kind,
                            position,
                            count,
                            fault: GrantFault::Io(e.kind()),
                        },
                    ));
                }
            }
        }
        let jail_dir = tempfile::tempdir().map_err(|e| {
            RunnerError::new(
                "adapter_spawn_error",
                RunnerMessage::JailDirectoryCreate(e.kind()),
            )
        })?;
        let jail_path = jail_dir.path().canonicalize().map_err(|e| {
            RunnerError::new(
                "adapter_spawn_error",
                RunnerMessage::JailDirectoryCanonicalize(e.kind()),
            )
        })?;
        for (name, bytes) in files {
            if name.contains('/') || name.contains("..") {
                return Err(RunnerError::new(
                    "adapter_spawn_error",
                    RunnerMessage::InputNameNotBare,
                ));
            }
            std::fs::write(jail_path.join(name), bytes).map_err(|e| {
                RunnerError::new("adapter_spawn_error", RunnerMessage::StageInput(e.kind()))
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
        let mut child = command.spawn().map_err(|e| {
            RunnerError::new("adapter_spawn_error", RunnerMessage::SpawnWorker(e.kind()))
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
        return Err(RunnerError::new(
            "adapter_drain_timeout",
            RunnerMessage::DrainTimeout(
                u64::try_from(DRAIN_JOIN_BOUND.as_millis()).unwrap_or(u64::MAX),
            ),
        ));
    };

    if let Some(failure) = memory_failure {
        return Err(failure);
    }
    if timed_out {
        return Err(RunnerError::new(
            "adapter_timeout",
            RunnerMessage::WallTimeout(
                u64::try_from(limits.wall_timeout.as_millis()).unwrap_or(u64::MAX),
            ),
        ));
    }
    if let StdoutEnd::Oversized { declared } = stdout_end {
        return Err(RunnerError::new(
            "adapter_frame_oversized",
            RunnerMessage::ResponseFrameOversized {
                declared,
                ceiling: u64::from(limits.max_response_bytes),
            },
        ));
    }
    if stderr_total > limits.max_stderr_bytes {
        return Err(RunnerError::new(
            "adapter_output_overflow",
            RunnerMessage::StderrOverflow {
                written: stderr_total,
                ceiling: limits.max_stderr_bytes,
            },
        ));
    }
    if matches!(stdout_end, StdoutEnd::Trailing) {
        return Err(RunnerError::new(
            "adapter_output_overflow",
            RunnerMessage::TrailingStdout,
        ));
    }
    if !status.success() {
        let stderr_text = String::from_utf8_lossy(&stderr_kept);
        let stderr_text = scrub_stderr(&stderr_text, limits.max_stderr_bytes);
        if !stderr_text.is_empty() {
            eprintln!("adapter stderr: {stderr_text}");
        }
        #[cfg(unix)]
        let refusal = helper_refusal(status.code());
        #[cfg(not(unix))]
        let refusal = None;
        if let Some(error) = refusal {
            return Err(error);
        }
        return Err(RunnerError::new(
            "adapter_crash",
            RunnerMessage::Exit(worker_crash_detail(&status)),
        ));
    }
    let payload = match stdout_end {
        StdoutEnd::Frame(payload) => payload,
        StdoutEnd::Empty => {
            return Err(RunnerError::new(
                "adapter_protocol_error",
                RunnerMessage::EmptyResponse,
            ));
        }
        StdoutEnd::Truncated => {
            return Err(RunnerError::new(
                "adapter_protocol_error",
                RunnerMessage::TruncatedResponse,
            ));
        }
        StdoutEnd::ReadError(detail) => {
            return Err(RunnerError::new(
                "adapter_protocol_error",
                RunnerMessage::ReadResponse(detail),
            ));
        }
        StdoutEnd::Oversized { .. } | StdoutEnd::Trailing => unreachable!("handled above"),
    };
    let response: Response = serde_json::from_slice(&payload)
        .map_err(|_| RunnerError::new("adapter_protocol_error", RunnerMessage::ParseResponse))?;
    response.validate().map_err(|detail| {
        RunnerError::new(
            "adapter_protocol_error",
            RunnerMessage::ValidateResponse(detail),
        )
    })?;
    Ok(response)
}

/// Replaces each stderr line carrying a path separator before writing
/// it to the parent's stderr. Redacting the whole line also covers a
/// path with spaces. The returned text stays within the configured
/// stderr byte ceiling.
fn scrub_stderr(stderr_text: &str, max_bytes: u64) -> String {
    const PATH_PLACEHOLDER: &str = "[path]";

    let max_bytes = usize::try_from(max_bytes).unwrap_or(usize::MAX);
    let mut scrubbed = String::new();
    for line in stderr_text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        let line = if line.contains(['/', '\\']) {
            PATH_PLACEHOLDER
        } else {
            line
        };
        let separator = usize::from(!scrubbed.is_empty());
        if scrubbed
            .len()
            .saturating_add(separator)
            .saturating_add(line.len())
            > max_bytes
        {
            break;
        }
        if separator == 1 {
            scrubbed.push(' ');
        }
        scrubbed.push_str(line);
    }
    scrubbed
}

/// Interprets a helper exit code that refused before any adapter ran.
/// A failed jail setup is `sandbox_unavailable`. A process count the
/// host would not answer is `process-count-unavailable`, kept apart
/// because a spawn budget whose baseline is unknown is refused, not
/// guessed at. Any other exit code is the adapter's own.
#[cfg_attr(not(unix), allow(dead_code))]
fn helper_refusal(exit: Option<i32>) -> Option<RunnerError> {
    let exit = exit?;
    let (code, detail) = match exit {
        SANDBOX_SETUP_EXIT => (
            "sandbox_unavailable",
            ExitDetail::SandboxSetup(SANDBOX_SETUP_EXIT),
        ),
        PROCESS_COUNT_EXIT => (
            "process-count-unavailable",
            ExitDetail::ProcessCount(PROCESS_COUNT_EXIT),
        ),
        _ => return None,
    };
    Some(RunnerError::new(code, RunnerMessage::Exit(detail)))
}

/// Interprets one resident-memory measurement against the ceiling.
/// Over the ceiling is `worker-memory-exceeded`; a failed measurement
/// is `memory-monitor-failed`, because a guard that cannot see is a
/// guard that must fail closed.
fn memory_verdict(
    measurement: Result<u64, memory::MemoryError>,
    ceiling: u64,
) -> Option<RunnerError> {
    match measurement {
        Ok(total) if total > ceiling => Some(RunnerError::new(
            "worker-memory-exceeded",
            RunnerMessage::MemoryExceeded { total, ceiling },
        )),
        Ok(_) => None,
        Err(error) => Some(RunnerError::new(
            "memory-monitor-failed",
            RunnerMessage::Memory(error),
        )),
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

fn worker_crash_detail(status: &std::process::ExitStatus) -> ExitDetail {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return ExitDetail::WorkerSignal(signal);
        }
    }
    match status.code() {
        Some(code) => ExitDetail::WorkerCode(code),
        None => ExitDetail::WorkerNoStatus,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_helper_refusal_is_named_and_never_folded_into_a_crash() {
        // A failed jail setup keeps the code it always had.
        let setup = helper_refusal(Some(SANDBOX_SETUP_EXIT)).expect("a setup exit is a refusal");
        assert_eq!(setup.code, "sandbox_unavailable");
        assert_eq!(
            setup.message(),
            "the sandbox helper refused to engage the jail (exit 71)"
        );
        // An unmeasurable process count is named on its own, so the
        // manifest says why the spawn never happened.
        let count = helper_refusal(Some(PROCESS_COUNT_EXIT)).expect("a count exit is a refusal");
        assert_eq!(count.code, "process-count-unavailable");
        assert_eq!(
            count.message(),
            "the sandbox helper could not measure the user's process count and refused the spawn (exit 72)"
        );
        // Everything else is the adapter's own exit, not a refusal.
        assert!(helper_refusal(Some(1)).is_none());
        assert!(helper_refusal(None).is_none());
    }

    #[test]
    fn stderr_log_scrub_replaces_plain_and_spaced_paths() {
        let absolute = "/runtime/worker";
        let spaced = "/runtime/private deploy secret";
        let detail = format!(
            "fixed helper detail\nsandbox_setup_failed: open {absolute}\nsandbox_setup_failed: open {spaced}"
        );
        let scrubbed = scrub_stderr(&detail, 1024);
        assert_eq!(scrubbed, "fixed helper detail [path] [path]");
        assert!(!scrubbed.contains(absolute), "{scrubbed}");
        for component in spaced.split_whitespace() {
            assert!(!scrubbed.contains(component), "{scrubbed}");
        }
        assert!(scrubbed.len() <= 1024);
    }

    #[cfg(unix)]
    #[test]
    fn a_helper_failure_detail_never_enters_a_record_or_bundle() {
        use std::os::unix::process::CommandExt;

        let marker = format!("spaced_path_{}", std::process::id());
        let pieces = [
            format!("{marker}_root"),
            format!("{marker}_first"),
            format!("{marker}_second"),
            format!("{marker}_third"),
        ];
        let private_path = std::path::Path::new("/")
            .join(&pieces[0])
            .join(format!("{} {} {}", pieces[1], pieces[2], pieces[3]));
        let stderr = format!(
            "sandbox_setup_failed: cannot open {}",
            private_path.display()
        );
        let mut command = std::process::Command::new("/bin/sh");
        command
            .arg("-c")
            .arg("printf '%s\\n' \"$1\" >&2; exit 71")
            .arg("helper")
            .arg(stderr)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);
        let mut child = command.spawn().unwrap();
        let failure = drive(&mut child, &Limits::default()).expect_err("the helper refuses");
        assert_eq!(failure.code, "sandbox_unavailable");
        assert_eq!(
            failure.message(),
            "the sandbox helper refused to engage the jail (exit 71)"
        );

        let dir = tempfile::tempdir().unwrap();
        let manifest_dir = dir.path().join("manifest");
        std::fs::create_dir_all(&manifest_dir).unwrap();
        let record = crate::manifest::Record {
            schema: crate::manifest::ManifestSchema,
            source_path: "input.bin".to_string(),
            source_hash: crate::hash::hash_bytes(b"input"),
            source_size: 5,
            declared_format: None,
            detected_format: "unknown".to_string(),
            format_mismatch: false,
            status: crate::manifest::Status::Failed,
            text_path: None,
            text_hash: None,
            artifact_kind: None,
            converter_id: Some("adapter".to_string()),
            converter_version: Some("1".to_string()),
            tool_version: None,
            rules_version: crate::pipeline::Rules::builtin()
                .unwrap()
                .version()
                .to_string(),
            media: None,
            parent_source: None,
            dedup_of: None,
            warnings: Vec::new(),
            error: Some(failure.to_string()),
            duration_ms: Some(0),
        };
        assert_eq!(
            record.error.as_deref(),
            Some("sandbox_unavailable: the sandbox helper refused to engage the jail (exit 71)")
        );
        let serialized = serde_json::to_vec(&record).unwrap();
        let shard = manifest_dir.join("alpha.jsonl");
        let mut writer = crate::manifest::ManifestWriter::open(&shard).unwrap();
        writer.append(&record).unwrap();
        drop(writer);

        let bundle = dir.path().join("bundle");
        crate::bundle::bundle(&crate::bundle::BundleOptions {
            mirror_root: &dir.path().join("mirror"),
            manifest_dir: &manifest_dir,
            division: "alpha",
            output: &bundle,
        })
        .unwrap();

        fn assert_absent(bytes: &[u8], piece: &[u8]) {
            assert!(
                !bytes.windows(piece.len()).any(|window| window == piece),
                "a path component reached stored bytes"
            );
        }

        fn check_tree(dir: &std::path::Path, pieces: &[String]) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    check_tree(&path, pieces);
                } else {
                    let bytes = std::fs::read(path).unwrap();
                    for piece in pieces {
                        assert_absent(&bytes, piece.as_bytes());
                    }
                }
            }
        }

        for piece in &pieces {
            assert_absent(&serialized, piece.as_bytes());
        }
        check_tree(&bundle, &pieces);
    }

    #[cfg(unix)]
    #[test]
    fn a_worker_crash_message_carries_only_the_exit_classification() {
        use std::os::unix::process::CommandExt;

        let marker = format!("worker_path_{}", std::process::id());
        let stderr = format!("worker failed while reading /{marker}/with spaces");
        let mut command = std::process::Command::new("/bin/sh");
        command
            .arg("-c")
            .arg("printf '%s\\n' \"$1\" >&2; exit 9")
            .arg("worker")
            .arg(stderr)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);
        let mut child = command.spawn().unwrap();
        let failure = drive(&mut child, &Limits::default()).expect_err("the worker fails");
        assert_eq!(failure.code, "adapter_crash");
        assert_eq!(
            failure.message(),
            "worker exited with code 9, any response frame is discarded"
        );
        assert!(!failure.message().contains(&marker), "{failure}");
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
            error.message(),
            "the worker binary cannot be hashed: NotFound"
        );
        let message = error.message();
        for component in missing.components() {
            let std::path::Component::Normal(component) = component else {
                continue;
            };
            assert!(
                !message
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
        let failed = memory_verdict(
            Err(memory::MemoryError::ProcessTable(
                std::io::ErrorKind::PermissionDenied,
            )),
            200,
        )
        .expect("a failed measurement is a verdict");
        assert_eq!(failed.code, "memory-monitor-failed");
        assert_eq!(
            failed.message(),
            "cannot enumerate the process table: PermissionDenied"
        );
    }
}

/// Renders every message variant with boundary values.
#[cfg(test)]
mod runner_message_tests {
    use super::*;
    use std::io::ErrorKind;

    #[test]
    fn every_runner_message_variant_is_path_free() {
        const IO_KINDS: &[ErrorKind] = &[
            ErrorKind::NotFound,
            ErrorKind::PermissionDenied,
            ErrorKind::ConnectionRefused,
            ErrorKind::ConnectionReset,
            ErrorKind::HostUnreachable,
            ErrorKind::NetworkUnreachable,
            ErrorKind::ConnectionAborted,
            ErrorKind::NotConnected,
            ErrorKind::AddrInUse,
            ErrorKind::AddrNotAvailable,
            ErrorKind::NetworkDown,
            ErrorKind::BrokenPipe,
            ErrorKind::AlreadyExists,
            ErrorKind::WouldBlock,
            ErrorKind::NotADirectory,
            ErrorKind::IsADirectory,
            ErrorKind::DirectoryNotEmpty,
            ErrorKind::ReadOnlyFilesystem,
            ErrorKind::StaleNetworkFileHandle,
            ErrorKind::InvalidInput,
            ErrorKind::InvalidData,
            ErrorKind::TimedOut,
            ErrorKind::WriteZero,
            ErrorKind::StorageFull,
            ErrorKind::NotSeekable,
            ErrorKind::QuotaExceeded,
            ErrorKind::FileTooLarge,
            ErrorKind::ResourceBusy,
            ErrorKind::ExecutableFileBusy,
            ErrorKind::CrossesDevices,
            ErrorKind::TooManyLinks,
            ErrorKind::InvalidFilename,
            ErrorKind::ArgumentListTooLong,
            ErrorKind::Interrupted,
            ErrorKind::Unsupported,
            ErrorKind::UnexpectedEof,
            ErrorKind::OutOfMemory,
            ErrorKind::Other,
        ];
        const USIZES: &[usize] = &[0, 1, usize::MAX];
        const U64S: &[u64] = &[0, 1, u64::MAX];
        const U32S: &[u32] = &[0, 1, u32::MAX];
        const I32S: &[i32] = &[i32::MIN, -1, 0, 1, i32::MAX];
        const PROBE_NAMES: &[ProbeName] = &[
            ProbeName::Ipv4Tcp,
            ProbeName::Ipv6Tcp,
            ProbeName::UnixSocket,
            ProbeName::UdpSend,
        ];
        const PROBE_OUTCOMES: &[ProbeOutcome] = &[
            ProbeOutcome::Connected,
            ProbeOutcome::Denied,
            ProbeOutcome::Timeout,
            ProbeOutcome::InvalidTarget,
        ];

        let render = |message: RunnerMessage| {
            let text = message.to_string();
            assert!(!text.contains('/'), "separator in runner message: {text}");
            assert!(!text.contains('\\'), "separator in runner message: {text}");
            assert!(
                text.is_ascii(),
                "non-ASCII byte in runner message: {text:?}"
            );
        };

        for &kind in IO_KINDS {
            render(RunnerMessage::CurrentExecutable(kind));
            render(RunnerMessage::WorkerBinaryResolve(kind));
            render(RunnerMessage::JailDirectoryCreate(kind));
            render(RunnerMessage::JailDirectoryCanonicalize(kind));
            render(RunnerMessage::StageInput(kind));
            render(RunnerMessage::SpawnWorker(kind));
            render(RunnerMessage::ReadResponse(kind));
            render(RunnerMessage::WorkerHash(kind));
            render(RunnerMessage::ProbeListener(kind));
            for &grant in &[GrantKind::Executable, GrantKind::Read] {
                render(RunnerMessage::Grant {
                    kind: grant,
                    position: usize::MAX,
                    count: usize::MAX,
                    fault: GrantFault::Io(kind),
                });
            }
            for &name in PROBE_NAMES {
                for &outcome in PROBE_OUTCOMES {
                    render(RunnerMessage::ProbeAttempt {
                        name,
                        outcome,
                        error_kind: kind,
                    });
                }
            }
            for error in [
                memory::MemoryError::ProcessTable(kind),
                memory::MemoryError::ProcessGroup(kind),
                memory::MemoryError::ProcessGroupRecheck(kind),
                memory::MemoryError::ProcessRecords(u32::MAX, kind),
                memory::MemoryError::ProcessRecheck(u32::MAX, kind),
            ] {
                render(RunnerMessage::Memory(error));
            }
        }

        render(RunnerMessage::CurrentExecutableHasNoDirectory);
        render(RunnerMessage::WorkerBinaryMissing);
        render(RunnerMessage::InputNameNotBare);
        render(RunnerMessage::TrailingStdout);
        render(RunnerMessage::EmptyResponse);
        render(RunnerMessage::TruncatedResponse);
        render(RunnerMessage::ParseResponse);
        render(RunnerMessage::ProbeRequestEncode);
        render(RunnerMessage::ProbeReportedFailure);
        render(RunnerMessage::ProbeResponseParse);
        render(RunnerMessage::ServiceNamespace);
        render(RunnerMessage::TempDirectoryVariable);
        render(RunnerMessage::PlatformBackendMissing);
        render(RunnerMessage::ProviderNeedsWiring);
        render(RunnerMessage::SandboxHelperMissing);
        render(RunnerMessage::ProviderPlatformUnsupported);
        render(RunnerMessage::SyscallProbeAllowed);
        render(RunnerMessage::SyscallProbeFailed);

        for &value in USIZES {
            for &kind in &[GrantKind::Executable, GrantKind::Read] {
                for &fault in &[GrantFault::Symlink, GrantFault::NotRegular] {
                    render(RunnerMessage::Grant {
                        kind,
                        position: value,
                        count: value,
                        fault,
                    });
                }
            }
            for &fault in &[
                ClosureFault::NotAbsolute,
                ClosureFault::NotNormal,
                ClosureFault::Symlink,
                ClosureFault::SharedRoot,
                ClosureFault::Unresolved,
                ClosureFault::NotFileOrDirectory,
                ClosureFault::ResolvedSharedRoot,
            ] {
                render(RunnerMessage::Closure {
                    position: value,
                    count: value,
                    fault,
                });
            }
            render(RunnerMessage::ClosureNotUtf8 {
                position: value,
                count: value,
            });
            render(RunnerMessage::ClosureCannotBeQuoted {
                position: value,
                count: value,
            });
        }

        for &value in U64S {
            render(RunnerMessage::DrainTimeout(value));
            render(RunnerMessage::WallTimeout(value));
            render(RunnerMessage::ResponseFrameOversized {
                declared: value,
                ceiling: value,
            });
            render(RunnerMessage::StderrOverflow {
                written: value,
                ceiling: value,
            });
            render(RunnerMessage::MemoryExceeded {
                total: value,
                ceiling: value,
            });
        }

        for &value in U32S {
            for error in [
                memory::MemoryError::GroupLeaderPid(value),
                memory::MemoryError::GroupMemberPid(value),
                memory::MemoryError::ResidentSizeRead(value),
                memory::MemoryError::StatRecord(value),
            ] {
                render(RunnerMessage::Memory(error));
            }
        }
        for error in [
            memory::MemoryError::ResidentSizeSum,
            memory::MemoryError::ResidentSizeValue,
            memory::MemoryError::ResidentSizeUnit,
            memory::MemoryError::ResidentSizeScale,
            memory::MemoryError::MonitorUnavailable,
        ] {
            render(RunnerMessage::Memory(error));
        }

        for &value in I32S {
            render(RunnerMessage::Exit(ExitDetail::SandboxSetup(value)));
            render(RunnerMessage::Exit(ExitDetail::ProcessCount(value)));
            render(RunnerMessage::Exit(ExitDetail::WorkerCode(value)));
            render(RunnerMessage::Exit(ExitDetail::WorkerSignal(value)));
        }
        render(RunnerMessage::Exit(ExitDetail::WorkerNoStatus));

        for detail in [
            ResponseValidationError::BothBodies,
            ResponseValidationError::NoBody,
        ] {
            render(RunnerMessage::ValidateResponse(detail));
        }
        for &name in PROBE_NAMES {
            render(RunnerMessage::ProbeAttemptMissing(name));
        }
        for value in [
            TemplateValue::Jail,
            TemplateValue::Worker,
            TemplateValue::Closures,
            TemplateValue::Service,
            TemplateValue::Grants,
        ] {
            render(RunnerMessage::TemplateBrace(value));
        }
        for class in [
            PathClass::Jail,
            PathClass::Worker,
            PathClass::ExecutableGrantDirectory,
            PathClass::ExecutableGrant,
            PathClass::ReadGrant,
        ] {
            render(RunnerMessage::PathNotUtf8(class));
            render(RunnerMessage::PathCannotBeQuoted(class));
        }
    }
}
