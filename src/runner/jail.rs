//! The jail contract every subprocess adapter runs under.
//!
//! One trait presents the contract and platform backends implement
//! it. No jail means no run: the runner only obtains child commands
//! from a backend, every backend routes through the sandbox helper
//! mode, and a platform without a backend refuses the adapter run
//! with a machine reason. An unjailed run is not a degraded mode, it
//! is impossible by construction.
//!
//! Before a backend accepts adapter work, a capability probe must
//! prove the jail from the inside: an outbound IPv4 connection, an
//! outbound IPv6 connection, a Unix socket connection to a listener
//! the parent holds outside the jail, and a UDP send must each
//! return an error before the probe deadline. A success or a hang
//! proves nothing and fails the probe. Only a passed probe is cached, keyed by the policy digest,
//! and the cache lives in this process, which cannot outlive the
//! boot, so a cached pass never crosses a boot or a policy change.

use std::collections::HashSet;
use std::path::Path;
use std::process::Command;
use std::sync::{Mutex, OnceLock};

use super::protocol::bodies::{ProbeNetRequest, ProbeReport};
use super::{Limits, Runner, RunnerError};
use crate::hash;

/// What one adapter invocation needs from a backend.
pub struct SpawnSpec<'a> {
    /// Absolute path of the worker binary.
    pub worker: &'a Path,
    /// Absolute path of the per-run jail directory.
    pub jail: &'a Path,
    /// The worker mode to execute after sandbox setup.
    pub mode: &'a str,
    /// Resource limits the helper applies before exec.
    pub limits: &'a Limits,
    /// Whether the syscall filter layer engages. Always true for
    /// adapter work. The network probe disables it once, on Linux, to
    /// observe namespace denial directly, and a second probe stage
    /// proves the filter kills socket creation.
    pub seccomp: bool,
}

/// A platform jail backend.
///
/// Implementations must never return a command that runs the worker
/// outside the platform jail.
pub trait JailBackend: Send + Sync {
    /// Stable backend name for probe failures and diagnostics.
    fn name(&self) -> &'static str;

    /// Builds the jailed command for one invocation. The runner still
    /// applies the portable contract on top: cleared environment,
    /// working directory inside the jail, piped stdio, and a fresh
    /// process group.
    fn command(&self, spec: &SpawnSpec<'_>) -> Result<Command, RunnerError>;

    /// A stable description of the enforced policy. It feeds the
    /// probe cache digest, so any policy change invalidates every
    /// cached probe pass.
    fn policy_material(&self) -> String;

    /// Proves the jail from the inside before any adapter work.
    fn probe(&self, runner: &Runner) -> Result<(), RunnerError>;
}

/// The backend for the current platform, or a refusal on a platform
/// without one.
pub fn platform_backend() -> Result<Box<dyn JailBackend>, RunnerError> {
    #[cfg(target_os = "linux")]
    {
        Ok(Box::new(super::linux::NamespaceJail))
    }
    #[cfg(target_os = "macos")]
    {
        Ok(Box::new(super::macos::SeatbeltJail))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Err(RunnerError {
            code: "sandbox_unavailable",
            message: "no jail backend exists for this platform, refusing to run adapters"
                .to_string(),
        })
    }
}

fn probe_cache() -> &'static Mutex<HashSet<String>> {
    static CACHE: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashSet::new()))
}

/// The digest a cached probe pass is keyed by: the backend policy,
/// the worker path, and the worker binary hash.
pub(super) fn policy_digest(
    backend: &dyn JailBackend,
    worker: &Path,
) -> Result<String, RunnerError> {
    let worker_hash = hash::hash_file(worker).map_err(|e| RunnerError {
        code: "worker_not_found",
        message: format!("cannot hash worker binary {}: {e}", worker.display()),
    })?;
    let material = format!(
        "{}\n{}\n{}\n{}",
        backend.name(),
        backend.policy_material(),
        worker.display(),
        worker_hash
    );
    Ok(hash::hash_bytes(material.as_bytes()))
}

/// Runs the capability probe unless this policy digest already
/// passed in this process. Only success is cached.
pub(super) fn ensure_probed(runner: &Runner, digest: &str) -> Result<(), RunnerError> {
    if probe_cache()
        .lock()
        .is_ok_and(|cache| cache.contains(digest))
    {
        return Ok(());
    }
    runner.backend().probe(runner)?;
    if let Ok(mut cache) = probe_cache().lock() {
        cache.insert(digest.to_string());
    }
    Ok(())
}

/// Whether a digest is already cached, for tests.
pub fn probe_cached(digest: &str) -> bool {
    probe_cache()
        .lock()
        .is_ok_and(|cache| cache.contains(digest))
}

/// Runs the `probe-net` worker mode inside the jail and requires
/// every egress attempt to return an error before the probe deadline.
///
/// The parent holds a live Unix socket listener outside the jail for
/// the duration. The Unix attempt would succeed from an unjailed
/// process, so when it fails the jail provably blocked it.
pub(super) fn probe_net(runner: &Runner, seccomp: bool) -> Result<(), RunnerError> {
    let listener = UnixProbeListener::bind()?;
    // Loopback TCP listeners the parent holds for the probe's
    // duration. From an unjailed process both connects would succeed,
    // so an immediate failure is evidence of the jail, and a timeout
    // is scored as its own outcome and fails the probe.
    let tcp4 = std::net::TcpListener::bind("127.0.0.1:0").map_err(probe_bind_error)?;
    let tcp6 = std::net::TcpListener::bind("[::1]:0").map_err(probe_bind_error)?;
    let tcp4_target = tcp4.local_addr().map_err(probe_bind_error)?.to_string();
    let tcp6_target = tcp6.local_addr().map_err(probe_bind_error)?.to_string();
    let payload = serde_json::to_value(ProbeNetRequest {
        unix_target: listener.target.clone(),
        tcp4_target,
        tcp6_target,
    })
    .map_err(|e| RunnerError {
        code: "sandbox_probe_failed",
        message: format!("cannot encode probe request: {e}"),
    })?;
    let response = runner.run_unprobed("probe-net", payload, &[], seccomp)?;
    let Some(ok) = response.ok else {
        let detail = response
            .error
            .map(|e| format!("{}: {}", e.code, e.message))
            .unwrap_or_else(|| "empty response".to_string());
        return Err(RunnerError {
            code: "sandbox_probe_failed",
            message: format!("network probe reported a failure: {detail}"),
        });
    };
    let report: ProbeReport = serde_json::from_value(ok).map_err(|e| RunnerError {
        code: "sandbox_probe_failed",
        message: format!("network probe response did not parse: {e}"),
    })?;
    let expected = ["ipv4_tcp", "ipv6_tcp", "unix_socket", "udp_send"];
    for name in expected {
        let Some(attempt) = report.attempts.iter().find(|a| a.name == name) else {
            return Err(RunnerError {
                code: "sandbox_probe_failed",
                message: format!("network probe skipped the {name} attempt"),
            });
        };
        if attempt.outcome != "denied" {
            return Err(RunnerError {
                code: "sandbox_probe_failed",
                message: format!(
                    "network probe attempt {name} ended {} ({}), the jail is not proven",
                    attempt.outcome, attempt.detail
                ),
            });
        }
    }
    Ok(())
}

/// A Unix socket listener the parent holds open outside the jail
/// while the probe runs.
struct UnixProbeListener {
    target: String,
    // Held for their drop side effects: the listener keeps the socket
    // connectable and the directory removes a path-based socket file.
    _listener: std::os::unix::net::UnixListener,
    _dir: Option<tempfile::TempDir>,
}

impl UnixProbeListener {
    #[cfg(target_os = "linux")]
    fn bind() -> Result<UnixProbeListener, RunnerError> {
        use std::os::linux::net::SocketAddrExt;
        use std::sync::atomic::{AtomicU64, Ordering};
        // The abstract name must be unique across concurrent probes in
        // one process, so a monotonic counter joins the process id.
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let name = format!(
            "text-mirror-probe-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        let address = std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes())
            .map_err(probe_bind_error)?;
        let listener =
            std::os::unix::net::UnixListener::bind_addr(&address).map_err(probe_bind_error)?;
        Ok(UnixProbeListener {
            target: name,
            _listener: listener,
            _dir: None,
        })
    }

    #[cfg(not(target_os = "linux"))]
    fn bind() -> Result<UnixProbeListener, RunnerError> {
        let dir = tempfile::tempdir().map_err(probe_bind_error)?;
        let path = dir.path().join("probe.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).map_err(probe_bind_error)?;
        Ok(UnixProbeListener {
            target: path.display().to_string(),
            _listener: listener,
            _dir: Some(dir),
        })
    }
}

fn probe_bind_error(e: std::io::Error) -> RunnerError {
    RunnerError {
        code: "sandbox_probe_failed",
        message: format!("cannot stand up the Unix probe listener: {e}"),
    }
}
