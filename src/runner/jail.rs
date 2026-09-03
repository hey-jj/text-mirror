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

/// Which measured jail profile a worker mode runs under.
///
/// The class is the authorization, not a convenience: the accelerator
/// allowances were measured for one pinned engine driven by one
/// worker mode, so only that mode may ask for them. A backend keys
/// those allowances on this class alone and never on the presence of
/// an executable grant, so a future granted worker inherits nothing
/// unmeasured. The literal grant lines stay keyed on the grants
/// themselves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeProfile {
    /// The base profile every worker mode runs under.
    Plain,
    /// The base profile plus the device allowances measured for the
    /// pinned accelerator engine. Only the audio worker mode.
    Accelerator,
    /// The provider jail: the widened profile measured for the pinned
    /// external rasterizer, which spawns helper processes, reads a
    /// larger runtime closure, and registers its own services. Only the
    /// svg raster worker mode. It is a class of its own and shares
    /// nothing with the accelerator class above: neither inherits the
    /// other's allowances, and a platform with no measured provider
    /// profile refuses this class outright.
    Provider,
}

impl RuntimeProfile {
    /// The stable name this class contributes to the policy digest.
    pub(super) fn label(self) -> &'static str {
        match self {
            RuntimeProfile::Plain => "plain",
            RuntimeProfile::Accelerator => "accelerator",
            RuntimeProfile::Provider => "provider",
        }
    }
}

/// The provider jail's measured parameters: the executable closures the
/// pinned components load from, the service namespace their runtime
/// registers under, and the temp-directory variable it reads.
///
/// All three are deployment data, so none is a literal in this crate.
/// The fields are private and the only constructor validates: the
/// closures must not be shared roots, the namespace must fit the one
/// closed grammar the profile accepts, and the variable must be a
/// bounded identifier. A caller inside or outside the crate cannot
/// hand the renderer a value the configuration layer would have
/// refused, so the render boundary and the configuration boundary
/// enforce the same shapes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProviderJail {
    closures: Vec<std::path::PathBuf>,
    service_prefix: Option<String>,
    temp_env: Option<String>,
}

impl ProviderJail {
    /// Validates and builds the parameters. Every refusal is
    /// `sandbox_unavailable`, because a jail that cannot be rendered
    /// as measured is a jail that must not run.
    pub fn new(
        closures: Vec<std::path::PathBuf>,
        service_prefix: Option<String>,
        temp_env: Option<String>,
    ) -> Result<ProviderJail, RunnerError> {
        let refuse = |message: String| RunnerError {
            code: "sandbox_unavailable",
            message,
        };
        // Every entry is rendered as a grant on the tree it really
        // names: resolved here, refused when it cannot be, so an alias
        // through `..` or a link never reaches the profile and the
        // shared-root refusal judges the real path.
        let mut real_closures = Vec::with_capacity(closures.len());
        for closure in &closures {
            if !closure.is_absolute() {
                return Err(refuse(format!(
                    "closure entry {} is not absolute",
                    closure.display()
                )));
            }
            if !crate::convert::provider::is_normal_form(closure) {
                return Err(refuse(format!(
                    "closure entry {} is not in normal form",
                    closure.display()
                )));
            }
            if crate::convert::provider::is_symlink_entry(closure) {
                return Err(refuse(format!(
                    "closure entry {} is a symlink, not the tree it names",
                    closure.display()
                )));
            }
            let Some(real) = crate::convert::provider::canonical(closure) else {
                return Err(refuse(format!(
                    "closure entry {} cannot be resolved",
                    closure.display()
                )));
            };
            if crate::convert::provider::is_shared_root(closure)
                || crate::convert::provider::is_shared_root(&real)
            {
                return Err(refuse(format!(
                    "closure entry {} is a shared root, not a measured dependency",
                    closure.display()
                )));
            }
            real_closures.push(real);
        }
        if let Some(prefix) = &service_prefix
            && !crate::convert::provider::is_service_namespace(prefix)
        {
            return Err(refuse(
                "the service namespace is not an anchored dotted prefix".to_string(),
            ));
        }
        if let Some(name) = &temp_env
            && !crate::convert::provider::is_env_name(name)
        {
            return Err(refuse(
                "the temp-directory variable is not a bounded identifier".to_string(),
            ));
        }
        Ok(ProviderJail {
            closures: real_closures,
            service_prefix,
            temp_env,
        })
    }

    /// The enumerated closure entries, each granted on its own.
    pub fn closures(&self) -> &[std::path::PathBuf] {
        &self.closures
    }

    /// The service namespace, when the runtime registers any.
    pub fn service_prefix(&self) -> Option<&str> {
        self.service_prefix.as_deref()
    }

    /// The additional temp-directory variable, when the runtime reads
    /// one. Not rendered into the profile, but part of this jail's
    /// identity all the same.
    pub fn temp_env(&self) -> Option<&str> {
        self.temp_env.as_deref()
    }
}

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
    /// Literal files the jail additionally grants read and execute
    /// on: the pinned engine and probe binaries. Never a directory.
    pub exec_grants: &'a [std::path::PathBuf],
    /// Literal files the jail additionally grants read on: the pinned
    /// weights and other read-only runtime files. Never a directory.
    pub read_grants: &'a [std::path::PathBuf],
    /// The measured jail profile this worker mode is authorized for.
    pub runtime_profile: RuntimeProfile,
    /// The provider jail's measured parameters, present only for the
    /// provider class. The class is the authorization and these are the
    /// necessity: without them the provider profile renders nothing
    /// wider than the base, so no other worker can reach the widened
    /// allowances by naming the class alone.
    pub provider: Option<&'a ProviderJail>,
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
/// the worker path, the worker binary hash, the literal grant paths,
/// and the runtime profile class, so a grant or class change
/// invalidates every cached probe pass and a probe result for one
/// class never satisfies the other.
pub(super) fn policy_digest(
    backend: &dyn JailBackend,
    worker: &Path,
    exec_grants: &[std::path::PathBuf],
    read_grants: &[std::path::PathBuf],
    runtime_profile: RuntimeProfile,
    provider: Option<&ProviderJail>,
) -> Result<String, RunnerError> {
    let worker_hash = hash::hash_file(worker).map_err(|e| RunnerError {
        code: "worker_not_found",
        message: format!("cannot hash worker binary {}: {e}", worker.display()),
    })?;
    let grant_lines = |label: &str, grants: &[std::path::PathBuf]| {
        grants
            .iter()
            .map(|path| format!("{label}={}", path.display()))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let provider_material = match provider {
        Some(provider) => format!(
            "closures={}\nservice-prefix={}\ntemp-env={}",
            provider
                .closures
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>()
                .join(","),
            provider.service_prefix().unwrap_or_default(),
            provider.temp_env().unwrap_or_default()
        ),
        None => String::new(),
    };
    let material = format!(
        "{}\n{}\n{}\n{}\n{}\n{}\nruntime-profile={}\n{}",
        backend.name(),
        backend.policy_material(),
        worker.display(),
        worker_hash,
        grant_lines("exec", exec_grants),
        grant_lines("read", read_grants),
        runtime_profile.label(),
        provider_material,
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
