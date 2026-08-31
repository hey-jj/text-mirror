//! The sandbox helper: the single-threaded first stage of every
//! jailed spawn.
//!
//! The parent never does sandbox work in a `pre_exec` closure. It
//! spawns the worker binary in this mode, a fresh single-threaded
//! process, which applies the platform jail and resource limits and
//! then execs the requested adapter mode of the same binary. Any
//! setup failure writes one diagnostic line to stderr and exits with
//! [`super::SANDBOX_SETUP_EXIT`], which the parent reports as
//! `sandbox_unavailable`. The helper never runs adapter code before
//! the jail is fully engaged.
//!
//! Order on Linux: namespaces and ID maps, resource limits,
//! descriptor hygiene, Landlock, seccomp, exec. Descriptor hygiene
//! runs before Landlock because it enumerates `/proc/self/fd`, which
//! the filesystem policy then denies. On macOS the Seatbelt profile
//! is already engaged by `sandbox-exec` before this mode starts, so
//! only resource limits and descriptor hygiene remain.

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

use super::{SANDBOX_SETUP_EXIT, WORKER_BINARY};

/// Parsed helper arguments.
pub struct HelperConfig {
    /// The jail directory, already the working directory.
    pub jail: PathBuf,
    /// Absolute path of the worker binary to exec.
    pub worker: PathBuf,
    /// The adapter mode to exec into.
    pub adapter: String,
    /// RLIMIT_AS in bytes, or `None` when the profile leaves the
    /// limit unset.
    pub address_space_bytes: Option<u64>,
    /// RLIMIT_CPU in seconds.
    pub cpu_seconds: u64,
    /// RLIMIT_FSIZE in bytes.
    pub file_size_bytes: u64,
    /// RLIMIT_NPROC, the process and thread cap.
    pub max_processes: u64,
    /// Whether the syscall filter engages. Linux only.
    pub seccomp: bool,
    /// Literal files granted read and execute beyond the worker: the
    /// pinned engine and probe binaries.
    pub exec_grants: Vec<PathBuf>,
    /// Literal files granted read only: the pinned weights and other
    /// read-only runtime files.
    pub read_grants: Vec<PathBuf>,
}

/// Parses the `sandbox-helper` argument list.
pub fn parse_args(args: &[String]) -> Result<HelperConfig, String> {
    let mut jail = None;
    let mut worker = None;
    let mut adapter = None;
    let mut address_space_bytes: Option<Option<u64>> = None;
    let mut cpu_seconds = None;
    let mut file_size_bytes = None;
    let mut max_processes = None;
    let mut seccomp = None;
    let mut exec_grants = Vec::new();
    let mut read_grants = Vec::new();
    let mut iter = args.iter();
    while let Some(flag) = iter.next() {
        let value = iter
            .next()
            .ok_or_else(|| format!("flag {flag} is missing its value"))?;
        match flag.as_str() {
            "--jail" => jail = Some(PathBuf::from(value)),
            "--worker" => worker = Some(PathBuf::from(value)),
            "--adapter" => adapter = Some(value.clone()),
            "--rlimit-as" => {
                address_space_bytes = Some(if value == "none" {
                    None
                } else {
                    Some(parse_number(flag, value)?)
                })
            }
            "--rlimit-cpu" => cpu_seconds = Some(parse_number(flag, value)?),
            "--rlimit-fsize" => file_size_bytes = Some(parse_number(flag, value)?),
            "--rlimit-nproc" => max_processes = Some(parse_number(flag, value)?),
            "--seccomp" => {
                seccomp = Some(match value.as_str() {
                    "kill" => true,
                    "off" => false,
                    other => return Err(format!("unknown seccomp mode {other:?}")),
                })
            }
            "--grant-exec" => exec_grants.push(PathBuf::from(value)),
            "--grant-read" => read_grants.push(PathBuf::from(value)),
            other => return Err(format!("unknown flag {other:?}")),
        }
    }
    Ok(HelperConfig {
        jail: jail.ok_or("missing --jail")?,
        worker: worker.ok_or("missing --worker")?,
        adapter: adapter.ok_or("missing --adapter")?,
        address_space_bytes: address_space_bytes.ok_or("missing --rlimit-as")?,
        cpu_seconds: cpu_seconds.ok_or("missing --rlimit-cpu")?,
        file_size_bytes: file_size_bytes.ok_or("missing --rlimit-fsize")?,
        max_processes: max_processes.ok_or("missing --rlimit-nproc")?,
        seccomp: seccomp.ok_or("missing --seccomp")?,
        exec_grants,
        read_grants,
    })
}

fn parse_number(flag: &str, value: &str) -> Result<u64, String> {
    value
        .parse()
        .map_err(|e| format!("flag {flag} value {value:?} is not a number: {e}"))
}

/// Runs the helper: engage the jail, then exec the adapter mode.
/// Never returns. Every failure refuses the run.
pub fn helper_main(args: &[String]) -> ! {
    let config = match parse_args(args) {
        Ok(config) => config,
        Err(detail) => die(&detail),
    };
    if let Err(detail) = engage(&config) {
        die(&detail);
    }
    // exec only returns on failure.
    let error = exec_adapter(&config);
    die(&error)
}

fn die(detail: &str) -> ! {
    eprintln!("sandbox_setup_failed: {detail}");
    std::process::exit(SANDBOX_SETUP_EXIT)
}

#[cfg(target_os = "linux")]
fn engage(config: &HelperConfig) -> Result<(), String> {
    super::linux::unshare_namespaces()?;
    apply_rlimits(config)?;
    close_extra_fds()?;
    super::linux::apply_landlock(
        &config.jail,
        &config.worker,
        &config.exec_grants,
        &config.read_grants,
    )?;
    if config.seccomp {
        super::linux::apply_seccomp()?;
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn engage(config: &HelperConfig) -> Result<(), String> {
    // The Seatbelt profile is already applied by sandbox-exec.
    apply_rlimits(config)?;
    close_extra_fds()?;
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn engage(_config: &HelperConfig) -> Result<(), String> {
    Err("no jail backend exists for this platform".to_string())
}

/// Sets the address-space, CPU, file-size, process-count, and core
/// limits. Any failed call refuses the run.
///
/// `RLIMIT_NPROC` caps the process and thread count of the mapped
/// real user id, so a compromised adapter cannot fork-bomb the host.
/// `RLIMIT_AS` is applied on Linux only, and only when the profile
/// carries a value: a profile whose mapped accelerator runtime
/// reserves a virtual range above any sane cap leaves it unset and
/// relies on the parent-side resident-memory guard. On macOS the dyld
/// shared cache reserves a large and version-dependent virtual range,
/// so a hard address-space cap turns the next allocation into an
/// abort. The CPU, file-size, process-count, and core limits hold on
/// every platform, and the macOS backend is development containment
/// where the wall-clock and output caps are the bounds that hold.
fn apply_rlimits(config: &HelperConfig) -> Result<(), String> {
    use rlimit::{Resource, setrlimit};
    let apply = |resource: Resource, name: &str, value: u64| {
        setrlimit(resource, value, value).map_err(|e| format!("setrlimit {name} failed: {e}"))
    };
    #[cfg(target_os = "linux")]
    if let Some(bytes) = config.address_space_bytes {
        apply(Resource::AS, "RLIMIT_AS", bytes)?;
    }
    apply(Resource::CPU, "RLIMIT_CPU", config.cpu_seconds)?;
    apply(Resource::FSIZE, "RLIMIT_FSIZE", config.file_size_bytes)?;
    apply(
        Resource::NPROC,
        "RLIMIT_NPROC",
        nproc_limit(config.max_processes)?,
    )?;
    apply(Resource::CORE, "RLIMIT_CORE", 0)?;
    Ok(())
}

/// The applied process-count limit: the configured value as headroom
/// above the real user id's pre-existing process count, clamped to
/// the hard limit.
///
/// `RLIMIT_NPROC` counts every process of the real user id, not this
/// invocation's descendants. Measured on a desktop-class host: the
/// user already ran several hundred processes, so an absolute cap of
/// 64 made every fork fail with EAGAIN before the adapter could spawn
/// its engine child. The configured number's intent is the
/// invocation's spawn budget, so it is applied on top of the load
/// that already exists: this invocation may add at most that many
/// processes, and the fork-bomb bound is preserved. A failed count
/// falls back to the absolute value, which only ever narrows.
fn nproc_limit(configured: u64) -> Result<u64, String> {
    use rlimit::{Resource, getrlimit};
    let (_, hard) =
        getrlimit(Resource::NPROC).map_err(|e| format!("getrlimit RLIMIT_NPROC failed: {e}"))?;
    let base = current_uid_process_count().unwrap_or(0);
    Ok(base.saturating_add(configured).min(hard))
}

/// The real user id's current process count, from the platform's
/// process listing.
#[cfg(target_os = "macos")]
fn current_uid_process_count() -> Option<u64> {
    use libproc::processes::{ProcFilter, pids_by_type};
    let uid = nix::unistd::getuid().as_raw();
    let pids = pids_by_type(ProcFilter::ByUID { uid }).ok()?;
    Some(pids.len() as u64)
}

/// The real user id's current process count, from the `/proc` view.
#[cfg(target_os = "linux")]
fn current_uid_process_count() -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    let uid = u32::from(nix::unistd::getuid().as_raw());
    let entries = std::fs::read_dir("/proc").ok()?;
    let mut count: u64 = 0;
    for entry in entries.flatten() {
        let name = entry.file_name();
        if name.to_str().is_none_or(|n| n.parse::<u32>().is_err()) {
            continue;
        }
        if entry.metadata().is_ok_and(|m| m.uid() == uid) {
            count += 1;
        }
    }
    Some(count)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn current_uid_process_count() -> Option<u64> {
    None
}

/// Closes every descriptor above stderr, with no fixed ceiling. The
/// open descriptors are enumerated through the kernel's descriptor
/// directory, `/proc/self/fd` on Linux and `/dev/fd` on macOS, so a
/// descriptor above any fixed range is still found and closed. The
/// parent opens everything close-on-exec, so this is belt and
/// suspenders against descriptors injected by wrappers or held by a
/// host embedder.
fn close_extra_fds() -> Result<(), String> {
    #[cfg(target_os = "linux")]
    const FD_DIR: &str = "/proc/self/fd";
    #[cfg(not(target_os = "linux"))]
    const FD_DIR: &str = "/dev/fd";
    let entries =
        std::fs::read_dir(FD_DIR).map_err(|e| format!("cannot enumerate descriptors: {e}"))?;
    let mut fds = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| format!("cannot enumerate descriptors: {e}"))?;
        if let Some(fd) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<i32>().ok())
            && fd > 2
        {
            fds.push(fd);
        }
    }
    for fd in fds {
        // EBADF covers the enumeration descriptor itself.
        let _ = nix::unistd::close(fd);
    }
    Ok(())
}

/// Execs the adapter mode of the worker binary. Returns only the
/// failure detail.
fn exec_adapter(config: &HelperConfig) -> String {
    let path = match CString::new(config.worker.as_os_str().as_bytes()) {
        Ok(path) => path,
        Err(_) => return "worker path contains a NUL byte".to_string(),
    };
    let argv0 = CString::new(WORKER_BINARY).expect("static name has no NUL");
    let mode = match CString::new(config.adapter.as_str()) {
        Ok(mode) => mode,
        Err(_) => return "adapter mode contains a NUL byte".to_string(),
    };
    match nix::unistd::execv(&path, &[argv0.as_c_str(), mode.as_c_str()]) {
        Ok(infallible) => match infallible {},
        Err(e) => format!("exec of the adapter mode failed: {e}"),
    }
}
