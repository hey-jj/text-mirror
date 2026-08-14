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
    /// RLIMIT_AS in bytes.
    pub address_space_bytes: u64,
    /// RLIMIT_CPU in seconds.
    pub cpu_seconds: u64,
    /// RLIMIT_FSIZE in bytes.
    pub file_size_bytes: u64,
    /// RLIMIT_NPROC, the process and thread cap.
    pub max_processes: u64,
    /// Whether the syscall filter engages. Linux only.
    pub seccomp: bool,
}

/// Parses the `sandbox-helper` argument list.
pub fn parse_args(args: &[String]) -> Result<HelperConfig, String> {
    let mut jail = None;
    let mut worker = None;
    let mut adapter = None;
    let mut address_space_bytes = None;
    let mut cpu_seconds = None;
    let mut file_size_bytes = None;
    let mut max_processes = None;
    let mut seccomp = None;
    let mut iter = args.iter();
    while let Some(flag) = iter.next() {
        let value = iter
            .next()
            .ok_or_else(|| format!("flag {flag} is missing its value"))?;
        match flag.as_str() {
            "--jail" => jail = Some(PathBuf::from(value)),
            "--worker" => worker = Some(PathBuf::from(value)),
            "--adapter" => adapter = Some(value.clone()),
            "--rlimit-as" => address_space_bytes = Some(parse_number(flag, value)?),
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
    super::linux::apply_landlock(&config.jail, &config.worker)?;
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
/// `RLIMIT_AS` is applied on Linux only. On macOS the dyld shared
/// cache reserves a large and version-dependent virtual range, so a
/// hard address-space cap aborts the process on its next allocation
/// rather than bounding it. The CPU, file-size, process-count, and
/// core limits hold on every platform, and the macOS backend is
/// development containment where the wall-clock and output caps are
/// the load-bearing bounds.
fn apply_rlimits(config: &HelperConfig) -> Result<(), String> {
    use rlimit::{Resource, setrlimit};
    let apply = |resource: Resource, name: &str, value: u64| {
        setrlimit(resource, value, value).map_err(|e| format!("setrlimit {name} failed: {e}"))
    };
    #[cfg(target_os = "linux")]
    apply(Resource::AS, "RLIMIT_AS", config.address_space_bytes)?;
    apply(Resource::CPU, "RLIMIT_CPU", config.cpu_seconds)?;
    apply(Resource::FSIZE, "RLIMIT_FSIZE", config.file_size_bytes)?;
    apply(Resource::NPROC, "RLIMIT_NPROC", config.max_processes)?;
    apply(Resource::CORE, "RLIMIT_CORE", 0)?;
    Ok(())
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
