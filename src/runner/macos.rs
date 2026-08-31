//! The macOS jail backend over `sandbox-exec` with a deny-first
//! Seatbelt profile.
//!
//! This backend is development containment. Apple has deprecated
//! `sandbox-exec` since 2017 and the Seatbelt profile language
//! carries no stability promise for third-party tools, so this
//! boundary contains crashes and blocks casual egress on developer
//! machines, and every release decision must rest on the Linux
//! namespace, Landlock, and seccomp path. The profile still fails
//! closed: it denies by default, and a missing `sandbox-exec` or a
//! rejected profile refuses the adapter run outright.
//!
//! The profile denies by default and grants only what the process
//! needs to boot plus the jail, the worker, and the minimal runtime.
//! It does not import `system.sb`, whose broad file grants would let
//! an adapter read arbitrary host files such as `/etc/passwd` and
//! return them in an artifact. Instead it imports only the dynamic
//! loader support the base itself uses, then allows execute and read
//! of the worker, read of the system framework and library trees the
//! loader maps, read of the standard random and null devices, and
//! read and write of the per-run jail. Reads and writes outside that
//! set are denied, as is the network.

use std::path::Path;
use std::process::Command;

use super::jail::{JailBackend, SpawnSpec};
use super::{Runner, RunnerError};

const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";

/// The runtime read trees the dynamic loader maps and the process
/// needs to boot. These are read-only and hold no user data.
const RUNTIME_READ_SUBPATHS: &[&str] = &["/usr/lib", "/System"];

/// The device files the runtime reads.
const RUNTIME_READ_DEVICES: &[&str] = &["/dev/urandom", "/dev/random", "/dev/null"];

/// The Seatbelt jail.
pub struct SeatbeltJail;

fn profile(
    jail: &Path,
    worker: &Path,
    exec_grants: &[std::path::PathBuf],
    read_grants: &[std::path::PathBuf],
) -> Result<String, RunnerError> {
    let literal = |path: &Path| -> Result<String, RunnerError> {
        let text = path.to_str().ok_or_else(|| RunnerError {
            code: "sandbox_unavailable",
            message: format!("path {} is not UTF-8", path.display()),
        })?;
        if text.contains('"') || text.contains('\\') {
            return Err(RunnerError {
                code: "sandbox_unavailable",
                message: format!("path {text:?} cannot be quoted in a Seatbelt profile"),
            });
        }
        Ok(text.to_string())
    };
    let jail = literal(jail)?;
    let worker = literal(worker)?;
    let runtime_reads = RUNTIME_READ_SUBPATHS
        .iter()
        .map(|path| format!("  (subpath \"{path}\")"))
        .chain(
            RUNTIME_READ_DEVICES
                .iter()
                .map(|path| format!("  (literal \"{path}\")")),
        )
        .collect::<Vec<_>>()
        .join("\n");
    // Additional literal-file grants for the pinned runtime the
    // deployment wired in: read and execute for engine and probe
    // binaries, read only for weights. Literal files only, never a
    // parent directory, so nothing beside the pinned artifacts
    // becomes readable.
    let mut grant_lines = String::new();
    for path in exec_grants {
        // Measured need: the pinned engine lists its own directory at
        // startup and aborts when the listing is denied. The
        // allowance is the narrowest form that passed measurement,
        // directory-entry listing on the literal parent only: sibling
        // FILES stay unreadable under the default denial, so nothing
        // beside names leaks from the deployment directory.
        if let Some(parent) = path.parent() {
            let parent = literal(parent)?;
            grant_lines.push_str(&format!("(allow file-read-data (literal \"{parent}\"))\n"));
        }
        let path = literal(path)?;
        grant_lines.push_str(&format!(
            "(allow process-exec* file-read* file-map-executable (literal \"{path}\"))\n"
        ));
    }
    for path in read_grants {
        let path = literal(path)?;
        grant_lines.push_str(&format!("(allow file-read* (literal \"{path}\"))\n"));
    }
    // The accelerator runtime allowances, present only when the spec
    // carries executable grants, which is exactly the shape of a
    // wired pinned engine: a grant-free jail keeps the narrower
    // profile unchanged. Measured minimum, each line justified by an
    // observed failure without it:
    // - iokit-get-properties: the accelerator device's property reads
    //   during initialization.
    // - iokit-open, scoped to the accelerator device user-client
    //   class: without it the device still enumerates by TYPE but
    //   never initializes (empty device name, no compute library), so
    //   a backend check could pass over an unusable device and the
    //   engine would fail at first use. The scoped class was
    //   sufficient in measurement; nothing wider is granted.
    if !exec_grants.is_empty() {
        grant_lines.push_str("(allow iokit-get-properties)\n");
        grant_lines
            .push_str("(allow iokit-open (iokit-user-client-class \"AGXDeviceUserClient\"))\n");
    }
    // Deny by default. Grant only the mach, sysctl, and loader
    // allowances a process needs to reach main, execute and read the
    // worker, read the fixed runtime trees, read and write the jail,
    // and read the descriptor directory the fd sweep enumerates.
    // Reads outside this set are denied, so an adapter cannot read a
    // host file and return it in an artifact.
    Ok(format!(
        r#"(version 1)
(deny default)
(deny network*)
(allow process-fork)
(allow process-exec* (literal "{worker}"))
(allow mach-lookup)
(allow mach-bootstrap)
(allow ipc-posix-shm*)
(allow sysctl-read)
(allow system-sched)
(allow signal (target same-sandbox))
(import "dyld-support.sb")
(allow file-read-metadata)
(allow file-read* file-map-executable (literal "{worker}"))
(allow file-read* file-map-executable
{runtime_reads}
  (subpath "/dev/fd"))
(allow file-read* file-write* (subpath "{jail}"))
{grant_lines}"#
    ))
}

/// The `--rlimit-as` argument value: a byte count, or `none` when the
/// profile leaves the limit unset.
fn rlimit_as_argument(limit: Option<u64>) -> String {
    match limit {
        Some(bytes) => bytes.to_string(),
        None => "none".to_string(),
    }
}

impl JailBackend for SeatbeltJail {
    fn name(&self) -> &'static str {
        "macos-seatbelt"
    }

    fn command(&self, spec: &SpawnSpec<'_>) -> Result<Command, RunnerError> {
        if !Path::new(SANDBOX_EXEC).is_file() {
            return Err(RunnerError {
                code: "sandbox_unavailable",
                message: format!("{SANDBOX_EXEC} is missing, refusing to run adapters"),
            });
        }
        let mut command = Command::new(SANDBOX_EXEC);
        command
            .arg("-p")
            .arg(profile(
                spec.jail,
                spec.worker,
                spec.exec_grants,
                spec.read_grants,
            )?)
            .arg(spec.worker)
            .arg("sandbox-helper")
            .arg("--jail")
            .arg(spec.jail)
            .arg("--worker")
            .arg(spec.worker)
            .arg("--adapter")
            .arg(spec.mode)
            .arg("--rlimit-as")
            .arg(rlimit_as_argument(spec.limits.address_space_bytes))
            .arg("--rlimit-cpu")
            .arg(spec.limits.cpu_seconds.to_string())
            .arg("--rlimit-fsize")
            .arg(spec.limits.file_size_bytes.to_string())
            .arg("--rlimit-nproc")
            .arg(spec.limits.max_processes.to_string())
            .arg("--seccomp")
            .arg("off");
        for path in spec.exec_grants {
            command.arg("--grant-exec").arg(path);
        }
        for path in spec.read_grants {
            command.arg("--grant-read").arg(path);
        }
        Ok(command)
    }

    fn policy_material(&self) -> String {
        // The profile is jail-specific, so the material is its fixed
        // shape: deny-default with the fixed runtime read set and the
        // network denial.
        format!(
            "seatbelt deny-default deny-network runtime-read={} devices={} jail-read-write",
            RUNTIME_READ_SUBPATHS.join(","),
            RUNTIME_READ_DEVICES.join(",")
        )
    }

    fn probe(&self, runner: &Runner) -> Result<(), RunnerError> {
        super::jail::probe_net(runner, false)
    }
}
