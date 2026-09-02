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

use super::jail::{JailBackend, RuntimeProfile, SpawnSpec};
use super::{Runner, RunnerError};

const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";

/// The runtime read trees the dynamic loader maps and the process
/// needs to boot. These are read-only and hold no user data.
const RUNTIME_READ_SUBPATHS: &[&str] = &["/usr/lib", "/System"];

/// The device files the runtime reads.
const RUNTIME_READ_DEVICES: &[&str] = &["/dev/urandom", "/dev/random", "/dev/null"];

/// The Seatbelt jail.
pub struct SeatbeltJail;

/// The scoped device-access line the pinned accelerator engine was
/// measured to need: `iokit-open` on the one user-client class, never
/// the unscoped operation.
const ACCELERATOR_OPEN_LINE: &str =
    "(allow iokit-open (iokit-user-client-class \"AGXDeviceUserClient\"))\n";

/// The device property-read line the same measurement required.
const ACCELERATOR_PROPERTIES_LINE: &str = "(allow iokit-get-properties)\n";

fn profile(
    jail: &Path,
    worker: &Path,
    exec_grants: &[std::path::PathBuf],
    read_grants: &[std::path::PathBuf],
    runtime_profile: RuntimeProfile,
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
    //
    // The accelerator allowances below belong to one worker mode, the
    // one that drives the pinned accelerator engine, and the spec
    // names that class explicitly. All three key on the class ALONE,
    // never on the presence of an executable grant: grant presence is
    // what let allowances measured for one engine reach every other
    // granted worker, so an image worker carrying its own engine
    // grant renders the base profile plus its literal grant lines and
    // nothing else.
    let accelerator = runtime_profile == RuntimeProfile::Accelerator;
    let mut grant_lines = String::new();
    for path in exec_grants {
        // Measured need: the pinned accelerator engine lists its own
        // directory at startup and aborts when the listing is denied.
        // The allowance is the narrowest form that passed measurement,
        // directory-entry listing on the literal parent only: sibling
        // FILES stay unreadable under the default denial, so nothing
        // beside names leaks from the deployment directory.
        if accelerator && let Some(parent) = path.parent() {
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
    // The accelerator device allowances, present for the one worker
    // mode measured to need them. Measured minimum, each line
    // justified by an
    // observed failure without it:
    // - iokit-get-properties: the accelerator device's property reads
    //   during initialization.
    // - iokit-open, scoped to the accelerator device user-client
    //   class: without it the device still enumerates by TYPE but
    //   never initializes (empty device name, no compute library), so
    //   a backend check could pass over an unusable device and the
    //   engine would fail at first use. The scoped class was
    //   sufficient in measurement; nothing wider is granted.
    if accelerator {
        grant_lines.push_str(ACCELERATOR_PROPERTIES_LINE);
        grant_lines.push_str(ACCELERATOR_OPEN_LINE);
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
                spec.runtime_profile,
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// The 0.6.0 profile, byte for byte, for a fixed jail and worker.
    /// A literal, not a re-rendering, so drift in the base shape fails
    /// here instead of being re-derived into the expectation.
    const BASE_0_6_0: &str = r#"(version 1)
(deny default)
(deny network*)
(allow process-fork)
(allow process-exec* (literal "/opt/worker/text-mirror-worker"))
(allow mach-lookup)
(allow mach-bootstrap)
(allow ipc-posix-shm*)
(allow sysctl-read)
(allow system-sched)
(allow signal (target same-sandbox))
(import "dyld-support.sb")
(allow file-read-metadata)
(allow file-read* file-map-executable (literal "/opt/worker/text-mirror-worker"))
(allow file-read* file-map-executable
  (subpath "/usr/lib")
  (subpath "/System")
  (literal "/dev/urandom")
  (literal "/dev/random")
  (literal "/dev/null")
  (subpath "/dev/fd"))
(allow file-read* file-write* (subpath "/jail/run"))
"#;

    const ENGINE_LINE: &str =
        "(allow process-exec* file-read* file-map-executable (literal \"/deploy/engine-cli\"))\n";
    const WEIGHTS_LINE: &str = "(allow file-read* (literal \"/deploy/weights.bin\"))\n";
    const PARENT_LISTING_LINE: &str = "(allow file-read-data (literal \"/deploy\"))\n";
    /// The device pair as literal text, deliberately not the source
    /// constants, so a widened constant fails here instead of moving
    /// the expectation with it.
    const DEVICE_LINES: &str = "(allow iokit-get-properties)\n(allow iokit-open (iokit-user-client-class \"AGXDeviceUserClient\"))\n";

    fn render(exec: &[&str], read: &[&str], runtime_profile: RuntimeProfile) -> String {
        let exec: Vec<PathBuf> = exec.iter().map(PathBuf::from).collect();
        let read: Vec<PathBuf> = read.iter().map(PathBuf::from).collect();
        profile(
            Path::new("/jail/run"),
            Path::new("/opt/worker/text-mirror-worker"),
            &exec,
            &read,
            runtime_profile,
        )
        .expect("the fixed paths render")
    }

    #[test]
    fn a_grant_free_plain_jail_renders_the_0_6_0_profile_byte_for_byte() {
        assert_eq!(render(&[], &[], RuntimeProfile::Plain), BASE_0_6_0);
    }

    #[test]
    fn the_plain_class_with_grants_is_the_base_plus_the_literal_grant_lines_only() {
        // 128 test (a). The image-shaped spec: one executable grant,
        // one read grant, the base class. Exact string equality, so
        // any added line fails, and no device token or parent listing
        // may appear whatever grants the spec carries.
        let rendered = render(
            &["/deploy/engine-cli"],
            &["/deploy/weights.bin"],
            RuntimeProfile::Plain,
        );
        assert_eq!(
            rendered,
            format!("{BASE_0_6_0}{ENGINE_LINE}{WEIGHTS_LINE}"),
            "{rendered}"
        );
        assert!(!rendered.contains("iokit"), "{rendered}");
        assert!(!rendered.contains("file-read-data"), "{rendered}");
    }

    #[test]
    fn the_accelerator_class_carries_the_parent_listing_and_exactly_two_device_lines() {
        // 128 test (b). The audio-shaped spec: the parent listing in
        // its literal form, exactly the two device lines with the
        // single user-client class, and no other device token
        // anywhere in the profile.
        let rendered = render(
            &["/deploy/engine-cli"],
            &["/deploy/weights.bin"],
            RuntimeProfile::Accelerator,
        );
        assert_eq!(
            rendered,
            format!("{BASE_0_6_0}{PARENT_LISTING_LINE}{ENGINE_LINE}{WEIGHTS_LINE}{DEVICE_LINES}"),
            "{rendered}"
        );
        assert!(rendered.contains(PARENT_LISTING_LINE), "{rendered}");
        let device_lines: Vec<&str> = rendered
            .lines()
            .filter(|line| line.contains("iokit"))
            .collect();
        assert_eq!(
            device_lines,
            vec![
                "(allow iokit-get-properties)",
                r#"(allow iokit-open (iokit-user-client-class "AGXDeviceUserClient"))"#,
            ],
            "{rendered}"
        );
        // The widening forms, each named so it fails here.
        assert!(!rendered.contains("(allow iokit-open)"), "{rendered}");
        assert!(!rendered.contains("(allow iokit*"), "{rendered}");
        assert!(!rendered.contains("file-read-data (subpath"), "{rendered}");
    }
}
