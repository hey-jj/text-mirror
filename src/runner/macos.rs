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

use super::jail::{JailBackend, ProviderJail, RuntimeProfile, SpawnSpec};
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

/// The provider jail profile, as one template whose only substitutions
/// are the per-run jail, the worker binary, the deployment's measured
/// closures, the deployment's service namespace, and the literal grant
/// lines for the pinned executables. The rendered profile is the
/// template and nothing else, so the template's BLAKE3 covers the whole
/// text a jail runs under.
///
/// This is the profile the provider spike measured, with three
/// deliberate differences, each recorded with the pin:
///
/// - The closure entries and the service expression are placeholders
///   filled from the deployment configuration, because both name an
///   installed product and this crate carries no product name.
/// - The worker binary is granted execute and read, because the
///   provider runs through the same two-stage spawn as every other
///   adapter rather than as a bare external process, so it inherits the
///   resource limits, the descriptor sweep, the process group, the
///   output caps, and the wall clock.
/// - The exec allowance names the worker and the closures, which is
///   what the two spike parameters resolved to.
///
/// Everything else is byte for byte the measured profile. A test pins
/// this template's own BLAKE3, so any edit fails there and has to be
/// re-measured and re-approved rather than shipped quietly.
///
/// Two allowances are wider than a literal grant and are recorded with
/// the pin as the widest surface this jail keeps: device access is
/// unscoped, because scoping it to any
/// user-client class crashed the renderer in measurement, and the
/// closures are readable as subpaths rather than as literal files. The
/// aggregate closure digest the worker asserts before every execution
/// is the integrity control that stands in for that granularity.
const PROVIDER_PROFILE_TEMPLATE: &str = r#"(version 1)
(deny default)
(deny network*)
(allow network-bind network-outbound
  (subpath "{jail}"))
(allow process-fork)
(allow process-exec*
  (literal "{worker}")
{closures})
(allow signal (target same-sandbox))
(import "dyld-support.sb")
(allow file-read-metadata)
(allow sysctl-read)
(allow system-sched)
(allow ipc-posix-shm*)
(allow mach-lookup)
(allow mach-bootstrap)
{service}(allow iokit-open)
(allow file-read* file-map-executable
  (literal "{worker}")
{closures}  (subpath "/usr/lib")
  (subpath "/System")
  (subpath "/dev/fd"))
(allow file-read*
  (literal "/dev/urandom")
  (literal "/dev/random")
  (literal "/dev/null")
  (subpath "/System/Library/Fonts")
  (subpath "/Library/Fonts"))
(allow file-write-data (literal "/dev/null"))
(allow file-read* file-write* (subpath "{jail}"))
{grants}"#;

/// The BLAKE3 of the provider profile template: the identity of the
/// jail every provider execution runs under, which the effective rules
/// version digests so an edited template re-runs every provider-derived
/// child.
pub fn provider_profile_template_blake3() -> String {
    crate::hash::hash_bytes(PROVIDER_PROFILE_TEMPLATE.as_bytes())
}

/// The five substitution points, in template order.
const PLACEHOLDERS: [&str; 5] = ["{jail}", "{worker}", "{closures}", "{service}", "{grants}"];

/// Substitutes each placeholder exactly once, from a map, so text a
/// substitution inserts is never scanned for placeholders by another.
/// Every value must be free of braces, which is asserted before the
/// pass, so a value cannot carry template syntax at all.
fn substitute(template: &str, values: &[(&str, &str)]) -> Result<String, RunnerError> {
    for (name, value) in values {
        if value.contains('{') || value.contains('}') {
            return Err(RunnerError {
                code: "sandbox_unavailable",
                message: format!("the {name} value carries a brace and cannot be rendered"),
            });
        }
    }
    let mut out = String::with_capacity(template.len() * 2);
    let mut rest = template;
    loop {
        // The next placeholder occurrence, whichever it is.
        let next = PLACEHOLDERS
            .iter()
            .filter_map(|name| rest.find(name).map(|at| (at, *name)))
            .min();
        let Some((at, name)) = next else {
            out.push_str(rest);
            break;
        };
        out.push_str(&rest[..at]);
        let value = values
            .iter()
            .find(|(candidate, _)| *candidate == name)
            .map(|(_, value)| *value)
            .unwrap_or_default();
        out.push_str(value);
        rest = &rest[at + name.len()..];
    }
    Ok(out)
}

/// Renders the provider profile for one invocation.
fn provider_profile(
    jail: &str,
    worker: &str,
    provider: &ProviderJail,
    grant_lines: &str,
) -> Result<String, RunnerError> {
    let refuse = |message: String| RunnerError {
        code: "sandbox_unavailable",
        message,
    };
    let mut closures = Vec::new();
    let total = provider.closures().len();
    for (index, path) in provider.closures().iter().enumerate() {
        let entry = format!("closure entry {} of {total}", index + 1);
        let text = path
            .to_str()
            .ok_or_else(|| refuse(format!("{entry} is not UTF-8")))?;
        if text.contains('"') || text.contains('\\') {
            return Err(refuse(format!(
                "{entry} cannot be quoted in a jail profile"
            )));
        }
        // Both filter forms per entry, so one enumeration covers a
        // directory and a single file alike: a subpath filter grants a
        // tree, a literal filter grants a file, and neither form does
        // the other's job.
        closures.push(format!("  (subpath \"{text}\")\n  (literal \"{text}\")\n"));
    }
    let service = match provider.service_prefix() {
        Some(prefix) => {
            // The render boundary re-applies the configuration
            // grammar: a value that is not an anchored dotted prefix
            // never reaches a registration allowance, whatever
            // constructed the parameters.
            if !crate::convert::provider::is_service_namespace(prefix) {
                return Err(refuse(
                    "the provider service namespace is not an anchored dotted prefix".to_string(),
                ));
            }
            format!("(allow mach-register (global-name-regex #\"{prefix}\"))\n")
        }
        None => String::new(),
    };
    substitute(
        PROVIDER_PROFILE_TEMPLATE,
        &[
            ("{jail}", jail),
            ("{worker}", worker),
            ("{closures}", &closures.concat()),
            ("{service}", &service),
            ("{grants}", grant_lines),
        ],
    )
}

fn profile(
    jail: &Path,
    worker: &Path,
    exec_grants: &[std::path::PathBuf],
    read_grants: &[std::path::PathBuf],
    runtime_profile: RuntimeProfile,
    provider: Option<&ProviderJail>,
) -> Result<String, RunnerError> {
    // A refusal names which path class was refused, never the path:
    // these messages can reach a record.
    let literal = |label: &str, path: &Path| -> Result<String, RunnerError> {
        let text = path.to_str().ok_or_else(|| RunnerError {
            code: "sandbox_unavailable",
            message: format!("{label} is not UTF-8"),
        })?;
        if text.contains('"') || text.contains('\\') {
            return Err(RunnerError {
                code: "sandbox_unavailable",
                message: format!("{label} cannot be quoted in a Seatbelt profile"),
            });
        }
        Ok(text.to_string())
    };
    let jail = literal("the jail path", jail)?;
    let worker = literal("the worker path", worker)?;
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
    // names that class explicitly. The class is the authorization, an
    // executable grant is the necessity; neither alone emits the
    // allowances. Grant presence by itself is what let allowances
    // measured for one engine reach every other granted worker, so an
    // image worker carrying its own engine grant renders the base
    // profile plus its literal grant lines and nothing else, and the
    // authorized class with no engine wired has nothing to open and
    // keeps the base profile too.
    let accelerator = runtime_profile == RuntimeProfile::Accelerator && !exec_grants.is_empty();
    let mut grant_lines = String::new();
    for path in exec_grants {
        // Measured need: the pinned accelerator engine lists its own
        // directory at startup and aborts when the listing is denied.
        // The allowance is the narrowest form that passed measurement,
        // directory-entry listing on the literal parent only: sibling
        // FILES stay unreadable under the default denial, so nothing
        // beside names leaks from the deployment directory.
        if accelerator && let Some(parent) = path.parent() {
            let parent = literal("an executable grant's directory", parent)?;
            grant_lines.push_str(&format!("(allow file-read-data (literal \"{parent}\"))\n"));
        }
        let path = literal("an executable grant", path)?;
        grant_lines.push_str(&format!(
            "(allow process-exec* file-read* file-map-executable (literal \"{path}\"))\n"
        ));
    }
    for path in read_grants {
        let path = literal("a read grant", path)?;
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
    // The provider class renders its own measured profile. The class
    // is the authorization and the wired components are the necessity:
    // the widened profile appears only when the class arrives together
    // with an executable grant and the deployment's measured
    // parameters, so no other worker mode can reach these allowances.
    if runtime_profile == RuntimeProfile::Provider {
        let Some(provider) = provider.filter(|_| !exec_grants.is_empty()) else {
            return Err(RunnerError {
                code: "sandbox_unavailable",
                message: "the provider jail class needs a wired provider, refusing the run"
                    .to_string(),
            });
        };
        return provider_profile(&jail, &worker, provider, &grant_lines);
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
                message: "the sandbox helper is missing, refusing to run adapters".to_string(),
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
                spec.provider,
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
        render_with(exec, read, runtime_profile, None).expect("the fixed paths render")
    }

    fn render_with(
        exec: &[&str],
        read: &[&str],
        runtime_profile: RuntimeProfile,
        provider: Option<&ProviderJail>,
    ) -> Result<String, RunnerError> {
        let exec: Vec<PathBuf> = exec.iter().map(PathBuf::from).collect();
        let read: Vec<PathBuf> = read.iter().map(PathBuf::from).collect();
        profile(
            Path::new("/jail/run"),
            Path::new("/opt/worker/text-mirror-worker"),
            &exec,
            &read,
            runtime_profile,
            provider,
        )
    }

    /// The provider profile a wired provider renders, byte for byte,
    /// for fixed paths. A literal, not a re-rendering, so any drift in
    /// the shape fails here instead of moving the expectation with it.
    const PROVIDER_0_7_0: &str = r#"(version 1)
(deny default)
(deny network*)
(allow network-bind network-outbound
  (subpath "/jail/run"))
(allow process-fork)
(allow process-exec*
  (literal "/opt/worker/text-mirror-worker")
  (subpath "/deploy/closure")
  (literal "/deploy/closure")
)
(allow signal (target same-sandbox))
(import "dyld-support.sb")
(allow file-read-metadata)
(allow sysctl-read)
(allow system-sched)
(allow ipc-posix-shm*)
(allow mach-lookup)
(allow mach-bootstrap)
(allow mach-register (global-name-regex #"^ex\.ample\."))
(allow iokit-open)
(allow file-read* file-map-executable
  (literal "/opt/worker/text-mirror-worker")
  (subpath "/deploy/closure")
  (literal "/deploy/closure")
  (subpath "/usr/lib")
  (subpath "/System")
  (subpath "/dev/fd"))
(allow file-read*
  (literal "/dev/urandom")
  (literal "/dev/random")
  (literal "/dev/null")
  (subpath "/System/Library/Fonts")
  (subpath "/Library/Fonts"))
(allow file-write-data (literal "/dev/null"))
(allow file-read* file-write* (subpath "/jail/run"))
(allow process-exec* file-read* file-map-executable (literal "/deploy/engine-cli"))
"#;

    fn provider(closures: &[&str], service: Option<&str>) -> ProviderJail {
        ProviderJail::new(
            closures.iter().map(PathBuf::from).collect(),
            service.map(str::to_string),
            None,
        )
        .expect("the test parameters fit the grammar")
    }

    /// A real closure directory, resolved, since every entry must
    /// resolve to be granted, and the profile carries the resolved
    /// path.
    fn closure_fixture() -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().unwrap();
        let closure = dir.path().canonicalize().unwrap().join("closure");
        std::fs::create_dir_all(&closure).unwrap();
        let text = closure.to_str().unwrap().to_string();
        (dir, text)
    }

    #[test]
    fn the_provider_profile_template_is_pinned_to_its_own_bytes() {
        // The profile is a measured artifact, not a convenience. Its
        // bytes are pinned here so an edit fails this test and has to
        // be measured and approved rather than shipped quietly.
        assert_eq!(
            crate::hash::hash_bytes(PROVIDER_PROFILE_TEMPLATE.as_bytes()),
            "6cab9514f16c626cdd936e779a72845a9d72c2c04857c7eb4a6f25942e8ef5f2"
        );
    }

    #[test]
    fn a_wired_provider_renders_the_measured_profile_byte_for_byte() {
        let (_dir, closure) = closure_fixture();
        let rendered = render_with(
            &["/deploy/engine-cli"],
            &[],
            RuntimeProfile::Provider,
            Some(&provider(&[&closure], Some(r"^ex\.ample\."))),
        )
        .expect("the fixed paths render");
        let expected = PROVIDER_0_7_0.replace("/deploy/closure", &closure);
        assert_eq!(rendered, expected, "{rendered}");
        // The class carries no allowance measured for a different
        // engine: the device pair the accelerator class emits is not
        // this profile's, and the scoped user-client class never
        // appears here.
        assert!(!rendered.contains("iokit-get-properties"), "{rendered}");
        assert!(!rendered.contains("iokit-user-client-class"), "{rendered}");
        assert!(!rendered.contains("file-read-data"), "{rendered}");
    }

    #[test]
    fn a_value_carrying_template_syntax_is_rendered_verbatim_or_refused() {
        // Single-pass substitution: a closure path that happens to spell
        // a placeholder is inserted as text and never re-scanned, so
        // it cannot pull another value into itself.
        let dir = tempfile::tempdir().unwrap();
        let closure = dir.path().canonicalize().unwrap().join("closure-jail");
        std::fs::create_dir_all(&closure).unwrap();
        let closure = closure.to_str().unwrap().to_string();
        let rendered = render_with(
            &["/deploy/engine-cli"],
            &[],
            RuntimeProfile::Provider,
            Some(&provider(&[&closure], None)),
        )
        .expect("a placeholder-looking path renders");
        assert!(
            rendered.contains(&format!("(subpath \"{closure}\")")),
            "{rendered}"
        );
        // A path spelling `{worker}` inside a quoted string cannot be
        // built, because braces are refused at the boundary: that is
        // the guard, not a re-scan that would have expanded it.
        let error = substitute(
            PROVIDER_PROFILE_TEMPLATE,
            &[
                ("{jail}", "/jail/{worker}"),
                ("{worker}", "/opt/worker"),
                ("{closures}", ""),
                ("{service}", ""),
                ("{grants}", ""),
            ],
        )
        .expect_err("a brace-bearing value must refuse");
        assert_eq!(error.code, "sandbox_unavailable");
        // Every placeholder is substituted exactly once, and the
        // values appear verbatim.
        let rendered = substitute(
            PROVIDER_PROFILE_TEMPLATE,
            &[
                ("{jail}", "/jail/one"),
                ("{worker}", "/opt/worker"),
                ("{closures}", "  (subpath \"/deploy/c\")\n"),
                (
                    "{service}",
                    "(allow mach-register (global-name-regex #\"^a\\\\.\"))\n",
                ),
                (
                    "{grants}",
                    "(allow process-exec* (literal \"/deploy/x\"))\n",
                ),
            ],
        )
        .unwrap();
        for name in PLACEHOLDERS {
            assert!(
                !rendered.contains(name),
                "{name} survived rendering: {rendered}"
            );
        }
        assert!(rendered.ends_with("(allow process-exec* (literal \"/deploy/x\"))\n"));
    }

    #[test]
    fn the_render_boundary_holds_the_parameter_grammar() {
        // The parameters can only be built through the validating
        // constructor, and a value outside the closed grammar never
        // becomes a registration allowance: a free expression, an
        // unanchored prefix, a shared root as a closure, a malformed
        // variable name.
        let (dir, closure) = closure_fixture();
        for bad in [r"^.*", r"ex\.ample\.", r"^(a|b)\.", r"^a\.[a-z]+\."] {
            let error =
                ProviderJail::new(vec![PathBuf::from(&closure)], Some(bad.to_string()), None)
                    .expect_err("a non-conforming namespace must refuse");
            assert_eq!(error.code, "sandbox_unavailable", "{bad}");
        }
        let error = ProviderJail::new(vec![PathBuf::from("/usr/lib")], None, None)
            .expect_err("a shared root must refuse");
        assert_eq!(error.code, "sandbox_unavailable");
        let error = ProviderJail::new(
            vec![PathBuf::from(&closure)],
            None,
            Some("lowercase".to_string()),
        )
        .expect_err("a malformed variable name must refuse");
        assert_eq!(error.code, "sandbox_unavailable");
        // The entries are judged on the trees they really name: an
        // alias of a shared root through `..` is refused as written, a
        // link whose target is a shared root is refused as an entry, a
        // link to any tree is refused as an entry, and an entry that
        // does not exist cannot be granted.
        let error = ProviderJail::new(vec![PathBuf::from("/private/tmp/../tmp")], None, None)
            .expect_err("an alias of a shared root must refuse");
        assert_eq!(error.code, "sandbox_unavailable");
        assert!(error.message.contains("normal form"), "{}", error.message);
        let store = dir.path().join("store");
        std::os::unix::fs::symlink("/usr/lib", &store).unwrap();
        let error = ProviderJail::new(vec![store], None, None)
            .expect_err("a link to a shared root must refuse");
        assert_eq!(error.code, "sandbox_unavailable");
        assert!(error.message.contains("symlink"), "{}", error.message);
        let alias = dir.path().join("alias");
        std::os::unix::fs::symlink(&closure, &alias).unwrap();
        let error =
            ProviderJail::new(vec![alias], None, None).expect_err("a link entry must refuse");
        assert_eq!(error.code, "sandbox_unavailable");
        let error = ProviderJail::new(vec![PathBuf::from("/deploy/closure")], None, None)
            .expect_err("an entry that does not exist must refuse");
        assert_eq!(error.code, "sandbox_unavailable");
        assert!(error.message.contains("resolved"), "{}", error.message);
        // The resolved shared-root comparison itself: a real directory
        // reached through an ancestor link into a shared root.
        let usrlink = dir.path().join("usrlink");
        std::os::unix::fs::symlink("/usr", &usrlink).unwrap();
        let error = ProviderJail::new(vec![usrlink.join("lib")], None, None)
            .expect_err("a real entry carried into a shared root must refuse");
        assert_eq!(error.code, "sandbox_unavailable");
        assert!(error.message.contains("shared root"), "{}", error.message);
        // An entry that is neither a directory nor a regular file.
        let socket = dir.path().join("sock");
        let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        let error =
            ProviderJail::new(vec![socket], None, None).expect_err("a socket entry must refuse");
        assert_eq!(error.code, "sandbox_unavailable");
        assert!(
            error.message.contains("not a directory or a regular file"),
            "{}",
            error.message
        );
        // A FIFO is refused the same way.
        let fifo = dir.path().join("fifo");
        assert!(
            std::process::Command::new("/usr/bin/mkfifo")
                .arg(&fifo)
                .status()
                .unwrap()
                .success()
        );
        let error = ProviderJail::new(vec![fifo.clone()], None, None)
            .expect_err("a FIFO entry must refuse");
        assert!(
            error.message.contains("not a directory or a regular file"),
            "{}",
            error.message
        );
        // No refusal names a path: these messages can reach a record.
        for entry in [
            fifo,
            PathBuf::from("relative"),
            PathBuf::from("/private/tmp/../tmp"),
            dir.path().join("store"),
            dir.path().join("sock"),
            PathBuf::from("/deploy/closure"),
            PathBuf::from("/usr/lib"),
            usrlink.join("lib"),
        ] {
            let error = ProviderJail::new(vec![entry.clone()], None, None)
                .expect_err("every one of these refuses");
            assert!(
                !error.message.contains('/'),
                "{}: {}",
                entry.display(),
                error.message
            );
        }
        // The conforming shape builds and renders, on the resolved
        // path: an unresolved spelling of the same tree is granted as
        // the tree.
        let jail = ProviderJail::new(
            vec![PathBuf::from(&closure)],
            Some(r"^ex\.ample\.".to_string()),
            Some("EXAMPLE_TMPDIR".to_string()),
        )
        .unwrap();
        assert_eq!(jail.closures(), &[PathBuf::from(&closure)]);
        let unresolved = dir.path().join("closure");
        let jail = ProviderJail::new(vec![unresolved], None, None).unwrap();
        assert_eq!(jail.closures(), &[PathBuf::from(&closure)]);
    }

    #[test]
    fn the_provider_profile_omits_what_the_deployment_did_not_configure() {
        // No service namespace configured means no registration
        // allowance at all, and no closure means no subpath grant: the
        // profile grants what was measured and nothing by default.
        let rendered = render_with(
            &["/deploy/engine-cli"],
            &[],
            RuntimeProfile::Provider,
            Some(&provider(&[], None)),
        )
        .expect("the fixed paths render");
        assert!(!rendered.contains("mach-register"), "{rendered}");
        assert!(!rendered.contains("subpath \"/deploy"), "{rendered}");
        // The jail, the worker, and the literal grant are still there.
        assert!(rendered.contains("(subpath \"/jail/run\")"), "{rendered}");
        assert!(rendered.contains("/deploy/engine-cli"), "{rendered}");
    }

    #[test]
    fn the_provider_class_renders_nothing_without_a_wired_provider() {
        // The class is the authorization and the wiring is the
        // necessity. Neither alone renders the widened profile: with
        // no provider parameters, or with no executable grant, the
        // backend refuses instead of falling back to something else.
        let error = render_with(&["/deploy/engine-cli"], &[], RuntimeProfile::Provider, None)
            .expect_err("an unwired provider class must refuse");
        assert_eq!(error.code, "sandbox_unavailable");
        let (_dir, closure) = closure_fixture();
        let error = render_with(
            &[],
            &[],
            RuntimeProfile::Provider,
            Some(&provider(&[&closure], None)),
        )
        .expect_err("a grant-free provider class must refuse");
        assert_eq!(error.code, "sandbox_unavailable");
    }

    #[test]
    fn a_provider_path_that_cannot_be_quoted_refuses_the_run() {
        let (dir, _closure) = closure_fixture();
        for name in ["quote\"mark", "back\\slash"] {
            let closure = dir.path().canonicalize().unwrap().join(name);
            std::fs::create_dir_all(&closure).unwrap();
            let error = render_with(
                &["/deploy/engine-cli"],
                &[],
                RuntimeProfile::Provider,
                Some(&provider(&[closure.to_str().unwrap()], None)),
            )
            .expect_err("an unquotable closure must refuse");
            assert_eq!(error.code, "sandbox_unavailable");
        }
        // A service value that could break the profile's quoting never
        // reaches the renderer: the parameters' own constructor refuses
        // it under the grammar before any render happens.
        let (_dir, closure) = closure_fixture();
        let error = ProviderJail::new(
            vec![PathBuf::from(&closure)],
            Some("bad\"expression".to_string()),
            None,
        )
        .expect_err("an unquotable service expression must refuse");
        assert_eq!(error.code, "sandbox_unavailable");
    }

    #[test]
    fn a_grant_free_jail_renders_the_0_6_0_profile_byte_for_byte() {
        // Both classes: the authorized class with no engine wired has
        // nothing to open, so it keeps the base profile as well.
        assert_eq!(render(&[], &[], RuntimeProfile::Plain), BASE_0_6_0);
        assert_eq!(render(&[], &[], RuntimeProfile::Accelerator), BASE_0_6_0);
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
