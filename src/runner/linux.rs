//! The Linux jail backend: user and network namespaces, Landlock
//! filesystem rules, and a seccomp allow-list.
//!
//! The network boundary is a fresh network namespace created together
//! with a user namespace, which Linux permits unprivileged when
//! unprivileged user namespaces are enabled. The new namespace has a
//! private network stack and no external interface. A seccomp
//! allow-list is the second layer: it omits every socket, io_uring,
//! bpf, setsid, and setpgid family syscall, and any syscall outside
//! the list kills the process. Landlock confines the filesystem to
//! the jail read-write, the worker binary execute-read, and a fixed
//! runtime set read-only, with no best-effort mode: a kernel that
//! cannot fully enforce the policy refuses the run. The kernel floor
//! is Landlock ABI v3, Linux 6.2.

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

use landlock::{
    ABI, Access, AccessFs, CompatLevel, Compatible, PathBeneath, PathFd, Ruleset, RulesetAttr,
    RulesetCreatedAttr, RulesetStatus,
};
use nix::libc;
use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, SeccompRule, TargetArch};

use super::jail::{JailBackend, RuntimeProfile, SpawnSpec};
use super::{Runner, RunnerError};

/// The Landlock ABI this backend requires in full.
const LANDLOCK_ABI: ABI = ABI::V3;

/// Runtime paths the adapter may read: the dynamic loader, the shared
/// library trees, and the loader cache, and nothing else. The shipped
/// worker is the pure-Rust anydoc PDF path, which links only the
/// loader, libc, libm, and libgcc_s, so the minimum set is the
/// standard library directories. The list deliberately excludes the
/// rest of `/usr`, so `/usr/local`, `/usr/share`, `/usr/bin`, and
/// site data are not readable. Missing entries are skipped, so one
/// list serves distributions that place the libraries under `/lib`,
/// `/lib64`, `/usr/lib`, or `/usr/lib64`.
const RUNTIME_READ_PATHS: &[&str] = &[
    "/lib",
    "/lib64",
    "/usr/lib",
    "/usr/lib64",
    "/etc/ld.so.cache",
];

/// The namespace, Landlock, and seccomp jail.
pub struct NamespaceJail;

impl JailBackend for NamespaceJail {
    fn name(&self) -> &'static str {
        "linux-namespace"
    }

    fn command(&self, spec: &SpawnSpec<'_>) -> Result<Command, RunnerError> {
        // The provider jail is a measured macOS profile. No provider
        // profile has been measured for this platform, so the class is
        // refused here rather than silently running the external
        // components under the base policy.
        if spec.runtime_profile == RuntimeProfile::Provider {
            return Err(RunnerError {
                code: "sandbox_unavailable",
                message: "no provider jail profile is measured for this platform, refusing the run"
                    .to_string(),
            });
        }
        let mut command = Command::new(spec.worker);
        command
            .arg("sandbox-helper")
            .arg("--jail")
            .arg(spec.jail)
            .arg("--worker")
            .arg(spec.worker)
            .arg("--adapter")
            .arg(spec.mode)
            .arg("--rlimit-as")
            .arg(match spec.limits.address_space_bytes {
                Some(bytes) => bytes.to_string(),
                None => "none".to_string(),
            })
            .arg("--rlimit-cpu")
            .arg(spec.limits.cpu_seconds.to_string())
            .arg("--rlimit-fsize")
            .arg(spec.limits.file_size_bytes.to_string())
            .arg("--rlimit-nproc")
            .arg(spec.limits.max_processes.to_string())
            .arg("--seccomp")
            .arg(if spec.seccomp { "kill" } else { "off" });
        for path in spec.exec_grants {
            command.arg("--grant-exec").arg(path);
        }
        for path in spec.read_grants {
            command.arg("--grant-read").arg(path);
        }
        Ok(command)
    }

    fn policy_material(&self) -> String {
        format!(
            "newuser+newnet landlock-abi-v3 runtime={} seccomp-allow={}",
            RUNTIME_READ_PATHS.join(","),
            allowed_syscalls()
                .iter()
                .map(|n| n.to_string())
                .collect::<Vec<_>>()
                .join(",")
        )
    }

    /// Two stages. The first runs the network probe with the syscall
    /// filter off, so the namespace layer's denial is observed
    /// directly. The second proves the filter layer by attempting one
    /// socket creation under it and requiring the kernel to kill the
    /// process.
    fn probe(&self, runner: &Runner) -> Result<(), RunnerError> {
        super::jail::probe_net(runner, false)?;
        match runner.run_unprobed("probe-seccomp", serde_json::json!({}), &[], true) {
            Err(e) if e.code == "adapter_crash" => Ok(()),
            Ok(_) => Err(RunnerError {
                code: "sandbox_probe_failed",
                message: "the syscall filter let a socket creation through".to_string(),
            }),
            Err(e) => Err(RunnerError {
                code: "sandbox_probe_failed",
                message: format!("the syscall filter probe failed to run: {}", e.code),
            }),
        }
    }
}

/// Applies the namespace layer: a fresh user namespace with one-ID
/// maps and a fresh network namespace.
pub(super) fn unshare_namespaces() -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let this = std::fs::metadata("/proc/self")
        .map_err(|e| format!("cannot read process identity: {:?}", e.kind()))?;
    let (uid, gid) = (this.uid(), this.gid());
    nix::sched::unshare(
        nix::sched::CloneFlags::CLONE_NEWUSER | nix::sched::CloneFlags::CLONE_NEWNET,
    )
    .map_err(|e| format!("unshare(newuser|newnet) failed: {e:?}"))?;
    std::fs::write("/proc/self/setgroups", "deny")
        .map_err(|e| format!("cannot deny setgroups: {:?}", e.kind()))?;
    std::fs::write("/proc/self/uid_map", format!("{uid} {uid} 1\n"))
        .map_err(|e| format!("cannot write the uid map: {:?}", e.kind()))?;
    std::fs::write("/proc/self/gid_map", format!("{gid} {gid} 1\n"))
        .map_err(|e| format!("cannot write the gid map: {:?}", e.kind()))?;
    Ok(())
}

/// Applies the Landlock filesystem policy and requires it fully
/// enforced. Best-effort is only acceptable in nothing: a partial
/// policy refuses the run. Literal grant files, when supplied, gain
/// execute-and-read or read-only access; a grant that cannot be
/// opened refuses the run, because a missing pinned artifact must
/// fail loudly rather than silently narrow the policy.
pub(super) fn apply_landlock(
    jail: &Path,
    worker: &Path,
    exec_grants: &[std::path::PathBuf],
    read_grants: &[std::path::PathBuf],
) -> Result<(), String> {
    let ruleset_kind = |error: &landlock::RulesetError| match error {
        landlock::RulesetError::HandleAccesses(_) => "HandleAccesses",
        landlock::RulesetError::CreateRuleset(_) => "CreateRuleset",
        landlock::RulesetError::AddRules(_) => "AddRules",
        landlock::RulesetError::RestrictSelf(_) => "RestrictSelf",
        landlock::RulesetError::Scope(_) => "Scope",
        landlock::RulesetError::RestrictSelfFlags(_) => "RestrictSelfFlags",
        _ => "Unknown",
    };
    let path_fd_kind = |error: landlock::PathFdError| match error {
        landlock::PathFdError::OpenCall { source, .. } => source.kind(),
    };
    let fail = |stage: &str, kind: &str| format!("landlock {stage}: {kind}");
    let mut ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_all(LANDLOCK_ABI))
        .map_err(|e| fail("handle_access", ruleset_kind(&e)))?
        .create()
        .map_err(|e| fail("create", ruleset_kind(&e)))?;
    ruleset = ruleset
        .add_rule(PathBeneath::new(
            PathFd::new(jail)
                .map_err(|e| format!("landlock jail directory: {:?}", path_fd_kind(e)))?,
            AccessFs::from_all(LANDLOCK_ABI),
        ))
        .map_err(|e| fail("jail directory rule", ruleset_kind(&e)))?;
    ruleset = ruleset
        .add_rule(PathBeneath::new(
            PathFd::new(worker)
                .map_err(|e| format!("landlock worker binary: {:?}", path_fd_kind(e)))?,
            AccessFs::Execute | AccessFs::ReadFile,
        ))
        .map_err(|e| fail("worker binary rule", ruleset_kind(&e)))?;
    for (index, path) in exec_grants.iter().enumerate() {
        let label = format!("executable grant {} of {}", index + 1, exec_grants.len());
        ruleset = ruleset
            .add_rule(PathBeneath::new(
                PathFd::new(path)
                    .map_err(|e| format!("landlock {label}: {:?}", path_fd_kind(e)))?,
                AccessFs::Execute | AccessFs::ReadFile,
            ))
            .map_err(|e| fail(&format!("{label} rule"), ruleset_kind(&e)))?;
    }
    for (index, path) in read_grants.iter().enumerate() {
        let label = format!("read grant {} of {}", index + 1, read_grants.len());
        ruleset = ruleset
            .add_rule(PathBeneath::new(
                PathFd::new(path)
                    .map_err(|e| format!("landlock {label}: {:?}", path_fd_kind(e)))?,
                AccessFs::ReadFile.into(),
            ))
            .map_err(|e| fail(&format!("{label} rule"), ruleset_kind(&e)))?;
    }
    let runtime_total = RUNTIME_READ_PATHS.len();
    for (index, path) in RUNTIME_READ_PATHS.iter().enumerate() {
        if !Path::new(path).exists() {
            continue;
        }
        let access = if Path::new(path).is_dir() {
            AccessFs::from_read(LANDLOCK_ABI)
        } else {
            AccessFs::ReadFile.into()
        };
        ruleset = ruleset
            .add_rule(PathBeneath::new(
                PathFd::new(path).map_err(|e| {
                    format!(
                        "landlock runtime grant {} of {runtime_total}: {:?}",
                        index + 1,
                        path_fd_kind(e)
                    )
                })?,
                access,
            ))
            .map_err(|e| {
                fail(
                    &format!("runtime grant {} of {runtime_total} rule", index + 1),
                    ruleset_kind(&e),
                )
            })?;
    }
    let status = ruleset
        .restrict_self()
        .map_err(|e| fail("restrict_self", ruleset_kind(&e)))?;
    if status.ruleset != RulesetStatus::FullyEnforced {
        return Err(format!(
            "landlock policy is {:?}, full enforcement is required, the kernel floor is 6.2",
            status.ruleset
        ));
    }
    Ok(())
}

/// Installs the seccomp allow-list with kill-process as the mismatch
/// action.
pub(super) fn apply_seccomp() -> Result<(), String> {
    let arch = TargetArch::try_from(std::env::consts::ARCH)
        .map_err(|e| format!("seccomp does not support this architecture: {e:?}"))?;
    let rules: BTreeMap<i64, Vec<SeccompRule>> = allowed_syscalls()
        .iter()
        .map(|syscall| (*syscall, Vec::new()))
        .collect();
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::KillProcess,
        SeccompAction::Allow,
        arch,
    )
    .map_err(|e| format!("seccomp filter build failed: {e}"))?;
    let program: BpfProgram = filter
        .try_into()
        .map_err(|e: seccompiler::BackendError| format!("seccomp compile failed: {e}"))?;
    seccompiler::apply_filter(&program).map_err(|e| format!("seccomp install failed: {e}"))
}

/// The syscall allow-list for the adapter and the loader under it.
///
/// The list deliberately omits every socket-family syscall, io_uring,
/// bpf, setsid, setpgid, setns, mount, and ptrace. Threads are
/// allowed because they do not weaken the network or filesystem
/// boundary.
fn allowed_syscalls() -> Vec<i64> {
    let mut list = vec![
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_readv,
        libc::SYS_writev,
        libc::SYS_pread64,
        libc::SYS_pwrite64,
        libc::SYS_close,
        libc::SYS_fstat,
        libc::SYS_newfstatat,
        libc::SYS_statx,
        libc::SYS_lseek,
        libc::SYS_mmap,
        libc::SYS_mprotect,
        libc::SYS_munmap,
        libc::SYS_mremap,
        libc::SYS_madvise,
        libc::SYS_brk,
        libc::SYS_futex,
        libc::SYS_sched_yield,
        libc::SYS_sched_getaffinity,
        libc::SYS_clock_gettime,
        libc::SYS_clock_getres,
        libc::SYS_clock_nanosleep,
        libc::SYS_gettimeofday,
        libc::SYS_getrandom,
        libc::SYS_exit,
        libc::SYS_exit_group,
        libc::SYS_rt_sigaction,
        libc::SYS_rt_sigprocmask,
        libc::SYS_rt_sigreturn,
        libc::SYS_sigaltstack,
        libc::SYS_tgkill,
        libc::SYS_tkill,
        libc::SYS_getpid,
        libc::SYS_gettid,
        libc::SYS_getppid,
        libc::SYS_getuid,
        libc::SYS_geteuid,
        libc::SYS_getgid,
        libc::SYS_getegid,
        libc::SYS_getrlimit,
        libc::SYS_prlimit64,
        libc::SYS_getrusage,
        libc::SYS_sysinfo,
        libc::SYS_times,
        libc::SYS_uname,
        libc::SYS_umask,
        libc::SYS_openat,
        libc::SYS_faccessat,
        libc::SYS_faccessat2,
        libc::SYS_getdents64,
        libc::SYS_readlinkat,
        libc::SYS_getcwd,
        libc::SYS_chdir,
        libc::SYS_fchdir,
        libc::SYS_fcntl,
        libc::SYS_dup,
        libc::SYS_dup3,
        libc::SYS_pipe2,
        libc::SYS_ioctl,
        libc::SYS_ppoll,
        libc::SYS_pselect6,
        libc::SYS_epoll_create1,
        libc::SYS_epoll_ctl,
        libc::SYS_epoll_pwait,
        libc::SYS_eventfd2,
        libc::SYS_mkdirat,
        libc::SYS_unlinkat,
        libc::SYS_renameat,
        libc::SYS_ftruncate,
        libc::SYS_fallocate,
        libc::SYS_fsync,
        libc::SYS_fdatasync,
        libc::SYS_flock,
        libc::SYS_utimensat,
        libc::SYS_set_tid_address,
        libc::SYS_set_robust_list,
        libc::SYS_rseq,
        libc::SYS_membarrier,
        libc::SYS_prctl,
        libc::SYS_clone,
        libc::SYS_clone3,
        libc::SYS_execve,
        libc::SYS_wait4,
    ];
    #[cfg(target_arch = "x86_64")]
    list.extend_from_slice(&[
        libc::SYS_open,
        libc::SYS_stat,
        libc::SYS_lstat,
        libc::SYS_access,
        libc::SYS_readlink,
        libc::SYS_poll,
        libc::SYS_select,
        libc::SYS_dup2,
        libc::SYS_pipe,
        libc::SYS_epoll_wait,
        libc::SYS_mkdir,
        libc::SYS_unlink,
        libc::SYS_rename,
        libc::SYS_arch_prctl,
        libc::SYS_nanosleep,
        libc::SYS_time,
        libc::SYS_getdents,
    ]);
    list.sort_unstable();
    list
}
