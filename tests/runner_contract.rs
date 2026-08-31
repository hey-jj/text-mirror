//! Contract tests for the sandbox runner.
//!
//! Every term of the sandbox contract is exercised against the worker
//! binary's harness modes, which the `test-adapters` feature compiles
//! in: a wall-clock timeout kill, the two output caps, an oversized
//! frame refused before allocation, a truncated frame on a killed
//! child, network denial, environment scrubbing, a refused jail
//! escape, and a crash that writes plausible JSON but exits nonzero.
//!
//! These tests need a working jail backend for the host platform.
//! macOS runs them locally through the Seatbelt profile. Linux runs
//! them through user and network namespaces, Landlock, and seccomp,
//! which need unprivileged user namespaces enabled.

#![cfg(unix)]

use std::time::Duration;

use text_mirror::runner::jail::platform_backend;
use text_mirror::runner::{Limits, Runner, locate_worker};

fn worker_path() -> std::path::PathBuf {
    locate_worker().expect("the worker binary sits beside the test binary")
}

fn runner_with(limits: Limits) -> Runner {
    let backend = platform_backend().expect("this platform has a jail backend");
    Runner::new(backend, worker_path(), limits)
}

fn brisk_limits() -> Limits {
    Limits {
        // Generous enough that sandbox-exec and probe startup under
        // parallel load never race the deadline, tight enough that the
        // timeout test stays quick. A contract suite must be
        // deterministic, so this is not shaved to the floor.
        wall_timeout: Duration::from_secs(4),
        max_response_bytes: 4 * 1024 * 1024,
        max_stderr_bytes: 64 * 1024,
        ..Limits::default()
    }
}

fn runner() -> Runner {
    runner_with(brisk_limits())
}

#[test]
fn the_backend_probe_proves_the_network_is_denied() {
    // The probe creates the jail and requires an IPv4 connect, an
    // IPv6 connect, a Unix socket connect to a listener the parent
    // holds outside the jail, and a UDP send to all fail. A pass is
    // the standing proof that an adapter cannot reach the network.
    let runner = runner();
    runner
        .backend()
        .probe(&runner)
        .expect("the network probe must pass on a supported platform");
}

#[test]
fn a_hung_adapter_is_killed_at_the_wall_clock_deadline() {
    // A short but startup-safe deadline: well above sandbox-exec and
    // probe startup, so the kill is deterministic under load.
    let runner = runner_with(Limits {
        wall_timeout: Duration::from_millis(1500),
        ..brisk_limits()
    });
    let error = runner
        .run("harness-sleep", serde_json::json!({}), &[])
        .unwrap_err();
    assert_eq!(error.code, "adapter_timeout", "{error}");
}

#[test]
fn an_oversized_response_frame_is_refused_before_allocation() {
    let error = runner()
        .run("harness-oversized", serde_json::json!({}), &[])
        .unwrap_err();
    assert_eq!(error.code, "adapter_frame_oversized", "{error}");
}

#[test]
fn bytes_after_the_response_frame_overflow_the_output_budget() {
    let error = runner()
        .run("harness-trailing", serde_json::json!({}), &[])
        .unwrap_err();
    assert_eq!(error.code, "adapter_output_overflow", "{error}");
}

#[test]
fn a_stderr_flood_is_capped_and_kills_the_child() {
    let error = runner()
        .run("harness-stderr-flood", serde_json::json!({}), &[])
        .unwrap_err();
    assert_eq!(error.code, "adapter_output_overflow", "{error}");
}

#[test]
fn a_truncated_response_frame_is_a_protocol_error() {
    let error = runner()
        .run("harness-truncated", serde_json::json!({}), &[])
        .unwrap_err();
    assert_eq!(error.code, "adapter_protocol_error", "{error}");
    assert!(error.message.contains("truncated"), "{error}");
}

#[test]
fn a_crash_after_plausible_json_is_refused_on_the_nonzero_exit() {
    // The harness writes a complete, well-formed response frame and
    // then exits nonzero. A frame alone is never success.
    let error = runner()
        .run("harness-crash", serde_json::json!({}), &[])
        .unwrap_err();
    assert_eq!(error.code, "adapter_crash", "{error}");
}

#[test]
fn the_child_environment_is_scrubbed() {
    let response = runner()
        .run("harness-env", serde_json::json!({}), &[])
        .expect("harness-env runs to completion");
    let ok = response.ok.expect("harness-env succeeds");
    let env = ok
        .get("env")
        .and_then(|v| v.as_array())
        .expect("env array present");
    // The parent clears its environment before the spawn, so nothing
    // is inherited. The one tolerated key is the CoreFoundation text
    // encoding hint the macOS runtime injects through sandbox-exec
    // itself, which is not a leaked parent variable. On Linux the
    // environment is empty.
    const RUNTIME_INJECTED: &[&str] = &["__CF_USER_TEXT_ENCODING"];
    for pair in env {
        let key = pair
            .as_array()
            .and_then(|kv| kv.first())
            .and_then(|k| k.as_str())
            .unwrap_or("");
        assert!(
            RUNTIME_INJECTED.contains(&key),
            "the child inherited environment variable {key:?}"
        );
    }
    for leaked in [
        "PATH",
        "HOME",
        "USER",
        "TMPDIR",
        "LD_PRELOAD",
        "DYLD_INSERT_LIBRARIES",
    ] {
        assert!(
            !env.iter().any(|pair| pair
                .as_array()
                .and_then(|kv| kv.first())
                .and_then(|k| k.as_str())
                == Some(leaked)),
            "the child inherited {leaked}"
        );
    }
}

#[test]
fn a_jail_escape_read_and_write_are_refused() {
    // The read target is a real file on the host outside the jail, so
    // a denial is the filesystem policy and never a missing file. The
    // test asserts the file exists before it trusts the denial.
    let host_file = existing_host_file();
    assert!(
        std::path::Path::new(&host_file).exists(),
        "the escape read target {host_file} must exist on the host"
    );
    let response = runner()
        .run(
            "harness-escape",
            serde_json::json!({ "read_path": host_file }),
            &[],
        )
        .expect("harness-escape runs to completion");
    let ok = response.ok.expect("harness-escape succeeds");
    let read = ok.get("read").and_then(|v| v.as_str()).unwrap_or("");
    let write = ok.get("write").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        read.contains("denied"),
        "a read of a host file outside the jail was not denied: {read:?}"
    );
    assert!(
        write.contains("denied"),
        "a write outside the jail was not denied: {write:?}"
    );
}

/// A file that exists on the host outside the jail on either platform.
fn existing_host_file() -> String {
    for candidate in ["/etc/hosts", "/etc/services", "/etc/passwd"] {
        if std::path::Path::new(candidate).exists() {
            return candidate.to_string();
        }
    }
    panic!("no known host file exists to prove the read confinement");
}

// The process-tree cases run on Linux, where the seccomp filter keeps
// a descendant inside the group and an adapter can legitimately spawn
// a helper. The macOS profile denies the adapter from spawning at all,
// so a survivor cannot arise there; the macOS parent-never-hangs
// guarantee is proven by the stdout-holding test below instead.
#[cfg(target_os = "linux")]
#[test]
fn a_stdio_closing_descendant_does_not_outlive_the_invocation() {
    // The harness spawns a descendant into a hold mode with all stdio
    // detached, then exits cleanly. The runner's unconditional group
    // kill on the normal-exit path must still reap the descendant.
    let worker = worker_path();
    let response = runner()
        .run(
            "harness-survivor",
            serde_json::json!({ "program": worker.to_str().unwrap() }),
            &[],
        )
        .expect("harness-survivor runs to completion");
    let ok = response.ok.expect("harness-survivor succeeds");
    let pid = ok
        .get("survivor_pid")
        .and_then(|v| v.as_u64())
        .expect("survivor pid reported") as i32;

    // Poll briefly: the group kill is synchronous before the call
    // returns, so the descendant should already be gone.
    let mut alive = true;
    for _ in 0..50 {
        if !pid_alive(pid) {
            alive = false;
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        !alive,
        "a descendant that closed its stdio outlived the invocation (pid {pid})"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn the_process_count_limit_bounds_a_spawn_storm() {
    // The helper caps RLIMIT_NPROC before exec, so an adapter that
    // tries to fork many children is bounded and cannot exhaust the
    // host process table. The cap is small, so most attempts fail.
    let runner = runner_with(Limits {
        max_processes: 8,
        wall_timeout: Duration::from_secs(6),
        ..brisk_limits()
    });
    let worker = worker_path();
    let response = runner
        .run(
            "harness-spawn-storm",
            serde_json::json!({ "program": worker.to_str().unwrap(), "attempts": 200 }),
            &[],
        )
        .expect("harness-spawn-storm runs to completion");
    let ok = response.ok.expect("harness-spawn-storm succeeds");
    let spawned = ok.get("spawned").and_then(|v| v.as_u64()).unwrap();
    let failed = ok.get("failed").and_then(|v| v.as_u64()).unwrap();
    assert!(
        failed > 0,
        "the process-count limit let all 200 spawns through, spawned={spawned} failed={failed}"
    );
    assert!(
        spawned < 200,
        "the process-count limit bounded nothing, spawned={spawned}"
    );
}

// The adapter attempts to setsid out of its group and holds stdout
// past the kill, then self-terminates so the test leaks nothing. As
// shipped the escape cannot happen: the adapter leads its own group,
// so setsid fails, and the profile denies spawning a descendant that
// could escape. The test proves the parent returns fail-closed under
// a bound either way. The bounded drain join stays as defense in
// depth for a profile that permits spawning, and a real escapee test
// must accompany that widening.
#[cfg(target_os = "macos")]
#[test]
fn the_parent_never_hangs_on_a_stdout_holding_adapter() {
    let runner = runner_with(Limits {
        wall_timeout: Duration::from_millis(800),
        ..brisk_limits()
    });
    let started = std::time::Instant::now();
    let error = runner
        .run("harness-setsid-hold", serde_json::json!({}), &[])
        .unwrap_err();
    let elapsed = started.elapsed();
    // The call returns a fail-closed reason well before the adapter's
    // own self-exit, proving the parent did not block on the held
    // pipe. Either the wall kill or the drain bound may fire first.
    assert!(
        matches!(error.code, "adapter_timeout" | "adapter_drain_timeout"),
        "unexpected code {error}"
    );
    assert!(
        elapsed < Duration::from_secs(8),
        "the parent took {elapsed:?}, it may have hung on the escaped descendant"
    );
}

#[cfg(target_os = "linux")]
fn pid_alive(pid: i32) -> bool {
    // signal 0 probes existence without delivering a signal. A killed
    // descendant may linger as a zombie until reaped by its own
    // parent, so treat only a live, non-zombie process as alive.
    use std::process::Command;
    let output = Command::new("ps")
        .args(["-o", "state=", "-p", &pid.to_string()])
        .output();
    match output {
        Ok(out) if out.status.success() => {
            let state = String::from_utf8_lossy(&out.stdout);
            let state = state.trim();
            // Empty means no such process. A leading Z is a zombie,
            // which is dead for our purposes.
            !state.is_empty() && !state.starts_with('Z')
        }
        _ => false,
    }
}

#[test]
fn a_non_literal_grant_refuses_the_run_at_spawn() {
    // The grant lists carry literal regular files only, re-asserted
    // right before every spawn: a directory or a symlink refuses the
    // run instead of widening the jail.
    let dir = tempfile::tempdir().unwrap();
    let backend = platform_backend().unwrap();
    let runner = Runner::with_grants(
        backend,
        worker_path(),
        brisk_limits(),
        vec![dir.path().to_path_buf()],
        Vec::new(),
    );
    let error = runner
        .run("harness-echo", serde_json::json!({}), &[])
        .unwrap_err();
    assert_eq!(error.code, "adapter_spawn_error", "{error}");
    assert!(error.message.contains("literal"), "{error}");

    let real = dir.path().join("real");
    std::fs::write(&real, b"bytes").unwrap();
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let backend = platform_backend().unwrap();
    let runner = Runner::with_grants(
        backend,
        worker_path(),
        brisk_limits(),
        Vec::new(),
        vec![link],
    );
    let error = runner
        .run("harness-echo", serde_json::json!({}), &[])
        .unwrap_err();
    assert_eq!(error.code, "adapter_spawn_error", "{error}");
    assert!(error.message.contains("symlink"), "{error}");
}

#[test]
fn a_ballooned_descendant_cannot_hide_behind_a_fast_leader_exit() {
    // The leader spawns a ballooning descendant, answers cleanly, and
    // exits at once, usually inside the first polling interval. The
    // final group measurement on leader exit is what must refuse the
    // response; a slower run is caught by the ordinary poll, and the
    // verdict is the same either way. The process ceiling is raised
    // because the cap counts every process of this user.
    let runner = runner_with(Limits {
        max_resident_bytes: Some(64 * 1024 * 1024),
        wall_timeout: Duration::from_secs(20),
        max_processes: 1024,
        ..brisk_limits()
    });
    let worker = worker_path();
    let error = runner
        .run(
            "harness-balloon-survivor",
            serde_json::json!({ "program": worker.to_str().unwrap() }),
            &[],
        )
        .unwrap_err();
    assert_eq!(error.code, "worker-memory-exceeded", "{error}");
}

#[test]
fn the_resident_memory_guard_kills_an_overshooting_worker() {
    // The balloon harness writes far more resident pages than this
    // ceiling and then holds without responding, so the parent's
    // process-group memory poll is what must end the invocation, well
    // before the wall clock. The drains stay attached through the
    // termination, which is why the error is the guard's own code and
    // never a drain timeout.
    let runner = runner_with(Limits {
        max_resident_bytes: Some(64 * 1024 * 1024),
        wall_timeout: Duration::from_secs(20),
        ..brisk_limits()
    });
    let started = std::time::Instant::now();
    let error = runner
        .run("harness-balloon", serde_json::json!({}), &[])
        .unwrap_err();
    assert_eq!(error.code, "worker-memory-exceeded", "{error}");
    assert!(
        started.elapsed() < Duration::from_secs(15),
        "the guard, not the wall clock, must end the balloon"
    );
}

#[test]
fn a_valid_request_and_response_round_trip_through_the_jail() {
    let response = runner()
        .run("harness-echo", serde_json::json!({"token": "abc"}), &[])
        .expect("harness-echo runs to completion");
    let ok = response.ok.expect("harness-echo succeeds");
    assert_eq!(ok.get("token").and_then(|v| v.as_str()), Some("abc"));
}

#[test]
fn a_staged_input_is_readable_only_by_bare_name() {
    // The runner writes inputs into the jail, so an adapter reads them
    // from its working directory. The echo mode does not read files,
    // but staging must not error, and a name with a path separator is
    // refused.
    let error = runner()
        .run(
            "harness-echo",
            serde_json::json!({}),
            &[("../escape", b"x" as &[u8])],
        )
        .unwrap_err();
    assert_eq!(error.code, "adapter_spawn_error", "{error}");
}

/// A high-numbered descriptor a host embedder holds without
/// close-on-exec must not survive into the adapter. macOS cannot
/// revoke an already-open descriptor through the sandbox, so the
/// helper's descriptor sweep is the guarantee, and it must reach a
/// descriptor above any fixed range. Linux enumerates `/proc/self/fd`
/// and is covered by the same sweep, so this case runs on macOS.
#[cfg(target_os = "macos")]
#[test]
fn a_high_inherited_descriptor_does_not_reach_the_adapter() {
    use std::os::fd::AsRawFd;

    // Open a real file and duplicate it onto a high descriptor with
    // close-on-exec cleared, the shape of a descriptor an embedder
    // leaves open when it calls in. dup2 places the copy at the target
    // number and clears its close-on-exec flag, so without the sweep
    // it would inherit. An integration test may use unsafe; the
    // library crate stays unsafe-free.
    let file = std::fs::File::open("/etc/hosts").expect("open a host file");
    const HIGH_FD: i32 = 900;
    let copied = unsafe { nix::libc::dup2(file.as_raw_fd(), HIGH_FD) };
    assert_eq!(copied, HIGH_FD, "dup onto a high fd failed");

    let response = runner()
        .run(
            "harness-fd-check",
            serde_json::json!({ "fd": HIGH_FD }),
            &[],
        )
        .expect("harness-fd-check runs to completion");

    // Close our copy regardless of the outcome.
    unsafe {
        nix::libc::close(HIGH_FD);
    }

    let ok = response.ok.expect("harness-fd-check succeeds");
    let open = ok.get("open").and_then(|v| v.as_bool()).unwrap_or(true);
    assert!(
        !open,
        "a high inherited descriptor reached the adapter, the sweep missed it"
    );
}
