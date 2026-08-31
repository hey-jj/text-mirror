//! Parent-side aggregate resident-memory measurement over a worker's
//! whole process group.
//!
//! The jailed worker is not the main memory consumer on the engine
//! paths: the exec'd engine child maps the weights and holds the
//! working set. A direct-child-only reading would miss those pages, so
//! the monitor enumerates the child's process group and sums resident
//! bytes over every member with checked arithmetic. A failed query is
//! a runner failure, never a silent pass: the caller kills the group
//! and fails closed with `memory-monitor-failed`. The one tolerated
//! read failure is a confirmed exit race, a member that is provably
//! gone by the time its records are read.

/// The aggregate resident bytes of every process in the group led by
/// `leader`. An empty group sums to zero, which callers read as the
/// group having exited.
#[cfg(target_os = "macos")]
pub(super) fn group_resident_bytes(leader: u32) -> Result<u64, String> {
    use libproc::pid_rusage::{RUsageInfoV2, pidrusage};
    use libproc::processes::{ProcFilter, pids_by_type};

    let members = match pids_by_type(ProcFilter::ByProgramGroup { pgrpid: leader }) {
        Ok(members) => members,
        Err(e) => {
            // Enumerating a group that has fully exited can fail
            // instead of listing empty. Only a confirmed absence is
            // that shape: a zero-signal probe that finds no such group
            // sums to zero, and anything else fails the query closed,
            // because a live group the guard cannot enumerate is a
            // group it cannot bound.
            let Ok(leader_pid) = i32::try_from(leader) else {
                return Err(format!("group leader pid {leader} does not fit a pid_t"));
            };
            return match nix::sys::signal::killpg(nix::unistd::Pid::from_raw(leader_pid), None) {
                Err(nix::errno::Errno::ESRCH) => Ok(0),
                _ => Err(format!("cannot enumerate the process group: {e}")),
            };
        }
    };
    let mut total: u64 = 0;
    for pid in &members {
        let Ok(pid_i32) = i32::try_from(*pid) else {
            return Err(format!("group member pid {pid} does not fit a pid_t"));
        };
        match pidrusage::<RUsageInfoV2>(pid_i32) {
            Ok(usage) => {
                total = total
                    .checked_add(usage.ri_resident_size)
                    .ok_or_else(|| "the resident-size sum overflowed".to_string())?;
            }
            Err(e) => {
                // The member may have exited between the listing and
                // the query. Only a confirmed exit is a race: a member
                // a fresh listing still names is a real query failure,
                // and the guard fails closed on it.
                let still = pids_by_type(ProcFilter::ByProgramGroup { pgrpid: leader })
                    .map_err(|e| format!("cannot re-enumerate the process group: {e}"))?;
                if still.contains(pid) {
                    return Err(format!("cannot read a group member's resident size: {e}"));
                }
            }
        }
    }
    Ok(total)
}

/// The aggregate resident bytes of every process in the group led by
/// `leader`, from the `/proc` view.
#[cfg(target_os = "linux")]
pub(super) fn group_resident_bytes(leader: u32) -> Result<u64, String> {
    let entries = std::fs::read_dir("/proc").map_err(|e| format!("cannot enumerate /proc: {e}"))?;
    let mut pids = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| format!("cannot enumerate /proc: {e}"))?;
        if let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        {
            pids.push(pid);
        }
    }
    sum_group_records(
        leader,
        &pids,
        |pid, file| std::fs::read_to_string(format!("/proc/{pid}/{file}")),
        |pid| std::fs::exists(format!("/proc/{pid}")),
    )
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub(super) fn group_resident_bytes(_leader: u32) -> Result<u64, String> {
    Err("no resident-memory monitor exists for this platform".to_string())
}

/// The record-view summation with injected readers, so the error
/// discipline is testable on every platform. A process belongs to the
/// group when the third field after its `stat` comm names the leader,
/// and its resident size is the `VmRSS` line of its `status` record.
///
/// The error discipline is strict: only a NotFound read error,
/// confirmed by a re-check that itself succeeds and reports the
/// process gone, counts as an exit race and is skipped. Every other
/// error kind, a NotFound for a process the re-check still sees, and
/// a re-check that fails at all, fail the whole query closed, because
/// a member whose memory cannot be read is a member the guard cannot
/// bound.
#[cfg(any(target_os = "linux", test))]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn sum_group_records(
    leader: u32,
    pids: &[u32],
    read: impl Fn(u32, &str) -> std::io::Result<String>,
    still_exists: impl Fn(u32) -> std::io::Result<bool>,
) -> Result<u64, String> {
    let mut total: u64 = 0;
    for &pid in pids {
        let stat = match read(pid, "stat") {
            Ok(stat) => stat,
            Err(e) => {
                confirmed_exit_race(pid, &e, &still_exists)?;
                continue;
            }
        };
        let Some(pgrp) = stat_process_group(&stat) else {
            return Err(format!("cannot parse the stat record of process {pid}"));
        };
        if pgrp != leader {
            continue;
        }
        let status = match read(pid, "status") {
            Ok(status) => status,
            Err(e) => {
                confirmed_exit_race(pid, &e, &still_exists)?;
                continue;
            }
        };
        // A zombie member holds no resident pages and carries no VmRSS
        // line, which reads as zero.
        let bytes = vm_rss_bytes(&status)?.unwrap_or(0);
        total = total
            .checked_add(bytes)
            .ok_or_else(|| "the resident-size sum overflowed".to_string())?;
    }
    Ok(total)
}

/// Passes only for the confirmed exit race: a NotFound error for a
/// process the confirming re-check successfully reports gone. A
/// re-check that itself errors is indeterminate and fails the query
/// closed, exactly like every non-NotFound read error: the guard
/// never treats a member it cannot see as a member that exited.
#[cfg(any(target_os = "linux", test))]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn confirmed_exit_race(
    pid: u32,
    error: &std::io::Error,
    still_exists: &impl Fn(u32) -> std::io::Result<bool>,
) -> Result<(), String> {
    if error.kind() == std::io::ErrorKind::NotFound {
        match still_exists(pid) {
            Ok(false) => return Ok(()),
            Ok(true) => {}
            Err(recheck) => {
                return Err(format!(
                    "cannot re-check process {pid} after a read failure: {recheck}"
                ));
            }
        }
    }
    Err(format!("cannot read the records of process {pid}: {error}"))
}

/// The process-group id from one `stat` record: the third whitespace
/// field after the parenthesized comm, which itself may contain
/// spaces and parentheses, so the parse anchors on the last closing
/// parenthesis.
#[cfg(any(target_os = "linux", test))]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn stat_process_group(stat: &str) -> Option<u32> {
    let after_comm = &stat[stat.rfind(')')? + 1..];
    after_comm.split_whitespace().nth(2)?.parse().ok()
}

/// The `VmRSS` value of one `status` record, in bytes. `Ok(None)`
/// when the line is absent, the zombie shape. A present line that
/// does not parse as kibibytes fails the query.
#[cfg(any(target_os = "linux", test))]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn vm_rss_bytes(status: &str) -> Result<Option<u64>, String> {
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            let mut fields = rest.split_whitespace();
            let value: u64 = fields
                .next()
                .and_then(|v| v.parse().ok())
                .ok_or_else(|| "cannot parse a VmRSS value".to_string())?;
            if fields.next() != Some("kB") {
                return Err("a VmRSS line is not in kibibytes".to_string());
            }
            return value
                .checked_mul(1024)
                .map(Some)
                .ok_or_else(|| "a VmRSS value overflowed".to_string());
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Error, ErrorKind};

    #[test]
    fn the_stat_parse_survives_a_hostile_comm() {
        // A comm with spaces and a closing parenthesis: the parse
        // anchors on the LAST ')'.
        let stat = "1234 (evil) name)) R 1 5678 9012 0 -1";
        assert_eq!(stat_process_group(stat), Some(5678));
        assert_eq!(stat_process_group("garbage"), None);
    }

    #[test]
    fn vm_rss_parses_and_fails_closed_on_a_malformed_line() {
        let status = "Name:\tworker\nVmRSS:\t  2048 kB\nThreads:\t1\n";
        assert_eq!(vm_rss_bytes(status).unwrap(), Some(2048 * 1024));
        // Absent line is the zombie shape, zero bytes.
        assert_eq!(vm_rss_bytes("Name:\tworker\n").unwrap(), None);
        // A present but malformed line fails the query.
        assert!(vm_rss_bytes("VmRSS:\tnonsense kB\n").is_err());
        assert!(vm_rss_bytes("VmRSS:\t12 mB\n").is_err());
    }

    /// A two-member record view: a group member with 2 MiB resident
    /// and a stranger in another group.
    fn read_two(pid: u32, file: &str) -> std::io::Result<String> {
        Ok(match (pid, file) {
            (10, "stat") => "10 (worker) S 1 77 1".to_string(),
            (10, "status") => "VmRSS:\t2048 kB\n".to_string(),
            (11, "stat") => "11 (other) S 1 99 1".to_string(),
            (11, "status") => "VmRSS:\t4096 kB\n".to_string(),
            _ => return Err(Error::new(ErrorKind::NotFound, "no such process")),
        })
    }

    #[test]
    fn the_summation_counts_only_the_leaders_group() {
        let total = sum_group_records(77, &[10, 11], read_two, |_| Ok(true)).unwrap();
        assert_eq!(total, 2048 * 1024);
    }

    #[test]
    fn only_a_confirmed_exit_race_is_skipped() {
        // NotFound plus a re-check that no longer sees the process:
        // the ordinary exit race, skipped, the rest still summed.
        let total = sum_group_records(77, &[10, 12], read_two, |pid| Ok(pid != 12)).unwrap();
        assert_eq!(total, 2048 * 1024);

        // NotFound for a process the re-check STILL sees: the guard
        // cannot bound that member, so the query fails closed.
        let error = sum_group_records(77, &[10, 12], read_two, |_| Ok(true))
            .expect_err("an unconfirmed read failure must fail the query");
        assert!(error.contains("12"), "{error}");
    }

    #[test]
    fn an_indeterminate_recheck_fails_the_query_closed() {
        // NotFound from the record read, and the confirming re-check
        // itself errors: the guard cannot tell an exit from a member
        // it is not allowed to see, so the query fails closed rather
        // than treating the member as gone.
        let error = sum_group_records(77, &[10, 12], read_two, |_| {
            Err(Error::new(ErrorKind::PermissionDenied, "re-check denied"))
        })
        .expect_err("an indeterminate re-check must fail the query");
        assert!(error.contains("re-check"), "{error}");
    }

    #[test]
    fn every_other_error_kind_fails_the_query_closed() {
        let denied = |pid: u32, file: &str| -> std::io::Result<String> {
            if pid == 12 {
                return Err(Error::new(ErrorKind::PermissionDenied, "denied"));
            }
            read_two(pid, file)
        };
        // PermissionDenied never counts as a race, whatever the
        // re-check says: a live member the guard cannot read is an
        // unbounded member.
        let error = sum_group_records(77, &[10, 12], denied, |_| Ok(false))
            .expect_err("a denied read must fail the query");
        assert!(error.contains("denied"), "{error}");
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn the_current_process_group_measures_nonzero() {
        // This test process belongs to its own process group and holds
        // resident pages, so the group sum is positive.
        let group = u32::try_from(nix::unistd::getpgrp().as_raw()).unwrap();
        let total = group_resident_bytes(group).unwrap();
        assert!(total > 0, "the group sum was {total}");
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn an_empty_group_sums_to_zero() {
        // No process group with this id exists (pid_max-adjacent ids
        // are not allocated to a group we could observe): the sum is
        // zero rather than an error, which the caller reads as the
        // group having exited.
        let total = group_resident_bytes(u32::MAX - 7).unwrap();
        assert_eq!(total, 0);
    }
}
