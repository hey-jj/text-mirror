//! Parent-side aggregate resident-memory measurement over a worker's
//! whole process group.
//!
//! The jailed worker is not the main memory consumer on the engine
//! paths: the exec'd engine child maps the weights and holds the
//! working set. A direct-child-only reading would miss those pages, so
//! the monitor enumerates the child's process group and sums resident
//! bytes over every member with checked arithmetic. A failed query is
//! a runner failure, never a silent pass: the caller kills the group
//! and fails closed with `memory-monitor-failed`.

/// The aggregate resident bytes of every process in the group led by
/// `leader`. An empty group sums to zero, which callers read as the
/// group having exited.
#[cfg(target_os = "macos")]
pub(super) fn group_resident_bytes(leader: u32) -> Result<u64, String> {
    use libproc::pid_rusage::{RUsageInfoV2, pidrusage};
    use libproc::processes::{ProcFilter, pids_by_type};

    let members = pids_by_type(ProcFilter::ByProgramGroup { pgrpid: leader })
        .map_err(|e| format!("cannot enumerate the process group: {e}"))?;
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
                // the query, which is an ordinary race. Only a member
                // still in the group is a real query failure.
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
/// `leader`, from the `/proc` view: a process belongs when the third
/// field after its `stat` comm is the leader's id, and its resident
/// size is the `VmRSS` line of its `status` file. A process that
/// vanishes mid-scan is an ordinary race and is skipped; a process
/// whose records cannot be parsed fails the query.
#[cfg(target_os = "linux")]
pub(super) fn group_resident_bytes(leader: u32) -> Result<u64, String> {
    let entries = std::fs::read_dir("/proc").map_err(|e| format!("cannot enumerate /proc: {e}"))?;
    let mut total: u64 = 0;
    for entry in entries {
        let entry = entry.map_err(|e| format!("cannot enumerate /proc: {e}"))?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        // A vanished process between listing and read is a race, not
        // a failure.
        let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
            continue;
        };
        let Some(pgrp) = stat_process_group(&stat) else {
            return Err(format!("cannot parse the stat record of process {pid}"));
        };
        if pgrp != leader {
            continue;
        }
        let Ok(status) = std::fs::read_to_string(format!("/proc/{pid}/status")) else {
            continue;
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

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub(super) fn group_resident_bytes(_leader: u32) -> Result<u64, String> {
    Err("no resident-memory monitor exists for this platform".to_string())
}

/// The process-group id from one `/proc/<pid>/stat` record: the third
/// whitespace field after the parenthesized comm, which itself may
/// contain spaces and parentheses, so the parse anchors on the last
/// closing parenthesis.
#[cfg(any(target_os = "linux", test))]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn stat_process_group(stat: &str) -> Option<u32> {
    let after_comm = &stat[stat.rfind(')')? + 1..];
    after_comm.split_whitespace().nth(2)?.parse().ok()
}

/// The `VmRSS` value of one `/proc/<pid>/status` record, in bytes.
/// `Ok(None)` when the line is absent, the zombie shape. A present
/// line that does not parse as kibibytes fails the query.
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
