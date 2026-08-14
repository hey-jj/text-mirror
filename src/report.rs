//! JSON summary types the CLI verbs emit.

use serde::{Deserialize, Serialize};

use crate::manifest::Record;

/// Inventory of one detected format in a scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormatCount {
    /// Format id.
    pub format: String,
    /// Number of files.
    pub files: u64,
    /// Total size in bytes.
    pub bytes: u64,
}

/// A file whose size stands out from the rest of the tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SizeOutlier {
    /// Path relative to the scanned root.
    pub path: String,
    /// Size in bytes.
    pub bytes: u64,
    /// Detected format id.
    pub format: String,
}

/// The `scan` verb output. A dry-run inventory of a division root.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    /// The scanned root.
    pub root: String,
    /// Version of the rules files used for detection.
    pub rules_version: String,
    /// Total number of files.
    pub files: u64,
    /// Total size in bytes.
    pub bytes: u64,
    /// Per-format counts, sorted by format id.
    pub formats: Vec<FormatCount>,
    /// Size outliers, largest first.
    pub outliers: Vec<SizeOutlier>,
}

/// Terminal record counts by status.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StatusCounts {
    /// Sources with a fresh text artifact.
    pub converted: u64,
    /// Sources whose conversion failed.
    pub failed: u64,
    /// Sources no converter claims.
    pub unsupported: u64,
    /// Sources skipped because the checkpoint key matched.
    pub skipped_unchanged: u64,
    /// Sources deduplicated against an identical source.
    pub dedup: u64,
}

/// The `run` verb output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunReport {
    /// The division that ran.
    pub division: String,
    /// The division root.
    pub root: String,
    /// Number of walked sources that received a manifest record.
    pub sources: u64,
    /// Walked entries with no manifest representation yet, meaning
    /// FIFOs, sockets, and other special files.
    pub special_entries: u64,
    /// Outcome counts for this run.
    pub counts: StatusCounts,
    /// Non-fatal findings, such as a discarded torn manifest line.
    pub warnings: Vec<String>,
}

/// Coverage for one division, computed over terminal records.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DivisionStatus {
    /// Division name, from the shard file name.
    pub division: String,
    /// Number of distinct source paths.
    pub sources: u64,
    /// Sources whose terminal record carries a text artifact.
    pub with_text: u64,
    /// `with_text` over `sources`, 0.0 for an empty shard.
    pub coverage: f64,
    /// Terminal record counts by status.
    pub counts: StatusCounts,
    /// Non-fatal reader findings for this shard.
    pub warnings: Vec<String>,
}

/// The `status` verb output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusReport {
    /// One entry per division shard, sorted by division name.
    pub divisions: Vec<DivisionStatus>,
}

/// One manifest record with the division shard it came from.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExplainEntry {
    /// Division name, from the shard file name.
    pub division: String,
    /// The record as written.
    pub record: Record,
}
