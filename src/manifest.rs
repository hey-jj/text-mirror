//! Serde types for the manifest schema `text-mirror/manifest@1`, the
//! append-only JSONL writer, and the shard reader.
//!
//! The manifest is the public interface of this crate. Each division
//! writes one shard, `manifest/<division>.jsonl`. One line is one
//! [`Record`]. Shards are append-only, and the latest record for a
//! source path is its terminal outcome.
//!
//! Every record self-describes its schema in its first field, so a
//! shard separated from its bundle stays verifiable. A consumer must
//! reject any record whose `schema` value it does not recognize.
//! [`ManifestSchema`] enforces both rules at the serde layer, and
//! records reject unknown fields, so an additive change is a breaking
//! change that bumps the schema version.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{Error, Result};

/// The schema identifier carried by every manifest@1 record.
pub const MANIFEST_SCHEMA: &str = "text-mirror/manifest@1";

/// The `schema` field of a [`Record`].
///
/// Serializes to the literal `text-mirror/manifest@1`. Deserialization
/// rejects every other value, so a consumer of these types fails
/// closed on a schema version it does not recognize.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ManifestSchema;

impl Serialize for ManifestSchema {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(MANIFEST_SCHEMA)
    }
}

impl<'de> Deserialize<'de> for ManifestSchema {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        if value == MANIFEST_SCHEMA {
            Ok(ManifestSchema)
        } else {
            Err(D::Error::custom(format!(
                "unrecognized schema {value:?}, this consumer accepts only {MANIFEST_SCHEMA:?}"
            )))
        }
    }
}

/// The outcome recorded for one source file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// A converter produced a text artifact.
    Converted,
    /// A converter ran and failed. `error` names the reason.
    Failed,
    /// No converter claims the detected format.
    Unsupported,
    /// The checkpoint key matched a prior record, so no work was done.
    SkippedUnchanged,
    /// The source hash matched an already converted source. The text
    /// artifact is a copy, and `dedup_of` names the canonical source.
    Dedup,
}

/// How a text artifact was derived from its source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    /// Text extracted or passed through from a text-bearing source.
    Text,
    /// A transcript derived from audio or video.
    Transcript,
    /// Text recognized from images.
    Ocr,
    /// A combination of the other kinds.
    Mixed,
}

/// Media provenance for artifacts derived from audio or video.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Media {
    /// Source duration in seconds.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub duration_seconds: Option<f64>,
    /// Detected language tag.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub language: Option<String>,
    /// Transcription model id.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub model_id: Option<String>,
    /// Hash of the transcription model.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub model_hash: Option<String>,
    /// Hash of the pinned decode options.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub decode_options_hash: Option<String>,
    /// Number of distinct speakers.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub speaker_count: Option<u32>,
}

/// One manifest@1 record. One line of a JSONL shard.
///
/// Field names and their JSON spellings are the frozen contract.
/// Unknown fields are rejected on read.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    /// The literal string `text-mirror/manifest@1`, always first.
    pub schema: ManifestSchema,
    /// Source path relative to the division root.
    pub source_path: String,
    /// Lowercase hex BLAKE3 hash of the source bytes.
    pub source_hash: String,
    /// Source size in bytes.
    pub source_size: u64,
    /// Format id the file extension declares, when known.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub declared_format: Option<String>,
    /// Resolved format id from detection.
    pub detected_format: String,
    /// True when magic bytes and the extension disagree.
    pub format_mismatch: bool,
    /// The recorded outcome.
    pub status: Status,
    /// Text artifact path relative to the mirror root, beginning with
    /// the record's division segment: `<division>/<source_path>.txt`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub text_path: Option<String>,
    /// Lowercase hex BLAKE3 hash of the text artifact bytes.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub text_hash: Option<String>,
    /// How the artifact was derived.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub artifact_kind: Option<ArtifactKind>,
    /// Converter that handled the source.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub converter_id: Option<String>,
    /// Version of that converter.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub converter_version: Option<String>,
    /// Version of an external tool the converter wrapped, when any.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub tool_version: Option<String>,
    /// Version of the rules files the run used.
    pub rules_version: String,
    /// Media provenance for transcript artifacts.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub media: Option<Media>,
    /// Container source this record was expanded from, when any.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub parent_source: Option<String>,
    /// Canonical source path for a `dedup` record.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub dedup_of: Option<String>,
    /// Non-fatal notes from conversion.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub warnings: Vec<String>,
    /// Machine-readable reason for a `failed` record, or the declared
    /// capability gap on an `unsupported` record. Forbidden on every
    /// other status.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub error: Option<String>,
    /// Wall-clock milliseconds spent on this source.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub duration_ms: Option<u64>,
}

fn status_name(status: Status) -> &'static str {
    match status {
        Status::Converted => "converted",
        Status::Failed => "failed",
        Status::Unsupported => "unsupported",
        Status::SkippedUnchanged => "skipped_unchanged",
        Status::Dedup => "dedup",
    }
}

impl Record {
    /// Checks the cross-field invariants of the schema.
    ///
    /// A record with a text-bearing status must carry `text_path` and
    /// `text_hash`. A `failed` or `unsupported` record must not. A
    /// `dedup` record must name `dedup_of`, and a `failed` record must
    /// name `error`. An `unsupported` record may carry `error` to name
    /// a declared capability gap, such as a spreadsheet format with no
    /// visibility reader yet.
    pub fn validate(&self) -> std::result::Result<(), String> {
        let name = status_name(self.status);
        match self.status {
            Status::Converted | Status::SkippedUnchanged | Status::Dedup => {
                if self.text_path.is_none() || self.text_hash.is_none() {
                    return Err(format!("status {name} requires text_path and text_hash"));
                }
                if self.error.is_some() {
                    return Err(format!("status {name} forbids error"));
                }
            }
            Status::Failed | Status::Unsupported => {
                if self.text_path.is_some() || self.text_hash.is_some() {
                    return Err(format!("status {name} forbids text_path and text_hash"));
                }
            }
        }
        if self.status == Status::Dedup && self.dedup_of.is_none() {
            return Err("status dedup requires dedup_of".to_string());
        }
        if self.status == Status::Failed && self.error.is_none() {
            return Err("status failed requires error".to_string());
        }
        Ok(())
    }
}

/// Appends records to a JSONL shard. One record per line, LF only.
pub struct ManifestWriter {
    path: PathBuf,
    file: File,
}

impl ManifestWriter {
    /// Opens a shard for append, creating parent directories.
    ///
    /// A record never starts on a line that lacks a trailing LF. When
    /// the existing shard ends mid-line, a complete final record gets
    /// its missing LF, and a torn partial tail from a killed run is
    /// dropped so the next run re-records that source.
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir).map_err(|e| Error::io("create_dir", dir, e))?;
        }
        repair_tail(path)?;
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| Error::io("open", path, e))?;
        Ok(ManifestWriter {
            path: path.to_path_buf(),
            file,
        })
    }

    /// Serializes one record and appends it as one line.
    pub fn append(&mut self, record: &Record) -> Result<()> {
        let mut line = serde_json::to_string(record).map_err(|e| Error::Encode {
            path: self.path.clone(),
            message: e.to_string(),
        })?;
        line.push('\n');
        self.file
            .write_all(line.as_bytes())
            .map_err(|e| Error::io("append", &self.path, e))?;
        self.file
            .flush()
            .map_err(|e| Error::io("flush", &self.path, e))?;
        Ok(())
    }
}

fn repair_tail(path: &Path) -> Result<()> {
    let content = match fs::read(path) {
        Ok(content) => content,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(Error::io("read", path, e)),
    };
    if content.is_empty() || content.ends_with(b"\n") {
        return Ok(());
    }
    let keep = content
        .iter()
        .rposition(|b| *b == b'\n')
        .map(|position| position + 1)
        .unwrap_or(0);
    let tail = &content[keep..];
    if parse_record(tail).is_ok() {
        let mut file = OpenOptions::new()
            .append(true)
            .open(path)
            .map_err(|e| Error::io("open", path, e))?;
        file.write_all(b"\n")
            .map_err(|e| Error::io("append", path, e))?;
    } else {
        let file = OpenOptions::new()
            .write(true)
            .open(path)
            .map_err(|e| Error::io("open", path, e))?;
        file.set_len(keep as u64)
            .map_err(|e| Error::io("truncate", path, e))?;
    }
    Ok(())
}

/// One shard's records plus reader warnings.
#[derive(Debug, Clone)]
pub struct Shard {
    /// The records, in append order.
    pub records: Vec<Record>,
    /// Non-fatal reader findings, such as a discarded torn tail.
    pub warnings: Vec<String>,
}

fn parse_record(line: &[u8]) -> std::result::Result<Record, String> {
    let text = std::str::from_utf8(line)
        .map_err(|e| format!("invalid UTF-8 at byte {}", e.valid_up_to()))?;
    if text.ends_with('\r') {
        return Err("carriage return before line ending, shards are LF only".to_string());
    }
    let record: Record = serde_json::from_str(text).map_err(|e| e.to_string())?;
    record.validate()?;
    Ok(record)
}

/// Reads every record from a shard in order.
///
/// The shard is read as bytes and split on LF, then each line decodes
/// on its own, so damage to one line never hides the rest. A malformed
/// complete line, invalid UTF-8, an unknown field, an unrecognized
/// schema value, a carriage return, or a cross-field invariant
/// violation fails the whole read and names the line. The one
/// tolerated defect is a torn final line without a trailing LF, the
/// footprint of a killed run, whether it breaks mid-record or
/// mid-character. It is dropped with a warning, and the next run
/// re-records the affected source.
pub fn read_shard(path: &Path) -> Result<Shard> {
    let content = fs::read(path).map_err(|e| Error::io("read", path, e))?;
    let mut records = Vec::new();
    let mut warnings = Vec::new();
    if content.is_empty() {
        return Ok(Shard { records, warnings });
    }
    let ends_with_lf = content.ends_with(b"\n");
    let mut lines: Vec<&[u8]> = content.split(|byte| *byte == b'\n').collect();
    if ends_with_lf {
        lines.pop();
    }
    let count = lines.len();
    for (index, line) in lines.iter().enumerate() {
        let number = index + 1;
        let partial = !ends_with_lf && number == count;
        match parse_record(line) {
            Ok(record) => records.push(record),
            Err(_) if partial => {
                warnings.push(format!("discarded torn final line {number}"));
            }
            Err(message) => {
                return Err(Error::Manifest {
                    path: path.to_path_buf(),
                    line: number,
                    message,
                });
            }
        }
    }
    Ok(Shard { records, warnings })
}

/// Reads a shard with no torn-line tolerance.
///
/// The producer's own resume path tolerates one torn final line, the
/// footprint of a killed run. A bundle must not: a torn tail means an
/// interrupted run and a possibly incomplete division, so packaging
/// and receiving both refuse it. Every line must parse as a complete
/// record and the shard must end with a newline, the clean-write
/// property bundle@1 declares.
pub fn read_shard_strict(path: &Path) -> Result<Vec<Record>> {
    let bytes = fs::read(path).map_err(|e| Error::io("read", path, e))?;
    if !bytes.is_empty() && !bytes.ends_with(b"\n") {
        return Err(Error::Manifest {
            path: path.to_path_buf(),
            line: 0,
            message: "shard does not end with a newline, resume the run to complete the division"
                .to_string(),
        });
    }
    let shard = read_shard(path)?;
    if let Some(warning) = shard.warnings.first() {
        return Err(Error::Manifest {
            path: path.to_path_buf(),
            line: 0,
            message: format!(
                "shard has a torn final line ({warning}), resume the run to complete the division"
            ),
        });
    }
    Ok(shard.records)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_record() -> Record {
        Record {
            schema: ManifestSchema,
            source_path: "docs/a.txt".to_string(),
            source_hash: "aa".to_string(),
            source_size: 5,
            declared_format: Some("text".to_string()),
            detected_format: "text".to_string(),
            format_mismatch: false,
            status: Status::Converted,
            text_path: Some("docs/a.txt.txt".to_string()),
            text_hash: Some("bb".to_string()),
            artifact_kind: Some(ArtifactKind::Text),
            converter_id: Some("text-passthrough".to_string()),
            converter_version: Some("1.0.0".to_string()),
            tool_version: None,
            rules_version: "1".to_string(),
            media: None,
            parent_source: None,
            dedup_of: None,
            warnings: vec!["stripped leading byte order mark".to_string()],
            error: None,
            duration_ms: Some(3),
        }
    }

    #[test]
    fn record_roundtrips_through_json() {
        let record = sample_record();
        let json = serde_json::to_string(&record).unwrap();
        let back: Record = serde_json::from_str(&json).unwrap();
        assert_eq!(record, back);
    }

    #[test]
    fn schema_is_the_first_field() {
        let json = serde_json::to_string(&sample_record()).unwrap();
        assert!(json.starts_with(r#"{"schema":"text-mirror/manifest@1""#));
    }

    #[test]
    fn unknown_schema_values_are_rejected() {
        let json = serde_json::to_string(&sample_record()).unwrap();
        let bumped = json.replace("text-mirror/manifest@1", "text-mirror/manifest@2");
        let result: std::result::Result<Record, _> = serde_json::from_str(&bumped);
        let message = result.unwrap_err().to_string();
        assert!(message.contains("unrecognized schema"));
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let json = serde_json::to_string(&sample_record()).unwrap();
        let extended = json.replacen('{', r#"{"surprise":true,"#, 1);
        let result: std::result::Result<Record, _> = serde_json::from_str(&extended);
        assert!(result.is_err());
    }

    #[test]
    fn writer_appends_one_lf_terminated_line_per_record() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("division.jsonl");
        let mut writer = ManifestWriter::open(&path).unwrap();
        writer.append(&sample_record()).unwrap();
        let mut second = sample_record();
        second.source_path = "docs/b.txt".to_string();
        writer.append(&second).unwrap();
        drop(writer);

        let raw = std::fs::read_to_string(&path).unwrap();
        assert_eq!(raw.lines().count(), 2);
        assert!(raw.ends_with('\n'));
        assert!(!raw.contains('\r'));

        let shard = read_shard(&path).unwrap();
        assert!(shard.warnings.is_empty());
        assert_eq!(shard.records.len(), 2);
        assert_eq!(shard.records[0], sample_record());
        assert_eq!(shard.records[1].source_path, "docs/b.txt");
    }

    #[test]
    fn read_shard_names_the_bad_line() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("division.jsonl");
        let good = serde_json::to_string(&sample_record()).unwrap();
        std::fs::write(&path, format!("{good}\nnot json\n")).unwrap();
        let err = read_shard(&path).unwrap_err();
        assert!(err.to_string().contains("line 2"));
    }

    #[test]
    fn read_shard_tolerates_only_a_torn_final_line() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("division.jsonl");
        let good = serde_json::to_string(&sample_record()).unwrap();
        let torn = &good[..good.len() / 2];
        std::fs::write(&path, format!("{good}\n{torn}")).unwrap();

        let shard = read_shard(&path).unwrap();
        assert_eq!(shard.records.len(), 1);
        assert_eq!(shard.warnings.len(), 1);
        assert!(shard.warnings[0].contains("line 2"));

        // The same damage on a non-final line still fails the read.
        std::fs::write(&path, format!("{torn}\n{good}\n")).unwrap();
        let err = read_shard(&path).unwrap_err();
        assert!(err.to_string().contains("line 1"));
    }

    #[test]
    fn read_shard_accepts_a_complete_final_record_without_lf() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("division.jsonl");
        let good = serde_json::to_string(&sample_record()).unwrap();
        std::fs::write(&path, &good).unwrap();
        let shard = read_shard(&path).unwrap();
        assert_eq!(shard.records.len(), 1);
        assert!(shard.warnings.is_empty());
    }

    #[test]
    fn read_shard_strict_rejects_an_unterminated_final_record() {
        // The tolerant reader above accepts this shape for the
        // producer's resume path. The strict reader enforces the
        // clean-write property itself, with no caller byte checks.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("division.jsonl");
        let good = serde_json::to_string(&sample_record()).unwrap();
        std::fs::write(&path, &good).unwrap();
        let err = read_shard_strict(&path).unwrap_err();
        assert!(
            err.to_string().contains("does not end with a newline"),
            "{err}"
        );

        std::fs::write(&path, format!("{good}\n")).unwrap();
        assert_eq!(read_shard_strict(&path).unwrap().len(), 1);
    }

    #[test]
    fn writer_finishes_a_final_line_that_lacks_lf_before_appending() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("division.jsonl");
        let good = serde_json::to_string(&sample_record()).unwrap();
        std::fs::write(&path, &good).unwrap();

        let mut writer = ManifestWriter::open(&path).unwrap();
        let mut second = sample_record();
        second.source_path = "docs/b.txt".to_string();
        writer.append(&second).unwrap();
        drop(writer);

        let shard = read_shard(&path).unwrap();
        assert_eq!(shard.records.len(), 2);
        assert!(shard.warnings.is_empty());
    }

    #[test]
    fn writer_drops_a_torn_tail_before_appending() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("division.jsonl");
        let good = serde_json::to_string(&sample_record()).unwrap();
        let torn = &good[..good.len() / 2];
        std::fs::write(&path, format!("{good}\n{torn}")).unwrap();

        let mut writer = ManifestWriter::open(&path).unwrap();
        let mut second = sample_record();
        second.source_path = "docs/b.txt".to_string();
        writer.append(&second).unwrap();
        drop(writer);

        let shard = read_shard(&path).unwrap();
        assert!(shard.warnings.is_empty());
        assert_eq!(shard.records.len(), 2);
        assert_eq!(shard.records[1].source_path, "docs/b.txt");
    }

    #[test]
    fn read_shard_tolerates_a_tail_torn_inside_a_multibyte_character() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("division.jsonl");
        let mut accented = sample_record();
        accented.source_path = "R\u{e9}sum\u{e9}.txt".to_string();
        let line = serde_json::to_string(&accented).unwrap();
        let bytes = line.as_bytes();

        // Cut immediately after the 0xC3 lead byte of the first
        // multibyte character, the footprint of a killed mid-write.
        let lead = bytes.iter().position(|b| *b == 0xC3).unwrap();
        let good = serde_json::to_string(&sample_record()).unwrap();
        let mut damaged = format!("{good}\n").into_bytes();
        damaged.extend_from_slice(&bytes[..=lead]);
        std::fs::write(&path, &damaged).unwrap();

        let shard = read_shard(&path).unwrap();
        assert_eq!(shard.records.len(), 1);
        assert_eq!(shard.warnings.len(), 1);
        assert!(shard.warnings[0].contains("line 2"));

        // The writer repairs the same tail, and appends land clean.
        let mut writer = ManifestWriter::open(&path).unwrap();
        writer.append(&accented).unwrap();
        drop(writer);
        let shard = read_shard(&path).unwrap();
        assert!(shard.warnings.is_empty());
        assert_eq!(shard.records.len(), 2);
        assert_eq!(shard.records[1].source_path, "R\u{e9}sum\u{e9}.txt");
    }

    #[test]
    fn read_shard_rejects_invalid_utf8_on_a_complete_line() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("division.jsonl");
        let good = serde_json::to_string(&sample_record()).unwrap();
        let mut damaged = b"\xc3\x28 not a record\n".to_vec();
        damaged.extend_from_slice(format!("{good}\n").as_bytes());
        std::fs::write(&path, &damaged).unwrap();

        let err = read_shard(&path).unwrap_err();
        let message = err.to_string();
        assert!(message.contains("line 1"));
        assert!(message.contains("invalid UTF-8"));
    }

    #[test]
    fn read_shard_rejects_carriage_returns() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("division.jsonl");
        let good = serde_json::to_string(&sample_record()).unwrap();
        std::fs::write(&path, format!("{good}\r\n")).unwrap();
        let err = read_shard(&path).unwrap_err();
        let message = err.to_string();
        assert!(message.contains("line 1"));
        assert!(message.contains("carriage return"));
    }

    #[test]
    fn read_shard_rejects_cross_field_invariant_violations() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("division.jsonl");
        let good = serde_json::to_string(&sample_record()).unwrap();

        // A converted record with no text fields is a false success.
        let mut bare = sample_record();
        bare.text_path = None;
        bare.text_hash = None;
        let bad = serde_json::to_string(&bare).unwrap();
        std::fs::write(&path, format!("{good}\n{bad}\n")).unwrap();
        let err = read_shard(&path).unwrap_err();
        let message = err.to_string();
        assert!(message.contains("line 2"));
        assert!(message.contains("requires text_path"));

        // A failed record must carry a reason and no text fields.
        let mut failed = sample_record();
        failed.status = Status::Failed;
        failed.error = Some("invalid_utf8: invalid UTF-8 at byte 0".to_string());
        let bad = serde_json::to_string(&failed).unwrap();
        std::fs::write(&path, format!("{bad}\n")).unwrap();
        assert!(read_shard(&path).is_err());

        // A dedup record must name its canonical source.
        let mut dedup = sample_record();
        dedup.status = Status::Dedup;
        let bad = serde_json::to_string(&dedup).unwrap();
        std::fs::write(&path, format!("{bad}\n")).unwrap();
        assert!(read_shard(&path).is_err());
    }

    #[test]
    fn error_is_forbidden_on_success_statuses() {
        for status in [Status::Converted, Status::SkippedUnchanged, Status::Dedup] {
            let mut record = sample_record();
            record.status = status;
            if status == Status::Dedup {
                record.dedup_of = Some("other.txt".to_string());
            }
            record.error = Some("stray reason".to_string());
            let message = record.validate().unwrap_err();
            assert!(message.contains("forbids error"), "{message}");
        }

        // Unsupported may carry the declared capability gap.
        let mut unsupported = sample_record();
        unsupported.status = Status::Unsupported;
        unsupported.text_path = None;
        unsupported.text_hash = None;
        unsupported.error = Some("hidden-visibility-unresolved".to_string());
        unsupported.validate().unwrap();
    }
}
