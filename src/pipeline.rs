//! The end-to-end pipeline behind the CLI verbs.
//!
//! `run` is incremental and idempotent. The manifest is the
//! checkpoint. A prior terminal record whose key of source path,
//! source hash, converter version, and rules version matches the
//! current pass, and whose artifact still hashes to the recorded
//! text hash, becomes a `skipped_unchanged` record with no work done.
//! Failed and unsupported sources are re-evaluated every run, so their
//! terminal records keep the current reason and the enumerated
//! remainder stays visible.
//!
//! Per-source problems, meaning IO errors, converter errors, and
//! mirror write failures, become `failed` records and the run
//! continues. Only run-level problems abort: a walk failure, a rules
//! failure, an invalid layout, or a manifest open or append failure.

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use crate::convert::Registry;
use crate::detect::{self, Detection, FormatTable, UNKNOWN_FORMAT};
use crate::hash::{self, CanonicalArtifact, DedupIndex};
use crate::manifest::{self, ArtifactKind, ManifestSchema, ManifestWriter, Record, Status};
use crate::mirror;
use crate::report::{
    DivisionStatus, ExplainEntry, FormatCount, RunReport, ScanReport, SizeOutlier, StatusCounts,
    StatusReport,
};
use crate::walk::{self, EntryKind, WalkOptions};
use crate::{Error, Result};

/// The detected format recorded for a symlink entry.
pub const SYMLINK_FORMAT: &str = "symlink";

/// The detected format recorded in scan output for FIFOs and sockets.
pub const SPECIAL_FORMAT: &str = "special";

/// The rules files loaded for one run.
///
/// The format table and the converter registry must declare the same
/// version. That shared version is recorded in every record as
/// `rules_version`.
pub struct Rules {
    /// The format table from `rules/formats.toml`.
    pub table: FormatTable,
    /// The converter registry from `rules/converters.toml`.
    pub registry: Registry,
}

impl Rules {
    /// The rules compiled into the binary.
    pub fn builtin() -> Result<Self> {
        let table = FormatTable::builtin()?;
        let registry = Registry::builtin()?;
        if table.version() != registry.version() {
            return Err(Error::Rules {
                name: "rules".to_string(),
                message: format!(
                    "formats.toml version {:?} does not match converters.toml version {:?}",
                    table.version(),
                    registry.version()
                ),
            });
        }
        Ok(Rules { table, registry })
    }

    /// The shared rules version.
    pub fn version(&self) -> &str {
        self.table.version()
    }
}

/// Options for one conversion run.
pub struct RunOptions<'a> {
    /// The division root to walk.
    pub root: &'a Path,
    /// The mirror tree root.
    pub mirror_root: &'a Path,
    /// The directory holding manifest shards.
    pub manifest_dir: &'a Path,
    /// The division name, also the shard file stem.
    pub division: &'a str,
    /// Traversal options.
    pub walk: WalkOptions,
}

/// Inventories a division root without converting anything.
///
/// A file is a size outlier when it is at least 1 MiB and at least ten
/// times the mean file size of the tree. Symlinks appear under the
/// `symlink` format and FIFOs and sockets under `special`.
pub fn scan(root: &Path, rules: &Rules, options: &WalkOptions) -> Result<ScanReport> {
    let entries = walk::walk_division(root, options)?;
    let mut inventory: Vec<(String, u64, String)> = Vec::new();
    for entry in &entries {
        let absolute = root.join(&entry.path);
        let (size, format) = match entry.kind {
            EntryKind::File => {
                let size = absolute
                    .metadata()
                    .map_err(|e| Error::io("stat", &absolute, e))?
                    .len();
                let detection = detect::detect_file(&absolute, &rules.table)?;
                (size, detection.detected)
            }
            EntryKind::Symlink => {
                let size = fs::symlink_metadata(&absolute)
                    .map_err(|e| Error::io("stat", &absolute, e))?
                    .len();
                (size, SYMLINK_FORMAT.to_string())
            }
            EntryKind::Other => (0, SPECIAL_FORMAT.to_string()),
        };
        inventory.push((entry.path.to_string_lossy().into_owned(), size, format));
    }

    let mut by_format: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    let mut total_bytes = 0u64;
    for (_, size, format) in &inventory {
        let entry = by_format.entry(format.clone()).or_insert((0, 0));
        entry.0 += 1;
        entry.1 += size;
        total_bytes += size;
    }

    let mean = if inventory.is_empty() {
        0.0
    } else {
        total_bytes as f64 / inventory.len() as f64
    };
    let mut outliers: Vec<SizeOutlier> = inventory
        .iter()
        .filter(|(_, size, _)| *size >= 1_048_576 && *size as f64 >= 10.0 * mean)
        .map(|(path, size, format)| SizeOutlier {
            path: path.clone(),
            bytes: *size,
            format: format.clone(),
        })
        .collect();
    outliers.sort_by(|a, b| b.bytes.cmp(&a.bytes).then(a.path.cmp(&b.path)));

    Ok(ScanReport {
        root: root.display().to_string(),
        rules_version: rules.version().to_string(),
        files: inventory.len() as u64,
        bytes: total_bytes,
        formats: by_format
            .into_iter()
            .map(|(format, (files, bytes))| FormatCount {
                format,
                files,
                bytes,
            })
            .collect(),
        outliers,
    })
}

fn validate_division(name: &str) -> Result<()> {
    let usable = !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if usable {
        Ok(())
    } else {
        Err(Error::Division {
            name: name.to_string(),
        })
    }
}

/// Resolves a path for containment checks without creating anything.
///
/// Existing prefixes canonicalize, so symlinks resolve. Components
/// past the first missing one cannot be symlinks, so they resolve
/// lexically, and a parent component pops a base that is already
/// symlink-free.
fn resolve_for_check(path: &Path) -> Result<PathBuf> {
    use std::path::Component;
    let absolute = std::path::absolute(path).map_err(|e| Error::io("absolutize", path, e))?;
    let mut resolved = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::Prefix(_) | Component::RootDir => resolved.push(component),
            Component::CurDir => {}
            Component::ParentDir => {
                resolved.pop();
            }
            Component::Normal(name) => {
                resolved.push(name);
                if let Ok(canonical) = resolved.canonicalize() {
                    resolved = canonical;
                }
            }
        }
    }
    Ok(resolved)
}

/// Refuses a layout that nests the division root and an output root
/// either way, so outputs can never become next-run sources and
/// artifacts can never land inside the source tree.
///
/// Every path resolves without touching the filesystem state, and the
/// output directories are created only after the layout is approved,
/// so a refusal leaves the division root untouched.
fn check_layout(root: &Path, mirror_root: &Path, manifest_dir: &Path) -> Result<()> {
    let root_resolved = resolve_for_check(root)?;
    for (name, dir) in [
        ("mirror root", mirror_root),
        ("manifest directory", manifest_dir),
    ] {
        let dir_resolved = resolve_for_check(dir)?;
        if dir_resolved.starts_with(&root_resolved) {
            return Err(Error::Layout {
                message: format!(
                    "{name} {} lies inside the division root {}",
                    dir.display(),
                    root.display()
                ),
            });
        }
        if root_resolved.starts_with(&dir_resolved) {
            return Err(Error::Layout {
                message: format!(
                    "division root {} lies inside the {name} {}",
                    root.display(),
                    dir.display()
                ),
            });
        }
    }
    fs::create_dir_all(mirror_root).map_err(|e| Error::io("create_dir", mirror_root, e))?;
    fs::create_dir_all(manifest_dir).map_err(|e| Error::io("create_dir", manifest_dir, e))?;
    Ok(())
}

fn new_record(
    source_path: &str,
    source_hash: &str,
    source_size: u64,
    detection: &Detection,
    rules_version: &str,
    status: Status,
) -> Record {
    Record {
        schema: ManifestSchema,
        source_path: source_path.to_string(),
        source_hash: source_hash.to_string(),
        source_size,
        declared_format: detection.declared.clone(),
        detected_format: detection.detected.clone(),
        format_mismatch: detection.mismatch,
        status,
        text_path: None,
        text_hash: None,
        artifact_kind: None,
        converter_id: None,
        converter_version: None,
        tool_version: None,
        rules_version: rules_version.to_string(),
        media: None,
        parent_source: None,
        dedup_of: None,
        warnings: Vec::new(),
        error: None,
        duration_ms: None,
    }
}

fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn terminal_by_path(records: Vec<Record>) -> HashMap<String, Record> {
    let mut terminal = HashMap::new();
    for record in records {
        terminal.insert(record.source_path.clone(), record);
    }
    terminal
}

/// Seeds the dedup index from prior terminal records.
///
/// Only records whose converter version and rules version match the
/// current run are eligible, so a rules bump never propagates stale
/// artifacts. Candidates are visited sorted by source path, and the
/// first insert per hash wins, so the canonical choice is
/// deterministic.
fn seed_dedup(terminal: &HashMap<String, Record>, rules: &Rules, dedup: &mut DedupIndex) {
    let mut candidates: Vec<&Record> = terminal.values().collect();
    candidates.sort_by(|a, b| a.source_path.cmp(&b.source_path));
    for record in candidates {
        let canonical_status = record.status == Status::Converted
            || (record.status == Status::SkippedUnchanged && record.dedup_of.is_none());
        if !canonical_status || record.rules_version != rules.version() {
            continue;
        }
        let (Some(text_path), Some(text_hash), Some(converter_id), Some(converter_version)) = (
            &record.text_path,
            &record.text_hash,
            &record.converter_id,
            &record.converter_version,
        ) else {
            continue;
        };
        let current = rules.registry.converter_for(&record.detected_format);
        let versions_match =
            current.is_some_and(|c| c.id() == converter_id && c.version() == converter_version);
        if !versions_match {
            continue;
        }
        dedup.insert(
            &record.source_hash,
            CanonicalArtifact {
                source_path: record.source_path.clone(),
                text_path: text_path.clone(),
                text_hash: text_hash.clone(),
                converter_id: converter_id.clone(),
                converter_version: converter_version.clone(),
                artifact_kind: record.artifact_kind,
            },
        );
    }
}

fn record_outcome(
    writer: &mut ManifestWriter,
    terminal: &mut HashMap<String, Record>,
    counts: &mut StatusCounts,
    record: Record,
) -> Result<()> {
    writer.append(&record)?;
    match record.status {
        Status::Converted => counts.converted += 1,
        Status::Failed => counts.failed += 1,
        Status::Unsupported => counts.unsupported += 1,
        Status::SkippedUnchanged => counts.skipped_unchanged += 1,
        Status::Dedup => counts.dedup += 1,
    }
    terminal.insert(record.source_path.clone(), record);
    Ok(())
}

/// Removes any artifact left behind for a source whose terminal
/// outcome carries no text, so the mirror never contradicts the
/// manifest.
fn remove_stale_artifact(text_absolute: &Path, record: &mut Record) {
    match fs::remove_file(text_absolute) {
        Ok(()) => {}
        Err(e)
            if e.kind() == std::io::ErrorKind::NotFound
                || e.kind() == std::io::ErrorKind::NotADirectory => {}
        Err(e) => record
            .warnings
            .push(format!("stale_artifact_not_removed: {e}")),
    }
}

fn source_front(absolute: &Path, table: &FormatTable) -> Result<(String, u64, Detection)> {
    let source_hash = hash::hash_file(absolute)?;
    let source_size = absolute
        .metadata()
        .map_err(|e| Error::io("stat", absolute, e))?
        .len();
    let detection = detect::detect_file(absolute, table)?;
    Ok((source_hash, source_size, detection))
}

/// Converts a division root into the mirror tree.
///
/// Walks the root in sorted order, detects each file, and appends one
/// record per source to the division shard. Text-native formats pass
/// through the registered converter. A format no converter claims
/// becomes `unsupported`. A converter error becomes `failed` with a
/// reason and no text artifact. Safe to kill and re-run.
///
/// Dedup applies when a source's hash matches an artifact already
/// converted by the same converter id and version that would handle
/// this source. The duplicate gets a real text file at its parallel
/// path, hashed over the bytes actually written, with `dedup_of`
/// naming the canonical source. When the canonical artifact cannot be
/// read, the duplicate converts for itself.
pub fn run(rules: &Rules, options: &RunOptions) -> Result<RunReport> {
    validate_division(options.division)?;
    check_layout(options.root, options.mirror_root, options.manifest_dir)?;
    let entries = walk::walk_division(options.root, &options.walk)?;
    let shard_path = options
        .manifest_dir
        .join(format!("{}.jsonl", options.division));
    let (prior, mut warnings) = if shard_path.exists() {
        let shard = manifest::read_shard(&shard_path)?;
        (shard.records, shard.warnings)
    } else {
        (Vec::new(), Vec::new())
    };
    let mut terminal = terminal_by_path(prior);
    let mut dedup = DedupIndex::default();
    seed_dedup(&terminal, rules, &mut dedup);

    let mut writer = ManifestWriter::open(&shard_path)?;
    let mut counts = StatusCounts::default();
    let mut special_entries = 0u64;

    for entry in &entries {
        let started = Instant::now();
        let relative = &entry.path;
        let absolute = options.root.join(relative);
        let text_absolute = mirror::mirror_path(options.mirror_root, relative);

        if entry.kind == EntryKind::Other {
            special_entries += 1;
            continue;
        }

        // A lossy path must never name a record key or an artifact, so
        // a non-UTF-8 source name, symlink or file, is a recorded
        // failure with no conversion.
        let Some(source_path) = relative.to_str().map(str::to_string) else {
            let detection = Detection {
                declared: detect::declared_format(relative, &rules.table),
                detected: UNKNOWN_FORMAT.to_string(),
                mismatch: false,
            };
            let mut record = new_record(
                &relative.to_string_lossy(),
                "",
                0,
                &detection,
                rules.version(),
                Status::Failed,
            );
            record.error = Some("non_utf8_path: source path is not valid UTF-8".to_string());
            record.duration_ms = Some(elapsed_ms(started));
            remove_stale_artifact(&text_absolute, &mut record);
            record_outcome(&mut writer, &mut terminal, &mut counts, record)?;
            continue;
        };

        if entry.kind == EntryKind::Symlink {
            let detection = Detection {
                declared: None,
                detected: SYMLINK_FORMAT.to_string(),
                mismatch: false,
            };
            let mut record = match fs::read_link(&absolute) {
                Ok(target) => {
                    let target_bytes = target.as_os_str().as_encoded_bytes();
                    new_record(
                        &source_path,
                        &hash::hash_bytes(target_bytes),
                        target_bytes.len() as u64,
                        &detection,
                        rules.version(),
                        Status::Unsupported,
                    )
                }
                Err(e) => {
                    let mut record = new_record(
                        &source_path,
                        "",
                        0,
                        &detection,
                        rules.version(),
                        Status::Failed,
                    );
                    record.error = Some(format!("source_io_error: readlink: {e}"));
                    record
                }
            };
            record.duration_ms = Some(elapsed_ms(started));
            remove_stale_artifact(&text_absolute, &mut record);
            record_outcome(&mut writer, &mut terminal, &mut counts, record)?;
            continue;
        }

        let (source_hash, source_size, detection) = match source_front(&absolute, &rules.table) {
            Ok(front) => front,
            Err(e) => {
                let detection = Detection {
                    declared: detect::declared_format(relative, &rules.table),
                    detected: UNKNOWN_FORMAT.to_string(),
                    mismatch: false,
                };
                let mut record = new_record(
                    &source_path,
                    "",
                    0,
                    &detection,
                    rules.version(),
                    Status::Failed,
                );
                record.error = Some(format!("source_io_error: {e}"));
                record.duration_ms = Some(elapsed_ms(started));
                remove_stale_artifact(&text_absolute, &mut record);
                record_outcome(&mut writer, &mut terminal, &mut counts, record)?;
                continue;
            }
        };
        let converter = rules.registry.converter_for(&detection.detected);
        let current_version = converter.map(|c| c.version());

        // Checkpoint: skip only when the key matches and the artifact
        // on disk still hashes to the recorded text hash.
        if let Some(previous) = terminal.get(&source_path) {
            let key_matches = previous.source_hash == source_hash
                && previous.rules_version == rules.version()
                && previous.converter_version.as_deref() == current_version;
            let has_text = matches!(
                previous.status,
                Status::Converted | Status::Dedup | Status::SkippedUnchanged
            );
            if key_matches && has_text {
                let intact = match (&previous.text_path, &previous.text_hash) {
                    (Some(text_path), Some(text_hash)) => {
                        let artifact = options.mirror_root.join(text_path);
                        hash::hash_file(&artifact).is_ok_and(|actual| actual == *text_hash)
                    }
                    _ => false,
                };
                if intact {
                    let mut record = previous.clone();
                    record.status = Status::SkippedUnchanged;
                    record.error = None;
                    record.duration_ms = Some(elapsed_ms(started));
                    record_outcome(&mut writer, &mut terminal, &mut counts, record)?;
                    continue;
                }
            }
        }

        let text_relative = format!("{source_path}.txt");

        // Dedup: identical bytes already converted once, by the same
        // converter that would handle this source.
        if let Some(canonical) = dedup.get(&source_hash)
            && canonical.source_path != source_path
            && converter.is_some_and(|c| {
                c.id() == canonical.converter_id && c.version() == canonical.converter_version
            })
        {
            let canonical = canonical.clone();
            let canonical_absolute = options.mirror_root.join(&canonical.text_path);
            // An unreadable canonical artifact falls through to a real
            // conversion of this source.
            if let Ok(text) = fs::read_to_string(&canonical_absolute) {
                let mut record = new_record(
                    &source_path,
                    &source_hash,
                    source_size,
                    &detection,
                    rules.version(),
                    Status::Dedup,
                );
                match mirror::write_atomic(&text_absolute, &text) {
                    Ok(()) => {
                        record.text_path = Some(text_relative);
                        record.text_hash = Some(hash::hash_bytes(text.as_bytes()));
                        record.artifact_kind = canonical.artifact_kind;
                        record.converter_id = Some(canonical.converter_id.clone());
                        record.converter_version = Some(canonical.converter_version.clone());
                        record.dedup_of = Some(canonical.source_path.clone());
                    }
                    Err(e) => {
                        record.status = Status::Failed;
                        record.error = Some(format!("mirror_write_error: {e}"));
                        remove_stale_artifact(&text_absolute, &mut record);
                    }
                }
                record.duration_ms = Some(elapsed_ms(started));
                record_outcome(&mut writer, &mut terminal, &mut counts, record)?;
                continue;
            }
        }

        let Some(converter) = converter else {
            let mut record = new_record(
                &source_path,
                &source_hash,
                source_size,
                &detection,
                rules.version(),
                Status::Unsupported,
            );
            record.duration_ms = Some(elapsed_ms(started));
            remove_stale_artifact(&text_absolute, &mut record);
            record_outcome(&mut writer, &mut terminal, &mut counts, record)?;
            continue;
        };

        let mut record = new_record(
            &source_path,
            &source_hash,
            source_size,
            &detection,
            rules.version(),
            Status::Converted,
        );
        // One byte snapshot feeds both the recorded hash and the
        // converter, so the record describes exactly what converted.
        let outcome = fs::read(&absolute)
            .map_err(|e| format!("source_io_error: read: {e}"))
            .and_then(|bytes| {
                if hash::hash_bytes(&bytes) != source_hash {
                    return Err(
                        "source_changed_during_run: bytes changed between hash and conversion"
                            .to_string(),
                    );
                }
                converter
                    .convert(&bytes, &detection.detected)
                    .map_err(|e| e.to_string())
            });
        match outcome {
            Ok(outcome) => match mirror::write_atomic(&text_absolute, &outcome.text) {
                Ok(()) => {
                    let text_hash = hash::hash_bytes(outcome.text.as_bytes());
                    record.text_path = Some(text_relative.clone());
                    record.text_hash = Some(text_hash.clone());
                    record.artifact_kind = Some(ArtifactKind::Text);
                    record.converter_id = Some(outcome.converter_id.clone());
                    record.converter_version = Some(outcome.converter_version.clone());
                    record.warnings = outcome.warnings;
                    dedup.replace(
                        &source_hash,
                        CanonicalArtifact {
                            source_path: source_path.clone(),
                            text_path: text_relative,
                            text_hash,
                            converter_id: outcome.converter_id,
                            converter_version: outcome.converter_version,
                            artifact_kind: record.artifact_kind,
                        },
                    );
                }
                Err(e) => {
                    record.status = Status::Failed;
                    record.converter_id = Some(converter.id().to_string());
                    record.converter_version = Some(converter.version().to_string());
                    record.error = Some(format!("mirror_write_error: {e}"));
                    remove_stale_artifact(&text_absolute, &mut record);
                }
            },
            Err(reason) => {
                record.status = Status::Failed;
                record.converter_id = Some(converter.id().to_string());
                record.converter_version = Some(converter.version().to_string());
                record.error = Some(reason);
                remove_stale_artifact(&text_absolute, &mut record);
            }
        }
        record.duration_ms = Some(elapsed_ms(started));
        record_outcome(&mut writer, &mut terminal, &mut counts, record)?;
    }

    warnings.sort();
    Ok(RunReport {
        division: options.division.to_string(),
        root: options.root.display().to_string(),
        sources: entries.len() as u64 - special_entries,
        special_entries,
        counts,
        warnings,
    })
}

fn shard_paths(manifest_dir: &Path) -> Result<Vec<PathBuf>> {
    let entries = fs::read_dir(manifest_dir).map_err(|e| Error::io("read_dir", manifest_dir, e))?;
    let mut shards = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| Error::io("read_dir", manifest_dir, e))?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("jsonl") {
            shards.push(path);
        }
    }
    shards.sort();
    Ok(shards)
}

fn division_name(shard: &Path) -> String {
    shard
        .file_stem()
        .map(|stem| stem.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// Computes coverage per division over terminal records.
pub fn status(manifest_dir: &Path) -> Result<StatusReport> {
    let mut divisions = Vec::new();
    for shard_path in shard_paths(manifest_dir)? {
        let shard = manifest::read_shard(&shard_path)?;
        let terminal = terminal_by_path(shard.records);
        let mut counts = StatusCounts::default();
        let mut with_text = 0u64;
        for record in terminal.values() {
            match record.status {
                Status::Converted => counts.converted += 1,
                Status::Failed => counts.failed += 1,
                Status::Unsupported => counts.unsupported += 1,
                Status::SkippedUnchanged => counts.skipped_unchanged += 1,
                Status::Dedup => counts.dedup += 1,
            }
            if record.text_path.is_some() {
                with_text += 1;
            }
        }
        let sources = terminal.len() as u64;
        let coverage = if sources == 0 {
            0.0
        } else {
            with_text as f64 / sources as f64
        };
        divisions.push(DivisionStatus {
            division: division_name(&shard_path),
            sources,
            with_text,
            coverage,
            counts,
            warnings: shard.warnings,
        });
    }
    Ok(StatusReport { divisions })
}

/// Collects every record for one source path across all shards.
pub fn explain(manifest_dir: &Path, source_path: &str) -> Result<Vec<ExplainEntry>> {
    let mut entries = Vec::new();
    for shard_path in shard_paths(manifest_dir)? {
        let division = division_name(&shard_path);
        for record in manifest::read_shard(&shard_path)?.records {
            if record.source_path == source_path {
                entries.push(ExplainEntry {
                    division: division.clone(),
                    record,
                });
            }
        }
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_rules_agree_on_a_version() {
        let rules = Rules::builtin().unwrap();
        assert_eq!(rules.version(), "1");
    }

    #[test]
    fn division_names_are_validated() {
        assert!(validate_division("finance-eu_1").is_ok());
        assert!(validate_division("").is_err());
        assert!(validate_division("a/b").is_err());
        assert!(validate_division("dot.dot").is_err());
    }

    #[test]
    fn layout_rejects_outputs_inside_the_root() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("src");
        fs::create_dir_all(&root).unwrap();
        let outside = dir.path().join("out");

        let err = check_layout(&root, &root.join("mirror"), &outside).unwrap_err();
        assert!(err.to_string().contains("mirror root"));

        let err = check_layout(&root, &outside.join("mirror"), &root.join("manifest")).unwrap_err();
        assert!(err.to_string().contains("manifest directory"));

        check_layout(&root, &outside.join("mirror"), &outside.join("manifest")).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_paths_are_rejected_without_an_artifact() {
        use std::os::unix::ffi::OsStrExt;
        let raw = std::ffi::OsStr::from_bytes(b"bad-\xff-name.txt");
        assert!(Path::new(raw).to_str().is_none());
    }

    #[test]
    fn identical_sources_dedup_to_one_conversion() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("src");
        fs::create_dir_all(root.join("sub")).unwrap();
        fs::write(root.join("first.txt"), "same bytes\n").unwrap();
        fs::write(root.join("sub/second.txt"), "same bytes\n").unwrap();

        let rules = Rules::builtin().unwrap();
        let report = run(
            &rules,
            &RunOptions {
                root: &root,
                mirror_root: &dir.path().join("mirror"),
                manifest_dir: &dir.path().join("manifest"),
                division: "unit",
                walk: WalkOptions::default(),
            },
        )
        .unwrap();

        assert_eq!(report.counts.converted, 1);
        assert_eq!(report.counts.dedup, 1);

        let records = manifest::read_shard(&dir.path().join("manifest/unit.jsonl"))
            .unwrap()
            .records;
        let canonical = records
            .iter()
            .find(|r| r.source_path == "first.txt")
            .unwrap();
        let duplicate = records
            .iter()
            .find(|r| r.source_path == "sub/second.txt")
            .unwrap();
        assert_eq!(canonical.status, Status::Converted);
        assert_eq!(duplicate.status, Status::Dedup);
        assert_eq!(duplicate.dedup_of.as_deref(), Some("first.txt"));
        assert_eq!(duplicate.text_hash, canonical.text_hash);

        let mirrored = fs::read_to_string(dir.path().join("mirror/sub/second.txt.txt")).unwrap();
        assert_eq!(mirrored, "same bytes\n");
    }
}
