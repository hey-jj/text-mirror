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

use crate::convert::{self, Registry};
use crate::detect::{self, Detection, FormatTable, UNKNOWN_FORMAT};
use crate::hash::{self, CanonicalArtifact, DedupIndex};
use crate::manifest::{self, ArtifactKind, ManifestSchema, ManifestWriter, Record, Status};
use crate::mirror;
use crate::report::{
    DivisionStatus, ExplainEntry, FormatCount, RunReport, ScanReport, SizeOutlier, StatusCounts,
    StatusReport,
};
use crate::segments;
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

pub(crate) fn validate_division(name: &str) -> Result<()> {
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
                warnings: record.warnings.clone(),
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

/// Removes any artifact and segments file left behind for a source
/// whose terminal outcome carries no text, so the mirror never
/// contradicts the manifest.
fn remove_stale_artifact(text_absolute: &Path, segments_absolute: &Path, record: &mut Record) {
    for stale in [text_absolute, segments_absolute] {
        match fs::remove_file(stale) {
            Ok(()) => {}
            Err(e)
                if e.kind() == std::io::ErrorKind::NotFound
                    || e.kind() == std::io::ErrorKind::NotADirectory => {}
            Err(e) => record
                .warnings
                .push(format!("stale_artifact_not_removed: {e}")),
        }
    }
}

/// True when an artifact and its sidecar still match the recorded
/// hash: the text bytes hash to `text_hash` and the sidecar parses as
/// segments@1 and validates against the text.
fn envelope_intact(artifact: &Path, text_hash: &str, segments_path: &Path) -> bool {
    let Ok(text) = fs::read_to_string(artifact) else {
        return false;
    };
    if hash::hash_bytes(text.as_bytes()) != text_hash {
        return false;
    }
    let Ok(sidecar) = fs::read_to_string(segments_path) else {
        return false;
    };
    segments::parse_jsonl(&sidecar).is_ok_and(|segs| segments::validate(&segs, &text).is_ok())
}

fn source_front(
    absolute: &Path,
    table: &FormatTable,
) -> Result<(String, u64, Detection, Vec<String>)> {
    let source_hash = hash::hash_file(absolute)?;
    let source_size = absolute
        .metadata()
        .map_err(|e| Error::io("stat", absolute, e))?
        .len();
    let (detection, warnings) = detect::detect_file_with_warnings(absolute, table)?;
    Ok((source_hash, source_size, detection, warnings))
}

/// Identity of one source, container child or top-level file alike.
struct Meta {
    source_path: String,
    parent_source: Option<String>,
    source_hash: String,
    source_size: u64,
    detection: Detection,
    detect_warnings: Vec<String>,
}

/// Where a unit's bytes come from. A top-level file reads from disk
/// after the skip and dedup decisions, so an unchanged file never
/// pays a second read. A container member already holds its bytes.
enum UnitBytes {
    Disk(PathBuf),
    Mem(Vec<u8>),
}

impl UnitBytes {
    fn load(self, expected_hash: &str) -> std::result::Result<Vec<u8>, String> {
        match self {
            UnitBytes::Mem(bytes) => Ok(bytes),
            UnitBytes::Disk(path) => {
                let bytes = fs::read(&path).map_err(|e| format!("source_io_error: read: {e}"))?;
                if hash::hash_bytes(&bytes) != expected_hash {
                    return Err(
                        "source_changed_during_run: bytes changed between hash and conversion"
                            .to_string(),
                    );
                }
                Ok(bytes)
            }
        }
    }
}

/// One unit of conversion work: a top-level source or a container
/// member.
struct Unit {
    meta: Meta,
    bytes: UnitBytes,
    depth: usize,
    /// Container hashes on this unit's chain, for the quine guard.
    ancestors: Vec<String>,
}

/// Which container family a detected format belongs to, if any.
enum ContainerKind {
    Zip,
    Eml,
}

/// True when a container member's hash repeats a container already on
/// its chain, which is the zip-quine signature. Kills a quine before
/// it spends the depth budget.
fn hash_on_chain(hash: &str, ancestors: &[String]) -> bool {
    ancestors.iter().any(|ancestor| ancestor == hash)
}

/// Case-folded, NFC-normalized key for a child source path, so two
/// members whose paths differ only by case or Unicode form collide.
fn collision_key(source_path: &str) -> String {
    use unicode_normalization::UnicodeNormalization;
    source_path.nfc().collect::<String>().to_lowercase()
}

/// The claimed-path state for one top-level container's whole
/// expansion, so members cannot alias each other's paths and a
/// re-expansion can retire the descendants a shrunken member set
/// dropped.
struct ClaimState {
    /// `<container>.d/`, the namespace every descendant path begins
    /// with.
    prefix: String,
    /// Collision keys already claimed this expansion.
    claimed: std::collections::HashSet<String>,
    /// Actual descendant source paths recorded this expansion.
    emitted: std::collections::HashSet<String>,
    /// Counter for synthetic collision-child paths.
    collisions: usize,
}

/// Reason recorded when a re-expanded container no longer holds a
/// member its prior manifest still named.
const REMOVED_MEMBER_REASON: &str = "container-member-removed";

fn container_kind(detected: &str) -> Option<ContainerKind> {
    match detected {
        "zip" => Some(ContainerKind::Zip),
        "eml" => Some(ContainerKind::Eml),
        _ => None,
    }
}

/// Shared run state for the recursive conversion of one division.
struct Expander<'a> {
    rules: &'a Rules,
    mirror_root: &'a Path,
    division: &'a str,
    walked: &'a std::collections::HashSet<String>,
    limits: &'a convert::ContainerLimits,
    writer: &'a mut ManifestWriter,
    terminal: &'a mut HashMap<String, Record>,
    counts: &'a mut StatusCounts,
    dedup: &'a mut DedupIndex,
    /// Set while a top-level container expands, tracking claimed and
    /// emitted descendant paths for aliasing and reconciliation.
    claim: Option<ClaimState>,
}

impl Expander<'_> {
    fn artifact_paths(&self, source_path: &str) -> (PathBuf, PathBuf, String) {
        let relative = Path::new(source_path);
        (
            mirror::mirror_path(self.mirror_root, self.division, relative),
            segments::segments_path(self.mirror_root, self.division, relative),
            mirror::recorded_text_path(self.division, source_path),
        )
    }

    fn emit(&mut self, record: Record) -> Result<()> {
        if let Some(claim) = &mut self.claim
            && record.source_path.starts_with(&claim.prefix)
        {
            claim.emitted.insert(record.source_path.clone());
        }
        record_outcome(self.writer, self.terminal, self.counts, record)
    }

    fn base_record(&self, meta: &Meta, status: Status) -> Record {
        let mut record = new_record(
            &meta.source_path,
            &meta.source_hash,
            meta.source_size,
            &meta.detection,
            self.rules.version(),
            status,
        );
        record.parent_source.clone_from(&meta.parent_source);
        record.warnings.clone_from(&meta.detect_warnings);
        record
    }

    /// Emits a failed record for a whole unit and clears any stale
    /// artifact.
    fn fail(&mut self, meta: &Meta, reason: String, started: Instant) -> Result<()> {
        let (text_absolute, segments_absolute, _) = self.artifact_paths(&meta.source_path);
        let mut record = self.base_record(meta, Status::Failed);
        record.error = Some(reason);
        record.duration_ms = Some(elapsed_ms(started));
        remove_stale_artifact(&text_absolute, &segments_absolute, &mut record);
        self.emit(record)
    }

    /// True when a real walked source already occupies this
    /// container's expansion namespace, which would collide two
    /// artifacts on one mirror path.
    fn expansion_collides(&self, source_path: &str) -> bool {
        let prefix = format!("{source_path}.d/");
        self.walked.iter().any(|walked| walked.starts_with(&prefix))
    }

    /// Processes one unit: checkpoint, dedup, then conversion or
    /// container expansion, appending one record per source.
    fn process(&mut self, unit: Unit, started: Instant, expanded: &mut u64) -> Result<()> {
        let Unit {
            meta,
            bytes,
            depth,
            ancestors,
        } = unit;
        let (text_absolute, segments_absolute, text_relative) =
            self.artifact_paths(&meta.source_path);
        let kind = container_kind(&meta.detection.detected);
        let converter = self.rules.registry.converter_for(&meta.detection.detected);
        let current_version = match kind {
            Some(ContainerKind::Zip) => Some(convert::CONTAINER_ZIP_VERSION),
            _ => converter.map(|c| c.version()),
        };

        // Checkpoint: an unchanged source with an intact artifact
        // skips, containers included. A skipped container leaves its
        // children untouched, and their prior records stay terminal.
        if let Some(previous) = self.terminal.get(&meta.source_path) {
            let key_matches = previous.source_hash == meta.source_hash
                && previous.rules_version == self.rules.version()
                && previous.converter_version.as_deref() == current_version;
            let has_text = matches!(
                previous.status,
                Status::Converted | Status::Dedup | Status::SkippedUnchanged
            );
            if key_matches && has_text {
                let intact = match (&previous.text_path, &previous.text_hash) {
                    (Some(text_path), Some(text_hash)) => {
                        mirror::resolve_recorded_path(self.mirror_root, text_path).is_ok_and(
                            |artifact| envelope_intact(&artifact, text_hash, &segments_absolute),
                        )
                    }
                    _ => false,
                };
                // A container is reachable only through its parent,
                // so an intact parent envelope is not enough: every
                // text-bearing descendant must still hash to its
                // record, or the container re-expands.
                let descendants_ok = kind.is_none() || self.descendants_intact(&meta.source_path);
                if intact && descendants_ok {
                    // A nested container that skips inside a
                    // re-expanding parent just validated its whole
                    // subtree intact, so every prior descendant under
                    // it is kept: the owner's reconciliation must not
                    // retire them as removed.
                    if kind.is_some() && self.claim.is_some() {
                        let prefix = format!("{}.d/", meta.source_path);
                        let kept: Vec<String> = self
                            .terminal
                            .keys()
                            .filter(|path| path.starts_with(&prefix))
                            .cloned()
                            .collect();
                        if let Some(claim) = &mut self.claim {
                            claim.emitted.extend(kept);
                        }
                    }
                    let mut record = previous.clone();
                    record.status = Status::SkippedUnchanged;
                    record.error = None;
                    record.duration_ms = Some(elapsed_ms(started));
                    return self.emit(record);
                }
            }
        }

        // Container guards, before any expansion. A container past the
        // depth cap or one whose bytes repeat an ancestor container is
        // a failed child, unexpanded.
        if kind.is_some() {
            if depth > self.limits.max_depth {
                return self.fail(&meta, "container-depth-exceeded".to_string(), started);
            }
            if hash_on_chain(&meta.source_hash, &ancestors) {
                return self.fail(&meta, "container-recursive".to_string(), started);
            }
        }

        // Dedup borrow, non-containers only. A container never dedups,
        // because borrowing its artifact would skip re-expanding its
        // members under their own paths.
        if kind.is_none()
            && let Some(canonical) = self.dedup.get(&meta.source_hash)
            && canonical.source_path != meta.source_path
            && converter.is_some_and(|c| {
                c.id() == canonical.converter_id && c.version() == canonical.converter_version
            })
        {
            let canonical = canonical.clone();
            let canonical_segments = segments::segments_path(
                self.mirror_root,
                self.division,
                Path::new(&canonical.source_path),
            );
            if let Ok(canonical_text) =
                mirror::resolve_recorded_path(self.mirror_root, &canonical.text_path)
                && let (Ok(text), Ok(segment_lines)) = (
                    fs::read_to_string(&canonical_text),
                    fs::read_to_string(&canonical_segments),
                )
                && hash::hash_bytes(text.as_bytes()) == canonical.text_hash
                && segments::parse_jsonl(&segment_lines)
                    .is_ok_and(|segs| segments::validate(&segs, &text).is_ok())
            {
                let mut record = self.base_record(&meta, Status::Dedup);
                for warning in &canonical.warnings {
                    if !record.warnings.contains(warning) {
                        record.warnings.push(warning.clone());
                    }
                }
                match mirror::write_atomic(&text_absolute, &text)
                    .and_then(|()| mirror::write_atomic(&segments_absolute, &segment_lines))
                {
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
                        remove_stale_artifact(&text_absolute, &segments_absolute, &mut record);
                    }
                }
                record.duration_ms = Some(elapsed_ms(started));
                return self.emit(record);
            }
        }

        let Some(kind) = kind else {
            return self.convert_leaf(meta, bytes, started);
        };
        // A top-level container owns the claim state for its whole
        // subtree. Nested containers share the owner's state.
        let owns_claim = self.claim.is_none();
        if owns_claim {
            self.claim = Some(ClaimState {
                prefix: format!("{}.d/", meta.source_path),
                claimed: std::collections::HashSet::new(),
                emitted: std::collections::HashSet::new(),
                collisions: 0,
            });
        }
        let root = meta.source_path.clone();
        let result = match kind {
            ContainerKind::Zip => self.expand_zip(meta, bytes, depth, ancestors, started, expanded),
            ContainerKind::Eml => self.expand_eml(meta, bytes, depth, ancestors, started, expanded),
        };
        if owns_claim {
            // Reconcile even on a failure path, so a container that
            // failed whole still retires the descendants it no longer
            // holds and never leaves a partial expansion live.
            if let Some(claim) = self.claim.take() {
                self.reconcile(&root, &claim, started)?;
            }
        }
        result
    }

    /// True when every text-bearing descendant of a container still
    /// hashes to its recorded value on disk.
    fn descendants_intact(&self, root: &str) -> bool {
        let prefix = format!("{root}.d/");
        for record in self.terminal.values() {
            if !record.source_path.starts_with(&prefix) {
                continue;
            }
            if let (Some(text_path), Some(text_hash)) = (&record.text_path, &record.text_hash) {
                let segments_absolute = segments::segments_path(
                    self.mirror_root,
                    self.division,
                    Path::new(&record.source_path),
                );
                let ok = mirror::resolve_recorded_path(self.mirror_root, text_path).is_ok_and(
                    |artifact| envelope_intact(&artifact, text_hash, &segments_absolute),
                );
                if !ok {
                    return false;
                }
            }
        }
        true
    }

    /// Retires every prior descendant a re-expansion no longer holds
    /// with a terminal non-text record, and removes its artifact, so
    /// no removed member survives as a live converted record.
    fn reconcile(&mut self, root: &str, claim: &ClaimState, started: Instant) -> Result<()> {
        let stale: Vec<Record> = self
            .terminal
            .values()
            .filter(|record| {
                record.source_path.starts_with(&claim.prefix)
                    && !claim.emitted.contains(&record.source_path)
                    // An already-retired record stays retired, so the
                    // reconciliation reaches a fixpoint and does not
                    // re-emit a removed member every run.
                    && !(record.status == Status::Failed
                        && record.error.as_deref() == Some(REMOVED_MEMBER_REASON))
            })
            .cloned()
            .collect();
        let _ = root;
        for record in stale {
            let (text_absolute, segments_absolute, _) = self.artifact_paths(&record.source_path);
            let detection = Detection {
                declared: record.declared_format.clone(),
                detected: UNKNOWN_FORMAT.to_string(),
                mismatch: false,
            };
            let mut retire = new_record(
                &record.source_path,
                "",
                0,
                &detection,
                self.rules.version(),
                Status::Failed,
            );
            retire.parent_source.clone_from(&record.parent_source);
            retire.error = Some(REMOVED_MEMBER_REASON.to_string());
            retire.duration_ms = Some(elapsed_ms(started));
            remove_stale_artifact(&text_absolute, &segments_absolute, &mut retire);
            self.emit(retire)?;
        }
        Ok(())
    }

    /// The non-container conversion path: unsupported when no converter
    /// claims the format, else convert under the ceilings.
    fn convert_leaf(&mut self, meta: Meta, bytes: UnitBytes, started: Instant) -> Result<()> {
        let (text_absolute, segments_absolute, text_relative) =
            self.artifact_paths(&meta.source_path);
        let Some(converter) = self.rules.registry.converter_for(&meta.detection.detected) else {
            let mut record = self.base_record(&meta, Status::Unsupported);
            record.error = self
                .rules
                .registry
                .unsupported_reason(&meta.detection.detected)
                .map(str::to_string);
            record.duration_ms = Some(elapsed_ms(started));
            remove_stale_artifact(&text_absolute, &segments_absolute, &mut record);
            return self.emit(record);
        };
        let converter_id = converter.id().to_string();
        let converter_version = converter.version().to_string();

        let mut record = self.base_record(&meta, Status::Converted);
        let outcome = if meta.source_size > convert::MAX_SOURCE_BYTES {
            Err(format!(
                "resource_limit: source is {} bytes over the {} byte ceiling",
                meta.source_size,
                convert::MAX_SOURCE_BYTES
            ))
        } else {
            bytes
                .load(&meta.source_hash)
                .and_then(|bytes| run_converter(converter, &bytes, &meta.detection.detected))
        };
        match outcome {
            Ok(outcome) => match segments::to_jsonl(&outcome.segments)
                .map_err(|e| e.to_string())
                .and_then(|lines| {
                    mirror::write_atomic(&text_absolute, &outcome.text)
                        .and_then(|()| mirror::write_atomic(&segments_absolute, &lines))
                        .map_err(|e| e.to_string())
                }) {
                Ok(()) => {
                    let text_hash = hash::hash_bytes(outcome.text.as_bytes());
                    record.text_path = Some(text_relative.clone());
                    record.text_hash = Some(text_hash.clone());
                    record.artifact_kind = Some(outcome.artifact_kind);
                    record.converter_id = Some(outcome.converter_id.clone());
                    record.converter_version = Some(outcome.converter_version.clone());
                    record.warnings.extend(outcome.warnings.iter().cloned());
                    self.dedup.replace(
                        &meta.source_hash,
                        CanonicalArtifact {
                            source_path: meta.source_path.clone(),
                            text_path: text_relative,
                            text_hash,
                            converter_id: outcome.converter_id,
                            converter_version: outcome.converter_version,
                            artifact_kind: record.artifact_kind,
                            warnings: outcome.warnings,
                        },
                    );
                }
                Err(detail) => {
                    record.status = Status::Failed;
                    record.converter_id = Some(converter_id);
                    record.converter_version = Some(converter_version);
                    record.error = Some(format!("mirror_write_error: {detail}"));
                    remove_stale_artifact(&text_absolute, &segments_absolute, &mut record);
                }
            },
            Err(reason) => {
                record.status = Status::Failed;
                record.converter_id = Some(converter_id);
                record.converter_version = Some(converter_version);
                record.error = Some(reason);
                remove_stale_artifact(&text_absolute, &segments_absolute, &mut record);
            }
        }
        record.duration_ms = Some(elapsed_ms(started));
        self.emit(record)
    }

    /// Writes a parent container artifact and records the parent as
    /// converted. Shared by both container families.
    fn write_parent(
        &mut self,
        meta: &Meta,
        outcome: &convert::Outcome,
        started: Instant,
    ) -> Result<bool> {
        let (text_absolute, segments_absolute, text_relative) =
            self.artifact_paths(&meta.source_path);
        let lines = match segments::to_jsonl(&outcome.segments) {
            Ok(lines) => lines,
            Err(e) => {
                self.fail(meta, format!("invalid_segments: {e}"), started)?;
                return Ok(false);
            }
        };
        match mirror::write_atomic(&text_absolute, &outcome.text)
            .and_then(|()| mirror::write_atomic(&segments_absolute, &lines))
        {
            Ok(()) => {
                let mut record = self.base_record(meta, Status::Converted);
                record.text_path = Some(text_relative);
                record.text_hash = Some(hash::hash_bytes(outcome.text.as_bytes()));
                // By design a container parent is a text manifest of its
                // members, not a recognized or transcribed artifact, so
                // it is always `Text` regardless of any member's kind. A
                // leaf converter's own kind flows through the single
                // source branch above instead.
                record.artifact_kind = Some(ArtifactKind::Text);
                record.converter_id = Some(outcome.converter_id.clone());
                record.converter_version = Some(outcome.converter_version.clone());
                record.warnings.extend(outcome.warnings.iter().cloned());
                record.duration_ms = Some(elapsed_ms(started));
                self.emit(record)?;
                Ok(true)
            }
            Err(e) => {
                self.fail(meta, format!("mirror_write_error: {e}"), started)?;
                Ok(false)
            }
        }
    }

    /// Builds and processes one container member as a child unit.
    fn process_member(
        &mut self,
        parent: &Meta,
        member_path: &str,
        member_bytes: Vec<u8>,
        depth: usize,
        ancestors: &[String],
        expanded: &mut u64,
    ) -> Result<()> {
        let source_path = format!("{}.d/{}", parent.source_path, member_path);
        // Two members whose normalized child paths collide would alias
        // one artifact, leaving two records with one file and a
        // mismatched hash. The later one is refused.
        if let Some(claim) = &mut self.claim {
            let key = collision_key(&source_path);
            if !claim.claimed.insert(key) {
                claim.collisions += 1;
                let synthetic = format!("{}.d/#collision-{}", parent.source_path, claim.collisions);
                return self.emit_member_failure(
                    parent,
                    synthetic,
                    member_bytes.len() as u64,
                    "member-path-collision".to_string(),
                    Instant::now(),
                );
            }
        }
        let (detection, detect_warnings) = detect::detect_bytes_with_warnings(
            Path::new(&source_path),
            &member_bytes,
            &self.rules.table,
        );
        let unit = Unit {
            meta: Meta {
                source_hash: hash::hash_bytes(&member_bytes),
                source_size: member_bytes.len() as u64,
                source_path,
                parent_source: Some(parent.source_path.clone()),
                detection,
                detect_warnings,
            },
            bytes: UnitBytes::Mem(member_bytes),
            depth,
            ancestors: ancestors.to_vec(),
        };
        self.process(unit, Instant::now(), expanded)
    }
}

/// The failure reason for a source over the conversion size ceiling.
fn over_source_ceiling(size: u64) -> String {
    format!(
        "resource_limit: source is {size} bytes over the {} byte ceiling",
        convert::MAX_SOURCE_BYTES
    )
}

/// Runs a converter under the panic boundary and output validation.
fn run_converter(
    converter: &dyn convert::Converter,
    bytes: &[u8],
    detected: &str,
) -> std::result::Result<convert::Outcome, String> {
    let guarded = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        converter.convert(bytes, detected)
    }));
    let outcome = match guarded {
        Ok(result) => result.map_err(|e| e.to_string())?,
        Err(_) => return Err("converter_panic: conversion panicked".to_string()),
    };
    validate_output(&outcome)?;
    Ok(outcome)
}

/// The shared output gate: output-size ceiling, the NUL refusal, and
/// segments validation.
fn validate_output(outcome: &convert::Outcome) -> std::result::Result<(), String> {
    if outcome.text.len() > convert::MAX_OUTPUT_BYTES {
        return Err(format!(
            "resource_limit: output is {} bytes over the {} byte ceiling",
            outcome.text.len(),
            convert::MAX_OUTPUT_BYTES
        ));
    }
    if let Some(offset) = outcome.text.find('\0') {
        return Err(format!(
            "nul_bytes: NUL at byte {offset} of the converted text"
        ));
    }
    segments::validate(&outcome.segments, &outcome.text)
        .map_err(|detail| format!("invalid_segments: {detail}"))
}

impl Expander<'_> {
    /// Emits one failed child record for a member refused before or
    /// during inflation.
    fn emit_member_failure(
        &mut self,
        parent: &Meta,
        child_source_path: String,
        source_size: u64,
        reason: String,
        started: Instant,
    ) -> Result<()> {
        let (text_absolute, segments_absolute, _) = self.artifact_paths(&child_source_path);
        let detection = Detection {
            declared: None,
            detected: UNKNOWN_FORMAT.to_string(),
            mismatch: false,
        };
        let mut record = new_record(
            &child_source_path,
            "",
            source_size,
            &detection,
            self.rules.version(),
            Status::Failed,
        );
        record.parent_source = Some(parent.source_path.clone());
        record.error = Some(reason);
        record.duration_ms = Some(elapsed_ms(started));
        remove_stale_artifact(&text_absolute, &segments_absolute, &mut record);
        self.emit(record)
    }

    /// Expands a zip container: a member listing artifact for the
    /// parent, then each member routed back through dispatch.
    fn expand_zip(
        &mut self,
        meta: Meta,
        bytes: UnitBytes,
        depth: usize,
        ancestors: Vec<String>,
        started: Instant,
        expanded: &mut u64,
    ) -> Result<()> {
        if self.expansion_collides(&meta.source_path) {
            return self.fail(&meta, "container-mirror-collision".to_string(), started);
        }
        if meta.source_size > convert::MAX_SOURCE_BYTES {
            return self.fail(&meta, over_source_ceiling(meta.source_size), started);
        }
        let bytes = match bytes.load(&meta.source_hash) {
            Ok(bytes) => bytes,
            Err(reason) => return self.fail(&meta, reason, started),
        };
        // Preflight the raw entry count from the end-of-central-
        // directory record before the zip crate parses and allocates
        // the whole directory, and refuse on the raw count, which its
        // name-keyed map would otherwise undercount.
        if let Some(entries) = convert::preflight_entry_count(&bytes)
            && entries > self.limits.max_children as u64
        {
            return self.fail(&meta, "container-children-exceeded".to_string(), started);
        }
        let mut container = match convert::ZipContainer::open(&bytes) {
            Ok(container) => container,
            Err(e) => return self.fail(&meta, e.to_string(), started),
        };

        // Stage 1: the child count and declared sizes, before any
        // inflation.
        let count = container.len();
        if count > self.limits.max_children {
            return self.fail(&meta, "container-children-exceeded".to_string(), started);
        }
        let mut declared_total: u64 = 0;
        for index in 0..count {
            match container.meta(index) {
                Ok(member) => declared_total = declared_total.saturating_add(member.declared_size),
                Err(e) => return self.fail(&meta, e.to_string(), started),
            }
        }
        if declared_total > self.limits.max_expanded_bytes {
            return self.fail(&meta, "container-expansion-cap".to_string(), started);
        }
        let listing = match container.listing() {
            Ok(listing) => listing,
            Err(e) => return self.fail(&meta, e.to_string(), started),
        };

        let mut child_ancestors = ancestors;
        child_ancestors.push(meta.source_hash.clone());

        // Stage 2: inflate and route each member. The cumulative
        // counter charges actual inflated bytes, and an overrun fails
        // the whole container.
        let mut parent_failure: Option<String> = None;
        for index in 0..count {
            let member = match container.meta(index) {
                Ok(member) => member,
                Err(e) => {
                    parent_failure = Some(e.to_string());
                    break;
                }
            };
            if member.is_dir {
                continue;
            }
            let Some(member_path) = member.safe_path.clone() else {
                self.emit_member_failure(
                    &meta,
                    format!("{}.d/#unsafe-member-{index}", meta.source_path),
                    0,
                    "unsafe-member-path".to_string(),
                    started,
                )?;
                continue;
            };
            let child_source = format!("{}.d/{}", meta.source_path, member_path);
            if member.is_symlink {
                self.emit_member_failure(
                    &meta,
                    child_source,
                    0,
                    "unsafe-member-path".to_string(),
                    started,
                )?;
                continue;
            }
            if member.encrypted {
                self.emit_member_failure(
                    &meta,
                    child_source,
                    member.declared_size,
                    "encrypted".to_string(),
                    started,
                )?;
                continue;
            }
            if member.declared_size > self.limits.max_member_size {
                self.emit_member_failure(
                    &meta,
                    child_source,
                    member.declared_size,
                    "container-member-too-large".to_string(),
                    started,
                )?;
                continue;
            }
            let remaining = self.limits.max_expanded_bytes.saturating_sub(*expanded);
            let cap = self.limits.max_member_size.min(remaining);
            match container.inflate(index, cap) {
                convert::Inflated::Ok(data) => {
                    *expanded = expanded.saturating_add(data.len() as u64);
                    self.process_member(
                        &meta,
                        &member_path,
                        data,
                        depth + 1,
                        &child_ancestors,
                        expanded,
                    )?;
                }
                convert::Inflated::TooLarge(inflated) => {
                    *expanded = expanded.saturating_add(inflated);
                    if inflated > self.limits.max_member_size {
                        self.emit_member_failure(
                            &meta,
                            child_source,
                            inflated,
                            "container-member-too-large".to_string(),
                            started,
                        )?;
                    }
                    if *expanded > self.limits.max_expanded_bytes {
                        parent_failure = Some("container-expansion-cap".to_string());
                        break;
                    }
                }
                convert::Inflated::Error(e) => {
                    self.emit_member_failure(
                        &meta,
                        child_source,
                        0,
                        format!("container-member-unreadable: {e}"),
                        started,
                    )?;
                }
            }
        }

        match parent_failure {
            Some(reason) => self.fail(&meta, reason, started),
            None => {
                let segments = vec![segments::Segment::span(0, listing.len(), "document")];
                let outcome = convert::Outcome {
                    converter_id: convert::CONTAINER_ZIP_ID.to_string(),
                    converter_version: convert::CONTAINER_ZIP_VERSION.to_string(),
                    detected_format: meta.detection.detected.clone(),
                    text: listing,
                    warnings: Vec::new(),
                    segments,
                    artifact_kind: manifest::ArtifactKind::Text,
                };
                if let Err(reason) = validate_output(&outcome) {
                    return self.fail(&meta, reason, started);
                }
                self.write_parent(&meta, &outcome, started).map(|_| ())
            }
        }
    }

    /// Expands an eml container: the message renders to the parent
    /// artifact, and each attachment routes back through dispatch as a
    /// member.
    fn expand_eml(
        &mut self,
        meta: Meta,
        bytes: UnitBytes,
        depth: usize,
        ancestors: Vec<String>,
        started: Instant,
        expanded: &mut u64,
    ) -> Result<()> {
        if self.expansion_collides(&meta.source_path) {
            return self.fail(&meta, "container-mirror-collision".to_string(), started);
        }
        let bytes = match bytes.load(&meta.source_hash) {
            Ok(bytes) => bytes,
            Err(reason) => return self.fail(&meta, reason, started),
        };
        if meta.source_size > convert::MAX_SOURCE_BYTES {
            return self.fail(&meta, over_source_ceiling(meta.source_size), started);
        }
        let guarded = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            convert::expand_eml(&bytes, &meta.detection.detected)
        }));
        let expansion = match guarded {
            Ok(Ok(expansion)) => expansion,
            Ok(Err(e)) => return self.fail(&meta, e.to_string(), started),
            Err(_) => {
                return self.fail(
                    &meta,
                    "converter_panic: conversion panicked".to_string(),
                    started,
                );
            }
        };
        if let Err(reason) = validate_output(&expansion.outcome) {
            return self.fail(&meta, reason, started);
        }

        // Expand the attachments first, so the parent record is
        // written last and an intact eml parent proves the whole
        // expansion finished, matching the zip ordering.
        let mut child_ancestors = ancestors;
        child_ancestors.push(meta.source_hash.clone());
        let mut parent_failure: Option<String> = None;
        for member in expansion.members {
            *expanded = expanded.saturating_add(member.bytes.len() as u64);
            if *expanded > self.limits.max_expanded_bytes {
                parent_failure = Some("container-expansion-cap".to_string());
                break;
            }
            self.process_member(
                &meta,
                &member.name,
                member.bytes,
                depth + 1,
                &child_ancestors,
                expanded,
            )?;
        }

        match parent_failure {
            Some(reason) => self.fail(&meta, reason, started),
            None => self
                .write_parent(&meta, &expansion.outcome, started)
                .map(|_| ()),
        }
    }
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

    // The mirror paths a container's `.d/` expansion would claim must
    // not collide with a real walked source, so the walked set is
    // checked before any container expands.
    let walked: std::collections::HashSet<String> = entries
        .iter()
        .filter_map(|entry| entry.path.to_str().map(str::to_string))
        .collect();
    let limits = rules.registry.container_limits().clone();

    let mut writer = ManifestWriter::open(&shard_path)?;
    let mut counts = StatusCounts::default();
    let mut special_entries = 0u64;

    for entry in &entries {
        let started = Instant::now();
        let relative = &entry.path;
        let absolute = options.root.join(relative);
        let text_absolute = mirror::mirror_path(options.mirror_root, options.division, relative);
        let segments_absolute =
            segments::segments_path(options.mirror_root, options.division, relative);

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
            remove_stale_artifact(&text_absolute, &segments_absolute, &mut record);
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
                    let mut record = new_record(
                        &source_path,
                        &hash::hash_bytes(target_bytes),
                        target_bytes.len() as u64,
                        &detection,
                        rules.version(),
                        Status::Unsupported,
                    );
                    // Symlinks are unsupported by pipeline design,
                    // whatever the registry claims, so the reason is
                    // set directly instead of looked up.
                    record.error = Some(convert::NO_CONVERTER_REASON.to_string());
                    record
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
            remove_stale_artifact(&text_absolute, &segments_absolute, &mut record);
            record_outcome(&mut writer, &mut terminal, &mut counts, record)?;
            continue;
        }

        // Gate the source size before detection. Format detection
        // reads from the file to sniff its type, and for a zip it can
        // allocate from a forged member size, so an oversized source
        // must fail before that read, containers included.
        let stat = match absolute.metadata() {
            Ok(metadata) => metadata,
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
                record.error = Some(format!("source_io_error: stat: {e}"));
                record.duration_ms = Some(elapsed_ms(started));
                remove_stale_artifact(&text_absolute, &segments_absolute, &mut record);
                record_outcome(&mut writer, &mut terminal, &mut counts, record)?;
                continue;
            }
        };
        if stat.len() > convert::MAX_SOURCE_BYTES {
            let detection = Detection {
                declared: detect::declared_format(relative, &rules.table),
                detected: UNKNOWN_FORMAT.to_string(),
                mismatch: false,
            };
            let mut record = new_record(
                &source_path,
                "",
                stat.len(),
                &detection,
                rules.version(),
                Status::Failed,
            );
            record.error = Some(over_source_ceiling(stat.len()));
            record.duration_ms = Some(elapsed_ms(started));
            remove_stale_artifact(&text_absolute, &segments_absolute, &mut record);
            record_outcome(&mut writer, &mut terminal, &mut counts, record)?;
            continue;
        }

        let front = match source_front(&absolute, &rules.table) {
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
                remove_stale_artifact(&text_absolute, &segments_absolute, &mut record);
                record_outcome(&mut writer, &mut terminal, &mut counts, record)?;
                continue;
            }
        };
        let (source_hash, source_size, detection, detect_warnings) = front;
        let mut expanded = 0u64;
        let unit = Unit {
            meta: Meta {
                source_path,
                parent_source: None,
                source_hash,
                source_size,
                detection,
                detect_warnings,
            },
            bytes: UnitBytes::Disk(absolute.clone()),
            depth: 0,
            ancestors: Vec::new(),
        };
        let mut expander = Expander {
            rules,
            mirror_root: options.mirror_root,
            division: options.division,
            walked: &walked,
            limits: &limits,
            writer: &mut writer,
            terminal: &mut terminal,
            counts: &mut counts,
            dedup: &mut dedup,
            claim: None,
        };
        expander.process(unit, started, &mut expanded)?;
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
        assert_eq!(rules.version(), "8");
    }

    #[test]
    fn the_quine_guard_matches_an_ancestor_hash() {
        let chain = vec!["aa".to_string(), "bb".to_string()];
        assert!(hash_on_chain("bb", &chain));
        assert!(hash_on_chain("aa", &chain));
        assert!(!hash_on_chain("cc", &chain));
        assert!(!hash_on_chain("aa", &[]));
    }

    use crate::convert::{ConvertError, Converter, Outcome, PlainTextPassthrough};
    use crate::segments::Segment;

    /// A converter that panics, for the boundary test. No shipped
    /// converter panics on purpose, so the test registry injects one.
    struct PanicConverter;

    impl Converter for PanicConverter {
        fn id(&self) -> &'static str {
            "panic-test"
        }
        fn version(&self) -> &'static str {
            "1.0.0"
        }
        fn convert(
            &self,
            _source: &[u8],
            _detected_format: &str,
        ) -> std::result::Result<Outcome, ConvertError> {
            panic!("deliberate test panic");
        }
    }

    /// A converter whose segments do not fit its text.
    struct BadSegmentsConverter;

    impl Converter for BadSegmentsConverter {
        fn id(&self) -> &'static str {
            "bad-segments-test"
        }
        fn version(&self) -> &'static str {
            "1.0.0"
        }
        fn convert(
            &self,
            _source: &[u8],
            detected_format: &str,
        ) -> std::result::Result<Outcome, ConvertError> {
            Ok(Outcome {
                converter_id: self.id().to_string(),
                converter_version: self.version().to_string(),
                detected_format: detected_format.to_string(),
                text: "ok".to_string(),
                warnings: Vec::new(),
                segments: vec![Segment::span(0, 999, "document")],
                artifact_kind: manifest::ArtifactKind::Text,
            })
        }
    }

    /// A converter that returns a valid outcome stamped
    /// [`manifest::ArtifactKind::Ocr`], so the pipeline's kind
    /// propagation through the single-source, dedup, and checkpoint paths
    /// can be exercised without a jailed engine.
    struct OcrKindConverter;

    impl Converter for OcrKindConverter {
        fn id(&self) -> &'static str {
            "ocr-kind-test"
        }
        fn version(&self) -> &'static str {
            "1.0.0"
        }
        fn convert(
            &self,
            _source: &[u8],
            detected_format: &str,
        ) -> std::result::Result<Outcome, ConvertError> {
            let text = "recognized text\n".to_string();
            Ok(Outcome {
                converter_id: self.id().to_string(),
                converter_version: self.version().to_string(),
                detected_format: detected_format.to_string(),
                segments: vec![Segment::span(0, text.len(), "document")],
                text,
                warnings: Vec::new(),
                artifact_kind: manifest::ArtifactKind::Ocr,
            })
        }
    }

    fn injected_rules() -> Rules {
        let table = FormatTable::parse(
            r#"
version = "9"

[[formats]]
id = "text"
name = "Plain text"
extensions = ["txt"]

[[formats]]
id = "panicfmt"
name = "Panic trigger"
extensions = ["panicfmt"]

[[formats]]
id = "badseg"
name = "Bad segments trigger"
extensions = ["badseg"]

[[formats]]
id = "ocrfmt"
name = "OCR kind trigger"
extensions = ["ocrfmt"]
"#,
            "formats.toml",
        )
        .unwrap();
        let registry = Registry::for_tests(
            "9",
            vec![
                (Box::new(PlainTextPassthrough), vec!["text"]),
                (Box::new(PanicConverter), vec!["panicfmt"]),
                (Box::new(BadSegmentsConverter), vec!["badseg"]),
                (Box::new(OcrKindConverter), vec!["ocrfmt"]),
            ],
        );
        Rules { table, registry }
    }

    #[test]
    fn a_panicking_converter_fails_one_source_and_the_division_survives() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("src");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("boom.panicfmt"), "trigger\n").unwrap();
        fs::write(root.join("fine.txt"), "safe content\n").unwrap();

        let rules = injected_rules();
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

        assert_eq!(report.counts.failed, 1);
        assert_eq!(report.counts.converted, 1);
        let records = manifest::read_shard(&dir.path().join("manifest/unit.jsonl"))
            .unwrap()
            .records;
        let failed = records.iter().find(|r| r.status == Status::Failed).unwrap();
        assert_eq!(failed.source_path, "boom.panicfmt");
        assert!(
            failed
                .error
                .as_deref()
                .unwrap()
                .starts_with("converter_panic")
        );
        assert!(!dir.path().join("mirror/unit/boom.panicfmt.txt").exists());
    }

    #[test]
    fn invalid_segments_from_a_converter_fail_before_any_write() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("src");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("bad.badseg"), "trigger\n").unwrap();

        let rules = injected_rules();
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

        assert_eq!(report.counts.failed, 1);
        let records = manifest::read_shard(&dir.path().join("manifest/unit.jsonl"))
            .unwrap()
            .records;
        assert!(
            records[0]
                .error
                .as_deref()
                .unwrap()
                .starts_with("invalid_segments")
        );
        assert!(!dir.path().join("mirror/unit/bad.badseg.txt").exists());
        assert!(
            !dir.path()
                .join("mirror/unit/bad.badseg.segments.jsonl")
                .exists()
        );
    }

    #[test]
    fn the_ocr_artifact_kind_propagates_through_dedup_and_checkpoint() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("src");
        let mirror = dir.path().join("mirror");
        let manifest_dir = dir.path().join("manifest");
        fs::create_dir_all(&root).unwrap();
        // Two identical-content OCR sources: the first converts, the
        // second dedups off it within the same run.
        fs::write(root.join("a.ocrfmt"), "same pixels\n").unwrap();
        fs::write(root.join("b.ocrfmt"), "same pixels\n").unwrap();

        let rules = injected_rules();
        let options = RunOptions {
            root: &root,
            mirror_root: &mirror,
            manifest_dir: &manifest_dir,
            division: "unit",
            walk: WalkOptions::default(),
        };
        run(&rules, &options).unwrap();

        let shard = manifest_dir.join("unit.jsonl");
        let latest = |path: &str| {
            manifest::read_shard(&shard)
                .unwrap()
                .records
                .into_iter()
                .rev()
                .find(|r| r.source_path == path)
                .unwrap()
        };

        // Same-run: one Converted, one Dedup, both carry the OCR kind.
        let a = latest("a.ocrfmt");
        let b = latest("b.ocrfmt");
        let (converted, deduped) = if a.status == Status::Converted {
            (a, b)
        } else {
            (b, a)
        };
        assert_eq!(converted.status, Status::Converted);
        assert_eq!(deduped.status, Status::Dedup);
        assert_eq!(converted.artifact_kind, Some(ArtifactKind::Ocr));
        assert_eq!(deduped.artifact_kind, Some(ArtifactKind::Ocr));

        // Second run with the prior manifest present. The unchanged
        // sources skip and keep their OCR kind (checkpoint-skip clones
        // the prior record); a new identical source dedups off the
        // seeded prior canonical and is also OCR (seeded dedup).
        fs::write(root.join("c.ocrfmt"), "same pixels\n").unwrap();
        run(&rules, &options).unwrap();

        let a2 = latest("a.ocrfmt");
        let b2 = latest("b.ocrfmt");
        let c = latest("c.ocrfmt");
        assert_eq!(a2.status, Status::SkippedUnchanged);
        assert_eq!(b2.status, Status::SkippedUnchanged);
        assert_eq!(a2.artifact_kind, Some(ArtifactKind::Ocr));
        assert_eq!(b2.artifact_kind, Some(ArtifactKind::Ocr));
        assert_eq!(c.status, Status::Dedup);
        assert_eq!(c.artifact_kind, Some(ArtifactKind::Ocr));
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

        let mirrored =
            fs::read_to_string(dir.path().join("mirror/unit/sub/second.txt.txt")).unwrap();
        assert_eq!(mirrored, "same bytes\n");
    }
}
