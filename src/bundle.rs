//! Bundle packaging, verification, and merging.
//!
//! A bundle is the self-contained handoff unit between the conversion
//! machine and the consumer: the division-namespaced mirror subtree,
//! the manifest shard, the rules snapshot that produced it,
//! `checksums.b3` over every bundle file, and `BUNDLE.json`. Bundles
//! are always written clean. The producer's torn-line tolerance is
//! crash recovery for its own resume path, and packaging refuses a
//! shard with a torn tail instead of repairing it, because a torn
//! tail means an interrupted run and the remedy is resuming the run.
//! Every line of every shard in a verified bundle parses as a
//! complete record.
//!
//! Verification refuses the whole bundle on any failure and names
//! every offender the failing step found. Merging verifies every
//! input, copies bytes without rewriting a record or a path, and
//! verifies its own output before reporting success. `BUNDLE.json`
//! carries no timestamp, so packaging and merging the same inputs
//! again is byte-identical.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::path::{Path, PathBuf};

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::manifest::{self, ManifestSchema, Record, Status};
use crate::{Error, Result, hash};

/// The bundle schema identifier carried by every BUNDLE.json.
pub const BUNDLE_SCHEMA: &str = "text-mirror/bundle@1";

/// The checksum file name at the bundle root.
pub const CHECKSUMS_NAME: &str = "checksums.b3";

/// The descriptor file name at the bundle root.
pub const DESCRIPTOR_NAME: &str = "BUNDLE.json";

/// The `schema` field of a [`BundleDescriptor`]. Serializes to the
/// literal `text-mirror/bundle@1` and rejects every other value, so a
/// consumer fails closed on a bundle version it does not recognize.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BundleSchema;

impl Serialize for BundleSchema {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(BUNDLE_SCHEMA)
    }
}

impl<'de> Deserialize<'de> for BundleSchema {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        if value == BUNDLE_SCHEMA {
            Ok(BundleSchema)
        } else {
            Err(D::Error::custom(format!(
                "unrecognized schema {value:?}, this consumer accepts only {BUNDLE_SCHEMA:?}"
            )))
        }
    }
}

/// Per-division record counts over every shard line, superseded
/// outcomes included.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DivisionCounts {
    /// Lines with status converted.
    pub converted: u64,
    /// Lines with status failed.
    pub failed: u64,
    /// Lines with status unsupported.
    pub unsupported: u64,
    /// Lines with status skipped_unchanged.
    pub skipped_unchanged: u64,
    /// Lines with status dedup.
    pub dedup: u64,
    /// Every line in the shard.
    pub total: u64,
}

/// Coverage for one division as an exact integer pair.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DivisionCoverage {
    /// Effective records with a text-bearing status: converted,
    /// dedup, or skipped_unchanged. Verify separately confirms every
    /// such artifact exists and matches its hash.
    pub covered: u64,
    /// All effective records.
    pub total: u64,
}

/// The BUNDLE.json contents. The seven-field set is the frozen
/// bundle@1 shape.
///
/// The descriptor carries no timestamp, so packaging or merging the
/// same inputs again is byte-identical.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleDescriptor {
    /// The literal string `text-mirror/bundle@1`.
    pub schema: BundleSchema,
    /// The manifest schema every shard record carries.
    pub manifest_schema: ManifestSchema,
    /// Bytewise-sorted identifiers of the runs whose outcomes the
    /// bundle carries, each matching the run id grammar. A run
    /// identifier is the BLAKE3 hex of the division's shard bytes at
    /// packaging time, so it names the exact outcome set and stays
    /// byte-identical across re-runs.
    pub run_ids: Vec<String>,
    /// Bytewise-sorted division names.
    pub divisions: Vec<String>,
    /// Per-division counts over every shard line, superseded records
    /// included, so a shard trimmed of history fails verification.
    pub counts: BTreeMap<String, DivisionCounts>,
    /// Per-division coverage over effective records only, the true
    /// denominator.
    pub coverage: BTreeMap<String, DivisionCoverage>,
    /// BLAKE3 hex of the exact bytes of checksums.b3. This chain
    /// detects corruption and partial transfer, and it does not
    /// detect tampering, because nothing signs BUNDLE.json.
    pub checksums_hash: String,
}

/// True when a run id fits the bundle@1 grammar: one to sixty four
/// ASCII characters, alphanumeric first, then alphanumerics, dot,
/// underscore, hyphen.
pub fn valid_run_id(id: &str) -> bool {
    let bytes = id.as_bytes();
    if bytes.is_empty() || bytes.len() > 64 || !bytes[0].is_ascii_alphanumeric() {
        return false;
    }
    bytes[1..]
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// The portable collision key for a text_path: NFC normalization and
/// ASCII case folding. Bytewise-distinct paths that fold together
/// would corrupt the mirror on a case-insensitive receiving
/// filesystem.
fn collision_key(text_path: &str) -> String {
    use unicode_normalization::UnicodeNormalization;
    text_path.nfc().collect::<String>().to_ascii_lowercase()
}

fn refused(verb: &'static str, problems: Vec<String>) -> Error {
    Error::Refused { verb, problems }
}

/// The `version` a rules file declares, read without binding the rest
/// of the file, so a snapshot from any rules generation parses.
fn rules_file_version(text: &str, name: &str) -> std::result::Result<String, String> {
    #[derive(Deserialize)]
    struct VersionOnly {
        version: String,
    }
    toml::from_str::<VersionOnly>(text)
        .map(|v| v.version)
        .map_err(|e| format!("{name}: cannot read the declared rules version: {e}"))
}

/// Every entry under `root`: sorted slash-relative paths with a
/// directory flag. Non-regular entries are refused, because a bundle
/// carries files and directories and nothing else.
fn enumerate_entries(root: &Path) -> Result<Vec<(String, bool)>> {
    fn visit(dir: &Path, base: &Path, out: &mut Vec<(String, bool)>) -> Result<()> {
        let entries = fs::read_dir(dir).map_err(|e| Error::io("read_dir", dir, e))?;
        for entry in entries {
            let entry = entry.map_err(|e| Error::io("read_dir", dir, e))?;
            let path = entry.path();
            let file_type = entry.file_type().map_err(|e| Error::io("stat", &path, e))?;
            let relative = path
                .strip_prefix(base)
                .expect("entries live under the base")
                .components()
                .map(|c| c.as_os_str().to_string_lossy())
                .collect::<Vec<_>>()
                .join("/");
            if file_type.is_dir() {
                out.push((relative, true));
                visit(&path, base, out)?;
            } else if file_type.is_file() {
                out.push((relative, false));
            } else {
                return Err(Error::io(
                    "enumerate",
                    &path,
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "bundle trees hold regular files only",
                    ),
                ));
            }
        }
        Ok(())
    }
    let mut entries = Vec::new();
    visit(root, root, &mut entries)?;
    entries.sort();
    Ok(entries)
}

/// The last record per source path within one shard's append order.
///
/// The effective-record key is (division, source_path). Division is
/// the shard identity from the shard filename, so this reduction runs
/// per shard and records are never pooled across shards.
fn effective_records(records: &[Record]) -> BTreeMap<String, &Record> {
    let mut effective = BTreeMap::new();
    for record in records {
        effective.insert(record.source_path.clone(), record);
    }
    effective
}

fn covered_status(status: Status) -> bool {
    matches!(
        status,
        Status::Converted | Status::Dedup | Status::SkippedUnchanged
    )
}

/// counts is a ledger over every shard line, superseded outcomes
/// included, and total equals the shard's line count.
fn tally_counts(records: &[Record]) -> DivisionCounts {
    let mut counts = DivisionCounts::default();
    for record in records {
        match record.status {
            Status::Converted => counts.converted += 1,
            Status::Failed => counts.failed += 1,
            Status::Unsupported => counts.unsupported += 1,
            Status::SkippedUnchanged => counts.skipped_unchanged += 1,
            Status::Dedup => counts.dedup += 1,
        }
        counts.total += 1;
    }
    counts
}

/// coverage is over effective records only.
fn tally_coverage(effective: &BTreeMap<String, &Record>) -> DivisionCoverage {
    let mut coverage = DivisionCoverage::default();
    for record in effective.values() {
        coverage.total += 1;
        if covered_status(record.status) {
            coverage.covered += 1;
        }
    }
    coverage
}

/// Every regular file under `root` as a sorted list of
/// slash-separated relative paths. Non-regular entries are refused,
/// because a bundle carries files and nothing else.
fn enumerate_files(root: &Path) -> Result<Vec<String>> {
    fn visit(dir: &Path, base: &Path, out: &mut Vec<String>) -> Result<()> {
        let entries = fs::read_dir(dir).map_err(|e| Error::io("read_dir", dir, e))?;
        for entry in entries {
            let entry = entry.map_err(|e| Error::io("read_dir", dir, e))?;
            let path = entry.path();
            let file_type = entry.file_type().map_err(|e| Error::io("stat", &path, e))?;
            if file_type.is_dir() {
                visit(&path, base, out)?;
            } else if file_type.is_file() {
                let relative = path
                    .strip_prefix(base)
                    .expect("entries live under the base")
                    .components()
                    .map(|c| c.as_os_str().to_string_lossy())
                    .collect::<Vec<_>>()
                    .join("/");
                out.push(relative);
            } else {
                return Err(Error::io(
                    "enumerate",
                    &path,
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "bundle trees hold regular files only",
                    ),
                ));
            }
        }
        Ok(())
    }
    let mut files = Vec::new();
    visit(root, root, &mut files)?;
    files.sort();
    Ok(files)
}

/// Builds the checksums.b3 content for the listed files: one
/// `<hash><two spaces><path>` line per file in bytewise path order,
/// LF endings, trailing newline.
fn checksum_lines(root: &Path, files: &[String]) -> Result<String> {
    let mut out = String::new();
    for relative in files {
        let digest = hash::hash_file(&root.join(relative))?;
        out.push_str(&digest);
        out.push_str("  ");
        out.push_str(relative);
        out.push('\n');
    }
    Ok(out)
}

fn write_file(root: &Path, relative: &str, bytes: &[u8]) -> Result<()> {
    let dest = root.join(relative);
    if let Some(dir) = dest.parent() {
        fs::create_dir_all(dir).map_err(|e| Error::io("create_dir", dir, e))?;
    }
    fs::write(&dest, bytes).map_err(|e| Error::io("write", &dest, e))
}

/// Copies every regular file under `from` to the same relative path
/// under `to`, byte-identical.
fn copy_tree(from: &Path, to: &Path) -> Result<u64> {
    let files = enumerate_files(from)?;
    for relative in &files {
        let source = from.join(relative);
        let dest = to.join(relative);
        if let Some(dir) = dest.parent() {
            fs::create_dir_all(dir).map_err(|e| Error::io("create_dir", dir, e))?;
        }
        fs::copy(&source, &dest).map_err(|e| Error::io("copy", &source, e))?;
    }
    Ok(files.len() as u64)
}

fn descriptor_bytes(descriptor: &BundleDescriptor) -> Result<Vec<u8>> {
    let mut json = serde_json::to_string_pretty(descriptor).map_err(|e| Error::Encode {
        path: PathBuf::from(DESCRIPTOR_NAME),
        message: e.to_string(),
    })?;
    json.push('\n');
    Ok(json.into_bytes())
}

fn refuse_dirty_output(output: &Path) -> Result<()> {
    if output.exists() {
        let mut entries = fs::read_dir(output).map_err(|e| Error::io("read_dir", output, e))?;
        if entries.next().is_some() {
            return Err(Error::Layout {
                message: format!("output {} exists and is not empty", output.display()),
            });
        }
    }
    Ok(())
}

/// Options for packaging one division.
pub struct BundleOptions<'a> {
    /// The mirror root the run wrote into.
    pub mirror_root: &'a Path,
    /// The directory holding manifest shards.
    pub manifest_dir: &'a Path,
    /// The division to package.
    pub division: &'a str,
    /// The bundle output directory, created empty.
    pub output: &'a Path,
}

/// The `bundle` verb output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleReport {
    /// The packaged division.
    pub division: String,
    /// The bundle root.
    pub output: String,
    /// Files listed in checksums.b3.
    pub files: u64,
    /// Counts over every shard line, superseded records included.
    pub counts: DivisionCounts,
    /// Coverage.
    pub coverage: DivisionCoverage,
    /// BLAKE3 hex of checksums.b3.
    pub checksums_hash: String,
}

/// Packages one division into a bundle and verifies the result.
pub fn bundle(options: &BundleOptions) -> Result<BundleReport> {
    crate::pipeline::validate_division(options.division)?;
    let shard_path = options
        .manifest_dir
        .join(format!("{}.jsonl", options.division));
    let shard_bytes = fs::read(&shard_path).map_err(|e| Error::io("read", &shard_path, e))?;
    // Clean-write is a bundle@1 property: every shard ends with a
    // newline and every line parses complete. A torn or unterminated
    // tail means an interrupted run, and the remedy is resuming the
    // run, not repairing the shard here.
    if !shard_bytes.ends_with(b"\n") {
        return Err(refused(
            "bundle",
            vec![format!(
                "shard {} does not end with a newline, resume the run to complete the division",
                shard_path.display()
            )],
        ));
    }
    let shard = manifest::read_shard(&shard_path)?;
    if !shard.warnings.is_empty() {
        return Err(refused(
            "bundle",
            vec![format!(
                "shard {} ends in a torn line, resume the run to complete the division",
                shard_path.display()
            )],
        ));
    }
    let effective = effective_records(&shard.records);
    let counts = tally_counts(&shard.records);
    let coverage = tally_coverage(&effective);

    // Every text-bearing effective record must have its artifact on
    // disk before anything is packaged.
    let mut problems = Vec::new();
    for record in effective.values() {
        let Some(text_path) = &record.text_path else {
            continue;
        };
        let present = crate::mirror::resolve_recorded_path(options.mirror_root, text_path)
            .is_ok_and(|artifact| artifact.is_file());
        if !present {
            problems.push(format!(
                "{}: artifact {text_path} is missing",
                record.source_path
            ));
        }
    }
    if !problems.is_empty() {
        return Err(refused("bundle", problems));
    }

    // The snapshot this bundle writes must describe the records it
    // carries. Effective records from another rules generation mean
    // the division needs a re-run under the current rules before it
    // can ship. Superseded lines are exempt, append-only history
    // legitimately spans rules bumps.
    let snapshot_version =
        rules_file_version(include_str!("../rules/converters.toml"), "converters.toml").map_err(
            |message| Error::Rules {
                name: "converters.toml".to_string(),
                message,
            },
        )?;
    let mut problems = Vec::new();
    for record in effective.values() {
        if record.rules_version != snapshot_version {
            problems.push(format!(
                "{}: record rules_version {:?} does not match the snapshot rules version {:?}, re-run the division under the current rules",
                record.source_path, record.rules_version, snapshot_version
            ));
        }
    }
    if !problems.is_empty() {
        return Err(refused("bundle", problems));
    }

    refuse_dirty_output(options.output)?;
    fs::create_dir_all(options.output).map_err(|e| Error::io("create_dir", options.output, e))?;

    // The mirror subtree copies byte-identical into the same shape,
    // so no recorded path is ever rewritten. The division's mirror
    // directory exists in every bundle, empty when nothing converted.
    let bundle_mirror = options.output.join("mirror").join(options.division);
    fs::create_dir_all(&bundle_mirror).map_err(|e| Error::io("create_dir", &bundle_mirror, e))?;
    let division_mirror = options.mirror_root.join(options.division);
    if division_mirror.is_dir() {
        copy_tree(&division_mirror, &bundle_mirror)?;
    }
    write_file(
        options.output,
        &format!("manifest/{}.jsonl", options.division),
        &shard_bytes,
    )?;
    write_file(
        options.output,
        "rules/formats.toml",
        include_str!("../rules/formats.toml").as_bytes(),
    )?;
    write_file(
        options.output,
        "rules/converters.toml",
        include_str!("../rules/converters.toml").as_bytes(),
    )?;

    let files = enumerate_files(options.output)?;
    let checksums = checksum_lines(options.output, &files)?;
    let checksums_hash = hash::hash_bytes(checksums.as_bytes());
    write_file(options.output, CHECKSUMS_NAME, checksums.as_bytes())?;

    let descriptor = BundleDescriptor {
        schema: BundleSchema,
        manifest_schema: ManifestSchema,
        run_ids: {
            let run_id = hash::hash_bytes(&shard_bytes);
            if !valid_run_id(&run_id) {
                return Err(refused(
                    "bundle",
                    vec![format!("run id {run_id:?} is outside the run id grammar")],
                ));
            }
            vec![run_id]
        },
        divisions: vec![options.division.to_string()],
        counts: BTreeMap::from([(options.division.to_string(), counts.clone())]),
        coverage: BTreeMap::from([(options.division.to_string(), coverage.clone())]),
        checksums_hash: checksums_hash.clone(),
    };
    write_file(
        options.output,
        DESCRIPTOR_NAME,
        &descriptor_bytes(&descriptor)?,
    )?;

    // A bundle that fails its own verification must not report
    // success, same rule merge follows.
    verify(options.output).map_err(|error| match error {
        Error::Refused { problems, .. } => refused("bundle", problems),
        other => other,
    })?;

    Ok(BundleReport {
        division: options.division.to_string(),
        output: options.output.display().to_string(),
        files: files.len() as u64,
        counts,
        coverage,
        checksums_hash,
    })
}

/// The `verify` verb output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyReport {
    /// The verified bundle root.
    pub bundle: String,
    /// Divisions the bundle carries.
    pub divisions: Vec<String>,
    /// Files whose checksums were recomputed and matched.
    pub files_verified: u64,
    /// Shard records parsed.
    pub records: u64,
    /// Counts per division over every shard line, recomputed.
    pub counts: BTreeMap<String, DivisionCounts>,
    /// Coverage per division, recomputed.
    pub coverage: BTreeMap<String, DivisionCoverage>,
}

fn parse_checksum_lines(content: &str) -> std::result::Result<Vec<(String, String)>, Vec<String>> {
    let mut problems = Vec::new();
    let mut entries: Vec<(String, String)> = Vec::new();
    let mut seen = BTreeSet::new();
    for (index, line) in content.lines().enumerate() {
        let number = index + 1;
        let Some((digest, path)) = line.split_once("  ") else {
            problems.push(format!("checksums.b3 line {number}: not a checksum line"));
            continue;
        };
        let digest_ok = digest.len() == 64 && digest.chars().all(|c| c.is_ascii_hexdigit());
        // Backslash and colon are separators on other hosts, so a
        // path carrying them does not mean one file everywhere.
        let path_ok = !path.is_empty()
            && !path.contains(['\\', ':'])
            && path
                .split('/')
                .all(|segment| !segment.is_empty() && segment != "." && segment != "..");
        if !digest_ok || !path_ok {
            problems.push(format!("checksums.b3 line {number}: malformed entry"));
            continue;
        }
        if !seen.insert(path.to_string()) {
            problems.push(format!("checksums.b3 line {number}: duplicate path {path}"));
            continue;
        }
        if let Some((_, previous)) = entries.last()
            && path <= previous.as_str()
        {
            problems.push(format!(
                "checksums.b3 line {number}: paths are not in bytewise order"
            ));
            continue;
        }
        entries.push((digest.to_ascii_lowercase(), path.to_string()));
    }
    if problems.is_empty() {
        Ok(entries)
    } else {
        Err(problems)
    }
}

fn read_descriptor(root: &Path) -> Result<BundleDescriptor> {
    let path = root.join(DESCRIPTOR_NAME);
    let bytes = fs::read(&path)
        .map_err(|e| refused("verify", vec![format!("{DESCRIPTOR_NAME} unreadable: {e}")]))?;
    serde_json::from_slice(&bytes)
        .map_err(|e| refused("verify", vec![format!("{DESCRIPTOR_NAME}: {e}")]))
}

/// Verifies a bundle in place.
///
/// Every descriptor value is untrusted until validated. The checks
/// run in order and any failing step refuses the whole bundle,
/// naming every offender that step found: descriptor schemas plus
/// division and run id validation, the normative layout at every
/// depth, checksum framing and the checksum chain with the listed
/// set proven equal to the enumerated tree before anything is hashed
/// by name, complete newline-terminated shards, the rules snapshot
/// bound to the effective records, artifact identity through the
/// pure path mapping with hashes and no unreferenced mirror file,
/// the portable collision check, and exact named count and coverage
/// agreement.
pub fn verify(root: &Path) -> Result<VerifyReport> {
    let verb = "verify";

    // Step 1: the descriptor parses, its schemas are recognized, and
    // its arrays hold: run ids inside the grammar, bytewise sorted,
    // unique. Division names inside the producer grammar, bytewise
    // sorted, unique, and unique under ASCII case folding, before any
    // name is ever used as a path.
    let descriptor = read_descriptor(root)?;
    let mut problems = Vec::new();
    for (index, run_id) in descriptor.run_ids.iter().enumerate() {
        if !valid_run_id(run_id) {
            problems.push(format!("run id {run_id:?} is outside the run id grammar"));
        }
        if index > 0 {
            match run_id.cmp(&descriptor.run_ids[index - 1]) {
                std::cmp::Ordering::Greater => {}
                std::cmp::Ordering::Equal => {
                    problems.push(format!("duplicate run id {run_id:?}"));
                }
                std::cmp::Ordering::Less => {
                    problems.push(format!("run id {run_id:?} is not in bytewise order"));
                }
            }
        }
    }
    let mut folded = BTreeSet::new();
    for (index, division) in descriptor.divisions.iter().enumerate() {
        if crate::pipeline::validate_division(division).is_err() {
            problems.push(format!("division name {division:?} is outside the grammar"));
            continue;
        }
        if index > 0 && division <= &descriptor.divisions[index - 1] {
            problems.push(format!(
                "division {division:?} is duplicated or not in bytewise order"
            ));
        }
        if !folded.insert(division.to_ascii_lowercase()) {
            problems.push(format!(
                "division {division:?} collides with another under ASCII case folding"
            ));
        }
    }
    if !problems.is_empty() {
        return Err(refused(verb, problems));
    }

    // Step 2: the normative layout at every depth. The root holds
    // exactly the five entries, manifest/ exactly the shard files,
    // rules/ exactly the two snapshot files, mirror/ exactly one
    // subtree per division, and no directory below mirror/<division>
    // exists without a file inside it.
    let entries = enumerate_entries(root)?;
    let mut problems = Vec::new();
    let mut expected_shards: BTreeSet<String> = descriptor
        .divisions
        .iter()
        .map(|d| format!("{d}.jsonl"))
        .collect();
    let division_set: BTreeSet<&str> = descriptor.divisions.iter().map(String::as_str).collect();
    let mut dirs_with_files: BTreeSet<String> = BTreeSet::new();
    for (path, is_dir) in &entries {
        if !is_dir {
            let mut ancestor = path.as_str();
            while let Some(slash) = ancestor.rfind('/') {
                ancestor = &ancestor[..slash];
                dirs_with_files.insert(ancestor.to_string());
            }
        }
    }
    for (path, is_dir) in &entries {
        let segments: Vec<&str> = path.split('/').collect();
        let expected = match (segments.as_slice(), *is_dir) {
            ([name], false) if *name == DESCRIPTOR_NAME || *name == CHECKSUMS_NAME => true,
            (["manifest"] | ["mirror"] | ["rules"], true) => true,
            (["manifest", shard], false) => expected_shards.remove(*shard),
            (["rules", file], false) => *file == "formats.toml" || *file == "converters.toml",
            (["mirror", division], true) => division_set.contains(division),
            (["mirror", division, ..], is_dir) => {
                division_set.contains(division) && (!is_dir || dirs_with_files.contains(path))
            }
            _ => false,
        };
        if !expected {
            let what = if *is_dir && dirs_with_files.contains(path) {
                "unexpected entry"
            } else if *is_dir {
                "empty directory"
            } else {
                "unexpected entry"
            };
            problems.push(format!("{what}: {path}"));
        }
    }
    for missing in &expected_shards {
        problems.push(format!("missing shard: manifest/{missing}"));
    }
    for required in [
        DESCRIPTOR_NAME,
        CHECKSUMS_NAME,
        "manifest",
        "mirror",
        "rules",
    ] {
        if !entries.iter().any(|(path, _)| path == required) {
            problems.push(format!("missing bundle entry: {required}"));
        }
    }
    for name in ["rules/formats.toml", "rules/converters.toml"] {
        if !entries.iter().any(|(path, is_dir)| path == name && !is_dir) {
            problems.push(format!("missing bundle entry: {name}"));
        }
    }
    for division in &descriptor.divisions {
        let dir = format!("mirror/{division}");
        if !entries.iter().any(|(path, is_dir)| *path == dir && *is_dir) {
            problems.push(format!("missing mirror subtree: {dir}"));
        }
    }
    if !problems.is_empty() {
        return Err(refused(verb, problems));
    }

    // Step 3: checksums.b3 framing (UTF-8, LF only, trailing
    // newline), the recorded hash, and the chain. The listed path set
    // must equal the enumerated tree set before anything is hashed,
    // so a listed path can never name a file outside the bundle on
    // any host.
    let checksums_path = root.join(CHECKSUMS_NAME);
    let checksums_bytes = fs::read(&checksums_path)
        .map_err(|e| refused(verb, vec![format!("{CHECKSUMS_NAME} unreadable: {e}")]))?;
    if checksums_bytes.contains(&b'\r') {
        return Err(refused(
            verb,
            vec![format!(
                "{CHECKSUMS_NAME} contains a carriage return, the file is LF only"
            )],
        ));
    }
    if !checksums_bytes.ends_with(b"\n") {
        return Err(refused(
            verb,
            vec![format!("{CHECKSUMS_NAME} does not end with a newline")],
        ));
    }
    let actual = hash::hash_bytes(&checksums_bytes);
    if actual != descriptor.checksums_hash {
        return Err(refused(
            verb,
            vec![format!(
                "{CHECKSUMS_NAME} hashes to {actual} but the descriptor records {}",
                descriptor.checksums_hash
            )],
        ));
    }
    let checksums_text = String::from_utf8(checksums_bytes)
        .map_err(|_| refused(verb, vec![format!("{CHECKSUMS_NAME} is not UTF-8")]))?;
    let listed =
        parse_checksum_lines(&checksums_text).map_err(|problems| refused(verb, problems))?;
    let tree_files: BTreeSet<&str> = entries
        .iter()
        .filter(|(path, is_dir)| !is_dir && path != DESCRIPTOR_NAME && path != CHECKSUMS_NAME)
        .map(|(path, _)| path.as_str())
        .collect();
    let listed_map: BTreeMap<&str, &str> = listed
        .iter()
        .map(|(digest, path)| (path.as_str(), digest.as_str()))
        .collect();
    let mut problems = Vec::new();
    for path in listed_map.keys() {
        if !tree_files.contains(path) {
            problems.push(format!("listed file missing: {path}"));
        }
    }
    for path in &tree_files {
        if !listed_map.contains_key(path) {
            problems.push(format!("unlisted file: {path}"));
        }
    }
    if !problems.is_empty() {
        return Err(refused(verb, problems));
    }
    let mut computed: HashMap<String, String> = HashMap::new();
    for path in &tree_files {
        let digest = hash::hash_file(&root.join(path))?;
        if digest != listed_map[path] {
            problems.push(format!("checksum mismatch: {path}"));
        }
        computed.insert((*path).to_string(), digest);
    }
    if !problems.is_empty() {
        return Err(refused(verb, problems));
    }

    // Step 4: every shard ends with a newline and every line parses
    // as a complete record. Clean-write is a bundle@1 property, and
    // the producer's torn-line tolerance never touches a bundle.
    let mut shards: Vec<(String, Vec<Record>)> = Vec::new();
    let mut record_count = 0u64;
    let mut problems = Vec::new();
    for division in &descriptor.divisions {
        let relative = format!("manifest/{division}.jsonl");
        match manifest::read_shard_strict(&root.join(&relative)) {
            Ok(records) => {
                record_count += records.len() as u64;
                shards.push((division.clone(), records));
            }
            Err(error) => problems.push(format!("{relative}: {error}")),
        }
    }
    if !problems.is_empty() {
        return Err(refused(verb, problems));
    }

    // Step 5: the rules snapshot binds to the records, and every
    // text-bearing effective record carries exactly the pure path
    // mapping with its artifact present and matching. text_path is
    // mirror-root-relative, checksums paths are bundle-root-relative,
    // and the mirror/ prefix maps between the two bases. Every mirror
    // file must belong to some effective record's envelope.
    let mut problems = Vec::new();
    let formats_text = fs::read_to_string(root.join("rules/formats.toml"))
        .map_err(|e| Error::io("read", &root.join("rules/formats.toml"), e))?;
    let converters_text = fs::read_to_string(root.join("rules/converters.toml"))
        .map_err(|e| Error::io("read", &root.join("rules/converters.toml"), e))?;
    let snapshot_version = match (
        rules_file_version(&formats_text, "rules/formats.toml"),
        rules_file_version(&converters_text, "rules/converters.toml"),
    ) {
        (Ok(formats_version), Ok(converters_version)) => {
            if formats_version != converters_version {
                return Err(refused(
                    verb,
                    vec![format!(
                        "rules snapshot files disagree: formats.toml declares {formats_version:?}, converters.toml declares {converters_version:?}"
                    )],
                ));
            }
            formats_version
        }
        (formats, converters) => {
            let mut problems = Vec::new();
            if let Err(message) = formats {
                problems.push(message);
            }
            if let Err(message) = converters {
                problems.push(message);
            }
            return Err(refused(verb, problems));
        }
    };
    let mut referenced: BTreeSet<String> = BTreeSet::new();
    let mut owners: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut counts = BTreeMap::new();
    let mut coverage = BTreeMap::new();
    let mut effective_by_division = Vec::new();
    for (division, records) in &shards {
        let effective = effective_records(records);
        counts.insert(division.clone(), tally_counts(records));
        coverage.insert(division.clone(), tally_coverage(&effective));
        effective_by_division.push((division.clone(), effective));
    }
    for (division, effective) in &effective_by_division {
        for record in effective.values() {
            if record.rules_version != snapshot_version {
                problems.push(format!(
                    "{division}:{}: record rules_version {:?} does not match the snapshot rules version {snapshot_version:?}",
                    record.source_path, record.rules_version
                ));
            }
            let (Some(text_path), Some(text_hash)) = (&record.text_path, &record.text_hash) else {
                continue;
            };
            let expected = crate::mirror::recorded_text_path(division, &record.source_path);
            if *text_path != expected {
                problems.push(format!(
                    "{division}:{}: text_path {text_path} is not the pure mapping {expected}",
                    record.source_path
                ));
                continue;
            }
            owners
                .entry(collision_key(text_path))
                .or_default()
                .push(format!("{division}:{}", record.source_path));
            let bundle_path = format!("mirror/{text_path}");
            match computed.get(bundle_path.as_str()) {
                Some(actual) if actual == text_hash => {}
                Some(_) => problems.push(format!(
                    "{division}:{}: artifact {text_path} does not hash to the recorded text_hash",
                    record.source_path
                )),
                None => problems.push(format!(
                    "{division}:{}: artifact {text_path} is missing",
                    record.source_path
                )),
            }
            referenced.insert(bundle_path.clone());
            if let Some(base) = bundle_path.strip_suffix(".txt") {
                referenced.insert(format!("{base}.segments.jsonl"));
                referenced.insert(format!("{base}.review.md"));
            }
        }
    }
    for path in &tree_files {
        if path.starts_with("mirror/") && !referenced.contains(*path) {
            problems.push(format!("unreferenced mirror file: {path}"));
        }
    }
    if !problems.is_empty() {
        return Err(refused(verb, problems));
    }

    // Step 6: the portable collision check. The receiving fleet has
    // case-insensitive filesystems, so paths that fold together after
    // NFC and ASCII case folding would corrupt the mirror on
    // extraction.
    let mut problems = Vec::new();
    for (key, owner) in &owners {
        if owner.len() > 1 {
            problems.push(format!(
                "text_path collision on {key}: {}",
                owner.join(", ")
            ));
        }
    }
    if !problems.is_empty() {
        return Err(refused(verb, problems));
    }

    // Step 7: the descriptor's counts and coverage match the shards
    // exactly, named per division and per field.
    let mut problems = Vec::new();
    let count_fields = |c: &DivisionCounts| {
        [
            ("converted", c.converted),
            ("failed", c.failed),
            ("unsupported", c.unsupported),
            ("skipped_unchanged", c.skipped_unchanged),
            ("dedup", c.dedup),
            ("total", c.total),
        ]
    };
    let divisions_union: BTreeSet<&String> =
        descriptor.counts.keys().chain(counts.keys()).collect();
    for division in divisions_union {
        match (descriptor.counts.get(division), counts.get(division)) {
            (Some(recorded), Some(recomputed)) => {
                for ((field, recorded), (_, recomputed)) in count_fields(recorded)
                    .into_iter()
                    .zip(count_fields(recomputed))
                {
                    if recorded != recomputed {
                        problems.push(format!(
                            "counts.{field} for {division}: descriptor {recorded}, shards {recomputed}"
                        ));
                    }
                }
            }
            (Some(_), None) => problems.push(format!("counts for {division}: no such shard")),
            (None, Some(_)) => {
                problems.push(format!("counts for {division}: absent from the descriptor"));
            }
            (None, None) => {}
        }
    }
    let coverage_fields = |c: &DivisionCoverage| [("covered", c.covered), ("total", c.total)];
    let divisions_union: BTreeSet<&String> =
        descriptor.coverage.keys().chain(coverage.keys()).collect();
    for division in divisions_union {
        match (descriptor.coverage.get(division), coverage.get(division)) {
            (Some(recorded), Some(recomputed)) => {
                for ((field, recorded), (_, recomputed)) in coverage_fields(recorded)
                    .into_iter()
                    .zip(coverage_fields(recomputed))
                {
                    if recorded != recomputed {
                        problems.push(format!(
                            "coverage.{field} for {division}: descriptor {recorded}, shards {recomputed}"
                        ));
                    }
                }
            }
            (Some(_), None) => problems.push(format!("coverage for {division}: no such shard")),
            (None, Some(_)) => {
                problems.push(format!(
                    "coverage for {division}: absent from the descriptor"
                ));
            }
            (None, None) => {}
        }
    }
    if !problems.is_empty() {
        return Err(refused(verb, problems));
    }

    Ok(VerifyReport {
        bundle: root.display().to_string(),
        divisions: descriptor.divisions.clone(),
        files_verified: listed.len() as u64,
        records: record_count,
        counts,
        coverage,
    })
}

/// The `merge` verb output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MergeReport {
    /// The merged bundle root.
    pub output: String,
    /// How many input bundles merged.
    pub inputs: u64,
    /// Divisions the merged bundle carries.
    pub divisions: Vec<String>,
    /// BLAKE3 hex of the merged checksums.b3.
    pub checksums_hash: String,
}

/// Merges two or more verified bundles into one.
///
/// Every input verifies first, divisions must be disjoint
/// case-insensitively, rules snapshots must be byte-identical, and
/// every shard, artifact, and rules file copies through byte for
/// byte. The output verifies before the merge reports success.
pub fn merge(inputs: &[PathBuf], output: &Path) -> Result<MergeReport> {
    let verb = "merge";
    if inputs.len() < 2 {
        return Err(Error::Layout {
            message: "merge needs at least two input bundles".to_string(),
        });
    }

    // Verify every input and load its descriptor. The schema tags
    // make every parsed descriptor carry identical schema and
    // manifest_schema strings, so equality holds by construction.
    let mut descriptors = Vec::new();
    for input in inputs {
        verify(input).map_err(|error| match error {
            Error::Refused { problems, .. } => refused(
                verb,
                problems
                    .into_iter()
                    .map(|p| format!("input {}: {p}", input.display()))
                    .collect(),
            ),
            other => other,
        })?;
        descriptors.push((input.clone(), read_descriptor(input)?));
    }

    // Divisions must be disjoint, case-insensitively, because a
    // re-bundle supersedes rather than unions and merge never guesses
    // which same-named division is newer.
    let mut problems = Vec::new();
    let mut owners: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (input, descriptor) in &descriptors {
        for division in &descriptor.divisions {
            owners
                .entry(division.to_ascii_lowercase())
                .or_default()
                .push(format!("{division} in {}", input.display()));
        }
    }
    for owner in owners.values() {
        if owner.len() > 1 {
            problems.push(format!(
                "division appears in more than one input: {}",
                owner.join(", ")
            ));
        }
    }

    // One bundle states one rules provenance.
    let rules_snapshot = |root: &Path| -> Result<BTreeMap<String, Vec<u8>>> {
        let rules_root = root.join("rules");
        let mut snapshot = BTreeMap::new();
        for relative in enumerate_files(&rules_root)? {
            let bytes = fs::read(rules_root.join(&relative))
                .map_err(|e| Error::io("read", &rules_root.join(&relative), e))?;
            snapshot.insert(relative, bytes);
        }
        Ok(snapshot)
    };
    let first_rules = rules_snapshot(&descriptors[0].0)?;
    for (input, _) in &descriptors[1..] {
        if rules_snapshot(input)? != first_rules {
            problems.push(format!(
                "rules snapshot in {} differs from {}",
                input.display(),
                descriptors[0].0.display()
            ));
        }
    }
    if !problems.is_empty() {
        return Err(refused(verb, problems));
    }

    refuse_dirty_output(output)?;
    fs::create_dir_all(output).map_err(|e| Error::io("create_dir", output, e))?;

    // Copy everything byte-identical: shards, mirror trees, and the
    // shared rules snapshot. Nothing is rewritten.
    let mut checksum_entries: Vec<String> = Vec::new();
    for (input, _descriptor) in &descriptors {
        for relative in enumerate_files(input)? {
            if relative == DESCRIPTOR_NAME || relative == CHECKSUMS_NAME {
                continue;
            }
            if relative.starts_with("rules/") && *input != descriptors[0].0 {
                continue;
            }
            let source = input.join(&relative);
            let dest = output.join(&relative);
            if let Some(dir) = dest.parent() {
                fs::create_dir_all(dir).map_err(|e| Error::io("create_dir", dir, e))?;
            }
            fs::copy(&source, &dest).map_err(|e| Error::io("copy", &source, e))?;
        }
        let checksums = fs::read_to_string(input.join(CHECKSUMS_NAME))
            .map_err(|e| Error::io("read", &input.join(CHECKSUMS_NAME), e))?;
        checksum_entries.extend(checksums.lines().map(str::to_string));
    }
    // Every division's mirror subtree exists in the output, empty
    // divisions included, so the merged layout stays normative.
    for (_, descriptor) in &descriptors {
        for division in &descriptor.divisions {
            let dir = output.join("mirror").join(division);
            fs::create_dir_all(&dir).map_err(|e| Error::io("create_dir", &dir, e))?;
        }
    }
    // Lines sort bytewise by path, not by the whole line, so the
    // merged file keeps the same canonical order bundle writes.
    checksum_entries.sort_by(|a, b| {
        let path_of = |line: &str| line.split_once("  ").map(|(_, p)| p.to_string());
        path_of(a).cmp(&path_of(b)).then_with(|| a.cmp(b))
    });
    checksum_entries.dedup();
    let mut checksums = checksum_entries.join("\n");
    checksums.push('\n');
    let checksums_hash = hash::hash_bytes(checksums.as_bytes());
    write_file(output, CHECKSUMS_NAME, checksums.as_bytes())?;

    // Aggregate the descriptor: sorted unions, entries carried
    // through unchanged.
    let mut run_ids: Vec<String> = descriptors
        .iter()
        .flat_map(|(_, d)| d.run_ids.iter().cloned())
        .collect();
    run_ids.sort();
    run_ids.dedup();
    let mut divisions: Vec<String> = descriptors
        .iter()
        .flat_map(|(_, d)| d.divisions.iter().cloned())
        .collect();
    divisions.sort();
    let mut counts = BTreeMap::new();
    let mut coverage = BTreeMap::new();
    for (_, descriptor) in &descriptors {
        counts.extend(descriptor.counts.clone());
        coverage.extend(descriptor.coverage.clone());
    }
    let descriptor = BundleDescriptor {
        schema: BundleSchema,
        manifest_schema: ManifestSchema,
        run_ids,
        divisions: divisions.clone(),
        counts,
        coverage,
        checksums_hash: checksums_hash.clone(),
    };
    write_file(output, DESCRIPTOR_NAME, &descriptor_bytes(&descriptor)?)?;

    // A merge that emits an unverifiable bundle is a failed merge.
    verify(output).map_err(|error| match error {
        Error::Refused { problems, .. } => refused(
            verb,
            problems
                .into_iter()
                .map(|p| format!("merged output: {p}"))
                .collect(),
        ),
        other => other,
    })?;

    Ok(MergeReport {
        output: output.display().to_string(),
        inputs: inputs.len() as u64,
        divisions,
        checksums_hash,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_id_grammar_accepts_and_rejects() {
        assert!(valid_run_id("a"));
        assert!(valid_run_id(&"f".repeat(64)));
        assert!(valid_run_id("run-1.2_3"));
        assert!(!valid_run_id(""));
        assert!(!valid_run_id(&"f".repeat(65)));
        assert!(!valid_run_id("-leading-dash"));
        assert!(!valid_run_id(".leading-dot"));
        assert!(!valid_run_id("has space"));
        assert!(!valid_run_id("ctrl\u{7}char"));
        assert!(!valid_run_id("caf\u{e9}"));
    }

    #[test]
    fn collision_keys_fold_ascii_case_and_nfc() {
        assert_eq!(
            collision_key("emea/A.TXT.txt"),
            collision_key("emea/a.txt.txt")
        );
        // Composed and decomposed forms of the same accented name.
        assert_eq!(
            collision_key("emea/r\u{e9}sum\u{e9}.txt"),
            collision_key("emea/re\u{301}sume\u{301}.txt")
        );
        // The fold is ASCII-only: non-ASCII case stays distinct.
        assert_ne!(
            collision_key("emea/\u{c9}.txt"),
            collision_key("emea/\u{e9}.txt")
        );
        assert_ne!(collision_key("emea/a.txt"), collision_key("apac/a.txt"));
    }
}
