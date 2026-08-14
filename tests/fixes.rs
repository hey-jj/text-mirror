//! Regression tests for reviewed failure scenarios, one per finding.

use std::fs;
use std::path::{Path, PathBuf};

use text_mirror::hash;
use text_mirror::manifest::{self, ArtifactKind, ManifestSchema, ManifestWriter, Record, Status};
use text_mirror::pipeline::{self, Rules, RunOptions};
use text_mirror::walk::WalkOptions;

struct Setup {
    _dir: tempfile::TempDir,
    root: PathBuf,
    mirror: PathBuf,
    manifest_dir: PathBuf,
}

fn setup() -> Setup {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("source");
    let mirror = dir.path().join("mirror");
    let manifest_dir = dir.path().join("manifest");
    fs::create_dir_all(&root).unwrap();
    Setup {
        _dir: dir,
        root,
        mirror,
        manifest_dir,
    }
}

fn run(setup: &Setup, rules: &Rules) -> text_mirror::report::RunReport {
    pipeline::run(
        rules,
        &RunOptions {
            root: &setup.root,
            mirror_root: &setup.mirror,
            manifest_dir: &setup.manifest_dir,
            division: "alpha",
            walk: WalkOptions::default(),
        },
    )
    .unwrap()
}

fn terminal(setup: &Setup, source_path: &str) -> Record {
    manifest::read_shard(&setup.manifest_dir.join("alpha.jsonl"))
        .unwrap()
        .records
        .into_iter()
        .rev()
        .find(|r| r.source_path == source_path)
        .unwrap()
}

/// Every path under `root` with a content hash for regular files, so
/// two snapshots compare byte-identical trees.
fn tree_snapshot(root: &Path) -> Vec<(PathBuf, Option<String>)> {
    fn visit(dir: &Path, base: &Path, out: &mut Vec<(PathBuf, Option<String>)>) {
        for entry in fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            let relative = path.strip_prefix(base).unwrap().to_path_buf();
            let file_type = entry.file_type().unwrap();
            if file_type.is_dir() {
                out.push((relative, None));
                visit(&path, base, out);
            } else {
                out.push((relative, hash::hash_file(&path).ok()));
            }
        }
    }
    let mut out = Vec::new();
    visit(root, root, &mut out);
    out.sort();
    out
}

// B1: identical bytes under a format handled by a different converter
// must not borrow the canonical artifact.
#[test]
fn dedup_respects_format_ownership() {
    let setup = setup();
    fs::write(setup.root.join("a.txt"), "shared payload\n").unwrap();
    fs::write(setup.root.join("b.pdf"), "shared payload\n").unwrap();
    fs::write(setup.root.join("c.xlsb"), "shared payload\n").unwrap();

    let rules = Rules::builtin().unwrap();
    let report = run(&setup, &rules);
    assert_eq!(report.counts.converted, 1);
    assert_eq!(report.counts.dedup, 0);

    // The pdf converter owns b.pdf, and these bytes are no pdf.
    let pdf = terminal(&setup, "b.pdf");
    assert_eq!(pdf.status, Status::Failed);
    assert!(pdf.text_path.is_none());
    assert!(!setup.mirror.join("b.pdf.txt").exists());

    // No converter claims xlsb, so it cannot borrow the artifact
    // either, and it carries the declared interim reason.
    let unclaimed = terminal(&setup, "c.xlsb");
    assert_eq!(unclaimed.status, Status::Unsupported);
    assert_eq!(
        unclaimed.error.as_deref(),
        Some("hidden-visibility-unresolved")
    );
    assert!(unclaimed.text_path.is_none());
    assert!(!setup.mirror.join("c.xlsb.txt").exists());
}

// B2 and B4: a seed from another rules version never becomes the
// canonical, and a dedup record hashes the bytes it actually wrote.
#[test]
fn stale_seed_is_ignored_and_dedup_hashes_written_bytes() {
    let setup = setup();
    fs::write(setup.root.join("a.txt"), "payload\n").unwrap();
    fs::write(setup.root.join("b.txt"), "payload\n").unwrap();

    // A prior shard from an older rules version, whose recorded text
    // hash matches nothing on disk.
    fs::create_dir_all(&setup.mirror).unwrap();
    fs::write(setup.mirror.join("a.txt.txt"), "old artifact\n").unwrap();
    let stale = Record {
        schema: ManifestSchema,
        source_path: "a.txt".to_string(),
        source_hash: hash::hash_bytes(b"payload\n"),
        source_size: 8,
        declared_format: Some("text".to_string()),
        detected_format: "text".to_string(),
        format_mismatch: false,
        status: Status::Converted,
        text_path: Some("a.txt.txt".to_string()),
        text_hash: Some(hash::hash_bytes(b"old artifact\n")),
        artifact_kind: Some(ArtifactKind::Text),
        converter_id: Some("text-passthrough".to_string()),
        converter_version: Some("1.0.0".to_string()),
        tool_version: None,
        rules_version: "0".to_string(),
        media: None,
        parent_source: None,
        dedup_of: None,
        warnings: Vec::new(),
        error: None,
        duration_ms: None,
    };
    let shard_path = setup.manifest_dir.join("alpha.jsonl");
    let mut writer = ManifestWriter::open(&shard_path).unwrap();
    writer.append(&stale).unwrap();
    drop(writer);

    let rules = Rules::builtin().unwrap();
    let report = run(&setup, &rules);
    assert_eq!(report.counts.converted, 1);
    assert_eq!(report.counts.dedup, 1);

    // The rules bump reconverted the canonical instead of trusting it.
    let canonical = terminal(&setup, "a.txt");
    assert_eq!(canonical.status, Status::Converted);
    assert_eq!(canonical.rules_version, "2");
    assert_eq!(
        fs::read_to_string(setup.mirror.join("a.txt.txt")).unwrap(),
        "payload\n"
    );

    // The duplicate followed the fresh conversion, and its text hash
    // matches the bytes at its own path.
    let duplicate = terminal(&setup, "b.txt");
    assert_eq!(duplicate.status, Status::Dedup);
    assert_eq!(duplicate.dedup_of.as_deref(), Some("a.txt"));
    let written = fs::read(setup.mirror.join("b.txt.txt")).unwrap();
    assert_eq!(
        duplicate.text_hash.as_deref(),
        Some(hash::hash_bytes(&written).as_str())
    );
    assert_eq!(written, b"payload\n");

    // H2: the recorded source hash binds to the bytes that converted.
    assert_eq!(canonical.source_hash, hash::hash_bytes(b"payload\n"));
}

// B3: a duplicate whose canonical artifact vanished converts for
// itself instead of failing forever.
#[test]
fn vanished_canonical_falls_through_to_conversion() {
    let setup = setup();
    fs::write(setup.root.join("a.txt"), "twin content\n").unwrap();
    fs::write(setup.root.join("b.txt"), "twin content\n").unwrap();

    let rules = Rules::builtin().unwrap();
    run(&setup, &rules);

    // The canonical source and both artifacts disappear.
    fs::remove_file(setup.root.join("a.txt")).unwrap();
    fs::remove_file(setup.mirror.join("a.txt.txt")).unwrap();
    fs::remove_file(setup.mirror.join("b.txt.txt")).unwrap();

    let report = run(&setup, &rules);
    assert_eq!(report.counts.converted, 1);
    assert_eq!(report.counts.failed, 0);

    let record = terminal(&setup, "b.txt");
    assert_eq!(record.status, Status::Converted);
    assert_eq!(
        fs::read_to_string(setup.mirror.join("b.txt.txt")).unwrap(),
        "twin content\n"
    );
}

// B5: a torn tail from a killed run is dropped with a warning, and the
// affected source is re-recorded by the next run.
#[test]
fn torn_manifest_tail_recovers_on_the_next_run() {
    let setup = setup();
    fs::write(setup.root.join("a.txt"), "content\n").unwrap();

    let rules = Rules::builtin().unwrap();
    run(&setup, &rules);

    let shard_path = setup.manifest_dir.join("alpha.jsonl");
    let mut damaged = fs::read(&shard_path).unwrap();
    damaged.extend_from_slice(br#"{"schema":"text-mirror/manifest@1","source_"#);
    fs::write(&shard_path, damaged).unwrap();

    let report = run(&setup, &rules);
    assert_eq!(report.warnings.len(), 1);
    assert!(report.warnings[0].contains("torn"));
    assert_eq!(report.counts.skipped_unchanged, 1);

    // The shard reads clean again after the repair.
    let shard = manifest::read_shard(&shard_path).unwrap();
    assert!(shard.warnings.is_empty());
    assert_eq!(shard.records.len(), 2);
}

// B6: a source that turns invalid loses its stale artifact in the same
// pass that records the failure.
#[test]
fn stale_artifact_is_removed_after_a_failed_outcome() {
    let setup = setup();
    let source = setup.root.join("report.txt");
    fs::write(&source, "valid text\n").unwrap();

    let rules = Rules::builtin().unwrap();
    run(&setup, &rules);
    assert!(setup.mirror.join("report.txt.txt").is_file());

    fs::write(&source, b"broken \xff bytes").unwrap();
    let report = run(&setup, &rules);
    assert_eq!(report.counts.failed, 1);

    let record = terminal(&setup, "report.txt");
    assert_eq!(record.status, Status::Failed);
    assert!(record.text_path.is_none());
    assert!(!setup.mirror.join("report.txt.txt").exists());
}

// B7: a mirror path collision fails one source and the run continues.
#[test]
fn mirror_collision_fails_one_source_and_continues() {
    let setup = setup();
    fs::write(setup.root.join("x.md"), "top\n").unwrap();
    fs::create_dir_all(setup.root.join("x.md.txt")).unwrap();
    fs::write(setup.root.join("x.md.txt/y.txt"), "inner\n").unwrap();
    fs::write(setup.root.join("z.txt"), "after\n").unwrap();

    let rules = Rules::builtin().unwrap();
    let report = run(&setup, &rules);
    assert_eq!(report.counts.converted, 2);
    assert_eq!(report.counts.failed, 1);

    let collided = terminal(&setup, "x.md.txt/y.txt");
    assert_eq!(collided.status, Status::Failed);
    assert!(
        collided
            .error
            .as_deref()
            .unwrap()
            .starts_with("mirror_write_error")
    );
    assert_eq!(terminal(&setup, "z.txt").status, Status::Converted);
}

// B8: one unreadable file fails alone and later sources still convert.
#[cfg(unix)]
#[test]
fn unreadable_file_does_not_starve_the_rest_of_the_run() {
    use std::os::unix::fs::PermissionsExt;

    let setup = setup();
    fs::write(setup.root.join("a.txt"), "first\n").unwrap();
    let blocked = setup.root.join("blocked.txt");
    fs::write(&blocked, "hidden\n").unwrap();
    fs::set_permissions(&blocked, fs::Permissions::from_mode(0o000)).unwrap();
    fs::write(setup.root.join("z.txt"), "last\n").unwrap();

    let rules = Rules::builtin().unwrap();
    let report = run(&setup, &rules);
    fs::set_permissions(&blocked, fs::Permissions::from_mode(0o644)).unwrap();

    assert_eq!(report.counts.converted, 2);
    assert_eq!(report.counts.failed, 1);
    let record = terminal(&setup, "blocked.txt");
    assert_eq!(record.status, Status::Failed);
    assert!(
        record
            .error
            .as_deref()
            .unwrap()
            .starts_with("source_io_error")
    );
    assert_eq!(terminal(&setup, "z.txt").status, Status::Converted);
}

// B9: a division root that is itself a symlink is refused.
#[cfg(unix)]
#[test]
fn symlinked_root_is_rejected() {
    let setup = setup();
    fs::write(setup.root.join("outside.txt"), "secret\n").unwrap();
    let link = setup.root.parent().unwrap().join("root-link");
    std::os::unix::fs::symlink(&setup.root, &link).unwrap();

    let rules = Rules::builtin().unwrap();
    let err = pipeline::run(
        &rules,
        &RunOptions {
            root: &link,
            mirror_root: &setup.mirror,
            manifest_dir: &setup.manifest_dir,
            division: "alpha",
            walk: WalkOptions::default(),
        },
    )
    .unwrap_err();
    assert!(err.to_string().contains("symlink"));
}

// B10: a symlink entry becomes a recorded outcome hashed over its
// readlink target bytes, and special entries are counted.
#[cfg(unix)]
#[test]
fn symlink_entries_are_recorded_not_skipped() {
    let setup = setup();
    fs::write(setup.root.join("real.txt"), "content\n").unwrap();
    std::os::unix::fs::symlink("real.txt", setup.root.join("link.txt")).unwrap();
    let fifo_made = std::process::Command::new("mkfifo")
        .arg(setup.root.join("pipe"))
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    let rules = Rules::builtin().unwrap();
    let report = run(&setup, &rules);
    assert_eq!(report.counts.converted, 1);
    assert_eq!(report.counts.unsupported, 1);
    if fifo_made {
        assert_eq!(report.special_entries, 1);
        assert_eq!(report.sources, 2);
    }

    let record = terminal(&setup, "link.txt");
    assert_eq!(record.status, Status::Unsupported);
    assert_eq!(record.detected_format, "symlink");
    assert_eq!(record.source_hash, hash::hash_bytes(b"real.txt"));
    assert_eq!(record.source_size, "real.txt".len() as u64);
    assert!(record.text_path.is_none());
    assert!(!setup.mirror.join("link.txt.txt").exists());
}

// B11 and F3: output roots inside the division root are refused
// before any work, and a refusal leaves the division root
// byte-identical, intermediate directories included.
#[test]
fn outputs_inside_the_root_are_refused() {
    let setup = setup();
    fs::write(setup.root.join("a.txt"), "content\n").unwrap();
    let rules = Rules::builtin().unwrap();
    let before = tree_snapshot(&setup.root);

    let err = pipeline::run(
        &rules,
        &RunOptions {
            root: &setup.root,
            mirror_root: &setup.root.join("mirror"),
            manifest_dir: &setup.manifest_dir,
            division: "alpha",
            walk: WalkOptions::default(),
        },
    )
    .unwrap_err();
    assert!(err.to_string().contains("mirror root"));
    assert_eq!(tree_snapshot(&setup.root), before);

    let err = pipeline::run(
        &rules,
        &RunOptions {
            root: &setup.root,
            mirror_root: &setup.mirror,
            manifest_dir: &setup.root.join("manifest"),
            division: "alpha",
            walk: WalkOptions::default(),
        },
    )
    .unwrap_err();
    assert!(err.to_string().contains("manifest directory"));
    assert_eq!(tree_snapshot(&setup.root), before);

    // A parent component cannot dodge the check, and the refusal
    // creates nothing, not even the intermediate directory.
    let dodged = setup.root.join("sub/../mirror");
    let err = pipeline::run(
        &rules,
        &RunOptions {
            root: &setup.root,
            mirror_root: &dodged,
            manifest_dir: &setup.manifest_dir,
            division: "alpha",
            walk: WalkOptions::default(),
        },
    )
    .unwrap_err();
    assert!(err.to_string().contains("mirror root"));
    assert!(!setup.root.join("sub").exists());
    assert_eq!(tree_snapshot(&setup.root), before);
}

// F2: an output root that is an ancestor of the division root is
// refused, so artifacts can never land inside the source tree when
// names collide.
#[test]
fn root_inside_an_output_root_is_refused() {
    let setup = setup();
    fs::create_dir_all(setup.root.join("src")).unwrap();
    fs::write(setup.root.join("src/a.txt"), "content\n").unwrap();
    let rules = Rules::builtin().unwrap();
    let ancestor = setup.root.parent().unwrap().to_path_buf();
    let before = tree_snapshot(&setup.root);

    let err = pipeline::run(
        &rules,
        &RunOptions {
            root: &setup.root,
            mirror_root: &ancestor,
            manifest_dir: &setup.manifest_dir,
            division: "alpha",
            walk: WalkOptions::default(),
        },
    )
    .unwrap_err();
    let message = err.to_string();
    assert!(message.contains("division root"));
    assert!(message.contains("mirror root"));

    let err = pipeline::run(
        &rules,
        &RunOptions {
            root: &setup.root,
            mirror_root: &setup.mirror,
            manifest_dir: &ancestor,
            division: "alpha",
            walk: WalkOptions::default(),
        },
    )
    .unwrap_err();
    assert!(err.to_string().contains("manifest directory"));
    assert_eq!(tree_snapshot(&setup.root), before);
}

// F1: a torn tail that breaks inside a multibyte UTF-8 character is
// tolerated like any other torn tail, and the next run recovers.
#[test]
fn multibyte_torn_tail_recovers_on_the_next_run() {
    let setup = setup();
    fs::write(setup.root.join("R\u{e9}sum\u{e9}.txt"), "accent\n").unwrap();

    let rules = Rules::builtin().unwrap();
    run(&setup, &rules);

    // The recorded path carries the accented name, so cutting right
    // after a 0xC3 lead byte leaves an invalid UTF-8 tail.
    let shard_path = setup.manifest_dir.join("alpha.jsonl");
    let content = fs::read(&shard_path).unwrap();
    let lead = content.iter().position(|b| *b == 0xC3).unwrap();
    let mut damaged = content.clone();
    damaged.extend_from_slice(&content[..=lead]);
    fs::write(&shard_path, damaged).unwrap();

    let report = run(&setup, &rules);
    assert_eq!(report.warnings.len(), 1);
    assert!(report.warnings[0].contains("torn"));
    assert_eq!(report.counts.skipped_unchanged, 1);

    let shard = manifest::read_shard(&shard_path).unwrap();
    assert!(shard.warnings.is_empty());
    assert_eq!(shard.records.len(), 2);
}

// Minor: a symlink whose own name is not valid UTF-8 takes the
// non_utf8_path branch instead of recording a lossy key. Guarded, most
// filesystems here refuse such names.
#[cfg(unix)]
#[test]
fn non_utf8_symlink_name_records_failed() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let setup = setup();
    fs::write(setup.root.join("ok.txt"), "content\n").unwrap();
    let bad_name = OsStr::from_bytes(b"link-\xff.txt");
    if std::os::unix::fs::symlink("ok.txt", setup.root.join(Path::new(bad_name))).is_err() {
        return;
    }

    let rules = Rules::builtin().unwrap();
    let report = run(&setup, &rules);
    assert_eq!(report.counts.converted, 1);
    assert_eq!(report.counts.failed, 1);
    assert_eq!(report.counts.unsupported, 0);

    let records = manifest::read_shard(&setup.manifest_dir.join("alpha.jsonl"))
        .unwrap()
        .records;
    let failed = records.iter().find(|r| r.status == Status::Failed).unwrap();
    assert!(
        failed
            .error
            .as_deref()
            .unwrap()
            .starts_with("non_utf8_path")
    );
}

// H1: a corrupted artifact is caught by the skip rehash and
// reconverted instead of trusted.
#[test]
fn corrupted_artifact_is_reconverted_not_skipped() {
    let setup = setup();
    fs::write(setup.root.join("a.txt"), "true content\n").unwrap();

    let rules = Rules::builtin().unwrap();
    run(&setup, &rules);
    fs::write(setup.mirror.join("a.txt.txt"), "tampered\n").unwrap();

    let report = run(&setup, &rules);
    assert_eq!(report.counts.skipped_unchanged, 0);
    assert_eq!(report.counts.converted, 1);
    assert_eq!(
        fs::read_to_string(setup.mirror.join("a.txt.txt")).unwrap(),
        "true content\n"
    );
}

// H5: a non-UTF-8 source name records a failure and never names an
// artifact. APFS refuses such names, so the tree setup is guarded.
#[cfg(unix)]
#[test]
fn non_utf8_source_name_fails_without_an_artifact() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let setup = setup();
    let bad_name = OsStr::from_bytes(b"bad-\xff-name.txt");
    let bad_path = setup.root.join(Path::new(bad_name));
    if fs::write(&bad_path, "content\n").is_err() {
        // The filesystem refuses the name, so the run can never see it.
        return;
    }
    fs::write(setup.root.join("ok.txt"), "content\n").unwrap();

    let rules = Rules::builtin().unwrap();
    let report = run(&setup, &rules);
    assert_eq!(report.counts.converted, 1);
    assert_eq!(report.counts.failed, 1);

    let records = manifest::read_shard(&setup.manifest_dir.join("alpha.jsonl"))
        .unwrap()
        .records;
    let failed = records.iter().find(|r| r.status == Status::Failed).unwrap();
    assert!(
        failed
            .error
            .as_deref()
            .unwrap()
            .starts_with("non_utf8_path")
    );
    assert!(failed.text_path.is_none());
}
