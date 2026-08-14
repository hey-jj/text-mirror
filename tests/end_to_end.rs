//! End-to-end test of the library pipeline on a temp tree.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use text_mirror::manifest::{self, Record, Status};
use text_mirror::pipeline::{self, Rules, RunOptions};
use text_mirror::walk::WalkOptions;

const PNG_MAGIC: &[u8] = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR";

fn build_tree(root: &Path) {
    fs::create_dir_all(root.join("docs/sub")).unwrap();
    fs::write(root.join("docs/crlf.txt"), "line one\r\nline two\r\n").unwrap();
    fs::write(root.join("docs/notes.md"), "# heading\nbody\n").unwrap();
    fs::write(root.join("docs/sub/table.csv"), "a,b\n1,2\n").unwrap();
    fs::write(root.join("dup-a.txt"), "duplicate payload\n").unwrap();
    fs::write(root.join("docs/dup-b.txt"), "duplicate payload\n").unwrap();
    fs::write(root.join("image.png"), PNG_MAGIC).unwrap();
    fs::write(root.join("trick.txt"), PNG_MAGIC).unwrap();
    fs::write(root.join("broken.txt"), b"hello \xff world").unwrap();
}

fn terminal_records(shard: &Path) -> HashMap<String, Record> {
    let mut terminal = HashMap::new();
    for record in manifest::read_shard(shard).unwrap().records {
        terminal.insert(record.source_path.clone(), record);
    }
    terminal
}

#[test]
fn run_converts_skips_and_counts_the_true_denominator() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("source");
    let mirror = dir.path().join("mirror");
    let manifest_dir = dir.path().join("manifest");
    build_tree(&root);

    let rules = Rules::builtin().unwrap();
    let options = RunOptions {
        root: &root,
        mirror_root: &mirror,
        manifest_dir: &manifest_dir,
        division: "alpha",
        walk: WalkOptions::default(),
    };

    // First run converts the text family and records the rest.
    let first = pipeline::run(&rules, &options).unwrap();
    assert_eq!(first.sources, 8);
    assert_eq!(first.counts.converted, 4);
    assert_eq!(first.counts.dedup, 1);
    assert_eq!(first.counts.unsupported, 2);
    assert_eq!(first.counts.failed, 1);
    assert_eq!(first.counts.skipped_unchanged, 0);

    // The mirror parallels the source tree with .txt appended, and
    // conversion normalized CRLF to LF.
    assert_eq!(
        fs::read_to_string(mirror.join("alpha/docs/crlf.txt.txt")).unwrap(),
        "line one\nline two\n"
    );
    assert!(mirror.join("alpha/docs/notes.md.txt").is_file());
    assert!(mirror.join("alpha/docs/sub/table.csv.txt").is_file());
    assert!(mirror.join("alpha/docs/dup-b.txt.txt").is_file());
    assert!(!mirror.join("alpha/image.png.txt").exists());
    assert!(!mirror.join("alpha/broken.txt.txt").exists());

    let shard = manifest_dir.join("alpha.jsonl");
    let after_first = manifest::read_shard(&shard).unwrap().records;
    assert_eq!(after_first.len(), 8);

    let terminal = terminal_records(&shard);
    assert_eq!(terminal.len(), 8);

    // Dedup: sorted traversal makes docs/dup-b.txt canonical.
    let duplicate = &terminal["dup-a.txt"];
    assert_eq!(duplicate.status, Status::Dedup);
    assert_eq!(duplicate.dedup_of.as_deref(), Some("docs/dup-b.txt"));
    assert_eq!(
        fs::read_to_string(mirror.join("alpha/dup-a.txt.txt")).unwrap(),
        "duplicate payload\n"
    );

    // A mislabeled binary is detected by magic bytes and flagged.
    let trick = &terminal["trick.txt"];
    assert_eq!(trick.status, Status::Unsupported);
    assert_eq!(trick.detected_format, "png");
    assert!(trick.format_mismatch);

    // A converter failure carries a machine-readable reason.
    let broken = &terminal["broken.txt"];
    assert_eq!(broken.status, Status::Failed);
    assert!(broken.error.as_deref().unwrap().starts_with("invalid_utf8"));
    assert!(broken.text_path.is_none());

    // Second run: the manifest is the checkpoint. Nothing converts
    // again. Unsupported and failed sources are re-evaluated.
    let second = pipeline::run(&rules, &options).unwrap();
    assert_eq!(second.counts.converted, 0);
    assert_eq!(second.counts.dedup, 0);
    assert_eq!(second.counts.skipped_unchanged, 5);
    assert_eq!(second.counts.unsupported, 2);
    assert_eq!(second.counts.failed, 1);

    // The shard is append-only and the true denominator holds: every
    // walked source has exactly one terminal record.
    let after_second = manifest::read_shard(&shard).unwrap().records;
    assert_eq!(after_second.len(), 16);
    let terminal = terminal_records(&shard);
    assert_eq!(terminal.len(), 8);
    let walked = text_mirror::walk::walk_division(&root, &WalkOptions::default()).unwrap();
    assert_eq!(walked.len(), terminal.len());
    for entry in &walked {
        assert!(terminal.contains_key(&entry.path.to_string_lossy().into_owned()));
    }

    // Coverage over terminal records.
    let status = pipeline::status(&manifest_dir).unwrap();
    assert_eq!(status.divisions.len(), 1);
    let division = &status.divisions[0];
    assert_eq!(division.division, "alpha");
    assert_eq!(division.sources, 8);
    assert_eq!(division.with_text, 5);
    assert_eq!(division.counts.skipped_unchanged, 5);
    assert_eq!(division.counts.unsupported, 2);
    assert_eq!(division.counts.failed, 1);

    // Explain returns the full append history for one source.
    let history = pipeline::explain(&manifest_dir, "docs/crlf.txt").unwrap();
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].record.status, Status::Converted);
    assert_eq!(history[1].record.status, Status::SkippedUnchanged);

    // A changed source converts again on the next run.
    fs::write(root.join("docs/crlf.txt"), "revised\r\n").unwrap();
    let third = pipeline::run(&rules, &options).unwrap();
    assert_eq!(third.counts.converted, 1);
    assert_eq!(third.counts.skipped_unchanged, 4);
    assert_eq!(
        fs::read_to_string(mirror.join("alpha/docs/crlf.txt.txt")).unwrap(),
        "revised\n"
    );
}
