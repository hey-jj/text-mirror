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
    // image.png and trick.txt both carry png bytes. png is a claimed
    // converter now (image-pixel-ocr), so their truncated bytes fail
    // closed in the jailed decoder rather than recording unsupported.
    // Each also gets an auxiliary metadata derived child that fails
    // closed on the same malformed carrier, so the two malformed pngs
    // touch four failed records, plus broken.txt for five.
    assert_eq!(first.counts.unsupported, 0);
    assert_eq!(first.counts.failed, 5);
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
    // Eight walked sources plus the two malformed-png metadata children.
    assert_eq!(after_first.len(), 10);

    let terminal = terminal_records(&shard);
    assert_eq!(terminal.len(), 10);

    // Dedup: sorted traversal makes docs/dup-b.txt canonical.
    let duplicate = &terminal["dup-a.txt"];
    assert_eq!(duplicate.status, Status::Dedup);
    assert_eq!(duplicate.dedup_of.as_deref(), Some("docs/dup-b.txt"));
    assert_eq!(
        fs::read_to_string(mirror.join("alpha/dup-a.txt.txt")).unwrap(),
        "duplicate payload\n"
    );

    // A mislabeled binary is detected by magic bytes and flagged. Its
    // png bytes are truncated, so the image converter fails closed.
    let trick = &terminal["trick.txt"];
    assert_eq!(trick.status, Status::Failed);
    assert_eq!(trick.detected_format, "png");
    assert!(trick.format_mismatch);
    assert!(
        trick
            .error
            .as_deref()
            .is_some_and(|e| e.starts_with("image-ocr-decode-failed")),
        "{:?}",
        trick.error
    );

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
    assert_eq!(second.counts.unsupported, 0);
    // The three failed sources re-evaluate, and the two malformed-png
    // metadata legs re-run and fail closed again.
    assert_eq!(second.counts.failed, 5);

    // The shard is append-only. Every walked source has exactly one
    // terminal record, and each malformed png adds one metadata child,
    // so the terminal set is the walked set plus the two children.
    let after_second = manifest::read_shard(&shard).unwrap().records;
    assert_eq!(after_second.len(), 20);
    let terminal = terminal_records(&shard);
    assert_eq!(terminal.len(), 10);
    let walked = text_mirror::walk::walk_division(&root, &WalkOptions::default()).unwrap();
    assert_eq!(walked.len(), 8);
    for entry in &walked {
        assert!(terminal.contains_key(&entry.path.to_string_lossy().into_owned()));
    }
    // The extra terminal records are the two metadata children.
    assert!(terminal.contains_key("image.png.d/#image-metadata"));
    assert!(terminal.contains_key("trick.txt.d/#image-metadata"));

    // Coverage over terminal records.
    let status = pipeline::status(&manifest_dir).unwrap();
    assert_eq!(status.divisions.len(), 1);
    let division = &status.divisions[0];
    assert_eq!(division.division, "alpha");
    // Status counts every terminal record: the eight walked sources plus
    // the two metadata children.
    assert_eq!(division.sources, 10);
    assert_eq!(division.with_text, 5);
    assert_eq!(division.counts.skipped_unchanged, 5);
    assert_eq!(division.counts.unsupported, 0);
    assert_eq!(division.counts.failed, 5);

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
