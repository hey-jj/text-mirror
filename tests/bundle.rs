//! Bundle, verify, and merge behavior over real conversion output.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use text_mirror::bundle::{self, BundleOptions};
use text_mirror::hash;
use text_mirror::manifest;
use text_mirror::pipeline::{self, Rules, RunOptions};
use text_mirror::walk::WalkOptions;

struct Setup {
    _dir: tempfile::TempDir,
    base: PathBuf,
    mirror: PathBuf,
    manifest_dir: PathBuf,
}

fn setup() -> Setup {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().to_path_buf();
    Setup {
        _dir: dir,
        mirror: base.join("mirror"),
        manifest_dir: base.join("manifest"),
        base,
    }
}

fn run_division(setup: &Setup, division: &str, files: &[(&str, &str)]) {
    let root = setup.base.join(format!("src-{division}"));
    for (path, content) in files {
        let absolute = root.join(path);
        fs::create_dir_all(absolute.parent().unwrap()).unwrap();
        fs::write(&absolute, content).unwrap();
    }
    let rules = Rules::builtin().unwrap();
    pipeline::run(
        &rules,
        &RunOptions {
            root: &root,
            mirror_root: &setup.mirror,
            manifest_dir: &setup.manifest_dir,
            division,
            walk: WalkOptions::default(),
        },
    )
    .unwrap();
}

fn bundle_division(setup: &Setup, division: &str, name: &str) -> PathBuf {
    let output = setup.base.join(name);
    bundle::bundle(&BundleOptions {
        mirror_root: &setup.mirror,
        manifest_dir: &setup.manifest_dir,
        division,
        output: &output,
    })
    .unwrap();
    output
}

fn tree_digest(root: &Path) -> BTreeMap<String, String> {
    fn visit(dir: &Path, base: &Path, out: &mut BTreeMap<String, String>) {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                visit(&path, base, out);
            } else {
                let relative = path
                    .strip_prefix(base)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned();
                out.insert(relative, hash::hash_file(&path).unwrap());
            }
        }
    }
    let mut out = BTreeMap::new();
    visit(root, root, &mut out);
    out
}

/// Rebuilds checksums.b3 and the descriptor's checksums_hash after a
/// test deliberately edits bundle contents, so a later refusal comes
/// from the edited content and not from a stale checksum.
fn refresh_checksums(root: &Path) {
    let digests = tree_digest(root);
    let mut lines = String::new();
    for (relative, digest) in &digests {
        if relative == bundle::DESCRIPTOR_NAME || relative == bundle::CHECKSUMS_NAME {
            continue;
        }
        lines.push_str(&format!("{digest}  {relative}\n"));
    }
    fs::write(root.join(bundle::CHECKSUMS_NAME), &lines).unwrap();
    patch_descriptor(root, |value| {
        value["checksums_hash"] = serde_json::Value::String(hash::hash_bytes(lines.as_bytes()));
    });
}

fn patch_descriptor(root: &Path, edit: impl FnOnce(&mut serde_json::Value)) {
    let path = root.join(bundle::DESCRIPTOR_NAME);
    let mut value: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    edit(&mut value);
    let mut json = serde_json::to_string_pretty(&value).unwrap();
    json.push('\n');
    fs::write(&path, json).unwrap();
}

fn refusal_of(result: text_mirror::Result<bundle::VerifyReport>) -> Vec<String> {
    match result.unwrap_err() {
        text_mirror::Error::Refused { problems, .. } => problems,
        other => panic!("expected a refusal, got {other}"),
    }
}

#[test]
fn round_trip_run_bundle_verify() {
    let setup = setup();
    run_division(
        &setup,
        "emea",
        &[
            ("reports/q3.txt", "quarterly numbers\n"),
            ("note.md", "# note\nbody\n"),
        ],
    );
    let out = bundle_division(&setup, "emea", "bundle-emea");

    // The bundle layout is division-namespaced and self-contained.
    assert!(out.join("mirror/emea/reports/q3.txt.txt").is_file());
    assert!(
        out.join("mirror/emea/reports/q3.txt.segments.jsonl")
            .is_file()
    );
    assert!(out.join("manifest/emea.jsonl").is_file());
    assert!(out.join("rules/formats.toml").is_file());
    assert!(out.join("rules/converters.toml").is_file());
    assert!(out.join("checksums.b3").is_file());
    assert!(out.join("BUNDLE.json").is_file());

    // Records carry mirror-root-relative division-qualified paths.
    let records = manifest::read_shard_strict(&out.join("manifest/emea.jsonl")).unwrap();
    let q3 = records
        .iter()
        .find(|r| r.source_path == "reports/q3.txt")
        .unwrap();
    assert_eq!(q3.text_path.as_deref(), Some("emea/reports/q3.txt.txt"));

    let report = bundle::verify(&out).unwrap();
    assert_eq!(report.divisions, vec!["emea".to_string()]);
    assert_eq!(report.coverage["emea"].covered, 2);
    assert_eq!(report.coverage["emea"].total, 2);
}

#[test]
fn bundle_rerun_is_byte_identical() {
    let setup = setup();
    run_division(&setup, "emea", &[("a.txt", "stable content\n")]);
    let first = bundle_division(&setup, "emea", "out-one");
    let second = bundle_division(&setup, "emea", "out-two");
    assert_eq!(tree_digest(&first), tree_digest(&second));
}

#[test]
fn verify_refuses_each_failure_class() {
    let setup = setup();
    run_division(
        &setup,
        "emea",
        &[("a.txt", "alpha content\n"), ("b.txt", "beta content\n")],
    );

    // Unrecognized schema.
    let out = bundle_division(&setup, "emea", "case-schema");
    patch_descriptor(&out, |v| {
        v["schema"] = serde_json::Value::String("text-mirror/bundle@2".to_string());
    });
    let problems = refusal_of(bundle::verify(&out));
    assert!(problems[0].contains("unrecognized schema"), "{problems:?}");

    // checksums_hash mismatch.
    let out = bundle_division(&setup, "emea", "case-hash");
    patch_descriptor(&out, |v| {
        v["checksums_hash"] = serde_json::Value::String("00".repeat(32));
    });
    let problems = refusal_of(bundle::verify(&out));
    assert!(
        problems[0].contains("checksums.b3 hashes to"),
        "{problems:?}"
    );

    // A tampered artifact.
    let out = bundle_division(&setup, "emea", "case-tamper");
    fs::write(out.join("mirror/emea/a.txt.txt"), "tampered\n").unwrap();
    let problems = refusal_of(bundle::verify(&out));
    assert!(
        problems
            .iter()
            .any(|p| p.contains("checksum mismatch: mirror/emea/a.txt.txt")),
        "{problems:?}"
    );

    // A smuggled unlisted file.
    let out = bundle_division(&setup, "emea", "case-smuggle");
    fs::write(out.join("mirror/emea/extra.bin"), b"stowaway").unwrap();
    let problems = refusal_of(bundle::verify(&out));
    assert!(
        problems
            .iter()
            .any(|p| p.contains("unlisted file: mirror/emea/extra.bin")),
        "{problems:?}"
    );

    // A torn final shard line, which also leaves the shard without
    // its terminating newline.
    let out = bundle_division(&setup, "emea", "case-torn");
    let shard = out.join("manifest/emea.jsonl");
    let mut file = fs::OpenOptions::new().append(true).open(&shard).unwrap();
    file.write_all(br#"{"schema":"text-mirror/manifest@1","source_"#)
        .unwrap();
    drop(file);
    refresh_checksums(&out);
    let problems = refusal_of(bundle::verify(&out));
    assert!(
        problems
            .iter()
            .any(|p| p.contains("does not end with a newline")),
        "{problems:?}"
    );

    // A complete final record whose terminating newline is missing.
    let out = bundle_division(&setup, "emea", "case-unterminated");
    let shard = out.join("manifest/emea.jsonl");
    let mut bytes = fs::read(&shard).unwrap();
    assert_eq!(bytes.pop(), Some(b'\n'));
    fs::write(&shard, &bytes).unwrap();
    refresh_checksums(&out);
    let problems = refusal_of(bundle::verify(&out));
    assert!(
        problems
            .iter()
            .any(|p| p.contains("does not end with a newline")),
        "{problems:?}"
    );

    // A malformed line anywhere in a shard, mid-file included.
    let out = bundle_division(&setup, "emea", "case-midline");
    let shard = out.join("manifest/emea.jsonl");
    let mut content = fs::read(&shard).unwrap();
    content.extend_from_slice(b"not a record\n");
    fs::write(&shard, &content).unwrap();
    refresh_checksums(&out);
    let problems = refusal_of(bundle::verify(&out));
    assert!(
        problems.iter().any(|p| p.contains("manifest")),
        "{problems:?}"
    );

    // A missing text artifact for an effective record.
    let out = bundle_division(&setup, "emea", "case-missing");
    fs::remove_file(out.join("mirror/emea/b.txt.txt")).unwrap();
    refresh_checksums(&out);
    let problems = refusal_of(bundle::verify(&out));
    assert!(
        problems
            .iter()
            .any(|p| p.contains("artifact emea/b.txt.txt is missing")),
        "{problems:?}"
    );

    // A count mismatch against the shards.
    let out = bundle_division(&setup, "emea", "case-counts");
    patch_descriptor(&out, |v| {
        v["counts"]["emea"]["converted"] = serde_json::Value::from(99);
    });
    let problems = refusal_of(bundle::verify(&out));
    assert!(
        problems
            .iter()
            .any(|p| p.contains("counts.converted for emea: descriptor 99, shards 2")),
        "{problems:?}"
    );

    // A coverage mismatch against the shards.
    let out = bundle_division(&setup, "emea", "case-coverage");
    patch_descriptor(&out, |v| {
        v["coverage"]["emea"]["covered"] = serde_json::Value::from(0);
    });
    let problems = refusal_of(bundle::verify(&out));
    assert!(
        problems
            .iter()
            .any(|p| p.contains("coverage.covered for emea: descriptor 0, shards 2")),
        "{problems:?}"
    );
}

// A forged record binding real artifact bytes to a false source
// identity is refused by the pure-mapping check. This exact forgery
// passed verify before the fix.
#[test]
fn forged_source_identity_is_refused_by_the_pure_mapping() {
    let setup = setup();
    run_division(&setup, "emea", &[("a.txt", "content\n")]);
    let out = bundle_division(&setup, "emea", "case-collision");
    let shard = out.join("manifest/emea.jsonl");
    let line = fs::read_to_string(&shard).unwrap();
    let mut forged: serde_json::Value = serde_json::from_str(line.trim_end()).unwrap();
    forged["source_path"] = serde_json::Value::String("b.txt".to_string());
    let mut content = line;
    content.push_str(&serde_json::to_string(&forged).unwrap());
    content.push('\n');
    fs::write(&shard, &content).unwrap();
    refresh_checksums(&out);
    patch_descriptor(&out, |v| {
        v["counts"]["emea"]["converted"] = serde_json::Value::from(2);
        v["counts"]["emea"]["total"] = serde_json::Value::from(2);
        v["coverage"]["emea"]["covered"] = serde_json::Value::from(2);
        v["coverage"]["emea"]["total"] = serde_json::Value::from(2);
    });
    let problems = refusal_of(bundle::verify(&out));
    assert!(
        problems
            .iter()
            .any(|p| p.contains("text_path emea/a.txt.txt is not the pure mapping emea/b.txt.txt")),
        "{problems:?}"
    );
}

#[test]
fn bundle_refuses_a_torn_tailed_shard() {
    let setup = setup();
    run_division(&setup, "emea", &[("a.txt", "content\n")]);
    let shard = setup.manifest_dir.join("emea.jsonl");
    let mut file = fs::OpenOptions::new().append(true).open(&shard).unwrap();
    file.write_all(br#"{"schema":"text-mirror/manifest@1","source_"#)
        .unwrap();
    drop(file);

    let result = bundle::bundle(&BundleOptions {
        mirror_root: &setup.mirror,
        manifest_dir: &setup.manifest_dir,
        division: "emea",
        output: &setup.base.join("refused"),
    });
    match result.unwrap_err() {
        text_mirror::Error::Refused { verb, problems } => {
            assert_eq!(verb, "bundle");
            assert!(problems[0].contains("resume the run"), "{problems:?}");
        }
        other => panic!("expected a refusal, got {other}"),
    }
}

#[test]
fn merge_joins_divisions_that_share_a_source_path() {
    // The exact downstream collision case: both divisions hold
    // reports/q3.txt, and the division namespace keeps them apart.
    let setup = setup();
    run_division(&setup, "emea", &[("reports/q3.txt", "emea numbers\n")]);
    run_division(&setup, "apac", &[("reports/q3.txt", "apac numbers\n")]);
    let emea = bundle_division(&setup, "emea", "bundle-emea");
    let apac = bundle_division(&setup, "apac", "bundle-apac");

    let merged = setup.base.join("merged");
    let report = bundle::merge(&[emea, apac], &merged).unwrap();
    assert_eq!(
        report.divisions,
        vec!["apac".to_string(), "emea".to_string()]
    );

    bundle::verify(&merged).unwrap();
    assert_eq!(
        fs::read_to_string(merged.join("mirror/emea/reports/q3.txt.txt")).unwrap(),
        "emea numbers\n"
    );
    assert_eq!(
        fs::read_to_string(merged.join("mirror/apac/reports/q3.txt.txt")).unwrap(),
        "apac numbers\n"
    );
}

#[test]
fn merge_rerun_is_byte_identical() {
    let setup = setup();
    run_division(&setup, "emea", &[("a.txt", "one\n")]);
    run_division(&setup, "apac", &[("b.txt", "two\n")]);
    let emea = bundle_division(&setup, "emea", "bundle-emea");
    let apac = bundle_division(&setup, "apac", "bundle-apac");

    let first = setup.base.join("merged-one");
    let second = setup.base.join("merged-two");
    bundle::merge(&[emea.clone(), apac.clone()], &first).unwrap();
    bundle::merge(&[emea, apac], &second).unwrap();
    assert_eq!(tree_digest(&first), tree_digest(&second));
}

#[test]
fn merge_refusals() {
    let setup = setup();
    run_division(&setup, "emea", &[("a.txt", "one\n")]);
    run_division(&setup, "apac", &[("c.txt", "three\n")]);
    let emea = bundle_division(&setup, "emea", "bundle-emea");
    let apac = bundle_division(&setup, "apac", "bundle-apac");

    // The case-variant division gets its own roots. Sharing a mirror
    // root across case-variant divisions is exactly the collision the
    // configuration uniqueness rule exists to refuse on a
    // case-insensitive filesystem.
    let upper_setup = self::setup();
    run_division(&upper_setup, "EMEA", &[("b.txt", "two\n")]);
    let emea_upper = bundle_division(&upper_setup, "EMEA", "bundle-emea-upper");

    // A division name in more than one input, case-insensitively.
    let result = bundle::merge(
        &[emea.clone(), emea_upper.clone()],
        &setup.base.join("m-dup"),
    );
    match result.unwrap_err() {
        text_mirror::Error::Refused { problems, .. } => {
            assert!(
                problems.iter().any(|p| p.contains("more than one input")),
                "{problems:?}"
            );
        }
        other => panic!("expected a refusal, got {other}"),
    }

    // A schema mismatch fails the input's own verification.
    patch_descriptor(&emea_upper, |v| {
        v["schema"] = serde_json::Value::String("text-mirror/bundle@2".to_string());
    });
    let result = bundle::merge(&[emea.clone(), emea_upper], &setup.base.join("m-schema"));
    match result.unwrap_err() {
        text_mirror::Error::Refused { problems, .. } => {
            assert!(
                problems.iter().any(|p| p.contains("unrecognized schema")),
                "{problems:?}"
            );
        }
        other => panic!("expected a refusal, got {other}"),
    }

    // Differing rules snapshots.
    let mut converters = fs::read_to_string(apac.join("rules/converters.toml")).unwrap();
    converters.push_str("\n# drift\n");
    fs::write(apac.join("rules/converters.toml"), &converters).unwrap();
    refresh_checksums(&apac);
    let result = bundle::merge(&[emea, apac], &setup.base.join("m-rules"));
    match result.unwrap_err() {
        text_mirror::Error::Refused { problems, .. } => {
            assert!(
                problems.iter().any(|p| p.contains("rules snapshot")),
                "{problems:?}"
            );
        }
        other => panic!("expected a refusal, got {other}"),
    }
}

// counts is a ledger over every line while coverage is over the
// terminal set, so a superseded record splits the two totals.
#[test]
fn counts_cover_history_and_coverage_covers_the_terminal_set() {
    let setup = setup();
    run_division(&setup, "emea", &[("a.txt", "content\n")]);
    // The second run appends a skipped_unchanged record for the same
    // source, so the shard holds two lines and one effective record.
    run_division(&setup, "emea", &[("a.txt", "content\n")]);
    let out = bundle_division(&setup, "emea", "bundle-history");

    let descriptor: serde_json::Value =
        serde_json::from_slice(&fs::read(out.join("BUNDLE.json")).unwrap()).unwrap();
    assert_eq!(descriptor["counts"]["emea"]["total"], 2);
    assert_eq!(descriptor["counts"]["emea"]["converted"], 1);
    assert_eq!(descriptor["counts"]["emea"]["skipped_unchanged"], 1);
    assert_eq!(descriptor["coverage"]["emea"]["total"], 1);
    assert_eq!(descriptor["coverage"]["emea"]["covered"], 1);
    bundle::verify(&out).unwrap();

    // A shard trimmed of its superseded line fails verification even
    // though the terminal set is intact.
    let shard = out.join("manifest/emea.jsonl");
    let content = fs::read_to_string(&shard).unwrap();
    let last_line = content.lines().last().unwrap();
    fs::write(&shard, format!("{last_line}\n")).unwrap();
    refresh_checksums(&out);
    let problems = refusal_of(bundle::verify(&out));
    assert!(
        problems
            .iter()
            .any(|p| p.contains("counts.total for emea: descriptor 2, shards 1")),
        "{problems:?}"
    );
}

// The normative layout: nothing else may live at the bundle root or
// inside manifest/.
#[test]
fn layout_strays_are_refused() {
    let setup = setup();
    run_division(&setup, "emea", &[("a.txt", "content\n")]);

    let out = bundle_division(&setup, "emea", "case-root-stray");
    fs::write(out.join("NOTES.txt"), "stray\n").unwrap();
    refresh_checksums(&out);
    let problems = refusal_of(bundle::verify(&out));
    assert!(
        problems
            .iter()
            .any(|p| p.contains("unexpected entry: NOTES.txt")),
        "{problems:?}"
    );

    let out = bundle_division(&setup, "emea", "case-manifest-stray");
    fs::write(out.join("manifest/readme.md"), "stray\n").unwrap();
    refresh_checksums(&out);
    let problems = refusal_of(bundle::verify(&out));
    assert!(
        problems
            .iter()
            .any(|p| p.contains("unexpected entry: manifest/readme.md")),
        "{problems:?}"
    );
}

// Run ids reach downstream catalogs verbatim, so anything outside the
// grammar is refused.
#[test]
fn run_id_outside_the_grammar_is_refused() {
    let setup = setup();
    run_division(&setup, "emea", &[("a.txt", "content\n")]);
    let out = bundle_division(&setup, "emea", "case-run-id");
    patch_descriptor(&out, |v| {
        v["run_ids"] = serde_json::json!(["bad id!"]);
    });
    let problems = refusal_of(bundle::verify(&out));
    assert!(
        problems
            .iter()
            .any(|p| p.contains("outside the run id grammar")),
        "{problems:?}"
    );
}

// bundle itself refuses a text-bearing effective record whose
// artifact is gone, before anything is packaged.
#[test]
fn bundle_refuses_a_missing_artifact() {
    let setup = setup();
    run_division(&setup, "emea", &[("a.txt", "content\n")]);
    fs::remove_file(setup.mirror.join("emea/a.txt.txt")).unwrap();

    let result = bundle::bundle(&BundleOptions {
        mirror_root: &setup.mirror,
        manifest_dir: &setup.manifest_dir,
        division: "emea",
        output: &setup.base.join("refused"),
    });
    match result.unwrap_err() {
        text_mirror::Error::Refused { verb, problems } => {
            assert_eq!(verb, "bundle");
            assert!(
                problems[0].contains("artifact emea/a.txt.txt is missing"),
                "{problems:?}"
            );
        }
        other => panic!("expected a refusal, got {other}"),
    }
    assert!(!setup.base.join("refused").exists());
}

// The portable collision check folds ASCII case, because the
// receiving fleet has case-insensitive filesystems. The forgery adds
// a second record in the same shard whose source name differs only in
// case: on a case-insensitive filesystem the two artifact paths alias
// one file, and on a case-sensitive one the second file is written
// with identical bytes, so the test runs everywhere.
#[test]
fn ascii_case_fold_collision_is_refused() {
    let setup = setup();
    run_division(&setup, "emea", &[("a.txt", "content\n")]);
    let out = bundle_division(&setup, "emea", "case-fold");

    let shard = out.join("manifest/emea.jsonl");
    let line = fs::read_to_string(&shard).unwrap();
    let mut forged: serde_json::Value = serde_json::from_str(line.trim_end()).unwrap();
    forged["source_path"] = serde_json::Value::String("A.txt".to_string());
    forged["text_path"] = serde_json::Value::String("emea/A.txt.txt".to_string());
    let mut content = line;
    content.push_str(&serde_json::to_string(&forged).unwrap());
    content.push('\n');
    fs::write(&shard, &content).unwrap();

    let original = fs::read(out.join("mirror/emea/a.txt.txt")).unwrap();
    fs::write(out.join("mirror/emea/A.txt.txt"), &original).unwrap();
    let digest = hash::hash_bytes(&original);
    let shard_bytes = fs::read(&shard).unwrap();
    let shard_digest = hash::hash_bytes(&shard_bytes);

    // Rebuild checksums by hand so both case variants are listed even
    // where the filesystem stores only one of them.
    let mut lines: Vec<String> = fs::read_to_string(out.join("checksums.b3"))
        .unwrap()
        .lines()
        .filter(|l| !l.ends_with("manifest/emea.jsonl") && !l.ends_with("mirror/emea/A.txt.txt"))
        .map(str::to_string)
        .collect();
    lines.push(format!("{digest}  mirror/emea/A.txt.txt"));
    lines.push(format!("{shard_digest}  manifest/emea.jsonl"));
    lines.sort_by_key(|line| line.split_once("  ").map(|(_, p)| p.to_string()));
    let sorted = format!("{}\n", lines.join("\n"));
    fs::write(out.join("checksums.b3"), &sorted).unwrap();
    patch_descriptor(&out, |v| {
        v["counts"]["emea"]["converted"] = serde_json::Value::from(2);
        v["counts"]["emea"]["total"] = serde_json::Value::from(2);
        v["coverage"]["emea"]["covered"] = serde_json::Value::from(2);
        v["coverage"]["emea"]["total"] = serde_json::Value::from(2);
        v["checksums_hash"] = serde_json::Value::String(hash::hash_bytes(sorted.as_bytes()));
    });

    let problems = refusal_of(bundle::verify(&out));
    // On a case-sensitive filesystem both files exist and the fold
    // check refuses the collision. On a case-insensitive filesystem
    // the bundle cannot physically hold both names, so the listed set
    // no longer matches the tree and the set-equality check refuses
    // first. Either way the case-fold pair cannot verify.
    assert!(
        problems
            .iter()
            .any(|p| p.contains("text_path collision on emea/a.txt.txt")
                || p.contains("listed file missing: mirror/emea/A.txt.txt")),
        "{problems:?}"
    );
}

// Descriptor arrays are untrusted. The EMEA and emea pair passed
// verify before the fix and would alias on the receiving fleet.
#[test]
fn descriptor_division_and_run_id_arrays_are_validated() {
    let setup = setup();
    run_division(&setup, "emea", &[("a.txt", "content\n")]);

    let out = bundle_division(&setup, "emea", "case-divisions-fold");
    patch_descriptor(&out, |v| {
        v["divisions"] = serde_json::json!(["EMEA", "emea"]);
    });
    let problems = refusal_of(bundle::verify(&out));
    assert!(
        problems
            .iter()
            .any(|p| p.contains("collides with another under ASCII case folding")),
        "{problems:?}"
    );

    let out = bundle_division(&setup, "emea", "case-divisions-order");
    patch_descriptor(&out, |v| {
        v["divisions"] = serde_json::json!(["emea", "apac"]);
    });
    let problems = refusal_of(bundle::verify(&out));
    assert!(
        problems
            .iter()
            .any(|p| p.contains("duplicated or not in bytewise order")),
        "{problems:?}"
    );

    let out = bundle_division(&setup, "emea", "case-divisions-grammar");
    patch_descriptor(&out, |v| {
        v["divisions"] = serde_json::json!(["emea/../evil"]);
    });
    let problems = refusal_of(bundle::verify(&out));
    assert!(
        problems.iter().any(|p| p.contains("outside the grammar")),
        "{problems:?}"
    );

    let out = bundle_division(&setup, "emea", "case-runids-order");
    patch_descriptor(&out, |v| {
        v["run_ids"] = serde_json::json!(["bbb", "aaa"]);
    });
    let problems = refusal_of(bundle::verify(&out));
    assert!(
        problems.iter().any(|p| p.contains("not in bytewise order")),
        "{problems:?}"
    );

    let out = bundle_division(&setup, "emea", "case-runids-dup");
    patch_descriptor(&out, |v| {
        v["run_ids"] = serde_json::json!(["aaa", "aaa"]);
    });
    let problems = refusal_of(bundle::verify(&out));
    assert!(
        problems.iter().any(|p| p.contains("duplicate run id")),
        "{problems:?}"
    );
}

// The layout holds at every depth. All three shapes passed verify
// before the fix.
#[test]
fn deep_layout_strays_are_refused() {
    let setup = setup();
    run_division(&setup, "emea", &[("a.txt", "content\n")]);

    // An empty directory below mirror/<division>/.
    let out = bundle_division(&setup, "emea", "case-empty-mirror-dir");
    fs::create_dir_all(out.join("mirror/emea/stowaway")).unwrap();
    let problems = refusal_of(bundle::verify(&out));
    assert!(
        problems
            .iter()
            .any(|p| p.contains("empty directory: mirror/emea/stowaway")),
        "{problems:?}"
    );

    // A checksummed stray file under rules/.
    let out = bundle_division(&setup, "emea", "case-rules-stray");
    fs::write(out.join("rules/extra.toml"), "stray\n").unwrap();
    refresh_checksums(&out);
    let problems = refusal_of(bundle::verify(&out));
    assert!(
        problems
            .iter()
            .any(|p| p.contains("unexpected entry: rules/extra.toml")),
        "{problems:?}"
    );

    // An empty directory under rules/.
    let out = bundle_division(&setup, "emea", "case-rules-dir");
    fs::create_dir_all(out.join("rules/sub")).unwrap();
    let problems = refusal_of(bundle::verify(&out));
    assert!(
        problems
            .iter()
            .any(|p| p.contains("empty directory: rules/sub")),
        "{problems:?}"
    );

    // A non-division stray inside mirror/.
    let out = bundle_division(&setup, "emea", "case-mirror-stray");
    fs::create_dir_all(out.join("mirror/notadivision")).unwrap();
    let problems = refusal_of(bundle::verify(&out));
    assert!(
        problems.iter().any(|p| p.contains("mirror/notadivision")),
        "{problems:?}"
    );
}

// Checksums.b3 framing is enforced like shard framing. Both
// shapes passed verify before the fix with the chain rebuilt.
#[test]
fn checksums_framing_is_enforced() {
    let setup = setup();
    run_division(&setup, "emea", &[("a.txt", "content\n")]);

    let out = bundle_division(&setup, "emea", "case-checksums-newline");
    let mut bytes = fs::read(out.join("checksums.b3")).unwrap();
    assert_eq!(bytes.pop(), Some(b'\n'));
    fs::write(out.join("checksums.b3"), &bytes).unwrap();
    patch_descriptor(&out, |v| {
        v["checksums_hash"] = serde_json::Value::String(hash::hash_bytes(&bytes));
    });
    let problems = refusal_of(bundle::verify(&out));
    assert!(
        problems
            .iter()
            .any(|p| p.contains("does not end with a newline")),
        "{problems:?}"
    );

    let out = bundle_division(&setup, "emea", "case-checksums-crlf");
    let text = fs::read_to_string(out.join("checksums.b3")).unwrap();
    let crlf = text.replace('\n', "\r\n");
    fs::write(out.join("checksums.b3"), &crlf).unwrap();
    patch_descriptor(&out, |v| {
        v["checksums_hash"] = serde_json::Value::String(hash::hash_bytes(crlf.as_bytes()));
    });
    let problems = refusal_of(bundle::verify(&out));
    assert!(
        problems.iter().any(|p| p.contains("carriage return")),
        "{problems:?}"
    );
}

// The rules snapshot binds to the effective records. A record
// claiming another rules generation verified before the fix.
#[test]
fn rules_snapshot_binds_to_the_records() {
    let setup = setup();
    run_division(&setup, "emea", &[("a.txt", "content\n")]);

    // Receiving side: a forged effective record from rules 9.
    let out = bundle_division(&setup, "emea", "case-rules-version");
    let shard = out.join("manifest/emea.jsonl");
    let line = fs::read_to_string(&shard).unwrap();
    let forged = line.replace("\"rules_version\":\"3\"", "\"rules_version\":\"9\"");
    assert_ne!(line, forged);
    fs::write(&shard, &forged).unwrap();
    refresh_checksums(&out);
    let problems = refusal_of(bundle::verify(&out));
    assert!(
        problems
            .iter()
            .any(|p| p.contains("does not match the snapshot rules version \"3\"")),
        "{problems:?}"
    );

    // Receiving side: the two snapshot files disagree.
    let out = bundle_division(&setup, "emea", "case-rules-disagree");
    let formats = fs::read_to_string(out.join("rules/formats.toml")).unwrap();
    let bumped = formats.replace("version = \"3\"", "version = \"4\"");
    assert_ne!(formats, bumped);
    fs::write(out.join("rules/formats.toml"), &bumped).unwrap();
    refresh_checksums(&out);
    let problems = refusal_of(bundle::verify(&out));
    assert!(
        problems
            .iter()
            .any(|p| p.contains("rules snapshot files disagree")),
        "{problems:?}"
    );

    // Packaging side: bundle refuses the same mismatch and directs
    // the operator to re-run.
    let prep_shard = setup.manifest_dir.join("emea.jsonl");
    let line = fs::read_to_string(&prep_shard).unwrap();
    let forged = line.replace("\"rules_version\":\"3\"", "\"rules_version\":\"9\"");
    fs::write(&prep_shard, &forged).unwrap();
    let result = bundle::bundle(&BundleOptions {
        mirror_root: &setup.mirror,
        manifest_dir: &setup.manifest_dir,
        division: "emea",
        output: &setup.base.join("refused-rules"),
    });
    match result.unwrap_err() {
        text_mirror::Error::Refused { verb, problems } => {
            assert_eq!(verb, "bundle");
            assert!(
                problems[0].contains("re-run the division under the current rules"),
                "{problems:?}"
            );
        }
        other => panic!("expected a refusal, got {other}"),
    }
}

// Defense in depth: separator bytes that mean something on other
// hosts are refused in checksum paths outright.
#[test]
fn foreign_separator_bytes_in_checksum_paths_are_refused() {
    let setup = setup();
    run_division(&setup, "emea", &[("a.txt", "content\n")]);
    let out = bundle_division(&setup, "emea", "case-separators");

    let mut lines: Vec<String> = fs::read_to_string(out.join("checksums.b3"))
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect();
    lines.insert(0, format!("{}  ..\\outside.txt", "0".repeat(64)));
    let content = format!("{}\n", lines.join("\n"));
    fs::write(out.join("checksums.b3"), &content).unwrap();
    patch_descriptor(&out, |v| {
        v["checksums_hash"] = serde_json::Value::String(hash::hash_bytes(content.as_bytes()));
    });
    let problems = refusal_of(bundle::verify(&out));
    assert!(
        problems.iter().any(|p| p.contains("malformed entry")),
        "{problems:?}"
    );
}

// Refusal branches that were correct by inspection but undriven.
#[test]
fn undriven_refusal_branches_are_locked() {
    let setup = setup();
    run_division(&setup, "emea", &[("a.txt", "content\n")]);

    // A checksummed mirror file no effective record references.
    let out = bundle_division(&setup, "emea", "case-unreferenced");
    fs::write(out.join("mirror/emea/orphan.txt.txt"), "orphan\n").unwrap();
    refresh_checksums(&out);
    let problems = refusal_of(bundle::verify(&out));
    assert!(
        problems
            .iter()
            .any(|p| p.contains("unreferenced mirror file: mirror/emea/orphan.txt.txt")),
        "{problems:?}"
    );

    // An unknown manifest_schema through verify itself.
    let out = bundle_division(&setup, "emea", "case-manifest-schema");
    patch_descriptor(&out, |v| {
        v["manifest_schema"] = serde_json::Value::String("text-mirror/manifest@2".to_string());
    });
    let problems = refusal_of(bundle::verify(&out));
    assert!(problems[0].contains("unrecognized schema"), "{problems:?}");

    // An unknown record schema through verify itself.
    let out = bundle_division(&setup, "emea", "case-record-schema");
    let shard = out.join("manifest/emea.jsonl");
    let line = fs::read_to_string(&shard).unwrap();
    let forged = line.replace("text-mirror/manifest@1", "text-mirror/manifest@2");
    fs::write(&shard, &forged).unwrap();
    refresh_checksums(&out);
    let problems = refusal_of(bundle::verify(&out));
    assert!(
        problems.iter().any(|p| p.contains("unrecognized schema")),
        "{problems:?}"
    );
}
