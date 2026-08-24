//! Scrub battery: the public crate must carry generic role labels only
//! and no process or review vocabulary, so an internal identity cannot
//! leak into a published artifact.
//!
//! The gate walks the packaged crate surface (the source, the tests, the
//! rules, the manifest, and the changelog) and asserts that no forbidden
//! token appears anywhere in it. The forbidden set is fixed here, not
//! sourced from any design note: it fails closed on the internal engine
//! codename and on the review vocabulary that must never ship. When a
//! forbidden token would collide with legitimate English in a comment,
//! the remedy is to reword the comment, never to weaken this battery.

use std::fs;
use std::path::{Path, PathBuf};

/// The tokens that must never appear in the crate, matched
/// case-insensitively. `m3e` is the internal engine codename in every
/// form (including any role label built from it); `residual` and
/// `amendment` are the process and review vocabulary that must not ship.
const FORBIDDEN: &[&str] = &["m3e", "residual", "amendment"];

/// Directory and file names skipped: build output, VCS metadata, and
/// this battery itself, which necessarily names the forbidden tokens.
fn is_skipped(path: &Path) -> bool {
    matches!(
        path.file_name().and_then(|n| n.to_str()),
        Some("target") | Some(".git") | Some("scrub.rs")
    )
}

/// Whether a file's bytes are in scope for the scrub: source, tests,
/// rules, and the outbound prose files.
fn in_scope(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|e| e.to_str()),
        Some("rs") | Some("toml") | Some("md")
    )
}

fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if is_skipped(&path) {
            continue;
        }
        if path.is_dir() {
            collect(&path, out);
        } else if in_scope(&path) {
            out.push(path);
        }
    }
}

#[test]
fn no_forbidden_token_appears_in_the_crate() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    for sub in ["src", "tests", "rules"] {
        collect(&root.join(sub), &mut files);
    }
    for top in ["Cargo.toml", "CHANGELOG.md", "README.md"] {
        let path = root.join(top);
        if path.is_file() {
            files.push(path);
        }
    }
    assert!(!files.is_empty(), "the scrub found no files to scan");

    let mut violations = Vec::new();
    for file in &files {
        let Ok(text) = fs::read_to_string(file) else {
            continue;
        };
        let lowered = text.to_ascii_lowercase();
        for token in FORBIDDEN {
            if lowered.contains(token) {
                violations.push(format!("{} contains {:?}", file.display(), token));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "forbidden tokens found:\n{}",
        violations.join("\n")
    );
}
