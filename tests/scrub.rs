//! Scrub battery: the public crate must carry generic role labels only
//! and no process or review vocabulary, so an internal identity cannot
//! leak into a published artifact.
//!
//! The gate walks the packaged crate surface (the source, the tests, the
//! rules, the manifest, and the changelog) and asserts that no forbidden
//! token appears anywhere in it. This battery scans every in-scope file,
//! itself included: the tokens it forbids are assembled at run time from
//! separate fragments, so this file names none of them as a literal and
//! is clean under its own scan. When a forbidden token would collide with
//! legitimate English in a comment, the remedy is to reword the comment,
//! never to weaken this battery.

use std::fs;
use std::path::{Path, PathBuf};

/// The tokens that must never appear in the crate, matched
/// case-insensitively. Each spelling is stored reversed and rebuilt at run
/// time, so the forbidden byte sequence appears nowhere as a literal —
/// neither in this source nor in the compiled test binary's read-only data
/// (a forward-fragment concat would leave the short fragments in rodata for
/// the linker to pack back into the token). The set is: the internal engine
/// codename in every form (including any role label built from it); and the
/// two pieces of process and review vocabulary that must not ship.
fn forbidden() -> [String; 3] {
    [
        "e3m".chars().rev().collect(),
        "laudiser".chars().rev().collect(),
        "tnemdnema".chars().rev().collect(),
    ]
}

/// Directory names skipped: build output and VCS metadata. Every other
/// file is in scope, including this battery itself.
fn is_skipped(path: &Path) -> bool {
    matches!(
        path.file_name().and_then(|n| n.to_str()),
        Some("target") | Some(".git")
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

/// Scan one body of text, appending a violation line for each forbidden
/// token it contains. Shared by the crate sweep and the negative control.
fn scan_text(label: &str, text: &str, violations: &mut Vec<String>) {
    let lowered = text.to_ascii_lowercase();
    for token in forbidden() {
        if lowered.contains(token.as_str()) {
            violations.push(format!("{label} contains {token:?}"));
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
        scan_text(&file.display().to_string(), &text, &mut violations);
    }
    assert!(
        violations.is_empty(),
        "forbidden tokens found:\n{}",
        violations.join("\n")
    );
}

/// Negative control: a body that names all three forbidden tokens must
/// trip the gate. The probe is assembled from the same run-time fragments,
/// so this file still holds no literal token. The inner assertion is the
/// exact one the crate sweep uses, so a body carrying the tokens makes it
/// fire (panic / exit 101) — proving the gate catches every token rather
/// than silently passing.
#[test]
#[should_panic(expected = "forbidden tokens found")]
fn negative_control_gate_fires_on_all_forbidden_tokens() {
    let probe = forbidden().join(" and ");
    let mut violations = Vec::new();
    scan_text("planted-probe", &probe, &mut violations);
    assert_eq!(
        violations.len(),
        forbidden().len(),
        "the gate must catch every planted token, found: {violations:?}"
    );
    assert!(
        violations.is_empty(),
        "forbidden tokens found:\n{}",
        violations.join("\n")
    );
}
