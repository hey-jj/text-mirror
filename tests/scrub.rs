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

/// One forbidden token: its spelling, and whether it matches only as a
/// whole word. A whole-word token is one whose spelling is also the
/// start of ordinary words in this crate (an English word that begins
/// with it, or a phrase whose last letter begins another word), so a
/// bare substring match would fire on legitimate prose; every other
/// token matches anywhere.
struct Forbidden {
    token: String,
    whole_word: bool,
}

/// The tokens that must never appear in the crate, matched
/// case-insensitively. Each spelling is stored reversed and rebuilt at run
/// time, so the forbidden byte sequence appears nowhere as a literal —
/// neither in this source nor in the compiled test binary's read-only data
/// (a forward-fragment concat would leave the short fragments in rodata for
/// the linker to pack back into the token). The set is: the internal engine
/// codename in every form (including any role label built from it); the
/// process, review, and decision vocabulary that must not ship; the labels
/// of the review stages and their participants; the internal document
/// series names; and the names of the tools and models that took part.
fn forbidden() -> Vec<Forbidden> {
    let reversed: &[(&str, bool)] = &[
        ("e3m", false),
        ("repsihw", false),
        ("laudiser", false),
        ("tnemdnema", false),
        ("kcehc dliub", false),
        ("nocer", true),
        ("xedoc", false),
        ("elbaf", false),
        ("tartsehcro", false),
        ("ffo-ngis", false),
        ("ffongis", false),
        ("gnilur", false),
        ("fitar", false),
        ("detag-renwo", false),
        ("gel weiver", false),
        ("a gel", true),
        ("b gel", true),
        ("1-egats", false),
        ("2-egats", false),
        ("citehtnys cd", false),
        ("dliub-rorrim-txet", false),
        ("6202-noisiced", false),
    ];
    reversed
        .iter()
        .map(|(spelling, whole_word)| Forbidden {
            token: spelling.chars().rev().collect(),
            whole_word: *whole_word,
        })
        .collect()
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

/// A byte that continues a word, for the whole-word tokens.
fn is_word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// Whether `text` contains `token`, as a substring or, for a whole-word
/// token, only where no word byte touches either end of the match.
fn contains_token(text: &str, forbidden: &Forbidden) -> bool {
    let haystack = text.as_bytes();
    let needle = forbidden.token.as_bytes();
    let mut from = 0;
    while let Some(offset) = text[from..].find(forbidden.token.as_str()) {
        let start = from + offset;
        let end = start + needle.len();
        if !forbidden.whole_word {
            return true;
        }
        let before = start.checked_sub(1).map(|i| haystack[i]);
        let after = haystack.get(end).copied();
        if !before.is_some_and(is_word_byte) && !after.is_some_and(is_word_byte) {
            return true;
        }
        from = start + 1;
    }
    false
}

/// Scan one body of text, appending a violation line for each forbidden
/// token it contains. Shared by the crate sweep and the negative control.
fn scan_text(label: &str, text: &str, violations: &mut Vec<String>) {
    let lowered = text.to_ascii_lowercase();
    for forbidden in forbidden() {
        if contains_token(&lowered, &forbidden) {
            violations.push(format!("{label} contains {:?}", forbidden.token));
        }
    }
}

#[test]
fn no_forbidden_token_appears_in_the_crate() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    for sub in ["src", "tests", "rules", "docs", "skills"] {
        collect(&root.join(sub), &mut files);
    }
    for top in [
        "Cargo.toml",
        "CHANGELOG.md",
        "README.md",
        "THIRD-PARTY-NOTICES.md",
    ] {
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

/// The whole-word tokens match a bare word and not a longer word that
/// merely begins with one, so the sweep cannot fire on ordinary prose.
#[test]
fn whole_word_tokens_do_not_match_inside_longer_words() {
    let bounded: Vec<Forbidden> = forbidden().into_iter().filter(|f| f.whole_word).collect();
    assert!(!bounded.is_empty(), "the set has whole-word tokens");
    for forbidden in &bounded {
        let inside = format!("x{}x", forbidden.token);
        let mut violations = Vec::new();
        scan_text("embedded", &inside, &mut violations);
        assert!(violations.is_empty(), "{violations:?}");
        let bare = format!("({}).", forbidden.token);
        scan_text("bare", &bare, &mut violations);
        assert_eq!(violations.len(), 1, "{violations:?}");
    }
}

/// Negative control: a body that names every forbidden token must trip
/// the gate. The probe is assembled from the same run-time fragments, so
/// this file still holds no literal token. The inner assertion is the
/// exact one the crate sweep uses, so a body carrying the tokens makes it
/// fire (panic / exit 101) — proving the gate catches every token rather
/// than silently passing.
#[test]
#[should_panic(expected = "forbidden tokens found")]
fn negative_control_gate_fires_on_all_forbidden_tokens() {
    let probe = forbidden()
        .iter()
        .map(|f| f.token.clone())
        .collect::<Vec<String>>()
        .join(" and ");
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
