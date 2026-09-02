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
        ("tacidujda", false),
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

/// The product identities that must never appear on an implementation
/// or product surface: the rasterizer, its vendor, the encoder, the
/// platform preview tools, and the automation driver whose calibration
/// the provider tuple came from. Same reversed-spelling construction as
/// the set above, and the same case-insensitive matching.
///
/// These are separate from the set above because of one carveout: a
/// bundled license text may name a vendor, and removing an attribution
/// to satisfy a scrub would be worse than the leak it prevents. The
/// legal-notice file is scanned against the set above and exempt from
/// this one; every other file, source and prose alike, is held to
/// both.
///
/// The generic role labels stay permitted, which is what they exist
/// for: `raster-magick` names a role, not a product, and the full
/// product identity is what is banned here.
fn forbidden_products() -> Vec<Forbidden> {
    let reversed: &[(&str, bool)] = &[
        ("emorhc", false),
        ("muimorhc", false),
        ("elgoog", false),
        ("kcigamegami", false),
        ("eganamlq", false),
        ("koolkciuq", false),
        ("reeteppup", false),
        ("spis", true),
    ];
    reversed
        .iter()
        .map(|(spelling, whole_word)| Forbidden {
            token: spelling.chars().rev().collect(),
            whole_word: *whole_word,
        })
        .collect()
}

/// The one file exempt from the product set: the bundled license text
/// at the crate root legitimately names its copyright holders. The
/// carveout is that exact path, not any file of that name.
const LEGAL_NOTICE: &str = "THIRD-PARTY-NOTICES.md";

/// Every text file the public tree tracks. Tracked files come from
/// version control, so nothing generated or ignored is in scope and
/// nothing tracked is out of it; a file whose head holds a NUL byte is
/// a binary fixture and is skipped by content, never by name. Without
/// version control the walk below stands in, with the same sniff.
fn tracked_text_files(root: &Path) -> Vec<PathBuf> {
    let listed = std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["ls-files", "-z"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| {
            output
                .stdout
                .split(|byte| *byte == 0)
                .filter(|name| !name.is_empty())
                .map(|name| root.join(String::from_utf8_lossy(name).as_ref()))
                .collect::<Vec<PathBuf>>()
        });
    let candidates = match listed {
        Some(files) if !files.is_empty() => files,
        _ => {
            let mut files = Vec::new();
            collect(root, &mut files);
            files
        }
    };
    candidates
        .into_iter()
        .filter(|path| path.is_file() && is_text(path))
        .collect()
}

/// Whether a file's first bytes look like text.
fn is_text(path: &Path) -> bool {
    use std::io::Read;
    let Ok(mut file) = fs::File::open(path) else {
        return false;
    };
    let mut head = [0u8; 8192];
    let Ok(read) = file.read(&mut head) else {
        return false;
    };
    !head[..read].contains(&0)
}

/// Directory names skipped by the fallback walk: build output and VCS
/// metadata.
fn is_skipped(path: &Path) -> bool {
    matches!(
        path.file_name().and_then(|n| n.to_str()),
        Some("target") | Some(".git")
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
        } else {
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
/// Scan one body against one token set.
fn scan_with(label: &str, text: &str, tokens: &[Forbidden], violations: &mut Vec<String>) {
    let lowered = text.to_ascii_lowercase();
    for forbidden in tokens {
        if contains_token(&lowered, forbidden) {
            violations.push(format!("{label} contains {:?}", forbidden.token));
        }
    }
}

#[test]
fn no_forbidden_token_appears_in_the_crate() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let files = tracked_text_files(&root);
    assert!(
        files.len() > 40,
        "the scrub found too few files: {}",
        files.len()
    );
    // Every surface class is in scope: source, tests, rules, prose,
    // manifests, and anything else tracked.
    for expected in [
        "src/lib.rs",
        "rules/converters.toml",
        "README.md",
        "Cargo.toml",
    ] {
        assert!(
            files.iter().any(|f| f.ends_with(expected)),
            "{expected} is not in the scrub scope"
        );
    }

    let mut violations = Vec::new();
    let base = forbidden();
    let products = forbidden_products();
    let notice = root.join(LEGAL_NOTICE);
    for file in &files {
        let Ok(text) = fs::read_to_string(file) else {
            continue;
        };
        let label = file.display().to_string();
        scan_with(&label, &text, &base, &mut violations);
        // The legal-notice carveout: the bundled license at the crate
        // root may name its copyright holders, and the fix for a hit
        // there is never to edit the notice. It is that one path.
        if *file != notice {
            scan_with(&label, &text, &products, &mut violations);
        }
    }
    assert!(
        violations.is_empty(),
        "forbidden tokens found:\n{}",
        violations.join("\n")
    );
}

/// The legal-notice carveout is exactly one file wide and covers only
/// the product set: the process vocabulary is forbidden there too, and
/// every other file is held to both sets.
#[test]
fn the_legal_notice_carveout_is_narrow() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let notice = root.join(LEGAL_NOTICE);
    assert!(notice.is_file(), "the legal notice ships with the crate");
    let text = fs::read_to_string(&notice).unwrap();
    // The carveout is the root path alone: a file of the same name
    // anywhere else is scanned like everything else.
    let elsewhere = root.join("docs").join(LEGAL_NOTICE);
    assert_ne!(elsewhere, notice);
    assert!(tracked_text_files(&root).iter().all(|f| *f != elsewhere));
    // It is scanned against the process vocabulary like anything else.
    let mut violations = Vec::new();
    scan_with("notice", &text, &forbidden(), &mut violations);
    assert!(violations.is_empty(), "{violations:?}");
    // And the carveout is needed: the notice does name a vendor the
    // product set forbids everywhere else.
    let mut vendor = Vec::new();
    scan_with("notice", &text, &forbidden_products(), &mut vendor);
    assert!(
        !vendor.is_empty(),
        "the carveout exists for an attribution that is actually there"
    );
}

/// The role labels this crate ships publicly stay legal under the
/// product set, so tightening the scrub can never force a rename of a
/// settled public label.
#[test]
fn the_public_role_labels_survive_the_product_set() {
    let mut violations = Vec::new();
    let labels = "raster-browser raster-magick engine-cli vision-weights vision-projector \
                  ocr-prompt ocr-limit-policy asr-cli asr-weights asr-probe asr-decode-policy";
    scan_with("labels", labels, &forbidden_products(), &mut violations);
    assert!(violations.is_empty(), "{violations:?}");
}

#[test]
fn whole_word_tokens_do_not_match_inside_longer_words() {
    let all: Vec<Forbidden> = forbidden()
        .into_iter()
        .chain(forbidden_products())
        .collect();
    let bounded: Vec<&Forbidden> = all.iter().filter(|f| f.whole_word).collect();
    assert!(!bounded.is_empty(), "the set has whole-word tokens");
    for forbidden in &bounded {
        let inside = format!("x{}x", forbidden.token);
        let mut violations = Vec::new();
        scan_with("embedded", &inside, &all, &mut violations);
        assert!(violations.is_empty(), "{violations:?}");
        let bare = format!("({}).", forbidden.token);
        scan_with("bare", &bare, &all, &mut violations);
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
    let all: Vec<Forbidden> = forbidden()
        .into_iter()
        .chain(forbidden_products())
        .collect();
    let probe = all
        .iter()
        .map(|f| f.token.clone())
        .collect::<Vec<String>>()
        .join(" and ");
    let mut violations = Vec::new();
    scan_with("planted-probe", &probe, &all, &mut violations);
    assert_eq!(
        violations.len(),
        all.len(),
        "the gate must catch every planted token, found: {violations:?}"
    );
    assert!(
        violations.is_empty(),
        "forbidden tokens found:\n{}",
        violations.join("\n")
    );
}
