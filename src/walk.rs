//! Deterministic traversal of a division root.

use std::path::{Path, PathBuf};

use walkdir::WalkDir;

use crate::{Error, Result};

/// Traversal options for a division root.
///
/// Two exclusion lists, both matched against a bare entry name at any
/// depth: [`ignore_names`](Self::ignore_names) by exact equality and
/// [`ignore_suffixes`](Self::ignore_suffixes) by a plain name suffix.
/// The suffix list is a small fixed set, not a glob or regex engine, so
/// the policy stays explicit and cheap to read. A skipped directory
/// hides its whole subtree under either list.
///
/// [`Default`] ships the noise policy, so the excludes are on at every
/// call site that builds options this way rather than opt-in.
#[derive(Debug, Clone)]
pub struct WalkOptions {
    /// Exact file and directory names to skip at any depth.
    pub ignore_names: Vec<String>,
    /// Name suffixes to skip at any depth. An entry is skipped when its
    /// bare name ends with any listed suffix.
    pub ignore_suffixes: Vec<String>,
}

impl Default for WalkOptions {
    /// The shipped noise policy: the macOS `.DS_Store` sidecar by exact
    /// name, and the SQLite write-ahead sidecars plus generic temp
    /// files by suffix.
    ///
    /// Data-bearing dotfiles are deliberately absent: `.env`, ssh keys,
    /// `.gitconfig`, and `.config`-style files are primary
    /// classification targets, so nothing here excludes them.
    ///
    /// The crate's own mirror work directories need no exclusion here.
    /// A container expands its members under a `<source>.d/` namespace
    /// in the mirror tree, and `check_layout` (pipeline.rs) forces the
    /// mirror root and the division root to be mutually disjoint, so
    /// those directories never fall under a source walk. Their absence
    /// from this list is a decision, not an oversight, and the
    /// `walks_config_dot_d_directories` test blocks any bare `.d`
    /// suffix from being added back.
    fn default() -> Self {
        WalkOptions {
            ignore_names: vec![".DS_Store".to_string()],
            ignore_suffixes: vec!["-wal".to_string(), "-shm".to_string(), ".tmp".to_string()],
        }
    }
}

/// How the walk classified a directory entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    /// A regular file.
    File,
    /// A symlink. Symlinks are never followed.
    Symlink,
    /// Anything else, such as a FIFO or a socket.
    Other,
}

/// One entry found by the walk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalkedEntry {
    /// Path relative to the walked root.
    pub path: PathBuf,
    /// The entry kind.
    pub kind: EntryKind,
}

/// Walks `root` and returns every non-directory entry.
///
/// Entries are sorted by file name at each directory, so two walks of
/// the same tree return the same list in the same order. Symlinks are
/// never followed, and a root that is itself a symlink is rejected
/// before any traversal. Entries whose name matches
/// [`WalkOptions::ignore_names`] exactly or ends with any
/// [`WalkOptions::ignore_suffixes`] entry are skipped, and a skipped
/// directory hides its whole subtree.
pub fn walk_division(root: &Path, options: &WalkOptions) -> Result<Vec<WalkedEntry>> {
    let root_meta = std::fs::symlink_metadata(root).map_err(|e| Error::io("walk", root, e))?;
    if root_meta.file_type().is_symlink() {
        return Err(Error::Layout {
            message: format!("division root {} is a symlink", root.display()),
        });
    }
    if !root_meta.is_dir() {
        return Err(Error::io(
            "walk",
            root,
            std::io::Error::new(std::io::ErrorKind::NotFound, "not a directory"),
        ));
    }
    let mut entries = Vec::new();
    let walker = WalkDir::new(root)
        .follow_links(false)
        .follow_root_links(false)
        .sort_by_file_name()
        .into_iter()
        .filter_entry(|entry| {
            if entry.depth() == 0 {
                return true;
            }
            let name = entry.file_name().to_string_lossy();
            if options.ignore_names.iter().any(|ignored| ignored == &name) {
                return false;
            }
            !options
                .ignore_suffixes
                .iter()
                .any(|suffix| name.ends_with(suffix.as_str()))
        });
    for entry in walker {
        let entry = entry.map_err(|e| {
            let path = e.path().unwrap_or(root).to_path_buf();
            let source = e
                .into_io_error()
                .unwrap_or_else(|| std::io::Error::other("walk failed"));
            Error::Io {
                op: "walk",
                path,
                source,
            }
        })?;
        let file_type = entry.file_type();
        let kind = if file_type.is_file() {
            EntryKind::File
        } else if file_type.is_symlink() {
            EntryKind::Symlink
        } else if file_type.is_dir() {
            continue;
        } else {
            EntryKind::Other
        };
        let relative = entry
            .path()
            .strip_prefix(root)
            .expect("walk entries live under the root")
            .to_path_buf();
        entries.push(WalkedEntry {
            path: relative,
            kind,
        });
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn touch(path: &Path) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, b"x").unwrap();
    }

    fn paths(entries: &[WalkedEntry]) -> Vec<&Path> {
        entries.iter().map(|e| e.path.as_path()).collect()
    }

    #[test]
    fn walk_is_sorted_and_repeatable() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        touch(&root.join("zeta.txt"));
        touch(&root.join("alpha.txt"));
        touch(&root.join("mid/inner.txt"));
        touch(&root.join("mid/another.txt"));

        let options = WalkOptions::default();
        let first = walk_division(root, &options).unwrap();
        let second = walk_division(root, &options).unwrap();
        let expected = [
            Path::new("alpha.txt"),
            Path::new("mid/another.txt"),
            Path::new("mid/inner.txt"),
            Path::new("zeta.txt"),
        ];
        assert_eq!(paths(&first), expected);
        assert_eq!(first, second);
        assert!(first.iter().all(|e| e.kind == EntryKind::File));
    }

    #[test]
    fn walk_skips_ignored_names() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        touch(&root.join("keep.txt"));
        touch(&root.join(".cache/skip.txt"));
        touch(&root.join("thumbs.db"));

        let options = WalkOptions {
            ignore_names: vec![".cache".to_string(), "thumbs.db".to_string()],
            ignore_suffixes: Vec::new(),
        };
        let entries = walk_division(root, &options).unwrap();
        assert_eq!(paths(&entries), [Path::new("keep.txt")]);
    }

    // The default noise policy is locked below. These tests exercise
    // `WalkOptions::default()`, the exact value built at the real call
    // sites (main.rs scan and run), so they assert the shipped policy,
    // not a test-only construction.

    #[test]
    fn walks_sensitive_dotfiles_by_default() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        touch(&root.join(".env"));
        touch(&root.join(".ssh/id_rsa"));
        touch(&root.join(".config"));
        touch(&root.join(".gitconfig"));

        let entries = walk_division(root, &WalkOptions::default()).unwrap();
        let found = paths(&entries);
        for expected in [
            Path::new(".config"),
            Path::new(".env"),
            Path::new(".gitconfig"),
            Path::new(".ssh/id_rsa"),
        ] {
            assert!(found.contains(&expected), "{expected:?} must be walked");
        }
    }

    #[test]
    fn walks_config_dot_d_directories() {
        // A `.d` config directory is a first-class source, not noise.
        // This locks the config crawl and blocks anyone reintroducing a
        // bare `.d` suffix exclude.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        touch(&root.join("conf.d/app.conf"));
        touch(&root.join("init.d/service"));

        let entries = walk_division(root, &WalkOptions::default()).unwrap();
        let found = paths(&entries);
        assert!(found.contains(&Path::new("conf.d/app.conf")));
        assert!(found.contains(&Path::new("init.d/service")));
    }

    #[test]
    fn excludes_the_default_noise_set() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        touch(&root.join("keep.txt"));
        touch(&root.join(".DS_Store"));
        touch(&root.join("foo-wal"));
        touch(&root.join("foo-shm"));
        touch(&root.join("bar.tmp"));

        let entries = walk_division(root, &WalkOptions::default()).unwrap();
        assert_eq!(paths(&entries), [Path::new("keep.txt")]);
    }

    #[test]
    fn default_options_carry_the_noise_policy() {
        // The policy is on by default: the exact set below is what the
        // real call sites apply. Nothing more is excluded.
        let options = WalkOptions::default();
        assert_eq!(options.ignore_names, vec![".DS_Store".to_string()]);
        assert_eq!(
            options.ignore_suffixes,
            vec!["-wal".to_string(), "-shm".to_string(), ".tmp".to_string()]
        );
    }

    #[cfg(unix)]
    #[test]
    fn walk_returns_symlinks_as_entries_without_following() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        touch(&root.join("outside/secret.txt"));

        let scoped = root.join("division");
        fs::create_dir_all(&scoped).unwrap();
        touch(&scoped.join("real.txt"));
        std::os::unix::fs::symlink(root.join("outside/secret.txt"), scoped.join("link.txt"))
            .unwrap();
        std::os::unix::fs::symlink(root.join("outside"), scoped.join("linked-dir")).unwrap();

        let entries = walk_division(&scoped, &WalkOptions::default()).unwrap();
        assert_eq!(
            entries,
            vec![
                WalkedEntry {
                    path: PathBuf::from("link.txt"),
                    kind: EntryKind::Symlink,
                },
                WalkedEntry {
                    path: PathBuf::from("linked-dir"),
                    kind: EntryKind::Symlink,
                },
                WalkedEntry {
                    path: PathBuf::from("real.txt"),
                    kind: EntryKind::File,
                },
            ]
        );
    }

    #[cfg(unix)]
    #[test]
    fn walk_rejects_a_symlinked_root() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        touch(&root.join("outside/secret.txt"));
        let link = root.join("root-link");
        std::os::unix::fs::symlink(root.join("outside"), &link).unwrap();

        let err = walk_division(&link, &WalkOptions::default()).unwrap_err();
        assert!(err.to_string().contains("symlink"));
    }
}
