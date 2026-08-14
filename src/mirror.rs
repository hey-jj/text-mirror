//! Mirror path mapping and atomic writes.
//!
//! The mirror is division-namespaced: the artifact for source path
//! `p` in division `d` lives at `<mirror root>/<d>/<p>.txt`, and a
//! manifest record's `text_path` value is mirror-root-relative with
//! the division segment first: `<d>/<p>.txt`, no `mirror/` prefix.
//! First path segments are distinct by construction, so two divisions
//! holding the same source path can never collide, on the prep
//! machine or in a merged bundle.

use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::{Error, Result};

/// Maps a division and a source path onto the on-disk mirror.
///
/// The artifact lives under the division segment, and the full source
/// name keeps its extension and gains `.txt`, so `Q3 Budget.xlsx` in
/// division `emea` becomes `<root>/emea/Q3 Budget.xlsx.txt`.
/// Appending preserves source identity and keeps sources that differ
/// only by extension from colliding on one output path.
pub fn mirror_path(mirror_root: &Path, division: &str, relative_source: &Path) -> PathBuf {
    let mut mapped = mirror_root.join(division).join(relative_source);
    let mut name = mapped.file_name().map(OsString::from).unwrap_or_default();
    name.push(".txt");
    mapped.set_file_name(name);
    mapped
}

/// The mirror-root-relative `text_path` value recorded in the
/// manifest for a source path in a division: the division segment
/// first, then the source path, then the appended extension.
pub fn recorded_text_path(division: &str, source_path: &str) -> String {
    format!("{division}/{source_path}.txt")
}

/// Resolves a recorded mirror-root-relative path to its on-disk
/// location under the mirror root.
///
/// The recorded value must be a bare division-qualified path, at
/// least two clean segments, staying inside the tree. Anything else
/// is a malformed record, not a file to go looking for.
pub fn resolve_recorded_path(mirror_root: &Path, recorded: &str) -> Result<PathBuf> {
    let segments: Vec<&str> = recorded.split('/').collect();
    // Backslash and colon are separators on hosts this crate does not
    // run on, and a recorded path must mean the same file everywhere.
    let clean = segments.len() >= 2
        && !recorded.contains(['\\', ':'])
        && segments
            .iter()
            .all(|segment| !segment.is_empty() && *segment != "." && *segment != "..");
    if !clean {
        return Err(Error::io(
            "resolve",
            Path::new(recorded),
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "recorded path is not a clean division-qualified mirror path",
            ),
        ));
    }
    Ok(mirror_root.join(recorded))
}

/// Writes `text` to `dest` atomically.
///
/// The bytes land in a temp file in the destination directory, then a
/// rename moves the file into place, so a reader never sees a partial
/// artifact. Parent directories are created as needed.
pub fn write_atomic(dest: &Path, text: &str) -> Result<()> {
    let dir = dest.parent().ok_or_else(|| {
        Error::io(
            "write",
            dest,
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "no parent directory"),
        )
    })?;
    fs::create_dir_all(dir).map_err(|e| Error::io("create_dir", dir, e))?;
    let mut tmp = tempfile::NamedTempFile::new_in(dir).map_err(|e| Error::io("write", dest, e))?;
    tmp.as_file_mut()
        .write_all(text.as_bytes())
        .map_err(|e| Error::io("write", dest, e))?;
    tmp.persist(dest)
        .map_err(|e| Error::io("persist", dest, e.error))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mirror_path_is_division_namespaced() {
        let mapped = mirror_path(
            Path::new("/mirror"),
            "emea",
            Path::new("a/b/Q3 Budget.xlsx"),
        );
        assert_eq!(mapped, PathBuf::from("/mirror/emea/a/b/Q3 Budget.xlsx.txt"));
    }

    #[test]
    fn mirror_path_keeps_extensionless_names_distinct() {
        let with = mirror_path(Path::new("/m"), "d", Path::new("readme.md"));
        let without = mirror_path(Path::new("/m"), "d", Path::new("readme"));
        assert_eq!(with, PathBuf::from("/m/d/readme.md.txt"));
        assert_eq!(without, PathBuf::from("/m/d/readme.txt"));
        assert_ne!(with, without);
    }

    #[test]
    fn same_source_path_in_two_divisions_cannot_collide() {
        let emea = recorded_text_path("emea", "reports/q3.docx");
        let apac = recorded_text_path("apac", "reports/q3.docx");
        assert_eq!(emea, "emea/reports/q3.docx.txt");
        assert_eq!(apac, "apac/reports/q3.docx.txt");
        assert_ne!(emea, apac);
        assert_ne!(
            mirror_path(Path::new("/m"), "emea", Path::new("reports/q3.docx")),
            mirror_path(Path::new("/m"), "apac", Path::new("reports/q3.docx"))
        );
    }

    #[test]
    fn recorded_paths_resolve_and_escapes_are_refused() {
        let resolved = resolve_recorded_path(Path::new("/m"), "emea/a.txt.txt").unwrap();
        assert_eq!(resolved, PathBuf::from("/m/emea/a.txt.txt"));
        // A bare file name lacks the division segment.
        assert!(resolve_recorded_path(Path::new("/m"), "a.txt.txt").is_err());
        assert!(resolve_recorded_path(Path::new("/m"), "emea/../evil").is_err());
        assert!(resolve_recorded_path(Path::new("/m"), "emea//x").is_err());
        assert!(resolve_recorded_path(Path::new("/m"), "emea/").is_err());
        assert!(resolve_recorded_path(Path::new("/m"), "").is_err());
    }

    #[test]
    fn write_atomic_creates_directories_and_content() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("deep/nested/file.txt");
        write_atomic(&dest, "content\n").unwrap();
        assert_eq!(fs::read_to_string(&dest).unwrap(), "content\n");
    }

    #[test]
    fn write_atomic_replaces_existing_content() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("file.txt");
        write_atomic(&dest, "old\n").unwrap();
        write_atomic(&dest, "new\n").unwrap();
        assert_eq!(fs::read_to_string(&dest).unwrap(), "new\n");
    }
}
