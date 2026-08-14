//! Mirror path mapping and atomic writes.

use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::{Error, Result};

/// Maps a source path relative to the division root onto the mirror.
///
/// The full source name keeps its extension and gains `.txt`, so
/// `Q3 Budget.xlsx` becomes `Q3 Budget.xlsx.txt`. Appending preserves
/// source identity and keeps sources that differ only by extension
/// from colliding on one output path.
pub fn mirror_path(mirror_root: &Path, relative_source: &Path) -> PathBuf {
    let mut mapped = mirror_root.join(relative_source);
    let mut name = mapped.file_name().map(OsString::from).unwrap_or_default();
    name.push(".txt");
    mapped.set_file_name(name);
    mapped
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
    fn mirror_path_appends_txt_to_the_full_name() {
        let mapped = mirror_path(Path::new("/mirror"), Path::new("a/b/Q3 Budget.xlsx"));
        assert_eq!(mapped, PathBuf::from("/mirror/a/b/Q3 Budget.xlsx.txt"));
    }

    #[test]
    fn mirror_path_keeps_extensionless_names_distinct() {
        let with = mirror_path(Path::new("/m"), Path::new("readme.md"));
        let without = mirror_path(Path::new("/m"), Path::new("readme"));
        assert_eq!(with, PathBuf::from("/m/readme.md.txt"));
        assert_eq!(without, PathBuf::from("/m/readme.txt"));
        assert_ne!(with, without);
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
