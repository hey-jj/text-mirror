//! Format detection. Magic bytes first, extension as tiebreak.
//!
//! Detection resolves every file against the versioned format table in
//! `rules/formats.toml`. Magic bytes win when they map to a table
//! entry. When magic bytes are inconclusive, or point at a format the
//! table does not name, the file extension decides. Both views are
//! recorded, with a mismatch flag when they disagree.

use std::collections::HashMap;
use std::path::Path;

use file_format::FileFormat;
use serde::Deserialize;

use crate::{Error, Result};

/// The detected id for a file neither magic bytes nor the extension
/// can place.
pub const UNKNOWN_FORMAT: &str = "unknown";

/// One entry in the format table.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FormatDef {
    /// Stable format id recorded in the manifest.
    pub id: String,
    /// Human-readable format name.
    pub name: String,
    /// Lowercase extensions that declare this format.
    pub extensions: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTable {
    version: String,
    formats: Vec<FormatDef>,
}

/// The parsed format table from `rules/formats.toml`.
#[derive(Debug)]
pub struct FormatTable {
    version: String,
    formats: Vec<FormatDef>,
    by_extension: HashMap<String, String>,
}

impl FormatTable {
    /// The table compiled into the binary from `rules/formats.toml`.
    pub fn builtin() -> Result<Self> {
        Self::parse(include_str!("../rules/formats.toml"), "formats.toml")
    }

    /// Parses a format table and validates it.
    pub fn parse(text: &str, name: &str) -> Result<Self> {
        let raw: RawTable = toml::from_str(text).map_err(|e| Error::Rules {
            name: name.to_string(),
            message: e.to_string(),
        })?;
        let mut by_extension = HashMap::new();
        let mut ids = HashMap::new();
        for format in &raw.formats {
            if ids.insert(format.id.clone(), ()).is_some() {
                return Err(Error::Rules {
                    name: name.to_string(),
                    message: format!("duplicate format id {:?}", format.id),
                });
            }
            for extension in &format.extensions {
                if by_extension
                    .insert(extension.clone(), format.id.clone())
                    .is_some()
                {
                    return Err(Error::Rules {
                        name: name.to_string(),
                        message: format!("extension {extension:?} claimed twice"),
                    });
                }
            }
        }
        Ok(FormatTable {
            version: raw.version,
            formats: raw.formats,
            by_extension,
        })
    }

    /// The table version, part of the run's rules version.
    pub fn version(&self) -> &str {
        &self.version
    }

    /// All table entries.
    pub fn formats(&self) -> &[FormatDef] {
        &self.formats
    }

    /// Maps a lowercase extension to a format id.
    pub fn id_for_extension(&self, extension: &str) -> Option<&str> {
        self.by_extension.get(extension).map(String::as_str)
    }
}

/// The detection outcome for one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detection {
    /// Format id the file extension declares, when the table knows it.
    pub declared: Option<String>,
    /// Resolved format id, [`UNKNOWN_FORMAT`] when nothing matches.
    pub detected: String,
    /// True when magic bytes and the extension resolve to different ids.
    pub mismatch: bool,
}

/// The format id a file's extension declares, when the table knows it.
///
/// Needs no file access, so it works for a file the run cannot read.
pub fn declared_format(path: &Path, table: &FormatTable) -> Option<String> {
    path.extension()
        .and_then(|e| e.to_str())
        .and_then(|e| table.id_for_extension(&e.to_ascii_lowercase()))
        .map(String::from)
}

/// Detects the format of one file against the table.
///
/// Magic detection of a real format outside the table cannot resolve
/// to an id, so the extension decides. When that happens against a
/// declared format, the mismatch flag is still set, because the bytes
/// contradict the extension.
pub fn detect_file(path: &Path, table: &FormatTable) -> Result<Detection> {
    let declared = declared_format(path, table);
    let magic = FileFormat::from_file(path).map_err(|e| Error::io("detect", path, e))?;
    let magic_known = magic != FileFormat::default() && magic != FileFormat::Empty;
    let magic_id = if magic_known {
        table.id_for_extension(magic.extension()).map(String::from)
    } else {
        None
    };
    let (detected, mismatch) = match (&magic_id, &declared) {
        (Some(magic), Some(declared)) => (magic.clone(), magic != declared),
        (Some(magic), None) => (magic.clone(), false),
        (None, Some(declared)) => (declared.clone(), magic_known),
        (None, None) => (UNKNOWN_FORMAT.to_string(), false),
    };
    Ok(Detection {
        declared,
        detected,
        mismatch,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    const PNG_MAGIC: &[u8] = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR";

    #[test]
    fn builtin_table_parses() {
        let table = FormatTable::builtin().unwrap();
        assert_eq!(table.version(), "3");
        assert_eq!(table.id_for_extension("txt"), Some("text"));
        assert_eq!(table.id_for_extension("docx"), Some("docx"));
    }

    #[test]
    fn extension_decides_when_magic_is_inconclusive() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("notes.md");
        fs::write(&path, b"# heading\n").unwrap();
        let table = FormatTable::builtin().unwrap();
        let detection = detect_file(&path, &table).unwrap();
        assert_eq!(detection.declared.as_deref(), Some("markdown"));
        assert_eq!(detection.detected, "markdown");
        assert!(!detection.mismatch);
    }

    #[test]
    fn magic_wins_and_flags_a_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fake.txt");
        fs::write(&path, PNG_MAGIC).unwrap();
        let table = FormatTable::builtin().unwrap();
        let detection = detect_file(&path, &table).unwrap();
        assert_eq!(detection.declared.as_deref(), Some("text"));
        assert_eq!(detection.detected, "png");
        assert!(detection.mismatch);
    }

    #[test]
    fn out_of_table_magic_still_flags_a_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pic.png");
        std::fs::write(&path, b"GIF89a\x01\x00\x01\x00").unwrap();
        let table = FormatTable::builtin().unwrap();
        let detection = detect_file(&path, &table).unwrap();
        assert_eq!(detection.declared.as_deref(), Some("png"));
        assert_eq!(detection.detected, "png");
        assert!(detection.mismatch);
    }

    #[test]
    fn empty_file_is_not_a_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.txt");
        std::fs::write(&path, b"").unwrap();
        let table = FormatTable::builtin().unwrap();
        let detection = detect_file(&path, &table).unwrap();
        assert_eq!(detection.detected, "text");
        assert!(!detection.mismatch);
    }

    #[test]
    fn unplaceable_file_is_unknown() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blob.xyz");
        fs::write(&path, b"opaque bytes").unwrap();
        let table = FormatTable::builtin().unwrap();
        let detection = detect_file(&path, &table).unwrap();
        assert_eq!(detection.declared, None);
        assert_eq!(detection.detected, UNKNOWN_FORMAT);
        assert!(!detection.mismatch);
    }
}
