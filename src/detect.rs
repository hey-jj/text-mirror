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
struct RawFormatDef {
    id: String,
    name: String,
    extensions: Vec<String>,
    /// Id of the generic parent format this entry is a specific form
    /// of, such as svg refining xml. Carried privately by the table.
    #[serde(default)]
    refines: Option<String>,
    /// Exact file names that declare this format for paths with no
    /// extension, such as a file named exactly `.env`. Carried
    /// privately by the table.
    #[serde(default)]
    basenames: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTable {
    version: String,
    formats: Vec<RawFormatDef>,
}

/// Format ids the pipeline synthesizes, so no rules file may claim
/// them: a table entry or registry claim on `unknown` would route
/// every unplaceable file, and one on `symlink` would contradict the
/// symlink records the pipeline writes itself.
pub(crate) const RESERVED_FORMAT_IDS: [&str; 2] = [UNKNOWN_FORMAT, crate::pipeline::SYMLINK_FORMAT];

/// The parsed format table from `rules/formats.toml`.
#[derive(Debug)]
pub struct FormatTable {
    version: String,
    formats: Vec<FormatDef>,
    by_extension: HashMap<String, String>,
    by_basename: HashMap<String, String>,
    refines_by_id: HashMap<String, String>,
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
        let rules_error = |message: String| Error::Rules {
            name: name.to_string(),
            message,
        };
        let mut by_extension = HashMap::new();
        let mut by_basename = HashMap::new();
        let mut ids = HashMap::new();
        let mut refines_by_id = HashMap::new();
        for format in &raw.formats {
            if RESERVED_FORMAT_IDS.contains(&format.id.as_str()) {
                return Err(rules_error(format!(
                    "format id {:?} is reserved",
                    format.id
                )));
            }
            if ids.insert(format.id.clone(), ()).is_some() {
                return Err(rules_error(format!("duplicate format id {:?}", format.id)));
            }
            for extension in &format.extensions {
                if by_extension
                    .insert(extension.clone(), format.id.clone())
                    .is_some()
                {
                    return Err(rules_error(format!(
                        "extension {extension:?} claimed twice"
                    )));
                }
            }
            for basename in &format.basenames {
                if basename.is_empty()
                    || by_basename
                        .insert(basename.clone(), format.id.clone())
                        .is_some()
                {
                    return Err(rules_error(format!("basename {basename:?} claimed twice")));
                }
            }
            if let Some(target) = &format.refines {
                refines_by_id.insert(format.id.clone(), target.clone());
            }
        }
        // Refinement is one level deep: every target must be a real
        // entry that refines nothing itself, and no entry refines
        // itself.
        for (id, target) in &refines_by_id {
            if target == id {
                return Err(rules_error(format!("format {id:?} refines itself")));
            }
            if !ids.contains_key(target) {
                return Err(rules_error(format!(
                    "format {id:?} refines unknown format {target:?}"
                )));
            }
            if refines_by_id.contains_key(target) {
                return Err(rules_error(format!(
                    "format {id:?} refines {target:?}, which refines another format itself"
                )));
            }
        }
        let formats = raw
            .formats
            .into_iter()
            .map(|format| FormatDef {
                id: format.id,
                name: format.name,
                extensions: format.extensions,
            })
            .collect();
        Ok(FormatTable {
            version: raw.version,
            formats,
            by_extension,
            by_basename,
            refines_by_id,
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

    /// The generic parent id a format refines, when the table names
    /// one.
    fn refined_parent(&self, id: &str) -> Option<&str> {
        self.refines_by_id.get(id).map(String::as_str)
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
/// A path with no extension falls back to the table's exact basename
/// entries, so a file named exactly `.env` still declares its format.
/// Needs no file access, so it works for a file the run cannot read.
pub fn declared_format(path: &Path, table: &FormatTable) -> Option<String> {
    if let Some(extension) = path.extension().and_then(|e| e.to_str()) {
        return table
            .id_for_extension(&extension.to_ascii_lowercase())
            .map(String::from);
    }
    path.file_name()
        .and_then(|n| n.to_str())
        .and_then(|n| table.by_basename.get(n))
        .cloned()
}

/// Detects the format of one file against the table.
///
/// Same outcome as [`detect_file_with_warnings`] with the warnings
/// dropped, for callers that only need the resolved ids.
pub fn detect_file(path: &Path, table: &FormatTable) -> Result<Detection> {
    Ok(detect_file_with_warnings(path, table)?.0)
}

/// Detects the format of one file and collects detection warnings.
///
/// The mismatch flag is true only when the declared and detected ids
/// genuinely disagree. Two resolutions keep it down. When magic
/// resolves to the generic parent the declared id refines, svg bytes
/// reading as bare xml, the observations agree and the declared id
/// wins as the more specific truth. When magic resolves to a real
/// format outside the table, the extension decides, the ids are
/// identical, and a warning names the out-of-table format instead, as
/// `magic-format-outside-table: cfb` for an encrypted docx whose
/// bytes are a bare compound file. The warnings belong on the
/// manifest record beside the flag.
pub fn detect_file_with_warnings(
    path: &Path,
    table: &FormatTable,
) -> Result<(Detection, Vec<String>)> {
    let declared = declared_format(path, table);
    let magic = FileFormat::from_file(path).map_err(|e| Error::io("detect", path, e))?;
    let magic_known = magic != FileFormat::default() && magic != FileFormat::Empty;
    let magic_id = if magic_known {
        table.id_for_extension(magic.extension()).map(String::from)
    } else {
        None
    };
    let mut warnings = Vec::new();
    let (detected, mismatch) = match (&magic_id, &declared) {
        (Some(magic), Some(declared)) => {
            if magic != declared && table.refined_parent(declared) == Some(magic.as_str()) {
                (declared.clone(), false)
            } else {
                (magic.clone(), magic != declared)
            }
        }
        (Some(magic), None) => (magic.clone(), false),
        (None, Some(declared)) => {
            if magic_known {
                warnings.push(format!("magic-format-outside-table: {}", magic.extension()));
            }
            (declared.clone(), false)
        }
        (None, None) => (UNKNOWN_FORMAT.to_string(), false),
    };
    Ok((
        Detection {
            declared,
            detected,
            mismatch,
        },
        warnings,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    const PNG_MAGIC: &[u8] = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR";

    #[test]
    fn builtin_table_parses() {
        let table = FormatTable::builtin().unwrap();
        assert_eq!(table.version(), "5");
        assert_eq!(table.id_for_extension("txt"), Some("text"));
        assert_eq!(table.id_for_extension("docx"), Some("docx"));
        assert_eq!(table.id_for_extension("json"), Some("json"));
        assert_eq!(table.id_for_extension("yml"), Some("yaml"));
        assert_eq!(table.id_for_extension("py"), Some("python"));
        assert_eq!(table.id_for_extension("pkl"), Some("pickle"));
        assert_eq!(table.id_for_extension("psb"), Some("psd"));
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
    fn out_of_table_magic_is_a_warning_not_a_same_id_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pic.png");
        std::fs::write(&path, b"GIF89a\x01\x00\x01\x00").unwrap();
        let table = FormatTable::builtin().unwrap();
        let (detection, warnings) = detect_file_with_warnings(&path, &table).unwrap();
        assert_eq!(detection.declared.as_deref(), Some("png"));
        assert_eq!(detection.detected, "png");
        assert!(!detection.mismatch);
        assert_eq!(
            warnings,
            vec!["magic-format-outside-table: gif".to_string()]
        );
    }

    #[test]
    fn cfb_magic_under_a_matching_extension_is_not_a_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("locked.docx");
        let mut bytes = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1".to_vec();
        bytes.extend_from_slice(&[0u8; 24]);
        std::fs::write(&path, &bytes).unwrap();
        let table = FormatTable::builtin().unwrap();
        let (detection, warnings) = detect_file_with_warnings(&path, &table).unwrap();
        assert_eq!(detection.declared.as_deref(), Some("docx"));
        assert_eq!(detection.detected, "docx");
        assert!(!detection.mismatch);
        assert_eq!(
            warnings,
            vec!["magic-format-outside-table: cfb".to_string()]
        );
    }

    const XML_PROLOG_SVG: &[u8] =
        b"<?xml version=\"1.0\"?>\n<svg xmlns=\"http://www.w3.org/2000/svg\"/>\n";

    #[test]
    fn a_declared_refinement_of_the_magic_format_is_not_a_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let table = FormatTable::builtin().unwrap();
        for (file, id) in [
            ("pic.svg", "svg"),
            ("dash.twb", "tableau-workbook"),
            ("src.tds", "tableau-datasource"),
        ] {
            let path = dir.path().join(file);
            fs::write(&path, XML_PROLOG_SVG).unwrap();
            let (detection, warnings) = detect_file_with_warnings(&path, &table).unwrap();
            assert_eq!(detection.declared.as_deref(), Some(id), "{file}");
            assert_eq!(detection.detected, id, "{file}");
            assert!(!detection.mismatch, "{file}");
            assert!(warnings.is_empty(), "{file}: {warnings:?}");
        }
    }

    #[test]
    fn a_plain_xml_file_stays_same_id_without_a_flag() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("feed.xml");
        fs::write(&path, b"<?xml version=\"1.0\"?>\n<feed/>\n").unwrap();
        let table = FormatTable::builtin().unwrap();
        let detection = detect_file(&path, &table).unwrap();
        assert_eq!(detection.declared.as_deref(), Some("xml"));
        assert_eq!(detection.detected, "xml");
        assert!(!detection.mismatch);
    }

    #[test]
    fn a_sibling_disagreement_still_flags_a_mismatch() {
        // A shell shebang under a python name is a disagreement
        // between siblings, so refinement does not apply.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tool.py");
        fs::write(&path, b"#!/bin/sh\necho hi\n").unwrap();
        let table = FormatTable::builtin().unwrap();
        let detection = detect_file(&path, &table).unwrap();
        assert_eq!(detection.declared.as_deref(), Some("python"));
        assert_eq!(detection.detected, "shell");
        assert!(detection.mismatch);
    }

    fn table_with(entries: &str) -> Result<FormatTable> {
        FormatTable::parse(&format!("version = \"1\"\n{entries}"), "formats.toml")
    }

    #[test]
    fn parse_refuses_a_refine_target_missing_from_the_table() {
        let err = table_with(
            "[[formats]]\nid = \"a\"\nname = \"A\"\nextensions = [\"a\"]\nrefines = \"b\"\n",
        )
        .unwrap_err();
        assert!(err.to_string().contains("unknown format"), "{err}");
    }

    #[test]
    fn parse_refuses_a_self_refining_entry() {
        let err = table_with(
            "[[formats]]\nid = \"a\"\nname = \"A\"\nextensions = [\"a\"]\nrefines = \"a\"\n",
        )
        .unwrap_err();
        assert!(err.to_string().contains("refines itself"), "{err}");
    }

    #[test]
    fn parse_refuses_a_refinement_chain() {
        let err = table_with(concat!(
            "[[formats]]\nid = \"a\"\nname = \"A\"\nextensions = [\"a\"]\nrefines = \"b\"\n",
            "[[formats]]\nid = \"b\"\nname = \"B\"\nextensions = [\"b\"]\nrefines = \"c\"\n",
            "[[formats]]\nid = \"c\"\nname = \"C\"\nextensions = [\"c\"]\n",
        ))
        .unwrap_err();
        assert!(err.to_string().contains("refines another format"), "{err}");
    }

    #[test]
    fn a_bare_dotfile_declares_its_format_by_basename() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".env");
        fs::write(&path, b"API_URL=http://localhost\n").unwrap();
        let table = FormatTable::builtin().unwrap();
        let detection = detect_file(&path, &table).unwrap();
        assert_eq!(detection.declared.as_deref(), Some("env"));
        assert_eq!(detection.detected, "env");
        assert!(!detection.mismatch);
    }

    #[test]
    fn parse_refuses_a_basename_claimed_twice() {
        let err = table_with(concat!(
            "[[formats]]\nid = \"a\"\nname = \"A\"\nextensions = [\"a\"]\nbasenames = [\".rc\"]\n",
            "[[formats]]\nid = \"b\"\nname = \"B\"\nextensions = [\"b\"]\nbasenames = [\".rc\"]\n",
        ))
        .unwrap_err();
        assert!(err.to_string().contains("basename"), "{err}");
    }

    #[test]
    fn parse_refuses_the_reserved_format_ids() {
        for id in ["symlink", "unknown"] {
            let err = table_with(&format!(
                "[[formats]]\nid = \"{id}\"\nname = \"X\"\nextensions = [\"x\"]\n"
            ))
            .unwrap_err();
            assert!(err.to_string().contains("reserved"), "{id}: {err}");
        }
    }

    #[test]
    fn in_table_magic_against_a_different_extension_still_flags() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fake.json");
        fs::write(&path, PNG_MAGIC).unwrap();
        let table = FormatTable::builtin().unwrap();
        let (detection, warnings) = detect_file_with_warnings(&path, &table).unwrap();
        assert_eq!(detection.declared.as_deref(), Some("json"));
        assert_eq!(detection.detected, "png");
        assert!(detection.mismatch);
        assert!(warnings.is_empty());
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
