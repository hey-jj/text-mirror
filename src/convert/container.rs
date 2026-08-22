//! Zip container expansion.
//!
//! A source detected as a plain zip is a container. Its artifact is a
//! member listing, and each member is extracted and routed back
//! through the pipeline's dispatch as a child source under a sibling
//! `.d/` directory. The member loop, recursion, and record writing
//! live in the pipeline. This module owns the zip reading: the
//! listing, per-member hygiene, and capped inflation.
//!
//! The zip-bomb surface is bounded in two stages. The central
//! directory is read first, so the child count and the declared sizes
//! are checked before any inflation. Then each member inflates through
//! a capped reader that never trusts a declared size as its
//! allocation budget, and the actual inflated bytes charge a
//! cumulative counter across the whole expansion.

use std::io::{Cursor, Read};

use serde::Deserialize;

use super::ConvertError;

/// Synthetic converter id recorded for a zip container's listing
/// artifact. No registry entry claims it, the pipeline synthesizes it.
pub const CONTAINER_ZIP_ID: &str = "container-zip";
/// Version of the container listing format.
pub const CONTAINER_ZIP_VERSION: &str = "1.0.0";

/// Expansion ceilings from the `[containers]` section of
/// `rules/converters.toml`, versioned with the rest of the rules.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContainerLimits {
    /// Maximum nesting depth. The outer file is depth 0.
    pub max_depth: usize,
    /// Maximum members per container.
    pub max_children: usize,
    /// Cumulative inflated bytes across one top-level container's
    /// whole tree, dedup copies included.
    pub max_expanded_bytes: u64,
    /// Maximum uncompressed bytes of one member.
    pub max_member_size: u64,
}

impl Default for ContainerLimits {
    fn default() -> Self {
        ContainerLimits {
            max_depth: 4,
            max_children: 1000,
            max_expanded_bytes: 1_073_741_824,
            max_member_size: 268_435_456,
        }
    }
}

/// One member's central-directory metadata, read before any inflation.
#[derive(Debug, Clone)]
pub struct MemberMeta {
    /// The raw entry name as stored in the archive.
    pub name: String,
    /// The safe relative path, or `None` when the entry name is
    /// absolute, escapes with `..`, carries a drive prefix, or is
    /// otherwise unsafe as a mirror path.
    pub safe_path: Option<String>,
    /// Declared uncompressed size from the central directory.
    pub declared_size: u64,
    /// True for a directory entry, which is listed but never a child.
    pub is_dir: bool,
    /// True for a symlink entry, refused like an unsafe path.
    pub is_symlink: bool,
    /// True when the member is encrypted.
    pub encrypted: bool,
}

/// The outcome of inflating one member under a byte cap.
pub enum Inflated {
    /// The member inflated within the cap.
    Ok(Vec<u8>),
    /// The member overran the cap. Carries the bytes inflated before
    /// the cap tripped, so a cumulative counter can charge them.
    TooLarge(u64),
    /// The member could not be read.
    Error(String),
}

/// A zip archive opened over borrowed bytes.
pub struct ZipContainer<'a> {
    archive: zip::ZipArchive<Cursor<&'a [u8]>>,
}

fn open_error(detail: impl std::fmt::Display) -> ConvertError {
    ConvertError {
        code: "container-unreadable",
        message: format!("zip central directory unreadable: {detail}"),
    }
}

impl<'a> ZipContainer<'a> {
    /// Opens the archive and reads its central directory.
    pub fn open(bytes: &'a [u8]) -> Result<Self, ConvertError> {
        let archive = zip::ZipArchive::new(Cursor::new(bytes)).map_err(open_error)?;
        Ok(ZipContainer { archive })
    }

    /// The member count from the central directory.
    pub fn len(&self) -> usize {
        self.archive.len()
    }

    /// True when the archive holds no members.
    pub fn is_empty(&self) -> bool {
        self.archive.is_empty()
    }

    /// The member listing artifact: one line per entry in archive
    /// order, the entry name, a tab, and the declared uncompressed
    /// size.
    pub fn listing(&mut self) -> Result<String, ConvertError> {
        let mut out = String::new();
        for index in 0..self.archive.len() {
            let entry = self.archive.by_index(index).map_err(open_error)?;
            out.push_str(&escape_listing_name(entry.name()));
            out.push('\t');
            out.push_str(&entry.size().to_string());
            out.push('\n');
        }
        Ok(out)
    }

    /// The metadata for member `index`, read from the central
    /// directory before any inflation.
    pub fn meta(&mut self, index: usize) -> Result<MemberMeta, ConvertError> {
        let entry = self.archive.by_index(index).map_err(open_error)?;
        let safe_path = classify_member_name(entry.name());
        Ok(MemberMeta {
            name: entry.name().to_string(),
            safe_path,
            declared_size: entry.size(),
            is_dir: entry.is_dir(),
            is_symlink: entry.is_symlink(),
            encrypted: entry.encrypted(),
        })
    }

    /// Inflates member `index` through a reader capped at `cap` bytes.
    /// A declared size is never trusted as the allocation budget, so
    /// the read stops one byte past the cap and reports the overrun.
    pub fn inflate(&mut self, index: usize, cap: u64) -> Inflated {
        let entry = match self.archive.by_index(index) {
            Ok(entry) => entry,
            Err(e) => return Inflated::Error(e.to_string()),
        };
        let mut buffer = Vec::new();
        match entry.take(cap + 1).read_to_end(&mut buffer) {
            Ok(_) => {
                if buffer.len() as u64 > cap {
                    Inflated::TooLarge(buffer.len() as u64)
                } else {
                    Inflated::Ok(buffer)
                }
            }
            Err(e) => Inflated::Error(e.to_string()),
        }
    }
}

/// Validates a raw member name and returns its safe forward-slash
/// relative path, or `None` when the name is unsafe as a mirror path.
///
/// The raw name is inspected before any normalization, so an absolute,
/// rooted, or drive-prefixed name is refused rather than rebased, and
/// a `..` component, a control character, or an empty segment is
/// refused. This is stricter than the zip crate's `enclosed_name`,
/// which silently rebases an absolute path into a relative one.
pub fn classify_member_name(raw: &str) -> Option<String> {
    if raw.is_empty() {
        return None;
    }
    // A control character in a member name would enter the manifest
    // key, the mirror path, and the bundle checksum file, one line per
    // artifact. Refuse it.
    if raw.chars().any(|c| c.is_control()) {
        return None;
    }
    // Absolute or rooted names.
    if raw.starts_with('/') || raw.starts_with('\\') {
        return None;
    }
    // A drive prefix such as `C:`.
    let drive = raw.as_bytes();
    if drive.len() >= 2 && drive[0].is_ascii_alphabetic() && drive[1] == b':' {
        return None;
    }
    let mut segments = Vec::new();
    for segment in raw.split(['/', '\\']) {
        if segment.is_empty() || segment == "." || segment == ".." {
            return None;
        }
        segments.push(segment);
    }
    if segments.is_empty() {
        return None;
    }
    Some(segments.join("/"))
}

/// Escapes control characters in a member name for the parent listing,
/// so a newline or tab in a name cannot break the one-line-per-member,
/// tab-separated format.
fn escape_listing_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for c in name.chars() {
        match c {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\x{:02x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Reads the total central-directory entry count from the end-of-
/// central-directory record with bounded tail reads, before the full
/// archive is parsed.
///
/// The zip crate folds entries into a map keyed by raw name, so its
/// `len` undercounts an archive of duplicate names, and it parses the
/// whole directory before any count is available. This reads only the
/// EOCD, and the ZIP64 EOCD when the 16-bit count saturates, so the
/// child-count limit can refuse an oversized directory before it is
/// allocated. `None` means no EOCD was found and the caller falls
/// back to opening the archive, which reports the error.
pub fn preflight_entry_count(bytes: &[u8]) -> Option<u64> {
    const EOCD_SIG: [u8; 4] = [0x50, 0x4b, 0x05, 0x06];
    const LOCATOR_SIG: [u8; 4] = [0x50, 0x4b, 0x06, 0x07];
    const ZIP64_EOCD_SIG: [u8; 4] = [0x50, 0x4b, 0x06, 0x06];
    // The EOCD is 22 bytes plus a comment of at most 0xFFFF bytes.
    let scan_start = bytes.len().saturating_sub(22 + 0xFFFF);
    let window = &bytes[scan_start..];
    let mut eocd = None;
    let upper = window.len().saturating_sub(4);
    for start in (0..=upper).rev() {
        if window[start..start + 4] == EOCD_SIG {
            eocd = Some(scan_start + start);
            break;
        }
    }
    let eocd = eocd?;
    if eocd + 22 > bytes.len() {
        return None;
    }
    let total = u16::from_le_bytes([bytes[eocd + 10], bytes[eocd + 11]]) as u64;
    if total != 0xFFFF {
        return Some(total);
    }
    // A saturated 16-bit count points at the ZIP64 records.
    if eocd < 20 {
        return Some(total);
    }
    let locator = eocd - 20;
    if bytes[locator..locator + 4] != LOCATOR_SIG {
        return Some(total);
    }
    let z64_offset = u64::from_le_bytes(bytes[locator + 8..locator + 16].try_into().ok()?) as usize;
    if z64_offset + 40 > bytes.len() || bytes[z64_offset..z64_offset + 4] != ZIP64_EOCD_SIG {
        return Some(total);
    }
    Some(u64::from_le_bytes(
        bytes[z64_offset + 32..z64_offset + 40].try_into().ok()?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use zip::write::SimpleFileOptions;

    fn zip_with(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        for (name, bytes) in entries {
            writer
                .start_file(*name, SimpleFileOptions::default())
                .unwrap();
            writer.write_all(bytes).unwrap();
        }
        writer.finish().unwrap().into_inner()
    }

    #[test]
    fn listing_names_every_entry_with_its_declared_size() {
        let bytes = zip_with(&[("a.txt", b"hello"), ("dir/b.txt", b"hi")]);
        let Ok(mut container) = ZipContainer::open(&bytes) else {
            panic!("open failed")
        };
        assert_eq!(container.len(), 2);
        let listing = container.listing().unwrap();
        assert_eq!(listing, "a.txt\t5\ndir/b.txt\t2\n");
    }

    #[test]
    fn a_normal_member_has_a_safe_path() {
        let bytes = zip_with(&[("inner/report.txt", b"x")]);
        let Ok(mut container) = ZipContainer::open(&bytes) else {
            panic!("open failed")
        };
        let meta = container.meta(0).unwrap();
        assert_eq!(meta.safe_path.as_deref(), Some("inner/report.txt"));
        assert!(!meta.is_dir && !meta.is_symlink && !meta.encrypted);
    }

    #[test]
    fn a_traversal_member_has_no_safe_path() {
        let bytes = zip_with(&[("../escape.txt", b"x")]);
        let Ok(mut container) = ZipContainer::open(&bytes) else {
            panic!("open failed")
        };
        let meta = container.meta(0).unwrap();
        assert_eq!(meta.safe_path, None);
    }

    #[test]
    fn inflation_stops_one_byte_past_the_cap() {
        let big = [b'x'; 100];
        let bytes = zip_with(&[("big.txt", &big)]);
        let Ok(mut container) = ZipContainer::open(&bytes) else {
            panic!("open failed")
        };
        match container.inflate(0, 10) {
            Inflated::TooLarge(n) => assert_eq!(n, 11),
            _ => panic!("expected TooLarge"),
        }
        match container.inflate(0, 1000) {
            Inflated::Ok(data) => assert_eq!(data.len(), 100),
            _ => panic!("expected Ok"),
        }
    }

    #[test]
    fn member_name_validation_refuses_unsafe_shapes() {
        assert_eq!(
            classify_member_name("inner/report.txt").as_deref(),
            Some("inner/report.txt")
        );
        assert_eq!(classify_member_name("a\\b.txt").as_deref(), Some("a/b.txt"));
        assert_eq!(classify_member_name("../escape.txt"), None);
        assert_eq!(classify_member_name("/abs.txt"), None);
        assert_eq!(classify_member_name("C:\\win.txt"), None);
        assert_eq!(classify_member_name("line1\nline2.txt"), None);
        assert_eq!(classify_member_name("tab\there.txt"), None);
        assert_eq!(classify_member_name(""), None);
        assert_eq!(classify_member_name("dir/"), None);
    }

    #[test]
    fn listing_escapes_control_characters_in_names() {
        let bytes = zip_with(&[("a\tb.txt", b"x"), ("c\nd.txt", b"y")]);
        let Ok(mut container) = ZipContainer::open(&bytes) else {
            panic!("open failed")
        };
        let listing = container.listing().unwrap();
        assert!(listing.contains("a\\tb.txt\t1\n"), "{listing:?}");
        assert!(listing.contains("c\\nd.txt\t1\n"), "{listing:?}");
        // Every line is a real record line: the escaped names added no
        // extra newline or tab.
        assert_eq!(listing.lines().count(), 2);
    }

    #[test]
    fn preflight_reads_the_entry_count_from_the_eocd() {
        let bytes = zip_with(&[("a.txt", b"1"), ("b.txt", b"2"), ("c.txt", b"3")]);
        assert_eq!(preflight_entry_count(&bytes), Some(3));
        assert_eq!(preflight_entry_count(b"not a zip"), None);
    }

    #[test]
    fn a_non_zip_fails_to_open() {
        let err = match ZipContainer::open(b"not a zip at all") {
            Ok(_) => panic!("expected an open error"),
            Err(e) => e,
        };
        assert_eq!(err.code, "container-unreadable");
    }
}
