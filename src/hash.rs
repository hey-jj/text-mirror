//! Streaming BLAKE3 file hashing and the dedup index.

use std::collections::HashMap;
use std::fs::File;
use std::path::Path;

use crate::manifest::ArtifactKind;
use crate::{Error, Result};

/// Hashes a file with BLAKE3, streaming, and returns lowercase hex.
pub fn hash_file(path: &Path) -> Result<String> {
    let file = File::open(path).map_err(|e| Error::io("open", path, e))?;
    let mut hasher = blake3::Hasher::new();
    hasher
        .update_reader(file)
        .map_err(|e| Error::io("read", path, e))?;
    Ok(hasher.finalize().to_hex().to_string())
}

/// Hashes a byte slice with BLAKE3 and returns lowercase hex.
pub fn hash_bytes(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

/// The conversion outcome of the first source seen with a given hash.
///
/// A later source with the same hash becomes a `dedup` record that
/// copies this artifact instead of converting again.
#[derive(Debug, Clone)]
pub struct CanonicalArtifact {
    /// Source path of the canonical copy, relative to the division root.
    pub source_path: String,
    /// Text path of the canonical artifact, relative to the mirror root.
    pub text_path: String,
    /// BLAKE3 hash of the canonical artifact text.
    pub text_hash: String,
    /// Converter that produced the canonical artifact.
    pub converter_id: String,
    /// Version of that converter.
    pub converter_version: String,
    /// The canonical artifact's kind.
    pub artifact_kind: Option<ArtifactKind>,
}

/// Maps a source hash to the canonical artifact that converted it.
///
/// The first insert for a hash wins. Traversal is sorted, so the
/// canonical copy is stable across runs of the same tree.
#[derive(Debug, Default)]
pub struct DedupIndex {
    by_hash: HashMap<String, CanonicalArtifact>,
}

impl DedupIndex {
    /// Registers a converted artifact unless the hash already has one.
    pub fn insert(&mut self, source_hash: &str, canonical: CanonicalArtifact) {
        self.by_hash
            .entry(source_hash.to_string())
            .or_insert(canonical);
    }

    /// Registers a converted artifact, replacing any seeded entry.
    ///
    /// An in-run conversion is fresher than anything seeded from a
    /// prior manifest, so it wins.
    pub fn replace(&mut self, source_hash: &str, canonical: CanonicalArtifact) {
        self.by_hash.insert(source_hash.to_string(), canonical);
    }

    /// Looks up the canonical artifact for a source hash.
    pub fn get(&self, source_hash: &str) -> Option<&CanonicalArtifact> {
        self.by_hash.get(source_hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn hash_bytes_matches_known_vector() {
        assert_eq!(
            hash_bytes(b""),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
    }

    #[test]
    fn hash_file_matches_hash_bytes() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(b"mirror me").unwrap();
        file.flush().unwrap();
        assert_eq!(hash_file(file.path()).unwrap(), hash_bytes(b"mirror me"));
    }

    #[test]
    fn dedup_index_keeps_first_insert() {
        let mut index = DedupIndex::default();
        let first = CanonicalArtifact {
            source_path: "a.txt".to_string(),
            text_path: "a.txt.txt".to_string(),
            text_hash: "aa".to_string(),
            converter_id: "text-passthrough".to_string(),
            converter_version: "1.0.0".to_string(),
            artifact_kind: Some(ArtifactKind::Text),
        };
        let mut second = first.clone();
        second.source_path = "b.txt".to_string();
        index.insert("h1", first);
        index.insert("h1", second.clone());
        assert_eq!(index.get("h1").unwrap().source_path, "a.txt");
        assert!(index.get("h2").is_none());

        index.replace("h1", second);
        assert_eq!(index.get("h1").unwrap().source_path, "b.txt");
    }
}
