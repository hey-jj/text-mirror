//! The `<source>.segments.jsonl` file beside each converted artifact.
//!
//! Segments map the content text back to source structure, out of
//! band. The artifact text carries no marker strings. A boundary is a
//! zero-width record naming the start of a page, sheet, or slide. A
//! span covers a half-open byte range of the artifact and can mark
//! content that was hidden in the source. Records are ordered by
//! start offset, then end offset.

use std::path::Path;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::mirror;
use crate::{Error, Result};

/// The schema identifier carried by every segments@1 record.
pub const SEGMENTS_SCHEMA: &str = "text-mirror/segments@1";

/// The offset unit every segments@1 record uses.
pub const SEGMENTS_UNIT: &str = "utf8_bytes";

/// The `schema` field of a [`Segment`]. Serializes to the literal
/// `text-mirror/segments@1` and rejects every other value on read.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SegmentsSchema;

impl Serialize for SegmentsSchema {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(SEGMENTS_SCHEMA)
    }
}

impl<'de> Deserialize<'de> for SegmentsSchema {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        if value == SEGMENTS_SCHEMA {
            Ok(SegmentsSchema)
        } else {
            Err(D::Error::custom(format!(
                "unrecognized schema {value:?}, this consumer accepts only {SEGMENTS_SCHEMA:?}"
            )))
        }
    }
}

/// What a segments record is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SegmentKind {
    /// A content span over a byte range of the artifact.
    Span,
    /// Zero-width boundary at the start of a page.
    Page,
    /// Zero-width boundary at the start of a sheet.
    Sheet,
    /// Zero-width boundary at the start of a slide.
    Slide,
}

/// One record of a segments file.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Segment {
    /// The literal string `text-mirror/segments@1`, always first.
    pub schema: SegmentsSchema,
    /// Record kind. Boundary kinds are zero-width.
    pub kind: SegmentKind,
    /// Start offset into the artifact, in UTF-8 bytes.
    pub start: u64,
    /// End offset, exclusive. Equal to `start` for a boundary.
    pub end: u64,
    /// The offset unit, the literal `utf8_bytes`.
    pub unit: String,
    /// The source structure a span maps to, such as `document`,
    /// `sheet`, `row`, or `column`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub source: Option<String>,
    /// Structure name, such as a sheet name.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub name: Option<String>,
    /// True when the covered content was hidden in the source.
    #[serde(skip_serializing_if = "std::ops::Not::not", default)]
    pub hidden: bool,
}

impl Segment {
    /// A content span over `start..end`.
    pub fn span(start: usize, end: usize, source: &str) -> Segment {
        Segment {
            schema: SegmentsSchema,
            kind: SegmentKind::Span,
            start: start as u64,
            end: end as u64,
            unit: SEGMENTS_UNIT.to_string(),
            source: Some(source.to_string()),
            name: None,
            hidden: false,
        }
    }

    /// A zero-width boundary at `at`.
    pub fn boundary(kind: SegmentKind, at: usize) -> Segment {
        Segment {
            schema: SegmentsSchema,
            kind,
            start: at as u64,
            end: at as u64,
            unit: SEGMENTS_UNIT.to_string(),
            source: None,
            name: None,
            hidden: false,
        }
    }

    /// The same segment with a name attached.
    pub fn named(mut self, name: &str) -> Segment {
        self.name = Some(name.to_string());
        self
    }

    /// The same segment marked hidden.
    pub fn hidden(mut self) -> Segment {
        self.hidden = true;
        self
    }
}

/// Maps a source path to its segments file in the mirror, the full
/// source name plus `.segments.jsonl`.
pub fn segments_path(
    mirror_root: &Path,
    division: &str,
    relative_source: &Path,
) -> std::path::PathBuf {
    let mut mapped = mirror::mirror_path(mirror_root, division, relative_source);
    let mut name = mapped
        .file_name()
        .map(std::ffi::OsString::from)
        .unwrap_or_default();
    // mirror_path appended ".txt", swap that suffix for ".segments.jsonl"
    let text_name = name.to_string_lossy().into_owned();
    let base = text_name.strip_suffix(".txt").unwrap_or(&text_name);
    name = std::ffi::OsString::from(format!("{base}.segments.jsonl"));
    mapped.set_file_name(name);
    mapped
}

/// Serializes segments to JSONL, one record per line, LF only.
pub fn to_jsonl(segments: &[Segment]) -> Result<String> {
    let mut out = String::new();
    for segment in segments {
        let line = serde_json::to_string(segment).map_err(|e| Error::Encode {
            path: std::path::PathBuf::from("segments"),
            message: e.to_string(),
        })?;
        out.push_str(&line);
        out.push('\n');
    }
    Ok(out)
}

/// Parses a segments sidecar back into records. Any malformed line or
/// unrecognized schema fails the whole parse.
pub fn parse_jsonl(content: &str) -> std::result::Result<Vec<Segment>, String> {
    content
        .lines()
        .enumerate()
        .map(|(index, line)| {
            serde_json::from_str(line).map_err(|e| format!("segments line {}: {e}", index + 1))
        })
        .collect()
}

/// Checks that segments address `text` cleanly.
///
/// Every offset must land on a UTF-8 character boundary within the
/// text, spans must be half-open with `start <= end`, boundaries must
/// be zero-width, and records must be ordered by start, then end.
pub fn validate(segments: &[Segment], text: &str) -> std::result::Result<(), String> {
    let len = text.len() as u64;
    let mut previous = (0u64, 0u64);
    for (index, segment) in segments.iter().enumerate() {
        if segment.start > segment.end {
            return Err(format!(
                "segment {index}: start {} after end {}",
                segment.start, segment.end
            ));
        }
        if segment.end > len {
            return Err(format!(
                "segment {index}: end {} past text length {len}",
                segment.end
            ));
        }
        if segment.kind != SegmentKind::Span && segment.start != segment.end {
            return Err(format!("segment {index}: boundary is not zero-width"));
        }
        for offset in [segment.start, segment.end] {
            if !text.is_char_boundary(offset as usize) {
                return Err(format!(
                    "segment {index}: offset {offset} splits a character"
                ));
            }
        }
        if (segment.start, segment.end) < previous {
            return Err(format!("segment {index}: out of order"));
        }
        previous = (segment.start, segment.end);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn segments_serialize_with_schema_first() {
        let segment = Segment::span(0, 4, "document");
        let json = serde_json::to_string(&segment).unwrap();
        assert!(json.starts_with(r#"{"schema":"text-mirror/segments@1""#));
        let back: Segment = serde_json::from_str(&json).unwrap();
        assert_eq!(segment, back);
    }

    #[test]
    fn unknown_segment_schema_is_rejected() {
        let json = serde_json::to_string(&Segment::span(0, 1, "document")).unwrap();
        let bumped = json.replace("segments@1", "segments@2");
        assert!(serde_json::from_str::<Segment>(&bumped).is_err());
    }

    #[test]
    fn segments_path_swaps_the_txt_suffix() {
        let path = segments_path(Path::new("/m"), "emea", Path::new("a/Q3 Budget.xlsx"));
        assert_eq!(
            path,
            std::path::PathBuf::from("/m/emea/a/Q3 Budget.xlsx.segments.jsonl")
        );
    }

    #[test]
    fn validate_accepts_clean_spans_and_rejects_bad_ones() {
        let text = "caf\u{e9} au lait";
        let good = vec![
            Segment::boundary(SegmentKind::Page, 0),
            Segment::span(0, text.len(), "document"),
        ];
        validate(&good, text).unwrap();

        // An offset inside the two-byte character fails.
        let bad = vec![Segment::span(0, 4, "document")];
        assert!(validate(&bad, text).unwrap_err().contains("splits"));

        let past = vec![Segment::span(0, text.len() + 1, "document")];
        assert!(validate(&past, text).unwrap_err().contains("past"));

        let unordered = vec![Segment::span(3, 5, "row"), Segment::span(0, 2, "row")];
        assert!(validate(&unordered, text).unwrap_err().contains("order"));
    }
}
