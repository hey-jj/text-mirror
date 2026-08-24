//! The image-metadata derived-child leg: the textual metadata a raster
//! carries, lifted out behind the subprocess jail and rendered as a
//! hidden child beside the pixel-OCR artifact.
//!
//! One image source yields two independent artifacts. The pixel text
//! from the separate `image-pixel-ocr` converter is the primary
//! artifact at `<source>.txt`. The metadata is a derived child at
//! `<source>.d/#image-metadata`, every row marked hidden, reusing the
//! same derived-child record shape a container member already uses. The
//! two legs share nothing in routing, execution, artifact path, or
//! failure state, so a failure of one never fails the other.
//!
//! Every carrier and surface parser runs inside the jailed worker, on
//! the records-worker precedent. Pure Rust removes native memory
//! corruption but not decompression and expansion floods, and those are
//! exactly the metadata attack surface: a `zTXt` decompression bomb, an
//! xml event flood, and a box-count flood in an iso base media file
//! format carrier. The jail bounds wall clock, address space, cpu, and
//! output, so a hostile image fails a child without touching the
//! pipeline. The parent adapter here holds no parser code: it stages the
//! bytes, drives one worker mode, and renders the returned rows to the
//! tabular artifact with one hidden segment per row.
//!
//! Fail closed with no partial artifact on every malformation. A
//! multi-block surface, an oversized block, or a malformed block fails
//! the whole child. An image that carries no textual metadata is
//! not-applicable and produces nothing: no empty child, no failed
//! record.

/// Registry id of the image-metadata converter.
pub const IMAGE_METADATA_ID: &str = "image-metadata";
/// Version of the image-metadata converter.
pub const IMAGE_METADATA_VERSION: &str = "1.0.0";

/// The reason code an image-metadata conversion returns when the source
/// carries no textual metadata. The pipeline treats a failure whose
/// reason begins with this code as the not-applicable outcome: it writes
/// no child and records no failure, distinct from a real conversion
/// failure.
pub const IMAGE_METADATA_NOT_APPLICABLE: &str = "image-metadata-not-applicable";

/// The warning recorded on an image's parent record when a real walked
/// source already occupies the image `.d/` namespace, so the metadata
/// leg is skipped rather than overwriting a real source's artifact.
pub const IMAGE_METADATA_NAMESPACE_OCCUPIED: &str = "image-metadata-namespace-occupied";

/// Whether the metadata derived-child leg applies to a detected format.
///
/// The leg attaches to the raster and vector image carriers whose
/// textual metadata the worker can lift: the three the pixel-OCR
/// converter claims, plus the vector and modern-container carriers that
/// have their own metadata surfaces. It is auxiliary and never a format
/// claim, so it does not compete with a primary converter.
pub fn image_metadata_applies(format: &str) -> bool {
    matches!(format, "png" | "jpeg" | "webp" | "heic" | "svg")
}

#[cfg(all(unix, feature = "image-metadata"))]
pub(crate) use render::render_rows;

/// Parent-side rendering: rows to the deterministic tabular artifact and
/// one hidden segment per row. Pure and jail-free, so the output
/// contract and the hidden marking are testable in process.
#[cfg(all(unix, feature = "image-metadata"))]
mod render {
    use unicode_normalization::UnicodeNormalization;

    use crate::runner::protocol::bodies::MetadataRow;
    use crate::segments::Segment;

    /// Renders non-empty rows to the five-column escaped tabular text in
    /// a fixed sorted order, with one hidden `metadata` span per row.
    ///
    /// Columns are `carrier`, `surface`, `path`, `language`, `value`,
    /// tab-separated, rows LF-separated. Every field is NFC-normalized
    /// and then escaped so a tab, a newline, or a control byte inside a
    /// value can never break the column or line framing, which keeps the
    /// artifact bytes final and the segment offsets exact. Rows sort by
    /// carrier, then surface, then path, then language, then value, so
    /// the same input renders byte-identical output on every run.
    pub(crate) fn render_rows(rows: &[MetadataRow]) -> (String, Vec<Segment>) {
        let mut ordered: Vec<&MetadataRow> = rows.iter().collect();
        ordered.sort_by(|a, b| {
            a.carrier
                .cmp(&b.carrier)
                .then_with(|| a.surface.cmp(&b.surface))
                .then_with(|| a.path.cmp(&b.path))
                .then_with(|| a.language.cmp(&b.language))
                .then_with(|| a.value.cmp(&b.value))
        });
        let mut text = String::new();
        let mut segments = Vec::new();
        for row in ordered {
            let line = format!(
                "{}\t{}\t{}\t{}\t{}",
                escape_field(&row.carrier),
                escape_field(&row.surface),
                escape_field(&row.path),
                escape_field(row.language.as_deref().unwrap_or("")),
                escape_field(&row.value),
            );
            let start = text.len();
            text.push_str(&line);
            let end = text.len();
            text.push('\n');
            // Every metadata row is hidden content by definition: none of
            // it was visible in the rendered image.
            segments.push(Segment::span(start, end, "metadata").hidden());
        }
        (text, segments)
    }

    /// NFC-normalizes then escapes one field so no control character can
    /// break the tab-and-line framing. NFC runs first, so the returned
    /// bytes are final and a later normalization pass cannot shift a
    /// segment boundary, matching the records worker's per-cell rule.
    fn escape_field(raw: &str) -> String {
        let mut out = String::with_capacity(raw.len());
        for c in raw.nfc() {
            match c {
                '\\' => out.push_str("\\\\"),
                '"' => out.push_str("\\\""),
                '\t' => out.push_str("\\t"),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                c if (c as u32) < 0x20 => {
                    out.push_str(&format!("\\u{:04x}", c as u32));
                }
                c => out.push(c),
            }
        }
        out
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn row(carrier: &str, surface: &str, path: &str, value: &str) -> MetadataRow {
            MetadataRow {
                carrier: carrier.to_string(),
                surface: surface.to_string(),
                path: path.to_string(),
                language: None,
                value: value.to_string(),
            }
        }

        #[test]
        fn rows_render_sorted_and_escaped_with_hidden_spans() {
            let rows = vec![
                row("exif", "exif-imagedescription", "270", "a\tb\nc"),
                row("exif", "exif-artist", "315", "author"),
            ];
            let (text, segments) = render_rows(&rows);
            // Sorted by surface within the same carrier: artist before
            // imagedescription.
            assert!(text.starts_with("exif\texif-artist\t315\t\tauthor\n"));
            // The tab and newline inside the value are escaped, so the
            // row keeps its five columns and its single line.
            assert!(text.contains("a\\tb\\nc"));
            assert_eq!(text.lines().count(), 2);
            // Every segment is a hidden metadata span, and the spans land
            // on the row byte ranges in order.
            assert_eq!(segments.len(), 2);
            for segment in &segments {
                assert_eq!(segment.source.as_deref(), Some("metadata"));
                assert!(segment.hidden);
            }
            crate::segments::validate(&segments, &text).unwrap();
        }

        #[test]
        fn a_backslash_or_quote_in_a_value_is_escaped() {
            let rows = vec![row("svg", "svg-title", "/svg/title", "a\\b\"c")];
            let (text, segments) = render_rows(&rows);
            assert!(text.contains("a\\\\b\\\"c"));
            crate::segments::validate(&segments, &text).unwrap();
        }
    }
}

/// The jailed worker-side extraction: one parser per carrier surface,
/// all pinned pure-Rust or first-party bounded code, none of which runs
/// in the parent process. The worker returns structured rows; the parent
/// renders them. A malformation at any stage fails the whole child.
#[cfg(all(unix, feature = "image-metadata"))]
pub(crate) mod extract {
    use std::io::Cursor;
    use std::path::Path;

    use crate::runner::protocol::bodies::MetadataRow;

    /// The ceilings the worker enforces, supplied by the parent from the
    /// rules.
    pub struct Ceilings {
        /// Inflated-size ceiling for any single compressed text block.
        pub max_decompressed_bytes: u64,
        /// Nesting-depth ceiling for an xmp or svg parse.
        pub max_xml_depth: u32,
        /// Event-count ceiling for an xmp or svg parse.
        pub max_xml_events: u64,
        /// Box-count ceiling for an iso base media file format carrier.
        pub max_boxes: u64,
        /// Ceiling on emitted rows.
        pub max_rows: u64,
        /// Ceiling on the rendered value bytes.
        pub max_output_bytes: u64,
    }

    /// An extraction failure with a stable reason code. The message
    /// never embeds a path, host, endpoint, or device identity.
    #[derive(Debug)]
    pub struct MetadataError {
        /// Stable reason, such as `image-metadata-malformed`.
        pub code: &'static str,
        /// Detail for a human reading the manifest.
        pub message: String,
    }

    impl MetadataError {
        fn new(code: &'static str, message: impl Into<String>) -> MetadataError {
            MetadataError {
                code,
                message: message.into(),
            }
        }

        fn malformed(message: impl Into<String>) -> MetadataError {
            MetadataError::new("image-metadata-malformed", message)
        }
    }

    /// Accumulates rows under the row and output ceilings, so a run-away
    /// surface fails closed instead of buying memory. Rows whose value is
    /// blank after trimming are dropped, so a present-but-empty field
    /// never becomes a row and an image with only such fields stays
    /// not-applicable.
    struct Collector {
        rows: Vec<MetadataRow>,
        bytes: u64,
        max_rows: u64,
        max_output_bytes: u64,
    }

    impl Collector {
        fn new(ceilings: &Ceilings) -> Collector {
            Collector {
                rows: Vec::new(),
                bytes: 0,
                max_rows: ceilings.max_rows,
                max_output_bytes: ceilings.max_output_bytes,
            }
        }

        fn push(
            &mut self,
            carrier: &str,
            surface: &str,
            path: &str,
            language: Option<String>,
            value: String,
        ) -> Result<(), MetadataError> {
            if value.trim().is_empty() {
                return Ok(());
            }
            let charge = carrier.len() as u64
                + surface.len() as u64
                + path.len() as u64
                + language.as_ref().map(|l| l.len() as u64).unwrap_or(0)
                + value.len() as u64;
            if self.rows.len() as u64 + 1 > self.max_rows {
                return Err(MetadataError::new(
                    "image-metadata-limit-exceeded",
                    format!("more than {} metadata rows", self.max_rows),
                ));
            }
            if self.bytes + charge > self.max_output_bytes {
                return Err(MetadataError::new(
                    "image-metadata-limit-exceeded",
                    format!("metadata over the {} byte ceiling", self.max_output_bytes),
                ));
            }
            self.bytes += charge;
            self.rows.push(MetadataRow {
                carrier: carrier.to_string(),
                surface: surface.to_string(),
                path: path.to_string(),
                language,
                value,
            });
            Ok(())
        }

        fn into_rows(self) -> Vec<MetadataRow> {
            self.rows
        }
    }

    /// Converts one staged image to metadata rows. `input` is a bare
    /// name in the worker's jail directory. Zero rows is not-applicable;
    /// any malformation fails closed with no rows.
    pub fn extract(
        input: &Path,
        format: &str,
        ceilings: &Ceilings,
    ) -> Result<Vec<MetadataRow>, MetadataError> {
        let bytes = std::fs::read(input)
            .map_err(|e| MetadataError::new("io", format!("cannot read the staged input: {e}")))?;
        let mut collector = Collector::new(ceilings);
        match format {
            "png" => png::collect(&bytes, &mut collector, ceilings)?,
            "jpeg" => jpeg::collect(&bytes, &mut collector, ceilings)?,
            "webp" => webp::collect(&bytes, &mut collector, ceilings)?,
            "heic" => heic::collect(&bytes, &mut collector, ceilings)?,
            "svg" => svg::collect(&bytes, &mut collector, ceilings)?,
            other => {
                return Err(MetadataError::new(
                    "image-metadata-unsupported",
                    format!("the image-metadata worker does not read {other}"),
                ));
            }
        }
        Ok(collector.into_rows())
    }

    // --- exif ---------------------------------------------------------

    /// The exif surfaces scored, each a tag, a surface family, and the
    /// tag number rendered as the path. The gps group is read from its
    /// own context; the caption-adjacent fields from the primary ifd.
    fn exif_surfaces() -> Vec<(exif::Tag, &'static str, &'static str)> {
        use exif::{Context, Tag};
        vec![
            (Tag::ImageDescription, "exif-imagedescription", "270"),
            (Tag::Software, "exif-software", "305"),
            (Tag::DateTime, "exif-datetime", "306"),
            (Tag::Artist, "exif-artist", "315"),
            (Tag::Copyright, "exif-copyright", "33432"),
            (Tag::UserComment, "exif-usercomment", "37510"),
            (Tag::GPSLatitudeRef, "exif-gps-latituderef", "gps:1"),
            (Tag::GPSLatitude, "exif-gps-latitude", "gps:2"),
            (Tag::GPSLongitudeRef, "exif-gps-longituderef", "gps:3"),
            (Tag::GPSLongitude, "exif-gps-longitude", "gps:4"),
            (Tag::GPSDateStamp, "exif-gps-datestamp", "gps:29"),
            // Windows unicode caption fields, addressed by number in the
            // primary ifd. Rendered through the reader's own display.
            (Tag(Context::Tiff, 0x9c9b), "exif-xptitle", "40091"),
            (Tag(Context::Tiff, 0x9c9c), "exif-xpcomment", "40092"),
            (Tag(Context::Tiff, 0x9c9e), "exif-xpkeywords", "40094"),
            (Tag(Context::Tiff, 0x9c9f), "exif-xpsubject", "40095"),
        ]
    }

    /// Reads one raw exif payload and scores its fields. An optional
    /// `Exif\0\0` prefix is stripped first. A malformed payload fails the
    /// whole child.
    fn collect_exif(raw: &[u8], collector: &mut Collector) -> Result<(), MetadataError> {
        use exif::In;
        let body = raw.strip_prefix(b"Exif\x00\x00").unwrap_or(raw);
        let exif = exif::Reader::new()
            .read_raw(body.to_vec())
            .map_err(|e| MetadataError::malformed(format!("unreadable exif: {e}")))?;
        for (tag, surface, path) in exif_surfaces() {
            if let Some(field) = exif.get_field(tag, In::PRIMARY) {
                // Ascii values decode straight to text; the reader's
                // display form quotes them and is kept only for the
                // structured types such as gps rationals.
                let value = match &field.value {
                    exif::Value::Ascii(chunks) => chunks
                        .iter()
                        .map(|chunk| String::from_utf8_lossy(chunk))
                        .collect::<Vec<_>>()
                        .join(" "),
                    _ => field.display_value().to_string(),
                };
                collector.push("exif", surface, path, None, value)?;
            }
        }
        Ok(())
    }

    // --- png ----------------------------------------------------------

    mod png {
        use super::*;

        pub(super) fn collect(
            bytes: &[u8],
            collector: &mut Collector,
            ceilings: &Ceilings,
        ) -> Result<(), MetadataError> {
            let decoder = ::png::Decoder::new(Cursor::new(bytes));
            let reader = decoder
                .read_info()
                .map_err(|e| MetadataError::malformed(format!("unreadable png: {e}")))?;
            let info = reader.info();

            if let Some(exif) = &info.exif_metadata {
                collect_exif(exif, collector)?;
            }

            for chunk in &info.uncompressed_latin1_text {
                collector.push(
                    "png-text",
                    "png-text",
                    &chunk.keyword,
                    None,
                    chunk.text.clone(),
                )?;
            }

            let limit = usize::try_from(ceilings.max_decompressed_bytes).unwrap_or(usize::MAX);
            for chunk in &info.compressed_latin1_text {
                // The compressed-chunk path is exactly why png parsing is
                // jailed: a crafted deflate stream is a decompression
                // bomb. The inflate is bounded by the ceiling and fails
                // closed the moment it is crossed, never silently
                // dropped.
                let mut chunk = chunk.clone();
                decompress_or_fail(chunk.decompress_text_with_limit(limit))?;
                let text = chunk
                    .get_text()
                    .map_err(|e| MetadataError::malformed(format!("bad ztxt text: {e}")))?;
                collector.push("png-ztext", "png-text", &chunk.keyword, None, text)?;
            }

            for chunk in &info.utf8_text {
                let mut owned = chunk.clone();
                decompress_or_fail(owned.decompress_text_with_limit(limit))?;
                let text = owned
                    .get_text()
                    .map_err(|e| MetadataError::malformed(format!("bad itxt text: {e}")))?;
                let language = if chunk.language_tag.is_empty() {
                    None
                } else {
                    Some(chunk.language_tag.clone())
                };
                if chunk.keyword == "XML:com.adobe.xmp" {
                    super::xmp::collect(&text, "png-itxt-xmp", collector, ceilings)?;
                } else {
                    collector.push("png-itxt", "png-text", &chunk.keyword, language, text)?;
                }
            }
            Ok(())
        }

        /// Maps a compressed-text-chunk decompression result to the
        /// fail-closed vocabulary: an inflated size over the ceiling is a
        /// distinct reason from a corrupt stream, and neither is ever a
        /// silent skip.
        fn decompress_or_fail(
            result: Result<(), ::png::DecodingError>,
        ) -> Result<(), MetadataError> {
            match result {
                Ok(()) => Ok(()),
                Err(e) => {
                    let message = e.to_string();
                    if message.to_ascii_lowercase().contains("decompression space") {
                        Err(MetadataError::new(
                            "image-metadata-decompress-exceeded",
                            "a compressed text chunk inflates past the ceiling",
                        ))
                    } else {
                        Err(MetadataError::malformed(format!(
                            "a compressed text chunk cannot be inflated: {message}"
                        )))
                    }
                }
            }
        }
    }

    // --- jpeg ---------------------------------------------------------

    mod jpeg {
        use super::*;
        use img_parts::jpeg::{Jpeg, markers};

        const XMP_NS: &[u8] = b"http://ns.adobe.com/xap/1.0/\x00";

        pub(super) fn collect(
            bytes: &[u8],
            collector: &mut Collector,
            ceilings: &Ceilings,
        ) -> Result<(), MetadataError> {
            let jpeg = Jpeg::from_bytes(img_parts::Bytes::copy_from_slice(bytes))
                .map_err(|e| MetadataError::malformed(format!("unreadable jpeg: {e}")))?;

            let app1: Vec<_> = jpeg.segments_by_marker(markers::APP1).collect();
            let mut xmp_segments: Vec<&[u8]> = Vec::new();
            for segment in &app1 {
                let contents = segment.contents();
                if contents.starts_with(b"Exif\x00\x00") {
                    collect_exif(contents, collector)?;
                } else if contents.starts_with(XMP_NS) {
                    xmp_segments.push(&contents[XMP_NS.len()..]);
                }
            }
            // Extended xmp split across multiple app1 segments is
            // reassembled only when unambiguous. More than one xmp
            // segment is an extended-xmp shape this bounded reader does
            // not model, so it fails closed rather than guess.
            match xmp_segments.len() {
                0 => {}
                1 => {
                    let text = String::from_utf8_lossy(xmp_segments[0]).into_owned();
                    super::xmp::collect(&text, "jpeg-app1-xmp", collector, ceilings)?;
                }
                _ => {
                    return Err(MetadataError::malformed(
                        "ambiguous extended xmp split across app1 segments",
                    ));
                }
            }

            for segment in jpeg.segments_by_marker(markers::APP13) {
                super::iptc::collect(segment.contents(), collector, ceilings)?;
            }
            Ok(())
        }
    }

    // --- webp ---------------------------------------------------------

    mod webp {
        use super::*;
        use img_parts::webp::WebP;

        const CHUNK_EXIF: [u8; 4] = *b"EXIF";
        const CHUNK_XMP: [u8; 4] = *b"XMP ";

        pub(super) fn collect(
            bytes: &[u8],
            collector: &mut Collector,
            ceilings: &Ceilings,
        ) -> Result<(), MetadataError> {
            let webp = WebP::from_bytes(img_parts::Bytes::copy_from_slice(bytes))
                .map_err(|e| MetadataError::malformed(format!("unreadable webp: {e}")))?;
            for chunk in webp.chunks() {
                let Some(data) = chunk.content().data() else {
                    continue;
                };
                if chunk.id() == CHUNK_EXIF {
                    collect_exif(data, collector)?;
                } else if chunk.id() == CHUNK_XMP {
                    let text = String::from_utf8_lossy(data).into_owned();
                    super::xmp::collect(&text, "webp-xmp", collector, ceilings)?;
                }
            }
            Ok(())
        }
    }

    // --- xmp and svg, via quick-xml -----------------------------------

    mod xmp {
        use super::*;
        use quick_xml::Reader;
        use quick_xml::events::Event;

        /// Known xmp human-text properties, keyed by local name, mapping
        /// to a surface family and a property path. Matching by local
        /// name is namespace-agnostic, which is enough for the scored
        /// surface set.
        fn property(local: &[u8]) -> Option<(&'static str, &'static str)> {
            match local {
                b"title" => Some(("xmp-dc-title", "dc:title")),
                b"description" => Some(("xmp-dc-description", "dc:description")),
                b"subject" => Some(("xmp-dc-subject", "dc:subject")),
                b"creator" => Some(("xmp-dc-creator", "dc:creator")),
                b"rights" => Some(("xmp-dc-rights", "dc:rights")),
                b"CreatorTool" => Some(("xmp-xmp-creatortool", "xmp:CreatorTool")),
                b"Headline" => Some(("xmp-photoshop-headline", "photoshop:Headline")),
                _ => None,
            }
        }

        pub(super) fn collect(
            xml: &str,
            carrier: &str,
            collector: &mut Collector,
            ceilings: &Ceilings,
        ) -> Result<(), MetadataError> {
            let mut reader = Reader::from_str(xml);
            let mut depth: u32 = 0;
            let mut events: u64 = 0;
            // The currently open scored property, if any: its surface,
            // path, the text runs collected, and any language seen.
            let mut active: Option<(&'static str, &'static str, Vec<String>, Option<String>)> =
                None;
            loop {
                events += 1;
                if events > ceilings.max_xml_events {
                    return Err(MetadataError::new(
                        "image-metadata-xml-exceeded",
                        "xmp event count over the ceiling",
                    ));
                }
                let event = reader
                    .read_event()
                    .map_err(|e| MetadataError::malformed(format!("malformed xmp: {e}")))?;
                match event {
                    Event::Start(start) => {
                        depth += 1;
                        if depth > ceilings.max_xml_depth {
                            return Err(MetadataError::new(
                                "image-metadata-xml-exceeded",
                                "xmp nesting over the depth ceiling",
                            ));
                        }
                        collect_attribute_properties(&start, carrier, collector)?;
                        if active.is_none()
                            && let Some((surface, path)) = property(start.local_name().as_ref())
                        {
                            active = Some((surface, path, Vec::new(), None));
                        } else if let Some((_, _, _, language)) = active.as_mut() {
                            // A language tag on an alternative or list item
                            // inside the open property.
                            if let Some(found) = attribute_language(&start) {
                                *language = Some(found);
                            }
                        }
                    }
                    Event::Empty(start) => {
                        collect_attribute_properties(&start, carrier, collector)?;
                    }
                    Event::Text(text) => {
                        if let Some((_, _, runs, _)) = active.as_mut() {
                            let decoded = text
                                .decode()
                                .map_err(|e| MetadataError::malformed(format!("bad text: {e}")))?;
                            let unescaped = quick_xml::escape::unescape(&decoded)
                                .map(|c| c.into_owned())
                                .unwrap_or_else(|_| decoded.into_owned());
                            let trimmed = unescaped.trim();
                            if !trimmed.is_empty() {
                                runs.push(trimmed.to_string());
                            }
                        }
                    }
                    Event::End(_) => {
                        depth = depth.saturating_sub(1);
                        if let Some((surface, path, runs, language)) = active.take()
                            && !runs.is_empty()
                        {
                            collector.push(carrier, surface, path, language, runs.join("; "))?;
                        }
                    }
                    Event::Eof => break,
                    _ => {}
                }
            }
            Ok(())
        }

        /// The compact xmp form carries properties as attributes on
        /// `rdf:Description`. Each attribute whose local name is a scored
        /// property becomes a row.
        fn collect_attribute_properties(
            start: &quick_xml::events::BytesStart<'_>,
            carrier: &str,
            collector: &mut Collector,
        ) -> Result<(), MetadataError> {
            for attribute in start.attributes() {
                let attribute = attribute
                    .map_err(|e| MetadataError::malformed(format!("bad attribute: {e}")))?;
                let local = local_name(attribute.key.as_ref());
                if let Some((surface, path)) = property(local) {
                    let raw = String::from_utf8_lossy(&attribute.value);
                    let value = quick_xml::escape::unescape(&raw)
                        .map(|c| c.into_owned())
                        .unwrap_or_else(|_| raw.into_owned());
                    collector.push(carrier, surface, path, None, value)?;
                }
            }
            Ok(())
        }

        /// The `xml:lang` attribute value on an element, if present.
        fn attribute_language(start: &quick_xml::events::BytesStart<'_>) -> Option<String> {
            for attribute in start.attributes().flatten() {
                if attribute.key.as_ref() == b"xml:lang" {
                    return Some(String::from_utf8_lossy(&attribute.value).into_owned());
                }
            }
            None
        }
    }

    mod svg {
        use super::*;
        use quick_xml::Reader;
        use quick_xml::events::Event;

        fn element(local: &[u8]) -> Option<(&'static str, &'static str)> {
            match local {
                b"metadata" => Some(("svg-metadata", "/svg/metadata")),
                b"title" => Some(("svg-title", "/svg/title")),
                b"desc" => Some(("svg-desc", "/svg/desc")),
                _ => None,
            }
        }

        pub(super) fn collect(
            bytes: &[u8],
            collector: &mut Collector,
            ceilings: &Ceilings,
        ) -> Result<(), MetadataError> {
            let xml = std::str::from_utf8(bytes)
                .map_err(|e| MetadataError::malformed(format!("svg is not utf-8: {e}")))?;
            let mut reader = Reader::from_str(xml);
            let mut depth: u32 = 0;
            let mut events: u64 = 0;
            let mut active: Option<(&'static str, &'static str, Vec<String>)> = None;
            loop {
                events += 1;
                if events > ceilings.max_xml_events {
                    return Err(MetadataError::new(
                        "image-metadata-xml-exceeded",
                        "svg event count over the ceiling",
                    ));
                }
                let event = reader
                    .read_event()
                    .map_err(|e| MetadataError::malformed(format!("malformed svg: {e}")))?;
                match event {
                    Event::Start(start) => {
                        depth += 1;
                        if depth > ceilings.max_xml_depth {
                            return Err(MetadataError::new(
                                "image-metadata-xml-exceeded",
                                "svg nesting over the depth ceiling",
                            ));
                        }
                        if active.is_none()
                            && let Some((surface, path)) = element(start.local_name().as_ref())
                        {
                            active = Some((surface, path, Vec::new()));
                        }
                    }
                    Event::Text(text) => {
                        if let Some((_, _, runs)) = active.as_mut() {
                            let decoded = text
                                .decode()
                                .map_err(|e| MetadataError::malformed(format!("bad text: {e}")))?;
                            let unescaped = quick_xml::escape::unescape(&decoded)
                                .map(|c| c.into_owned())
                                .unwrap_or_else(|_| decoded.into_owned());
                            let trimmed = unescaped.trim();
                            if !trimmed.is_empty() {
                                runs.push(trimmed.to_string());
                            }
                        }
                    }
                    Event::End(_) => {
                        depth = depth.saturating_sub(1);
                        if let Some((surface, path, runs)) = active.take()
                            && !runs.is_empty()
                        {
                            collector.push("svg", surface, path, None, runs.join(" "))?;
                        }
                    }
                    Event::Eof => break,
                    _ => {}
                }
            }
            Ok(())
        }
    }

    // --- iptc iim, first-party bounded parser -------------------------

    mod iptc {
        use super::*;

        /// The scored iptc iim record-2 caption and keyword datasets.
        fn dataset(record: u8, dataset: u8) -> Option<(&'static str, &'static str)> {
            match (record, dataset) {
                (2, 5) => Some(("iptc-2-05-objectname", "2:05")),
                (2, 25) => Some(("iptc-2-25-keywords", "2:25")),
                (2, 80) => Some(("iptc-2-80-byline", "2:80")),
                (2, 105) => Some(("iptc-2-105-headline", "2:105")),
                (2, 120) => Some(("iptc-2-120-caption", "2:120")),
                _ => None,
            }
        }

        /// Reads iptc iim out of the 8bim image resource block carried in
        /// a jpeg app13 segment. The resource walk is bounded by checked
        /// arithmetic and never recurses; a malformed block fails closed.
        pub(super) fn collect(
            app13: &[u8],
            collector: &mut Collector,
            ceilings: &Ceilings,
        ) -> Result<(), MetadataError> {
            // The 8bim blocks follow a Photoshop identifier. Start the
            // walk at the first block marker.
            let Some(start) = find(app13, b"8BIM") else {
                return Ok(());
            };
            let irb = &app13[start..];
            let mut pos = 0usize;
            let mut blocks: u64 = 0;
            while pos + 4 <= irb.len() {
                if &irb[pos..pos + 4] != b"8BIM" {
                    break;
                }
                pos += 4;
                blocks += 1;
                if blocks > ceilings.max_boxes {
                    return Err(MetadataError::new(
                        "image-metadata-limit-exceeded",
                        "more image resource blocks than the ceiling",
                    ));
                }
                let id = read_u16(irb, &mut pos)?;
                // Pascal name: one length byte plus the name, padded so
                // the length byte and name together are even.
                let name_len = *irb
                    .get(pos)
                    .ok_or_else(|| MetadataError::malformed("truncated resource name"))?
                    as usize;
                pos += 1;
                pos = pos
                    .checked_add(name_len)
                    .ok_or_else(|| MetadataError::malformed("resource name overruns"))?;
                if (1 + name_len) % 2 == 1 {
                    pos += 1;
                }
                let data_len = read_u32(irb, &mut pos)? as usize;
                let end = pos
                    .checked_add(data_len)
                    .ok_or_else(|| MetadataError::malformed("resource data overruns"))?;
                if end > irb.len() {
                    return Err(MetadataError::malformed("resource data past the block"));
                }
                if id == 0x0404 {
                    parse_iim(&irb[pos..end], collector)?;
                }
                pos = end;
                if data_len % 2 == 1 {
                    pos += 1;
                }
            }
            Ok(())
        }

        /// Walks the flat iim dataset sequence: each dataset is a `0x1C`
        /// marker, a record number, a dataset number, a two-byte length,
        /// and the value. A bad marker or an overrunning length fails the
        /// whole child.
        fn parse_iim(iim: &[u8], collector: &mut Collector) -> Result<(), MetadataError> {
            let mut pos = 0usize;
            while pos < iim.len() {
                if iim[pos] != 0x1C {
                    return Err(MetadataError::malformed("bad iptc dataset marker"));
                }
                if pos + 5 > iim.len() {
                    return Err(MetadataError::malformed("truncated iptc dataset header"));
                }
                let record = iim[pos + 1];
                let number = iim[pos + 2];
                let length = u16::from_be_bytes([iim[pos + 3], iim[pos + 4]]) as usize;
                // The extended-length form is not modeled; it fails closed
                // rather than being misread.
                if length & 0x8000 != 0 {
                    return Err(MetadataError::malformed("extended iptc length not modeled"));
                }
                pos += 5;
                let end = pos
                    .checked_add(length)
                    .ok_or_else(|| MetadataError::malformed("iptc value overruns"))?;
                if end > iim.len() {
                    return Err(MetadataError::malformed("iptc value past the block"));
                }
                if let Some((surface, path)) = dataset(record, number) {
                    let value = String::from_utf8_lossy(&iim[pos..end]).into_owned();
                    collector.push("iptc-iim", surface, path, None, value)?;
                }
                pos = end;
            }
            Ok(())
        }

        fn read_u16(data: &[u8], pos: &mut usize) -> Result<u16, MetadataError> {
            if *pos + 2 > data.len() {
                return Err(MetadataError::malformed("truncated u16"));
            }
            let value = u16::from_be_bytes([data[*pos], data[*pos + 1]]);
            *pos += 2;
            Ok(value)
        }

        fn read_u32(data: &[u8], pos: &mut usize) -> Result<u32, MetadataError> {
            if *pos + 4 > data.len() {
                return Err(MetadataError::malformed("truncated u32"));
            }
            let value =
                u32::from_be_bytes([data[*pos], data[*pos + 1], data[*pos + 2], data[*pos + 3]]);
            *pos += 4;
            Ok(value)
        }
    }

    // --- heic and iso base media file format, first-party walker ------

    mod heic {
        use super::*;

        /// The user-type of an xmp `uuid` box.
        pub(super) const XMP_UUID: [u8; 16] = [
            0xBE, 0x7A, 0xCF, 0xCB, 0x97, 0xA9, 0x42, 0xE8, 0x9C, 0x71, 0x99, 0x94, 0x91, 0xE3,
            0xAF, 0xAC,
        ];

        /// One parsed box: its four-byte type, the range of its payload
        /// in the source, and the position just past the whole box.
        struct BoxHeader {
            kind: [u8; 4],
            payload: (usize, usize),
            next: usize,
        }

        /// Reads one box header at `pos` from `data`, bounding every
        /// length against the source. A size that overruns the parent, a
        /// zero-or-underlength header, or an arithmetic overflow fails
        /// closed.
        fn read_box(data: &[u8], pos: usize, end: usize) -> Result<BoxHeader, MetadataError> {
            if pos + 8 > end {
                return Err(MetadataError::malformed("truncated box header"));
            }
            let size32 =
                u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
            let mut kind = [0u8; 4];
            kind.copy_from_slice(&data[pos + 4..pos + 8]);
            let (header_len, box_size) = if size32 == 1 {
                if pos + 16 > end {
                    return Err(MetadataError::malformed("truncated large box header"));
                }
                let large = u64::from_be_bytes([
                    data[pos + 8],
                    data[pos + 9],
                    data[pos + 10],
                    data[pos + 11],
                    data[pos + 12],
                    data[pos + 13],
                    data[pos + 14],
                    data[pos + 15],
                ]);
                (16usize, usize::try_from(large).unwrap_or(usize::MAX))
            } else if size32 == 0 {
                (8usize, end - pos)
            } else {
                (8usize, size32 as usize)
            };
            if box_size < header_len {
                return Err(MetadataError::malformed("box smaller than its header"));
            }
            let next = pos
                .checked_add(box_size)
                .ok_or_else(|| MetadataError::malformed("box size overflows"))?;
            if next > end {
                return Err(MetadataError::malformed("box overruns its parent"));
            }
            Ok(BoxHeader {
                kind,
                payload: (pos + header_len, next),
                next,
            })
        }

        /// Walks the boxes in `data[start..end]`, calling `visit` for
        /// each, bounded by the box-count ceiling.
        fn walk(
            data: &[u8],
            start: usize,
            end: usize,
            count: &mut u64,
            ceilings: &Ceilings,
            visit: &mut dyn FnMut(&BoxHeader) -> Result<(), MetadataError>,
        ) -> Result<(), MetadataError> {
            let mut pos = start;
            while pos + 8 <= end {
                let header = read_box(data, pos, end)?;
                *count += 1;
                if *count > ceilings.max_boxes {
                    return Err(MetadataError::new(
                        "image-metadata-limit-exceeded",
                        "more iso base media file format boxes than the ceiling",
                    ));
                }
                visit(&header)?;
                pos = header.next;
            }
            Ok(())
        }

        pub(super) fn collect(
            bytes: &[u8],
            collector: &mut Collector,
            ceilings: &Ceilings,
        ) -> Result<(), MetadataError> {
            let mut count: u64 = 0;
            let mut meta_range: Option<(usize, usize)> = None;
            let mut xmp_packets: Vec<(usize, usize)> = Vec::new();
            walk(bytes, 0, bytes.len(), &mut count, ceilings, &mut |header| {
                match &header.kind {
                    b"meta" => meta_range = Some(header.payload),
                    b"uuid" => {
                        let (s, e) = header.payload;
                        if e >= s + 16 && bytes[s..s + 16] == XMP_UUID {
                            xmp_packets.push((s + 16, e));
                        }
                    }
                    _ => {}
                }
                Ok(())
            })?;

            for (s, e) in &xmp_packets {
                let text = String::from_utf8_lossy(&bytes[*s..*e]).into_owned();
                super::xmp::collect(&text, "heic-uuid", collector, ceilings)?;
            }

            if let Some((meta_start, meta_end)) = meta_range {
                collect_meta(bytes, meta_start, meta_end, collector, &mut count, ceilings)?;
            }
            Ok(())
        }

        /// Walks a `meta` box: its item info and item location boxes name
        /// and place the `Exif` and `mime` items, which resolve to an
        /// exif blob and an xmp packet.
        fn collect_meta(
            data: &[u8],
            start: usize,
            end: usize,
            collector: &mut Collector,
            count: &mut u64,
            ceilings: &Ceilings,
        ) -> Result<(), MetadataError> {
            // meta is a full box: skip its version and flags.
            if start + 4 > end {
                return Err(MetadataError::malformed("truncated meta box"));
            }
            let mut iinf: Option<(usize, usize)> = None;
            let mut iloc: Option<(usize, usize)> = None;
            let mut idat: Option<(usize, usize)> = None;
            let mut nested_xmp: Vec<(usize, usize)> = Vec::new();
            walk(data, start + 4, end, count, ceilings, &mut |header| {
                match &header.kind {
                    b"iinf" => iinf = Some(header.payload),
                    b"iloc" => iloc = Some(header.payload),
                    b"idat" => idat = Some(header.payload),
                    b"uuid" => {
                        let (s, e) = header.payload;
                        if e >= s + 16 && data[s..s + 16] == XMP_UUID {
                            nested_xmp.push((s + 16, e));
                        }
                    }
                    _ => {}
                }
                Ok(())
            })?;

            for (s, e) in &nested_xmp {
                let text = String::from_utf8_lossy(&data[*s..*e]).into_owned();
                super::xmp::collect(&text, "heic-uuid", collector, ceilings)?;
            }

            let (Some(iinf), Some(iloc)) = (iinf, iloc) else {
                return Ok(());
            };
            let types = parse_iinf(data, iinf.0, iinf.1, count, ceilings)?;
            let locations = parse_iloc(data, iloc.0, iloc.1)?;
            for (item_id, item_type) in &types {
                let Some(location) = locations.iter().find(|l| l.item_id == *item_id) else {
                    continue;
                };
                let item = resolve_item(data, location, idat)?;
                match item_type.as_slice() {
                    b"Exif" => {
                        // The exif item payload begins with a four-byte
                        // offset to the tiff header.
                        if item.len() >= 4 {
                            let skip =
                                u32::from_be_bytes([item[0], item[1], item[2], item[3]]) as usize;
                            let body_start = 4usize
                                .checked_add(skip)
                                .filter(|s| *s <= item.len())
                                .ok_or_else(|| {
                                    MetadataError::malformed("exif item offset overruns")
                                })?;
                            collect_exif(&item[body_start..], collector)?;
                        }
                    }
                    b"mime" => {
                        let text = String::from_utf8_lossy(&item).into_owned();
                        if text.contains('<') {
                            super::xmp::collect(&text, "heic-mime", collector, ceilings)?;
                        }
                    }
                    _ => {}
                }
            }
            Ok(())
        }

        /// Parses `iinf` to a map of item id to four-byte item type,
        /// reading each `infe` entry far enough to reach its type.
        fn parse_iinf(
            data: &[u8],
            start: usize,
            end: usize,
            count: &mut u64,
            ceilings: &Ceilings,
        ) -> Result<Vec<(u32, Vec<u8>)>, MetadataError> {
            if start + 6 > end {
                return Err(MetadataError::malformed("truncated iinf box"));
            }
            let version = data[start];
            // version(1) flags(3) then the entry count.
            let mut pos = start + 4;
            let _entry_count = if version == 0 {
                let value = u16::from_be_bytes([data[pos], data[pos + 1]]) as u32;
                pos += 2;
                value
            } else {
                let value =
                    u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
                pos += 4;
                value
            };
            let mut types = Vec::new();
            walk(data, pos, end, count, ceilings, &mut |header| {
                if &header.kind == b"infe"
                    && let Some(entry) = parse_infe(data, header.payload.0, header.payload.1)
                {
                    types.push(entry);
                }
                Ok(())
            })?;
            Ok(types)
        }

        /// Parses one `infe` entry to its item id and item type. Only the
        /// version-2 and version-3 shapes are modeled; an older shape
        /// yields nothing rather than a misread.
        fn parse_infe(data: &[u8], start: usize, end: usize) -> Option<(u32, Vec<u8>)> {
            if start + 4 > end {
                return None;
            }
            let version = data[start];
            let mut pos = start + 4;
            let item_id = match version {
                2 => {
                    if pos + 2 > end {
                        return None;
                    }
                    let id = u16::from_be_bytes([data[pos], data[pos + 1]]) as u32;
                    pos += 2;
                    id
                }
                3 => {
                    if pos + 4 > end {
                        return None;
                    }
                    let id = u32::from_be_bytes([
                        data[pos],
                        data[pos + 1],
                        data[pos + 2],
                        data[pos + 3],
                    ]);
                    pos += 4;
                    id
                }
                _ => return None,
            };
            // protection index (2), then the four-byte item type.
            pos += 2;
            if pos + 4 > end {
                return None;
            }
            Some((item_id, data[pos..pos + 4].to_vec()))
        }

        /// One item's storage: its construction method and byte extents.
        struct Location {
            item_id: u32,
            method: u8,
            base_offset: u64,
            extents: Vec<(u64, u64)>,
        }

        /// Parses `iloc` to per-item extents. Supports construction
        /// method 0 (file offset) and method 1 (idat offset), with
        /// checked reads; an addressing shape this bounded reader does
        /// not model fails closed.
        fn parse_iloc(
            data: &[u8],
            start: usize,
            end: usize,
        ) -> Result<Vec<Location>, MetadataError> {
            let mut cursor = Cur::new(data, start, end);
            let version = cursor.u8()?;
            cursor.skip(3)?; // flags
            let sizes = cursor.u8()?;
            let offset_size = (sizes >> 4) & 0xf;
            let length_size = sizes & 0xf;
            let bases = cursor.u8()?;
            let base_offset_size = (bases >> 4) & 0xf;
            let index_size = bases & 0xf;
            let item_count = if version < 2 {
                cursor.u16()? as u32
            } else {
                cursor.u32()?
            };
            let mut locations = Vec::new();
            for _ in 0..item_count {
                let item_id = if version < 2 {
                    cursor.u16()? as u32
                } else {
                    cursor.u32()?
                };
                let method = if version == 1 || version == 2 {
                    let value = cursor.u16()?;
                    (value & 0xf) as u8
                } else {
                    0
                };
                let _data_ref = cursor.u16()?;
                let base_offset = cursor.uint(base_offset_size)?;
                let extent_count = cursor.u16()?;
                let mut extents = Vec::new();
                for _ in 0..extent_count {
                    if (version == 1 || version == 2) && index_size > 0 {
                        cursor.uint(index_size)?;
                    }
                    let extent_offset = cursor.uint(offset_size)?;
                    let extent_length = cursor.uint(length_size)?;
                    extents.push((extent_offset, extent_length));
                }
                locations.push(Location {
                    item_id,
                    method,
                    base_offset,
                    extents,
                });
            }
            Ok(locations)
        }

        /// Resolves one item's bytes from its extents, checking every
        /// offset and length against the source or the idat box before
        /// any read.
        fn resolve_item(
            data: &[u8],
            location: &Location,
            idat: Option<(usize, usize)>,
        ) -> Result<Vec<u8>, MetadataError> {
            let mut out = Vec::new();
            for (offset, length) in &location.extents {
                let base = location.base_offset;
                let start = base
                    .checked_add(*offset)
                    .ok_or_else(|| MetadataError::malformed("item offset overflows"))?;
                let (region_start, region_end) = match location.method {
                    0 => (0usize, data.len()),
                    1 => {
                        idat.ok_or_else(|| MetadataError::malformed("idat item with no idat box"))?
                    }
                    other => {
                        return Err(MetadataError::new(
                            "image-metadata-unsupported",
                            format!("item construction method {other} not modeled"),
                        ));
                    }
                };
                let from = region_start
                    .checked_add(usize::try_from(start).unwrap_or(usize::MAX))
                    .ok_or_else(|| MetadataError::malformed("item start overflows"))?;
                let to = from
                    .checked_add(usize::try_from(*length).unwrap_or(usize::MAX))
                    .ok_or_else(|| MetadataError::malformed("item length overflows"))?;
                if to > region_end || from > region_end {
                    return Err(MetadataError::malformed("item extent past its region"));
                }
                out.extend_from_slice(&data[from..to]);
            }
            Ok(out)
        }

        /// A checked big-endian cursor over a byte range.
        struct Cur<'a> {
            data: &'a [u8],
            pos: usize,
            end: usize,
        }

        impl<'a> Cur<'a> {
            fn new(data: &'a [u8], pos: usize, end: usize) -> Cur<'a> {
                Cur { data, pos, end }
            }

            fn take(&mut self, n: usize) -> Result<&'a [u8], MetadataError> {
                let to = self
                    .pos
                    .checked_add(n)
                    .ok_or_else(|| MetadataError::malformed("iloc read overflows"))?;
                if to > self.end {
                    return Err(MetadataError::malformed("iloc read past the box"));
                }
                let slice = &self.data[self.pos..to];
                self.pos = to;
                Ok(slice)
            }

            fn skip(&mut self, n: usize) -> Result<(), MetadataError> {
                self.take(n).map(|_| ())
            }

            fn u8(&mut self) -> Result<u8, MetadataError> {
                Ok(self.take(1)?[0])
            }

            fn u16(&mut self) -> Result<u16, MetadataError> {
                let b = self.take(2)?;
                Ok(u16::from_be_bytes([b[0], b[1]]))
            }

            fn u32(&mut self) -> Result<u32, MetadataError> {
                let b = self.take(4)?;
                Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
            }

            /// Reads an `n`-byte big-endian unsigned, where `n` is 0, 4,
            /// or 8, matching the iloc field-size nibbles.
            fn uint(&mut self, n: u8) -> Result<u64, MetadataError> {
                match n {
                    0 => Ok(0),
                    4 => Ok(self.u32()? as u64),
                    8 => {
                        let b = self.take(8)?;
                        Ok(u64::from_be_bytes([
                            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
                        ]))
                    }
                    other => Err(MetadataError::new(
                        "image-metadata-unsupported",
                        format!("iloc field size {other} not modeled"),
                    )),
                }
            }
        }
    }

    /// The local part of a possibly-prefixed xml name.
    fn local_name(qname: &[u8]) -> &[u8] {
        match qname.iter().rposition(|&b| b == b':') {
            Some(index) => &qname[index + 1..],
            None => qname,
        }
    }

    /// The first index of `needle` in `haystack`.
    fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        if needle.is_empty() || haystack.len() < needle.len() {
            return None;
        }
        (0..=haystack.len() - needle.len()).find(|&i| &haystack[i..i + needle.len()] == needle)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn ceilings() -> Ceilings {
            Ceilings {
                max_decompressed_bytes: 16 * 1024 * 1024,
                max_xml_depth: 100,
                max_xml_events: 1_000_000,
                max_boxes: 10_000,
                max_rows: 4096,
                max_output_bytes: 16 * 1024 * 1024,
            }
        }

        fn row_for<'a>(rows: &'a [MetadataRow], surface: &str) -> Option<&'a MetadataRow> {
            rows.iter().find(|r| r.surface == surface)
        }

        // --- png text chunks and the inflate path (build check b) -----

        fn png_with<F: FnOnce(&mut ::png::Encoder<'_, &mut Vec<u8>>)>(build: F) -> Vec<u8> {
            let mut out = Vec::new();
            {
                let mut encoder = ::png::Encoder::new(&mut out, 2, 2);
                encoder.set_color(::png::ColorType::Grayscale);
                encoder.set_depth(::png::BitDepth::Eight);
                build(&mut encoder);
                let mut writer = encoder.write_header().unwrap();
                writer.write_image_data(&[0, 0, 0, 0]).unwrap();
            }
            out
        }

        #[test]
        fn png_itxt_xmp_yields_the_dc_description_surface() {
            let xmp = r#"<?xpacket?><rdf:RDF xmlns:rdf="rdf" xmlns:dc="dc">
                <rdf:Description><dc:description><rdf:Alt><rdf:li xml:lang="x-default">metadata sentinel</rdf:li></rdf:Alt></dc:description></rdf:Description>
                </rdf:RDF>"#;
            let bytes = png_with(|e| {
                e.add_itxt_chunk("XML:com.adobe.xmp".to_string(), xmp.to_string())
                    .unwrap();
            });
            let mut collector = Collector::new(&ceilings());
            png::collect(&bytes, &mut collector, &ceilings()).unwrap();
            let rows = collector.into_rows();
            let row = row_for(&rows, "xmp-dc-description").expect("dc:description row");
            assert_eq!(row.carrier, "png-itxt-xmp");
            assert_eq!(row.value, "metadata sentinel");
        }

        #[test]
        fn png_ztxt_is_decompressed_and_extracted() {
            // The compressed chunk reaches the inflate path and its text
            // is recovered, proving the minimal png profile decompresses
            // zTXt rather than silently dropping it.
            let bytes = png_with(|e| {
                e.add_ztxt_chunk("Comment".to_string(), "inflated comment body".to_string())
                    .unwrap();
            });
            let mut collector = Collector::new(&ceilings());
            png::collect(&bytes, &mut collector, &ceilings()).unwrap();
            let rows = collector.into_rows();
            let row = rows
                .iter()
                .find(|r| r.carrier == "png-ztext")
                .expect("ztxt row");
            assert_eq!(row.value, "inflated comment body");
        }

        #[test]
        fn png_ztxt_bomb_fails_closed_not_silently_dropped() {
            // A highly compressible payload that inflates far past a low
            // ceiling. The inflate is bounded and fails closed, never
            // dropped.
            let big = "A".repeat(4 * 1024 * 1024);
            let bytes = png_with(|e| {
                e.add_ztxt_chunk("Comment".to_string(), big).unwrap();
            });
            let mut tight = ceilings();
            tight.max_decompressed_bytes = 4096;
            let mut collector = Collector::new(&tight);
            let error = png::collect(&bytes, &mut collector, &tight).unwrap_err();
            assert_eq!(error.code, "image-metadata-decompress-exceeded");
        }

        #[test]
        fn png_text_chunk_yields_a_row() {
            let bytes = png_with(|e| {
                e.add_text_chunk("Author".to_string(), "a name".to_string())
                    .unwrap();
            });
            let mut collector = Collector::new(&ceilings());
            png::collect(&bytes, &mut collector, &ceilings()).unwrap();
            let rows = collector.into_rows();
            let row = rows.iter().find(|r| r.path == "Author").expect("text row");
            assert_eq!(row.carrier, "png-text");
            assert_eq!(row.value, "a name");
        }

        // --- exif -----------------------------------------------------

        fn exif_tiff(fields: Vec<exif::Field>) -> Vec<u8> {
            use exif::experimental::Writer;
            let mut writer = Writer::new();
            for field in &fields {
                writer.push_field(field);
            }
            let mut cursor = std::io::Cursor::new(Vec::new());
            writer.write(&mut cursor, false).unwrap();
            cursor.into_inner()
        }

        #[test]
        fn exif_image_description_and_gps_are_scored() {
            use exif::{Field, In, Tag, Value};
            let tiff = exif_tiff(vec![
                Field {
                    tag: Tag::ImageDescription,
                    ifd_num: In::PRIMARY,
                    value: Value::Ascii(vec![b"a photo caption".to_vec()]),
                },
                Field {
                    tag: Tag::GPSLatitudeRef,
                    ifd_num: In::PRIMARY,
                    value: Value::Ascii(vec![b"N".to_vec()]),
                },
                Field {
                    tag: Tag::GPSLatitude,
                    ifd_num: In::PRIMARY,
                    value: Value::Rational(vec![
                        exif::Rational { num: 51, denom: 1 },
                        exif::Rational { num: 30, denom: 1 },
                        exif::Rational { num: 0, denom: 1 },
                    ]),
                },
            ]);
            let mut collector = Collector::new(&ceilings());
            collect_exif(&tiff, &mut collector).unwrap();
            let rows = collector.into_rows();
            let desc = row_for(&rows, "exif-imagedescription").expect("imagedescription row");
            assert_eq!(desc.carrier, "exif");
            assert_eq!(desc.path, "270");
            assert_eq!(desc.value, "a photo caption");
            assert!(row_for(&rows, "exif-gps-latitude").is_some(), "gps scored");
        }

        #[test]
        fn a_truncated_exif_ifd_fails_closed() {
            let mut tiff = exif_tiff(vec![exif::Field {
                tag: exif::Tag::ImageDescription,
                ifd_num: exif::In::PRIMARY,
                value: exif::Value::Ascii(vec![b"caption".to_vec()]),
            }]);
            tiff.truncate(tiff.len() / 2);
            let mut collector = Collector::new(&ceilings());
            let error = collect_exif(&tiff, &mut collector).unwrap_err();
            assert_eq!(error.code, "image-metadata-malformed");
        }

        // --- xmp and svg ----------------------------------------------

        #[test]
        fn xmp_attribute_form_is_scored() {
            let xmp = r#"<rdf:RDF xmlns:rdf="rdf" xmlns:dc="dc" xmlns:xmp="xmp">
                <rdf:Description dc:title="the title" xmp:CreatorTool="the tool"/></rdf:RDF>"#;
            let mut collector = Collector::new(&ceilings());
            xmp::collect(xmp, "jpeg-app1-xmp", &mut collector, &ceilings()).unwrap();
            let rows = collector.into_rows();
            assert_eq!(
                row_for(&rows, "xmp-dc-title").map(|r| r.value.as_str()),
                Some("the title")
            );
            assert_eq!(
                row_for(&rows, "xmp-xmp-creatortool").map(|r| r.value.as_str()),
                Some("the tool")
            );
        }

        #[test]
        fn xmp_depth_flood_fails_closed() {
            let mut xml = String::from("<rdf:RDF xmlns:rdf=\"rdf\">");
            for _ in 0..50 {
                xml.push_str("<n>");
            }
            let mut tight = ceilings();
            tight.max_xml_depth = 8;
            let mut collector = Collector::new(&tight);
            let error = xmp::collect(&xml, "png-itxt-xmp", &mut collector, &tight).unwrap_err();
            assert_eq!(error.code, "image-metadata-xml-exceeded");
        }

        #[test]
        fn svg_metadata_title_and_desc_are_scored() {
            let svg = br#"<svg xmlns="svg"><title>the drawing</title><desc>a description</desc>
                <metadata>the metadata block</metadata></svg>"#;
            let mut collector = Collector::new(&ceilings());
            svg::collect(svg, &mut collector, &ceilings()).unwrap();
            let rows = collector.into_rows();
            assert_eq!(
                row_for(&rows, "svg-metadata").map(|r| r.path.as_str()),
                Some("/svg/metadata")
            );
            assert!(row_for(&rows, "svg-title").is_some());
            assert!(row_for(&rows, "svg-desc").is_some());
        }

        // --- iptc iim -------------------------------------------------

        fn app13_with_caption(caption: &str) -> Vec<u8> {
            // One iim dataset: 0x1C, record 2, dataset 120, length, value.
            let mut iim = Vec::new();
            iim.push(0x1C);
            iim.push(2);
            iim.push(120);
            iim.extend_from_slice(&(caption.len() as u16).to_be_bytes());
            iim.extend_from_slice(caption.as_bytes());
            // One 8BIM resource block, id 0x0404, empty pascal name.
            let mut irb = Vec::new();
            irb.extend_from_slice(b"8BIM");
            irb.extend_from_slice(&0x0404u16.to_be_bytes());
            irb.push(0); // pascal name length 0
            irb.push(0); // pad to even (name field is one byte)
            irb.extend_from_slice(&(iim.len() as u32).to_be_bytes());
            irb.extend_from_slice(&iim);
            if iim.len() % 2 == 1 {
                irb.push(0);
            }
            let mut app13 = Vec::new();
            app13.extend_from_slice(b"Photoshop 3.0\x00");
            app13.extend_from_slice(&irb);
            app13
        }

        #[test]
        fn iptc_caption_dataset_is_scored() {
            let app13 = app13_with_caption("the iptc caption");
            let mut collector = Collector::new(&ceilings());
            iptc::collect(&app13, &mut collector, &ceilings()).unwrap();
            let rows = collector.into_rows();
            let row = row_for(&rows, "iptc-2-120-caption").expect("caption row");
            assert_eq!(row.carrier, "iptc-iim");
            assert_eq!(row.path, "2:120");
            assert_eq!(row.value, "the iptc caption");
        }

        #[test]
        fn an_overrunning_iptc_length_fails_closed() {
            let mut app13 = app13_with_caption("cap");
            // Corrupt the dataset length to overrun the block.
            let marker = find(&app13, &[0x1C, 2, 120]).unwrap();
            app13[marker + 3] = 0xFF;
            app13[marker + 4] = 0xFF;
            let mut collector = Collector::new(&ceilings());
            let error = iptc::collect(&app13, &mut collector, &ceilings()).unwrap_err();
            assert_eq!(error.code, "image-metadata-malformed");
        }

        // --- heic / iso base media file format ------------------------

        fn push_box(out: &mut Vec<u8>, kind: &[u8; 4], body: &[u8]) {
            let size = (8 + body.len()) as u32;
            out.extend_from_slice(&size.to_be_bytes());
            out.extend_from_slice(kind);
            out.extend_from_slice(body);
        }

        #[test]
        fn heic_uuid_xmp_box_is_scored() {
            let xmp = r#"<rdf:RDF xmlns:rdf="rdf" xmlns:dc="dc"><rdf:Description dc:description="heic sentinel"/></rdf:RDF>"#;
            let mut uuid_payload = heic::XMP_UUID.to_vec();
            uuid_payload.extend_from_slice(xmp.as_bytes());
            let mut bytes = Vec::new();
            push_box(&mut bytes, b"ftyp", b"heic\x00\x00\x00\x00heic");
            push_box(&mut bytes, b"uuid", &uuid_payload);
            let mut collector = Collector::new(&ceilings());
            heic::collect(&bytes, &mut collector, &ceilings()).unwrap();
            let rows = collector.into_rows();
            let row = row_for(&rows, "xmp-dc-description").expect("heic uuid xmp row");
            assert_eq!(row.carrier, "heic-uuid");
            assert_eq!(row.value, "heic sentinel");
        }

        #[test]
        fn heic_exif_item_via_meta_is_scored() {
            use exif::{Field, In, Tag, Value};
            let tiff = exif_tiff(vec![Field {
                tag: Tag::ImageDescription,
                ifd_num: In::PRIMARY,
                value: Value::Ascii(vec![b"heic exif caption".to_vec()]),
            }]);
            // The exif item payload begins with a four-byte tiff offset.
            let mut exif_item = vec![0u8, 0, 0, 0];
            exif_item.extend_from_slice(&tiff);

            // infe: version 2, item_id 1, protection 0, type "Exif".
            let mut infe = vec![2u8, 0, 0, 0];
            infe.extend_from_slice(&1u16.to_be_bytes());
            infe.extend_from_slice(&0u16.to_be_bytes());
            infe.extend_from_slice(b"Exif");
            let mut iinf = vec![0u8, 0, 0, 0];
            iinf.extend_from_slice(&1u16.to_be_bytes());
            let mut iinf_box = Vec::new();
            push_box(&mut iinf_box, b"infe", &infe);
            iinf.extend_from_slice(&iinf_box);

            // iloc: version 1, offset/length size 4, base/index 0, one
            // item, construction method 1 (idat), one extent at offset 0.
            let mut iloc = vec![1u8, 0, 0, 0, 0x44, 0x00];
            iloc.extend_from_slice(&1u16.to_be_bytes()); // item_count
            iloc.extend_from_slice(&1u16.to_be_bytes()); // item_id
            iloc.extend_from_slice(&1u16.to_be_bytes()); // construction method 1
            iloc.extend_from_slice(&0u16.to_be_bytes()); // data ref
            iloc.extend_from_slice(&1u16.to_be_bytes()); // extent count
            iloc.extend_from_slice(&0u32.to_be_bytes()); // extent offset
            iloc.extend_from_slice(&(exif_item.len() as u32).to_be_bytes()); // extent length

            let mut meta_body = vec![0u8, 0, 0, 0]; // fullbox header
            push_box(&mut meta_body, b"iinf", &iinf);
            push_box(&mut meta_body, b"iloc", &iloc);
            push_box(&mut meta_body, b"idat", &exif_item);

            let mut bytes = Vec::new();
            push_box(&mut bytes, b"ftyp", b"heic\x00\x00\x00\x00heic");
            push_box(&mut bytes, b"meta", &meta_body);

            let mut collector = Collector::new(&ceilings());
            heic::collect(&bytes, &mut collector, &ceilings()).unwrap();
            let rows = collector.into_rows();
            let row = row_for(&rows, "exif-imagedescription").expect("heic exif row");
            assert_eq!(row.value, "heic exif caption");
        }

        #[test]
        fn a_heic_box_that_overruns_its_parent_fails_closed() {
            let mut bytes = Vec::new();
            push_box(&mut bytes, b"ftyp", b"heic\x00\x00\x00\x00heic");
            // A box declaring a size past the buffer.
            bytes.extend_from_slice(&0xFFFFu32.to_be_bytes());
            bytes.extend_from_slice(b"meta");
            bytes.extend_from_slice(&[0u8; 8]);
            let mut collector = Collector::new(&ceilings());
            let error = heic::collect(&bytes, &mut collector, &ceilings()).unwrap_err();
            assert_eq!(error.code, "image-metadata-malformed");
        }
    }
}
