//! The PDF text-layer conversion, shared by the sandbox worker.
//!
//! This is the anydoc PDF path that once lived in the in-process
//! document adapter. It now runs inside the subprocess worker, so
//! hostile PDF bytes crash a jailed child and never the pipeline. The
//! outcome shape, the `pdf_partial_text` warning, and the failure
//! reasons such as `pdf_no_text_layer` are unchanged, so a converted
//! PDF's manifest record differs only in its converter id.
//!
//! The anydoc markdown path classifies a page before it extracts, and
//! declines a page whose live text is small next to its vector artwork
//! as image-based: it returns `Unsupported` and drops the page. Some of
//! those pages carry a real, if small, text layer. When the markdown
//! path declines a PDF, this module attempts a direct text extraction
//! from the same pinned parser. Recovered text is emitted as a
//! content-bearing conversion under a converter id that names the
//! recovery path, always beside the stable `pdf_partial_text` warning
//! so the file is still routed to OCR review. Only when the direct
//! extraction also finds nothing does the genuine `pdf_no_text_layer`
//! failure stand.

use crate::segments::Segment;

use super::anydoc_log::capture_anydoc;
use super::{ConvertError, markdown_to_plain, normalize_text};

/// A successful PDF conversion: text, warnings, and structure spans.
#[derive(Debug)]
pub struct PdfConversion {
    /// The converted text, UTF-8, NFC, LF line endings.
    pub text: String,
    /// Non-fatal notes, such as `pdf_partial_text`.
    pub warnings: Vec<String>,
    /// Structure spans over the text.
    pub segments: Vec<Segment>,
    /// Whether the text came from the direct recovery extractor rather
    /// than the anydoc markdown path. The parent adapter maps this to
    /// the manifest converter id, so a recovered document is never
    /// recorded under the markdown path's id.
    pub recovered: bool,
}

/// The stable warning a recovered page carries after the markdown path
/// declined it. The `pdf_partial_text:` prefix is the same prefix the
/// anydoc pages-need-OCR warning uses, so downstream tooling routes
/// both to OCR with one rule. Only the message after the prefix names
/// the vector-artwork case.
const RECOVERED_TEXT_WARNING: &str = "pdf_partial_text: text recovered from a page reported as \
image-based; route to OCR to confirm completeness";

/// Maps an anydoc PDF error to the stable reason code. A scanned or
/// image-only PDF is `pdf_no_text_layer`, so it converts once an OCR
/// converter lands.
fn error_code(error: &anydoc::ConvertError) -> &'static str {
    if matches!(error, anydoc::ConvertError::Unsupported(_)) {
        return "pdf_no_text_layer";
    }
    match error.code() {
        "unsupported" => "unsupported",
        "malformed" => "malformed",
        "encrypted" => "encrypted",
        "resourceLimit" => "resourceLimit",
        "missingPart" => "missingPart",
        _ => "io",
    }
}

/// Promotes a captured anydoc message to a manifest warning. The
/// partial-text case keeps its stable prefix so downstream tooling can
/// route those files to OCR.
fn promote_warning(message: &str) -> String {
    if message.contains("pages need OCR") {
        let head = message.split(" and ").next().unwrap_or(message);
        return format!("pdf_partial_text: {head}");
    }
    format!("anydoc_recovery: {message}")
}

/// Invisible format characters: code points that render nothing yet are
/// neither whitespace nor control characters, so a bare emptiness check
/// would let them through. The set is the soft hyphen, the zero-width
/// and bidi marks (`U+200B`–`U+200F`), the bidi overrides and embeddings
/// (`U+202A`–`U+202E`), the word joiner and invisible-operator block
/// (`U+2060`–`U+2064`), and the byte-order mark (`U+FEFF`). A page whose
/// only recovered code points are these carries no readable text. The
/// set is a documented minimum and is not narrowed; whitespace and
/// control characters are handled separately by the meaningful-text
/// check, so the two together cover the empty-render cases.
fn is_invisible_format(c: char) -> bool {
    matches!(
        c as u32,
        0x00AD | 0x200B..=0x200F | 0x202A..=0x202E | 0x2060..=0x2064 | 0xFEFF
    )
}

/// Whether a character is meaningful recovered content: something a
/// reader would see on the page. Whitespace, control characters, and
/// invisible format characters are not.
fn is_meaningful(c: char) -> bool {
    !c.is_whitespace() && !c.is_control() && !is_invisible_format(c)
}

/// Attempts a direct text extraction from the pinned PDF parser,
/// bypassing the markdown classifier. Returns the normalized text when a
/// real text layer is present, or `None` when the page yields nothing a
/// reader would see. Recovery stands only if at least one meaningful
/// character remains: a page whose only recovered code points are
/// whitespace, control characters, or invisible format characters (for
/// example a font whose glyphs map to `U+0007` or a page of `U+200B`)
/// has nothing to recover and still fails closed. The check gates on the
/// presence of meaningful text; it does not scrub embedded control
/// characters out of otherwise-real text, which stays a cross-converter
/// question. This is the recovery path: it runs only after the markdown
/// path has declined the PDF as image-based.
fn recover_text_layer(source: &[u8]) -> Option<String> {
    let raw = pdf_inspector::extractor::extract_text_mem(source).ok()?;
    let text = normalize_text(&raw);
    if text.chars().any(is_meaningful) {
        Some(text)
    } else {
        None
    }
}

/// Converts PDF bytes to text through the anydoc text-layer path, with
/// a direct-extraction recovery when the markdown path declines a page
/// as image-based.
pub fn convert_pdf(source: &[u8]) -> Result<PdfConversion, ConvertError> {
    let (converted, captured) =
        capture_anydoc(|| anydoc::to_markdown_bytes(source, anydoc::Format::Pdf));
    match converted {
        Ok(markdown) => {
            let text = normalize_text(&markdown_to_plain(&markdown));
            if !source.is_empty() && text.is_empty() {
                return Err(empty_output(source.len()));
            }
            let warnings = captured
                .iter()
                .map(|message| promote_warning(message))
                .collect();
            let segments = vec![Segment::span(0, text.len(), "document")];
            Ok(PdfConversion {
                text,
                warnings,
                segments,
                recovered: false,
            })
        }
        // The markdown path declined this PDF as image-based or
        // low-text. Attempt a direct extraction: if a real text layer
        // is present, the classifier and the extractor disagree, and
        // that disagreement is the sole signal to recover rather than
        // fail closed. No ratio or threshold gates the recovery.
        Err(error) if matches!(error, anydoc::ConvertError::Unsupported(_)) => {
            match recover_text_layer(source) {
                Some(text) => {
                    let mut warnings: Vec<String> = captured
                        .iter()
                        .map(|message| promote_warning(message))
                        .collect();
                    // Bias: the markdown path disputed this page, so it
                    // is always routed to OCR review, never returned as
                    // bare success. The captured log usually already
                    // carries the pages-need-OCR warning; add the
                    // recovery warning when it does not.
                    if !warnings
                        .iter()
                        .any(|warning| warning.starts_with("pdf_partial_text:"))
                    {
                        warnings.push(RECOVERED_TEXT_WARNING.to_string());
                    }
                    let segments = vec![Segment::span(0, text.len(), "document")];
                    Ok(PdfConversion {
                        text,
                        warnings,
                        segments,
                        recovered: true,
                    })
                }
                None => Err(ConvertError {
                    code: "pdf_no_text_layer",
                    message: error.to_string(),
                }),
            }
        }
        Err(error) => Err(ConvertError {
            code: error_code(&error),
            message: error.to_string(),
        }),
    }
}

fn empty_output(source_len: usize) -> ConvertError {
    ConvertError {
        code: "empty_output",
        message: format!("source is {source_len} bytes but conversion produced no text"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Synthetic PDF fixture generator ---------------------------------
    //
    // These build minimal one-page PDFs in bytes, with no copied files.
    // A fixture pairs a run of path-drawing operators (vector artwork)
    // with an optional text block, so a page can carry heavy vector
    // paths next to a small live-text layer — the shape the classifier
    // reports as image-based while a real text layer is still present.

    /// Assembles a single-page PDF around one content stream, with a
    /// Helvetica Type1 font so any text layer is extractable.
    fn build_pdf(content: &str) -> Vec<u8> {
        let objects = [
            "<< /Type /Catalog /Pages 2 0 R >>".to_string(),
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_string(),
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] \
             /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>"
                .to_string(),
            format!(
                "<< /Length {} >>\nstream\n{content}\nendstream",
                content.len()
            ),
            "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica \
             /Encoding /WinAnsiEncoding >>"
                .to_string(),
        ];
        let mut pdf = String::from("%PDF-1.6\n");
        let mut offsets = Vec::new();
        for (index, body) in objects.iter().enumerate() {
            offsets.push(pdf.len());
            pdf.push_str(&format!("{} 0 obj\n{body}\nendobj\n", index + 1));
        }
        let xref_at = pdf.len();
        pdf.push_str(&format!("xref\n0 {}\n", objects.len() + 1));
        pdf.push_str("0000000000 65535 f \n");
        for offset in &offsets {
            pdf.push_str(&format!("{offset:010} 00000 n \n"));
        }
        pdf.push_str(&format!(
            "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref_at}\n%%EOF\n",
            objects.len() + 1
        ));
        pdf.into_bytes()
    }

    /// A run of `count` path operators: each iteration draws and strokes
    /// one line (`m l S`), the high-volume operators of vector artwork.
    fn vector_paths(count: usize) -> String {
        let mut stream = String::new();
        for step in 0..count {
            let n = (step % 500) + 50;
            stream.push_str(&format!("{n} {n} m {n} {n} l S\n"));
        }
        stream
    }

    /// A text block: one `Tj` per line under the F1 font.
    fn text_block(lines: &[&str]) -> String {
        let mut stream = String::from("BT /F1 12 Tf 72 700 Td\n");
        for (index, line) in lines.iter().enumerate() {
            if index > 0 {
                stream.push_str("0 -14 Td\n");
            }
            stream.push_str(&format!("({line}) Tj\n"));
        }
        stream.push_str("ET\n");
        stream
    }

    /// A single-page PDF whose one glyph decodes, through a Type0
    /// Identity-H font's `ToUnicode` CMap, to `dst` (a four-hex-digit
    /// UTF-16 code point). Paired with heavy vector paths so the page is
    /// reported image-based. The extractor returns exactly that code
    /// point, so it stands in for a page whose only recovered character
    /// is invisible: the markdown path declines the page, and the direct
    /// extraction recovers a code point with no readable content.
    fn image_based_with_glyph_decoding_to(dst: &str) -> Vec<u8> {
        let cmap = format!(
            "/CIDInit /ProcSet findresource begin\n12 dict begin\nbegincmap\n\
             /CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) /Supplement 0 >> def\n\
             /CMapName /Adobe-Identity-UCS def\n/CMapType 2 def\n\
             1 begincodespacerange\n<0000> <FFFF>\nendcodespacerange\n\
             1 beginbfchar\n<0001> <{dst}>\nendbfchar\nendcmap\n\
             CMapName currentdict /CMap defineresource pop\nend\nend"
        );
        let content = format!("{}BT /F1 12 Tf 72 700 Td <0001> Tj ET\n", vector_paths(600));
        let objects = [
            "<< /Type /Catalog /Pages 2 0 R >>".to_string(),
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_string(),
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] \
             /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>"
                .to_string(),
            format!(
                "<< /Length {} >>\nstream\n{content}\nendstream",
                content.len()
            ),
            "<< /Type /Font /Subtype /Type0 /BaseFont /ABCDEE+Test \
             /Encoding /Identity-H /DescendantFonts [7 0 R] /ToUnicode 6 0 R >>"
                .to_string(),
            format!("<< /Length {} >>\nstream\n{cmap}\nendstream", cmap.len()),
            "<< /Type /Font /Subtype /CIDFontType2 /BaseFont /ABCDEE+Test \
             /CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >> \
             /FontDescriptor 8 0 R /CIDToGIDMap /Identity /DW 1000 >>"
                .to_string(),
            "<< /Type /FontDescriptor /FontName /ABCDEE+Test /Flags 4 \
             /FontBBox [0 0 1000 1000] /ItalicAngle 0 /Ascent 1000 /Descent 0 \
             /CapHeight 1000 /StemV 80 >>"
                .to_string(),
        ];
        let mut pdf = String::from("%PDF-1.6\n");
        let mut offsets = Vec::new();
        for (index, body) in objects.iter().enumerate() {
            offsets.push(pdf.len());
            pdf.push_str(&format!("{} 0 obj\n{body}\nendobj\n", index + 1));
        }
        let xref_at = pdf.len();
        pdf.push_str(&format!("xref\n0 {}\n", objects.len() + 1));
        pdf.push_str("0000000000 65535 f \n");
        for offset in &offsets {
            pdf.push_str(&format!("{offset:010} 00000 n \n"));
        }
        pdf.push_str(&format!(
            "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref_at}\n%%EOF\n",
            objects.len() + 1
        ));
        pdf.into_bytes()
    }

    /// (a) Heavy vector paths beside a small live-text layer, no images.
    /// The classifier reports this image-based and the markdown path
    /// declines it, but the text layer is real.
    fn image_based_with_text_layer() -> Vec<u8> {
        build_pdf(&format!(
            "{}{}",
            vector_paths(600),
            text_block(&["Small text layer only"])
        ))
    }

    /// (b) A text-rich page with some vector paths. The classifier
    /// reports this text-based and the markdown path extracts it.
    fn text_rich_with_vector_paths() -> Vec<u8> {
        let lines = [
            "Quarterly report of the working group on data handling",
            "The committee reviewed the summary and approved the plan",
            "Revenue increased while costs held steady this period",
            "Next review is scheduled for the following fiscal quarter",
            "Signatures and approvals are recorded on the final page",
        ];
        build_pdf(&format!("{}{}", vector_paths(80), text_block(&lines)))
    }

    /// (c) Vector paths with no text operators at all: a genuine no-text
    /// page that must still fail closed.
    fn vector_only_no_text() -> Vec<u8> {
        build_pdf(&vector_paths(300))
    }

    #[test]
    fn partial_pdf_warnings_keep_their_prefix() {
        assert_eq!(
            promote_warning("1 of 2 pages need OCR and were not extracted"),
            "pdf_partial_text: 1 of 2 pages need OCR"
        );
        assert_eq!(
            promote_warning("recovered a broken xref"),
            "anydoc_recovery: recovered a broken xref"
        );
    }

    #[test]
    fn image_based_page_with_text_layer_recovers_with_the_ocr_warning() {
        let conversion = convert_pdf(&image_based_with_text_layer())
            .expect("a real text layer behind vector artwork is recovered, not failed closed");
        assert!(conversion.recovered, "the recovery path produced the text");
        assert!(
            conversion.text.contains("Small text layer only"),
            "recovered text: {:?}",
            conversion.text
        );
        assert!(
            conversion
                .warnings
                .iter()
                .any(|warning| warning.starts_with("pdf_partial_text:")),
            "a disputed page is always routed to OCR: {:?}",
            conversion.warnings
        );
    }

    #[test]
    fn text_rich_page_converts_without_warning_spam() {
        let conversion = convert_pdf(&text_rich_with_vector_paths())
            .expect("a text-based page converts through the markdown path");
        assert!(
            !conversion.recovered,
            "a text-based page does not use the recovery path"
        );
        assert!(
            conversion.text.contains("Quarterly report"),
            "text: {:?}",
            conversion.text
        );
        assert!(
            conversion.warnings.is_empty(),
            "a text-rich page carries no OCR-routing warning: {:?}",
            conversion.warnings
        );
    }

    #[test]
    fn vector_only_page_without_text_fails_closed() {
        let error = convert_pdf(&vector_only_no_text())
            .expect_err("a page with no text layer has nothing to recover");
        assert_eq!(
            error.code, "pdf_no_text_layer",
            "the genuine no-text class still fails closed: {error:?}"
        );
    }

    #[test]
    fn a_page_whose_glyphs_decode_to_control_only_fails_closed() {
        // The extractor recovers one code point, U+0007 (BELL), a
        // control character with no readable content. The meaningful-text
        // floor rejects it, so the page fails closed rather than
        // converting to a control character masquerading as recovered
        // text.
        let error = convert_pdf(&image_based_with_glyph_decoding_to("0007"))
            .expect_err("a page of control characters has nothing meaningful to recover");
        assert_eq!(error.code, "pdf_no_text_layer", "error: {error:?}");
    }

    #[test]
    fn a_page_of_zero_width_spaces_only_fails_closed() {
        // The extractor recovers one code point, U+200B (zero-width
        // space), an invisible format character. The meaningful-text
        // floor rejects it, so the page fails closed.
        let error = convert_pdf(&image_based_with_glyph_decoding_to("200B"))
            .expect_err("a page of zero-width spaces has nothing meaningful to recover");
        assert_eq!(error.code, "pdf_no_text_layer", "error: {error:?}");
    }

    #[test]
    fn outcomes_are_byte_reproducible() {
        // The fixtures build identically and each class converts to the
        // same bytes and warnings on a second pass.
        assert_eq!(
            image_based_with_text_layer(),
            image_based_with_text_layer(),
            "the fixture generator is deterministic"
        );
        let first = convert_pdf(&image_based_with_text_layer()).unwrap();
        let second = convert_pdf(&image_based_with_text_layer()).unwrap();
        assert_eq!(first.text, second.text);
        assert_eq!(first.warnings, second.warnings);
        assert_eq!(first.recovered, second.recovered);
        assert_eq!(first.segments.len(), second.segments.len());
    }
}
