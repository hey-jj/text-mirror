//! The PDF text-layer conversion, shared by the sandbox worker.
//!
//! This is the anydoc PDF path that once lived in the in-process
//! document adapter. It now runs inside the subprocess worker, so
//! hostile PDF bytes crash a jailed child and never the pipeline. The
//! outcome shape, the `pdf_partial_text` warning, and the failure
//! reasons such as `pdf_no_text_layer` are unchanged, so a converted
//! PDF's manifest record differs only in its converter id.

use crate::segments::Segment;

use super::anydoc_log::capture_anydoc;
use super::{ConvertError, markdown_to_plain, normalize_text};

/// A successful PDF conversion: text, warnings, and structure spans.
pub struct PdfConversion {
    /// The converted text, UTF-8, NFC, LF line endings.
    pub text: String,
    /// Non-fatal notes, such as `pdf_partial_text`.
    pub warnings: Vec<String>,
    /// Structure spans over the text.
    pub segments: Vec<Segment>,
}

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

/// Converts PDF bytes to text through the anydoc text-layer path.
pub fn convert_pdf(source: &[u8]) -> Result<PdfConversion, ConvertError> {
    let (converted, captured) =
        capture_anydoc(|| anydoc::to_markdown_bytes(source, anydoc::Format::Pdf));
    let markdown = converted.map_err(|error| ConvertError {
        code: error_code(&error),
        message: error.to_string(),
    })?;
    let text = normalize_text(&markdown_to_plain(&markdown));
    if !source.is_empty() && text.is_empty() {
        return Err(ConvertError {
            code: "empty_output",
            message: format!(
                "source is {} bytes but conversion produced no text",
                source.len()
            ),
        });
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
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
