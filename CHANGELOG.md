# Changelog

All notable changes to this project are documented here. The format
follows Keep a Changelog, and the project adheres to Semantic
Versioning.

## [0.5.0] - 2026-08-22

### Changed

- The public `PdfConversion` and `PdfOk` structs gained a `recovered`
  field that records whether a document's text came from the direct
  extraction path. Because both structs are exhaustive, external code
  that constructs or destructures them by listing every field must
  account for the new field. This is a breaking change for those
  callers, which is why this release moves to 0.5.0. The on-disk
  `manifest@1` and `bundle@1` serialization stays the same: the field is
  omitted from the wire when false, so a 0.4.0 reader sees identical
  bytes for any non-recovered outcome.

### Fixed

- A PDF with a real but small text layer set against heavy vector
  artwork was misclassified as image-based and failed closed with
  `pdf_no_text_layer`, dropping text that was there to be read. The PDF
  converter now attempts a direct text extraction whenever the primary
  path declines a page as image-based. When a readable text layer is
  present, it is extracted and the document converts, carrying the
  stable `pdf_partial_text` warning that routes the file to OCR review.
  A page whose only recoverable characters are blank, control, or
  invisible still fails closed with `pdf_no_text_layer`. Recovered text
  is recorded under a converter id that names the recovery path, so the
  manifest attributes it to the extractor that produced it. The
  `manifest@1` and `bundle@1` schemas and every reason code stay
  unchanged. The fix narrows which PDFs receive `pdf_no_text_layer` and
  leaves what the code means alone.
