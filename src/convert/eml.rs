//! MIME message to text conversion for eml.
//!
//! The artifact is a fixed header subset, one per line in a fixed
//! order when present, then one blank line, then the message text.
//! Encoded header words decode per RFC 2047. Body selection follows
//! the alternative and mixed rules: an alternative group renders its
//! plain part, or its html part through the strip path when no plain
//! part exists, and a mixed group concatenates its text parts in MIME
//! order separated by one blank line.
//!
//! Attachments become container members. Each one is decoded and
//! lifted out with a name built from its 1-based index and sanitized
//! filename, and the pipeline routes it back through dispatch under
//! the message's `.d/` directory. A nested message counts as an
//! attachment. Hard ceilings on header bytes, header count, part
//! count, nesting depth, per-part decoded bytes, and the running
//! total of decoded attachment bytes fail closed before the parser or
//! a decoder can be driven past them.

use mailparse::body::Body;
use mailparse::{DispositionType, MailHeaderMap, ParsedMail};

use super::html::strip_html;
use super::{ConvertError, Converter, MAX_PART_BYTES, MAX_SOURCE_BYTES, Outcome, normalize_text};
use crate::segments::Segment;

/// Registry id of the eml converter.
pub const EML_ID: &str = "eml-mime";
/// Version of the eml converter.
pub const EML_VERSION: &str = "1.0.0";

/// Headers rendered into the artifact, in this order, when present.
const RENDERED_HEADERS: &[&str] = &["From", "To", "Cc", "Bcc", "Reply-To", "Date", "Subject"];

/// Ceiling on total header bytes across every part.
pub const MAX_EML_HEADER_BYTES: usize = 1024 * 1024;
/// Ceiling on total header count across every part.
pub const MAX_EML_HEADERS: usize = 1000;
/// Ceiling on MIME parts in one message.
pub const MAX_EML_PARTS: usize = 1000;
/// Ceiling on MIME nesting depth. The outer message is depth 0.
pub const MAX_EML_DEPTH: usize = 16;
/// Ceiling on raw `content-type` header keys in the source, checked
/// before the parser runs. The parser recurses once per multipart
/// level, every level needs a Content-Type header whose field name is
/// never RFC 2047 encoded, and a stack overflow aborts the process
/// where no cap of ours can reach, which is why this count must run
/// first. Counting raw substrings can only overcount, so the ceiling
/// is a guaranteed upper bound on recursion depth.
pub const MAX_EML_CONTENT_TYPE_HEADERS: usize = 1000;
/// Ceiling on raw boundary-delimiter line starts in the source,
/// checked before the parser runs. The parser allocates one part per
/// boundary line, so a flat message with millions of sibling parts
/// would allocate far past the part ceiling before it could fire.
/// Body lines that merely start with two hyphens inflate the count,
/// so the ceiling sits well above the semantic part cap.
pub const MAX_EML_BOUNDARY_LINES: usize = 10_000;

/// MIME message converter for eml.
pub struct EmlMime;

/// One attachment lifted out as a container member.
pub struct EmlMember {
    /// Member name, the 1-based attachment index, a hyphen, and the
    /// sanitized filename, so names never collide or go missing.
    pub name: String,
    /// Decoded attachment bytes, routed back through dispatch.
    pub bytes: Vec<u8>,
}

/// An eml conversion plus the attachment members it expands into.
pub struct EmlExpansion {
    /// The parent artifact: rendered headers and text bodies.
    pub outcome: Outcome,
    /// Attachment members, in walk order.
    pub members: Vec<EmlMember>,
}

#[derive(Default)]
struct MessageState {
    bodies: Vec<String>,
    warnings: Vec<String>,
    members: Vec<EmlMember>,
    attachments: usize,
    decoded_bytes: usize,
    parts: usize,
    headers: usize,
    header_bytes: usize,
}

fn cap_error(what: &str, ceiling: usize) -> ConvertError {
    ConvertError {
        code: "resource_limit",
        message: format!("{what} exceeds the {ceiling} ceiling"),
    }
}

fn decode_error(detail: mailparse::MailParseError) -> ConvertError {
    ConvertError {
        code: "mime_decode_error",
        message: detail.to_string(),
    }
}

/// The raw transfer-encoded length of a part's body, which bounds its
/// decoded length, so the ceiling applies before any decoder runs.
fn raw_body_len(part: &ParsedMail) -> usize {
    match part.get_body_encoded() {
        Body::Base64(body) | Body::QuotedPrintable(body) => body.get_raw().len(),
        Body::SevenBit(body) | Body::EightBit(body) => body.get_raw().len(),
        Body::Binary(body) => body.get_raw().len(),
    }
}

/// The filename a part declares, from its disposition or type params.
fn part_filename(part: &ParsedMail) -> String {
    let disposition = part.get_content_disposition();
    disposition
        .params
        .get("filename")
        .or_else(|| part.ctype.params.get("name"))
        .cloned()
        .unwrap_or_else(|| "unnamed".to_string())
}

/// Reduces a declared filename to one safe path segment: the final
/// component, control and separator characters dropped. An empty
/// result becomes `unnamed`, so a member name never goes missing.
fn sanitize_filename(name: &str) -> String {
    let last = name.rsplit(['/', '\\']).next().unwrap_or(name);
    let cleaned: String = last
        .chars()
        .filter(|c| !c.is_control() && *c != '/' && *c != '\\')
        .collect();
    let trimmed = cleaned.trim().trim_matches('.').trim();
    if trimmed.is_empty() {
        "unnamed".to_string()
    } else {
        trimmed.to_string()
    }
}

fn is_attachment(part: &ParsedMail) -> bool {
    if part.get_content_disposition().disposition == DispositionType::Attachment {
        return true;
    }
    let mimetype = part.ctype.mimetype.as_str();
    // A nested message counts as an attachment until container
    // expansion lands. So does any non-text leaf, an inline image
    // for example, because its bytes need a converter of their own.
    mimetype == "message/rfc822"
        || !(mimetype.starts_with("text/") || mimetype.starts_with("multipart/"))
}

fn decoded_text(part: &ParsedMail) -> Result<String, ConvertError> {
    let raw_len = raw_body_len(part);
    if raw_len > MAX_PART_BYTES as usize {
        return Err(cap_error("part body bytes", MAX_PART_BYTES as usize));
    }
    part.get_body().map_err(decode_error)
}

fn account_part(part: &ParsedMail, state: &mut MessageState) -> Result<(), ConvertError> {
    state.parts += 1;
    if state.parts > MAX_EML_PARTS {
        return Err(cap_error("MIME part count", MAX_EML_PARTS));
    }
    state.headers += part.headers.len();
    if state.headers > MAX_EML_HEADERS {
        return Err(cap_error("header count", MAX_EML_HEADERS));
    }
    state.header_bytes += part
        .headers
        .iter()
        .map(|h| h.get_key_raw().len() + h.get_value_raw().len())
        .sum::<usize>();
    if state.header_bytes > MAX_EML_HEADER_BYTES {
        return Err(cap_error("header bytes", MAX_EML_HEADER_BYTES));
    }
    Ok(())
}

/// Walks one part, collecting rendered bodies and attachment
/// warnings.
fn walk(part: &ParsedMail, depth: usize, state: &mut MessageState) -> Result<(), ConvertError> {
    if depth > MAX_EML_DEPTH {
        return Err(cap_error("MIME nesting depth", MAX_EML_DEPTH));
    }
    account_part(part, state)?;
    if is_attachment(part) {
        let raw_len = raw_body_len(part);
        if raw_len > MAX_PART_BYTES as usize {
            return Err(cap_error("attachment body bytes", MAX_PART_BYTES as usize));
        }
        let bytes = part.get_body_raw().map_err(decode_error)?;
        // Charge the running total of decoded attachment bytes as
        // each one lands, so a message cannot accumulate more decoded
        // attachment content than one source before the cap fires.
        state.decoded_bytes = state.decoded_bytes.saturating_add(bytes.len());
        if state.decoded_bytes > MAX_SOURCE_BYTES as usize {
            return Err(cap_error(
                "decoded attachment bytes",
                MAX_SOURCE_BYTES as usize,
            ));
        }
        state.attachments += 1;
        let name = format!(
            "{}-{}",
            state.attachments,
            sanitize_filename(&part_filename(part))
        );
        state.members.push(EmlMember { name, bytes });
        return Ok(());
    }
    let mimetype = part.ctype.mimetype.as_str();
    if mimetype == "multipart/alternative" {
        let chosen = part
            .subparts
            .iter()
            .find(|p| p.ctype.mimetype == "text/plain")
            .or_else(|| {
                part.subparts
                    .iter()
                    .find(|p| p.ctype.mimetype == "text/html")
            })
            .or_else(|| part.subparts.first());
        if let Some(chosen) = chosen {
            // The unchosen renditions are alternatives of the same
            // content, so they are neither rendered nor warned
            // about, but they still count against the part ceilings.
            for unchosen in part.subparts.iter().filter(|p| !std::ptr::eq(*p, chosen)) {
                account_part(unchosen, state)?;
            }
            walk(chosen, depth + 1, state)?;
        }
        return Ok(());
    }
    if mimetype.starts_with("multipart/") {
        for subpart in &part.subparts {
            walk(subpart, depth + 1, state)?;
        }
        return Ok(());
    }
    if mimetype == "text/html" {
        let html = decoded_text(part)?;
        let (stripped, strip_warnings) = strip_html(html.as_bytes())?;
        state.warnings.extend(strip_warnings);
        push_body(state, stripped);
        return Ok(());
    }
    // Any other text part renders as the text it is.
    push_body(state, decoded_text(part)?);
    Ok(())
}

fn push_body(state: &mut MessageState, text: String) {
    let trimmed = text.trim_matches('\n');
    if !trimmed.is_empty() {
        state.bodies.push(trimmed.to_string());
    }
}

impl Converter for EmlMime {
    fn id(&self) -> &'static str {
        EML_ID
    }

    fn version(&self) -> &'static str {
        EML_VERSION
    }

    fn convert(
        &self,
        source: &[u8],
        detected_format: &str,
    ) -> std::result::Result<Outcome, ConvertError> {
        Ok(expand_eml(source, detected_format)?.outcome)
    }
}

/// Renders an eml message to its parent artifact and lifts its
/// attachments into container members.
pub fn expand_eml(source: &[u8], detected_format: &str) -> Result<EmlExpansion, ConvertError> {
    let content_type_keys = source
        .windows(b"content-type".len())
        .filter(|window| window.eq_ignore_ascii_case(b"content-type"))
        .count();
    if content_type_keys > MAX_EML_CONTENT_TYPE_HEADERS {
        return Err(cap_error(
            "content-type headers",
            MAX_EML_CONTENT_TYPE_HEADERS,
        ));
    }
    let boundary_lines = source.windows(3).filter(|window| window == b"\n--").count();
    if boundary_lines > MAX_EML_BOUNDARY_LINES {
        return Err(cap_error(
            "boundary delimiter lines",
            MAX_EML_BOUNDARY_LINES,
        ));
    }
    let message = mailparse::parse_mail(source).map_err(|e| ConvertError {
        code: "mime_parse_error",
        message: e.to_string(),
    })?;
    let mut state = MessageState::default();
    walk(&message, 0, &mut state)?;

    let mut rendered = String::new();
    for name in RENDERED_HEADERS {
        if let Some(value) = message.headers.get_first_value(name) {
            let value = value.trim();
            if !value.is_empty() {
                rendered.push_str(name);
                rendered.push_str(": ");
                rendered.push_str(value);
                rendered.push('\n');
            }
        }
    }
    if !state.bodies.is_empty() {
        if !rendered.is_empty() {
            rendered.push('\n');
        }
        rendered.push_str(&state.bodies.join("\n\n"));
        rendered.push('\n');
    }

    let text = normalize_text(&rendered);
    if !source.is_empty() && text.is_empty() {
        return Err(ConvertError {
            code: "empty_output",
            message: format!(
                "source is {} bytes but renders no headers and no text body",
                source.len()
            ),
        });
    }
    let segments = vec![Segment::span(0, text.len(), "document")];
    Ok(EmlExpansion {
        outcome: Outcome {
            artifact_kind: crate::manifest::ArtifactKind::Text,
            converter_id: EML_ID.to_string(),
            converter_version: EML_VERSION.to_string(),
            detected_format: detected_format.to_string(),
            text,
            warnings: state.warnings,
            segments,
        },
        members: state.members,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const MULTIPART: &str = "From: =?UTF-8?B?WsO8cmljaCBPZmZpY2U=?= <office@example.com>\r\n\
To: team@example.com\r\n\
Subject: =?UTF-8?Q?Q3_plan=2C_r=C3=A9sum=C3=A9?=\r\n\
Date: Fri, 21 Aug 2026 09:00:00 +0000\r\n\
MIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; boundary=\"outer\"\r\n\
\r\n\
--outer\r\n\
Content-Type: multipart/alternative; boundary=\"inner\"\r\n\
\r\n\
--inner\r\n\
Content-Type: text/plain; charset=utf-8\r\n\
\r\n\
The plain rendition.\r\n\
--inner\r\n\
Content-Type: text/html; charset=utf-8\r\n\
\r\n\
<p>The html rendition.</p>\r\n\
--inner--\r\n\
--outer\r\n\
Content-Type: application/pdf\r\n\
Content-Disposition: attachment; filename=\"budget.pdf\"\r\n\
Content-Transfer-Encoding: base64\r\n\
\r\n\
JVBERi0xLjQK\r\n\
--outer--\r\n";

    #[test]
    fn headers_render_decoded_and_the_plain_part_wins() {
        let outcome = EmlMime.convert(MULTIPART.as_bytes(), "eml").unwrap();
        let text = &outcome.text;
        assert!(
            text.starts_with("From: Z\u{fc}rich Office <office@example.com>\n"),
            "{text:?}"
        );
        assert!(
            text.contains("Subject: Q3 plan, r\u{e9}sum\u{e9}\n"),
            "{text:?}"
        );
        assert!(text.contains("\n\nThe plain rendition.\n"), "{text:?}");
        assert!(!text.contains("html rendition"));
        // The attachment is lifted as a member, not a warning.
        assert!(outcome.warnings.is_empty(), "{:?}", outcome.warnings);
        let expansion = expand_eml(MULTIPART.as_bytes(), "eml").unwrap();
        assert_eq!(expansion.members.len(), 1);
        assert_eq!(expansion.members[0].name, "1-budget.pdf");
        assert_eq!(expansion.members[0].bytes, b"%PDF-1.4\n");
    }

    #[test]
    fn an_html_only_body_routes_through_the_strip_path() {
        let source = "From: a@example.com\r\n\
Content-Type: text/html; charset=utf-8\r\n\
\r\n\
<html><body><p>Only &amp; ever html.</p><script>leak()</script></body></html>\r\n";
        let outcome = EmlMime.convert(source.as_bytes(), "eml").unwrap();
        assert!(
            outcome.text.contains("Only & ever html.\n"),
            "{:?}",
            outcome.text
        );
        assert!(!outcome.text.contains("leak"));
        assert!(!outcome.text.contains("<p>"));
    }

    #[test]
    fn a_nested_message_counts_as_an_attachment() {
        let source = "From: a@example.com\r\n\
Content-Type: multipart/mixed; boundary=\"b\"\r\n\
\r\n\
--b\r\n\
Content-Type: text/plain\r\n\
\r\n\
covering note\r\n\
--b\r\n\
Content-Type: message/rfc822\r\n\
\r\n\
From: c@example.com\r\n\
\r\n\
inner body\r\n\
--b--\r\n";
        let expansion = expand_eml(source.as_bytes(), "eml").unwrap();
        assert!(expansion.outcome.text.contains("covering note"));
        assert!(!expansion.outcome.text.contains("inner body"));
        // The nested message is a member, and its bytes are the raw
        // rfc822 message so dispatch re-detects it as eml.
        assert_eq!(expansion.members.len(), 1);
        assert_eq!(expansion.members[0].name, "1-unnamed");
        assert!(
            expansion.members[0]
                .bytes
                .starts_with(b"From: c@example.com"),
            "{:?}",
            String::from_utf8_lossy(&expansion.members[0].bytes)
        );
    }

    #[test]
    fn mixed_text_parts_concatenate_with_one_blank_line() {
        let source = "Content-Type: multipart/mixed; boundary=\"b\"\r\n\
\r\n\
--b\r\n\
Content-Type: text/plain\r\n\
\r\n\
first part\r\n\
--b\r\n\
Content-Type: text/plain\r\n\
\r\n\
second part\r\n\
--b--\r\n";
        let outcome = EmlMime.convert(source.as_bytes(), "eml").unwrap();
        assert_eq!(outcome.text, "first part\n\nsecond part\n");
    }

    #[test]
    fn nesting_past_the_ceiling_fails_closed() {
        let mut inner = "Content-Type: text/plain\r\n\r\ndeep\r\n".to_string();
        for level in 0..(MAX_EML_DEPTH + 2) {
            inner = format!(
                "Content-Type: multipart/mixed; boundary=\"b{level}\"\r\n\r\n\
                 --b{level}\r\n{inner}--b{level}--\r\n"
            );
        }
        let source = format!("From: a@example.com\r\n{inner}");
        let err = EmlMime.convert(source.as_bytes(), "eml").unwrap_err();
        assert_eq!(err.code, "resource_limit");
        assert!(err.message.contains("nesting"), "{}", err.message);
    }

    // The parser recurses per nesting level, so the content-type key
    // ceiling must fire before it runs. A deep enough nest would
    // otherwise exhaust the stack and abort the process.
    #[test]
    fn the_content_type_ceiling_fires_before_the_parser() {
        let mut msg = String::from("Content-Type: text/plain\r\n\r\ndeep\r\n");
        for level in 0..(MAX_EML_CONTENT_TYPE_HEADERS + 1) {
            msg = format!(
                "Content-Type: multipart/mixed; boundary=\"b{level}\"\r\n\r\n\
                 --b{level}\r\n{msg}--b{level}--\r\n"
            );
        }
        let err = EmlMime.convert(msg.as_bytes(), "eml").unwrap_err();
        assert_eq!(err.code, "resource_limit");
        assert!(
            err.message.contains("content-type headers"),
            "{}",
            err.message
        );
    }

    // The mimetype value can arrive RFC 2047 encoded with no literal
    // `multipart` byte anywhere, but the field name cannot, so the
    // key count still bounds the recursion.
    #[test]
    fn an_encoded_word_content_type_bomb_fails_closed() {
        let mut msg = String::from("X-Filler: none\r\n\r\ndeep\r\n");
        for level in 0..(MAX_EML_CONTENT_TYPE_HEADERS + 1) {
            msg = format!(
                "Content-Type: =?UTF-8?B?bXVsdGlwYXJ0L21peGVk?= ; boundary=\"b{level}\"\r\n\r\n\
                 --b{level}\r\n{msg}--b{level}--\r\n"
            );
        }
        assert!(!msg.to_ascii_lowercase().contains("multipart"));
        let err = EmlMime.convert(msg.as_bytes(), "eml").unwrap_err();
        assert_eq!(err.code, "resource_limit");
        assert!(
            err.message.contains("content-type headers"),
            "{}",
            err.message
        );
    }

    // One flat multipart level with millions of sibling parts carries
    // one content-type header, so the boundary-line ceiling is the
    // guard that must fire before the parser allocates per part.
    #[test]
    fn a_sibling_breadth_bomb_fails_closed_before_the_parser() {
        let mut msg = String::from("Content-Type: multipart/mixed; boundary=\"b\"\r\n\r\n");
        for _ in 0..(MAX_EML_BOUNDARY_LINES + 1) {
            msg.push_str("--b\r\n\r\nx\r\n");
        }
        msg.push_str("--b--\r\n");
        let err = EmlMime.convert(msg.as_bytes(), "eml").unwrap_err();
        assert_eq!(err.code, "resource_limit");
        assert!(
            err.message.contains("boundary delimiter lines"),
            "{}",
            err.message
        );
    }

    #[test]
    fn a_message_with_nothing_to_render_is_suspiciously_empty() {
        let err = EmlMime
            .convert(b"X-Other: value\r\n\r\n", "eml")
            .unwrap_err();
        assert_eq!(err.code, "empty_output");
    }
}
