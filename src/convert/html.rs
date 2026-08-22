//! Strip-to-text conversion for html.
//!
//! A streaming pass over the markup collects the visible text and
//! nothing else. Script, style, template, and noscript content is
//! suppressed, head content other than the title is dropped, and the
//! title text becomes the first line. Block boundaries become line
//! breaks: the ruled set, `p`, `div`, `li`, `tr`, `br`, the headings,
//! `blockquote`, and `pre`, plus the HTML5 sectioning and grouping
//! containers, and table cells within a row separate with a tab.
//! Character references decode, whitespace runs collapse to one
//! space, and blank-line runs collapse to one blank line. Reading
//! order and table reconstruction are out of scope.
//!
//! The stream never builds a document tree, so memory stays bounded
//! under hostile nesting, and a run over the memory ceiling or the
//! working budget fails closed. Captured text, block breaks, and cell
//! tabs all charge one working budget, so a dense page of short
//! blocks cannot grow converter-owned state past the order of the
//! output ceiling. Suppression of script, style, and
//! noscript rides the lexer's own text typing rather than end-tag
//! bookkeeping, so a missing closing tag cannot leak script text into
//! the capture.

use std::cell::RefCell;
use std::rc::Rc;

use lol_html::html_content::{TextChunk, TextType};
use lol_html::{HtmlRewriter, MemorySettings, Settings, doc_text, element, end_tag};

use super::{ConvertError, Converter, MAX_OUTPUT_BYTES, MAX_PART_BYTES, Outcome, normalize_text};
use crate::segments::Segment;

/// Registry id of the html strip converter.
pub const HTML_STRIP_ID: &str = "html-strip";
/// Version of the html strip converter.
pub const HTML_STRIP_VERSION: &str = "1.0.0";

/// Strip-to-text converter for html.
pub struct HtmlStrip;

/// Elements whose start tag does not imply the head has ended.
///
/// The stream has no tree builder, so an unclosed `<head>` would
/// otherwise swallow the whole document. The first start tag outside
/// this set ends head suppression, which mirrors the implied close a
/// tree builder performs.
const HEAD_CONTENT: &[&str] = &[
    "base", "basefont", "bgsound", "head", "html", "link", "meta", "noscript", "script", "style",
    "template", "title",
];

/// The block set: the ruled elements plus the HTML5 sectioning and
/// grouping containers, so adjacent blocks never concatenate words.
/// Start and end both mark a line break.
const BLOCK_ELEMENTS: &[&str] = &[
    "address",
    "article",
    "aside",
    "blockquote",
    "dd",
    "div",
    "dl",
    "dt",
    "figure",
    "footer",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "header",
    "li",
    "main",
    "nav",
    "ol",
    "p",
    "pre",
    "section",
    "table",
    "tr",
    "ul",
];

#[derive(Default)]
struct StripState {
    /// Captured content: collapsed text, `\n` for block boundaries,
    /// `\t` for cell separators. One flat buffer, so the working
    /// memory stays on the order of the budget.
    raw: String,
    title: String,
    in_title: bool,
    title_done: bool,
    in_head: bool,
    template_depth: u32,
    row_has_cell: bool,
    node_buf: String,
    node_type: Option<TextType>,
    charged_bytes: usize,
    budget: usize,
}

impl StripState {
    /// Charges bytes against the working budget. Text, block breaks,
    /// and cell tabs all pay, so no shape of markup grows the
    /// converter's own memory past the order of the budget.
    fn charge(&mut self, bytes: usize) -> std::result::Result<(), String> {
        self.charged_bytes += bytes;
        if self.charged_bytes > self.budget {
            Err(format!(
                "captured content exceeds the {} byte ceiling",
                self.budget
            ))
        } else {
            Ok(())
        }
    }

    fn push_break(&mut self) -> std::result::Result<(), String> {
        self.charge(1)?;
        self.raw.push('\n');
        Ok(())
    }

    fn push_tab(&mut self) -> std::result::Result<(), String> {
        self.charge(1)?;
        self.raw.push('\t');
        Ok(())
    }

    fn flush_node(&mut self, fallback_type: TextType) {
        let text = std::mem::take(&mut self.node_buf);
        let text_type = self.node_type.take().unwrap_or(fallback_type);
        if text.is_empty() || self.template_depth > 0 {
            return;
        }
        let keep = matches!(
            text_type,
            TextType::Data | TextType::RCData | TextType::PlainText
        );
        if !keep {
            return;
        }
        let decoded = if text_type.allows_html_entities() {
            decode_entities(&text)
        } else {
            text
        };
        if self.in_title {
            self.title.push_str(&decoded);
        } else if !self.in_head {
            // Collapsed at capture, so the buffer holds no literal
            // newline or tab except the structural ones above.
            self.raw.push_str(&collapse_whitespace(&decoded));
        }
    }
}

/// Strips markup from html bytes and returns the visible text beside
/// conversion warnings. Shared with the eml converter for html-only
/// message bodies.
pub(crate) fn strip_html(source: &[u8]) -> Result<(String, Vec<String>), ConvertError> {
    strip_html_with_budget(source, MAX_OUTPUT_BYTES)
}

/// [`strip_html`] with an explicit working budget, so tests can prove
/// the charging without gigabyte fixtures.
fn strip_html_with_budget(
    source: &[u8],
    budget: usize,
) -> Result<(String, Vec<String>), ConvertError> {
    let text_source = std::str::from_utf8(source).map_err(|e| ConvertError {
        code: "invalid_utf8",
        message: format!("invalid UTF-8 at byte {}", e.valid_up_to()),
    })?;
    let mut warnings = Vec::new();
    let text_source = match text_source.strip_prefix('\u{feff}') {
        Some(stripped) => {
            warnings.push("stripped leading byte order mark".to_string());
            stripped
        }
        None => text_source,
    };

    let state = Rc::new(RefCell::new(StripState {
        budget,
        ..StripState::default()
    }));
    let element_state = state.clone();
    let text_state = state.clone();
    let settings = Settings::new()
        .with_memory_settings(
            MemorySettings::new().with_max_allowed_memory_usage(MAX_PART_BYTES as usize),
        )
        .append_element_content_handler(element!("*", move |el| {
            let tag = el.tag_name();
            let mut st = element_state.borrow_mut();
            if st.in_head && !HEAD_CONTENT.contains(&tag.as_str()) {
                st.in_head = false;
            }
            match tag.as_str() {
                "head" => {
                    st.in_head = true;
                    let state = element_state.clone();
                    drop(st);
                    el.on_end_tag(end_tag!(move |_| {
                        state.borrow_mut().in_head = false;
                        Ok(())
                    }))?;
                }
                "title" if !st.title_done => {
                    st.in_title = true;
                    let state = element_state.clone();
                    drop(st);
                    el.on_end_tag(end_tag!(move |_| {
                        let mut st = state.borrow_mut();
                        st.in_title = false;
                        st.title_done = true;
                        Ok(())
                    }))?;
                }
                "template" => {
                    st.template_depth += 1;
                    let state = element_state.clone();
                    drop(st);
                    el.on_end_tag(end_tag!(move |_| {
                        let mut st = state.borrow_mut();
                        st.template_depth = st.template_depth.saturating_sub(1);
                        Ok(())
                    }))?;
                }
                "br" => st.push_break()?,
                "td" | "th" => {
                    if st.row_has_cell {
                        st.push_tab()?;
                    } else {
                        st.row_has_cell = true;
                    }
                }
                block if BLOCK_ELEMENTS.contains(&block) => {
                    st.push_break()?;
                    if block == "tr" {
                        st.row_has_cell = false;
                    }
                    let state = element_state.clone();
                    drop(st);
                    el.on_end_tag(end_tag!(move |_| {
                        state.borrow_mut().push_break()?;
                        Ok(())
                    }))?;
                }
                _ => {}
            }
            Ok(())
        }))
        .append_document_content_handler(doc_text!(move |chunk: &mut TextChunk| {
            let mut st = text_state.borrow_mut();
            let piece = chunk.as_str();
            st.charge(piece.len())?;
            if st.node_type.is_none() && !piece.is_empty() {
                st.node_type = Some(chunk.text_type());
            }
            st.node_buf.push_str(piece);
            if chunk.last_in_text_node() {
                let text_type = chunk.text_type();
                st.flush_node(text_type);
            }
            Ok(())
        }));

    let mut rewriter = HtmlRewriter::new(settings, |_: &[u8]| {});
    rewriter
        .write(text_source.as_bytes())
        .and_then(|()| rewriter.end())
        .map_err(|e| match e {
            lol_html::errors::RewritingError::MemoryLimitExceeded(_) => ConvertError {
                code: "resource_limit",
                message: format!("markup working memory exceeds the {MAX_PART_BYTES} byte ceiling"),
            },
            lol_html::errors::RewritingError::ContentHandlerError(detail) => ConvertError {
                code: "resource_limit",
                message: detail.to_string(),
            },
            other => ConvertError {
                code: "html_parse_error",
                message: other.to_string(),
            },
        })?;

    let mut state = state.borrow_mut();
    state.flush_node(TextType::Data);
    Ok((assemble(&state.title, &state.raw), warnings))
}

impl Converter for HtmlStrip {
    fn id(&self) -> &'static str {
        HTML_STRIP_ID
    }

    fn version(&self) -> &'static str {
        HTML_STRIP_VERSION
    }

    fn convert(
        &self,
        source: &[u8],
        detected_format: &str,
    ) -> std::result::Result<Outcome, ConvertError> {
        let (stripped, warnings) = strip_html(source)?;
        let text = normalize_text(&stripped);
        if !source.is_empty() && text.is_empty() {
            return Err(ConvertError {
                code: "empty_output",
                message: format!("source is {} bytes but holds no visible text", source.len()),
            });
        }
        let segments = vec![Segment::span(0, text.len(), "document")];
        Ok(Outcome {
            converter_id: HTML_STRIP_ID.to_string(),
            converter_version: HTML_STRIP_VERSION.to_string(),
            detected_format: detected_format.to_string(),
            text,
            warnings,
            segments,
        })
    }
}

/// Collapses ASCII whitespace runs to one space. Non-breaking spaces
/// stay, matching how a browser lays the text out.
fn collapse_whitespace(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut in_run = false;
    for c in text.chars() {
        if matches!(c, ' ' | '\t' | '\n' | '\r' | '\x0c') {
            if !in_run {
                out.push(' ');
                in_run = true;
            }
        } else {
            out.push(c);
            in_run = false;
        }
    }
    out
}

/// Renders the captured buffer to the final text: the title line
/// first, one line per block run, cells joined with tabs, whitespace
/// collapsed, and blank-line runs reduced to one blank line.
fn assemble(title: &str, raw: &str) -> String {
    let mut lines: Vec<String> = Vec::new();
    for raw_line in raw.split('\n') {
        let mut cells: Vec<String> = raw_line
            .split('\t')
            .map(|cell| collapse_whitespace(cell).trim().to_string())
            .collect();
        while cells.last().is_some_and(String::is_empty) && cells.len() > 1 {
            cells.pop();
        }
        lines.push(cells.join("\t"));
    }

    let mut out = String::new();
    let mut body_started = false;
    let mut blank_pending = false;
    for line in &lines {
        if line.is_empty() {
            // A blank line renders only between body lines, so
            // neither the title nor leading block breaks open the
            // text with one.
            blank_pending = body_started;
            continue;
        }
        if blank_pending {
            out.push('\n');
            blank_pending = false;
        }
        out.push_str(line);
        out.push('\n');
        body_started = true;
    }
    let title_line = collapse_whitespace(title);
    let title_line = title_line.trim();
    if title_line.is_empty() {
        out
    } else {
        format!("{title_line}\n{out}")
    }
}

/// Decodes numeric character references and the named references in
/// [`NAMED_ENTITIES`]. Anything else stays literal.
pub(crate) fn decode_entities(text: &str) -> String {
    if !text.contains('&') {
        return text.to_string();
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(position) = rest.find('&') {
        out.push_str(&rest[..position]);
        rest = &rest[position..];
        match decode_reference(rest) {
            Some((decoded, consumed)) => {
                out.push(decoded);
                rest = &rest[consumed..];
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// Decodes one reference at the start of `text`, which begins with an
/// ampersand. Returns the character and the bytes consumed.
fn decode_reference(text: &str) -> Option<(char, usize)> {
    let semicolon = text.as_bytes().iter().take(40).position(|&b| b == b';')?;
    let body = &text[1..semicolon];
    if let Some(number) = body.strip_prefix('#') {
        let value = if let Some(hex) = number.strip_prefix(['x', 'X']) {
            u32::from_str_radix(hex, 16).ok()?
        } else if number.is_empty() {
            return None;
        } else {
            number.parse::<u32>().ok()?
        };
        let decoded = char::from_u32(value)?;
        if decoded == '\0' {
            return None;
        }
        return Some((decoded, semicolon + 1));
    }
    NAMED_ENTITIES
        .binary_search_by(|(name, _)| (*name).cmp(body))
        .ok()
        .map(|index| (NAMED_ENTITIES[index].1, semicolon + 1))
}

/// Named character references this converter decodes: the XML five,
/// the Latin-1 set, and the common HTML punctuation and symbol names.
/// Sorted by name for binary search. An unrecognized reference stays
/// literal, which is the text as authored.
///
/// Known subset, tracked for a later quality pass: extend toward the
/// full HTML named set, the Greek block first, and accept a
/// semicolon-less numeric reference.
const NAMED_ENTITIES: &[(&str, char)] = &[
    ("AElig", '\u{c6}'),
    ("Aacute", '\u{c1}'),
    ("Acirc", '\u{c2}'),
    ("Agrave", '\u{c0}'),
    ("Aring", '\u{c5}'),
    ("Atilde", '\u{c3}'),
    ("Auml", '\u{c4}'),
    ("Ccedil", '\u{c7}'),
    ("Dagger", '\u{2021}'),
    ("ETH", '\u{d0}'),
    ("Eacute", '\u{c9}'),
    ("Ecirc", '\u{ca}'),
    ("Egrave", '\u{c8}'),
    ("Euml", '\u{cb}'),
    ("Iacute", '\u{cd}'),
    ("Icirc", '\u{ce}'),
    ("Igrave", '\u{cc}'),
    ("Iuml", '\u{cf}'),
    ("Ntilde", '\u{d1}'),
    ("OElig", '\u{152}'),
    ("Oacute", '\u{d3}'),
    ("Ocirc", '\u{d4}'),
    ("Ograve", '\u{d2}'),
    ("Oslash", '\u{d8}'),
    ("Otilde", '\u{d5}'),
    ("Ouml", '\u{d6}'),
    ("Prime", '\u{2033}'),
    ("Scaron", '\u{160}'),
    ("THORN", '\u{de}'),
    ("Uacute", '\u{da}'),
    ("Ucirc", '\u{db}'),
    ("Ugrave", '\u{d9}'),
    ("Uuml", '\u{dc}'),
    ("Yacute", '\u{dd}'),
    ("Yuml", '\u{178}'),
    ("aacute", '\u{e1}'),
    ("acirc", '\u{e2}'),
    ("acute", '\u{b4}'),
    ("aelig", '\u{e6}'),
    ("agrave", '\u{e0}'),
    ("amp", '\u{26}'),
    ("apos", '\u{27}'),
    ("aring", '\u{e5}'),
    ("atilde", '\u{e3}'),
    ("auml", '\u{e4}'),
    ("bdquo", '\u{201e}'),
    ("brvbar", '\u{a6}'),
    ("bull", '\u{2022}'),
    ("ccedil", '\u{e7}'),
    ("cedil", '\u{b8}'),
    ("cent", '\u{a2}'),
    ("circ", '\u{2c6}'),
    ("copy", '\u{a9}'),
    ("curren", '\u{a4}'),
    ("dagger", '\u{2020}'),
    ("deg", '\u{b0}'),
    ("divide", '\u{f7}'),
    ("eacute", '\u{e9}'),
    ("ecirc", '\u{ea}'),
    ("egrave", '\u{e8}'),
    ("emsp", '\u{2003}'),
    ("ensp", '\u{2002}'),
    ("eth", '\u{f0}'),
    ("euml", '\u{eb}'),
    ("euro", '\u{20ac}'),
    ("fnof", '\u{192}'),
    ("frac12", '\u{bd}'),
    ("frac14", '\u{bc}'),
    ("frac34", '\u{be}'),
    ("frasl", '\u{2044}'),
    ("gt", '\u{3e}'),
    ("hellip", '\u{2026}'),
    ("iacute", '\u{ed}'),
    ("icirc", '\u{ee}'),
    ("iexcl", '\u{a1}'),
    ("igrave", '\u{ec}'),
    ("iquest", '\u{bf}'),
    ("iuml", '\u{ef}'),
    ("laquo", '\u{ab}'),
    ("ldquo", '\u{201c}'),
    ("lrm", '\u{200e}'),
    ("lsaquo", '\u{2039}'),
    ("lsquo", '\u{2018}'),
    ("lt", '\u{3c}'),
    ("macr", '\u{af}'),
    ("mdash", '\u{2014}'),
    ("micro", '\u{b5}'),
    ("middot", '\u{b7}'),
    ("minus", '\u{2212}'),
    ("nbsp", '\u{a0}'),
    ("ndash", '\u{2013}'),
    ("not", '\u{ac}'),
    ("ntilde", '\u{f1}'),
    ("oacute", '\u{f3}'),
    ("ocirc", '\u{f4}'),
    ("oelig", '\u{153}'),
    ("ograve", '\u{f2}'),
    ("oline", '\u{203e}'),
    ("ordf", '\u{aa}'),
    ("ordm", '\u{ba}'),
    ("oslash", '\u{f8}'),
    ("otilde", '\u{f5}'),
    ("ouml", '\u{f6}'),
    ("para", '\u{b6}'),
    ("permil", '\u{2030}'),
    ("plusmn", '\u{b1}'),
    ("pound", '\u{a3}'),
    ("prime", '\u{2032}'),
    ("quot", '\u{22}'),
    ("raquo", '\u{bb}'),
    ("rdquo", '\u{201d}'),
    ("reg", '\u{ae}'),
    ("rlm", '\u{200f}'),
    ("rsaquo", '\u{203a}'),
    ("rsquo", '\u{2019}'),
    ("sbquo", '\u{201a}'),
    ("scaron", '\u{161}'),
    ("sect", '\u{a7}'),
    ("shy", '\u{ad}'),
    ("sup1", '\u{b9}'),
    ("sup2", '\u{b2}'),
    ("sup3", '\u{b3}'),
    ("szlig", '\u{df}'),
    ("thinsp", '\u{2009}'),
    ("thorn", '\u{fe}'),
    ("tilde", '\u{2dc}'),
    ("times", '\u{d7}'),
    ("trade", '\u{2122}'),
    ("uacute", '\u{fa}'),
    ("ucirc", '\u{fb}'),
    ("ugrave", '\u{f9}'),
    ("uml", '\u{a8}'),
    ("uuml", '\u{fc}'),
    ("yacute", '\u{fd}'),
    ("yen", '\u{a5}'),
    ("yuml", '\u{ff}'),
    ("zwj", '\u{200d}'),
    ("zwnj", '\u{200c}'),
];

#[cfg(test)]
mod tests {
    use super::*;

    // Prototype proof 1: character references decode, and the raw
    // reference never ships.
    #[test]
    fn entities_decode_and_the_raw_reference_never_ships() {
        let (text, _) =
            strip_html(b"<p>a &amp; b &#169; &lt;tag&gt; &euro;9 &bogus; x</p>").unwrap();
        assert_eq!(text, "a & b \u{a9} <tag> \u{20ac}9 &bogus; x\n");
        assert!(!text.contains("&amp;"));
        // Sensitivity control: a doubly escaped reference decodes to
        // the literal reference string, so the leak assertion above
        // can fire.
        let (control, _) = strip_html(b"<p>&amp;amp;</p>").unwrap();
        assert!(control.contains("&amp;"));
    }

    // Prototype proof 2: suppressed element text never reaches the
    // capture, a missing closing tag included.
    #[test]
    fn suppressed_element_text_never_reaches_the_capture() {
        let html = b"<p>keep</p><script>var leak = 'scriptleak';</script>\
            <style>.styleleak{}</style><noscript>noscriptleak</noscript>\
            <template>templateleak</template><script>runs to eof scriptleaktwo";
        let (text, _) = strip_html(html).unwrap();
        assert!(text.contains("keep"));
        for leak in [
            "scriptleak",
            "styleleak",
            "noscriptleak",
            "templateleak",
            "scriptleaktwo",
        ] {
            assert!(!text.contains(leak), "{leak} leaked into {text:?}");
        }
        // Sensitivity control: the same marker in a paragraph is
        // captured, so the leak assertions above can fire.
        let (control, _) = strip_html(b"<p>var leak = 'scriptleak';</p>").unwrap();
        assert!(control.contains("scriptleak"));
    }

    // Prototype proof 3: implied closures still yield deterministic
    // line breaks with every item on its own line.
    #[test]
    fn implied_closures_break_lines_deterministically() {
        let source = b"<ul><li>one<li>two<li>three</ul><p>para";
        let (first, _) = strip_html(source).unwrap();
        let (second, _) = strip_html(source).unwrap();
        assert_eq!(first, second);
        assert!(first.contains("one\ntwo\nthree"), "{first:?}");
        assert!(first.contains("para"));
        // Sensitivity control: without the list markup the same words
        // stay on one line, so the own-line assertion can fire.
        let (control, _) = strip_html(b"<p>one two three</p>").unwrap();
        assert_eq!(control, "one two three\n");
    }

    // Sectioning and grouping containers are boundaries, so adjacent
    // blocks never concatenate words.
    #[test]
    fn sectioning_containers_break_instead_of_concatenating() {
        let (text, _) = strip_html(b"<article>alpha</article><section>beta</section>").unwrap();
        assert_eq!(
            text,
            "alpha

beta
"
        );
        assert!(!text.contains("alphabeta"));
        let (more, _) = strip_html(
            b"<header>top</header><nav>menu</nav><main>body</main><footer>legal</footer>",
        )
        .unwrap();
        assert_eq!(
            more,
            "top

menu

body

legal
"
        );
    }

    // Block breaks and cell tabs charge the same working budget as
    // captured text, so a dense page of short blocks fails closed
    // instead of growing converter-owned state without bound.
    #[test]
    fn dense_short_blocks_fail_closed_on_the_working_budget() {
        let page = "<p>x</p>".repeat(64);
        // 64 blocks charge 64 text bytes plus 128 break bytes.
        let err = strip_html_with_budget(page.as_bytes(), 100).unwrap_err();
        assert_eq!(err.code, "resource_limit");
        assert!(err.message.contains("byte ceiling"), "{}", err.message);
        // Sensitivity control: the same page inside the budget
        // converts, so the ceiling is what fired above.
        let (text, _) = strip_html_with_budget(page.as_bytes(), 4096).unwrap();
        assert_eq!(text, vec!["x"; 64].join("\n\n") + "\n");
    }

    #[test]
    fn title_is_the_first_line_and_head_content_drops() {
        let html = b"<html><head><meta charset=\"utf-8\"><title>Q3 Plan</title>\
            <style>.x{}</style></head><body><p>body text</p></body></html>";
        let (text, _) = strip_html(html).unwrap();
        assert_eq!(text, "Q3 Plan\nbody text\n");
    }

    #[test]
    fn an_unclosed_head_does_not_swallow_the_body() {
        let (text, _) =
            strip_html(b"<html><head><title>T</title><p>after an unclosed head").unwrap();
        assert_eq!(text, "T\nafter an unclosed head\n");
    }

    #[test]
    fn paragraphs_separate_with_one_blank_line() {
        let (text, _) =
            strip_html(b"<p>first</p>\n\n\n<p>second</p><div><div><p>third</p></div></div>")
                .unwrap();
        assert_eq!(text, "first\n\nsecond\n\nthird\n");
    }

    #[test]
    fn table_cells_join_with_tabs_within_a_row() {
        let (text, _) = strip_html(
            b"<table><tr><td>a</td><td>b</td></tr><tr><td>c</td><td>d</td></tr></table>",
        )
        .unwrap();
        assert!(text.contains("a\tb"), "{text:?}");
        assert!(text.contains("c\td"), "{text:?}");
    }

    #[test]
    fn whitespace_collapses_and_inline_markup_flows() {
        let (text, _) = strip_html(b"<p>a\n   lot\t of <b>bold</b>\nspace</p>").unwrap();
        assert_eq!(text, "a lot of bold space\n");
    }

    #[test]
    fn invalid_utf8_fails_closed() {
        let err = strip_html(b"<p>ok \xff</p>").unwrap_err();
        assert_eq!(err.code, "invalid_utf8");
    }

    #[test]
    fn a_page_with_no_visible_text_is_suspiciously_empty() {
        let err = HtmlStrip
            .convert(b"<script>var x = 1;</script>", "html")
            .unwrap_err();
        assert_eq!(err.code, "empty_output");
    }
}
