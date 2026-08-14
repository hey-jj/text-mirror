//! Differential comparison for legacy Office conversions.
//!
//! The primary converter's text is checked against a second,
//! independent extraction. Agreement is silent. Divergence appends a
//! structured warning. The one failing case is a primary that
//! extracted under half of what the secondary found, because an
//! artifact missing that much content must not present as converted.
//! A secondary crash appends an unavailability warning and never
//! sinks a sound primary conversion.

use std::collections::HashMap;
use std::io::Cursor;
use std::panic::{AssertUnwindSafe, catch_unwind};

use unicode_normalization::UnicodeNormalization;

/// The secondary extractor identity carried in every differential
/// warning and error string.
pub const SECONDARY_ID: &str = "office_oxide/0.1.8";

/// Length ratio at or above this bound counts toward agreement.
pub const LEN_RATIO_BOUND: f64 = 0.90;

/// Dice coefficient at or above this bound counts toward agreement.
pub const DICE_BOUND: f64 = 0.95;

/// Primary shorter than this fraction of the secondary is a failure.
pub const FAILURE_FRACTION: f64 = 0.50;

/// The two comparison metrics.
///
/// Length is the UTF-8 byte length of the normalized comparison text.
/// That unit is the contract, because changing it would silently move
/// verdicts near the thresholds.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DiffMetrics {
    /// Normalized length ratio, shorter over longer, 1.0 when equal.
    pub len_ratio: f64,
    /// Dice coefficient over token multisets.
    pub dice: f64,
}

/// The comparison verdict.
#[derive(Debug, Clone, PartialEq)]
pub enum DiffVerdict {
    /// Both metrics at or above their bounds. Nothing is recorded.
    Agreement,
    /// A metric fell below its bound but the primary holds enough
    /// text. The conversion stands with a warning.
    Divergence,
    /// The primary extracted under half of the secondary's text. The
    /// conversion fails.
    Failure,
}

/// Normalizes text for comparison: NFC, every whitespace run
/// collapsed to one space, trimmed. No case folding.
pub fn normalize_for_diff(text: &str) -> String {
    let composed: String = text.nfc().collect();
    let mut out = String::with_capacity(composed.len());
    let mut in_space = true;
    for c in composed.chars() {
        if c.is_whitespace() {
            if !in_space {
                out.push(' ');
                in_space = true;
            }
        } else {
            out.push(c);
            in_space = false;
        }
    }
    while out.ends_with(' ') {
        out.pop();
    }
    out
}

fn dice_over_tokens(a: &str, b: &str) -> f64 {
    let mut counts: HashMap<&str, (u64, u64)> = HashMap::new();
    let mut total_a = 0u64;
    let mut total_b = 0u64;
    for token in a.split(' ').filter(|t| !t.is_empty()) {
        counts.entry(token).or_default().0 += 1;
        total_a += 1;
    }
    for token in b.split(' ').filter(|t| !t.is_empty()) {
        counts.entry(token).or_default().1 += 1;
        total_b += 1;
    }
    if total_a + total_b == 0 {
        return 1.0;
    }
    let intersection: u64 = counts.values().map(|(x, y)| (*x).min(*y)).sum();
    (2 * intersection) as f64 / (total_a + total_b) as f64
}

/// Compares two already-normalized texts and returns the metrics and
/// the verdict per the thresholds.
pub fn compare_texts(primary: &str, secondary: &str) -> (DiffMetrics, DiffVerdict) {
    let primary_len = primary.len() as f64;
    let secondary_len = secondary.len() as f64;
    let len_ratio = if primary_len == 0.0 && secondary_len == 0.0 {
        1.0
    } else {
        primary_len.min(secondary_len) / primary_len.max(secondary_len)
    };
    let dice = dice_over_tokens(primary, secondary);
    let metrics = DiffMetrics { len_ratio, dice };
    let verdict = if len_ratio >= LEN_RATIO_BOUND && dice >= DICE_BOUND {
        DiffVerdict::Agreement
    } else if primary_len < FAILURE_FRACTION * secondary_len {
        DiffVerdict::Failure
    } else {
        DiffVerdict::Divergence
    };
    (metrics, verdict)
}

/// The structured divergence string used in warnings and error detail.
/// Metrics print with four decimals so a reader can reproduce the
/// threshold decision from the record alone.
pub fn divergence_message(metrics: DiffMetrics) -> String {
    format!(
        "differential-divergence: secondary={SECONDARY_ID} len_ratio={:.4} dice={:.4}",
        metrics.len_ratio, metrics.dice
    )
}

/// The unavailability warning for a secondary that errored or panicked.
pub fn unavailable_message(error_class: &str) -> String {
    format!("differential-unavailable: {error_class}")
}

fn office_error_class(error: &office_oxide::OfficeError) -> &'static str {
    use office_oxide::OfficeError;
    match error {
        OfficeError::Core(_) => "core",
        OfficeError::Docx(_) => "docx",
        OfficeError::Xlsx(_) => "xlsx",
        OfficeError::Pptx(_) => "pptx",
        OfficeError::Doc(_) => "doc",
        OfficeError::Xls(_) => "xls",
        OfficeError::Ppt(_) => "ppt",
        OfficeError::UnsupportedFormat(_) => "unsupported_format",
    }
}

/// Extracts the secondary's plain text for a legacy Office format.
/// Errors and panics both come back as an error class string.
pub fn secondary_text(bytes: &[u8], format_id: &str) -> std::result::Result<String, String> {
    let format = match format_id {
        "doc" => office_oxide::DocumentFormat::Doc,
        "xls" => office_oxide::DocumentFormat::Xls,
        "ppt" => office_oxide::DocumentFormat::Ppt,
        other => return Err(format!("no secondary for format {other}")),
    };
    let owned = bytes.to_vec();
    let extraction = catch_unwind(AssertUnwindSafe(move || {
        office_oxide::Document::from_reader(Cursor::new(owned), format)
            .map(|document| document.plain_text())
    }));
    match extraction {
        Ok(Ok(text)) => Ok(text),
        Ok(Err(error)) => Err(office_error_class(&error).to_string()),
        Err(_) => Err("panic".to_string()),
    }
}

/// What a full differential check concluded.
#[derive(Debug, Clone, PartialEq)]
pub enum DifferentialOutcome {
    /// Both metrics inside their bounds. Nothing is recorded.
    Agreement,
    /// A warning string to append, for divergence or for a secondary
    /// that could not run.
    Warning(String),
    /// The failure detail for a failed record with reason
    /// `differential-divergence`.
    Failure(String),
}

/// Runs the whole check: secondary extraction, normalization of both
/// sides, metrics, and verdict.
pub fn check(primary_text: &str, source: &[u8], format_id: &str) -> DifferentialOutcome {
    match secondary_text(source, format_id) {
        Err(class) => DifferentialOutcome::Warning(unavailable_message(&class)),
        Ok(secondary) => {
            let primary_norm = normalize_for_diff(primary_text);
            let secondary_norm = normalize_for_diff(&secondary);
            let (metrics, verdict) = compare_texts(&primary_norm, &secondary_norm);
            match verdict {
                DiffVerdict::Agreement => DifferentialOutcome::Agreement,
                DiffVerdict::Divergence => {
                    DifferentialOutcome::Warning(divergence_message(metrics))
                }
                DiffVerdict::Failure => DifferentialOutcome::Failure(format!(
                    "secondary={SECONDARY_ID} len_ratio={:.4} dice={:.4}",
                    metrics.len_ratio, metrics.dice
                )),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_collapses_whitespace_and_composes() {
        assert_eq!(
            normalize_for_diff("  a\t\tb\n\nc  cafe\u{301} "),
            "a b c caf\u{e9}"
        );
    }

    #[test]
    fn identical_texts_agree() {
        let (metrics, verdict) = compare_texts("alpha beta gamma", "alpha beta gamma");
        assert_eq!(metrics.len_ratio, 1.0);
        assert_eq!(metrics.dice, 1.0);
        assert_eq!(verdict, DiffVerdict::Agreement);
        let (_, verdict) = compare_texts("", "");
        assert_eq!(verdict, DiffVerdict::Agreement);
    }

    #[test]
    fn small_disagreement_diverges_with_a_warning_string() {
        // Same length class, different tokens: dice falls, length holds.
        let (metrics, verdict) = compare_texts(
            "alpha beta gamma delta epsilon",
            "alpha beta gamma delta zzzzzzz",
        );
        assert_eq!(verdict, DiffVerdict::Divergence);
        let message = divergence_message(metrics);
        assert!(message.starts_with("differential-divergence: secondary=office_oxide/0.1.8"));
        assert!(message.contains("len_ratio=1.0000"));
        assert!(message.contains("dice=0.8000"));
    }

    #[test]
    fn four_decimals_separate_a_near_threshold_dice() {
        // A dice of 0.949 fails the 0.95 bound and must not print as
        // if it passed.
        let metrics = DiffMetrics {
            len_ratio: 1.0,
            dice: 0.949,
        };
        let message = divergence_message(metrics);
        assert!(message.contains("dice=0.9490"));
        assert!(!message.contains("dice=0.95"));
    }

    #[test]
    fn short_primary_fails_and_short_secondary_only_warns() {
        let long = "one two three four five six seven eight nine ten";
        let short = "one two three";
        let (_, verdict) = compare_texts(short, long);
        assert_eq!(verdict, DiffVerdict::Failure);
        // The same gap the other way is the secondary's weakness.
        let (_, verdict) = compare_texts(long, short);
        assert_eq!(verdict, DiffVerdict::Divergence);
    }

    #[test]
    fn secondary_garbage_reports_an_error_class() {
        let class = secondary_text(b"not an office file", "doc").unwrap_err();
        assert!(!class.is_empty());
    }

    #[test]
    fn unavailable_message_names_the_class() {
        assert_eq!(
            unavailable_message("panic"),
            "differential-unavailable: panic"
        );
    }
}
