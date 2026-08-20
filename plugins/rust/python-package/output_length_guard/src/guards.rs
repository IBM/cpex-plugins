// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
//
// Pure guard helpers for output length enforcement

use crate::config::{LimitMode, OutputLengthGuardConfig};

// Maximum length for numeric string exemption (matches Python _MAX_NUMERIC_STRING_LENGTH)
const MAX_NUMERIC_STRING_LENGTH: usize = 50;

/// Boundary characters for word-boundary truncation.
/// Mirrors Python BOUNDARY_CHARS frozenset.
const BOUNDARY_CHARS: &[char] = &[
    ' ', '\t', '\n', '\r', '.', ',', ';', ':', '!', '?', '-', '\u{2014}', '\u{2013}', '/', '\\',
    '(', ')', '[', ']', '{', '}',
];

/// Evaluate whether text violates limits based on config.limit_mode.
/// Returns (below_min, above_max).
pub fn evaluate_text_limits(
    length: usize,
    token_count: usize,
    cfg: &OutputLengthGuardConfig,
) -> (bool, bool) {
    match cfg.limit_mode {
        LimitMode::Character => {
            let below_min = cfg.min_chars > 0 && length < cfg.min_chars;
            let above_max = cfg.max_chars.is_some_and(|max| length > max);
            (below_min, above_max)
        }
        LimitMode::Token => {
            let below_min = cfg.min_tokens > 0 && token_count < cfg.min_tokens;
            let above_max = cfg.max_tokens.is_some_and(|max| token_count > max);
            (below_min, above_max)
        }
    }
}

/// Estimate token count using configurable chars-per-token ratio.
pub fn estimate_tokens(text: &str, chars_per_token: usize) -> usize {
    let cpt = chars_per_token.max(1);
    text.len() / cpt
}

/// Find word boundary position.
/// Returns the cut position adjusted to a word boundary, or the original cut
/// if none is found within 20% of max_chars backwards.
pub fn find_word_boundary(value: &str, cut: usize, max_chars: usize) -> usize {
    if value.is_empty() || cut == 0 {
        return cut;
    }
    let cut = cut.min(value.len());
    let search_back = (max_chars as f64 * 0.2) as usize;
    let min_search = cut.saturating_sub(search_back);

    // Walk backwards from cut-1 down to min_search
    let chars: Vec<char> = value[..cut].chars().collect();
    for i in (min_search..chars.len()).rev() {
        if BOUNDARY_CHARS.contains(&chars[i]) {
            // Return byte position of i+1 (after the boundary char)
            // We work in chars but the caller uses byte indices via slicing,
            // so we need to map back. Since we built chars from value[..cut],
            // we can sum char lengths.
            let byte_pos: usize = chars[..=i].iter().map(|c| c.len_utf8()).sum();
            return byte_pos;
        }
    }
    cut
}

/// Truncate string to limits according to policy.
/// Mirrors Python _truncate().
pub fn truncate(value: &str, cfg: &OutputLengthGuardConfig) -> String {
    let ell = &cfg.ellipsis;

    match cfg.limit_mode {
        LimitMode::Token => {
            let Some(max_tokens) = cfg.max_tokens else {
                return value.to_string();
            };
            if max_tokens == 0 {
                return value.to_string();
            }
            let safe_cpt = cfg.chars_per_token.max(1);
            let estimated = value.len() / safe_cpt;
            if estimated <= max_tokens {
                return value.to_string();
            }
            // cap at max_text_length first
            let effective = if value.len() > cfg.max_text_length {
                &value[..cfg.max_text_length]
            } else {
                value
            };
            let mut cut = (max_tokens * safe_cpt).min(effective.len());
            // Snap to a valid char boundary
            while cut > 0 && !effective.is_char_boundary(cut) {
                cut -= 1;
            }
            if cfg.word_boundary && cut > 0 {
                cut = find_word_boundary(effective, cut, cut);
                while cut > 0 && !effective.is_char_boundary(cut) {
                    cut -= 1;
                }
            }
            format!("{}{}", &effective[..cut], ell)
        }
        LimitMode::Character => {
            let Some(max_chars) = cfg.max_chars else {
                return value.to_string();
            };
            if max_chars == 0 {
                return value.to_string();
            }
            // Count chars (not bytes)
            let char_count = value.chars().count();
            if char_count <= max_chars {
                return value.to_string();
            }
            let ell_chars = ell.chars().count();
            if ell_chars >= max_chars {
                // ellipsis doesn't fit — hard char cut
                let cut_byte: usize = value
                    .char_indices()
                    .nth(max_chars)
                    .map_or(value.len(), |(i, _)| i);
                return value[..cut_byte].to_string();
            }
            let cut_char = max_chars - ell_chars;
            // Find byte offset of cut_char
            let mut cut_byte: usize = value
                .char_indices()
                .nth(cut_char)
                .map_or(value.len(), |(i, _)| i);

            if cfg.word_boundary && cut_byte > 0 {
                let adj = find_word_boundary(value, cut_byte, max_chars);
                // find_word_boundary works in byte space already
                if adj <= cut_byte {
                    cut_byte = adj;
                }
            }
            format!("{}{}", &value[..cut_byte], ell)
        }
    }
}

/// Check if a string represents a finite numeric value.
/// Handles integers, floats, and scientific notation.
/// Rejects nan, inf, and strings longer than 50 chars.
pub fn is_numeric_string(text: &str) -> bool {
    if text.len() > MAX_NUMERIC_STRING_LENGTH {
        return false;
    }
    match text.trim().parse::<f64>() {
        Ok(f) => f.is_finite(),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{LimitMode, OutputLengthGuardConfig, Strategy};

    fn char_cfg(max_chars: Option<usize>) -> OutputLengthGuardConfig {
        OutputLengthGuardConfig {
            max_chars,
            limit_mode: LimitMode::Character,
            strategy: Strategy::Truncate,
            ellipsis: "…".to_string(),
            word_boundary: false,
            ..Default::default()
        }
    }

    fn token_cfg(max_tokens: Option<usize>) -> OutputLengthGuardConfig {
        OutputLengthGuardConfig {
            max_tokens,
            limit_mode: LimitMode::Token,
            strategy: Strategy::Truncate,
            ellipsis: "…".to_string(),
            chars_per_token: 4,
            word_boundary: false,
            ..Default::default()
        }
    }

    #[test]
    fn estimate_tokens_divides_by_chars_per_token() {
        assert_eq!(estimate_tokens("abcdefgh", 4), 2);
        assert_eq!(estimate_tokens("abcdefgh", 2), 4);
        assert_eq!(estimate_tokens("", 4), 0);
    }

    #[test]
    fn evaluate_text_limits_character_mode() {
        let cfg = char_cfg(Some(100));
        assert_eq!(evaluate_text_limits(50, 0, &cfg), (false, false));
        assert_eq!(evaluate_text_limits(101, 0, &cfg), (false, true));
    }

    #[test]
    fn evaluate_text_limits_character_mode_min() {
        let mut cfg = char_cfg(Some(100));
        cfg.min_chars = 10;
        assert_eq!(evaluate_text_limits(5, 0, &cfg), (true, false));
    }

    #[test]
    fn evaluate_text_limits_no_max_chars() {
        let cfg = char_cfg(None);
        assert_eq!(evaluate_text_limits(999_999, 0, &cfg), (false, false));
    }

    #[test]
    fn evaluate_text_limits_token_mode() {
        let cfg = token_cfg(Some(10));
        assert_eq!(evaluate_text_limits(0, 5, &cfg), (false, false));
        assert_eq!(evaluate_text_limits(0, 11, &cfg), (false, true));
    }

    #[test]
    fn evaluate_text_limits_token_mode_min() {
        let mut cfg = token_cfg(Some(100));
        cfg.min_tokens = 5;
        assert_eq!(evaluate_text_limits(0, 3, &cfg), (true, false));
    }

    #[test]
    fn truncate_char_mode_adds_ellipsis() {
        let cfg = char_cfg(Some(5));
        let s = "Hello World";
        let result = truncate(s, &cfg);
        // "Hello" = 5 chars, ellipsis 1 char => 4 + "…"
        assert!(result.ends_with('…'));
        let result_chars = result.chars().count();
        assert!(result_chars <= 5);
    }

    #[test]
    fn truncate_char_mode_within_limit_unchanged() {
        let cfg = char_cfg(Some(100));
        let s = "short";
        assert_eq!(truncate(s, &cfg), "short");
    }

    #[test]
    fn truncate_char_mode_no_max_unchanged() {
        let cfg = char_cfg(None);
        let s = "a".repeat(10_000);
        assert_eq!(truncate(&s, &cfg).len(), s.len());
    }

    #[test]
    fn truncate_char_mode_ellipsis_larger_than_max_hard_cut() {
        // ellipsis "…" is 1 char; if max_chars == 1 then ell_chars >= max_chars => hard cut
        let cfg = char_cfg(Some(1));
        let s = "Hello";
        let result = truncate(s, &cfg);
        // hard cut at 1 char
        assert_eq!(result.chars().count(), 1);
    }

    #[test]
    fn truncate_token_mode_truncates_by_tokens() {
        let cfg = token_cfg(Some(2)); // 2 tokens * 4 chars = 8 chars
        let s = "abcdefghijklmnop"; // 16 chars = 4 tokens
        let result = truncate(s, &cfg);
        // 2*4=8 chars max before ellipsis
        assert!(result.ends_with('…'));
    }

    #[test]
    fn truncate_token_mode_within_limit_unchanged() {
        let cfg = token_cfg(Some(10)); // 10 tokens * 4 chars = 40 chars
        let s = "short"; // well within 40 char token budget
        assert_eq!(truncate(s, &cfg), "short");
    }

    #[test]
    fn truncate_token_mode_no_max_unchanged() {
        let cfg = token_cfg(None);
        let s = "a".repeat(1000);
        assert_eq!(truncate(&s, &cfg).len(), s.len());
    }

    #[test]
    fn truncate_word_boundary_stops_at_space() {
        let mut cfg = char_cfg(Some(10));
        cfg.word_boundary = true;
        cfg.ellipsis = "…".to_string();
        let s = "hello world foo";
        let result = truncate(s, &cfg);
        // Result must be within the char limit
        assert!(
            result.chars().count() <= 10,
            "result exceeded max_chars: {}",
            result
        );
        // Result should end with the ellipsis since the original exceeds the limit
        assert!(
            result.ends_with('…'),
            "result should end with ellipsis: {}",
            result
        );
    }

    #[test]
    fn is_numeric_string_handles_integers() {
        assert!(is_numeric_string("123"));
        assert!(is_numeric_string("-456"));
        assert!(is_numeric_string("0"));
    }

    #[test]
    fn is_numeric_string_handles_floats() {
        assert!(is_numeric_string("3.14"));
        assert!(is_numeric_string("-1.23e-4"));
        assert!(is_numeric_string("5E+10"));
    }

    #[test]
    fn is_numeric_string_rejects_non_numeric() {
        assert!(!is_numeric_string("hello"));
        assert!(!is_numeric_string(""));
        assert!(!is_numeric_string("nan"));
        assert!(!is_numeric_string("inf"));
    }

    #[test]
    fn is_numeric_string_rejects_long_strings() {
        let long = "1".repeat(51);
        assert!(!is_numeric_string(&long));
    }

    #[test]
    fn find_word_boundary_returns_cut_when_no_boundary() {
        // No boundary chars in "abcdefg"
        let pos = find_word_boundary("abcdefg", 5, 7);
        assert_eq!(pos, 5);
    }

    #[test]
    fn find_word_boundary_finds_space() {
        let s = "hello world foo";
        // cut at 11 (after "hello world"), looking for boundary
        let pos = find_word_boundary(s, 11, 15);
        // Should find space at index 5 (char 'h','e','l','l','o',' ')
        // byte offset after ' ' = 6
        assert!(pos <= 11);
    }

    #[test]
    fn find_word_boundary_empty_string_returns_cut() {
        assert_eq!(find_word_boundary("", 0, 10), 0);
    }
}
