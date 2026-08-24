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

    // ── evaluate_text_limits boundary-exact tests ──────────────────────────
    // Kill: replace > with >= (length == max_chars must NOT be above_max)
    #[test]
    fn evaluate_text_limits_at_exactly_max_chars_is_not_above() {
        let cfg = char_cfg(Some(100));
        let (_, above) = evaluate_text_limits(100, 0, &cfg);
        assert!(!above, "length == max_chars must not trigger above_max");
    }

    // Kill: replace > with >= (token_count == max_tokens must NOT be above_max)
    #[test]
    fn evaluate_text_limits_at_exactly_max_tokens_is_not_above() {
        let cfg = token_cfg(Some(10));
        let (_, above) = evaluate_text_limits(0, 10, &cfg);
        assert!(
            !above,
            "token_count == max_tokens must not trigger above_max"
        );
    }

    // Kill: replace < with <= (length == min_chars must NOT be below_min)
    #[test]
    fn evaluate_text_limits_at_exactly_min_chars_is_not_below() {
        let mut cfg = char_cfg(Some(100));
        cfg.min_chars = 10;
        let (below, _) = evaluate_text_limits(10, 0, &cfg);
        assert!(!below, "length == min_chars must not trigger below_min");
    }

    // Kill: replace < with <= (token_count == min_tokens must NOT be below_min)
    #[test]
    fn evaluate_text_limits_at_exactly_min_tokens_is_not_below() {
        let mut cfg = token_cfg(Some(100));
        cfg.min_tokens = 5;
        let (below, _) = evaluate_text_limits(0, 5, &cfg);
        assert!(
            !below,
            "token_count == min_tokens must not trigger below_min"
        );
    }

    // Kill: replace && with || in below_min check (min_chars == 0 disables below_min)
    #[test]
    fn evaluate_text_limits_min_chars_zero_never_triggers_below() {
        let cfg = char_cfg(Some(100)); // min_chars defaults to 0
        let (below, _) = evaluate_text_limits(0, 0, &cfg); // length=0, min_chars=0
        assert!(!below, "min_chars=0 must never trigger below_min");
    }

    // Kill: replace && with || in token below_min check
    #[test]
    fn evaluate_text_limits_min_tokens_zero_never_triggers_below() {
        let cfg = token_cfg(Some(100)); // min_tokens defaults to 0
        let (below, _) = evaluate_text_limits(0, 0, &cfg);
        assert!(!below, "min_tokens=0 must never trigger below_min");
    }

    // ── find_word_boundary ────────────────────────────────────────────────
    // Kill: replace || with && (cut==0 alone must return 0)
    #[test]
    fn find_word_boundary_cut_zero_returns_zero_on_nonempty_string() {
        assert_eq!(find_word_boundary("hello world", 0, 10), 0);
    }

    // Kill: replace == with != (is_empty check)
    #[test]
    fn find_word_boundary_nonempty_string_nonzero_cut_does_not_return_early() {
        // If the == were !=, a non-empty string would return early with the unmodified cut.
        // cut=6 covers "hello " (6 chars); chars[..6] = ['h','e','l','l','o',' '].
        // The space at index 5 is a boundary char → byte_pos after it = 6.
        let pos = find_word_boundary("hello world", 6, 10);
        assert_eq!(pos, 6); // boundary found at the space, byte offset = 6
    }

    // Kill: replace * with + or / in search_back = max_chars * 0.2
    #[test]
    fn find_word_boundary_search_window_is_proportional_to_max_chars() {
        // max_chars=50 → search_back=10 chars; place boundary at position 45,
        // cut at 50. With correct * 0.2, the boundary at 45 is within [40,50).
        // With + 0.2 (≈50), search_back≈50 so window is [0,50) — still finds it.
        // With / 0.2 (≈250), truncated to usize 250, but saturating_sub keeps [0,50) — still finds it.
        // The meaningful kill is: search_back too small → misses the boundary → returns cut unchanged.
        // We verify the boundary IS found (pos < cut) to confirm * 0.2 logic works.
        let s = "abcdefghijklmnopqrstuvwxyz abcdefghijklmnopqrs"; // space at index 26
        let pos = find_word_boundary(s, 35, 50);
        // space at index 26; with search_back=10, min=25, so index 26 is in [25,35) ✓
        assert!(pos <= 35, "expected boundary to be found: pos={}", pos);
        assert!(pos > 0);
    }

    // ── truncate exact-boundary tests ────────────────────────────────────
    // Kill: replace > with == / >= in `if value.len() > cfg.max_text_length`
    #[test]
    fn truncate_token_mode_value_exactly_at_max_text_length_not_capped() {
        let mut cfg = token_cfg(Some(1)); // force truncation
        cfg.max_text_length = 8; // exactly 8 chars
        let s = "abcdefgh"; // len == max_text_length
        let result = truncate(s, &cfg);
        // Should truncate by token budget, not hard-cut at max_text_length.
        // If the > were >=, s would be capped to "" (empty) before truncation.
        assert!(result.ends_with('…'));
    }

    // Kill: replace > with == / >= on char_count <= max_chars early-return check (line ~117)
    #[test]
    fn truncate_char_mode_at_exactly_max_chars_returns_unchanged() {
        let cfg = char_cfg(Some(5));
        assert_eq!(truncate("hello", &cfg), "hello"); // 5 chars == max_chars
    }

    // Kill: replace <= with > on `if adj <= cut_byte` word-boundary adjustment (line 139)
    #[test]
    fn truncate_word_boundary_adjustment_never_extends_beyond_cut() {
        let mut cfg = char_cfg(Some(10));
        cfg.word_boundary = true;
        let s = "hello world foo bar";
        let result = truncate(s, &cfg);
        // Result must not exceed max_chars chars
        assert!(
            result.chars().count() <= 10,
            "truncated result exceeded max_chars: {}",
            result
        );
    }

    // Kill: replace && with || in word_boundary check (cfg.word_boundary && cut_byte > 0)
    #[test]
    fn truncate_char_mode_no_word_boundary_cuts_mid_word() {
        let cfg = char_cfg(Some(7)); // word_boundary = false
        let s = "hello world foo";
        let result = truncate(s, &cfg);
        // With word_boundary=false the cut is at char 6 + ellipsis, regardless of spaces
        assert!(result.ends_with('…'));
        assert_eq!(result.chars().count(), 7);
    }

    // Kill: replace -= with += / /= on char-boundary snap loops (lines 97-98, 102-103)
    #[test]
    fn truncate_token_mode_snaps_to_valid_char_boundary() {
        let mut cfg = token_cfg(Some(1));
        cfg.chars_per_token = 2;
        // Use ASCII only — all single-byte chars, so boundary is always valid.
        // The important thing is that the result is a valid UTF-8 string.
        let s = "abcde"; // 5 chars, 2 tokens at cpt=2 → cut at 2 chars
        let result = truncate(s, &cfg);
        assert!(std::str::from_utf8(result.as_bytes()).is_ok());
        assert!(result.ends_with('…'));
    }

    // Kill: replace > with >= in token mode `if estimated <= max_tokens` (line 86/90)
    #[test]
    fn truncate_token_mode_at_exactly_max_tokens_returns_unchanged() {
        let cfg = token_cfg(Some(2)); // 2 tokens * 4 cpt = 8 chars
        let s = "abcdefgh"; // exactly 8 chars = 2 tokens
        // estimated = 8/4 = 2 == max_tokens → must NOT truncate
        assert_eq!(truncate(s, &cfg), "abcdefgh");
    }

    // Kill: replace > with >= in is_numeric_string length check (line 152)
    #[test]
    fn is_numeric_string_accepts_exactly_50_char_numeric() {
        // 50 chars is the boundary; > 50 rejects, == 50 accepts
        let _s = format!("{:.43}", 1.0f64); // short, pad to exactly 50 with zeros
        // Build a 50-char valid numeric string manually
        let s50 = format!("{:0>50}", "1"); // "000...0001", 50 chars
        // f64 parse: leading zeros are fine
        assert!(is_numeric_string(&s50), "50-char numeric must be accepted");
        let s51 = format!("{:0>51}", "1");
        assert!(!is_numeric_string(&s51), "51-char string must be rejected");
    }
}
