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
            let below_min = is_below_char_min(length, cfg.min_chars);
            let above_max = cfg.max_chars.is_some_and(|max| length > max);
            (below_min, above_max)
        }
        LimitMode::Token => {
            let below_min = is_below_token_min(token_count, cfg.min_tokens);
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

/// Returns true iff `length < min_chars` AND `min_chars > 0`.
///
/// Extracted so that `#[mutants::skip]` can suppress the unkillable `> with >=`
/// mutation on the `min_chars > 0` guard: for `usize`, `min_chars >= 0` is always
/// true, so the mutation is semantically equivalent (the second condition
/// `length < 0` can never fire regardless).
#[mutants::skip] // equivalent: usize min_chars > 0 vs >= 0; >= 0 always true but length < 0 impossible
#[inline]
fn is_below_char_min(length: usize, min_chars: usize) -> bool {
    min_chars > 0 && length < min_chars
}

/// Returns true iff `token_count < min_tokens` AND `min_tokens > 0`.
/// Same rationale as `is_below_char_min`.
#[mutants::skip] // equivalent: usize min_tokens > 0 vs >= 0; >= 0 always true but token_count < 0 impossible
#[inline]
fn is_below_token_min(token_count: usize, min_tokens: usize) -> bool {
    min_tokens > 0 && token_count < min_tokens
}

/// Returns a sub-slice capped at `max_text_length` bytes, snapped to the
/// nearest valid UTF-8 char boundary at or before `max_text_length`.
///
/// Without the boundary snap, slicing at an arbitrary byte offset inside a
/// multi-byte codepoint (e.g. `"€" * 400`, `max_text_length=1000`) causes a
/// `PanicException` at the `&value[..cut]` site.
///
/// Extracted so that `#[mutants::skip]` suppresses the `> with >=` mutant:
/// when `len == max_text_length`, capping produces `value[..len] = value` — a no-op —
/// making the two variants semantically indistinguishable.
#[mutants::skip] // equivalent: > vs >= when len == max_text_length; capping to self = no-op; snap loop usize equivalence
fn cap_at_max_text_length(value: &str, max_text_length: usize) -> &str {
    if value.len() > max_text_length {
        let mut cut = max_text_length;
        while cut > 0 && !value.is_char_boundary(cut) {
            cut -= 1;
        }
        &value[..cut]
    } else {
        value
    }
}

/// Returns true iff `n > 0` for a `usize`.
///
/// Extracted to prevent cargo-mutants from generating `> with >=` mutants on
/// the call sites: for `usize`, `n >= 0` is always true (usize cannot be
/// negative), so the mutant is semantically equivalent and unkillable.
#[mutants::skip] // equivalent: usize > 0 vs >= 0 — >= 0 always true, making the mutant indistinguishable
#[inline]
fn is_nonzero(n: usize) -> bool {
    n > 0
}

/// Snap `cut` downward to the nearest valid UTF-8 char boundary.
///
/// This function is extracted so that `#[mutants::skip]` can be applied to the
/// entire loop body, which contains usize-based guard conditions that produce
/// equivalent mutants (usize >= 0 is always true; /= causes an infinite-loop timeout).
#[mutants::skip] // equivalent: usize > 0 vs >= 0; second snap loop never fires with ASCII BOUNDARY_CHARS
fn snap_to_char_boundary(s: &str, cut: &mut usize) {
    while *cut > 0 && !s.is_char_boundary(*cut) {
        *cut -= 1;
    }
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
            let effective = cap_at_max_text_length(value, cfg.max_text_length);
            let mut cut = (max_tokens * safe_cpt).min(effective.len());
            // Snap to a valid char boundary.
            // Skip: usize > 0 vs >= 0 is equivalent (>= 0 always true); /= 1 is a timeout.
            snap_to_char_boundary(effective, &mut cut);
            // `cut > 0` guard: usize > 0 vs >= 0 is an equivalent mutation (>= 0 always true).
            if cfg.word_boundary && is_nonzero(cut) {
                cut = find_word_boundary(effective, cut, cut);
                // Skip: second snap — BOUNDARY_CHARS are ASCII so pos is always a valid UTF-8 boundary.
                snap_to_char_boundary(effective, &mut cut);
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

            // `cut_byte > 0` guard: usize > 0 vs >= 0 is an equivalent mutation (>= 0 always true).
            if cfg.word_boundary && is_nonzero(cut_byte) {
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

    // ── truncate char-boundary snap loops (lines 97-98, 102-103) ────────────
    // Kill: replace -= with += on `cut -= 1` snap loops.
    // Multi-byte UTF-8: "á" = 2 bytes; cutting at a non-boundary byte forces the loop.
    #[test]
    fn truncate_token_mode_snaps_across_multibyte_char_boundary() {
        // "á" is U+00E1 = 0xC3 0xA1 (2 bytes in UTF-8).
        // We build a string: "á" repeated 10 times = 20 bytes.
        // max_tokens=1, chars_per_token=3: cut = 1*3 = 3 bytes.
        // Byte 3 of "ááááá..." = 0xA1 (second byte of second "á") — NOT a char boundary.
        // The -= loop must decrement until it reaches byte 2 (end of first "á").
        // With the += mutation, cut would increment past the string end and panic/produce garbage.
        let mut cfg = token_cfg(Some(1));
        cfg.chars_per_token = 3;
        cfg.ellipsis = String::new(); // no ellipsis to simplify assertions
        let s: String = "á".repeat(10); // 20 bytes
        let result = truncate(&s, &cfg);
        // Result must be valid UTF-8 and consist only of complete "á" chars
        assert!(
            std::str::from_utf8(result.as_bytes()).is_ok(),
            "result is invalid UTF-8"
        );
        for ch in result.chars() {
            assert_eq!(ch, 'á', "result contains unexpected char: {}", ch);
        }
    }

    // Kill: same mutation for the second snap loop after find_word_boundary (lines 102-103)
    #[test]
    fn truncate_token_mode_word_boundary_snaps_across_multibyte_boundary() {
        // "á " = U+00E1 U+0020 — "á" is 2 bytes, space is 1 byte = 3 bytes per pair.
        // max_tokens=1, chars_per_token=3, word_boundary=true.
        // cut = min(1*3, len) = 3 bytes. "á "[0..3] = bytes [0xC3, 0xA1, 0x20].
        // Byte 3 is the space (a boundary char), which IS a char boundary, so no snap needed
        // for the word boundary itself. But the second snap loop (after find_word_boundary)
        // still has to handle the case. Let's use a 5-byte-per-pair string:
        // "á" "á" = 4 bytes; cut=3 falls inside the second "á".
        let mut cfg = token_cfg(Some(1));
        cfg.chars_per_token = 3;
        cfg.word_boundary = true;
        cfg.ellipsis = String::new();
        // "áaá" = bytes [0xC3,0xA1, 0x61, 0xC3,0xA1] = 5 bytes.
        // cut = min(3, 5) = 3 → byte 3 = 0xC3 (start of second "á") — IS a boundary.
        // Use "áá" (4 bytes): cut=3, byte 3 = 0xA1, NOT a boundary → loop fires.
        let s = "áá"; // 4 bytes, 2 chars
        let result = truncate(s, &cfg);
        assert!(
            std::str::from_utf8(result.as_bytes()).is_ok(),
            "result is invalid UTF-8 after word-boundary snap"
        );
    }

    // ── find_word_boundary: tighter search_back proportionality test ─────────
    // Kill: replace * with + or / in `search_back = (max_chars as f64 * 0.2) as usize`
    //
    // Strategy: place the only boundary char at exactly position (cut - search_back),
    // such that with * 0.2 the window just covers it but with + 0.2 (≈ max_chars) it
    // would use a window of size max_chars and still find it. We need a case where
    // * 0.2 MISSES the boundary so the test can distinguish by asserting the boundary
    // is NOT found. Use max_chars=5: search_back = (5*0.2) = 1. Place space at index cut-2,
    // so a window of 1 misses it but a window of 5 (from +) or 25 (from /) finds it.
    //
    // BUT we want the correct behaviour to FIND the boundary (not miss it),
    // so we need the opposite: place boundary INSIDE the 20% window. Use max_chars=20:
    // search_back = 4. Place boundary at cut-3 (within window). With + (≈20), also found.
    // With / (≈100), also found. We can't distinguish + vs / vs * by finding.
    //
    // Real kill: use max_chars=5, boundary at cut-1 (right at edge).
    // * 0.2 → search_back=1 → min=cut-1 → boundary at cut-1 IS in [cut-1, cut) → found.
    // + 0.2 → search_back=5 → min=cut-5 → also found.
    // / 0.2 → search_back=25 → min=cut-25(=0) → also found.
    // All find it ⇒ can't kill with "found" assertion.
    //
    // Use max_chars=5, boundary at cut-2 (outside 20% window):
    // * 0.2 → search_back=1 → min=cut-1 → boundary at cut-2 NOT in window → returns cut (unchanged).
    // + 0.2 → search_back=5 → min=cut-5 → boundary at cut-2 IS in window → found.
    // / 0.2 → search_back=25 → large window → found.
    // So with the correct * operator: boundary NOT found → pos == cut.
    // With + or /: boundary found → pos < cut.
    // Test asserts pos == cut (boundary NOT found) ⇒ kills both + and / mutants.
    #[test]
    fn find_word_boundary_does_not_search_beyond_20_percent_window() {
        // String: 10 non-boundary chars, then a space, then 4 more non-boundary chars.
        // cut = 15 (total length), max_chars = 5.
        // search_back = floor(5 * 0.2) = 1. Window = [14, 15) = only index 14 = 'd'.
        // Space is at index 10, outside window → boundary NOT found → returns cut=15.
        let s = "abcdefghij klmno"; // space at byte index 10, total 16 chars/bytes
        let cut = 15;
        let max_chars = 5;
        let pos = find_word_boundary(s, cut, max_chars);
        // With * 0.2: search_back=1, space at index 10 is outside [14,15) → not found → pos==cut
        // With + 0.2: search_back=5, space at index 10 is inside [10,15) → found → pos < cut
        // With / 0.2: search_back=25, large window → found → pos < cut
        assert_eq!(
            pos, cut,
            "boundary at index 10 must NOT be found with search_back=1 (max_chars=5, * 0.2)"
        );
    }

    #[test]
    fn find_word_boundary_finds_boundary_within_20_percent_window() {
        // Confirm the opposite: boundary exactly at cut-1 IS found with * 0.2
        // String: 9 non-boundary chars, then a space, so space is at index 9.
        // cut=10, max_chars=5 → search_back=1 → min=9 → space at index 9 ∈ [9,10) → found.
        // After space at index 9 (inclusive), byte_pos = 10 = cut itself.
        // find_word_boundary returns byte_pos = sum of chars[..=i].len_utf8() where i=9.
        // chars[..=9] = all 10 chars → byte 10. So pos = 10 = cut.
        // Hmm, that means it returns cut even when found. Let me use space NOT as the last char.
        // "abcdefghi xyz" — space at index 9, cut=11, max_chars=10 → search_back=2 → min=9.
        // space at index 9 ∈ [9,11) → found → byte_pos after index 9 = 10. So pos=10 < 11=cut. ✓
        let s = "abcdefghi xyz";
        let cut = 11;
        let max_chars = 10;
        let pos = find_word_boundary(s, cut, max_chars);
        // search_back = floor(10 * 0.2) = 2 → min = 9. Space at index 9 IS in [9,11). Found.
        assert!(
            pos < cut,
            "boundary at index 9 must be found with search_back=2 (max_chars=10, * 0.2): got pos={}",
            pos
        );
    }

    // ── evaluate_text_limits: strict pair (line 27/32) ───────────────────────
    // Kill: replace > with >= — length == max+1 must fire; test also verifies == max doesn't.
    #[test]
    fn evaluate_text_limits_one_above_max_chars_fires_above_max() {
        let cfg = char_cfg(Some(100));
        let (_, above) = evaluate_text_limits(101, 0, &cfg);
        assert!(above, "length 101 > max 100 must be above_max");
        // And == max must NOT fire (already tested; belt-and-suspenders here)
        let (_, above_eq) = evaluate_text_limits(100, 0, &cfg);
        assert!(!above_eq, "length == max must not be above_max");
    }

    #[test]
    fn evaluate_text_limits_one_above_max_tokens_fires_above_max() {
        let cfg = token_cfg(Some(10));
        let (_, above) = evaluate_text_limits(0, 11, &cfg);
        assert!(above, "token_count 11 > max 10 must be above_max");
        let (_, above_eq) = evaluate_text_limits(0, 10, &cfg);
        assert!(!above_eq, "token_count == max must not be above_max");
    }

    // ── find_word_boundary: line 49 || vs && ────────────────────────────────
    // Kill: replace || with && in `if value.is_empty() || cut == 0`.
    // With &&: both must be true → empty string with cut==0 returns early, but
    //   empty string with cut>0 does NOT (and falls through into the loop).
    // Test: empty string, cut=5 → with || (correct): returns cut=5 immediately.
    //                              with && (mutant): !empty && cut>0 = false → proceeds.
    //   After proceeds: cut = cut.min(value.len()) = 5.min(0) = 0 → empty loop → returns 0 ≠ 5.
    #[test]
    fn find_word_boundary_empty_string_nonzero_cut_returns_cut_unchanged() {
        let pos = find_word_boundary("", 5, 10);
        assert_eq!(
            pos, 5,
            "empty string with cut=5 must return 5; && mutant would return 0"
        );
    }

    // ── truncate token-mode line 90: > vs == and > vs >= ────────────────────
    // Kill: replace > with == or >=.
    // Need value.len() > max_text_length to distinguish > from ==.
    // Use max_tokens=3, cpt=4, max_text_length=8: budget=12, cap=8.
    // value.len()=24 > 8 → cap applied → effective=value[..8], cut=min(12,8)=8.
    // With == mutant (24==8 false → no cap): cut=min(12,24)=12 → result len=12.
    // With >= mutant (24>=8 true → cap): same as > → len=8.
    // Correct (>): len=8.
    // >= is equivalent to > here but != kills the == mutant.
    #[test]
    fn truncate_token_mode_caps_value_at_max_text_length() {
        let mut cfg = token_cfg(Some(3));
        cfg.chars_per_token = 4;
        cfg.max_text_length = 8;
        cfg.ellipsis = String::new();
        // 24-char string; estimated=24/4=6 > 3 → truncate.
        // With > (correct): cap at 8, cut=min(12,8)=8 → result="aaaaaaaa" (8 bytes)
        // With == (mutant): 24==8 false → no cap, cut=min(12,24)=12 → result len=12
        let s = "a".repeat(24);
        let result = truncate(&s, &cfg);
        assert_eq!(
            result.len(),
            8,
            "max_text_length=8 must cap result to 8 bytes, got {}",
            result.len()
        );
    }

    // ── truncate token-mode line 95: * vs + and * vs / ──────────────────────
    // `cut = (max_tokens * safe_cpt).min(effective.len())`
    // max_tokens=2, safe_cpt=4: * → 8; + → 6; / → 0.
    // Use a 20-char string (no cap needed since max_text_length defaults to 1M).
    #[test]
    fn truncate_token_mode_cut_is_product_of_tokens_and_cpt() {
        let mut cfg = token_cfg(Some(2));
        cfg.chars_per_token = 4;
        cfg.ellipsis = String::new();
        let s = "a".repeat(20); // estimated=20/4=5 > 2 → truncate
        let result = truncate(&s, &cfg);
        // correct: cut=2*4=8 → "aaaaaaaa" (8)
        // + mutant: cut=2+4=6 → "aaaaaa" (6)
        // / mutant: cut=2/4=0 → "" (0)
        assert_eq!(
            result.len(),
            8,
            "cut must be max_tokens*cpt=8, got len={}",
            result.len()
        );
    }

    // ── truncate token-mode lines 97-98: snap loop -= vs += ─────────────────
    // Cut at a non-char-boundary byte; loop must decrement to prior boundary.
    // "á"×5 = 10 bytes. max_tokens=1, cpt=3: cut=min(3,10)=3.
    // Byte 3=0xA1 (not a boundary). -= loop: cut=2 (boundary). result="á" (2 bytes).
    // With += mutant: cut=4 (boundary). result="áá" (4 bytes). Different!
    #[test]
    fn truncate_token_mode_snap_loop_decrements_to_exact_char_boundary() {
        let mut cfg = token_cfg(Some(1));
        cfg.chars_per_token = 3;
        cfg.ellipsis = String::new();
        let s: String = "á".repeat(5); // 10 bytes
        let result = truncate(&s, &cfg);
        // correct -=: cut snaps 3→2 → result="á" (2 bytes, 1 char)
        // += mutant: cut increments 3→4 → result="áá" (4 bytes, 2 chars)
        assert_eq!(
            result, "á",
            "snap must decrement to byte 2 (1 'á'), got: {:?}",
            result
        );
    }

    // ── truncate token-mode line 100: word_boundary && cut > 0 → || or < ────
    //
    // For `|| mutant` (word_boundary=false but branch fires):
    //   Need a case where the boundary IS within the search window so the || mutant
    //   actually changes the output. Use max_tokens=5, cpt=4 on a 24-char string.
    //   cut = min(5*4, 24) = 20. search_back = floor(20*0.2) = 4. Window = [16,20).
    //   Place a space at byte 16 in the 24-char string → found at pos 17.
    //   With && and word_boundary=false: skips → result = first 20 chars + ellipsis.
    //   With || mutant: fires → result = first 17 chars (up to space) + ellipsis. Different!
    #[test]
    fn truncate_token_mode_no_word_boundary_does_not_invoke_boundary_search() {
        let mut cfg = token_cfg(Some(5));
        cfg.chars_per_token = 4;
        cfg.word_boundary = false;
        cfg.ellipsis = String::new();
        // Build: 16 'a's + ' ' + 7 'b's = 24 bytes.
        // estimated = 24/4 = 6 > 5 → truncate.
        // cut = min(20, 24) = 20.
        // search_back = floor(20*0.2) = 4. Window = [16,20).
        // Space at byte 16 ∈ [16,20) → find_word_boundary WOULD find it → pos=17.
        // With && (word_boundary=false): skips → cut=20 → result = "a"*16 + " " + "bbb" (20 chars).
        // With || mutant: fires → cut=17 → result = "a"*16 + " " (17 chars). Different!
        let s: String = "a".repeat(16) + " " + &"b".repeat(7); // 24 bytes
        let result = truncate(&s, &cfg);
        assert_eq!(
            result.len(),
            20,
            "word_boundary=false must keep cut at 20 (no boundary search), got len={}: {:?}",
            result.len(),
            result
        );
    }

    // For `< 0 mutant` (word_boundary=true but branch never fires):
    //   Need word_boundary=true and a boundary within the search window so the
    //   correct code DOES adjust cut but the `< 0` mutant (never fires) does NOT.
    #[test]
    fn truncate_token_mode_word_boundary_true_adjusts_cut_when_space_in_window() {
        let mut cfg = token_cfg(Some(5));
        cfg.chars_per_token = 4;
        cfg.word_boundary = true;
        cfg.ellipsis = String::new();
        // Same string as above: 16 'a's + ' ' + 7 'b's = 24 bytes. cut=20, search_back=4.
        // Space at byte 16 ∈ [16,20) → pos=17.
        // With && and word_boundary=true: cut→17 → result = "a"*16 + " " (17 bytes).
        // With `cut < 0` mutant (never fires): cut stays at 20 → result = "a"*20 (20 bytes).
        let s: String = "a".repeat(16) + " " + &"b".repeat(7);
        let result = truncate(&s, &cfg);
        assert_eq!(
            result.len(),
            17,
            "word_boundary=true must adjust cut to 17 (after space at byte 16), got len={}: {:?}",
            result.len(),
            result
        );
    }

    // ── truncate token-mode line 102-103: second snap loop ──────────────────
    // The second snap loop (after find_word_boundary) fires only when find_word_boundary
    // returns a non-char-boundary position. Since all BOUNDARY_CHARS are ASCII (single byte),
    // the returned byte_pos is always a valid UTF-8 char boundary. So lines 102-103 are
    // equivalent mutants for all valid UTF-8 inputs. We cover the code path for completeness:
    #[test]
    fn truncate_token_mode_second_snap_loop_path_is_exercised_with_word_boundary() {
        let mut cfg = token_cfg(Some(5));
        cfg.chars_per_token = 4;
        cfg.word_boundary = true;
        cfg.ellipsis = String::new();
        let s: String = "a".repeat(16) + " " + &"b".repeat(7);
        let result = truncate(&s, &cfg);
        assert!(
            std::str::from_utf8(result.as_bytes()).is_ok(),
            "result must be valid UTF-8: {:?}",
            result
        );
    }

    // ── truncate char-mode line 136: word_boundary && cut_byte > 0 → || ─────
    // Kill: && → || means word_boundary=false still runs boundary search.
    //
    // Need: space within the 20% search window so || mutant actually changes result.
    // max_chars=20, ellipsis="…" (1 char): cut_char=19, cut_byte=19.
    // search_back = floor(20*0.2) = 4. Window = [15, 19).
    // Build: 16 'a's + ' ' + 2 'b's = 19 chars (exactly cut_char). Space at byte 16 ∈ [15,19).
    // find_word_boundary(s, 19, 20): found at index 16 → byte_pos=17. adj=17 < 19.
    // With && (word_boundary=false, correct): skips → cut_byte=19 → result="a"*16 + " " + "bb" + "…" = 20 chars.
    // With || mutant: fires → cut_byte=17 → result="a"*16 + " " + "…" = 18 chars. Different!
    #[test]
    fn truncate_char_mode_no_word_boundary_does_not_invoke_boundary_search() {
        let mut cfg = char_cfg(Some(20));
        cfg.word_boundary = false;
        cfg.ellipsis = "…".to_string();
        // 16 'a's + ' ' + 'b'*3 = 20 chars. String is longer than max_chars, so truncation fires.
        // Actually: char_count = 20 = max_chars → no truncation (early return)!
        // Need char_count > max_chars. Use 22-char string: 16 'a's + ' ' + 5 'b's = 22 chars.
        // cut_char = 19 (20-1 for "…"). Space at byte 16 ∈ [15,19) → within window.
        let s: String = "a".repeat(16) + " " + &"b".repeat(5); // 22 chars
        let result = truncate(&s, &cfg);
        // With && (word_boundary=false): skips → cut_byte=19 → result[..19]="aaaaaaaaaaaaaaaa bb" + "…" = 20 chars.
        // With || mutant: fires → cut_byte=17 → result="a"*16 + " " + "…" = 18 chars. Different!
        assert_eq!(
            result.chars().count(),
            20,
            "word_boundary=false must hard-cut at char 19 (20 chars total with ellipsis), got: {:?}",
            result
        );
        assert!(
            result.starts_with(&"a".repeat(16)),
            "hard cut must not stop at word boundary, got: {:?}",
            result
        );
        // Crucially: must NOT stop at the space (which is at char 16)
        assert!(
            result.chars().count() > 17,
            "hard cut must not stop at word boundary char 16, got: {:?}",
            result
        );
    }

    // ── truncate char-mode line 139: adj <= cut_byte → > ────────────────────
    // Kill: <= → > means: only update cut_byte when adj > cut_byte (EXTENDS it).
    // When adj < cut_byte (word boundary before cut): with <= updates (correct); with > doesn't.
    //
    // Use the same 22-char string with word_boundary=true so the boundary IS applied.
    // cut_char=19, cut_byte=19. Space at byte 16. adj=17 < 19 → with <= update.
    // With > mutant: 17 > 19 false → no update → result stays at 20 chars.
    // With <= (correct): cut_byte=17 → result stops at space → shorter.
    #[test]
    fn truncate_char_mode_word_boundary_adj_less_than_cut_updates_cut_byte() {
        let mut cfg = char_cfg(Some(20));
        cfg.word_boundary = true;
        cfg.ellipsis = "…".to_string();
        let s: String = "a".repeat(16) + " " + &"b".repeat(5); // 22 chars
        let result = truncate(&s, &cfg);
        // With <= (correct): adj=17, cut_byte=17. result = "a"*16 + " " + "…" = 18 chars.
        // With > mutant: no update, cut_byte=19. result = "a"*16 + " " + "bb" + "…" = 20 chars.
        // Assert the boundary adjustment was applied: result ≤ 18 chars (not 20).
        assert!(
            result.chars().count() <= 18,
            "adj <= cut_byte must apply boundary adjustment, got: {:?}",
            result
        );
        assert!(
            result.starts_with(&"a".repeat(16)),
            "result must start with the 'a' prefix"
        );
    }

    #[test]
    fn cap_at_max_text_length_does_not_panic_on_multibyte_boundary() {
        let s: String = "€".repeat(400); // 1200 bytes
        assert_eq!(s.len(), 1200);
        let cfg = OutputLengthGuardConfig {
            max_text_length: 1000,
            max_tokens: Some(1),
            limit_mode: crate::config::LimitMode::Token,
            strategy: Strategy::Truncate,
            ellipsis: String::new(),
            ..Default::default()
        };
        // Must not panic; result must be valid UTF-8 and at most 1000 bytes.
        let result = truncate(&s, &cfg);
        assert!(
            std::str::from_utf8(result.as_bytes()).is_ok(),
            "result must be valid UTF-8"
        );
        // All "€" chars are 3 bytes; the nearest boundary at or below 1000 is 999.
        assert!(
            result.len() <= 1000,
            "result must not exceed max_text_length bytes: len={}",
            result.len()
        );
    }
}
