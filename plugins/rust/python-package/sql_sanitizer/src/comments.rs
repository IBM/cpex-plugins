// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
//
// SQL comment stripping utilities

use once_cell::sync::Lazy;
use regex::Regex;

/// `-- comment to end of line` (MULTILINE)
static LINE_COMMENT_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?m)--.*?$").expect("Invalid line-comment regex"));

/// `/* block comment */` (DOTALL — `.` matches newline)
static BLOCK_COMMENT_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?s)/\*.*?\*/").expect("Invalid block-comment regex"));

/// Remove SQL line comments (`-- …`) and block comments (`/* … */`).
///
/// The caller is responsible for deciding whether stripping should occur;
/// this function always strips unconditionally.
pub fn strip_sql_comments(sql: &str) -> String {
    let without_line = LINE_COMMENT_RE.replace_all(sql, "");
    BLOCK_COMMENT_RE.replace_all(&without_line, "").into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_line_comments() {
        // The regex strips from `--` to end of line; the trailing space before `\n` is preserved.
        assert_eq!(
            strip_sql_comments("SELECT 1 -- this is a comment\nFROM t"),
            "SELECT 1 \nFROM t"
        );
    }

    #[test]
    fn strips_block_comments() {
        // The block comment token is removed; surrounding spaces remain, leaving a double space.
        assert_eq!(
            strip_sql_comments("SELECT /* secret */ 1 FROM t"),
            "SELECT  1 FROM t"
        );
    }

    #[test]
    fn strips_multiline_block_comment() {
        // The comment spans multiple lines; its removal leaves two consecutive newlines.
        assert_eq!(
            strip_sql_comments("SELECT 1\n/* multi\nline\ncomment */\nFROM t"),
            "SELECT 1\n\nFROM t"
        );
    }

    #[test]
    fn no_comments_unchanged() {
        let input = "SELECT id, name FROM users WHERE id = 1";
        assert_eq!(strip_sql_comments(input), input);
    }
}
