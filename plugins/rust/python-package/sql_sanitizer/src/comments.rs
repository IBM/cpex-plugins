// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
//
// SQL comment stripping utilities.
//
// Uses a character-level state machine that tracks whether the parser is inside
// a single-quoted string literal, so that comment markers embedded in literals
// (e.g. `'it -- stays'` or `'/* also stays */'`) are not removed.

/// Remove SQL line comments (`-- …`, MySQL `# …`) and block comments
/// (`/* … */`), preserving the original text inside single-quoted string
/// literals.
///
/// Comment markers that appear inside a quoted literal are left intact so that
/// the SQL value is not corrupted.  Single-quote escaping follows the SQL
/// standard: `''` inside a string is an escaped quote and does **not** end
/// the literal.
pub fn strip_sql_comments(sql: &str) -> String {
    let mut out = String::with_capacity(sql.len());
    let mut chars = sql.chars().peekable();
    let mut in_quote = false;

    while let Some(ch) = chars.next() {
        if in_quote {
            out.push(ch);
            if ch == '\'' {
                if chars.peek() == Some(&'\'') {
                    // SQL escaped-quote: '' — consume second quote, stay inside literal
                    out.push(chars.next().unwrap());
                } else {
                    in_quote = false;
                }
            }
        } else {
            match ch {
                '\'' => {
                    in_quote = true;
                    out.push(ch);
                }
                '-' if chars.peek() == Some(&'-') => {
                    // Line comment: discard everything up to (not including) the newline.
                    // The newline itself stays in the iterator and is emitted normally.
                    chars.next(); // consume second '-'
                    while let Some(&next) = chars.peek() {
                        if next == '\n' {
                            break;
                        }
                        chars.next();
                    }
                }
                '#' => {
                    // MySQL `#` line comment: discard to end of line.  This closes a
                    // bypass where a `WHERE` clause is hidden behind a `#` comment,
                    // e.g. `DELETE FROM t # WHERE id=1`.
                    //
                    // Trade-off: SQL Server temp-table identifiers (`#temp`) are also
                    // treated as comments here.  For a security guard that fails
                    // closed this is acceptable — the worst case is a false positive
                    // that blocks an otherwise-safe statement, never a missed DELETE.
                    while let Some(&next) = chars.peek() {
                        if next == '\n' {
                            break;
                        }
                        chars.next();
                    }
                }
                '/' if chars.peek() == Some(&'*') => {
                    // Block comment: discard up to and including '*/'
                    chars.next(); // consume '*'
                    let mut prev = '\0';
                    for c in chars.by_ref() {
                        if prev == '*' && c == '/' {
                            break;
                        }
                        prev = c;
                    }
                }
                _ => out.push(ch),
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn does_not_strip_single_hyphen() {
        // A lone '-' must not trigger line-comment stripping; only '--' does.
        // Catches: comments.rs#L39 match guard `peek() == Some(&'-')` → true
        let input = "SELECT x - 1 FROM t";
        assert_eq!(strip_sql_comments(input), input);
    }

    #[test]
    fn does_not_strip_lone_slash() {
        // A lone '/' must not trigger block-comment stripping; only '/*' does.
        // Catches: comments.rs#L47 match guard `peek() == Some(&'*')` → true
        let input = "SELECT 10 / 2 FROM t";
        assert_eq!(strip_sql_comments(input), input);
    }

    #[test]
    fn slash_inside_block_comment_does_not_end_it() {
        // A '/' inside a block comment must NOT terminate it; only '*/' does.
        // Catches: comments.rs#L52 `prev == '*' && c == '/'` → `||`
        assert_eq!(
            strip_sql_comments("SELECT /* he/she */ 1 FROM t"),
            "SELECT  1 FROM t"
        );
    }

    #[test]
    fn strips_line_comments() {
        // Strips from `--` to end of line; the trailing space and newline are preserved.
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
    fn strips_hash_line_comments() {
        // MySQL `#` comment is stripped to end of line; the newline is preserved.
        assert_eq!(
            strip_sql_comments("DELETE FROM t # WHERE id=1\nSELECT 1"),
            "DELETE FROM t \nSELECT 1"
        );
    }

    #[test]
    fn preserves_hash_inside_string_literal() {
        // `#` inside a quoted string is part of the value, not a comment.
        let input = "SELECT '# not a comment' FROM t";
        assert_eq!(strip_sql_comments(input), input);
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

    #[test]
    fn preserves_line_comment_marker_inside_string_literal() {
        // `--` inside a quoted string is part of the value, not a comment.
        let input = "SELECT '-- not a comment' FROM t";
        assert_eq!(strip_sql_comments(input), input);
    }

    #[test]
    fn preserves_block_comment_marker_inside_string_literal() {
        // `/* … */` inside a quoted string is part of the value, not a comment.
        let input = "SELECT '/* also stays */' FROM t";
        assert_eq!(strip_sql_comments(input), input);
    }

    #[test]
    fn strips_comment_after_literal() {
        // Comment after a closing quote is still stripped.
        assert_eq!(
            strip_sql_comments("SELECT 'hello' -- trailing comment\nFROM t"),
            "SELECT 'hello' \nFROM t"
        );
    }

    #[test]
    fn handles_escaped_quote_in_literal() {
        // `''` inside a string is an escaped quote; the string continues after it.
        let input = "SELECT 'it''s fine -- not a comment' FROM t";
        assert_eq!(strip_sql_comments(input), input);
    }
}
