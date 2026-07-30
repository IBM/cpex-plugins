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

/// Unwrap MySQL/MariaDB *executable* comments (`/*! … */`, `/*!50000 … */`,
/// and MariaDB's `/*M! … */`) so that the SQL hidden inside them is visible to
/// issue detection.
///
/// MySQL **executes** the body of `/*! … */` rather than ignoring it, while every
/// other engine treats it as an ordinary comment.  MariaDB additionally executes
/// `/*M! … */`, which MySQL itself ignores.  [`strip_sql_comments`] removes
/// it wholesale, which means a payload such as
/// `SELECT 1 /*!32302 ; DROP TABLE users */` would be analysed as a bare
/// `SELECT 1` while MySQL happily runs the `DROP` — the guard and the database
/// would disagree about what the string means.
///
/// This function rewrites the executable comment to its body (the `/*!`, any
/// version digits, and the closing `*/` become spaces) so that the analysis
/// pipeline sees the statements MySQL would actually run.  It is deliberately
/// **not** used when rebuilding the outgoing payload — there the comment is still
/// stripped entirely, so the hidden SQL never reaches any engine.
///
/// Ordinary block comments, line comments and quoted literals are copied through
/// verbatim; they are handled later by [`strip_sql_comments`].  Copying them
/// wholesale matters because an apostrophe inside a comment (`-- it's fine`)
/// would otherwise be mistaken for the start of a string literal and hide a
/// following executable comment.
pub fn unwrap_exec_comments(sql: &str) -> String {
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
            continue;
        }

        match ch {
            '\'' => {
                in_quote = true;
                out.push(ch);
            }
            // Line comments are copied verbatim so that apostrophes inside them
            // cannot flip quote tracking for the rest of the string.
            '-' if chars.peek() == Some(&'-') => {
                out.push(ch);
                copy_to_end_of_line(&mut chars, &mut out);
            }
            '#' => {
                out.push(ch);
                copy_to_end_of_line(&mut chars, &mut out);
            }
            '/' if chars.peek() == Some(&'*') => {
                chars.next(); // consume '*'

                // Two executable-comment spellings must be recognised:
                //   `/*!  …` — MySQL and MariaDB
                //   `/*M! …` — MariaDB only (MySQL treats it as an ordinary comment)
                // Anything else is an inert comment.  `consumed` remembers the
                // characters eaten while deciding, so a non-executable `/*M …`
                // can still be emitted verbatim.
                let mut consumed = String::from("/*");
                let mut is_exec = false;
                if chars.peek() == Some(&'!') {
                    chars.next();
                    is_exec = true;
                } else if matches!(chars.peek(), Some('M') | Some('m')) {
                    let marker = *chars.peek().expect("peeked Some above");
                    chars.next();
                    consumed.push(marker);
                    if chars.peek() == Some(&'!') {
                        chars.next();
                        is_exec = true;
                    }
                }

                if is_exec {
                    // Optional version gate: `/*!50000 …` — digits are not SQL.
                    while chars.peek().is_some_and(char::is_ascii_digit) {
                        chars.next();
                    }
                    // Emit the body, dropping the trailing `*/`.  An unterminated
                    // executable comment yields its whole remaining body, which
                    // fails closed: the hidden SQL is still analysed.
                    out.push(' ');
                    let mut body = String::new();
                    let mut prev = '\0';
                    for c in chars.by_ref() {
                        if prev == '*' && c == '/' {
                            body.pop(); // drop the '*' of the closing delimiter
                            break;
                        }
                        body.push(c);
                        prev = c;
                    }
                    out.push_str(&body);
                    out.push(' ');
                } else {
                    // Ordinary block comment — copy verbatim, delimiters included.
                    out.push_str(&consumed);
                    let mut prev = '\0';
                    for c in chars.by_ref() {
                        out.push(c);
                        if prev == '*' && c == '/' {
                            break;
                        }
                        prev = c;
                    }
                }
            }
            _ => out.push(ch),
        }
    }
    out
}

/// Copy characters up to (not including) the next newline into `out`.
fn copy_to_end_of_line(chars: &mut std::iter::Peekable<std::str::Chars<'_>>, out: &mut String) {
    while let Some(&next) = chars.peek() {
        if next == '\n' {
            break;
        }
        out.push(next);
        chars.next();
    }
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

    // -----------------------------------------------------------------------
    // MySQL executable comments
    // -----------------------------------------------------------------------

    #[test]
    fn unwraps_executable_comment() {
        // `/*! … */` is executed by MySQL, so its body must survive as live SQL.
        assert_eq!(unwrap_exec_comments("/*!DROP*/"), " DROP ");
    }

    #[test]
    fn unwraps_versioned_executable_comment() {
        // The `50000` version gate is not SQL and must not leak into the body.
        assert_eq!(unwrap_exec_comments("/*!50000 SELECT 1 */"), "  SELECT 1  ");
    }

    #[test]
    fn unwraps_mariadb_executable_comment() {
        // MariaDB executes `/*M! … */`; MySQL ignores it.  The guard must assume
        // the engine that runs the most.
        assert_eq!(unwrap_exec_comments("/*M!100000 DROP */"), "  DROP  ");
    }

    #[test]
    fn leaves_block_comment_starting_with_m_intact() {
        // `/*M …` without the `!` is an ordinary comment; the consumed `M` must
        // not be lost when it is emitted verbatim.
        let input = "SELECT 1 /*Multi-line note */ FROM t";
        assert_eq!(unwrap_exec_comments(input), input);
    }

    #[test]
    fn leaves_plain_block_comment_intact() {
        // Ordinary comments are inert everywhere; `strip_sql_comments` removes them.
        let input = "SELECT 1 /* DROP TABLE t */ FROM x";
        assert_eq!(unwrap_exec_comments(input), input);
    }

    #[test]
    fn preserves_executable_comment_inside_literal() {
        // Inside a quoted value it is data, not executable SQL.
        let input = "SELECT '/*!32302 DROP TABLE t */' FROM x";
        assert_eq!(unwrap_exec_comments(input), input);
    }

    #[test]
    fn apostrophe_in_line_comment_does_not_hide_executable_comment() {
        // The `'` in `it's` must not be read as opening a string literal; if it
        // were, the following executable comment would look like quoted data and
        // escape unwrapping entirely.
        let out = unwrap_exec_comments("SELECT 1 -- it's fine\n/*!DROP TABLE t*/");
        assert!(
            out.contains("DROP TABLE t") && !out.contains("/*!"),
            "executable comment after an apostrophe-bearing line comment must be unwrapped, got: {out:?}"
        );
    }

    /// A literal must stay open until its own closing quote, not end at the first
    /// character inside it — otherwise an executable comment further along the
    /// quoted value escapes into live SQL.
    /// Catches: `comments.rs` `ch == '\''` → `!=` in the in-quote branch.
    #[test]
    fn executable_comment_deep_inside_literal_is_preserved() {
        let input = "SELECT 'a /*!DROP*/ b'";
        assert_eq!(unwrap_exec_comments(input), input);
    }

    /// Same protection as the `--` case, for MySQL `#` line comments: the `'` in
    /// `it's` must not open a literal and swallow the following executable comment.
    /// Catches: deletion of the `'#'` match arm.
    #[test]
    fn apostrophe_in_hash_comment_does_not_hide_executable_comment() {
        let out = unwrap_exec_comments("SELECT 1 # it's fine\n/*!DROP TABLE t*/");
        assert!(
            out.contains("DROP TABLE t") && !out.contains("/*!"),
            "got: {out:?}"
        );
    }

    /// A lone `-` is arithmetic, not a comment; treating it as one would copy the
    /// rest of the line verbatim and leave an executable comment unexamined.
    /// Catches: the `'-'` match guard replaced with `true`, and its `==` → `!=`.
    #[test]
    fn single_hyphen_does_not_start_line_comment() {
        let out = unwrap_exec_comments("SELECT 1-1 /*!DROP*/");
        assert!(
            out.contains("DROP") && !out.contains("/*!"),
            "a lone '-' must not hide the executable comment, got: {out:?}"
        );
    }

    /// A lone `/` is division; entering the block-comment branch would consume the
    /// following character and corrupt the statement.
    /// Catches: the `'/'` match guard replaced with `true`.
    #[test]
    fn lone_slash_does_not_start_block_comment() {
        let input = "SELECT a/b FROM t";
        assert_eq!(unwrap_exec_comments(input), input);
    }

    /// A `/` inside an executable comment body is content, not the terminator.
    /// Catches: `prev == '*' && c == '/'` → `||` in the body loop.
    #[test]
    fn slash_inside_executable_comment_body_is_kept() {
        assert_eq!(unwrap_exec_comments("/*!SELECT a/b*/"), " SELECT a/b ");
    }

    /// An ordinary comment must be copied to its real terminator.  Stopping early
    /// would spill its contents into live parsing, where an apostrophe opens a
    /// literal and hides the executable comment that follows.
    /// Catches: `prev == '*' && c == '/'` → `||`, `prev != '*'`, and `c != '/'`
    /// in the verbatim-copy loop.
    #[test]
    fn plain_comment_is_copied_to_its_real_terminator() {
        let out = unwrap_exec_comments("SELECT 1 /* a/b it's */ /*!DROP*/");
        assert!(
            out.contains("DROP") && !out.contains("/*!"),
            "ordinary comment must not leak into parsing, got: {out:?}"
        );
    }

    #[test]
    fn unterminated_executable_comment_still_exposes_body() {
        // Fail closed: a missing `*/` must not swallow the hidden statement.
        let out = unwrap_exec_comments("SELECT 1 /*! ; DROP TABLE t");
        assert!(out.contains("DROP TABLE t"), "got: {out:?}");
    }
}
