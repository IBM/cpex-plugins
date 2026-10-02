// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
//
// SQL issue detection with per-statement analysis.
//
// Each SQL statement is checked independently after splitting on `;`, so a
// WHERE clause in one statement cannot mask a WHERE-less statement elsewhere
// in the same payload.

use once_cell::sync::Lazy;
use regex::Regex;

use crate::comments::{strip_sql_comments, unwrap_exec_comments};
use crate::config::SqlSanitizerConfig;

/// Matches common Python printf-style format specifiers (`%s`, `%d`, `%f`, `%i`, `%r`).
static PRINTF_FMT_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"%[sdfi]").expect("Invalid printf format regex"));

/// Erases `$N`, `:N`, `@N`, `?N` bind-parameter prefixes before literal detection.
/// `?N` covers SQLite numbered parameters (`?1`, `?2`).
static BIND_PARAM_DIGIT_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"[$:@?]\d+").expect("Invalid bind param digit regex"));

/// Matches a masked string literal (`''`) or a numeric literal in any of the
/// forms SQL dialects allow: integer, decimal, exponent (`1e3`), hex (`0xFF`).
/// Applied after `mask_string_literals`, `BIND_PARAM_DIGIT_RE` erasure, and
/// double-quoted identifier removal.
static INLINE_LITERAL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"''|0[xX][0-9A-Fa-f]+|-?\b\d+(?:[eE][+-]?\d+|(?:\.\d+)(?:[eE][+-]?\d+)?)\b|-?\b\d+\.\d+\b|-?\b\d+\b",
    )
    .expect("Invalid inline literal regex")
});

/// Strips ANSI double-quoted identifiers (e.g. `"2024"`) so their content is not
/// mistaken for a literal value during inline-literal detection.
static DQ_IDENT_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#""[^"]*""#).expect("Invalid double-quote ident regex"));

/// Guards `has_inline_literals`: skips non-SQL fields (HTTP codes, IDs, log lines)
/// to avoid false positives when `fields = null`.
/// `WITH` is intentionally omitted — it is too common in English prose.
static SQL_KEYWORD_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(?:SELECT|INSERT|UPDATE|DELETE|MERGE|REPLACE)\b")
        .expect("Invalid SQL keyword regex")
});

static DELETE_FROM_RE: Lazy<Regex> = Lazy::new(|| {
    // A statement whose leading keyword is DELETE is destructive regardless of
    // the table syntax that follows.  Anchoring at the statement start covers:
    //   * single-table:  `DELETE FROM users`
    //   * multi-table:    `DELETE u FROM users AS u`  (MySQL/`JOIN` deletes)
    //   * quoted tables:  `DELETE FROM "users"`
    // Statements are already split on `;` and trimmed before this runs.
    Regex::new(r"(?i)^\s*DELETE\b").expect("Invalid DELETE regex")
});

static UPDATE_RE: Lazy<Regex> = Lazy::new(|| {
    // SET is required so prose like "Append UPDATE query to file" is not matched.
    // Table-name component: bare word or any quoted form (ANSI, backtick, bracket).
    // Components are dot-separated, so "hr"."employees" and schema.table are covered.
    // Optional ONLY (PostgreSQL) before the table name.
    // Optional alias after: AS alias  or  implicit alias (bare word).
    Regex::new(
        r#"(?ix)
        \bUPDATE\b \s+
        (?:ONLY\s+)?
        (?:
            (?:\w+ | "[^"]*" | `[^`]*` | \[[^\]]*\])
            (?:\.(?:\w+ | "[^"]*" | `[^`]*` | \[[^\]]*\]))*
        )
        (?:\s+AS\s+\w+ | \s+\w+)?
        \s+SET\b"#,
    )
    .expect("Invalid UPDATE regex")
});

static WHERE_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\bWHERE\b").expect("Invalid WHERE regex"));

/// Replace the content of single-quoted SQL string literals with empty strings
/// so that analysis regexes do not match keywords or patterns inside values.
///
/// `UPDATE t SET x='WHERE 1=1'` → `UPDATE t SET x=''`
/// Handles SQL `''` escaped-quote convention.
fn mask_string_literals(sql: &str) -> String {
    let mut out = String::with_capacity(sql.len());
    let mut chars = sql.chars().peekable();
    let mut in_quote = false;

    while let Some(ch) = chars.next() {
        if !in_quote {
            out.push(ch);
            if ch == '\'' {
                in_quote = true;
            }
        } else if ch == '\'' {
            if chars.peek() == Some(&'\'') {
                chars.next(); // consume escaped-quote, discard both
            } else {
                out.push('\''); // emit closing quote
                in_quote = false;
            }
        }
        // else: discard literal content
    }
    out
}

/// Split SQL into statements on `;` separators, respecting single-quoted
/// literals so that `;` inside a literal is not treated as a boundary.
///
/// Empty and whitespace-only segments are omitted.
fn split_statements(sql: &str) -> Vec<String> {
    let mut stmts: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut chars = sql.chars().peekable();
    let mut in_quote = false;

    while let Some(ch) = chars.next() {
        if in_quote {
            current.push(ch);
            if ch == '\'' {
                if chars.peek() == Some(&'\'') {
                    current.push(chars.next().unwrap()); // escaped quote
                } else {
                    in_quote = false;
                }
            }
        } else if ch == '\'' {
            in_quote = true;
            current.push(ch);
        } else if ch == ';' {
            let s = current.trim().to_string();
            if !s.is_empty() {
                stmts.push(s);
            }
            current.clear();
        } else {
            current.push(ch);
        }
    }
    let tail = current.trim().to_string();
    if !tail.is_empty() {
        stmts.push(tail);
    }
    stmts
}

/// Check a **single** SQL statement (no semicolons) for security issues.
fn find_issues_in_statement(stmt: &str, cfg: &SqlSanitizerConfig) -> Vec<String> {
    // Mask string literal content so keywords inside quoted values
    // (e.g. `UPDATE t SET note='WHERE 1=1'`) cannot spoof or bypass detection.
    let masked = mask_string_literals(stmt);

    let mut issues = Vec::new();

    // Blocked statement patterns
    for (raw, re) in &cfg.blocked_patterns {
        if re.is_match(&masked) {
            issues.push(format!("Blocked statement matched: {}", raw));
        }
    }

    // DELETE FROM without WHERE
    if cfg.block_delete_without_where
        && DELETE_FROM_RE.is_match(&masked)
        && !WHERE_RE.is_match(&masked)
    {
        issues.push("DELETE without WHERE clause".to_string());
    }

    // UPDATE without WHERE
    if cfg.block_update_without_where && UPDATE_RE.is_match(&masked) && !WHERE_RE.is_match(&masked)
    {
        issues.push("UPDATE without WHERE clause".to_string());
    }

    issues
}

/// Find SQL security issues in a SQL string.
///
/// # Arguments
///
/// * `sql` – The original, un-processed SQL string (comments still present).
/// * `cfg` – Sanitizer configuration.
///
/// # Returns
///
/// A list of human-readable issue descriptions.  Empty means no issues found.
pub fn find_issues(sql: &str, cfg: &SqlSanitizerConfig) -> Vec<String> {
    // Reveal MySQL executable comments (`/*! … */`) before anything else: MySQL
    // runs their contents, so the guard has to analyse them as live SQL rather
    // than let `strip_sql_comments` discard them.  This happens regardless of
    // `strip_comments` — the setting governs the outgoing payload, not whether
    // hidden statements are inspected.
    let unwrapped = unwrap_exec_comments(sql);

    let processed = if cfg.strip_comments {
        strip_sql_comments(&unwrapped)
    } else {
        unwrapped
    };

    let mut issues = Vec::new();

    // Split on `;` (respecting literals) and analyse each statement independently
    // so that a WHERE clause in one statement cannot mask a violation elsewhere.
    for stmt in split_statements(&processed) {
        issues.extend(find_issues_in_statement(&stmt, cfg));
    }

    // Parameterization check on comment-stripped, literal-masked SQL.
    // Masking first prevents quoted content from spoofing or bypassing detection.
    let masked_processed = mask_string_literals(&processed);
    if cfg.require_parameterization {
        if has_interpolation(&masked_processed) {
            issues.push("Possible non-parameterized interpolation detected".to_string());
        } else if has_inline_literals(&masked_processed) {
            issues.push("Inline literal values detected; use bind parameters instead".to_string());
        }
    }

    issues
}

/// Heuristic check for naive SQL string interpolation.
///
/// Detects common patterns:
/// * `+`         — string concatenation
/// * `%s` / `%d` / `%f` / `%i` — Python printf-style format specifiers
/// * `{…}`       — f-string / `.format()` style
fn has_interpolation(sql: &str) -> bool {
    sql.contains('+') || PRINTF_FMT_RE.is_match(sql) || has_brace_template(sql)
}

/// Return `true` when `sql` contains a `{…}` template placeholder.
///
/// Checks that `{` appears before the first `}`.  This is an equivalent
/// mutation boundary: because `{` ≠ `}`, `find('{')` and `find('}')` can
/// never return the same index, so `l < r` and `l <= r` are indistinguishable
/// for all valid inputs.
#[mutants::skip] // equivalent mutation: `{` ≠ `}` so l == r is impossible
fn has_brace_template(sql: &str) -> bool {
    if let (Some(l), Some(r)) = (sql.find('{'), sql.find('}'))
        && l < r
    {
        return true;
    }
    false
}

/// Return `true` when `sql` contains a masked string literal or numeric literal.
/// Skips non-SQL strings; strips bind params and double-quoted identifiers before matching.
fn has_inline_literals(sql: &str) -> bool {
    if !SQL_KEYWORD_RE.is_match(sql) {
        return false;
    }
    let erased = BIND_PARAM_DIGIT_RE.replace_all(sql, "");
    let erased = DQ_IDENT_RE.replace_all(&erased, "");
    INLINE_LITERAL_RE.is_match(&erased)
}

#[cfg(test)]
mod tests {
    use crate::config::SqlSanitizerConfig;

    use super::*;

    fn default_cfg() -> SqlSanitizerConfig {
        SqlSanitizerConfig::default()
    }

    // -----------------------------------------------------------------------
    // Blocked statement patterns
    // -----------------------------------------------------------------------

    #[test]
    fn blocks_drop_table() {
        let issues = find_issues("DROP TABLE users", &default_cfg());
        assert_eq!(issues, vec!["Blocked statement matched: \\bDROP\\b"]);
    }

    #[test]
    fn blocks_truncate() {
        let issues = find_issues("TRUNCATE TABLE orders", &default_cfg());
        assert_eq!(issues, vec!["Blocked statement matched: \\bTRUNCATE\\b"]);
    }

    // -----------------------------------------------------------------------
    // DELETE / UPDATE without WHERE
    // -----------------------------------------------------------------------

    #[test]
    fn detects_delete_without_where() {
        let issues = find_issues("DELETE FROM employees", &default_cfg());
        assert_eq!(issues, vec!["DELETE without WHERE clause"]);
    }

    #[test]
    fn no_issue_for_delete_with_where() {
        let issues = find_issues("DELETE FROM employees WHERE id = 1", &default_cfg());
        assert_eq!(issues, Vec::<String>::new());
    }

    #[test]
    fn detects_update_without_where() {
        let issues = find_issues("UPDATE salary SET amount = 0", &default_cfg());
        assert_eq!(issues, vec!["UPDATE without WHERE clause"]);
    }

    #[test]
    fn no_issue_for_update_with_where() {
        let issues = find_issues("UPDATE salary SET amount = 0 WHERE id = 5", &default_cfg());
        assert_eq!(issues, Vec::<String>::new());
    }

    #[test]
    fn detects_multi_table_delete_without_where() {
        // MySQL multi-table DELETE: the table alias sits between DELETE and FROM,
        // so a `DELETE ... FROM` adjacency check misses it.  This still deletes
        // every row and must be blocked.
        let issues = find_issues("DELETE u FROM users AS u", &default_cfg());
        assert_eq!(issues, vec!["DELETE without WHERE clause"]);
    }

    #[test]
    fn no_issue_for_multi_table_delete_with_where() {
        let issues = find_issues("DELETE u FROM users AS u WHERE u.id = 1", &default_cfg());
        assert_eq!(issues, Vec::<String>::new());
    }

    #[test]
    fn detects_delete_with_where_hidden_in_hash_comment() {
        // MySQL `#` comment hides the apparent WHERE, so the real statement is a
        // WHERE-less DELETE that removes every row.
        let issues = find_issues("DELETE FROM users # WHERE id=1", &default_cfg());
        assert_eq!(issues, vec!["DELETE without WHERE clause"]);
    }

    // -----------------------------------------------------------------------
    // Per-statement splitting
    // -----------------------------------------------------------------------

    #[test]
    fn per_statement_fix_where_in_later_statement_does_not_hide_earlier_violation() {
        // Four WHERE-less UPDATEs followed by an UPDATE with WHERE.
        // The trailing WHERE must not suppress the four earlier violations.
        let sql = "\
            UPDATE a SET x=1;\
            UPDATE b SET x=2;\
            UPDATE c SET x=3;\
            UPDATE d SET x=4;\
            UPDATE e SET x=5 WHERE id=1\
        ";
        let issues = find_issues(sql, &default_cfg());
        assert_eq!(
            issues,
            vec![
                "UPDATE without WHERE clause",
                "UPDATE without WHERE clause",
                "UPDATE without WHERE clause",
                "UPDATE without WHERE clause",
            ]
        );
    }

    #[test]
    fn no_issue_for_single_update_with_where() {
        let issues = find_issues(
            "UPDATE employees SET salary = 5000 WHERE department = 'IT'",
            &default_cfg(),
        );
        assert_eq!(issues, Vec::<String>::new());
    }

    // -----------------------------------------------------------------------
    // Comment stripping
    // -----------------------------------------------------------------------

    #[test]
    fn comments_hide_drop_before_strip_is_applied() {
        // DROP lives inside a block comment; after stripping, the statement is
        // a plain SELECT — no issues should be reported at all.
        let sql = "SELECT 1 /* DROP TABLE secret */ FROM t";
        let issues = find_issues(sql, &default_cfg());
        assert_eq!(issues, Vec::<String>::new());
    }

    // -----------------------------------------------------------------------
    // Interpolation check
    // -----------------------------------------------------------------------

    #[test]
    fn detects_interpolation_when_required() {
        let mut cfg = default_cfg();
        cfg.require_parameterization = true;
        // Bare {} outside a literal — typical Python f-string / .format() template
        let issues = find_issues("SELECT * FROM users WHERE id = {}", &cfg);
        assert_eq!(
            issues,
            vec!["Possible non-parameterized interpolation detected"]
        );
    }

    #[test]
    fn no_false_positive_interpolation_when_not_required() {
        let cfg = default_cfg(); // require_parameterization = false
        let sql = "SELECT * FROM users WHERE name = '{}'";
        let issues = find_issues(sql, &cfg);
        assert_eq!(issues, Vec::<String>::new());
    }

    // -----------------------------------------------------------------------
    // Parameterization — extra coverage to catch missed mutants
    // -----------------------------------------------------------------------

    /// `require_parameterization=true` + SQL that uses bind parameters →
    /// empty issues.  Catches the mutant that replaces `has_interpolation`
    /// entirely with `true`.
    #[test]
    fn no_issue_for_parameterized_sql_when_parameterization_required() {
        let mut cfg = default_cfg();
        cfg.require_parameterization = true;
        // `?` is a positional bind parameter — no literals, no interpolation
        let issues = find_issues("SELECT id FROM users WHERE name = ?", &cfg);
        assert_eq!(issues, Vec::<String>::new());
    }

    /// `require_parameterization=true` + SQL with a named bind parameter (`$1`)
    /// → empty issues.  Verifies that positional parameters in PostgreSQL style
    /// are not mistaken for literals.
    #[test]
    fn no_issue_for_dollar_bind_param_when_parameterization_required() {
        let mut cfg = default_cfg();
        cfg.require_parameterization = true;
        let issues = find_issues("SELECT id FROM users WHERE name = $1", &cfg);
        assert_eq!(issues, Vec::<String>::new());
    }

    /// `require_parameterization=true` + SQL containing only `+` (no `%s` or
    /// `{…}`) → flagged.  Catches the `||` → `&&` mutant in `has_interpolation`.
    #[test]
    fn detects_plus_concatenation_as_interpolation() {
        let mut cfg = default_cfg();
        cfg.require_parameterization = true;
        let issues = find_issues("SELECT * FROM t WHERE x = val + 1", &cfg);
        assert_eq!(
            issues,
            vec!["Possible non-parameterized interpolation detected"]
        );
    }

    /// `require_parameterization=true` + SQL with a `%s` placeholder (no `+`
    /// or `{…}`) → flagged.  Catches the second `||` → `&&` mutant in
    /// `has_interpolation` and verifies the printf-format detection.
    #[test]
    fn detects_printf_format_as_interpolation() {
        let mut cfg = default_cfg();
        cfg.require_parameterization = true;
        // Bare %s outside a literal — typical Python %-operator SQL template
        let issues = find_issues("SELECT * FROM users WHERE name = %s", &cfg);
        assert_eq!(
            issues,
            vec!["Possible non-parameterized interpolation detected"]
        );
    }

    // -----------------------------------------------------------------------
    // Literal-aware detection (regression tests for literal-bypass bugs)
    // -----------------------------------------------------------------------

    /// WHERE appearing only inside a quoted value must not satisfy the WHERE
    /// guard — the statement still has no structural WHERE clause.
    /// Catches: `issues.rs#L46` `peek() == Some(&'\'')`→`!=` in `mask_string_literals`.
    /// With that mutant the closing `'` is not emitted and quote mode never exits,
    /// so everything after the literal (including WHERE) is masked away.
    #[test]
    fn where_clause_after_literal_is_recognized() {
        // Correct masking closes the literal; WHERE is visible → no issue.
        let issues = find_issues("UPDATE t SET x = 'value' WHERE id = 1", &default_cfg());
        assert_eq!(issues, Vec::<String>::new());
    }

    #[test]
    fn where_in_string_literal_is_not_treated_as_clause() {
        let issues = find_issues("UPDATE users SET note = 'has WHERE text'", &default_cfg());
        assert_eq!(issues, vec!["UPDATE without WHERE clause"]);
    }

    /// A semicolon inside a quoted string must not split the statement, so
    /// the DROP TABLE token inside the literal must not be flagged.
    #[test]
    fn semicolon_in_string_literal_does_not_split_statement() {
        let issues = find_issues("SELECT 'hello; DROP TABLE t'", &default_cfg());
        assert_eq!(issues, Vec::<String>::new());
    }

    // -----------------------------------------------------------------------
    // MySQL / MariaDB executable comments
    // -----------------------------------------------------------------------

    /// MySQL executes the body of `/*! … */`; treating it as a comment let a
    /// `DROP` reach the database while the guard saw only `SELECT 1`.
    #[test]
    fn executable_comment_hiding_drop_is_detected() {
        let issues = find_issues("SELECT 1 /*!32302 ; DROP TABLE users */", &default_cfg());
        assert_eq!(issues, vec!["Blocked statement matched: \\bDROP\\b"]);
    }

    #[test]
    fn executable_comment_hiding_unscoped_delete_is_detected() {
        let issues = find_issues("SELECT 1 /*!50000 ; DELETE FROM users */", &default_cfg());
        assert_eq!(issues, vec!["DELETE without WHERE clause"]);
    }

    /// MariaDB's `/*M! … */` is executed by MariaDB and ignored by MySQL, so it
    /// hides a statement from any guard that only knows the `/*!` spelling.
    #[test]
    fn mariadb_executable_comment_hiding_drop_is_detected() {
        let issues = find_issues("SELECT 1 /*M!100000 ; DROP TABLE users */", &default_cfg());
        assert_eq!(issues, vec!["Blocked statement matched: \\bDROP\\b"]);
    }

    #[test]
    fn executable_comment_without_version_is_detected() {
        let issues = find_issues("SELECT 1 /*! ; DROP TABLE users */", &default_cfg());
        assert_eq!(issues, vec!["Blocked statement matched: \\bDROP\\b"]);
    }

    /// Unwrapping must survive `strip_comments = false` too: the setting governs
    /// the outgoing payload, not whether hidden statements are inspected.
    #[test]
    fn executable_comment_detected_with_comment_stripping_disabled() {
        let mut cfg = default_cfg();
        cfg.strip_comments = false;
        let issues = find_issues("SELECT 1 /*!32302 ; DROP TABLE users */", &cfg);
        assert_eq!(issues, vec!["Blocked statement matched: \\bDROP\\b"]);
    }

    /// An optimizer hint is not an executable comment and carries no statement.
    #[test]
    fn optimizer_hint_is_not_flagged() {
        let issues = find_issues("SELECT /*+ INDEX(t idx) */ * FROM t", &default_cfg());
        assert_eq!(issues, Vec::<String>::new());
    }

    /// A version-gated comment that only sets a session variable is legitimate
    /// MySQL (common in dumps) and must not become a false positive.
    #[test]
    fn benign_versioned_executable_comment_is_allowed() {
        let issues = find_issues("/*!40101 SET NAMES utf8 */", &default_cfg());
        assert_eq!(issues, Vec::<String>::new());
    }

    /// Inside a quoted value the sequence is data — no engine executes it.
    #[test]
    fn executable_comment_inside_literal_is_not_flagged() {
        let issues = find_issues(
            "SELECT '/*!32302 ; DROP TABLE users */' AS note",
            &default_cfg(),
        );
        assert_eq!(issues, Vec::<String>::new());
    }

    /// `%s` inside a quoted literal is masked before interpolation detection runs.
    #[test]
    fn percent_s_inside_string_literal_is_not_flagged_as_interpolation() {
        let issues = find_issues("SELECT * FROM t WHERE name LIKE '%s%'", &default_cfg());
        assert_eq!(issues, Vec::<String>::new());
    }

    #[test]
    fn parameterized_like_with_bind_param_is_not_flagged() {
        let mut cfg = default_cfg();
        cfg.require_parameterization = true;
        let issues = find_issues("SELECT * FROM t WHERE name LIKE ?", &cfg);
        assert_eq!(issues, Vec::<String>::new());
    }

    /// Valid UPDATE with WHERE must not be blocked.
    #[test]
    fn valid_update_with_where_is_not_blocked() {
        let issues = find_issues(
            "UPDATE employees SET salary = 75000 WHERE employee_id = 101",
            &default_cfg(),
        );
        assert_eq!(issues, Vec::<String>::new());
    }

    /// Prose containing "UPDATE <word>" without SET must not trigger the WHERE-less UPDATE policy.
    #[test]
    fn prose_update_word_is_not_flagged() {
        let issues = find_issues("Append UPDATE query to TC1.SQL", &default_cfg());
        assert_eq!(issues, Vec::<String>::new());
    }

    /// WHERE-less UPDATE must still be blocked even when a prose field also contains "UPDATE".
    #[test]
    fn real_update_without_where_is_still_blocked() {
        let issues = find_issues("UPDATE employees SET salary = 75000", &default_cfg());
        assert_eq!(issues, vec!["UPDATE without WHERE clause"]);
    }

    /// SQL UPDATE with WHERE followed by prose containing "UPDATE" — only the WHERE-less prose is checked, not flagged.
    #[test]
    fn mixed_sql_and_prose_update_no_false_positive() {
        let issues = find_issues(
            "UPDATE employees SET salary = 75000 WHERE employee_id = 101; \
             Append UPDATE query to TC1.SQL",
            &default_cfg(),
        );
        assert_eq!(issues, Vec::<String>::new());
    }

    /// INSERT with inline literals is flagged when `require_parameterization` is enabled.
    #[test]
    fn insert_with_inline_literals_is_flagged() {
        let mut cfg = default_cfg();
        cfg.require_parameterization = true;
        let issues = find_issues("INSERT INTO employees VALUES (42, 'Alice', 75000)", &cfg);
        assert_eq!(
            issues,
            vec!["Inline literal values detected; use bind parameters instead"]
        );
    }

    /// INSERT with bind parameters passes when `require_parameterization` is enabled.
    #[test]
    fn insert_with_bind_params_is_allowed() {
        let mut cfg = default_cfg();
        cfg.require_parameterization = true;
        let issues = find_issues("INSERT INTO employees VALUES (?, ?, ?)", &cfg);
        assert_eq!(issues, Vec::<String>::new());
    }

    /// UPDATE with inline numeric literals is flagged when `require_parameterization` is enabled.
    #[test]
    fn update_with_inline_literal_where_is_flagged() {
        let mut cfg = default_cfg();
        cfg.require_parameterization = true;
        let issues = find_issues(
            "UPDATE employees SET salary = 75000 WHERE employee_id = 101",
            &cfg,
        );
        assert_eq!(
            issues,
            vec!["Inline literal values detected; use bind parameters instead"]
        );
    }

    /// UPDATE with bind parameters passes when `require_parameterization` is enabled.
    #[test]
    fn update_with_bind_params_is_allowed() {
        let mut cfg = default_cfg();
        cfg.require_parameterization = true;
        let issues = find_issues(
            "UPDATE employees SET salary = ? WHERE employee_id = ?",
            &cfg,
        );
        assert_eq!(issues, Vec::<String>::new());
    }

    // -----------------------------------------------------------------------
    // Schema-qualified UPDATE regressions
    // -----------------------------------------------------------------------

    /// Regression: `\w+` stopped at the dot in `schema.table`, bypassing the guard.
    #[test]
    fn schema_qualified_update_without_where_is_blocked() {
        let issues = find_issues("UPDATE hr.employees SET salary = 0", &default_cfg());
        assert_eq!(issues, vec!["UPDATE without WHERE clause"]);
    }

    #[test]
    fn schema_qualified_update_with_where_is_not_blocked() {
        let issues = find_issues(
            "UPDATE hr.employees SET salary = 0 WHERE id = 1",
            &default_cfg(),
        );
        assert_eq!(issues, Vec::<String>::new());
    }

    #[test]
    fn three_part_name_update_without_where_is_blocked() {
        let issues = find_issues("UPDATE mydb.hr.employees SET salary = 0", &default_cfg());
        assert_eq!(issues, vec!["UPDATE without WHERE clause"]);
    }

    // -----------------------------------------------------------------------
    // Non-SQL field regressions (fields = null + require_parameterization)
    // -----------------------------------------------------------------------

    #[test]
    fn non_sql_field_with_number_is_not_flagged() {
        let mut cfg = default_cfg();
        cfg.require_parameterization = true;
        let issues = find_issues("status: 200 OK", &cfg);
        assert_eq!(issues, Vec::<String>::new());
    }

    #[test]
    fn tool_call_id_field_is_not_flagged() {
        let mut cfg = default_cfg();
        cfg.require_parameterization = true;
        let issues = find_issues("call_42", &cfg);
        assert_eq!(issues, Vec::<String>::new());
    }

    #[test]
    fn version_string_is_not_flagged() {
        let mut cfg = default_cfg();
        cfg.require_parameterization = true;
        let issues = find_issues("v1.0.2", &cfg);
        assert_eq!(issues, Vec::<String>::new());
    }

    #[test]
    fn error_code_message_is_not_flagged() {
        let mut cfg = default_cfg();
        cfg.require_parameterization = true;
        let issues = find_issues("error code 404", &cfg);
        assert_eq!(issues, Vec::<String>::new());
    }

    /// `SELECT 1` is flagged because it contains a SQL keyword and a literal.
    /// Use `fields` filtering or disable `require_parameterization` for health checks.
    #[test]
    fn select_one_health_check_is_flagged_as_inline_literal() {
        let mut cfg = default_cfg();
        cfg.require_parameterization = true;
        let issues = find_issues("SELECT 1", &cfg);
        assert_eq!(
            issues,
            vec!["Inline literal values detected; use bind parameters instead"]
        );
    }

    // -----------------------------------------------------------------------
    // P1: UPDATE alias / ONLY / quoted schema regressions
    // -----------------------------------------------------------------------

    #[test]
    fn update_with_alias_without_where_is_blocked() {
        let issues = find_issues("UPDATE employees AS e SET salary = 0", &default_cfg());
        assert_eq!(issues, vec!["UPDATE without WHERE clause"]);
    }

    #[test]
    fn update_with_alias_with_where_is_not_blocked() {
        let issues = find_issues(
            "UPDATE employees AS e SET salary = 0 WHERE id = 1",
            &default_cfg(),
        );
        assert_eq!(issues, Vec::<String>::new());
    }

    #[test]
    fn update_only_without_where_is_blocked() {
        let issues = find_issues("UPDATE ONLY employees SET salary = 0", &default_cfg());
        assert_eq!(issues, vec!["UPDATE without WHERE clause"]);
    }

    #[test]
    fn update_quoted_schema_table_without_where_is_blocked() {
        let issues = find_issues(
            r#"UPDATE "hr"."employees" SET salary = 0"#,
            &default_cfg(),
        );
        assert_eq!(issues, vec!["UPDATE without WHERE clause"]);
    }

    #[test]
    fn update_quoted_schema_table_with_where_is_not_blocked() {
        let issues = find_issues(
            r#"UPDATE "hr"."employees" SET salary = 0 WHERE id = 1"#,
            &default_cfg(),
        );
        assert_eq!(issues, Vec::<String>::new());
    }

    // -----------------------------------------------------------------------
    // P2: WITH keyword removed from SQL context gate
    // -----------------------------------------------------------------------

    #[test]
    fn prose_with_word_and_number_is_not_flagged() {
        let mut cfg = default_cfg();
        cfg.require_parameterization = true;
        // "with" in English prose must not activate literal detection.
        let issues = find_issues("Request failed with status 503", &cfg);
        assert_eq!(issues, Vec::<String>::new());
    }

    // -----------------------------------------------------------------------
    // P2: SQLite ?N numbered bind parameters
    // -----------------------------------------------------------------------

    #[test]
    fn sqlite_numbered_bind_param_is_not_flagged() {
        let mut cfg = default_cfg();
        cfg.require_parameterization = true;
        let issues = find_issues("SELECT id FROM users WHERE id = ?1", &cfg);
        assert_eq!(issues, Vec::<String>::new());
    }

    // -----------------------------------------------------------------------
    // P2: double-quoted column identifier not treated as literal
    // -----------------------------------------------------------------------

    #[test]
    fn double_quoted_column_identifier_is_not_flagged() {
        let mut cfg = default_cfg();
        cfg.require_parameterization = true;
        let issues = find_issues(
            r#"SELECT "2024" FROM annual_report WHERE id = $1"#,
            &cfg,
        );
        assert_eq!(issues, Vec::<String>::new());
    }

    // -----------------------------------------------------------------------
    // P2: exponent and hexadecimal numeric literals
    // -----------------------------------------------------------------------

    #[test]
    fn insert_with_exponent_literal_is_flagged() {
        let mut cfg = default_cfg();
        cfg.require_parameterization = true;
        let issues = find_issues("INSERT INTO readings VALUES (1e3)", &cfg);
        assert_eq!(
            issues,
            vec!["Inline literal values detected; use bind parameters instead"]
        );
    }

    #[test]
    fn insert_with_hex_literal_is_flagged() {
        let mut cfg = default_cfg();
        cfg.require_parameterization = true;
        let issues = find_issues("INSERT INTO readings VALUES (0xFF)", &cfg);
        assert_eq!(
            issues,
            vec!["Inline literal values detected; use bind parameters instead"]
        );
    }

    #[test]
    fn insert_with_bind_params_passes_after_hex_exponent_fix() {
        let mut cfg = default_cfg();
        cfg.require_parameterization = true;
        let issues = find_issues("INSERT INTO readings VALUES (?)", &cfg);
        assert_eq!(issues, Vec::<String>::new());
    }
}
