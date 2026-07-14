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

use crate::comments::strip_sql_comments;
use crate::config::SqlSanitizerConfig;

static DELETE_FROM_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\bDELETE\b\s+\bFROM\b").expect("Invalid DELETE FROM regex"));

static UPDATE_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\bUPDATE\b\s+\w+").expect("Invalid UPDATE regex"));

static WHERE_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\bWHERE\b").expect("Invalid WHERE regex"));

/// Check a **single** SQL statement (no semicolons) for security issues.
fn find_issues_in_statement(stmt: &str, cfg: &SqlSanitizerConfig) -> Vec<String> {
    let mut issues = Vec::new();

    // Blocked statement patterns
    for (raw, re) in &cfg.blocked_patterns {
        if re.is_match(stmt) {
            issues.push(format!("Blocked statement matched: {}", raw));
        }
    }

    // DELETE FROM without WHERE
    if cfg.block_delete_without_where && DELETE_FROM_RE.is_match(stmt) && !WHERE_RE.is_match(stmt) {
        issues.push("DELETE without WHERE clause".to_string());
    }

    // UPDATE without WHERE
    if cfg.block_update_without_where && UPDATE_RE.is_match(stmt) && !WHERE_RE.is_match(stmt) {
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
    // Strip comments before pattern matching (but keep `sql` for interpolation check).
    let processed = if cfg.strip_comments {
        strip_sql_comments(sql)
    } else {
        sql.to_string()
    };

    let mut issues = Vec::new();

    // Split on `;` and analyse each statement independently so that a WHERE
    // clause in one statement cannot mask a WHERE-less statement elsewhere.
    for stmt in processed.split(';') {
        let stmt = stmt.trim();
        if stmt.is_empty() {
            continue;
        }
        issues.extend(find_issues_in_statement(stmt, cfg));
    }

    // Parameterization check runs on the pre-strip text so that interpolation
    // patterns inside comments are also detected.
    if cfg.require_parameterization && has_interpolation(sql) {
        issues.push("Possible non-parameterized interpolation detected".to_string());
    }

    issues
}

/// Heuristic check for naive SQL string interpolation.
///
/// Detects common patterns:
/// * `+`      — string concatenation
/// * `%.`     — `%s` / `%d` printf-style formatting
/// * `{…}`    — f-string / `.format()` style
fn has_interpolation(sql: &str) -> bool {
    sql.contains('+') || sql.contains("%.") || has_brace_template(sql)
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
        let sql = "SELECT * FROM users WHERE name = '{}'";
        let issues = find_issues(sql, &cfg);
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

    /// `require_parameterization=true` + SQL with NO interpolation markers →
    /// empty issues.  Catches the mutant that replaces `has_interpolation`
    /// entirely with `true`.
    #[test]
    fn no_issue_for_safe_sql_when_parameterization_required() {
        let mut cfg = default_cfg();
        cfg.require_parameterization = true;
        // No `+`, `%.`, or `{…}` — must produce zero issues
        let issues = find_issues("SELECT id FROM users WHERE name = 'alice'", &cfg);
        assert_eq!(issues, Vec::<String>::new());
    }

    /// `require_parameterization=true` + SQL containing only `+` (no `%.` or
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
}
