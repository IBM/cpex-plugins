// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
//
// Recursive scanner for Python dict/list/str argument trees.
//
// Behaviour:
//  - String leaves are scanned for SQL issues when their key matches `cfg.fields`
//    (or unconditionally when `fields` is `None`).
//  - Dicts are walked depth-first; each nested key is used as the scan key.
//  - Lists of dicts recurse into the dict items; lists of strings inherit the
//    parent key name.
//  - The `stripped` accumulator collects (key, stripped_sql) pairs where
//    SQL comments were removed.  These are applied as a shallow overlay on
//    `payload.args` before returning a modified-payload result.

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

use crate::comments::strip_sql_comments;
use crate::config::SqlSanitizerConfig;
use crate::issues::find_issues;

/// Recursively scan a single Python value and accumulate issues / stripped replacements.
///
/// # Arguments
///
/// * `key`     – Field name associated with this value (used for field filtering only).
/// * `value`   – The Python value to inspect.
/// * `cfg`     – Sanitizer configuration.
/// * `issues`  – Mutable accumulator for bare issue strings (e.g. `"DELETE without WHERE clause"`).
/// * `stripped`– Mutable accumulator of `(key, stripped_value)` pairs where comments were
///   removed.  Used by the caller to build a modified payload.
pub fn scan_value(
    key: &str,
    value: &Bound<'_, PyAny>,
    cfg: &SqlSanitizerConfig,
    issues: &mut Vec<String>,
    stripped: &mut StrippedFields,
) -> PyResult<()> {
    if let Ok(text) = value.extract::<String>() {
        // Leaf string — only analyse when the field name passes the filter
        let should_scan = cfg
            .fields
            .as_ref()
            .is_none_or(|f| f.iter().any(|s| s == key));

        if should_scan {
            let found = find_issues(&text, cfg);
            for issue in found {
                issues.push(issue);
            }
            if cfg.strip_comments {
                let clean = strip_sql_comments(&text);
                if clean != text {
                    stripped.push((key.to_string(), clean));
                }
            }
        }
    } else if let Ok(dict) = value.cast::<PyDict>() {
        for (k, v) in dict.iter() {
            let k_str: String = k.extract()?;
            scan_value(&k_str, &v, cfg, issues, stripped)?;
        }
    } else if let Ok(list) = value.cast::<PyList>() {
        for item in list.iter() {
            if let Ok(d) = item.cast::<PyDict>() {
                // Dict items: use their own keys
                for (k, v) in d.iter() {
                    let k_str: String = k.extract()?;
                    scan_value(&k_str, &v, cfg, issues, stripped)?;
                }
            } else if let Ok(text) = item.extract::<String>() {
                // Plain string items inherit the parent key name
                let should_scan = cfg
                    .fields
                    .as_ref()
                    .is_none_or(|f| f.iter().any(|s| s == key));
                if should_scan {
                    let found = find_issues(&text, cfg);
                    for issue in found {
                        issues.push(issue);
                    }
                }
            }
        }
    }
    // Other Python types (int, float, None, bytes …) are silently ignored.
    Ok(())
}

/// Flat list of `(field_name, stripped_sql_value)` produced when comments are removed.
pub type StrippedFields = Vec<(String, String)>;

/// Scan an `args` dict (the top-level `payload.args` value) for SQL issues.
///
/// # Returns
///
/// `(issues, stripped)` where:
/// * `issues`  – flat list of bare issue description strings.
/// * `stripped`– flat list of `(key, stripped_sql)` pairs ready to overlay onto args.
pub fn scan_args(
    args: &Bound<'_, PyAny>,
    cfg: &SqlSanitizerConfig,
) -> PyResult<(Vec<String>, StrippedFields)> {
    let mut issues = Vec::new();
    let mut stripped = Vec::new();

    if args.is_none() {
        return Ok((issues, stripped));
    }

    if let Ok(dict) = args.cast::<PyDict>() {
        for (k, v) in dict.iter() {
            let k_str: String = k.extract()?;
            scan_value(&k_str, &v, cfg, &mut issues, &mut stripped)?;
        }
    }
    // Non-dict args (should not happen in practice) are skipped silently.

    Ok((issues, stripped))
}
