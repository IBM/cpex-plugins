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
//    parent key name; lists inside lists are recursed into with the same key.
//  - Comment stripping only produces a patched payload for **top-level** string
//    values.  `rebuild_args_with_stripped` applies a shallow top-level overlay,
//    so recording a stripped value for a nested key would corrupt unrelated
//    top-level fields.  Nested strings are still **scanned** for issues.

use pyo3::prelude::*;
use pyo3::types::PyList;

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
///   removed.  Only populated for **top-level** string values (see `at_top_level`).
///   Used by the caller to build a modified payload.
/// * `at_top_level` – `true` only when called for a direct child of the top-level
///   `payload.args` dict.  Prevents nested strings from being recorded in `stripped`,
///   which would overwrite an unrelated top-level key with the same name.
pub fn scan_value(
    key: &str,
    value: &Bound<'_, PyAny>,
    cfg: &SqlSanitizerConfig,
    issues: &mut Vec<String>,
    stripped: &mut StrippedFields,
    at_top_level: bool,
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
            // Only record a stripped replacement for top-level values.
            // Nested keys share names with unrelated top-level keys; applying
            // a shallow overlay with just the key name would overwrite the
            // wrong field (or inject a spurious new key).
            if cfg.strip_comments && at_top_level {
                let clean = strip_sql_comments(&text);
                if clean != text {
                    stripped.push((key.to_string(), clean));
                }
            }
        }
    } else if let Ok(list) = value.cast::<PyList>() {
        // Lists are checked before the dict-like branch because dicts and lists
        // both support item access in Python; we want lists handled explicitly.
        for item in list.iter() {
            if let Ok(dict_items) = item.call_method0("items") {
                // Dict-like items: use Python-level items() so subclasses such as
                // CopyOnWriteDict (write-layer outside the C hash table) are
                // iterated correctly.
                for entry in dict_items.try_iter()? {
                    let entry = entry?;
                    let k_str: String = entry.get_item(0)?.extract()?;
                    scan_value(&k_str, &entry.get_item(1)?, cfg, issues, stripped, false)?;
                }
            } else if item.cast::<PyList>().is_ok() {
                // Nested list (e.g. `[["DROP TABLE users"]]`): recurse with the
                // same parent key so strings at any depth are scanned for issues.
                scan_value(key, &item, cfg, issues, stripped, false)?;
            } else if let Ok(text) = item.extract::<String>() {
                // Plain string items inherit the parent key name.
                // NOTE: list items are scanned for issues but are intentionally
                // excluded from `stripped`.  `rebuild_args_with_stripped` applies
                // a shallow top-level overlay, so recording a (key, value) pair
                // here would overwrite the whole list with a single string.
                // Path-aware payload reconstruction is deferred.
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
    } else if let Ok(dict_items) = value.call_method0("items") {
        // Dict-like value: use Python-level items() so subclasses such as
        // CopyOnWriteDict (which keep their visible entries in a write-layer
        // outside the C hash table) are iterated correctly.  Plain `dict` also
        // satisfies this branch.  The PyList branch above ensures lists are not
        // accidentally matched here.
        for item in dict_items.try_iter()? {
            let item = item?;
            let k_str: String = item.get_item(0)?.extract()?;
            scan_value(&k_str, &item.get_item(1)?, cfg, issues, stripped, false)?;
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

    // Use Python-level items() so dict subclasses (e.g. CopyOnWriteDict) whose
    // visible entries live in a write-layer outside the C hash table are iterated
    // correctly.  C-level PyDict_Next would silently miss them.
    if let Ok(dict_items) = args.call_method0("items") {
        for item in dict_items.try_iter()? {
            let item = item?;
            let k_str: String = item.get_item(0)?.extract()?;
            scan_value(
                &k_str,
                &item.get_item(1)?,
                cfg,
                &mut issues,
                &mut stripped,
                true, // direct child of args dict → top-level
            )?;
        }
    }
    // Non-mapping args (should not happen in practice) are skipped silently.

    Ok((issues, stripped))
}
