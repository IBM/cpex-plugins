// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
//
// Recursive scanner for Python dict/list/str argument trees.
//
// Behaviour:
//  - String leaves are scanned for SQL issues when their key matches `cfg.fields`
//    (or unconditionally when `fields` is `None`).
//  - Dicts are walked depth-first; each nested key is used as the scan key.
//  - Lists are walked by index; items inherit the parent key name for field
//    filtering, so `{"queries": ["…", "…"]}` filters on `queries`.
//  - Comment stripping records the **full path** to each rewritten value, so a
//    stripped replacement can be applied at any depth.  Recording only the leaf
//    key would be ambiguous (a nested `sql` key and a top-level `sql` key are
//    different fields) and would leave nested values un-rewritten — the payload
//    the database receives must match the text that was analysed.

use pyo3::prelude::*;
use pyo3::types::PyList;

use crate::comments::strip_sql_comments;
use crate::config::SqlSanitizerConfig;
use crate::issues::find_issues;

/// One step in the path from the top-level `args` dict down to a string leaf.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PathSeg {
    /// Mapping lookup by key.
    Key(String),
    /// Sequence lookup by position.
    Index(usize),
}

/// Flat list of `(path, stripped_sql_value)` produced when comments are removed.
///
/// `path` is rooted at the top-level `args` dict, so `[Key("wrapper"), Key("sql")]`
/// designates `args["wrapper"]["sql"]`.
pub type StrippedFields = Vec<(Vec<PathSeg>, String)>;

/// Recursively scan a single Python value and accumulate issues / stripped replacements.
///
/// # Arguments
///
/// * `key`     – Field name associated with this value (used for field filtering only).
///   List items inherit their parent's key so that a field filter applies to the
///   whole list.
/// * `value`   – The Python value to inspect.
/// * `cfg`     – Sanitizer configuration.
/// * `issues`  – Mutable accumulator for bare issue strings (e.g. `"DELETE without WHERE clause"`).
/// * `stripped`– Mutable accumulator of `(path, stripped_value)` pairs where comments
///   were removed.  Consumed by the caller to rebuild the outgoing payload.
/// * `path`    – Path from the top-level `args` dict to `value`.
pub fn scan_value(
    key: &str,
    value: &Bound<'_, PyAny>,
    cfg: &SqlSanitizerConfig,
    issues: &mut Vec<String>,
    stripped: &mut StrippedFields,
    path: &[PathSeg],
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
                    stripped.push((path.to_vec(), clean));
                }
            }
        }
    } else if let Ok(list) = value.cast::<PyList>() {
        // Lists are checked before the dict-like branch because dicts and lists
        // both support item access in Python; we want lists handled explicitly.
        // Items keep the parent key (for field filtering) and extend the path by
        // their index, so nested strings remain individually addressable.
        for (index, item) in list.iter().enumerate() {
            let mut child = path.to_vec();
            child.push(PathSeg::Index(index));
            scan_value(key, &item, cfg, issues, stripped, &child)?;
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
            let mut child = path.to_vec();
            child.push(PathSeg::Key(k_str.clone()));
            scan_value(&k_str, &item.get_item(1)?, cfg, issues, stripped, &child)?;
        }
    }
    // Other Python types (int, float, None, bytes …) are silently ignored.
    Ok(())
}

/// Scan an `args` dict (the top-level `payload.args` value) for SQL issues.
///
/// # Returns
///
/// `(issues, stripped)` where:
/// * `issues`  – flat list of bare issue description strings.
/// * `stripped`– flat list of `(path, stripped_sql)` pairs ready to apply to args.
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
                &[PathSeg::Key(k_str.clone())],
            )?;
        }
    }
    // Non-mapping args (should not happen in practice) are skipped silently.

    Ok((issues, stripped))
}
