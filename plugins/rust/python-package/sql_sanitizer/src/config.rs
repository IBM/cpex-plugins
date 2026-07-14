// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
//
// Configuration for SQL Sanitizer plugin

use once_cell::sync::Lazy;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use regex::Regex;

/// Default blocked SQL statement patterns compiled once at startup.
static DEFAULT_BLOCKED_PATTERNS: Lazy<Vec<(String, Regex)>> = Lazy::new(|| {
    let patterns = [
        r"\bDROP\b",
        r"\bTRUNCATE\b",
        r"\bALTER\b",
        r"\bGRANT\b",
        r"\bREVOKE\b",
    ];
    patterns
        .iter()
        .map(|p| {
            let re = Regex::new(&format!("(?i){}", p)).expect("Invalid default blocked pattern");
            ((*p).to_string(), re)
        })
        .collect()
});

/// Compiled runtime configuration for the SQL Sanitizer plugin.
pub struct SqlSanitizerConfig {
    /// If `Some`, only field names in this list are scanned.  `None` scans every string value.
    pub fields: Option<Vec<String>>,
    /// Each entry: `(raw_pattern_string, compiled_Regex)`.
    /// The raw string is used verbatim in violation messages.
    pub blocked_patterns: Vec<(String, Regex)>,
    /// Block `DELETE FROM …` without a `WHERE` clause.
    pub block_delete_without_where: bool,
    /// Block `UPDATE … SET` without a `WHERE` clause.
    pub block_update_without_where: bool,
    /// Strip `--` and `/* */` comments before analysis.
    pub strip_comments: bool,
    /// Heuristic check for non-parameterized interpolation (`+`, `{…}`, `%.`).
    pub require_parameterization: bool,
    /// Return `continue_processing=False` when a violation is found.
    pub block_on_violation: bool,
}

impl Default for SqlSanitizerConfig {
    fn default() -> Self {
        Self {
            fields: None,
            blocked_patterns: DEFAULT_BLOCKED_PATTERNS.clone(),
            block_delete_without_where: true,
            block_update_without_where: true,
            strip_comments: true,
            require_parameterization: false,
            block_on_violation: true,
        }
    }
}

impl SqlSanitizerConfig {
    /// Parse configuration from a Python object (plain `dict` or Pydantic model).
    pub fn from_py_object(obj: &Bound<'_, PyAny>) -> PyResult<Self> {
        if obj.is_none() {
            return Ok(Self::default());
        }

        let dict: Bound<'_, PyDict> = if obj.is_instance_of::<PyDict>() {
            obj.cast::<PyDict>()?.clone()
        } else if obj.hasattr("model_dump")? {
            obj.call_method0("model_dump")?.cast::<PyDict>()?.clone()
        } else {
            // Nothing useful — fall back to defaults
            return Ok(Self::default());
        };

        Self::from_py_dict(&dict)
    }

    fn from_py_dict(dict: &Bound<'_, PyDict>) -> PyResult<Self> {
        let mut cfg = Self::default();

        // fields: Optional[list[str]]
        if let Some(val) = dict.get_item("fields")?
            && !val.is_none()
        {
            cfg.fields = Some(val.extract::<Vec<String>>()?);
        }

        // blocked_statements: list[str | re.Pattern]
        // Accepts either raw strings or Python compiled regex objects (which have a `.pattern` attr).
        if let Some(val) = dict.get_item("blocked_statements")?
            && !val.is_none()
            && let Ok(list) = val.cast::<PyList>()
        {
            let mut patterns: Vec<(String, Regex)> = Vec::with_capacity(list.len());
            for item in list.iter() {
                let raw: String = if let Ok(s) = item.extract::<String>() {
                    s
                } else if let Ok(p) = item.getattr("pattern") {
                    p.extract::<String>()?
                } else {
                    continue;
                };
                // Avoid double-wrapping if the caller already embedded flags.
                let wrapped = if raw.starts_with("(?") {
                    raw.clone()
                } else {
                    format!("(?i){}", raw)
                };
                let re = Regex::new(&wrapped).map_err(|e| {
                    pyo3::exceptions::PyValueError::new_err(format!(
                        "Invalid blocked_statements pattern '{}': {}",
                        raw, e
                    ))
                })?;
                patterns.push((raw, re));
            }
            cfg.blocked_patterns = patterns;
        }

        // Boolean fields — helper macro avoids repetition.
        macro_rules! extract_bool {
            ($field:ident) => {
                if let Some(val) = dict.get_item(stringify!($field))? {
                    if !val.is_none() {
                        cfg.$field = val.extract::<bool>()?;
                    }
                }
            };
        }

        extract_bool!(block_delete_without_where);
        extract_bool!(block_update_without_where);
        extract_bool!(strip_comments);
        extract_bool!(require_parameterization);
        extract_bool!(block_on_violation);

        Ok(cfg)
    }
}
