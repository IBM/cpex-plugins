// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
//
// Regex Filter Plugin - Rust Implementation

use std::borrow::Cow;
use std::collections::HashSet;
use std::sync::Once;

use log::debug;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList, PyModule, PySet, PyString, PyTuple};
use pyo3_stub_gen::define_stub_info_gatherer;
use pyo3_stub_gen::derive::*;
use regex::{Captures, Regex, RegexSet};

pub mod plugin;

const DEFAULT_MAX_TEXT_BYTES: usize = 10 * 1024 * 1024;
const DEFAULT_MAX_TOTAL_TEXT_BYTES: usize = 10 * 1024 * 1024;
const DEFAULT_MAX_NESTED_DEPTH: usize = 64;
const DEFAULT_MAX_COLLECTION_ITEMS: usize = 4096;
const DEFAULT_MAX_TOTAL_ITEMS: usize = 65_536;
const DEFAULT_MAX_PATTERNS: usize = 1024;
const DEFAULT_MAX_SEARCH_BYTES: usize = 1024 * 1024;
const DEFAULT_MAX_REPLACE_BYTES: usize = 1024 * 1024;
const DEFAULT_MAX_OUTPUT_BYTES: usize = 10 * 1024 * 1024;

enum TraversalResult {
    Unchanged(Py<PyAny>),
    Modified(Py<PyAny>),
}

#[derive(Debug, Clone)]
pub struct SearchReplace {
    pub search: String,
    pub replace: String,
    pub compiled: Regex,
}

#[derive(Debug, Clone)]
pub struct SearchReplaceConfig {
    pub words: Vec<SearchReplace>,
    pub pattern_set: Option<RegexSet>,
    pub max_text_bytes: usize,
    pub max_total_text_bytes: usize,
    pub max_nested_depth: usize,
    pub max_collection_items: usize,
    pub max_total_items: usize,
    pub max_output_bytes: usize,
}

impl SearchReplaceConfig {
    pub fn from_py_dict(dict: &Bound<'_, PyDict>) -> PyResult<Self> {
        let mut words = Vec::new();
        let mut patterns = Vec::new();
        let mut validation_errors = Vec::new();
        let max_text_bytes = get_usize(dict, "max_text_bytes", DEFAULT_MAX_TEXT_BYTES)?;
        let max_total_text_bytes =
            get_usize(dict, "max_total_text_bytes", DEFAULT_MAX_TOTAL_TEXT_BYTES)?;
        let max_nested_depth = get_usize(dict, "max_nested_depth", DEFAULT_MAX_NESTED_DEPTH)?;
        let max_collection_items =
            get_usize(dict, "max_collection_items", DEFAULT_MAX_COLLECTION_ITEMS)?;
        let max_total_items = get_usize(dict, "max_total_items", DEFAULT_MAX_TOTAL_ITEMS)?;
        let max_patterns = get_usize(dict, "max_patterns", DEFAULT_MAX_PATTERNS)?;
        let max_search_bytes = get_usize(dict, "max_search_bytes", DEFAULT_MAX_SEARCH_BYTES)?;
        let max_replace_bytes = get_usize(dict, "max_replace_bytes", DEFAULT_MAX_REPLACE_BYTES)?;
        let max_output_bytes = get_usize(dict, "max_output_bytes", DEFAULT_MAX_OUTPUT_BYTES)?;

        if let Some(words_value) = dict.get_item("words")? {
            let py_list = words_value
                .cast::<PyList>()
                .map_err(|_| pyo3::exceptions::PyValueError::new_err("'words' must be a list"))?;
            if py_list.len() > max_patterns {
                return Err(pyo3::exceptions::PyValueError::new_err(format!(
                    "'words' contains {} patterns, maximum is {}",
                    py_list.len(),
                    max_patterns
                )));
            }
            for (idx, item) in py_list.iter().enumerate() {
                let py_dict = item.cast::<PyDict>()?;
                let search: String = py_dict
                    .get_item("search")?
                    .ok_or_else(|| {
                        pyo3::exceptions::PyValueError::new_err("Missing 'search' field")
                    })?
                    .extract()?;
                let replace: String = py_dict
                    .get_item("replace")?
                    .ok_or_else(|| {
                        pyo3::exceptions::PyValueError::new_err("Missing 'replace' field")
                    })?
                    .extract()?;
                if search.len() > max_search_bytes {
                    validation_errors.push(format!(
                        "Pattern {}: search exceeds max_search_bytes ({})",
                        idx, max_search_bytes
                    ));
                    continue;
                }
                if replace.len() > max_replace_bytes {
                    validation_errors.push(format!(
                        "Pattern {}: replacement exceeds max_replace_bytes ({})",
                        idx, max_replace_bytes
                    ));
                    continue;
                }

                match Regex::new(&search) {
                    Ok(compiled) => {
                        patterns.push(search.clone());
                        words.push(SearchReplace {
                            search,
                            replace,
                            compiled,
                        });
                    }
                    Err(error) => validation_errors.push(format!(
                        "Pattern {}: Invalid regex pattern '{}': {}",
                        idx, search, error
                    )),
                }
            }
        }

        if !validation_errors.is_empty() {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "Invalid regex patterns detected:\n{}",
                validation_errors.join("\n")
            )));
        }

        let pattern_set = if patterns.is_empty() {
            None
        } else {
            Some(RegexSet::new(&patterns).map_err(|error| {
                pyo3::exceptions::PyValueError::new_err(format!(
                    "Invalid regex set configuration: {}",
                    error
                ))
            })?)
        };

        Ok(Self {
            words,
            pattern_set,
            max_text_bytes,
            max_total_text_bytes,
            max_nested_depth,
            max_collection_items,
            max_total_items,
            max_output_bytes,
        })
    }
}

fn get_usize(dict: &Bound<'_, PyDict>, key: &str, default: usize) -> PyResult<usize> {
    match dict.get_item(key)? {
        Some(value) => value.extract::<usize>(),
        None => Ok(default),
    }
}

#[gen_stub_pyclass]
#[derive(Debug)]
#[pyclass]
pub struct SearchReplacePluginRust {
    pub config: SearchReplaceConfig,
}

fn output_limit_error(limit: usize) -> PyErr {
    pyo3::exceptions::PyValueError::new_err(format!("Output exceeds max_output_bytes ({})", limit))
}

fn apply_patterns_impl<'a>(
    config: &'a SearchReplaceConfig,
    text: &'a str,
) -> PyResult<Cow<'a, str>> {
    if let Some(ref pattern_set) = config.pattern_set
        && !pattern_set.is_match(text)
    {
        return Ok(Cow::Borrowed(text));
    }

    let mut result = Cow::Borrowed(text);

    for pattern in &config.words {
        let mut captures = pattern.compiled.captures_iter(&result).peekable();
        if captures.peek().is_none() {
            continue;
        }

        let mut replaced = String::new();
        let mut last_end = 0;
        for caps in captures {
            let matched = caps.get(0).expect("regex captures always include group 0");
            append_limited(
                &mut replaced,
                &result[last_end..matched.start()],
                config.max_output_bytes,
            )?;
            append_replacement_limited(
                &mut replaced,
                &pattern.replace,
                &caps,
                config.max_output_bytes,
            )?;
            last_end = matched.end();
        }
        append_limited(&mut replaced, &result[last_end..], config.max_output_bytes)?;
        result = Cow::Owned(replaced);
    }

    Ok(result)
}

fn append_limited(target: &mut String, value: &str, limit: usize) -> PyResult<()> {
    if target.len().saturating_add(value.len()) > limit {
        return Err(output_limit_error(limit));
    }
    target.push_str(value);
    Ok(())
}

fn append_replacement_limited(
    target: &mut String,
    replacement: &str,
    caps: &Captures<'_>,
    limit: usize,
) -> PyResult<()> {
    let mut chars = replacement.char_indices().peekable();
    while let Some((idx, ch)) = chars.next() {
        if ch != '$' {
            append_limited(target, &replacement[idx..idx + ch.len_utf8()], limit)?;
            continue;
        }

        let Some((next_idx, next_ch)) = chars.peek().copied() else {
            append_limited(target, "$", limit)?;
            continue;
        };

        if next_ch == '$' {
            chars.next();
            append_limited(target, "$", limit)?;
            continue;
        }

        if next_ch == '{' {
            chars.next();
            let name_start = next_idx + next_ch.len_utf8();
            let mut name_end = None;
            for (candidate_idx, candidate_ch) in chars.by_ref() {
                if candidate_ch == '}' {
                    name_end = Some(candidate_idx);
                    break;
                }
            }
            let Some(name_end) = name_end else {
                append_limited(target, "$", limit)?;
                append_limited(target, &replacement[next_idx..], limit)?;
                break;
            };
            append_capture_limited(target, caps, &replacement[name_start..name_end], limit)?;
            continue;
        }

        if is_unbraced_capture_char(next_ch) {
            let name_start = next_idx;
            let mut name_end = next_idx + next_ch.len_utf8();
            chars.next();
            while let Some((name_idx, name_ch)) = chars.peek().copied() {
                if !is_unbraced_capture_char(name_ch) {
                    break;
                }
                chars.next();
                name_end = name_idx + name_ch.len_utf8();
            }
            append_capture_limited(target, caps, &replacement[name_start..name_end], limit)?;
            continue;
        }

        append_limited(target, "$", limit)?;
    }
    Ok(())
}

fn append_capture_limited(
    target: &mut String,
    caps: &Captures<'_>,
    name: &str,
    limit: usize,
) -> PyResult<()> {
    let capture = name
        .parse::<usize>()
        .ok()
        .and_then(|index| caps.get(index))
        .or_else(|| caps.name(name));
    if let Some(capture) = capture {
        append_limited(target, capture.as_str(), limit)?;
    }
    Ok(())
}

fn is_unbraced_capture_char(ch: char) -> bool {
    ch == '_' || ch.is_ascii_alphanumeric()
}

pub(crate) fn apply_patterns_checked<'a>(
    config: &'a SearchReplaceConfig,
    text: &'a str,
) -> PyResult<Cow<'a, str>> {
    if text.len() > config.max_text_bytes {
        return Err(pyo3::exceptions::PyValueError::new_err(format!(
            "Text exceeds max_text_bytes ({})",
            config.max_text_bytes
        )));
    }
    let result = apply_patterns_impl(config, text)?;
    if result.len() > config.max_output_bytes {
        return Err(output_limit_error(config.max_output_bytes));
    }
    Ok(result)
}

struct TraversalBudget {
    visited: usize,
    max_total_items: usize,
    output_bytes: usize,
    max_output_bytes: usize,
    input_bytes: usize,
    max_total_text_bytes: usize,
}

impl TraversalBudget {
    fn new(max_total_items: usize, max_output_bytes: usize, max_total_text_bytes: usize) -> Self {
        Self {
            visited: 0,
            max_total_items,
            output_bytes: 0,
            max_output_bytes,
            input_bytes: 0,
            max_total_text_bytes,
        }
    }

    fn visit(&mut self) -> PyResult<()> {
        self.visited += 1;
        if self.visited > self.max_total_items {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "Traversal exceeds max_total_items ({})",
                self.max_total_items
            )));
        }
        Ok(())
    }

    fn add_output(&mut self, bytes: usize) -> PyResult<()> {
        self.output_bytes = self.output_bytes.saturating_add(bytes);
        if self.output_bytes > self.max_output_bytes {
            return Err(output_limit_error(self.max_output_bytes));
        }
        Ok(())
    }

    fn add_input(&mut self, bytes: usize) -> PyResult<()> {
        self.input_bytes = self.input_bytes.saturating_add(bytes);
        if self.input_bytes > self.max_total_text_bytes {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "Input exceeds max_total_text_bytes ({})",
                self.max_total_text_bytes
            )));
        }
        Ok(())
    }
}

fn process_nested_impl(
    plugin: &SearchReplacePluginRust,
    py: Python<'_>,
    data: &Bound<'_, PyAny>,
    depth: usize,
    seen: &mut HashSet<usize>,
    budget: &mut TraversalBudget,
) -> PyResult<TraversalResult> {
    budget.visit()?;

    if depth >= plugin.config.max_nested_depth {
        return Err(pyo3::exceptions::PyValueError::new_err(format!(
            "Maximum nested depth of {} exceeded",
            plugin.config.max_nested_depth
        )));
    }

    if let Ok(text) = data.cast::<PyString>() {
        let text = text.to_str()?;
        budget.add_input(text.len())?;
        let modified_text = apply_patterns_checked(&plugin.config, text)?;
        return match modified_text {
            Cow::Borrowed(_) => {
                budget.add_output(text.len())?;
                Ok(TraversalResult::Unchanged(data.clone().unbind()))
            }
            Cow::Owned(value) => {
                budget.add_output(value.len())?;
                Ok(TraversalResult::Modified(
                    value.into_pyobject(py)?.into_any().unbind(),
                ))
            }
        };
    }

    if let Ok(dict) = data.cast::<PyDict>() {
        if dict.len() > plugin.config.max_collection_items {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "Collection exceeds max_collection_items ({})",
                plugin.config.max_collection_items
            )));
        }
        let identity = dict.as_ptr() as usize;
        if !seen.insert(identity) {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "Cyclic containers are not supported",
            ));
        }

        let mut processed_items: Option<Vec<(Py<PyAny>, Py<PyAny>)>> = None;
        for (index, (key, value)) in dict.iter().enumerate() {
            match process_nested_impl(plugin, py, &value, depth + 1, seen, budget)? {
                TraversalResult::Unchanged(new_value) => {
                    if let Some(items) = processed_items.as_mut() {
                        items.push((key.clone().unbind(), new_value));
                    }
                }
                TraversalResult::Modified(new_value) => {
                    let items = processed_items.get_or_insert_with(|| {
                        let mut items = Vec::with_capacity(dict.len());
                        for (prior_key, prior_value) in dict.iter().take(index) {
                            items.push((prior_key.clone().unbind(), prior_value.clone().unbind()));
                        }
                        items
                    });
                    items.push((key.clone().unbind(), new_value));
                }
            }
        }
        seen.remove(&identity);

        let Some(processed_items) = processed_items else {
            return Ok(TraversalResult::Unchanged(data.clone().unbind()));
        };

        let new_dict = PyDict::new(py);
        for (key, value) in processed_items {
            new_dict.set_item(key.bind(py), value.bind(py))?;
        }
        return Ok(TraversalResult::Modified(new_dict.into_any().unbind()));
    }

    if let Ok(list) = data.cast::<PyList>() {
        if list.len() > plugin.config.max_collection_items {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "Collection exceeds max_collection_items ({})",
                plugin.config.max_collection_items
            )));
        }
        let identity = list.as_ptr() as usize;
        if !seen.insert(identity) {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "Cyclic containers are not supported",
            ));
        }

        let mut new_items: Option<Vec<Py<PyAny>>> = None;
        for (index, item) in list.iter().enumerate() {
            match process_nested_impl(plugin, py, &item, depth + 1, seen, budget)? {
                TraversalResult::Unchanged(new_item) => {
                    if let Some(items) = new_items.as_mut() {
                        items.push(new_item);
                    }
                }
                TraversalResult::Modified(new_item) => {
                    let items = new_items.get_or_insert_with(|| {
                        list.iter()
                            .take(index)
                            .map(|prior_item| prior_item.clone().unbind())
                            .collect()
                    });
                    items.push(new_item);
                }
            }
        }
        seen.remove(&identity);

        let Some(new_items) = new_items else {
            return Ok(TraversalResult::Unchanged(data.clone().unbind()));
        };

        let new_list = PyList::empty(py);
        for item in new_items {
            new_list.append(item.bind(py))?;
        }
        return Ok(TraversalResult::Modified(new_list.into_any().unbind()));
    }

    if let Ok(tuple) = data.cast::<PyTuple>() {
        if tuple.len() > plugin.config.max_collection_items {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "Collection exceeds max_collection_items ({})",
                plugin.config.max_collection_items
            )));
        }
        let identity = tuple.as_ptr() as usize;
        if !seen.insert(identity) {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "Cyclic containers are not supported",
            ));
        }

        let mut new_items: Option<Vec<Py<PyAny>>> = None;
        for (index, item) in tuple.iter().enumerate() {
            match process_nested_impl(plugin, py, &item, depth + 1, seen, budget)? {
                TraversalResult::Unchanged(new_item) => {
                    if let Some(items) = new_items.as_mut() {
                        items.push(new_item);
                    }
                }
                TraversalResult::Modified(new_item) => {
                    let items = new_items.get_or_insert_with(|| {
                        tuple
                            .iter()
                            .take(index)
                            .map(|prior_item| prior_item.clone().unbind())
                            .collect()
                    });
                    items.push(new_item);
                }
            }
        }
        seen.remove(&identity);

        let Some(new_items) = new_items else {
            return Ok(TraversalResult::Unchanged(data.clone().unbind()));
        };

        let new_tuple = PyTuple::new(py, new_items.iter().map(|item| item.bind(py)))?;
        return Ok(TraversalResult::Modified(new_tuple.into_any().unbind()));
    }

    if let Ok(set) = data.cast::<PySet>() {
        if set.len() > plugin.config.max_collection_items {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "Collection exceeds max_collection_items ({})",
                plugin.config.max_collection_items
            )));
        }
        let identity = set.as_ptr() as usize;
        if !seen.insert(identity) {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "Cyclic containers are not supported",
            ));
        }

        let mut new_items: Option<Vec<Py<PyAny>>> = None;
        for (index, item) in set.iter().enumerate() {
            match process_nested_impl(plugin, py, &item, depth + 1, seen, budget)? {
                TraversalResult::Unchanged(new_item) => {
                    if let Some(items) = new_items.as_mut() {
                        items.push(new_item);
                    }
                }
                TraversalResult::Modified(new_item) => {
                    let items = new_items.get_or_insert_with(|| {
                        set.iter()
                            .take(index)
                            .map(|prior_item| prior_item.clone().unbind())
                            .collect()
                    });
                    items.push(new_item);
                }
            }
        }
        seen.remove(&identity);

        let Some(new_items) = new_items else {
            return Ok(TraversalResult::Unchanged(data.clone().unbind()));
        };

        let new_set = PySet::new(py, new_items.iter().map(|item| item.bind(py)))?;
        return Ok(TraversalResult::Modified(new_set.into_any().unbind()));
    }

    Ok(TraversalResult::Unchanged(data.clone().unbind()))
}

#[gen_stub_pymethods]
#[pymethods]
impl SearchReplacePluginRust {
    #[new]
    pub fn new(config_dict: &Bound<'_, PyDict>) -> PyResult<Self> {
        let config = SearchReplaceConfig::from_py_dict(config_dict).map_err(|error| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Invalid config: {}", error))
        })?;
        Ok(Self { config })
    }

    pub fn apply_patterns(&self, text: &str) -> PyResult<String> {
        Ok(apply_patterns_checked(&self.config, text)?.into_owned())
    }

    pub fn process_nested(
        &self,
        py: Python<'_>,
        data: &Bound<'_, PyAny>,
    ) -> PyResult<(bool, Py<PyAny>)> {
        let mut seen = HashSet::new();
        let mut budget = TraversalBudget::new(
            self.config.max_total_items,
            self.config.max_output_bytes,
            self.config.max_total_text_bytes,
        );
        Ok(
            match process_nested_impl(self, py, data, 0, &mut seen, &mut budget)? {
                TraversalResult::Unchanged(value) => (false, value),
                TraversalResult::Modified(value) => (true, value),
            },
        )
    }
}

fn init_logging() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        pyo3_log::init();
    });
}

#[pymodule]
fn regex_filter_rust(m: &Bound<'_, PyModule>) -> PyResult<()> {
    init_logging();
    debug!("Initialized regex_filter Rust module");
    m.add_class::<SearchReplacePluginRust>()?;
    m.add_class::<plugin::RegexFilterPluginCore>()?;
    Ok(())
}

define_stub_info_gatherer!(stub_info);

#[cfg(test)]
mod tests {
    use super::*;

    fn plugin_with_words(words: Vec<(&str, &str)>) -> SearchReplacePluginRust {
        let patterns = words
            .iter()
            .map(|(search, _)| search.to_string())
            .collect::<Vec<_>>();
        let config = SearchReplaceConfig {
            words: words
                .into_iter()
                .map(|(search, replace)| SearchReplace {
                    search: search.to_string(),
                    replace: replace.to_string(),
                    compiled: Regex::new(search).unwrap(),
                })
                .collect(),
            pattern_set: RegexSet::new(patterns).ok(),
            max_text_bytes: DEFAULT_MAX_TEXT_BYTES,
            max_total_text_bytes: DEFAULT_MAX_TOTAL_TEXT_BYTES,
            max_nested_depth: DEFAULT_MAX_NESTED_DEPTH,
            max_collection_items: DEFAULT_MAX_COLLECTION_ITEMS,
            max_total_items: DEFAULT_MAX_TOTAL_ITEMS,
            max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
        };
        SearchReplacePluginRust { config }
    }

    #[test]
    fn test_apply_patterns() {
        let plugin = plugin_with_words(vec![
            (r"\bsecret\b", "[REDACTED]"),
            (r"\bpassword\b", "[REDACTED]"),
        ]);
        assert_eq!(
            plugin
                .apply_patterns("The secret password is hidden")
                .unwrap(),
            "The [REDACTED] [REDACTED] is hidden"
        );
    }

    #[test]
    fn test_no_match() {
        let plugin = plugin_with_words(vec![(r"\bsecret\b", "[REDACTED]")]);
        assert_eq!(
            plugin.apply_patterns("No sensitive data here").unwrap(),
            "No sensitive data here"
        );
    }

    #[test]
    fn test_multiple_matches() {
        let plugin = plugin_with_words(vec![(r"\d{3}-\d{2}-\d{4}", "XXX-XX-XXXX")]);
        assert_eq!(
            plugin
                .apply_patterns("SSN: 123-45-6789 and 987-65-4321")
                .unwrap(),
            "SSN: XXX-XX-XXXX and XXX-XX-XXXX"
        );
    }

    #[test]
    fn test_empty_config() {
        let plugin = SearchReplacePluginRust {
            config: SearchReplaceConfig {
                words: vec![],
                pattern_set: None,
                max_text_bytes: DEFAULT_MAX_TEXT_BYTES,
                max_total_text_bytes: DEFAULT_MAX_TOTAL_TEXT_BYTES,
                max_nested_depth: DEFAULT_MAX_NESTED_DEPTH,
                max_collection_items: DEFAULT_MAX_COLLECTION_ITEMS,
                max_total_items: DEFAULT_MAX_TOTAL_ITEMS,
                max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
            },
        };
        assert_eq!(
            plugin
                .apply_patterns("Any text should pass through unchanged")
                .unwrap(),
            "Any text should pass through unchanged"
        );
    }

    #[test]
    fn test_case_insensitive_matching() {
        let plugin = plugin_with_words(vec![(r"(?i)\bsecret\b", "[REDACTED]")]);
        assert_eq!(
            plugin.apply_patterns("Secret data").unwrap(),
            "[REDACTED] data"
        );
        assert_eq!(
            plugin.apply_patterns("secret data").unwrap(),
            "[REDACTED] data"
        );
        assert_eq!(
            plugin.apply_patterns("SECRET data").unwrap(),
            "[REDACTED] data"
        );
    }

    #[test]
    fn test_replacement_with_capture_groups() {
        let plugin = plugin_with_words(vec![(r"(\d{3})-(\d{2})-(\d{4})", "***-**-$3")]);
        assert_eq!(
            plugin.apply_patterns("SSN: 123-45-6789").unwrap(),
            "SSN: ***-**-6789"
        );
    }

    #[test]
    fn test_word_boundary_patterns() {
        let plugin = plugin_with_words(vec![(r"\bcat\b", "dog")]);
        assert_eq!(plugin.apply_patterns("the cat sat").unwrap(), "the dog sat");
        assert_eq!(plugin.apply_patterns("category").unwrap(), "category");
        assert_eq!(plugin.apply_patterns("scat").unwrap(), "scat");
    }

    #[test]
    fn test_email_pattern() {
        let plugin = plugin_with_words(vec![(
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
            "[EMAIL]",
        )]);
        assert_eq!(
            plugin
                .apply_patterns("Contact user@example.com for info")
                .unwrap(),
            "Contact [EMAIL] for info"
        );
    }

    #[test]
    fn test_url_pattern() {
        let plugin = plugin_with_words(vec![(r"https?://[^\s]+", "[URL]")]);
        assert_eq!(
            plugin
                .apply_patterns("Visit https://example.com for more")
                .unwrap(),
            "Visit [URL] for more"
        );
    }

    #[test]
    fn test_multiple_replacements_in_sequence() {
        let plugin = plugin_with_words(vec![("a", "1"), ("b", "2"), ("c", "3")]);
        assert_eq!(plugin.apply_patterns("abc").unwrap(), "123");
    }

    #[test]
    fn test_newline_handling() {
        let plugin = plugin_with_words(vec![("secret", "[REDACTED]")]);
        assert_eq!(
            plugin.apply_patterns("Line 1\nsecret\nLine 3").unwrap(),
            "Line 1\n[REDACTED]\nLine 3"
        );
    }

    #[test]
    fn test_empty_replacement() {
        let plugin = plugin_with_words(vec![(r"\bremove\b", "")]);
        assert_eq!(
            plugin.apply_patterns("Please remove this word").unwrap(),
            "Please  this word"
        );
    }

    #[test]
    fn test_invalid_config_reports_source_style_errors() {
        Python::initialize();
        Python::attach(|py| {
            let dict = PyDict::new(py);
            let words = PyList::empty(py);
            let word = PyDict::new(py);
            word.set_item("search", "[invalid(").unwrap();
            word.set_item("replace", "x").unwrap();
            words.append(word).unwrap();
            dict.set_item("words", words).unwrap();

            let error = SearchReplacePluginRust::new(&dict).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("Invalid regex patterns detected")
            );
            assert!(error.to_string().contains("[invalid("));
        });
    }

    #[test]
    fn test_config_limits_report_validation_errors() {
        Python::initialize();
        Python::attach(|py| {
            let dict = PyDict::new(py);
            let words = PyList::empty(py);
            let word = PyDict::new(py);
            word.set_item("search", "secret").unwrap();
            word.set_item("replace", "redacted").unwrap();
            words.append(word).unwrap();
            dict.set_item("words", words).unwrap();
            dict.set_item("max_search_bytes", 2).unwrap();
            dict.set_item("max_replace_bytes", 3).unwrap();

            let error = SearchReplacePluginRust::new(&dict).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("search exceeds max_search_bytes")
            );
        });
    }

    #[test]
    fn test_config_rejects_too_many_patterns_and_non_list_words() {
        Python::initialize();
        Python::attach(|py| {
            let dict = PyDict::new(py);
            let words = PyList::empty(py);
            for search in ["a", "b"] {
                let word = PyDict::new(py);
                word.set_item("search", search).unwrap();
                word.set_item("replace", "x").unwrap();
                words.append(word).unwrap();
            }
            dict.set_item("words", words).unwrap();
            dict.set_item("max_patterns", 1).unwrap();
            let error = SearchReplacePluginRust::new(&dict).unwrap_err();
            assert!(error.to_string().contains("'words' contains 2 patterns"));

            let dict = PyDict::new(py);
            dict.set_item("words", "not-a-list").unwrap();
            let error = SearchReplacePluginRust::new(&dict).unwrap_err();
            assert!(error.to_string().contains("'words' must be a list"));
        });
    }

    #[test]
    fn test_process_nested_rewrites_dict_list_tuple_and_set() {
        let plugin = plugin_with_words(vec![("bad", "good")]);
        Python::initialize();
        Python::attach(|py| {
            let nested = PyDict::new(py);
            nested.set_item("value", "bad").unwrap();
            let list = PyList::new(py, ["bad", "fine"]).unwrap();
            let tuple = PyTuple::new(py, ["bad"]).unwrap();
            let set = PySet::new(py, ["bad", "fine"]).unwrap();
            let payload = PyDict::new(py);
            payload.set_item("nested", nested).unwrap();
            payload.set_item("list", list).unwrap();
            payload.set_item("tuple", tuple).unwrap();
            payload.set_item("set", set).unwrap();

            let (modified, result) = plugin.process_nested(py, payload.as_any()).unwrap();
            assert!(modified);
            let result = result.bind(py).cast::<PyDict>().unwrap();
            let nested_obj = result.get_item("nested").unwrap().unwrap();
            let nested = nested_obj.cast::<PyDict>().unwrap();
            let nested_value: String = nested
                .get_item("value")
                .unwrap()
                .unwrap()
                .extract()
                .unwrap();
            assert_eq!(nested_value, "good");
            let list_obj = result.get_item("list").unwrap().unwrap();
            let list = list_obj.cast::<PyList>().unwrap();
            let list_value: String = list.get_item(0).unwrap().extract().unwrap();
            assert_eq!(list_value, "good");
            let tuple_obj = result.get_item("tuple").unwrap().unwrap();
            let tuple = tuple_obj.cast::<PyTuple>().unwrap();
            let tuple_value: String = tuple.get_item(0).unwrap().extract().unwrap();
            assert_eq!(tuple_value, "good");
            let set_obj = result.get_item("set").unwrap().unwrap();
            let set = set_obj.cast::<PySet>().unwrap();
            assert!(set.contains("good").unwrap());
        });
    }

    #[test]
    fn test_process_nested_returns_original_on_no_change() {
        let plugin = plugin_with_words(vec![("missing", "found")]);
        Python::initialize();
        Python::attach(|py| {
            let payload = PyList::new(py, ["clean"]).unwrap();
            let original_ptr = payload.as_ptr();
            let (modified, result) = plugin.process_nested(py, payload.as_any()).unwrap();
            assert!(!modified);
            assert_eq!(result.bind(py).as_ptr(), original_ptr);
        });
    }

    #[test]
    fn test_process_nested_enforces_runtime_budgets() {
        let mut plugin = plugin_with_words(vec![("a", "bbbb")]);
        plugin.config.max_text_bytes = 2;
        Python::initialize();
        Python::attach(|py| {
            let error = plugin
                .process_nested(py, PyString::new(py, "aaa").as_any())
                .unwrap_err();
            assert!(error.to_string().contains("Text exceeds max_text_bytes"));
        });

        let mut plugin = plugin_with_words(vec![("missing", "found")]);
        plugin.config.max_total_text_bytes = 5;
        Python::attach(|py| {
            let payload = PyList::new(py, ["aaa", "aaa"]).unwrap();
            let error = plugin.process_nested(py, payload.as_any()).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("Input exceeds max_total_text_bytes")
            );
        });

        let mut plugin = plugin_with_words(vec![("missing", "found")]);
        plugin.config.max_output_bytes = 5;
        Python::attach(|py| {
            let payload = PyList::new(py, ["aaa", "aaa"]).unwrap();
            let error = plugin.process_nested(py, payload.as_any()).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("Output exceeds max_output_bytes")
            );
        });
    }

    #[test]
    fn test_process_nested_enforces_shape_limits_and_cycles() {
        let mut plugin = plugin_with_words(vec![("bad", "good")]);
        plugin.config.max_collection_items = 1;
        Python::initialize();
        Python::attach(|py| {
            let payload = PyList::new(py, ["bad", "bad"]).unwrap();
            let error = plugin.process_nested(py, payload.as_any()).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("Collection exceeds max_collection_items")
            );
        });

        let mut plugin = plugin_with_words(vec![("bad", "good")]);
        plugin.config.max_total_items = 2;
        Python::attach(|py| {
            let inner_one = PyList::new(py, ["bad"]).unwrap();
            let inner_two = PyList::new(py, ["bad"]).unwrap();
            let outer = PyList::new(py, [inner_one.as_any(), inner_two.as_any()]).unwrap();
            let error = plugin.process_nested(py, outer.as_any()).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("Traversal exceeds max_total_items")
            );
        });

        let mut plugin = plugin_with_words(vec![("bad", "good")]);
        plugin.config.max_nested_depth = 1;
        Python::attach(|py| {
            let inner = PyList::new(py, ["bad"]).unwrap();
            let outer = PyList::new(py, [inner.as_any()]).unwrap();
            let error = plugin.process_nested(py, outer.as_any()).unwrap_err();
            assert!(error.to_string().contains("Maximum nested depth"));
        });
    }
}
