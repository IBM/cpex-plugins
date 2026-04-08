// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
//
// Regex Filter Plugin - Rust Implementation

use std::borrow::Cow;
use std::sync::Once;

use log::debug;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList, PyModule, PyTuple};
use pyo3_stub_gen::define_stub_info_gatherer;
use regex::{Regex, RegexSet};

pub mod plugin;

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
}

impl SearchReplaceConfig {
    pub fn from_py_dict(dict: &Bound<'_, PyDict>) -> PyResult<Self> {
        let mut words = Vec::new();
        let mut patterns = Vec::new();
        let mut validation_errors = Vec::new();

        if let Some(words_value) = dict.get_item("words")?
            && let Ok(py_list) = words_value.cast::<PyList>()
        {
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
            RegexSet::new(&patterns).ok()
        };

        Ok(Self { words, pattern_set })
    }
}

#[derive(Debug)]
#[pyclass]
pub struct SearchReplacePluginRust {
    pub config: SearchReplaceConfig,
}

#[pymethods]
impl SearchReplacePluginRust {
    #[new]
    pub fn new(config_dict: &Bound<'_, PyDict>) -> PyResult<Self> {
        let config = SearchReplaceConfig::from_py_dict(config_dict).map_err(|error| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Invalid config: {}", error))
        })?;
        Ok(Self { config })
    }

    pub fn apply_patterns(&self, text: &str) -> String {
        if let Some(ref pattern_set) = self.config.pattern_set
            && !pattern_set.is_match(text)
        {
            return text.to_string();
        }

        let mut result = Cow::Borrowed(text);
        let mut modified = false;

        for pattern in &self.config.words {
            if pattern.compiled.is_match(&result) {
                let replaced = pattern.compiled.replace_all(&result, &pattern.replace);
                if let Cow::Owned(new_text) = replaced {
                    result = Cow::Owned(new_text);
                    modified = true;
                } else if modified {
                    result = Cow::Owned(replaced.into_owned());
                }
            }
        }

        result.into_owned()
    }

    pub fn process_nested(
        &self,
        py: Python<'_>,
        data: &Bound<'_, PyAny>,
    ) -> PyResult<(bool, Py<PyAny>)> {
        if let Ok(text) = data.extract::<String>() {
            let modified_text = self.apply_patterns(&text);
            if modified_text == text {
                return Ok((false, data.clone().unbind()));
            }
            return Ok((true, modified_text.into_pyobject(py)?.into_any().unbind()));
        }

        if let Ok(dict) = data.cast::<PyDict>() {
            let mut any_modified = false;
            let mut processed_items = Vec::with_capacity(dict.len());
            for (key, value) in dict.iter() {
                let (item_modified, new_value) = self.process_nested(py, &value)?;
                any_modified |= item_modified;
                processed_items.push((key.clone().unbind(), new_value));
            }

            if !any_modified {
                return Ok((false, data.clone().unbind()));
            }

            let new_dict = PyDict::new(py);
            for (key, value) in processed_items {
                new_dict.set_item(key.bind(py), value.bind(py))?;
            }
            return Ok((true, new_dict.into_any().unbind()));
        }

        if let Ok(list) = data.cast::<PyList>() {
            let mut any_modified = false;
            let mut new_items = Vec::with_capacity(list.len());
            for item in list.iter() {
                let (item_modified, new_item) = self.process_nested(py, &item)?;
                any_modified |= item_modified;
                new_items.push(new_item);
            }

            if !any_modified {
                return Ok((false, data.clone().unbind()));
            }

            let new_list = PyList::empty(py);
            for item in new_items {
                new_list.append(item.bind(py))?;
            }
            return Ok((true, new_list.into_any().unbind()));
        }

        if let Ok(tuple) = data.cast::<PyTuple>() {
            let mut any_modified = false;
            let mut new_items = Vec::with_capacity(tuple.len());
            for item in tuple.iter() {
                let (item_modified, new_item) = self.process_nested(py, &item)?;
                any_modified |= item_modified;
                new_items.push(new_item);
            }

            if !any_modified {
                return Ok((false, data.clone().unbind()));
            }

            let new_tuple = PyTuple::new(py, new_items.iter().map(|item| item.bind(py)))?;
            return Ok((true, new_tuple.into_any().unbind()));
        }

        Ok((false, data.clone().unbind()))
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
            plugin.apply_patterns("The secret password is hidden"),
            "The [REDACTED] [REDACTED] is hidden"
        );
    }

    #[test]
    fn test_no_match() {
        let plugin = plugin_with_words(vec![(r"\bsecret\b", "[REDACTED]")]);
        assert_eq!(
            plugin.apply_patterns("No sensitive data here"),
            "No sensitive data here"
        );
    }

    #[test]
    fn test_multiple_matches() {
        let plugin = plugin_with_words(vec![(r"\d{3}-\d{2}-\d{4}", "XXX-XX-XXXX")]);
        assert_eq!(
            plugin.apply_patterns("SSN: 123-45-6789 and 987-65-4321"),
            "SSN: XXX-XX-XXXX and XXX-XX-XXXX"
        );
    }

    #[test]
    fn test_empty_config() {
        let plugin = SearchReplacePluginRust {
            config: SearchReplaceConfig {
                words: vec![],
                pattern_set: None,
            },
        };
        assert_eq!(
            plugin.apply_patterns("Any text should pass through unchanged"),
            "Any text should pass through unchanged"
        );
    }

    #[test]
    fn test_case_insensitive_matching() {
        let plugin = plugin_with_words(vec![(r"(?i)\bsecret\b", "[REDACTED]")]);
        assert_eq!(plugin.apply_patterns("Secret data"), "[REDACTED] data");
        assert_eq!(plugin.apply_patterns("secret data"), "[REDACTED] data");
        assert_eq!(plugin.apply_patterns("SECRET data"), "[REDACTED] data");
    }

    #[test]
    fn test_replacement_with_capture_groups() {
        let plugin = plugin_with_words(vec![(r"(\d{3})-(\d{2})-(\d{4})", "***-**-$3")]);
        assert_eq!(
            plugin.apply_patterns("SSN: 123-45-6789"),
            "SSN: ***-**-6789"
        );
    }

    #[test]
    fn test_word_boundary_patterns() {
        let plugin = plugin_with_words(vec![(r"\bcat\b", "dog")]);
        assert_eq!(plugin.apply_patterns("the cat sat"), "the dog sat");
        assert_eq!(plugin.apply_patterns("category"), "category");
        assert_eq!(plugin.apply_patterns("scat"), "scat");
    }

    #[test]
    fn test_email_pattern() {
        let plugin = plugin_with_words(vec![(
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
            "[EMAIL]",
        )]);
        assert_eq!(
            plugin.apply_patterns("Contact user@example.com for info"),
            "Contact [EMAIL] for info"
        );
    }

    #[test]
    fn test_url_pattern() {
        let plugin = plugin_with_words(vec![(r"https?://[^\s]+", "[URL]")]);
        assert_eq!(
            plugin.apply_patterns("Visit https://example.com for more"),
            "Visit [URL] for more"
        );
    }

    #[test]
    fn test_multiple_replacements_in_sequence() {
        let plugin = plugin_with_words(vec![("a", "1"), ("b", "2"), ("c", "3")]);
        assert_eq!(plugin.apply_patterns("abc"), "123");
    }

    #[test]
    fn test_newline_handling() {
        let plugin = plugin_with_words(vec![("secret", "[REDACTED]")]);
        assert_eq!(
            plugin.apply_patterns("Line 1\nsecret\nLine 3"),
            "Line 1\n[REDACTED]\nLine 3"
        );
    }

    #[test]
    fn test_empty_replacement() {
        let plugin = plugin_with_words(vec![(r"\bremove\b", "")]);
        assert_eq!(
            plugin.apply_patterns("Please remove this word"),
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
}
