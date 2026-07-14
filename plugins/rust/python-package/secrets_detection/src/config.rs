// Copyright 2026
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use pyo3::prelude::*;
use pyo3::types::{PyAny, PyDict};

use crate::patterns::PATTERNS;

const BROAD_PATTERNS: [&str; 4] = [
    "generic_api_key_assignment",
    "jwt_like",
    "hex_secret_32",
    "base64_24",
];

#[derive(Debug, Clone)]
pub struct SecretsDetectionConfig {
    pub enabled: HashMap<String, bool>,
    pub redact: bool,
    pub redaction_text: String,
    pub block_on_detection: bool,
    pub min_findings_to_block: usize,
    pub field_allowlist: Vec<FieldPath>,
    pub field_denylist: Vec<FieldPath>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldPath {
    segments: Vec<String>,
}

impl FieldPath {
    fn parse(path: String, field_name: &str) -> PyResult<Self> {
        if path.trim().is_empty() {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "{field_name} entries must not be empty or whitespace-only"
            )));
        }
        if path.starts_with('.') || path.ends_with('.') {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "{field_name} path {path:?} must not start or end with '.'"
            )));
        }

        let segments: Vec<String> = path.split('.').map(ToString::to_string).collect();
        if segments.iter().any(|segment| segment.trim().is_empty()) {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "{field_name} path {path:?} must not contain empty or whitespace-only segments"
            )));
        }

        Ok(Self { segments })
    }

    pub fn segments(&self) -> &[String] {
        &self.segments
    }

    fn matches_path_or_descendant(&self, path: &[String]) -> bool {
        path_starts_with(path, &self.segments)
    }

    fn can_be_reached_from(&self, path: &[String]) -> bool {
        path_starts_with(&self.segments, path)
    }
}

impl SecretsDetectionConfig {
    pub fn is_enabled(&self, name: &str) -> bool {
        self.enabled.get(name).copied().unwrap_or(false)
    }

    pub fn should_scan_field_path(&self, path: &[String], direct_scalar_root: bool) -> bool {
        if direct_scalar_root && path.is_empty() {
            return true;
        }
        if self.path_is_denied(path) {
            return false;
        }
        self.field_allowlist.is_empty()
            || self
                .field_allowlist
                .iter()
                .any(|allow_path| allow_path.matches_path_or_descendant(path))
    }

    pub fn should_traverse_field_path(&self, path: &[String]) -> bool {
        if path.is_empty() {
            return true;
        }
        if self.path_is_denied(path) {
            return false;
        }
        self.field_allowlist.is_empty()
            || self.field_allowlist.iter().any(|allow_path| {
                allow_path.matches_path_or_descendant(path) || allow_path.can_be_reached_from(path)
            })
    }

    fn path_is_denied(&self, path: &[String]) -> bool {
        self.field_denylist
            .iter()
            .any(|deny_path| deny_path.matches_path_or_descendant(path))
    }

    pub fn from_py_any(config: &Bound<'_, PyAny>) -> PyResult<Self> {
        if let Ok(dict) = config.cast::<PyDict>() {
            return Self::from_py_dict(dict);
        }

        let enabled = config
            .getattr("enabled")
            .ok()
            .map(|value| value.extract::<HashMap<String, bool>>())
            .transpose()?
            .map(merge_enabled_map)
            .unwrap_or_else(default_enabled_map);
        let redact = config
            .getattr("redact")
            .ok()
            .map(|value| value.extract::<bool>())
            .transpose()?
            .unwrap_or(false);
        let redaction_text = config
            .getattr("redaction_text")
            .ok()
            .map(|value| value.extract::<String>())
            .transpose()?
            .unwrap_or_else(|| "***REDACTED***".to_string());
        let block_on_detection = config
            .getattr("block_on_detection")
            .ok()
            .map(|value| value.extract::<bool>())
            .transpose()?
            .unwrap_or(true);
        let min_findings_to_block = config
            .getattr("min_findings_to_block")
            .ok()
            .map(|value| value.extract::<usize>())
            .transpose()?
            .unwrap_or(1);
        let field_allowlist = config
            .getattr("field_allowlist")
            .ok()
            .map(|value| parse_field_paths(&value, "field_allowlist"))
            .transpose()?
            .unwrap_or_default();
        let field_denylist = config
            .getattr("field_denylist")
            .ok()
            .map(|value| parse_field_paths(&value, "field_denylist"))
            .transpose()?
            .unwrap_or_default();

        Ok(Self {
            enabled,
            redact,
            redaction_text,
            block_on_detection,
            min_findings_to_block,
            field_allowlist,
            field_denylist,
        })
    }

    pub fn from_py_dict(dict: &Bound<'_, PyDict>) -> PyResult<Self> {
        let enabled = dict
            .get_item("enabled")?
            .map(|value| value.extract::<HashMap<String, bool>>())
            .transpose()?
            .map(merge_enabled_map)
            .unwrap_or_else(default_enabled_map);
        let redact = dict
            .get_item("redact")?
            .map(|value| value.extract::<bool>())
            .transpose()?
            .unwrap_or(false);
        let redaction_text = dict
            .get_item("redaction_text")?
            .map(|value| value.extract::<String>())
            .transpose()?
            .unwrap_or_else(|| "***REDACTED***".to_string());
        let block_on_detection = dict
            .get_item("block_on_detection")?
            .map(|value| value.extract::<bool>())
            .transpose()?
            .unwrap_or(true);
        let min_findings_to_block = dict
            .get_item("min_findings_to_block")?
            .map(|value| value.extract::<usize>())
            .transpose()?
            .unwrap_or(1);
        let field_allowlist = dict
            .get_item("field_allowlist")?
            .map(|value| parse_field_paths(&value, "field_allowlist"))
            .transpose()?
            .unwrap_or_default();
        let field_denylist = dict
            .get_item("field_denylist")?
            .map(|value| parse_field_paths(&value, "field_denylist"))
            .transpose()?
            .unwrap_or_default();

        Ok(Self {
            enabled,
            redact,
            redaction_text,
            block_on_detection,
            min_findings_to_block,
            field_allowlist,
            field_denylist,
        })
    }
}

impl Default for SecretsDetectionConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled_map(),
            redact: false,
            redaction_text: "***REDACTED***".to_string(),
            block_on_detection: true,
            min_findings_to_block: 1,
            field_allowlist: Vec::new(),
            field_denylist: Vec::new(),
        }
    }
}

fn parse_field_paths(value: &Bound<'_, PyAny>, field_name: &str) -> PyResult<Vec<FieldPath>> {
    value
        .extract::<Vec<String>>()
        .map_err(|_| {
            pyo3::exceptions::PyValueError::new_err(format!(
                "{field_name} must be a list of dotted field path strings"
            ))
        })?
        .into_iter()
        .map(|path| FieldPath::parse(path, field_name))
        .collect()
}

fn path_starts_with(path: &[String], prefix: &[String]) -> bool {
    path.len() >= prefix.len()
        && path
            .iter()
            .zip(prefix.iter())
            .all(|(left, right)| left == right)
}

fn default_enabled_map() -> HashMap<String, bool> {
    PATTERNS
        .keys()
        .map(|&name| (name.to_string(), !BROAD_PATTERNS.contains(&name)))
        .collect()
}

fn merge_enabled_map(overrides: HashMap<String, bool>) -> HashMap<String, bool> {
    let mut enabled = default_enabled_map();
    enabled.extend(overrides);
    enabled
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;

    use pyo3::types::PyModule;

    use super::*;

    #[test]
    fn broad_patterns_default_to_disabled() {
        let config = SecretsDetectionConfig::default();
        assert!(!config.is_enabled("generic_api_key_assignment"));
        assert!(!config.is_enabled("jwt_like"));
        assert!(config.is_enabled("aws_access_key_id"));
        assert!(config.field_allowlist.is_empty());
        assert!(config.field_denylist.is_empty());
    }

    #[test]
    fn from_py_dict_merges_overrides_with_defaults() {
        Python::initialize();
        Python::attach(|py| -> PyResult<()> {
            let dict = PyDict::new(py);
            let enabled = PyDict::new(py);
            enabled.set_item("jwt_like", true)?;
            enabled.set_item("aws_access_key_id", false)?;
            dict.set_item("enabled", enabled)?;
            dict.set_item("redact", true)?;
            dict.set_item("redaction_text", "[SECRET]")?;
            dict.set_item("block_on_detection", false)?;
            dict.set_item("min_findings_to_block", 3)?;
            dict.set_item("field_allowlist", ["layer1", "accounts.credentials"])?;
            dict.set_item(
                "field_denylist",
                ["layer1.layer2.layer3", "accounts.credentials.test_token"],
            )?;

            let config = SecretsDetectionConfig::from_py_dict(&dict)?;

            assert!(config.is_enabled("jwt_like"));
            assert!(!config.is_enabled("aws_access_key_id"));
            assert!(config.is_enabled("github_token"));
            assert!(config.redact);
            assert_eq!(config.redaction_text, "[SECRET]");
            assert!(!config.block_on_detection);
            assert_eq!(config.min_findings_to_block, 3);
            assert_eq!(segments(&config.field_allowlist[0]), vec!["layer1"]);
            assert_eq!(
                segments(&config.field_allowlist[1]),
                vec!["accounts", "credentials"]
            );
            assert_eq!(
                segments(&config.field_denylist[0]),
                vec!["layer1", "layer2", "layer3"]
            );
            assert_eq!(
                segments(&config.field_denylist[1]),
                vec!["accounts", "credentials", "test_token"]
            );
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn from_py_any_reads_attribute_config() {
        Python::initialize();
        Python::attach(|py| -> PyResult<()> {
            let code = CString::new(
                r#"
class Config:
    enabled = {"base64_24": True}
    redact = True
    redaction_text = "[MASKED]"
    block_on_detection = False
    min_findings_to_block = 2
    field_allowlist = ["payload.token"]
    field_denylist = ["payload.test_token"]
"#,
            )
            .unwrap();
            let module =
                PyModule::from_code(py, code.as_c_str(), c"config_test.py", c"config_test")?;
            let config_obj = module.getattr("Config")?.call0()?;

            let config = SecretsDetectionConfig::from_py_any(&config_obj)?;

            assert!(config.is_enabled("base64_24"));
            assert!(config.redact);
            assert_eq!(config.redaction_text, "[MASKED]");
            assert!(!config.block_on_detection);
            assert_eq!(config.min_findings_to_block, 2);
            assert_eq!(
                segments(&config.field_allowlist[0]),
                vec!["payload", "token"]
            );
            assert_eq!(
                segments(&config.field_denylist[0]),
                vec!["payload", "test_token"]
            );
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn from_py_dict_rejects_invalid_field_paths() {
        Python::initialize();
        Python::attach(|py| -> PyResult<()> {
            for (field_name, path, expected) in [
                (
                    "field_allowlist",
                    "",
                    "must not be empty or whitespace-only",
                ),
                (
                    "field_allowlist",
                    "   ",
                    "must not be empty or whitespace-only",
                ),
                ("field_denylist", ".token", "must not start or end with '.'"),
                ("field_denylist", "token.", "must not start or end with '.'"),
                (
                    "field_allowlist",
                    "layer1..layer3",
                    "must not contain empty or whitespace-only segments",
                ),
                (
                    "field_denylist",
                    "layer1. .layer3",
                    "must not contain empty or whitespace-only segments",
                ),
            ] {
                let dict = PyDict::new(py);
                dict.set_item(field_name, [path])?;

                let err = SecretsDetectionConfig::from_py_dict(&dict)
                    .expect_err("invalid field path should fail config parsing");

                assert!(
                    err.to_string().contains(expected),
                    "{field_name}={path:?}: {err}"
                );
            }
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn from_py_dict_rejects_non_string_field_path_entries() {
        Python::initialize();
        Python::attach(|py| -> PyResult<()> {
            let dict = PyDict::new(py);
            dict.set_item("field_allowlist", [1])?;

            let err = SecretsDetectionConfig::from_py_dict(&dict)
                .expect_err("non-string path should fail config parsing");

            assert!(
                err.to_string()
                    .contains("field_allowlist must be a list of dotted field path strings"),
                "{err}"
            );
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn field_path_matcher_scans_and_traverses_everything_by_default() {
        let config = SecretsDetectionConfig::default();

        assert!(config.should_scan_field_path(&path(&[]), true));
        assert!(config.should_scan_field_path(&path(&["layer1"]), false));
        assert!(config.should_scan_field_path(&path(&["accounts", "credentials", "token"]), false));
        assert!(config.should_traverse_field_path(&path(&[])));
        assert!(config.should_traverse_field_path(&path(&["layer1"])));
        assert!(config.should_traverse_field_path(&path(&["accounts", "credentials"])));
    }

    #[test]
    fn field_path_matcher_allows_listed_paths_and_descendants() {
        let config = config_with_field_paths(&["layer1"], &[]);

        assert!(config.should_scan_field_path(&path(&[]), true));
        assert!(!config.should_scan_field_path(&path(&[]), false));
        assert!(config.should_scan_field_path(&path(&["layer1"]), false));
        assert!(config.should_scan_field_path(&path(&["layer1", "public"]), false));
        assert!(config.should_traverse_field_path(&path(&[])));
        assert!(config.should_traverse_field_path(&path(&["layer1"])));
        assert!(config.should_traverse_field_path(&path(&["layer1", "public"])));
        assert!(!config.should_scan_field_path(&path(&["layer10"]), false));
        assert!(!config.should_traverse_field_path(&path(&["layer10"])));
    }

    #[test]
    fn field_path_matcher_traverses_unselected_parents_to_reach_nested_allowlist() {
        let config = config_with_field_paths(&["accounts.credentials.token"], &[]);

        assert!(config.should_traverse_field_path(&path(&[])));
        assert!(config.should_traverse_field_path(&path(&["accounts"])));
        assert!(config.should_traverse_field_path(&path(&["accounts", "credentials"])));
        assert!(!config.should_scan_field_path(&path(&["accounts"]), false));
        assert!(!config.should_scan_field_path(&path(&["accounts", "credentials"]), false));
        assert!(config.should_scan_field_path(&path(&["accounts", "credentials", "token"]), false));
        assert!(
            config.should_scan_field_path(
                &path(&["accounts", "credentials", "token", "value"]),
                false
            )
        );
        assert!(!config.should_traverse_field_path(&path(&["profile"])));
    }

    #[test]
    fn field_path_matcher_denylist_takes_precedence() {
        let config = config_with_field_paths(&["layer1"], &["layer1.layer2.layer3"]);

        assert!(config.should_scan_field_path(&path(&["layer1", "public"]), false));
        assert!(config.should_traverse_field_path(&path(&["layer1", "layer2"])));
        assert!(config.should_scan_field_path(&path(&["layer1", "layer2", "safe"]), false));
        assert!(!config.should_scan_field_path(&path(&["layer1", "layer2", "layer3"]), false));
        assert!(!config.should_traverse_field_path(&path(&["layer1", "layer2", "layer3"])));
        assert!(
            !config.should_scan_field_path(&path(&["layer1", "layer2", "layer3", "token"]), false)
        );
        assert!(
            !config.should_traverse_field_path(&path(&["layer1", "layer2", "layer3", "token"]))
        );
    }

    #[test]
    fn field_path_matcher_uses_segment_aware_matching() {
        let allow_config = config_with_field_paths(&["layer1"], &[]);
        assert!(allow_config.should_scan_field_path(&path(&["layer1"]), false));
        assert!(!allow_config.should_scan_field_path(&path(&["layer10"]), false));
        assert!(!allow_config.should_traverse_field_path(&path(&["layer10"])));

        let deny_config = config_with_field_paths(&[], &["layer1"]);
        assert!(!deny_config.should_scan_field_path(&path(&["layer1"]), false));
        assert!(!deny_config.should_scan_field_path(&path(&["layer1", "secret"]), false));
        assert!(deny_config.should_scan_field_path(&path(&["layer10"]), false));
        assert!(deny_config.should_traverse_field_path(&path(&["layer10"])));
    }

    fn segments(path: &FieldPath) -> Vec<&str> {
        path.segments().iter().map(String::as_str).collect()
    }

    fn config_with_field_paths(allow: &[&str], deny: &[&str]) -> SecretsDetectionConfig {
        SecretsDetectionConfig {
            field_allowlist: allow
                .iter()
                .map(|path| FieldPath::parse((*path).to_string(), "field_allowlist").unwrap())
                .collect(),
            field_denylist: deny
                .iter()
                .map(|path| FieldPath::parse((*path).to_string(), "field_denylist").unwrap())
                .collect(),
            ..Default::default()
        }
    }

    fn path(segments: &[&str]) -> Vec<String> {
        segments
            .iter()
            .map(|segment| (*segment).to_string())
            .collect()
    }
}
