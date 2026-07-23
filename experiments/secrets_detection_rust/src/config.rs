// Copyright 2026
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use serde::Deserialize;
use serde_json::Value;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError {
    message: String,
}

impl ConfigError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ConfigError {}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RawSecretsDetectionConfig {
    enabled: Option<HashMap<String, bool>>,
    redact: Option<bool>,
    redaction_text: Option<String>,
    block_on_detection: Option<bool>,
    min_findings_to_block: Option<usize>,
    field_allowlist: Option<Value>,
    field_denylist: Option<Value>,
}

impl FieldPath {
    pub fn parse(path: String, field_name: &str) -> Result<Self, ConfigError> {
        if path.trim().is_empty() {
            return Err(ConfigError::new(format!(
                "{field_name} entries must not be empty or whitespace-only"
            )));
        }
        if path.starts_with('.') || path.ends_with('.') {
            return Err(ConfigError::new(format!(
                "{field_name} path {path:?} must not start or end with '.'"
            )));
        }

        let segments: Vec<String> = path.split('.').map(ToString::to_string).collect();
        if segments.iter().any(|segment| segment.trim().is_empty()) {
            return Err(ConfigError::new(format!(
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
    pub fn from_value(value: Option<&Value>) -> Result<Self, ConfigError> {
        let raw = match value {
            Some(Value::Null) | None => RawSecretsDetectionConfig::default(),
            Some(value) => serde_json::from_value::<RawSecretsDetectionConfig>(value.clone())
                .map_err(|err| {
                    ConfigError::new(format!("invalid secrets_detection config: {err}"))
                })?,
        };

        Ok(Self {
            enabled: raw
                .enabled
                .map(merge_enabled_map)
                .unwrap_or_else(default_enabled_map),
            redact: raw.redact.unwrap_or(false),
            redaction_text: raw
                .redaction_text
                .unwrap_or_else(|| "***REDACTED***".to_string()),
            block_on_detection: raw.block_on_detection.unwrap_or(true),
            min_findings_to_block: raw.min_findings_to_block.unwrap_or(1),
            field_allowlist: parse_field_paths(raw.field_allowlist.as_ref(), "field_allowlist")?,
            field_denylist: parse_field_paths(raw.field_denylist.as_ref(), "field_denylist")?,
        })
    }

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

fn parse_field_paths(
    value: Option<&Value>,
    field_name: &str,
) -> Result<Vec<FieldPath>, ConfigError> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let entries = value.as_array().ok_or_else(|| {
        ConfigError::new(format!(
            "{field_name} must be a list of dotted field path strings"
        ))
    })?;
    entries
        .iter()
        .map(|entry| {
            let path = entry.as_str().ok_or_else(|| {
                ConfigError::new(format!(
                    "{field_name} must be a list of dotted field path strings"
                ))
            })?;
            FieldPath::parse(path.to_string(), field_name)
        })
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
    use serde_json::json;

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
    fn from_value_merges_overrides_with_defaults() {
        let value = json!({
            "enabled": {
                "jwt_like": true,
                "aws_access_key_id": false
            },
            "redact": true,
            "redaction_text": "[SECRET]",
            "block_on_detection": false,
            "min_findings_to_block": 3,
            "field_allowlist": ["layer1", "accounts.credentials"],
            "field_denylist": ["layer1.layer2.layer3", "accounts.credentials.test_token"]
        });

        let config = SecretsDetectionConfig::from_value(Some(&value)).unwrap();

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
    }

    #[test]
    fn from_value_rejects_invalid_field_paths() {
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
            let value = json!({ field_name: [path] });

            let err = SecretsDetectionConfig::from_value(Some(&value))
                .expect_err("invalid field path should fail config parsing");

            assert!(
                err.to_string().contains(expected),
                "{field_name}={path:?}: {err}"
            );
        }
    }

    #[test]
    fn from_value_rejects_non_string_field_path_entries() {
        let value = json!({ "field_allowlist": [1] });

        let err = SecretsDetectionConfig::from_value(Some(&value))
            .expect_err("non-string path should fail config parsing");

        assert!(
            err.to_string()
                .contains("field_allowlist must be a list of dotted field path strings"),
            "{err}"
        );
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
        assert!(config
            .should_scan_field_path(&path(&["accounts", "credentials", "token", "value"]), false));
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
        assert!(!config.should_traverse_field_path(&path(&["layer1", "layer2", "layer3", "token"])));
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

    fn path(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|part| (*part).to_string()).collect()
    }
}
