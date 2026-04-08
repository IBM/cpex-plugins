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
}

impl SecretsDetectionConfig {
    pub fn is_enabled(&self, name: &str) -> bool {
        self.enabled.get(name).copied().unwrap_or(false)
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

        Ok(Self {
            enabled,
            redact,
            redaction_text,
            block_on_detection,
            min_findings_to_block,
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

        Ok(Self {
            enabled,
            redact,
            redaction_text,
            block_on_detection,
            min_findings_to_block,
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
        }
    }
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
    use super::*;

    #[test]
    fn broad_patterns_default_to_disabled() {
        let config = SecretsDetectionConfig::default();
        assert!(!config.is_enabled("generic_api_key_assignment"));
        assert!(!config.is_enabled("jwt_like"));
        assert!(config.is_enabled("aws_access_key_id"));
    }
}
