// Copyright 2026
// SPDX-License-Identifier: Apache-2.0

use pyo3::prelude::*;
use pyo3::types::PyDict;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,

    #[serde(default = "default_backoff_base_ms")]
    pub backoff_base_ms: u64,

    #[serde(default = "default_max_backoff_ms")]
    pub max_backoff_ms: u64,

    #[serde(default = "default_retry_on_status")]
    pub retry_on_status: Vec<i32>,

    #[serde(default = "default_jitter")]
    pub jitter: bool,

    #[serde(default)]
    pub check_text_content: bool,

    #[serde(default)]
    pub tool_overrides: HashMap<String, ToolOverride>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolOverride {
    pub max_retries: Option<u32>,
    pub backoff_base_ms: Option<u64>,
    pub max_backoff_ms: Option<u64>,
    pub retry_on_status: Option<Vec<i32>>,
    pub jitter: Option<bool>,
    pub check_text_content: Option<bool>,
}

fn default_max_retries() -> u32 {
    2
}

fn default_backoff_base_ms() -> u64 {
    200
}

fn default_max_backoff_ms() -> u64 {
    5000
}

fn default_jitter() -> bool {
    true
}

fn default_retry_on_status() -> Vec<i32> {
    vec![429, 500, 502, 503, 504]
}

impl RetryConfig {
    /// Parse configuration from a Python dictionary
    pub fn from_py_dict(dict: &Bound<'_, PyDict>) -> PyResult<Self> {
        let max_retries = match dict.get_item("max_retries")? {
            Some(v) => v.extract::<u32>().map_err(|_| {
                PyErr::new::<pyo3::exceptions::PyValueError, _>(
                    "max_retries must be a non-negative integer",
                )
            })?,
            None => default_max_retries(),
        };

        let backoff_base_ms = match dict.get_item("backoff_base_ms")? {
            Some(v) => v.extract::<u64>().map_err(|_| {
                PyErr::new::<pyo3::exceptions::PyValueError, _>(
                    "backoff_base_ms must be a non-negative integer",
                )
            })?,
            None => default_backoff_base_ms(),
        };

        let max_backoff_ms = match dict.get_item("max_backoff_ms")? {
            Some(v) => v.extract::<u64>().map_err(|_| {
                PyErr::new::<pyo3::exceptions::PyValueError, _>(
                    "max_backoff_ms must be a non-negative integer",
                )
            })?,
            None => default_max_backoff_ms(),
        };

        let retry_on_status = match dict.get_item("retry_on_status")? {
            Some(v) => v.extract::<Vec<i32>>().map_err(|_| {
                PyErr::new::<pyo3::exceptions::PyValueError, _>(
                    "retry_on_status must be a list of integers",
                )
            })?,
            None => default_retry_on_status(),
        };

        let jitter = match dict.get_item("jitter")? {
            Some(v) => v.extract::<bool>().map_err(|_| {
                PyErr::new::<pyo3::exceptions::PyValueError, _>("jitter must be a boolean")
            })?,
            None => default_jitter(),
        };

        let check_text_content = match dict.get_item("check_text_content")? {
            Some(v) => v.extract::<bool>().map_err(|_| {
                PyErr::new::<pyo3::exceptions::PyValueError, _>(
                    "check_text_content must be a boolean",
                )
            })?,
            None => false,
        };

        let tool_overrides = match dict.get_item("tool_overrides")? {
            Some(v) => {
                let d = v.cast::<PyDict>().map_err(|_| {
                    PyErr::new::<pyo3::exceptions::PyValueError, _>(
                        "tool_overrides must be a dictionary",
                    )
                })?;
                parse_tool_overrides(d)?
            }
            None => HashMap::new(),
        };

        let config = Self {
            max_retries,
            backoff_base_ms,
            max_backoff_ms,
            retry_on_status,
            jitter,
            check_text_content,
            tool_overrides,
        };

        config.validate()?;
        Ok(config)
    }

    /// Validate configuration values
    pub fn validate(&self) -> PyResult<()> {
        if self.max_retries > 10 {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "max_retries cannot exceed 10",
            ));
        }
        if self.backoff_base_ms == 0 {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "backoff_base_ms must be > 0",
            ));
        }
        if self.max_backoff_ms < self.backoff_base_ms {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "max_backoff_ms must be >= backoff_base_ms",
            ));
        }
        Ok(())
    }

    /// Get configuration for a specific tool, applying overrides if present
    pub fn get_tool_config(&self, tool_name: &str) -> PyResult<Self> {
        let merged = if let Some(override_cfg) = self.tool_overrides.get(tool_name) {
            Self {
                max_retries: override_cfg.max_retries.unwrap_or(self.max_retries),
                backoff_base_ms: override_cfg.backoff_base_ms.unwrap_or(self.backoff_base_ms),
                max_backoff_ms: override_cfg.max_backoff_ms.unwrap_or(self.max_backoff_ms),
                retry_on_status: override_cfg
                    .retry_on_status
                    .clone()
                    .unwrap_or_else(|| self.retry_on_status.clone()),
                jitter: override_cfg.jitter.unwrap_or(self.jitter),
                check_text_content: override_cfg
                    .check_text_content
                    .unwrap_or(self.check_text_content),
                tool_overrides: HashMap::new(), // Don't nest overrides
            }
        } else {
            self.clone()
        };
        merged.validate()?;
        Ok(merged)
    }
}

fn parse_tool_overrides(dict: &Bound<'_, PyDict>) -> PyResult<HashMap<String, ToolOverride>> {
    let mut overrides = HashMap::new();

    for (key, value) in dict.iter() {
        let tool_name = key.extract::<String>()?;
        let override_dict = value.cast::<PyDict>()?;

        let tool_override = ToolOverride {
            max_retries: override_dict
                .get_item("max_retries")?
                .map(|v| v.extract::<u32>())
                .transpose()
                .map_err(|_| {
                    PyErr::new::<pyo3::exceptions::PyValueError, _>(
                        "tool override max_retries must be a non-negative integer",
                    )
                })?,
            backoff_base_ms: override_dict
                .get_item("backoff_base_ms")?
                .map(|v| v.extract::<u64>())
                .transpose()
                .map_err(|_| {
                    PyErr::new::<pyo3::exceptions::PyValueError, _>(
                        "tool override backoff_base_ms must be a non-negative integer",
                    )
                })?,
            max_backoff_ms: override_dict
                .get_item("max_backoff_ms")?
                .map(|v| v.extract::<u64>())
                .transpose()
                .map_err(|_| {
                    PyErr::new::<pyo3::exceptions::PyValueError, _>(
                        "tool override max_backoff_ms must be a non-negative integer",
                    )
                })?,
            retry_on_status: override_dict
                .get_item("retry_on_status")?
                .map(|v| v.extract::<Vec<i32>>())
                .transpose()
                .map_err(|_| {
                    PyErr::new::<pyo3::exceptions::PyValueError, _>(
                        "tool override retry_on_status must be a list of integers",
                    )
                })?,
            jitter: override_dict
                .get_item("jitter")?
                .map(|v| v.extract::<bool>())
                .transpose()
                .map_err(|_| {
                    PyErr::new::<pyo3::exceptions::PyValueError, _>(
                        "tool override jitter must be a boolean",
                    )
                })?,
            check_text_content: override_dict
                .get_item("check_text_content")?
                .map(|v| v.extract::<bool>())
                .transpose()
                .map_err(|_| {
                    PyErr::new::<pyo3::exceptions::PyValueError, _>(
                        "tool override check_text_content must be a boolean",
                    )
                })?,
        };

        overrides.insert(tool_name, tool_override);
    }

    Ok(overrides)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = RetryConfig {
            max_retries: default_max_retries(),
            backoff_base_ms: default_backoff_base_ms(),
            max_backoff_ms: default_max_backoff_ms(),
            retry_on_status: default_retry_on_status(),
            jitter: default_jitter(),
            check_text_content: false,
            tool_overrides: HashMap::new(),
        };

        assert_eq!(config.max_retries, 2);
        assert_eq!(config.backoff_base_ms, 200);
        assert_eq!(config.max_backoff_ms, 5000);
        assert_eq!(config.retry_on_status, vec![429, 500, 502, 503, 504]);
        assert!(config.jitter);
        assert!(!config.check_text_content);
    }

    #[test]
    fn test_config_validation_max_retries() {
        let config = RetryConfig {
            max_retries: 11,
            backoff_base_ms: 200,
            max_backoff_ms: 5000,
            retry_on_status: vec![500],
            jitter: true,
            check_text_content: false,
            tool_overrides: HashMap::new(),
        };

        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_validation_backoff_base_zero() {
        let config = RetryConfig {
            max_retries: 2,
            backoff_base_ms: 0,
            max_backoff_ms: 5000,
            retry_on_status: vec![500],
            jitter: true,
            check_text_content: false,
            tool_overrides: HashMap::new(),
        };

        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_validation_max_less_than_base() {
        let config = RetryConfig {
            max_retries: 2,
            backoff_base_ms: 5000,
            max_backoff_ms: 200,
            retry_on_status: vec![500],
            jitter: true,
            check_text_content: false,
            tool_overrides: HashMap::new(),
        };

        assert!(config.validate().is_err());
    }

    #[test]
    fn test_get_tool_config_no_override() {
        let config = RetryConfig {
            max_retries: 2,
            backoff_base_ms: 200,
            max_backoff_ms: 5000,
            retry_on_status: vec![500],
            jitter: true,
            check_text_content: false,
            tool_overrides: HashMap::new(),
        };

        let tool_config = config.get_tool_config("my_tool").unwrap();
        assert_eq!(tool_config.max_retries, 2);
        assert_eq!(tool_config.backoff_base_ms, 200);
    }

    #[test]
    fn test_get_tool_config_with_override() {
        let mut overrides = HashMap::new();
        overrides.insert(
            "my_tool".to_string(),
            ToolOverride {
                max_retries: Some(5),
                backoff_base_ms: Some(500),
                max_backoff_ms: None,
                retry_on_status: Some(vec![503]),
                jitter: Some(false),
                check_text_content: None,
            },
        );

        let config = RetryConfig {
            max_retries: 2,
            backoff_base_ms: 200,
            max_backoff_ms: 5000,
            retry_on_status: vec![500],
            jitter: true,
            check_text_content: false,
            tool_overrides: overrides,
        };

        let tool_config = config.get_tool_config("my_tool").unwrap();
        assert_eq!(tool_config.max_retries, 5);
        assert_eq!(tool_config.backoff_base_ms, 500);
        assert_eq!(tool_config.max_backoff_ms, 5000); // Uses base config
        assert_eq!(tool_config.retry_on_status, vec![503]);
        assert!(!tool_config.jitter);
    }

    #[test]
    fn test_config_validation_max_retries_at_limit_is_valid() {
        // max_retries = 10 is valid; > 10 is invalid.
        // Kills mutant: `replace > with >=` on the max_retries validation check.
        let config = RetryConfig {
            max_retries: 10,
            backoff_base_ms: 200,
            max_backoff_ms: 5000,
            retry_on_status: vec![500],
            jitter: true,
            check_text_content: false,
            tool_overrides: HashMap::new(),
        };
        assert!(config.validate().is_ok(), "max_retries = 10 must be valid");
    }

    #[test]
    fn test_config_validation_max_backoff_equals_base_is_valid() {
        // max_backoff_ms == backoff_base_ms is valid; max_backoff_ms < backoff_base_ms is invalid.
        // Kills mutant: `replace < with <=` on the max_backoff_ms validation check.
        let config = RetryConfig {
            max_retries: 2,
            backoff_base_ms: 200,
            max_backoff_ms: 200,
            retry_on_status: vec![500],
            jitter: true,
            check_text_content: false,
            tool_overrides: HashMap::new(),
        };
        assert!(
            config.validate().is_ok(),
            "max_backoff_ms == backoff_base_ms must be valid"
        );
    }
}
