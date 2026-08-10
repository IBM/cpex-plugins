// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
//
// Configuration for output length guard plugin

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyDict;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitMode {
    Character,
    Token,
}

impl LimitMode {
    pub fn parse(value: &str) -> Result<Self, ConfigError> {
        let normalized = value.trim().to_lowercase();
        match normalized.as_str() {
            "character" => Ok(Self::Character),
            "token" => Ok(Self::Token),
            _ => Err(ConfigError(format!(
                "Invalid limit_mode '{}'. Must be one of: character, token",
                normalized
            ))),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Character => "character",
            Self::Token => "token",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strategy {
    Truncate,
    Block,
}

impl Strategy {
    pub fn parse(value: &str) -> Result<Self, ConfigError> {
        let normalized = value.trim().to_lowercase();
        match normalized.as_str() {
            "truncate" => Ok(Self::Truncate),
            "block" => Ok(Self::Block),
            _ => Err(ConfigError(format!(
                "Invalid strategy '{}'. Must be one of: block, truncate",
                normalized
            ))),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Truncate => "truncate",
            Self::Block => "block",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError(pub String);

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl std::error::Error for ConfigError {}

impl From<ConfigError> for PyErr {
    fn from(err: ConfigError) -> Self {
        PyValueError::new_err(err.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputLengthGuardConfig {
    pub min_chars: u32,
    pub max_chars: Option<u32>,
    pub min_tokens: u32,
    pub max_tokens: Option<u32>,
    pub chars_per_token: u8,
    pub limit_mode: LimitMode,
    pub strategy: Strategy,
    pub ellipsis: String,
    pub word_boundary: bool,
    pub max_text_length: u32,
    pub max_structure_size: u32,
    pub max_recursion_depth: u32,
}

impl Default for OutputLengthGuardConfig {
    fn default() -> Self {
        Self {
            min_chars: 0,
            max_chars: None,
            min_tokens: 0,
            max_tokens: None,
            chars_per_token: 4,
            limit_mode: LimitMode::Character,
            strategy: Strategy::Truncate,
            ellipsis: "…".to_string(),
            word_boundary: false,
            max_text_length: 1_000_000,
            max_structure_size: 10_000,
            max_recursion_depth: 100,
        }
    }
}

impl OutputLengthGuardConfig {
    pub fn from_pydict(dict: &Bound<'_, PyDict>) -> PyResult<Self> {
        let mut config = Self::default();

        if let Some(value) = get_optional_i32(dict, "min_chars")? {
            config.min_chars = validate_min("min_chars", value)?;
        }

        if let Some(value) = get_optional_i32(dict, "max_chars")? {
            config.max_chars = validate_max("max_chars", value)?;
        }

        if let Some(value) = get_optional_i32(dict, "min_tokens")? {
            config.min_tokens = validate_min("min_tokens", value)?;
        }

        if let Some(value) = get_optional_i32(dict, "max_tokens")? {
            config.max_tokens = validate_max("max_tokens", value)?;
        }

        if let Some(value) = get_optional_i32(dict, "chars_per_token")? {
            if value < 1 || value > 10 {
                return Err(
                    ConfigError("chars_per_token must be between 1 and 10".to_string()).into(),
                );
            }
            config.chars_per_token = value as u8;
        }

        if let Some(value) = get_optional_string(dict, "limit_mode")? {
            config.limit_mode = LimitMode::parse(&value)?;
        }

        if let Some(value) = get_optional_string(dict, "strategy")? {
            config.strategy = Strategy::parse(&value)?;
        }

        if let Some(value) = get_optional_string(dict, "ellipsis")? {
            config.ellipsis = value;
        }

        if let Some(value) = get_optional_bool(dict, "word_boundary")? {
            config.word_boundary = value;
        }

        if let Some(value) = get_optional_i32(dict, "max_text_length")? {
            if !(1000..=10_000_000).contains(&value) {
                return Err(ConfigError(
                    "max_text_length must be between 1000 (1KB) and 10000000 (10MB)".to_string(),
                )
                .into());
            }
            config.max_text_length = value as u32;
        }

        if let Some(value) = get_optional_i32(dict, "max_structure_size")? {
            if !(10..=100_000).contains(&value) {
                return Err(ConfigError(
                    "max_structure_size must be between 10 and 100000".to_string(),
                )
                .into());
            }
            config.max_structure_size = value as u32;
        }

        if let Some(value) = get_optional_i32(dict, "max_recursion_depth")? {
            if !(10..=1000).contains(&value) {
                return Err(ConfigError(
                    "max_recursion_depth must be between 10 and 1000".to_string(),
                )
                .into());
            }
            config.max_recursion_depth = value as u32;
        }

        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if let Some(max_chars) = self.max_chars {
            if self.min_chars > max_chars {
                return Err(ConfigError(format!(
                    "min_chars ({}) cannot be greater than max_chars ({})",
                    self.min_chars, max_chars
                )));
            }
        }

        if let Some(max_tokens) = self.max_tokens {
            if self.min_tokens > max_tokens {
                return Err(ConfigError(format!(
                    "min_tokens ({}) cannot be greater than max_tokens ({})",
                    self.min_tokens, max_tokens
                )));
            }
        }

        Ok(())
    }

    pub fn is_blocking(&self) -> bool {
        self.strategy == Strategy::Block
    }
}

fn get_optional_string(dict: &Bound<'_, PyDict>, key: &str) -> PyResult<Option<String>> {
    if let Some(value) = dict.get_item(key)?
        && !value.is_none()
    {
        return Ok(Some(value.extract::<String>()?));
    }
    return Ok(None);
}

fn get_optional_bool(dict: &Bound<'_, PyDict>, key: &str) -> PyResult<Option<bool>> {
    match dict.get_item(key)? {
        Some(value) if value.is_none() => Ok(None),
        Some(value) => Ok(Some(value.extract::<bool>()?)),
        None => Ok(None),
    }
}

fn get_optional_i32(dict: &Bound<'_, PyDict>, key: &str) -> PyResult<Option<i32>> {
    if let Some(value) = dict.get_item(key)?
        && !value.is_none()
    {
        return Ok(Some(value.extract::<i32>()?));
    }
    return Ok(None);
}

fn validate_min(field_name: &str, value: i32) -> Result<u32, ConfigError> {
    if value < 0 {
        return Err(ConfigError(format!(
            "{} must be >= 0 (0 disables)",
            field_name
        )));
    }
    Ok(value as u32)
}
fn validate_max(field_name: &str, value: i32) -> Result<Option<u32>, ConfigError> {
    if value < 0 {
        return Err(ConfigError(format!(
            "{} must be >= 0 (0 disables), or None to disable",
            field_name
        )));
    }

    if value == 0 {
        Ok(None)
    } else {
        Ok(Some(value as u32))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pyo3::types::PyDict;

    fn parse_dict(dict: &Bound<'_, PyDict>) -> PyResult<OutputLengthGuardConfig> {
        OutputLengthGuardConfig::from_pydict(&dict)
    }

    #[test]
    fn default_config_matches_python_defaults() {
        let config = OutputLengthGuardConfig::default();

        assert_eq!(config.min_chars, 0);
        assert_eq!(config.max_chars, None);
        assert_eq!(config.min_tokens, 0);
        assert_eq!(config.max_tokens, None);
        assert_eq!(config.chars_per_token, 4);
        assert_eq!(config.limit_mode, LimitMode::Character);
        assert_eq!(config.strategy, Strategy::Truncate);
        assert_eq!(config.ellipsis, "…");
        assert!(!config.word_boundary);
        assert_eq!(config.max_text_length, 1_000_000);
        assert_eq!(config.max_structure_size, 10_000);
        assert_eq!(config.max_recursion_depth, 100);
    }

    #[test]
    fn limit_mode_is_trimmed_and_lowercased() {
        Python::initialize();
        Python::attach(|py| {
            let dict = PyDict::new(py);
            let _ = dict.set_item("limit_mode", "  ToKeN  ");

            let config = parse_dict(&dict).unwrap();
            assert_eq!(config.limit_mode, LimitMode::Token);
        });
    }

    #[test]
    fn strategy_is_trimmed_and_lowercased() {
        Python::initialize();
        Python::attach(|py| {
            let dict = PyDict::new(py);
            let _ = dict.set_item("strategy", "  BLOCK  ");

            let config = parse_dict(&dict).unwrap();
            assert_eq!(config.strategy, Strategy::Block);
        });
    }

    #[test]
    fn rejects_invalid_limit_mode() {
        Python::initialize();
        Python::attach(|py| {
            let dict = PyDict::new(py);
            let _ = dict.set_item("limit_mode", "  sentence  ");

            let err = parse_dict(&dict).unwrap_err().to_string();
            assert!(
                err.contains("Invalid limit_mode 'sentence'. Must be one of: character, token")
            );
        });
    }

    #[test]
    fn rejects_invalid_strategy() {
        Python::initialize();
        Python::attach(|py| {
            let dict = PyDict::new(py);
            let _ = dict.set_item("strategy", "  deny  ");

            let err = parse_dict(&dict).unwrap_err().to_string();
            assert!(err.contains("Invalid strategy 'deny'. Must be one of: block, truncate"));
        });
    }

    #[test]
    fn converts_zero_max_chars_to_none() {
        Python::initialize();
        Python::attach(|py| {
            let dict = PyDict::new(py);
            let _ = dict.set_item("max_chars", 0i32);

            let config = parse_dict(&dict).unwrap();
            assert_eq!(config.max_chars, None);
        });
    }

    #[test]
    fn converts_zero_max_tokens_to_none() {
        Python::initialize();
        Python::attach(|py| {
            let dict = PyDict::new(py);
            let _ = dict.set_item("max_tokens", -0i32);

            let config = parse_dict(&dict).unwrap();
            assert_eq!(config.max_tokens, None);
        });
    }

    #[test]
    fn rejects_negative_max_chars() {
        Python::initialize();
        Python::attach(|py| {
            let dict = PyDict::new(py);
            let _ = dict.set_item("max_chars", -10i32);

            let err = parse_dict(&dict).unwrap_err().to_string();
            assert!(err.contains("max_chars must be >= 0 (0 disables), or None to disable"));
        });
    }

    #[test]
    fn rejects_negative_max_tokens() {
        Python::initialize();
        Python::attach(|py| {
            let dict = PyDict::new(py);
            let _ = dict.set_item("max_tokens", -10i32);

            let err = parse_dict(&dict).unwrap_err().to_string();
            assert!(err.contains("max_tokens must be >= 0 (0 disables), or None to disable"));
        });
    }

    #[test]
    fn accepts_nonzero_max_limits() {
        Python::initialize();
        Python::attach(|py| {
            let dict = PyDict::new(py);
            let _ = dict.set_item("max_chars", 200i32);
            let _ = dict.set_item("max_tokens", 50i32);

            let config = parse_dict(&dict).unwrap();
            assert_eq!(config.max_chars, Some(200));
            assert_eq!(config.max_tokens, Some(50));
        });
    }

    #[test]
    fn rejects_chars_per_token_out_of_range() {
        Python::initialize();
        Python::attach(|py| {
            let low = PyDict::new(py);
            let _ = low.set_item("chars_per_token", 0i32);
            let high = PyDict::new(py);
            let _ = high.set_item("chars_per_token", 20i32);

            let err_low = parse_dict(&low).unwrap_err().to_string();
            assert!(err_low.contains("chars_per_token must be between 1 and 10"));

            let err_high = parse_dict(&high).unwrap_err().to_string();
            assert!(err_high.contains("chars_per_token must be between 1 and 10"));
        });
    }

    #[test]
    fn accepts_chars_per_token() {
        Python::attach(|py| {
            let dict = PyDict::new(py);
            let _ = dict.set_item("chars_per_token", 5i32);

            let config = parse_dict(&dict).unwrap();
            assert_eq!(config.chars_per_token, 5);
        });
    }

    #[test]
    fn rejects_max_text_length_out_of_range() {
        Python::initialize();
        Python::attach(|py| {
            let low = PyDict::new(py);
            let _ = low.set_item("max_text_length", 999i32);
            let high = PyDict::new(py);
            let _ = high.set_item("max_text_length", 10_000_100i32);

            let err_low = parse_dict(&low).unwrap_err().to_string();
            assert!(
                err_low.contains("max_text_length must be between 1000 (1KB) and 10000000 (10MB)")
            );

            let err_high = parse_dict(&high).unwrap_err().to_string();
            assert!(
                err_high.contains("max_text_length must be between 1000 (1KB) and 10000000 (10MB)")
            );
        });
    }

    #[test]
    fn rejects_max_structure_size_out_of_range() {
        Python::initialize();
        Python::attach(|py| {
            let low = PyDict::new(py);
            let _ = low.set_item("max_structure_size", 9i32);
            let high = PyDict::new(py);
            let _ = high.set_item("max_structure_size", 100_011i32);

            let err_low = parse_dict(&low).unwrap_err().to_string();
            assert!(err_low.contains("max_structure_size must be between 10 and 100000"));

            let err_high = parse_dict(&high).unwrap_err().to_string();
            assert!(err_high.contains("max_structure_size must be between 10 and 100000"));
        });
    }

    #[test]
    fn rejects_max_recursion_depth_out_of_range() {
        Python::initialize();
        Python::attach(|py| {
            let low = PyDict::new(py);
            let _ = low.set_item("max_recursion_depth", 9i32);
            let high = PyDict::new(py);
            let _ = high.set_item("max_recursion_depth", 1011i32);

            let err_low = parse_dict(&low).unwrap_err().to_string();
            assert!(err_low.contains("max_recursion_depth must be between 10 and 1000"));

            let err_high = parse_dict(&high).unwrap_err().to_string();
            assert!(err_high.contains("max_recursion_depth must be between 10 and 1000"));
        });
    }

    #[test]
    fn rejects_min_chars_greater_than_max_chars() {
        Python::initialize();
        Python::attach(|py| {
            let dict = PyDict::new(py);
            let _ = dict.set_item("min_chars", 110i32);
            let _ = dict.set_item("max_chars", 100i32);

            let err = parse_dict(&dict).unwrap_err().to_string();
            assert!(err.contains("min_chars (110) cannot be greater than max_chars (100)"));
        });
    }

    #[test]
    fn rejects_min_tokens_greater_than_max_tokens() {
        Python::initialize();
        Python::attach(|py| {
            let dict = PyDict::new(py);
            let _ = dict.set_item("min_tokens", 110i32);
            let _ = dict.set_item("max_tokens", 100i32);

            let err = parse_dict(&dict).unwrap_err().to_string();
            assert!(err.contains("min_tokens (110) cannot be greater than max_tokens (100)"));
        });
    }

    #[test]
    fn is_blocking_matches_python_behavior() {
        let blocking = OutputLengthGuardConfig {
            strategy: Strategy::Block,
            ..Default::default()
        };
        let truncating = OutputLengthGuardConfig {
            strategy: Strategy::Truncate,
            ..Default::default()
        };

        assert!(blocking.is_blocking());
        assert!(!truncating.is_blocking());
    }
}
