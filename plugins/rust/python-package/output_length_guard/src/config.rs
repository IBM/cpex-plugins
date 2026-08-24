// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
//
// Configuration types for Output Length Guard

use pyo3::prelude::*;
use pyo3::types::{PyAny, PyDict};
use thiserror::Error;

// Security limit constants (match Python config.py validators)
pub const MIN_MAX_TEXT_LENGTH: usize = 1_000;
pub const MAX_MAX_TEXT_LENGTH: usize = 10_000_000;
pub const DEFAULT_MAX_TEXT_LENGTH: usize = 1_000_000;

pub const MIN_MAX_STRUCTURE_SIZE: usize = 1;
pub const MAX_MAX_STRUCTURE_SIZE: usize = 100_000;
pub const DEFAULT_MAX_STRUCTURE_SIZE: usize = 10_000;

pub const MIN_MAX_RECURSION_DEPTH: usize = 10;
pub const MAX_MAX_RECURSION_DEPTH: usize = 1_000;
pub const DEFAULT_MAX_RECURSION_DEPTH: usize = 100;

pub const DEFAULT_CHARS_PER_TOKEN: usize = 4;
pub const MIN_CHARS_PER_TOKEN: usize = 1;
pub const MAX_CHARS_PER_TOKEN: usize = 10;

pub const DEFAULT_ELLIPSIS: &str = "\u{2026}"; // …
pub const DEFAULT_MAX_CHARS: Option<usize> = Some(15_000);

/// Strategy for out-of-bounds output
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strategy {
    Truncate,
    Block,
}

impl Strategy {
    pub fn as_str(&self) -> &'static str {
        match self {
            Strategy::Truncate => "truncate",
            Strategy::Block => "block",
        }
    }
}

/// Limit enforcement mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitMode {
    Character,
    Token,
}

impl LimitMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            LimitMode::Character => "character",
            LimitMode::Token => "token",
        }
    }
}

/// Configuration for Output Length Guard
#[derive(Debug, Clone)]
pub struct OutputLengthGuardConfig {
    // Output limits
    pub min_chars: usize,
    pub max_chars: Option<usize>,
    pub min_tokens: usize,
    pub max_tokens: Option<usize>,
    pub chars_per_token: usize,

    // Behavior
    pub limit_mode: LimitMode,
    pub strategy: Strategy,
    pub ellipsis: String,
    pub word_boundary: bool,

    // Security limits
    pub max_text_length: usize,
    pub max_structure_size: usize,
    pub max_recursion_depth: usize,
}

impl Default for OutputLengthGuardConfig {
    fn default() -> Self {
        Self {
            min_chars: 0,
            max_chars: DEFAULT_MAX_CHARS,
            min_tokens: 0,
            max_tokens: None,
            chars_per_token: DEFAULT_CHARS_PER_TOKEN,
            limit_mode: LimitMode::Character,
            strategy: Strategy::Truncate,
            ellipsis: DEFAULT_ELLIPSIS.to_string(),
            word_boundary: false,
            max_text_length: DEFAULT_MAX_TEXT_LENGTH,
            max_structure_size: DEFAULT_MAX_STRUCTURE_SIZE,
            max_recursion_depth: DEFAULT_MAX_RECURSION_DEPTH,
        }
    }
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("{0}")]
    InvalidValue(String),
}

impl From<ConfigError> for PyErr {
    fn from(e: ConfigError) -> Self {
        pyo3::exceptions::PyValueError::new_err(e.to_string())
    }
}

impl OutputLengthGuardConfig {
    fn parse_strategy(s: &str) -> Result<Strategy, ConfigError> {
        match s.to_lowercase().trim() {
            "truncate" => Ok(Strategy::Truncate),
            "block" => Ok(Strategy::Block),
            other => Err(ConfigError::InvalidValue(format!(
                "Invalid strategy '{}'. Must be one of: block, truncate",
                other
            ))),
        }
    }

    fn parse_limit_mode(s: &str) -> Result<LimitMode, ConfigError> {
        match s.to_lowercase().trim() {
            "character" => Ok(LimitMode::Character),
            "token" => Ok(LimitMode::Token),
            other => Err(ConfigError::InvalidValue(format!(
                "Invalid limit_mode '{}'. Must be one of: character, token",
                other
            ))),
        }
    }

    fn parse_optional_usize(
        dict: &Bound<'_, PyDict>,
        key: &str,
    ) -> PyResult<Option<Option<usize>>> {
        let Some(val) = dict.get_item(key)? else {
            return Ok(None); // key not present
        };
        if val.is_none() {
            return Ok(Some(None)); // key present, value is None/null
        }
        let n: i64 = val.extract()?;
        if n < 0 {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "{} must be >= 0 (0 disables), or None to disable",
                key
            )));
        }
        if n == 0 {
            Ok(Some(None)) // treat 0 as None (disabled)
        } else {
            Ok(Some(Some(n as usize)))
        }
    }

    /// Extract configuration from Python object (dict or Pydantic model)
    pub fn from_py_object(obj: &Bound<'_, PyAny>) -> PyResult<Self> {
        let dict = if obj.is_instance_of::<PyDict>() {
            obj.cast::<PyDict>()?.clone()
        } else {
            let model_dump = obj.getattr("model_dump")?;
            let dict_obj = model_dump.call0()?;
            dict_obj.cast::<PyDict>()?.clone()
        };
        Self::from_py_dict(&dict)
    }

    /// Extract configuration from Python dict
    pub fn from_py_dict(dict: &Bound<'_, PyDict>) -> PyResult<Self> {
        let mut cfg = Self::default();

        if let Some(val) = dict.get_item("min_chars")? {
            let n: i64 = val.extract()?;
            if n < 0 {
                return Err(pyo3::exceptions::PyValueError::new_err(
                    "min_chars must be >= 0",
                ));
            }
            cfg.min_chars = n as usize;
        }

        if let Some(resolved) = Self::parse_optional_usize(dict, "max_chars")? {
            cfg.max_chars = resolved;
        }

        if let Some(val) = dict.get_item("min_tokens")? {
            let n: i64 = val.extract()?;
            if n < 0 {
                return Err(pyo3::exceptions::PyValueError::new_err(
                    "min_tokens must be >= 0",
                ));
            }
            cfg.min_tokens = n as usize;
        }

        if let Some(resolved) = Self::parse_optional_usize(dict, "max_tokens")? {
            cfg.max_tokens = resolved;
        }

        if let Some(val) = dict.get_item("chars_per_token")? {
            let n: usize = val.extract()?;
            if !(MIN_CHARS_PER_TOKEN..=MAX_CHARS_PER_TOKEN).contains(&n) {
                return Err(pyo3::exceptions::PyValueError::new_err(
                    "chars_per_token must be between 1 and 10",
                ));
            }
            cfg.chars_per_token = n;
        }

        if let Some(val) = dict.get_item("limit_mode")? {
            let s: String = val.extract()?;
            cfg.limit_mode = Self::parse_limit_mode(&s).map_err(PyErr::from)?;
        }

        if let Some(val) = dict.get_item("strategy")? {
            let s: String = val.extract()?;
            cfg.strategy = Self::parse_strategy(&s).map_err(PyErr::from)?;
        }

        if let Some(val) = dict.get_item("ellipsis")? {
            cfg.ellipsis = val.extract()?;
        }

        if let Some(val) = dict.get_item("word_boundary")? {
            cfg.word_boundary = val.extract()?;
        }

        if let Some(val) = dict.get_item("max_text_length")? {
            let n: usize = val.extract()?;
            if !(MIN_MAX_TEXT_LENGTH..=MAX_MAX_TEXT_LENGTH).contains(&n) {
                return Err(pyo3::exceptions::PyValueError::new_err(format!(
                    "max_text_length must be between {} (1KB) and {} (10MB)",
                    MIN_MAX_TEXT_LENGTH, MAX_MAX_TEXT_LENGTH
                )));
            }
            cfg.max_text_length = n;
        }

        if let Some(val) = dict.get_item("max_structure_size")? {
            let n: usize = val.extract()?;
            if !(MIN_MAX_STRUCTURE_SIZE..=MAX_MAX_STRUCTURE_SIZE).contains(&n) {
                return Err(pyo3::exceptions::PyValueError::new_err(format!(
                    "max_structure_size must be between {} and {}",
                    MIN_MAX_STRUCTURE_SIZE, MAX_MAX_STRUCTURE_SIZE
                )));
            }
            cfg.max_structure_size = n;
        }

        if let Some(val) = dict.get_item("max_recursion_depth")? {
            let n: usize = val.extract()?;
            if !(MIN_MAX_RECURSION_DEPTH..=MAX_MAX_RECURSION_DEPTH).contains(&n) {
                return Err(pyo3::exceptions::PyValueError::new_err(format!(
                    "max_recursion_depth must be between {} and {}",
                    MIN_MAX_RECURSION_DEPTH, MAX_MAX_RECURSION_DEPTH
                )));
            }
            cfg.max_recursion_depth = n;
        }

        // Validate min/max relationships
        if let Some(max) = cfg.max_chars
            && cfg.min_chars > max
        {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "min_chars ({}) cannot be greater than max_chars ({})",
                cfg.min_chars, max
            )));
        }
        if let Some(max) = cfg.max_tokens
            && cfg.min_tokens > max
        {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "min_tokens ({}) cannot be greater than max_tokens ({})",
                cfg.min_tokens, max
            )));
        }

        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pyo3::types::PyDict;

    #[test]
    fn default_config_has_expected_values() {
        let cfg = OutputLengthGuardConfig::default();
        assert_eq!(cfg.min_chars, 0);
        assert_eq!(cfg.max_chars, Some(15_000));
        assert_eq!(cfg.chars_per_token, 4);
        assert!(matches!(cfg.limit_mode, LimitMode::Character));
        assert!(matches!(cfg.strategy, Strategy::Truncate));
        assert!(!cfg.word_boundary);
        assert_eq!(cfg.max_text_length, DEFAULT_MAX_TEXT_LENGTH);
        assert_eq!(cfg.max_structure_size, DEFAULT_MAX_STRUCTURE_SIZE);
        assert_eq!(cfg.max_recursion_depth, DEFAULT_MAX_RECURSION_DEPTH);
    }

    #[test]
    fn parse_strategy_accepts_valid_values() {
        assert!(matches!(
            OutputLengthGuardConfig::parse_strategy("truncate"),
            Ok(Strategy::Truncate)
        ));
        assert!(matches!(
            OutputLengthGuardConfig::parse_strategy("block"),
            Ok(Strategy::Block)
        ));
        assert!(matches!(
            OutputLengthGuardConfig::parse_strategy("TRUNCATE"),
            Ok(Strategy::Truncate)
        ));
    }

    #[test]
    fn parse_strategy_rejects_invalid() {
        assert!(OutputLengthGuardConfig::parse_strategy("skip").is_err());
    }

    #[test]
    fn parse_limit_mode_accepts_valid_values() {
        assert!(matches!(
            OutputLengthGuardConfig::parse_limit_mode("character"),
            Ok(LimitMode::Character)
        ));
        assert!(matches!(
            OutputLengthGuardConfig::parse_limit_mode("token"),
            Ok(LimitMode::Token)
        ));
    }

    #[test]
    fn parse_limit_mode_rejects_invalid() {
        assert!(OutputLengthGuardConfig::parse_limit_mode("bytes").is_err());
    }

    #[test]
    fn from_py_dict_parses_basic_config() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            let d = PyDict::new(py);
            d.set_item("max_chars", 500).unwrap();
            d.set_item("strategy", "block").unwrap();
            d.set_item("limit_mode", "character").unwrap();
            let cfg = OutputLengthGuardConfig::from_py_dict(&d).unwrap();
            assert_eq!(cfg.max_chars, Some(500));
            assert!(matches!(cfg.strategy, Strategy::Block));
        });
    }

    #[test]
    fn from_py_dict_treats_zero_max_chars_as_none() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            let d = PyDict::new(py);
            d.set_item("max_chars", 0).unwrap();
            let cfg = OutputLengthGuardConfig::from_py_dict(&d).unwrap();
            assert_eq!(cfg.max_chars, None);
        });
    }

    #[test]
    fn from_py_dict_treats_null_max_chars_as_none() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            let d = PyDict::new(py);
            d.set_item("max_chars", py.None()).unwrap();
            let cfg = OutputLengthGuardConfig::from_py_dict(&d).unwrap();
            assert_eq!(cfg.max_chars, None);
        });
    }

    #[test]
    fn from_py_dict_rejects_invalid_strategy() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            let d = PyDict::new(py);
            d.set_item("strategy", "skip").unwrap();
            assert!(OutputLengthGuardConfig::from_py_dict(&d).is_err());
        });
    }

    #[test]
    fn from_py_dict_rejects_invalid_limit_mode() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            let d = PyDict::new(py);
            d.set_item("limit_mode", "bytes").unwrap();
            assert!(OutputLengthGuardConfig::from_py_dict(&d).is_err());
        });
    }

    #[test]
    fn from_py_dict_rejects_min_greater_than_max_chars() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            let d = PyDict::new(py);
            d.set_item("min_chars", 1000).unwrap();
            d.set_item("max_chars", 500).unwrap();
            let err = OutputLengthGuardConfig::from_py_dict(&d).unwrap_err();
            assert!(err.to_string().contains("min_chars"));
        });
    }

    #[test]
    fn from_py_dict_rejects_invalid_max_text_length() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            let d = PyDict::new(py);
            d.set_item("max_text_length", 100).unwrap(); // below 1000 min
            assert!(OutputLengthGuardConfig::from_py_dict(&d).is_err());
        });
    }

    #[test]
    fn from_py_dict_rejects_invalid_max_structure_size() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            let d = PyDict::new(py);
            d.set_item("max_structure_size", 0).unwrap(); // below 1 min (0 is not valid)
            assert!(OutputLengthGuardConfig::from_py_dict(&d).is_err());
        });
    }

    #[test]
    fn from_py_dict_rejects_invalid_max_recursion_depth() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            let d = PyDict::new(py);
            d.set_item("max_recursion_depth", 5).unwrap(); // below 10 min
            assert!(OutputLengthGuardConfig::from_py_dict(&d).is_err());
        });
    }

    #[test]
    fn from_py_dict_rejects_invalid_chars_per_token() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            let d = PyDict::new(py);
            d.set_item("chars_per_token", 11).unwrap(); // above 10 max
            assert!(OutputLengthGuardConfig::from_py_dict(&d).is_err());
        });
    }

    #[test]
    fn strategy_as_str_returns_expected() {
        assert_eq!(Strategy::Truncate.as_str(), "truncate");
        assert_eq!(Strategy::Block.as_str(), "block");
    }

    #[test]
    fn limit_mode_as_str_returns_expected() {
        assert_eq!(LimitMode::Character.as_str(), "character");
        assert_eq!(LimitMode::Token.as_str(), "token");
    }
}
