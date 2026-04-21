// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
//
// Configuration types for PII Filter

use pyo3::prelude::*;
use pyo3::types::{PyAny, PyDict};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const MAX_TEXT_BYTES_LIMIT: usize = 100 * 1024 * 1024;
const MAX_NESTED_DEPTH_LIMIT: usize = 1000;
const MAX_COLLECTION_ITEMS_LIMIT: usize = 1_000_000;
const DEFAULT_MAX_TEXT_BYTES: usize = 10 * 1024 * 1024;
const DEFAULT_MAX_NESTED_DEPTH: usize = 32;
const DEFAULT_MAX_COLLECTION_ITEMS: usize = 4096;

/// PII types that can be detected
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PIIType {
    Ssn,
    Bsn,
    CreditCard,
    Email,
    Phone,
    IpAddress,
    DateOfBirth,
    Passport,
    DriverLicense,
    BankAccount,
    MedicalRecord,
    Custom,
}

impl PIIType {
    /// Convert PIIType to string for Python
    pub fn as_str(&self) -> &'static str {
        match self {
            PIIType::Ssn => "ssn",
            PIIType::Bsn => "bsn",
            PIIType::CreditCard => "credit_card",
            PIIType::Email => "email",
            PIIType::Phone => "phone",
            PIIType::IpAddress => "ip_address",
            PIIType::DateOfBirth => "date_of_birth",
            PIIType::Passport => "passport",
            PIIType::DriverLicense => "driver_license",
            PIIType::BankAccount => "bank_account",
            PIIType::MedicalRecord => "medical_record",
            PIIType::Custom => "custom",
        }
    }
}

/// Masking strategies for detected PII
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum MaskingStrategy {
    #[default]
    Redact, // Replace with [REDACTED]
    Partial,  // Show first/last chars (e.g., ***-**-1234)
    Hash,     // Replace with hash (e.g., [HASH:abc123])
    Tokenize, // Replace with token (e.g., [TOKEN:xyz789])
    Remove,   // Remove entirely
}

/// Custom pattern definition from Python
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomPattern {
    pub pattern: String,
    pub description: String,
    pub mask_strategy: Option<MaskingStrategy>,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_enabled() -> bool {
    true
}

/// Configuration for PII Filter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PIIConfig {
    // Detection flags
    pub detect_ssn: bool,
    pub detect_bsn: bool,
    pub detect_credit_card: bool,
    pub detect_email: bool,
    pub detect_phone: bool,
    pub detect_ip_address: bool,
    pub detect_date_of_birth: bool,
    pub detect_passport: bool,
    pub detect_driver_license: bool,
    pub detect_bank_account: bool,
    pub detect_medical_record: bool,

    // Masking configuration
    pub default_mask_strategy: MaskingStrategy,
    pub redaction_text: String,
    #[serde(skip)]
    pub hash_salt: String,

    // Behavior configuration
    pub block_on_detection: bool,
    pub log_detections: bool,
    pub include_detection_details: bool,

    // Resource limits
    pub max_text_bytes: usize,
    pub max_nested_depth: usize,
    pub max_collection_items: usize,

    // Custom patterns
    #[serde(default)]
    pub custom_patterns: Vec<CustomPattern>,

    // Whitelist patterns (regex strings)
    pub whitelist_patterns: Vec<String>,
}

impl Default for PIIConfig {
    fn default() -> Self {
        Self {
            // Enable all detections by default
            detect_ssn: true,
            detect_bsn: true,
            detect_credit_card: true,
            detect_email: true,
            detect_phone: true,
            detect_ip_address: true,
            detect_date_of_birth: true,
            detect_passport: true,
            detect_driver_license: true,
            detect_bank_account: true,
            detect_medical_record: true,

            // Default masking
            default_mask_strategy: MaskingStrategy::Redact,
            redaction_text: "[REDACTED]".to_string(),
            hash_salt: Uuid::new_v4().to_string(),

            // Default behavior
            block_on_detection: false,
            log_detections: false,
            include_detection_details: false,

            // Default resource limits
            max_text_bytes: DEFAULT_MAX_TEXT_BYTES,
            max_nested_depth: DEFAULT_MAX_NESTED_DEPTH,
            max_collection_items: DEFAULT_MAX_COLLECTION_ITEMS,

            // Custom patterns
            custom_patterns: Vec::new(),

            whitelist_patterns: Vec::new(),
        }
    }
}

impl PIIConfig {
    fn parse_mask_strategy(strategy_str: &str, field_name: &str) -> PyResult<MaskingStrategy> {
        match strategy_str {
            "redact" => Ok(MaskingStrategy::Redact),
            "partial" => Ok(MaskingStrategy::Partial),
            "hash" => Ok(MaskingStrategy::Hash),
            "tokenize" => Ok(MaskingStrategy::Tokenize),
            "remove" => Ok(MaskingStrategy::Remove),
            _ => Err(pyo3::exceptions::PyValueError::new_err(format!(
                "Invalid '{}' value '{}'. Expected one of: redact, partial, hash, tokenize, remove",
                field_name, strategy_str
            ))),
        }
    }

    /// Extract configuration from Python object (dict or Pydantic model)
    pub fn from_py_object(obj: &Bound<'_, PyAny>) -> PyResult<Self> {
        // Try to convert to dict first (handles both dict and Pydantic models)
        let dict = if obj.is_instance_of::<PyDict>() {
            obj.cast::<PyDict>()?.clone()
        } else {
            // For Pydantic models, call model_dump() to get a dict
            let model_dump = obj.getattr("model_dump")?;
            let dict_obj = model_dump.call0()?;
            dict_obj.cast::<PyDict>()?.clone()
        };

        Self::from_py_dict(&dict)
    }

    /// Extract configuration from Python dict
    pub fn from_py_dict(dict: &Bound<'_, PyDict>) -> PyResult<Self> {
        let mut config = Self::default();

        // Helper macro to extract boolean values
        macro_rules! extract_bool {
            ($field:ident) => {
                if let Some(value) = dict.get_item(stringify!($field))? {
                    config.$field = value.extract()?;
                }
            };
        }

        // Extract all boolean flags
        extract_bool!(detect_ssn);
        extract_bool!(detect_bsn);
        extract_bool!(detect_credit_card);
        extract_bool!(detect_email);
        extract_bool!(detect_phone);
        extract_bool!(detect_ip_address);
        extract_bool!(detect_date_of_birth);
        extract_bool!(detect_passport);
        extract_bool!(detect_driver_license);
        extract_bool!(detect_bank_account);
        extract_bool!(detect_medical_record);
        extract_bool!(block_on_detection);
        extract_bool!(log_detections);
        extract_bool!(include_detection_details);

        if let Some(value) = dict.get_item("max_text_bytes")? {
            config.max_text_bytes = value.extract()?;
        }
        if let Some(value) = dict.get_item("max_nested_depth")? {
            config.max_nested_depth = value.extract()?;
        }
        if let Some(value) = dict.get_item("max_collection_items")? {
            config.max_collection_items = value.extract()?;
        }

        if config.max_text_bytes == 0 {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "max_text_bytes must be greater than 0",
            ));
        }
        if config.max_text_bytes > MAX_TEXT_BYTES_LIMIT {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "max_text_bytes must be less than or equal to {}",
                MAX_TEXT_BYTES_LIMIT
            )));
        }
        if config.max_nested_depth == 0 {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "max_nested_depth must be greater than 0",
            ));
        }
        if config.max_nested_depth > MAX_NESTED_DEPTH_LIMIT {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "max_nested_depth must be less than or equal to {}",
                MAX_NESTED_DEPTH_LIMIT
            )));
        }
        if config.max_collection_items == 0 {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "max_collection_items must be greater than 0",
            ));
        }
        if config.max_collection_items > MAX_COLLECTION_ITEMS_LIMIT {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "max_collection_items must be less than or equal to {}",
                MAX_COLLECTION_ITEMS_LIMIT
            )));
        }

        // Extract string values
        if let Some(value) = dict.get_item("redaction_text")? {
            config.redaction_text = value.extract()?;
        }

        // Extract mask strategy
        if let Some(value) = dict.get_item("default_mask_strategy")? {
            let strategy_str: String = value.extract()?;
            config.default_mask_strategy =
                Self::parse_mask_strategy(&strategy_str, "default_mask_strategy")?;
        }

        // Extract custom patterns
        if let Some(value) = dict.get_item("custom_patterns")?
            && let Ok(py_list) = value.cast::<pyo3::types::PyList>()
        {
            for item in py_list.iter() {
                if let Ok(py_dict) = item.cast::<PyDict>() {
                    let pattern: String = py_dict
                        .get_item("pattern")?
                        .ok_or_else(|| {
                            pyo3::exceptions::PyValueError::new_err("Missing 'pattern' field")
                        })?
                        .extract()?;
                    let description: String = py_dict
                        .get_item("description")?
                        .ok_or_else(|| {
                            pyo3::exceptions::PyValueError::new_err("Missing 'description' field")
                        })?
                        .extract()?;
                    let mask_strategy = match py_dict.get_item("mask_strategy")? {
                        Some(val) if val.is_none() => None,
                        Some(val) => {
                            let mask_strategy_str: String = val.extract()?;
                            Some(Self::parse_mask_strategy(
                                &mask_strategy_str,
                                "custom_patterns[].mask_strategy",
                            )?)
                        }
                        None => None,
                    };
                    let enabled: bool = match py_dict.get_item("enabled")? {
                        Some(val) => val.extract()?,
                        None => true,
                    };

                    config.custom_patterns.push(CustomPattern {
                        pattern,
                        description,
                        mask_strategy,
                        enabled,
                    });
                }
            }
        }

        // Extract whitelist patterns
        if let Some(value) = dict.get_item("whitelist_patterns")? {
            config.whitelist_patterns = value.extract()?;
        }

        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pyo3::types::{PyDict, PyList, PyModule};

    #[test]
    fn test_pii_type_as_str() {
        assert_eq!(PIIType::Ssn.as_str(), "ssn");
        assert_eq!(PIIType::CreditCard.as_str(), "credit_card");
        assert_eq!(PIIType::Email.as_str(), "email");
    }

    #[test]
    fn test_default_config() {
        let config = PIIConfig::default();
        assert!(config.detect_ssn);
        assert!(config.detect_email);
        assert_eq!(config.redaction_text, "[REDACTED]");
        assert_eq!(config.default_mask_strategy, MaskingStrategy::Redact);
        assert_eq!(config.max_text_bytes, DEFAULT_MAX_TEXT_BYTES);
        assert_eq!(config.max_nested_depth, DEFAULT_MAX_NESTED_DEPTH);
        assert_eq!(config.max_collection_items, DEFAULT_MAX_COLLECTION_ITEMS);
    }

    #[test]
    fn test_from_py_dict_rejects_excessive_resource_limits() {
        Python::initialize();
        Python::attach(|py| {
            let dict = PyDict::new(py);
            dict.set_item("max_text_bytes", 100 * 1024 * 1024 + 1)
                .unwrap();

            let err = PIIConfig::from_py_dict(&dict).unwrap_err();
            assert!(err.to_string().contains("max_text_bytes"));
        });
    }

    #[test]
    fn test_from_py_dict_rejects_excessive_nested_depth() {
        Python::initialize();
        Python::attach(|py| {
            let dict = PyDict::new(py);
            dict.set_item("max_nested_depth", MAX_NESTED_DEPTH_LIMIT + 1)
                .unwrap();

            let err = PIIConfig::from_py_dict(&dict).unwrap_err();
            assert!(err.to_string().contains("max_nested_depth"));
        });
    }

    #[test]
    fn test_from_py_dict_rejects_excessive_collection_items() {
        Python::initialize();
        Python::attach(|py| {
            let dict = PyDict::new(py);
            dict.set_item("max_collection_items", MAX_COLLECTION_ITEMS_LIMIT + 1)
                .unwrap();

            let err = PIIConfig::from_py_dict(&dict).unwrap_err();
            assert!(err.to_string().contains("max_collection_items"));
        });
    }

    #[test]
    fn test_from_py_dict_custom_pattern_without_mask_strategy_keeps_none() {
        Python::initialize();
        Python::attach(|py| {
            let dict = PyDict::new(py);
            dict.set_item("default_mask_strategy", "partial").unwrap();

            let custom_pattern = PyDict::new(py);
            custom_pattern.set_item("pattern", r"\bEMP\d{6}\b").unwrap();
            custom_pattern
                .set_item("description", "Employee ID")
                .unwrap();

            let custom_patterns = pyo3::types::PyList::empty(py);
            custom_patterns.append(custom_pattern).unwrap();
            dict.set_item("custom_patterns", custom_patterns).unwrap();

            let config = PIIConfig::from_py_dict(&dict).unwrap();

            assert_eq!(config.default_mask_strategy, MaskingStrategy::Partial);
            assert_eq!(config.custom_patterns.len(), 1);
            assert_eq!(config.custom_patterns[0].mask_strategy, None);
        });
    }

    #[test]
    fn test_from_py_dict_custom_pattern_with_mask_strategy_none_keeps_none() {
        Python::initialize();
        Python::attach(|py| {
            let dict = PyDict::new(py);
            dict.set_item("default_mask_strategy", "partial").unwrap();

            let custom_pattern = PyDict::new(py);
            custom_pattern.set_item("pattern", r"\bEMP\d{6}\b").unwrap();
            custom_pattern
                .set_item("description", "Employee ID")
                .unwrap();
            custom_pattern.set_item("mask_strategy", py.None()).unwrap();

            let custom_patterns = PyList::empty(py);
            custom_patterns.append(custom_pattern).unwrap();
            dict.set_item("custom_patterns", custom_patterns).unwrap();

            let config = PIIConfig::from_py_dict(&dict).unwrap();

            assert_eq!(config.default_mask_strategy, MaskingStrategy::Partial);
            assert_eq!(config.custom_patterns.len(), 1);
            assert_eq!(config.custom_patterns[0].mask_strategy, None);
        });
    }

    #[test]
    fn test_from_py_object_model_dump_none_mask_strategy_keeps_none() {
        Python::initialize();
        Python::attach(|py| {
            let module = PyModule::from_code(
                py,
                pyo3::ffi::c_str!(
                    r#"
class ConfigModel:
    def model_dump(self):
        return {
            "default_mask_strategy": "partial",
            "custom_patterns": [
                {
                    "pattern": r"\bEMP\d{6}\b",
                    "description": "Employee ID",
                    "mask_strategy": None,
                }
            ],
        }
"#
                ),
                pyo3::ffi::c_str!("test_config_model.py"),
                pyo3::ffi::c_str!("test_config_model"),
            )
            .unwrap();
            let config_model = module.getattr("ConfigModel").unwrap().call0().unwrap();

            let config = PIIConfig::from_py_object(&config_model).unwrap();

            assert_eq!(config.default_mask_strategy, MaskingStrategy::Partial);
            assert_eq!(config.custom_patterns.len(), 1);
            assert_eq!(config.custom_patterns[0].mask_strategy, None);
        });
    }

    #[test]
    fn test_from_py_object_model_dump_omitted_mask_strategy_keeps_none() {
        Python::initialize();
        Python::attach(|py| {
            let module = PyModule::from_code(
                py,
                pyo3::ffi::c_str!(
                    r#"
class ConfigModel:
    def model_dump(self):
        return {
            "default_mask_strategy": "partial",
            "custom_patterns": [
                {
                    "pattern": r"\bEMP\d{6}\b",
                    "description": "Employee ID",
                }
            ],
        }
"#
                ),
                pyo3::ffi::c_str!("test_config_model_omitted.py"),
                pyo3::ffi::c_str!("test_config_model_omitted"),
            )
            .unwrap();
            let config_model = module.getattr("ConfigModel").unwrap().call0().unwrap();

            let config = PIIConfig::from_py_object(&config_model).unwrap();

            assert_eq!(config.default_mask_strategy, MaskingStrategy::Partial);
            assert_eq!(config.custom_patterns.len(), 1);
            assert_eq!(config.custom_patterns[0].mask_strategy, None);
        });
    }

    #[test]
    fn test_from_py_dict_rejects_invalid_default_mask_strategy() {
        Python::initialize();
        Python::attach(|py| {
            let dict = PyDict::new(py);
            dict.set_item("default_mask_strategy", "partail").unwrap();

            let err = PIIConfig::from_py_dict(&dict).unwrap_err();
            assert!(err.to_string().contains("default_mask_strategy"));
        });
    }

    #[test]
    fn test_from_py_dict_rejects_invalid_custom_mask_strategy() {
        Python::initialize();
        Python::attach(|py| {
            let dict = PyDict::new(py);

            let custom_pattern = PyDict::new(py);
            custom_pattern.set_item("pattern", r"\bEMP\d{6}\b").unwrap();
            custom_pattern
                .set_item("description", "Employee ID")
                .unwrap();
            custom_pattern.set_item("mask_strategy", "partail").unwrap();

            let custom_patterns = PyList::empty(py);
            custom_patterns.append(custom_pattern).unwrap();
            dict.set_item("custom_patterns", custom_patterns).unwrap();

            let err = PIIConfig::from_py_dict(&dict).unwrap_err();
            assert!(err.to_string().contains("custom_patterns[].mask_strategy"));
        });
    }

    #[test]
    fn test_from_py_object_rejects_invalid_default_mask_strategy_from_model_dump() {
        Python::initialize();
        Python::attach(|py| {
            let module = PyModule::from_code(
                py,
                pyo3::ffi::c_str!(
                    r#"
class ConfigModel:
    def model_dump(self):
        return {"default_mask_strategy": "partail"}
"#
                ),
                pyo3::ffi::c_str!("test_invalid_default_model.py"),
                pyo3::ffi::c_str!("test_invalid_default_model"),
            )
            .unwrap();
            let config_model = module.getattr("ConfigModel").unwrap().call0().unwrap();

            let err = PIIConfig::from_py_object(&config_model).unwrap_err();
            assert!(err.to_string().contains("default_mask_strategy"));
        });
    }

    #[test]
    fn test_from_py_object_rejects_invalid_custom_mask_strategy_from_model_dump() {
        Python::initialize();
        Python::attach(|py| {
            let module = PyModule::from_code(
                py,
                pyo3::ffi::c_str!(
                    r#"
class ConfigModel:
    def model_dump(self):
        return {
            "custom_patterns": [
                {
                    "pattern": r"\bEMP\d{6}\b",
                    "description": "Employee ID",
                    "mask_strategy": "partail",
                }
            ]
        }
"#
                ),
                pyo3::ffi::c_str!("test_invalid_custom_model.py"),
                pyo3::ffi::c_str!("test_invalid_custom_model"),
            )
            .unwrap();
            let config_model = module.getattr("ConfigModel").unwrap().call0().unwrap();

            let err = PIIConfig::from_py_object(&config_model).unwrap_err();
            assert!(err.to_string().contains("custom_patterns[].mask_strategy"));
        });
    }
}
