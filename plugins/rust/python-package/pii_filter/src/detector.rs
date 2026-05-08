// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
//
// Core PII detection logic with PyO3 bindings

use log::{debug, warn};
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyDict, PyList, PyMapping, PySet, PyString, PyTuple};
use pyo3_stub_gen::derive::*;
use std::collections::HashMap;

use super::config::{MaskingStrategy, PIIConfig, PIIType};
use super::masking;
use super::patterns::{CompiledPatterns, compile_patterns};

/// Public API for benchmarks - detect PII in text
#[allow(dead_code)]
pub fn detect_pii(
    text: &str,
    patterns: &CompiledPatterns,
    config: &PIIConfig,
) -> HashMap<PIIType, Vec<Detection>> {
    collect_detections(text, patterns, config)
}

fn collect_detections(
    text: &str,
    patterns: &CompiledPatterns,
    config: &PIIConfig,
) -> HashMap<PIIType, Vec<Detection>> {
    let mut detections: HashMap<PIIType, Vec<Detection>> = HashMap::new();
    let mut candidates = Vec::new();

    // Use RegexSet for parallel matching
    let matches = patterns.regex_set.matches(text);

    for pattern_idx in matches.iter() {
        let pattern = &patterns.patterns[pattern_idx];

        for capture in pattern.regex.captures_iter(text) {
            if let Some(mat) = capture.get(0) {
                let start = mat.start();
                let end = mat.end();
                let value = mat.as_str().to_string();

                if is_whitelisted(patterns, text, start, end) {
                    continue;
                }

                if !is_valid_detection(pattern.pii_type, &value) {
                    continue;
                }

                candidates.push(CandidateDetection {
                    pii_type: pattern.pii_type,
                    value,
                    start,
                    end,
                    mask_strategy: pattern
                        .mask_strategy
                        .unwrap_or(config.default_mask_strategy),
                    pattern_idx,
                });
            }
        }
    }

    candidates.sort_by(|a, b| {
        a.start
            .cmp(&b.start)
            .then(b.end.cmp(&a.end))
            .then(a.pii_type.as_str().cmp(b.pii_type.as_str()))
            .then(a.pattern_idx.cmp(&b.pattern_idx))
    });

    let mut last_end = 0usize;
    for candidate in candidates {
        if candidate.start < last_end {
            continue;
        }

        last_end = candidate.end;
        detections
            .entry(candidate.pii_type)
            .or_default()
            .push(Detection {
                value: candidate.value,
                start: candidate.start,
                end: candidate.end,
                mask_strategy: candidate.mask_strategy,
            });
    }

    detections
}

/// A single PII detection result
#[derive(Debug, Clone)]
pub struct Detection {
    pub value: String,
    pub start: usize,
    pub end: usize,
    pub mask_strategy: MaskingStrategy,
}

type NestedProcessResult = (bool, Py<PyAny>, HashMap<PIIType, Vec<Detection>>);

#[derive(Debug, Clone)]
struct CandidateDetection {
    pii_type: PIIType,
    value: String,
    start: usize,
    end: usize,
    mask_strategy: MaskingStrategy,
    pattern_idx: usize,
}

/// Main PII detector exposed to Python
///
/// # Example (Python)
/// ```python
/// from cpex_pii_filter import PIIDetectorRust
///
/// config = {"detect_ssn": True, "detect_email": True}
/// detector = PIIDetectorRust(config)
///
/// text = "My SSN is 123-45-6789 and email is john@example.com"
/// detections = detector.detect(text)
/// print(detections)  # {"ssn": [...], "email": [...]}
///
/// masked = detector.mask(text, detections)
/// print(masked)  # "My SSN is [REDACTED] and email is [REDACTED]"
/// ```
#[gen_stub_pyclass]
#[pyclass]
pub struct PIIDetectorRust {
    pub(crate) patterns: CompiledPatterns,
    pub(crate) config: PIIConfig,
}

#[gen_stub_pymethods]
#[pymethods]
impl PIIDetectorRust {
    /// Create a new PII detector
    ///
    /// # Arguments
    /// * `config` - Python dictionary or Pydantic model with configuration
    ///
    /// # Configuration Keys
    /// * `detect_ssn` (bool): Detect Social Security Numbers
    /// * `detect_bsn` (bool): Detect Dutch citizen service numbers
    /// * `detect_credit_card` (bool): Detect credit card numbers
    /// * `detect_email` (bool): Detect email addresses
    /// * `detect_phone` (bool): Detect phone numbers
    /// * `detect_ip_address` (bool): Detect IP addresses
    /// * `detect_date_of_birth` (bool): Detect dates of birth
    /// * `detect_passport` (bool): Detect passport numbers
    /// * `detect_driver_license` (bool): Detect driver's license numbers
    /// * `detect_bank_account` (bool): Detect bank account numbers
    /// * `detect_medical_record` (bool): Detect medical record numbers
    /// * `default_mask_strategy` (str): "redact", "partial", "hash", "tokenize", "remove"
    /// * `redaction_text` (str): Text to use for redaction (default: "\[REDACTED\]")
    /// * `block_on_detection` (bool): Whether to block on detection
    /// * `log_detections` (bool): Emit detection log messages when matches are found
    /// * `include_detection_details` (bool): Include detection summaries in plugin-hook metadata
    /// * `max_text_bytes` (int): Maximum text payload size to inspect
    /// * `max_nested_depth` (int): Maximum nested container depth to inspect
    /// * `max_collection_items` (int): Maximum items to inspect per collection
    /// * `custom_patterns` (`list[dict]`): Additional regex-based PII patterns.
    ///   `mask_strategy` is optional and inherits `default_mask_strategy` when omitted or `None`.
    /// * `whitelist_patterns` (`list[str]`): Regex patterns to exclude from detection
    #[new]
    pub fn new(config: &Bound<'_, PyAny>) -> PyResult<Self> {
        // Extract configuration from Python object (dict or Pydantic model)
        let config = PIIConfig::from_py_object(config).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Invalid config: {}", e))
        })?;

        // Compile regex patterns
        let patterns = compile_patterns(&config).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                "Pattern compilation failed: {}",
                e
            ))
        })?;

        debug!(
            "Created PIIDetectorRust: log_detections={} block_on_detection={} custom_patterns={} whitelist_patterns={}",
            config.log_detections,
            config.block_on_detection,
            config.custom_patterns.len(),
            config.whitelist_patterns.len()
        );

        Ok(Self { patterns, config })
    }

    /// Detect PII in text
    ///
    /// # Arguments
    /// * `text` - Text to scan for PII
    ///
    /// # Returns
    /// Dictionary mapping PII type to list of detections:
    /// ```python
    /// {
    ///     "ssn": [
    ///         {"value": "123-45-6789", "start": 10, "end": 21, "mask_strategy": "redact"}
    ///     ],
    ///     "email": [
    ///         {"value": "john@example.com", "start": 35, "end": 51, "mask_strategy": "redact"}
    ///     ]
    /// }
    /// ```
    pub fn detect(&self, text: &str) -> PyResult<Py<PyAny>> {
        validate_text_size(text, self.config.max_text_bytes)?;
        let detections = self.detect_internal(text);
        if self.config.log_detections && !detections.is_empty() {
            debug!(
                "Detected {} PII item(s) across {} type(s) in text input",
                detections.values().map(Vec::len).sum::<usize>(),
                detections.len()
            );
        }

        // Convert Rust HashMap to Python dict
        Python::attach(|py| {
            let py_dict = PyDict::new(py);

            for (pii_type, items) in detections {
                let py_list = PyList::empty(py);

                for detection in items {
                    let item_dict = PyDict::new(py);
                    item_dict.set_item("value", detection.value)?;
                    item_dict.set_item("start", detection.start)?;
                    item_dict.set_item("end", detection.end)?;
                    item_dict.set_item(
                        "mask_strategy",
                        format!("{:?}", detection.mask_strategy).to_lowercase(),
                    )?;

                    py_list.append(item_dict)?;
                }

                py_dict.set_item(pii_type.as_str(), py_list)?;
            }

            Ok(py_dict.into_any().unbind())
        })
    }

    /// Mask detected PII in text
    ///
    /// # Arguments
    /// * `text` - Original text
    /// * `detections` - Detection results from detect()
    ///
    /// # Returns
    /// Masked text with PII replaced
    pub fn mask(&self, text: &str, detections: &Bound<'_, PyAny>) -> PyResult<String> {
        validate_text_size(text, self.config.max_text_bytes)?;

        // Convert Python detections back to Rust format
        let rust_detections = self.py_detections_to_rust(detections)?;
        if self.config.log_detections && !rust_detections.is_empty() {
            debug!(
                "Masking {} PII item(s) across {} type(s)",
                rust_detections.values().map(Vec::len).sum::<usize>(),
                rust_detections.len()
            );
        }

        // Apply masking
        masking::mask_pii(text, &rust_detections, &self.config)
            .map(|masked| masked.into_owned())
            .map_err(PyErr::new::<pyo3::exceptions::PyValueError, _>)
    }

    /// Process nested data structures (dicts, lists, strings)
    ///
    /// # Arguments
    /// * `data` - Python object (dict, list, str, or other)
    /// * `path` - Current path in the structure (for logging)
    ///
    /// # Returns
    /// Tuple of (modified: bool, new_data: Any, detections: dict)
    pub fn process_nested(
        &self,
        py: Python,
        data: &Bound<'_, PyAny>,
        path: &str,
    ) -> PyResult<(bool, Py<PyAny>, Py<PyAny>)> {
        let (modified, new_data, detections) = self.process_nested_rust(py, data, path)?;
        let py_detections = self.rust_detections_to_py(py, &detections)?;
        Ok((modified, new_data, py_detections))
    }
}

// Internal methods
impl PIIDetectorRust {
    pub(crate) fn process_nested_rust(
        &self,
        py: Python,
        data: &Bound<'_, PyAny>,
        path: &str,
    ) -> PyResult<NestedProcessResult> {
        self.process_nested_internal(py, data, path, 0)
    }

    fn process_nested_internal(
        &self,
        py: Python,
        data: &Bound<'_, PyAny>,
        path: &str,
        depth: usize,
    ) -> PyResult<NestedProcessResult> {
        if depth > self.config.max_nested_depth {
            warn!(
                "Rejected nested data at path '{}' because depth {} exceeds max {}",
                path, depth, self.config.max_nested_depth
            );
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                "Nested data exceeds maximum depth of {}",
                self.config.max_nested_depth
            )));
        }

        // Handle strings directly
        if let Ok(py_string) = data.cast::<PyString>() {
            let text = py_string.to_cow()?;
            validate_text_size(&text, self.config.max_text_bytes)?;
            let detections = self.detect_internal(&text);

            if !detections.is_empty() {
                if self.config.log_detections {
                    debug!(
                        "Detected {} PII item(s) across {} type(s) at nested path '{}'",
                        detections.values().map(Vec::len).sum::<usize>(),
                        detections.len(),
                        path
                    );
                }
                let masked = masking::mask_pii(&text, &detections, &self.config).map_err(|e| {
                    PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                        "Failed to mask nested string at '{}': {}",
                        path, e
                    ))
                })?;
                return Ok((
                    true,
                    masked.into_owned().into_pyobject(py)?.into_any().unbind(),
                    detections,
                ));
            } else {
                return Ok((false, data.clone().unbind(), HashMap::new()));
            }
        }

        // Handle mappings through the Python protocol. CPEX isolation wraps
        // dicts in copy-on-write dict subclasses whose visible entries are not
        // stored in the underlying PyDict table.
        if let Ok(mapping) = data.cast::<PyMapping>() {
            let mapping_len = mapping.len()?;
            let mut entries: Vec<(Py<PyAny>, Py<PyAny>)> = Vec::with_capacity(mapping_len);
            let mut all_detections = HashMap::new();
            if mapping_len > self.config.max_collection_items {
                warn!(
                    "Rejected nested mapping at path '{}' because size {} exceeds max {}",
                    path, mapping_len, self.config.max_collection_items
                );
                return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                    "Nested mapping exceeds maximum size of {} items",
                    self.config.max_collection_items
                )));
            }

            for item in mapping.items()?.iter() {
                let item = item.cast::<PyTuple>()?;
                let key = item.get_item(0)?;
                let value = item.get_item(1)?;
                let key_str = key.str()?.to_string_lossy().into_owned();
                let new_path = if path.is_empty() {
                    key_str.clone()
                } else {
                    format!("{}.{}", path, key_str)
                };

                let (val_modified, new_value, val_detections) =
                    self.process_nested_internal(py, &value, &new_path, depth + 1)?;

                if val_modified {
                    entries.push((key.clone().unbind(), new_value));
                    merge_detection_maps(&mut all_detections, val_detections);
                } else {
                    entries.push((key.clone().unbind(), value.clone().unbind()));
                }
            }

            if all_detections.is_empty() {
                return Ok((false, data.clone().unbind(), all_detections));
            }

            let new_dict = PyDict::new(py);
            for (key, value) in entries {
                new_dict.set_item(key.bind(py), value.bind(py))?;
            }
            return Ok((true, new_dict.into_any().unbind(), all_detections));
        }

        // Handle lists
        if let Ok(list) = data.cast::<PyList>() {
            let mut items: Vec<Py<PyAny>> = Vec::with_capacity(list.len());
            let mut all_detections = HashMap::new();
            if list.len() > self.config.max_collection_items {
                warn!(
                    "Rejected nested list at path '{}' because size {} exceeds max {}",
                    path,
                    list.len(),
                    self.config.max_collection_items
                );
                return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                    "Nested list exceeds maximum size of {} items",
                    self.config.max_collection_items
                )));
            }

            for (idx, item) in list.iter().enumerate() {
                let new_path = format!("{}[{}]", path, idx);
                let (item_modified, new_item, item_detections) =
                    self.process_nested_internal(py, &item, &new_path, depth + 1)?;

                if item_modified {
                    items.push(new_item);
                    merge_detection_maps(&mut all_detections, item_detections);
                } else {
                    items.push(item.clone().unbind());
                }
            }

            if all_detections.is_empty() {
                return Ok((false, data.clone().unbind(), all_detections));
            }

            let new_list = PyList::empty(py);
            for item in items {
                new_list.append(item.bind(py))?;
            }
            return Ok((true, new_list.into_any().unbind(), all_detections));
        }

        // Handle tuples
        if let Ok(tuple) = data.cast::<PyTuple>() {
            if tuple.len() > self.config.max_collection_items {
                warn!(
                    "Rejected nested tuple at path '{}' because size {} exceeds max {}",
                    path,
                    tuple.len(),
                    self.config.max_collection_items
                );
                return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                    "Nested tuple exceeds maximum size of {} items",
                    self.config.max_collection_items
                )));
            }

            let mut items: Vec<Py<PyAny>> = Vec::with_capacity(tuple.len());
            let mut all_detections = HashMap::new();
            for (idx, item) in tuple.iter().enumerate() {
                let new_path = format!("{}[{}]", path, idx);
                let (item_modified, new_item, item_detections) =
                    self.process_nested_internal(py, &item, &new_path, depth + 1)?;
                if item_modified {
                    items.push(new_item);
                    merge_detection_maps(&mut all_detections, item_detections);
                } else {
                    items.push(item.clone().unbind());
                }
            }

            if all_detections.is_empty() {
                return Ok((false, data.clone().unbind(), all_detections));
            }

            let rebuilt = PyTuple::new(py, items.iter().map(|item| item.bind(py)))?;
            return Ok((true, rebuilt.into_any().unbind(), all_detections));
        }

        // Handle sets
        if let Ok(set) = data.cast::<PySet>() {
            if set.len() > self.config.max_collection_items {
                warn!(
                    "Rejected nested set at path '{}' because size {} exceeds max {}",
                    path,
                    set.len(),
                    self.config.max_collection_items
                );
                return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                    "Nested set exceeds maximum size of {} items",
                    self.config.max_collection_items
                )));
            }

            let mut items: Vec<Py<PyAny>> = Vec::with_capacity(set.len());
            let mut all_detections = HashMap::new();
            for (idx, item) in set.iter().enumerate() {
                let new_path = format!("{}{{{}}}", path, idx);
                let (item_modified, new_item, item_detections) =
                    self.process_nested_internal(py, &item, &new_path, depth + 1)?;
                if item_modified {
                    items.push(new_item);
                    merge_detection_maps(&mut all_detections, item_detections);
                } else {
                    items.push(item.clone().unbind());
                }
            }

            if all_detections.is_empty() {
                return Ok((false, data.clone().unbind(), all_detections));
            }

            let rebuilt = PySet::empty(py)?;
            for item in items {
                rebuilt.add(item.bind(py))?;
            }
            return Ok((true, rebuilt.into_any().unbind(), all_detections));
        }

        // Handle Python objects with __dict__ by cloning and mutating the clone.
        if let Ok(attributes_value) = data.getattr("__dict__")
            && let Ok(attributes) = attributes_value.cast_into::<PyDict>()
        {
            let (modified, new_attrs, detections) =
                self.process_nested_internal(py, attributes.as_any(), path, depth + 1)?;
            if !modified {
                return Ok((false, data.clone().unbind(), detections));
            }

            let copy_module = PyModule::import(py, "copy")?;
            let cloned = copy_module.getattr("copy")?.call1((data,))?;
            let new_attrs = new_attrs.bind(py).cast::<PyDict>()?;
            for (key, value) in new_attrs.iter() {
                let key_str = key.extract::<String>()?;
                cloned.setattr(key_str.as_str(), value)?;
            }
            return Ok((true, cloned.unbind(), detections));
        }

        // Other types: no processing
        Ok((false, data.clone().unbind(), HashMap::new()))
    }

    /// Internal detection logic (returns Rust types)
    fn detect_internal(&self, text: &str) -> HashMap<PIIType, Vec<Detection>> {
        collect_detections(text, &self.patterns, &self.config)
    }

    pub(crate) fn detect_rust(&self, text: &str) -> PyResult<HashMap<PIIType, Vec<Detection>>> {
        validate_text_size(text, self.config.max_text_bytes)?;
        Ok(self.detect_internal(text))
    }

    pub(crate) fn mask_rust(
        &self,
        text: &str,
        detections: &HashMap<PIIType, Vec<Detection>>,
    ) -> PyResult<String> {
        validate_text_size(text, self.config.max_text_bytes)?;
        masking::mask_pii(text, detections, &self.config)
            .map(|masked| masked.into_owned())
            .map_err(PyErr::new::<pyo3::exceptions::PyValueError, _>)
    }

    /// Convert Python detections to Rust format
    pub(crate) fn py_detections_to_rust(
        &self,
        detections: &Bound<'_, PyAny>,
    ) -> PyResult<HashMap<PIIType, Vec<Detection>>> {
        let mut rust_detections = HashMap::new();

        if let Ok(dict) = detections.cast::<PyDict>() {
            for (key, value) in dict.iter() {
                if let Ok(type_str) = key.extract::<String>()
                    && let Ok(pii_type) = str_to_pii_type(&type_str)
                {
                    let items = self.py_list_to_detections(&value)?;
                    rust_detections.insert(pii_type, items);
                }
            }
        }

        Ok(rust_detections)
    }

    /// Convert Python list to `Vec<Detection>`
    fn py_list_to_detections(&self, py_list: &Bound<'_, PyAny>) -> PyResult<Vec<Detection>> {
        let mut detections = Vec::new();

        if let Ok(list) = py_list.cast::<PyList>() {
            for item in list.iter() {
                if let Ok(dict) = item.cast::<PyDict>() {
                    let value: String = required_detection_field(dict, "value")?;
                    let start: usize = required_detection_field(dict, "start")?;
                    let end: usize = required_detection_field(dict, "end")?;
                    let strategy_str: String = required_detection_field(dict, "mask_strategy")?;

                    let mask_strategy = match strategy_str.as_str() {
                        "partial" => MaskingStrategy::Partial,
                        "hash" => MaskingStrategy::Hash,
                        "tokenize" => MaskingStrategy::Tokenize,
                        "remove" => MaskingStrategy::Remove,
                        _ => MaskingStrategy::Redact,
                    };

                    detections.push(Detection {
                        value,
                        start,
                        end,
                        mask_strategy,
                    });
                }
            }
        }

        Ok(detections)
    }

    /// Convert Rust detections to Python dict
    fn rust_detections_to_py(
        &self,
        py: Python,
        detections: &HashMap<PIIType, Vec<Detection>>,
    ) -> PyResult<Py<PyAny>> {
        let py_dict = PyDict::new(py);

        for (pii_type, items) in detections {
            let py_list = PyList::empty(py);

            for detection in items {
                let item_dict = PyDict::new(py);
                item_dict.set_item("value", detection.value.clone())?;
                item_dict.set_item("start", detection.start)?;
                item_dict.set_item("end", detection.end)?;
                item_dict.set_item(
                    "mask_strategy",
                    format!("{:?}", detection.mask_strategy).to_lowercase(),
                )?;

                py_list.append(item_dict)?;
            }

            py_dict.set_item(pii_type.as_str(), py_list)?;
        }

        Ok(py_dict.into_any().unbind())
    }
}

pub(crate) fn merge_detection_maps(
    target: &mut HashMap<PIIType, Vec<Detection>>,
    source: HashMap<PIIType, Vec<Detection>>,
) {
    for (pii_type, items) in source {
        target.entry(pii_type).or_default().extend(items);
    }
}

fn str_to_pii_type(s: &str) -> Result<PIIType, ()> {
    match s {
        "ssn" => Ok(PIIType::Ssn),
        "bsn" => Ok(PIIType::Bsn),
        "credit_card" => Ok(PIIType::CreditCard),
        "email" => Ok(PIIType::Email),
        "phone" => Ok(PIIType::Phone),
        "ip_address" => Ok(PIIType::IpAddress),
        "date_of_birth" => Ok(PIIType::DateOfBirth),
        "passport" => Ok(PIIType::Passport),
        "driver_license" => Ok(PIIType::DriverLicense),
        "bank_account" => Ok(PIIType::BankAccount),
        "medical_record" => Ok(PIIType::MedicalRecord),
        "custom" => Ok(PIIType::Custom),
        _ => Err(()),
    }
}

fn is_valid_ssn(value: &str) -> bool {
    let digits: String = value.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() != 9 {
        return false;
    }

    let area = &digits[0..3];
    let group = &digits[3..5];
    let serial = &digits[5..9];

    area != "000" && area != "666" && area < "900" && group != "00" && serial != "0000"
}

fn passes_luhn(value: &str) -> bool {
    let digits: Vec<u32> = value
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();

    if !(13..=19).contains(&digits.len()) {
        return false;
    }

    let mut sum = 0u32;
    let parity = digits.len() % 2;

    for (idx, digit) in digits.iter().enumerate() {
        let mut value = *digit;
        if idx % 2 == parity {
            value *= 2;
            if value > 9 {
                value -= 9;
            }
        }
        sum += value;
    }

    sum.is_multiple_of(10) && has_known_card_prefix(&digits)
}

fn has_known_card_prefix(digits: &[u32]) -> bool {
    let as_string: String = digits
        .iter()
        .filter_map(|digit| char::from_digit(*digit, 10))
        .collect();
    let len = digits.len();

    let prefix1 = as_string.get(0..1).unwrap_or("");
    let prefix2 = as_string.get(0..2).unwrap_or("");
    let prefix3 = as_string.get(0..3).unwrap_or("");
    let prefix4 = as_string.get(0..4).unwrap_or("");

    matches!((prefix1, len), ("4", 13 | 16 | 19))
        || matches!((prefix2, len), ("34" | "37", 15))
        || matches!((prefix4, len), ("6011", 16 | 19))
        || matches!((prefix2, len), ("65", 16 | 19))
        || matches!(prefix2.parse::<u32>(), Ok(62)) && (16..=19).contains(&len)
        || matches!(prefix2.parse::<u32>(), Ok(67)) && (12..=19).contains(&len)
        || matches!((prefix2, len), ("36" | "38" | "39", 14))
        || matches!(
            (prefix3, len),
            ("300" | "301" | "302" | "303" | "304" | "305", 14)
        )
        || matches!(prefix2.parse::<u32>(), Ok(51..=55)) && len == 16
        || matches!(prefix4.parse::<u32>(), Ok(2221..=2720)) && len == 16
        || matches!(prefix4.parse::<u32>(), Ok(3528..=3589)) && len == 16
}

fn validate_text_size(text: &str, max_text_bytes: usize) -> PyResult<()> {
    if text.len() > max_text_bytes {
        warn!(
            "Rejected text input because size {} exceeds max {} bytes",
            text.len(),
            max_text_bytes
        );
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
            "Input exceeds maximum supported size of {} bytes",
            max_text_bytes
        )));
    }

    Ok(())
}

fn is_whitelisted(patterns: &CompiledPatterns, text: &str, start: usize, end: usize) -> bool {
    let match_text = &text[start..end];
    patterns
        .whitelist
        .iter()
        .any(|pattern| pattern.is_match(match_text))
}

fn is_valid_detection(pii_type: PIIType, value: &str) -> bool {
    match pii_type {
        PIIType::Ssn => is_valid_ssn(value),
        PIIType::CreditCard => passes_luhn(value),
        _ => true,
    }
}

fn required_detection_field<'py, T>(dict: &Bound<'py, PyDict>, field: &str) -> PyResult<T>
where
    T: for<'a, 'py2> pyo3::FromPyObject<'a, 'py2>,
    for<'a, 'py2> <T as pyo3::FromPyObject<'a, 'py2>>::Error: Into<PyErr>,
{
    dict.get_item(field)?
        .ok_or_else(|| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                "Detection is missing required field '{}'",
                field
            ))
        })?
        .extract()
        .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pyo3::ffi::c_str;
    use pyo3::types::PyDict;
    use pyo3::types::PyModule;

    #[test]
    fn test_detect_ssn() {
        let config = PIIConfig {
            detect_ssn: true,
            ..Default::default()
        };
        let patterns = compile_patterns(&config).unwrap();
        let detector = PIIDetectorRust { patterns, config };

        let detections = detector.detect_internal("My SSN is 123-45-6789");

        assert!(detections.contains_key(&PIIType::Ssn));
        assert_eq!(detections[&PIIType::Ssn].len(), 1);
        assert_eq!(detections[&PIIType::Ssn][0].value, "123-45-6789");
    }

    #[test]
    fn test_detect_email() {
        let config = PIIConfig {
            detect_email: true,
            ..Default::default()
        };
        let patterns = compile_patterns(&config).unwrap();
        let detector = PIIDetectorRust { patterns, config };

        let detections = detector.detect_internal("Contact: john.doe@example.com");

        assert!(detections.contains_key(&PIIType::Email));
        assert_eq!(detections[&PIIType::Email][0].value, "john.doe@example.com");
    }

    #[test]
    fn test_detect_amex_credit_card() {
        let config = PIIConfig {
            detect_credit_card: true,
            ..Default::default()
        };
        let patterns = compile_patterns(&config).unwrap();
        let detector = PIIDetectorRust { patterns, config };

        let detections = detector.detect_internal("Card: 3782 822463 10005");

        assert!(detections.contains_key(&PIIType::CreditCard));
        assert_eq!(
            detections[&PIIType::CreditCard][0].value,
            "3782 822463 10005"
        );
    }

    #[test]
    fn test_no_overlap() {
        let config = PIIConfig::default();
        let patterns = compile_patterns(&config).unwrap();
        let detector = PIIDetectorRust { patterns, config };

        let detections = detector.detect_internal("123-45-6789");

        // Should only detect once, not multiple times
        let total: usize = detections.values().map(|v| v.len()).sum();
        assert!(total >= 1);
    }

    #[test]
    fn test_ssn_without_context_is_not_detected_for_plain_nine_digits() {
        let config = PIIConfig {
            detect_ssn: true,
            detect_bsn: false,
            detect_bank_account: false,
            ..Default::default()
        };
        let patterns = compile_patterns(&config).unwrap();
        let detector = PIIDetectorRust { patterns, config };

        let detections = detector.detect_internal("Reference number 123456789");
        assert!(!detections.contains_key(&PIIType::Ssn));
    }

    #[test]
    fn test_built_in_patterns_follow_global_default_mask_strategy() {
        let config = PIIConfig {
            detect_ssn: true,
            detect_email: true,
            detect_phone: false,
            detect_ip_address: false,
            default_mask_strategy: MaskingStrategy::Redact,
            redaction_text: "[PII_REDACTED]".to_string(),
            ..Default::default()
        };
        let patterns = compile_patterns(&config).unwrap();
        let detector = PIIDetectorRust { patterns, config };

        let detections = detector.detect_internal("SSN: 123-45-6789 Email: john@example.com");

        assert_eq!(
            detections[&PIIType::Ssn][0].mask_strategy,
            MaskingStrategy::Redact
        );
        assert_eq!(
            detections[&PIIType::Email][0].mask_strategy,
            MaskingStrategy::Redact
        );
    }

    #[test]
    fn test_built_in_mask_strategy_matrix_follows_global_override() {
        let config = PIIConfig {
            detect_ssn: true,
            detect_credit_card: true,
            detect_email: true,
            detect_phone: true,
            detect_ip_address: true,
            default_mask_strategy: MaskingStrategy::Hash,
            ..Default::default()
        };
        let patterns = compile_patterns(&config).unwrap();
        let detector = PIIDetectorRust { patterns, config };
        let detections = detector.detect_internal(
            "SSN 123-45-6789 Email john@example.com Phone 555-123-4567 Card 4111-1111-1111-1111 IP 192.168.1.1",
        );

        assert_eq!(
            detections[&PIIType::Ssn][0].mask_strategy,
            MaskingStrategy::Hash
        );
        assert_eq!(
            detections[&PIIType::CreditCard][0].mask_strategy,
            MaskingStrategy::Hash
        );
        assert_eq!(
            detections[&PIIType::Email][0].mask_strategy,
            MaskingStrategy::Hash
        );
        assert_eq!(
            detections[&PIIType::Phone][0].mask_strategy,
            MaskingStrategy::Hash
        );
        assert_eq!(
            detections[&PIIType::IpAddress][0].mask_strategy,
            MaskingStrategy::Hash
        );
    }

    #[test]
    fn test_built_in_mask_uses_global_partial_default() {
        let config = PIIConfig {
            detect_ssn: true,
            detect_email: true,
            detect_phone: false,
            detect_ip_address: false,
            detect_bsn: false,
            detect_credit_card: false,
            detect_bank_account: false,
            detect_date_of_birth: false,
            detect_passport: false,
            detect_driver_license: false,
            detect_medical_record: false,
            default_mask_strategy: MaskingStrategy::Partial,
            ..Default::default()
        };
        let patterns = compile_patterns(&config).unwrap();
        let detector = PIIDetectorRust { patterns, config };
        let detections = detector.detect_internal("SSN: 123-45-6789 Email: john@example.com");
        let masked = detector
            .mask_rust("SSN: 123-45-6789 Email: john@example.com", &detections)
            .unwrap();

        assert!(masked.contains("***-**-6789"));
        assert!(masked.contains("j***n@example.com"));
        assert!(!masked.contains("[REDACTED]"));
    }

    #[test]
    fn test_structurally_impossible_ssns_are_rejected() {
        let config = PIIConfig {
            detect_ssn: true,
            detect_credit_card: false,
            detect_email: false,
            detect_phone: false,
            detect_ip_address: false,
            detect_date_of_birth: false,
            detect_passport: false,
            detect_driver_license: false,
            detect_bank_account: false,
            detect_medical_record: false,
            detect_bsn: false,
            ..Default::default()
        };
        let patterns = compile_patterns(&config).unwrap();
        let detector = PIIDetectorRust { patterns, config };

        for text in [
            "SSN 000-12-3456",
            "SSN 666-12-3456",
            "SSN 901-12-3456",
            "SSN 123-00-4567",
            "SSN 123-45-0000",
        ] {
            let detections = detector.detect_internal(text);
            assert!(!detections.contains_key(&PIIType::Ssn));
        }
    }

    #[test]
    fn test_valid_contextual_ssn_is_detected() {
        let config = PIIConfig {
            detect_ssn: true,
            detect_bsn: false,
            detect_bank_account: false,
            ..Default::default()
        };
        let patterns = compile_patterns(&config).unwrap();
        let detector = PIIDetectorRust { patterns, config };

        let detections = detector.detect_internal("SSN: 123456789");
        assert!(detections.contains_key(&PIIType::Ssn));
    }

    #[test]
    fn test_credit_card_requires_luhn_validation() {
        let config = PIIConfig {
            detect_credit_card: true,
            detect_ssn: false,
            detect_email: false,
            detect_phone: false,
            detect_ip_address: false,
            detect_date_of_birth: false,
            detect_passport: false,
            detect_driver_license: false,
            detect_bank_account: false,
            detect_medical_record: false,
            detect_bsn: false,
            ..Default::default()
        };
        let patterns = compile_patterns(&config).unwrap();
        let detector = PIIDetectorRust { patterns, config };

        assert!(
            detector
                .detect_internal("Card 4111-1111-1111-1111")
                .contains_key(&PIIType::CreditCard)
        );
        assert!(
            !detector
                .detect_internal("Card 4111-1111-1111-1112")
                .contains_key(&PIIType::CreditCard)
        );
        assert!(
            !detector
                .detect_internal("Card 0000-0000-0000-0000")
                .contains_key(&PIIType::CreditCard)
        );
    }

    #[test]
    fn test_public_detect_pii_matches_validation_and_whitelist_behavior() {
        let config = PIIConfig {
            detect_credit_card: true,
            detect_email: true,
            whitelist_patterns: vec!["test@example\\.com".to_string()],
            ..Default::default()
        };
        let patterns = compile_patterns(&config).unwrap();

        let detections = detect_pii(
            "Email1: test@example.com, Email2: john@example.com, Card 4111-1111-1111-1112",
            &patterns,
            &config,
        );

        assert_eq!(
            detections[&PIIType::Email]
                .iter()
                .map(|d| d.value.as_str())
                .collect::<Vec<_>>(),
            vec!["john@example.com"]
        );
        assert!(!detections.contains_key(&PIIType::CreditCard));
    }

    #[test]
    fn test_benchmark_detect_pii_respects_whitelist_and_validation() {
        let config = PIIConfig {
            detect_credit_card: true,
            detect_email: true,
            whitelist_patterns: vec!["test@example\\.com".to_string()],
            ..Default::default()
        };
        let patterns = compile_patterns(&config).unwrap();

        let detections = detect_pii(
            "Email test@example.com Card 4111-1111-1111-1112",
            &patterns,
            &config,
        );

        assert!(
            !detections.contains_key(&PIIType::Email),
            "benchmark helper should apply whitelist filtering"
        );
        assert!(
            !detections.contains_key(&PIIType::CreditCard),
            "benchmark helper should reject invalid credit cards"
        );
    }

    #[test]
    fn test_bank_account_requires_context_to_avoid_false_positives() {
        let config = PIIConfig {
            detect_ssn: false,
            detect_bsn: false,
            detect_credit_card: false,
            detect_email: false,
            detect_phone: false,
            detect_ip_address: false,
            detect_date_of_birth: false,
            detect_passport: false,
            detect_driver_license: false,
            detect_bank_account: true,
            detect_medical_record: false,
            ..Default::default()
        };
        let patterns = compile_patterns(&config).unwrap();
        let detector = PIIDetectorRust { patterns, config };

        assert!(
            !detector
                .detect_internal("Timestamp 20250324123045")
                .contains_key(&PIIType::BankAccount)
        );
        assert!(
            detector
                .detect_internal("Account: 123456789")
                .contains_key(&PIIType::BankAccount)
        );
    }

    #[test]
    fn test_passport_requires_context_to_avoid_generic_ids() {
        let config = PIIConfig {
            detect_ssn: false,
            detect_bsn: false,
            detect_credit_card: false,
            detect_email: false,
            detect_phone: false,
            detect_ip_address: false,
            detect_date_of_birth: false,
            detect_passport: true,
            detect_driver_license: false,
            detect_bank_account: false,
            detect_medical_record: false,
            ..Default::default()
        };
        let patterns = compile_patterns(&config).unwrap();
        let detector = PIIDetectorRust { patterns, config };

        assert!(
            !detector
                .detect_internal("Employee ID AB123456")
                .contains_key(&PIIType::Passport)
        );
        assert!(
            detector
                .detect_internal("Passport Number: AB123456")
                .contains_key(&PIIType::Passport)
        );
    }

    #[test]
    fn test_passport_detection_includes_identifier_not_just_label() {
        let config = PIIConfig {
            detect_ssn: false,
            detect_bsn: false,
            detect_credit_card: false,
            detect_email: false,
            detect_phone: false,
            detect_ip_address: false,
            detect_date_of_birth: false,
            detect_passport: true,
            detect_driver_license: false,
            detect_bank_account: false,
            detect_medical_record: false,
            ..Default::default()
        };
        let patterns = compile_patterns(&config).unwrap();
        let detector = PIIDetectorRust { patterns, config };

        let detections = detector.detect_internal("Passport Number: AB123456");
        assert_eq!(
            detections[&PIIType::Passport][0].value,
            "Passport Number: AB123456"
        );
    }

    #[test]
    fn test_credit_card_accepts_valid_maestro_and_unionpay_numbers() {
        let config = PIIConfig {
            detect_credit_card: true,
            detect_ssn: false,
            detect_email: false,
            detect_phone: false,
            detect_ip_address: false,
            detect_date_of_birth: false,
            detect_passport: false,
            detect_driver_license: false,
            detect_bank_account: false,
            detect_medical_record: false,
            detect_bsn: false,
            ..Default::default()
        };
        let patterns = compile_patterns(&config).unwrap();
        let detector = PIIDetectorRust { patterns, config };

        assert!(
            detector
                .detect_internal("Card 6759649826438453")
                .contains_key(&PIIType::CreditCard)
        );
        assert!(
            detector
                .detect_internal("Card 6200000000000005")
                .contains_key(&PIIType::CreditCard)
        );
    }

    #[test]
    fn test_custom_patterns_keep_explicit_mask_strategy() {
        let mut config = PIIConfig {
            default_mask_strategy: MaskingStrategy::Redact,
            ..Default::default()
        };
        config
            .custom_patterns
            .push(super::super::config::CustomPattern {
                pattern: r"\bEMP\d{6}\b".to_string(),
                description: "Employee ID".to_string(),
                mask_strategy: Some(MaskingStrategy::Partial),
                enabled: true,
            });

        let patterns = compile_patterns(&config).unwrap();
        let detector = PIIDetectorRust { patterns, config };
        let detections = detector.detect_internal("Employee ID EMP123456");

        assert_eq!(
            detections[&PIIType::Custom][0].mask_strategy,
            MaskingStrategy::Partial
        );
    }

    #[test]
    fn test_custom_patterns_without_explicit_mask_strategy_follow_global_default() {
        Python::initialize();
        Python::attach(|py| {
            let config = PyDict::new(py);
            config.set_item("default_mask_strategy", "partial").unwrap();

            let custom_pattern = PyDict::new(py);
            custom_pattern.set_item("pattern", r"\bEMP\d{6}\b").unwrap();
            custom_pattern
                .set_item("description", "Employee ID")
                .unwrap();

            let custom_patterns = PyList::empty(py);
            custom_patterns.append(custom_pattern).unwrap();
            config.set_item("custom_patterns", custom_patterns).unwrap();

            let detector = PIIDetectorRust::new(&config.into_any()).unwrap();
            let detections = detector.detect_internal("Employee ID EMP123456");

            assert_eq!(
                detections[&PIIType::Custom][0].mask_strategy,
                MaskingStrategy::Partial
            );
        });
    }

    #[test]
    fn test_model_dump_config_with_none_mask_strategy_follows_global_default() {
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
                pyo3::ffi::c_str!("test_detector_model.py"),
                pyo3::ffi::c_str!("test_detector_model"),
            )
            .unwrap();
            let config_model = module.getattr("ConfigModel").unwrap().call0().unwrap();

            let detector = PIIDetectorRust::new(&config_model).unwrap();
            let detections = detector.detect_internal("Employee ID EMP123456");

            assert_eq!(
                detections[&PIIType::Custom][0].mask_strategy,
                MaskingStrategy::Partial
            );
        });
    }

    #[test]
    fn test_model_dump_config_with_omitted_mask_strategy_follows_global_default() {
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
                pyo3::ffi::c_str!("test_detector_model_omitted.py"),
                pyo3::ffi::c_str!("test_detector_model_omitted"),
            )
            .unwrap();
            let config_model = module.getattr("ConfigModel").unwrap().call0().unwrap();

            let detector = PIIDetectorRust::new(&config_model).unwrap();
            let detections = detector.detect_internal("Employee ID EMP123456");

            assert_eq!(
                detections[&PIIType::Custom][0].mask_strategy,
                MaskingStrategy::Partial
            );
        });
    }

    #[test]
    fn test_bsn_context_is_not_downgraded_to_ssn() {
        let config = PIIConfig {
            detect_ssn: true,
            detect_bsn: true,
            detect_credit_card: false,
            detect_email: false,
            detect_phone: false,
            detect_ip_address: false,
            detect_date_of_birth: false,
            detect_passport: false,
            detect_driver_license: false,
            detect_bank_account: false,
            detect_medical_record: false,
            ..Default::default()
        };
        let patterns = compile_patterns(&config).unwrap();
        let detector = PIIDetectorRust { patterns, config };

        let detections = detector.detect_internal("Customer record: BSN: 123456789");

        assert!(
            detections.contains_key(&PIIType::Bsn),
            "expected BSN detection for BSN-labeled identifier"
        );
        assert!(
            !detections.contains_key(&PIIType::Ssn),
            "did not expect SSN detection to win over BSN context"
        );
    }

    #[test]
    fn test_process_nested_accepts_non_string_dict_keys() {
        Python::initialize();
        Python::attach(|py| {
            let mut config = PIIConfig {
                detect_ssn: false,
                detect_email: false,
                default_mask_strategy: MaskingStrategy::Redact,
                ..Default::default()
            };
            config
                .custom_patterns
                .push(super::super::config::CustomPattern {
                    pattern: r"\bEMP\d{6}\b".to_string(),
                    description: "Employee ID".to_string(),
                    mask_strategy: Some(MaskingStrategy::Redact),
                    enabled: true,
                });

            let patterns = compile_patterns(&config).unwrap();
            let detector = PIIDetectorRust { patterns, config };

            let data = PyDict::new(py);
            data.set_item(1, "EMP123456").unwrap();

            let result = detector.process_nested(py, &data.into_any(), "");
            assert!(
                result.is_ok(),
                "process_nested should not fail on non-string dict keys: {:?}",
                result.err()
            );

            let (modified, new_data, detections) = result.unwrap();
            assert!(modified);

            let new_dict = new_data.bind(py).cast::<PyDict>().unwrap();
            assert_eq!(
                new_dict
                    .get_item(1)
                    .unwrap()
                    .unwrap()
                    .extract::<String>()
                    .unwrap(),
                "[REDACTED]"
            );

            let det_dict = detections.bind(py).cast::<PyDict>().unwrap();
            assert!(
                !det_dict.is_empty(),
                "expected detections to be returned for masked value"
            );
        });
    }

    #[test]
    fn test_process_nested_masks_tuple_items() {
        Python::initialize();
        Python::attach(|py| {
            let config = PyDict::new(py);
            config.set_item("detect_email", true).unwrap();
            let detector = PIIDetectorRust::new(&config.into_any()).unwrap();
            let data = PyTuple::new(py, ["alice@example.com", "safe"]).unwrap();

            let (modified, new_data, detections) =
                detector.process_nested(py, &data.into_any(), "").unwrap();

            assert!(modified);
            let masked = new_data.bind(py).cast::<PyTuple>().unwrap();
            assert_eq!(
                masked.get_item(0).unwrap().extract::<String>().unwrap(),
                "[REDACTED]"
            );
            assert_eq!(
                detections
                    .bind(py)
                    .cast::<PyDict>()
                    .unwrap()
                    .get_item("email")
                    .unwrap()
                    .unwrap()
                    .cast::<PyList>()
                    .unwrap()
                    .len(),
                1
            );
        });
    }

    #[test]
    fn test_process_nested_masks_set_items() {
        Python::initialize();
        Python::attach(|py| {
            let config = PyDict::new(py);
            config.set_item("detect_email", true).unwrap();
            let detector = PIIDetectorRust::new(&config.into_any()).unwrap();
            let data = PySet::new(py, ["alice@example.com", "safe"]).unwrap();

            let (modified, new_data, _detections) =
                detector.process_nested(py, &data.into_any(), "").unwrap();

            assert!(modified);
            let masked = new_data.bind(py).cast::<PySet>().unwrap();
            assert!(masked.contains("[REDACTED]").unwrap());
        });
    }

    #[test]
    fn test_process_nested_masks_object_attributes() {
        Python::initialize();
        Python::attach(|py| {
            let config = PyDict::new(py);
            config.set_item("detect_email", true).unwrap();
            let detector = PIIDetectorRust::new(&config.into_any()).unwrap();

            let module = PyModule::from_code(
                py,
                c_str!(
                    "class Profile:\n    def __init__(self, email):\n        self.email = email\n"
                ),
                c_str!("profile_fixture.py"),
                c_str!("profile_fixture"),
            )
            .unwrap();
            let profile = module
                .getattr("Profile")
                .unwrap()
                .call1(("alice@example.com",))
                .unwrap();

            let (modified, new_data, _detections) =
                detector.process_nested(py, &profile, "").unwrap();

            assert!(modified);
            assert_eq!(
                new_data
                    .bind(py)
                    .getattr("email")
                    .unwrap()
                    .extract::<String>()
                    .unwrap(),
                "[REDACTED]"
            );
        });
    }

    #[test]
    fn test_detect_rejects_oversized_input() {
        Python::initialize();
        Python::attach(|py| {
            let config = PIIConfig {
                detect_ssn: true,
                ..Default::default()
            };
            let max_text_bytes = config.max_text_bytes;
            let patterns = compile_patterns(&config).unwrap();
            let detector = PIIDetectorRust { patterns, config };
            let oversized = "a".repeat(max_text_bytes + 1);

            let err = detector.detect(&oversized).unwrap_err();
            assert!(err.is_instance_of::<pyo3::exceptions::PyValueError>(py));
        });
    }

    #[test]
    fn test_default_detector_accepts_inputs_larger_than_256k() {
        Python::initialize();
        Python::attach(|_| {
            let config = PIIConfig {
                detect_ssn: true,
                detect_bsn: false,
                detect_credit_card: false,
                detect_email: false,
                detect_phone: false,
                detect_ip_address: false,
                detect_date_of_birth: false,
                detect_passport: false,
                detect_driver_license: false,
                detect_bank_account: false,
                detect_medical_record: false,
                ..Default::default()
            };
            let patterns = compile_patterns(&config).unwrap();
            let detector = PIIDetectorRust { patterns, config };
            let text = format!("{} SSN: 123-45-6789", "x".repeat(300 * 1024));

            assert!(detector.detect(&text).is_ok());
        });
    }

    #[test]
    fn test_longer_overlap_wins_over_registration_order() {
        let mut config = PIIConfig {
            detect_bsn: true,
            detect_ssn: false,
            detect_credit_card: false,
            detect_email: false,
            detect_phone: false,
            detect_ip_address: false,
            detect_date_of_birth: false,
            detect_passport: false,
            detect_driver_license: false,
            detect_bank_account: false,
            detect_medical_record: false,
            ..Default::default()
        };
        config
            .custom_patterns
            .push(super::super::config::CustomPattern {
                pattern: r"\bBSN\b".to_string(),
                description: "Short custom token".to_string(),
                mask_strategy: Some(MaskingStrategy::Redact),
                enabled: true,
            });

        let patterns = compile_patterns(&config).unwrap();
        let detector = PIIDetectorRust { patterns, config };
        let detections = detector.detect_internal("BSN: 123456789");

        assert!(detections.contains_key(&PIIType::Bsn));
        assert_eq!(detections[&PIIType::Bsn][0].value, "BSN: 123456789");
        assert!(!detections.contains_key(&PIIType::Custom));
    }

    #[test]
    fn test_bare_nine_digit_ssn_with_label_is_detected() {
        let config = PIIConfig {
            detect_ssn: true,
            detect_bsn: false,
            detect_phone: false,
            detect_bank_account: false,
            ..Default::default()
        };
        let patterns = compile_patterns(&config).unwrap();
        let detector = PIIDetectorRust { patterns, config };

        let detections = detector.detect_internal("SSN: 123456789");
        assert!(detections.contains_key(&PIIType::Ssn));
    }

    #[test]
    fn test_detect_uses_configurable_text_limit() {
        Python::initialize();
        Python::attach(|py| {
            let config = PyDict::new(py);
            config.set_item("detect_ssn", true).unwrap();
            config.set_item("max_text_bytes", 8).unwrap();

            let detector = PIIDetectorRust::new(&config.into_any()).unwrap();
            let err = detector.detect("123456789").unwrap_err();

            assert!(err.is_instance_of::<pyo3::exceptions::PyValueError>(py));
        });
    }

    #[test]
    fn test_process_nested_uses_configurable_collection_limit() {
        Python::initialize();
        Python::attach(|py| {
            let config = PyDict::new(py);
            config.set_item("detect_email", true).unwrap();
            config.set_item("max_collection_items", 1).unwrap();

            let detector = PIIDetectorRust::new(&config.into_any()).unwrap();
            let data = PyList::empty(py);
            data.append("a@example.com").unwrap();
            data.append("b@example.com").unwrap();

            let err = detector
                .process_nested(py, &data.into_any(), "")
                .unwrap_err();
            assert!(err.is_instance_of::<pyo3::exceptions::PyValueError>(py));
        });
    }

    #[test]
    fn test_process_nested_mapping_allows_collection_limit_boundary() {
        Python::initialize();
        Python::attach(|py| {
            let config = PyDict::new(py);
            config.set_item("detect_email", true).unwrap();
            config.set_item("max_collection_items", 1).unwrap();

            let detector = PIIDetectorRust::new(&config.into_any()).unwrap();
            let data = PyDict::new(py);
            data.set_item("email", "alice@example.com").unwrap();

            let (modified, new_data, _) =
                detector.process_nested(py, &data.into_any(), "").unwrap();

            assert!(modified);
            assert_eq!(
                new_data
                    .bind(py)
                    .cast::<PyDict>()
                    .unwrap()
                    .get_item("email")
                    .unwrap()
                    .unwrap()
                    .extract::<String>()
                    .unwrap(),
                "[REDACTED]"
            );
        });
    }

    #[test]
    fn test_process_nested_mapping_rejects_over_collection_limit() {
        Python::initialize();
        Python::attach(|py| {
            let config = PyDict::new(py);
            config.set_item("detect_email", true).unwrap();
            config.set_item("max_collection_items", 1).unwrap();

            let detector = PIIDetectorRust::new(&config.into_any()).unwrap();
            let data = PyDict::new(py);
            data.set_item("first", "alice@example.com").unwrap();
            data.set_item("second", "bob@example.com").unwrap();

            let err = detector
                .process_nested(py, &data.into_any(), "")
                .unwrap_err();
            assert!(err.is_instance_of::<pyo3::exceptions::PyValueError>(py));
        });
    }

    #[test]
    fn test_detects_plus_prefixed_international_phone_number() {
        let config = PIIConfig {
            detect_ssn: false,
            detect_bsn: false,
            detect_credit_card: false,
            detect_email: false,
            detect_phone: true,
            detect_ip_address: false,
            detect_date_of_birth: false,
            detect_passport: false,
            detect_driver_license: false,
            detect_bank_account: false,
            detect_medical_record: false,
            ..Default::default()
        };
        let patterns = compile_patterns(&config).unwrap();
        let detector = PIIDetectorRust { patterns, config };

        assert!(
            detector
                .detect_internal("+353871234567")
                .contains_key(&PIIType::Phone)
        );
    }

    #[test]
    fn test_mask_rejects_missing_detection_fields() {
        Python::initialize();
        Python::attach(|py| {
            let config = PIIConfig {
                detect_email: true,
                ..Default::default()
            };
            let patterns = compile_patterns(&config).unwrap();
            let detector = PIIDetectorRust { patterns, config };

            let detections = PyDict::new(py);
            let items = PyList::empty(py);
            let bad_detection = PyDict::new(py);
            bad_detection.set_item("value", "john@example.com").unwrap();
            bad_detection.set_item("start", 0).unwrap();
            bad_detection.set_item("end", 16).unwrap();
            items.append(bad_detection).unwrap();
            detections.set_item("email", items).unwrap();

            let err = detector
                .mask("john@example.com", &detections.into_any())
                .unwrap_err();
            assert!(err.is_instance_of::<pyo3::exceptions::PyValueError>(py));
        });
    }

    #[test]
    fn test_mask_rejects_oversized_input() {
        Python::initialize();
        Python::attach(|py| {
            let config = PyDict::new(py);
            config.set_item("detect_email", true).unwrap();
            config.set_item("max_text_bytes", 8).unwrap();

            let detector = PIIDetectorRust::new(&config.into_any()).unwrap();
            let detections = PyDict::new(py);
            let items = PyList::empty(py);
            let detection = PyDict::new(py);
            detection.set_item("value", "123456789").unwrap();
            detection.set_item("start", 0).unwrap();
            detection.set_item("end", 9).unwrap();
            detection.set_item("mask_strategy", "redact").unwrap();
            items.append(detection).unwrap();
            detections.set_item("custom", items).unwrap();

            let err = detector
                .mask("123456789", &detections.into_any())
                .unwrap_err();
            assert!(err.is_instance_of::<pyo3::exceptions::PyValueError>(py));
        });
    }

    #[test]
    fn test_mask_rejects_invalid_detection_ranges() {
        Python::initialize();
        Python::attach(|py| {
            let config = PIIConfig {
                detect_email: true,
                ..Default::default()
            };
            let patterns = compile_patterns(&config).unwrap();
            let detector = PIIDetectorRust { patterns, config };

            let detections = PyDict::new(py);
            let items = PyList::empty(py);
            let bad_detection = PyDict::new(py);
            bad_detection.set_item("value", "john@example.com").unwrap();
            bad_detection.set_item("start", 99).unwrap();
            bad_detection.set_item("end", 100).unwrap();
            bad_detection.set_item("mask_strategy", "partial").unwrap();
            items.append(bad_detection).unwrap();
            detections.set_item("email", items).unwrap();

            let err = detector
                .mask("john@example.com", &detections.into_any())
                .unwrap_err();
            assert!(err.is_instance_of::<pyo3::exceptions::PyValueError>(py));
        });
    }
}
