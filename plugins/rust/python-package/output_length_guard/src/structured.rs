// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
//
// Structured data processing for output length guard

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

use crate::config::{OutputLengthGuardConfig, Strategy};
use crate::guards::{evaluate_text_limits, is_numeric_string, truncate};

/// Result of processing a structured value.
pub enum ProcessResult {
    /// No violation, data optionally modified.
    Ok { value: Py<PyAny>, modified: bool },
    /// A policy violation was detected.
    Violation {
        reason: String,
        description: String,
        code: String,
        details: Vec<(String, serde_json::Value)>,
    },
}

/// Recursively process structured data, applying length guard.
/// Mirrors Python _process_structured_data().
pub fn process_structured_data(
    py: Python<'_>,
    data: &Bound<'_, PyAny>,
    cfg: &OutputLengthGuardConfig,
    path: &str,
    depth: usize,
) -> PyResult<ProcessResult> {
    // Security: Check recursion depth
    if depth > cfg.max_recursion_depth {
        log::error!(
            "Recursion depth {} exceeds maximum {} at path: {}",
            depth,
            cfg.max_recursion_depth,
            path
        );
        if cfg.strategy == Strategy::Block {
            return Ok(ProcessResult::Violation {
                reason: "Recursion depth exceeds security limit".to_string(),
                description: format!(
                    "Nesting depth {} exceeds limit of {}",
                    depth, cfg.max_recursion_depth
                ),
                code: "STRUCTURE_DEPTH_VIOLATION".to_string(),
                details: vec![
                    ("depth".to_string(), serde_json::json!(depth)),
                    (
                        "max_depth".to_string(),
                        serde_json::json!(cfg.max_recursion_depth),
                    ),
                    (
                        "location".to_string(),
                        serde_json::json!(if path.is_empty() { "root" } else { path }),
                    ),
                ],
            });
        }
        return Ok(ProcessResult::Ok {
            value: data.clone().unbind(),
            modified: false,
        });
    }

    // Base case: string
    if let Ok(text) = data.extract::<String>() {
        return process_string(py, &text, cfg, path);
    }

    // Recursive case: list
    if let Ok(list) = data.cast::<PyList>() {
        return process_list(py, list, cfg, path, depth);
    }

    // Recursive case: dict
    if let Ok(dict) = data.cast::<PyDict>() {
        return process_dict(py, dict, cfg, path, depth);
    }

    // Other types (int, bool, None, etc.) — pass through
    Ok(ProcessResult::Ok {
        value: data.clone().unbind(),
        modified: false,
    })
}

fn process_string(
    py: Python<'_>,
    text: &str,
    cfg: &OutputLengthGuardConfig,
    path: &str,
) -> PyResult<ProcessResult> {
    if is_numeric_string(text) {
        return Ok(ProcessResult::Ok {
            value: text.into_pyobject(py)?.into_any().unbind(),
            modified: false,
        });
    }

    let length = text.len();
    let token_count = length / cfg.chars_per_token.max(1);
    let (below_min, above_max) = evaluate_text_limits(length, token_count, cfg);

    if !below_min && !above_max {
        return Ok(ProcessResult::Ok {
            value: text.into_pyobject(py)?.into_any().unbind(),
            modified: false,
        });
    }

    let location = if path.is_empty() { "root" } else { path };

    if cfg.strategy == Strategy::Block {
        let violation = if above_max && cfg.limit_mode == crate::config::LimitMode::Token {
            ProcessResult::Violation {
                reason: format!("Estimated token count out of bounds at {}", location),
                description: format!(
                    "Estimated token count {} exceeds max_tokens {} at {}",
                    token_count,
                    cfg.max_tokens.unwrap_or(0),
                    location
                ),
                code: "OUTPUT_TOKEN_VIOLATION".to_string(),
                details: vec![
                    ("token_count".to_string(), serde_json::json!(token_count)),
                    ("max_tokens".to_string(), serde_json::json!(cfg.max_tokens)),
                    (
                        "chars_per_token".to_string(),
                        serde_json::json!(cfg.chars_per_token),
                    ),
                    (
                        "strategy".to_string(),
                        serde_json::json!(cfg.strategy.as_str()),
                    ),
                    ("location".to_string(), serde_json::json!(location)),
                ],
            }
        } else if above_max {
            ProcessResult::Violation {
                reason: format!("String length out of bounds at {}", location),
                description: format!(
                    "String length {} exceeds max_chars {} at {}",
                    length,
                    cfg.max_chars.unwrap_or(0),
                    location
                ),
                code: "OUTPUT_LENGTH_VIOLATION".to_string(),
                details: vec![
                    ("length".to_string(), serde_json::json!(length)),
                    ("max_chars".to_string(), serde_json::json!(cfg.max_chars)),
                    (
                        "strategy".to_string(),
                        serde_json::json!(cfg.strategy.as_str()),
                    ),
                    ("location".to_string(), serde_json::json!(location)),
                ],
            }
        } else {
            // below_min
            ProcessResult::Violation {
                reason: format!("String length/tokens below minimum at {}", location),
                description: format!(
                    "String length {} or tokens {} below minimum at {}",
                    length, token_count, location
                ),
                code: "OUTPUT_LENGTH_VIOLATION".to_string(),
                details: vec![
                    ("length".to_string(), serde_json::json!(length)),
                    ("min_chars".to_string(), serde_json::json!(cfg.min_chars)),
                    ("token_count".to_string(), serde_json::json!(token_count)),
                    ("min_tokens".to_string(), serde_json::json!(cfg.min_tokens)),
                    ("location".to_string(), serde_json::json!(location)),
                ],
            }
        };
        return Ok(violation);
    }

    // Truncate mode: only truncate if above_max
    if above_max {
        let truncated = truncate(text, cfg);
        let modified = truncated != text;
        let value = truncated.into_pyobject(py)?.into_any().unbind();
        return Ok(ProcessResult::Ok { value, modified });
    }

    // Below min in truncate mode — allow through unchanged
    Ok(ProcessResult::Ok {
        value: text.into_pyobject(py)?.into_any().unbind(),
        modified: false,
    })
}

fn process_list(
    py: Python<'_>,
    list: &Bound<'_, PyList>,
    cfg: &OutputLengthGuardConfig,
    path: &str,
    depth: usize,
) -> PyResult<ProcessResult> {
    if list.len() > cfg.max_structure_size {
        log::error!(
            "List size {} exceeds maximum {} at path: {}",
            list.len(),
            cfg.max_structure_size,
            path
        );
        if cfg.strategy == Strategy::Block {
            return Ok(ProcessResult::Violation {
                reason: "Structure size exceeds security limit".to_string(),
                description: format!(
                    "List has {} items, exceeding limit of {}",
                    list.len(),
                    cfg.max_structure_size
                ),
                code: "STRUCTURE_SIZE_VIOLATION".to_string(),
                details: vec![
                    ("size".to_string(), serde_json::json!(list.len())),
                    (
                        "max_size".to_string(),
                        serde_json::json!(cfg.max_structure_size),
                    ),
                    (
                        "location".to_string(),
                        serde_json::json!(if path.is_empty() { "root" } else { path }),
                    ),
                ],
            });
        }
        return Ok(ProcessResult::Ok {
            value: list.clone().into_any().unbind(),
            modified: false,
        });
    }

    let mut modified = false;
    let out_list = PyList::empty(py);

    for (idx, item) in list.iter().enumerate() {
        let item_path = if path.is_empty() {
            format!("[{}]", idx)
        } else {
            format!("{}[{}]", path, idx)
        };

        match process_structured_data(py, &item, cfg, &item_path, depth + 1)? {
            v @ ProcessResult::Violation { .. } => return Ok(v),
            ProcessResult::Ok {
                value,
                modified: item_modified,
            } => {
                out_list.append(value.bind(py))?;
                if item_modified {
                    modified = true;
                }
            }
        }
    }

    Ok(ProcessResult::Ok {
        value: out_list.into_any().unbind(),
        modified,
    })
}

fn process_dict(
    py: Python<'_>,
    dict: &Bound<'_, PyDict>,
    cfg: &OutputLengthGuardConfig,
    path: &str,
    depth: usize,
) -> PyResult<ProcessResult> {
    if dict.len() > cfg.max_structure_size {
        log::error!(
            "Dict size {} exceeds maximum {} at path: {}",
            dict.len(),
            cfg.max_structure_size,
            path
        );
        if cfg.strategy == Strategy::Block {
            return Ok(ProcessResult::Violation {
                reason: "Structure size exceeds security limit".to_string(),
                description: format!(
                    "Dict has {} items, exceeding limit of {}",
                    dict.len(),
                    cfg.max_structure_size
                ),
                code: "STRUCTURE_SIZE_VIOLATION".to_string(),
                details: vec![
                    ("size".to_string(), serde_json::json!(dict.len())),
                    (
                        "max_size".to_string(),
                        serde_json::json!(cfg.max_structure_size),
                    ),
                    (
                        "location".to_string(),
                        serde_json::json!(if path.is_empty() { "root" } else { path }),
                    ),
                ],
            });
        }
        return Ok(ProcessResult::Ok {
            value: dict.clone().into_any().unbind(),
            modified: false,
        });
    }

    let mut modified = false;
    let out_dict = PyDict::new(py);

    for (key, value) in dict.iter() {
        let key_str = key.extract::<String>().unwrap_or_default();
        let value_path = if path.is_empty() {
            key_str.clone()
        } else {
            format!("{}.{}", path, key_str)
        };

        match process_structured_data(py, &value, cfg, &value_path, depth + 1)? {
            v @ ProcessResult::Violation { .. } => return Ok(v),
            ProcessResult::Ok {
                value: new_val,
                modified: val_modified,
            } => {
                out_dict.set_item(&key, new_val.bind(py))?;
                if val_modified {
                    modified = true;
                }
            }
        }
    }

    Ok(ProcessResult::Ok {
        value: out_dict.into_any().unbind(),
        modified,
    })
}

/// Generate a text representation of structured data.
/// Mirrors Python _generate_text_representation().
pub fn generate_text_representation(data: &Bound<'_, PyAny>, depth: usize) -> PyResult<String> {
    if let Ok(s) = data.extract::<String>() {
        return Ok(s);
    }

    // Single-key dict unwrapping with depth limit
    if let Ok(dict) = data.cast::<PyDict>() {
        if dict.len() == 1
            && depth < 10
            && let Some((_, val)) = dict.iter().next()
        {
            return generate_text_representation(&val, depth + 1);
        }
        // Multi-key dict or depth limit reached
        let json_module = pyo3::Python::attach(|_py| {
            // We already have access to py via data's GIL
            Ok::<_, PyErr>(())
        });
        let _ = json_module;
        return json_dumps(data);
    }

    if let Ok(list) = data.cast::<PyList>() {
        let _ = list;
        return json_dumps(data);
    }

    // Fallback to repr()
    Ok(data.repr()?.to_string())
}

fn json_dumps(data: &Bound<'_, PyAny>) -> PyResult<String> {
    let py = data.py();
    let json_module = pyo3::types::PyModule::import(py, "json")?;
    let result = json_module.getattr("dumps")?.call(
        (data,),
        Some(&{
            let kw = PyDict::new(py);
            kw.set_item("ensure_ascii", false)?;
            kw.set_item("separators", (",", ":"))?;
            kw
        }),
    )?;
    result.extract::<String>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{LimitMode, OutputLengthGuardConfig, Strategy};
    use pyo3::types::{PyDict, PyList};

    fn block_char_cfg(max_chars: usize) -> OutputLengthGuardConfig {
        OutputLengthGuardConfig {
            max_chars: Some(max_chars),
            limit_mode: LimitMode::Character,
            strategy: Strategy::Block,
            ellipsis: "…".to_string(),
            ..Default::default()
        }
    }

    fn truncate_char_cfg(max_chars: usize) -> OutputLengthGuardConfig {
        OutputLengthGuardConfig {
            max_chars: Some(max_chars),
            limit_mode: LimitMode::Character,
            strategy: Strategy::Truncate,
            ellipsis: "…".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn process_string_within_limit_unchanged() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            let cfg = truncate_char_cfg(100);
            let s = "hello world".into_pyobject(py).unwrap().into_any();
            match process_structured_data(py, &s, &cfg, "", 0).unwrap() {
                ProcessResult::Ok { modified, value } => {
                    assert!(!modified);
                    assert_eq!(value.bind(py).extract::<String>().unwrap(), "hello world");
                }
                ProcessResult::Violation { .. } => panic!("unexpected violation"),
            }
        });
    }

    #[test]
    fn process_string_truncates_when_over_limit() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            let cfg = truncate_char_cfg(5);
            let s = "hello world".into_pyobject(py).unwrap().into_any();
            match process_structured_data(py, &s, &cfg, "", 0).unwrap() {
                ProcessResult::Ok { modified, value } => {
                    assert!(modified);
                    let result = value.bind(py).extract::<String>().unwrap();
                    assert!(result.chars().count() <= 5);
                }
                ProcessResult::Violation { .. } => panic!("unexpected violation"),
            }
        });
    }

    #[test]
    fn process_string_blocks_when_over_limit_in_block_mode() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            let cfg = block_char_cfg(5);
            let s = "hello world".into_pyobject(py).unwrap().into_any();
            match process_structured_data(py, &s, &cfg, "", 0).unwrap() {
                ProcessResult::Violation { code, .. } => {
                    assert_eq!(code, "OUTPUT_LENGTH_VIOLATION");
                }
                ProcessResult::Ok { .. } => panic!("expected violation"),
            }
        });
    }

    #[test]
    fn process_string_skips_numeric_strings() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            let cfg = block_char_cfg(3); // "123" is 3 chars, would pass but it's numeric
            let s = "123".into_pyobject(py).unwrap().into_any();
            match process_structured_data(py, &s, &cfg, "", 0).unwrap() {
                ProcessResult::Ok { modified, .. } => assert!(!modified),
                ProcessResult::Violation { .. } => panic!("numeric string should pass through"),
            }
        });
    }

    #[test]
    fn process_list_processes_each_element() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            let cfg = truncate_char_cfg(5);
            let list = PyList::new(py, ["hello world", "short"]).unwrap();
            match process_structured_data(py, list.as_any(), &cfg, "", 0).unwrap() {
                ProcessResult::Ok { modified, value } => {
                    assert!(modified);
                    let out: Vec<String> = value
                        .bind(py)
                        .cast::<PyList>()
                        .unwrap()
                        .iter()
                        .map(|i| i.extract().unwrap())
                        .collect();
                    assert!(out[0].chars().count() <= 5);
                    assert_eq!(out[1], "short");
                }
                ProcessResult::Violation { .. } => panic!("unexpected violation"),
            }
        });
    }

    #[test]
    fn process_list_blocks_on_violation() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            let cfg = block_char_cfg(3);
            let list = PyList::new(py, ["hi", "hello world"]).unwrap();
            match process_structured_data(py, list.as_any(), &cfg, "", 0).unwrap() {
                ProcessResult::Violation { code, .. } => {
                    assert_eq!(code, "OUTPUT_LENGTH_VIOLATION");
                }
                ProcessResult::Ok { .. } => panic!("expected violation"),
            }
        });
    }

    #[test]
    fn process_list_rejects_oversized_list_in_block_mode() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            let mut cfg = truncate_char_cfg(1000);
            cfg.max_structure_size = 2;
            cfg.strategy = Strategy::Block;
            let list = PyList::new(py, ["a", "b", "c"]).unwrap();
            match process_structured_data(py, list.as_any(), &cfg, "", 0).unwrap() {
                ProcessResult::Violation { code, .. } => {
                    assert_eq!(code, "STRUCTURE_SIZE_VIOLATION");
                }
                ProcessResult::Ok { .. } => panic!("expected violation"),
            }
        });
    }

    #[test]
    fn process_dict_processes_text_values() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            let cfg = truncate_char_cfg(5);
            let d = PyDict::new(py);
            d.set_item("key", "hello world").unwrap();
            match process_structured_data(py, d.as_any(), &cfg, "", 0).unwrap() {
                ProcessResult::Ok { modified, value } => {
                    assert!(modified);
                    let out = value.bind(py).cast::<PyDict>().unwrap();
                    let v: String = out.get_item("key").unwrap().unwrap().extract().unwrap();
                    assert!(v.chars().count() <= 5);
                }
                ProcessResult::Violation { .. } => panic!("unexpected violation"),
            }
        });
    }

    #[test]
    fn process_dict_rejects_oversized_dict_in_block_mode() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            let mut cfg = truncate_char_cfg(1000);
            cfg.max_structure_size = 1;
            cfg.strategy = Strategy::Block;
            let d = PyDict::new(py);
            d.set_item("a", "v1").unwrap();
            d.set_item("b", "v2").unwrap();
            match process_structured_data(py, d.as_any(), &cfg, "", 0).unwrap() {
                ProcessResult::Violation { code, .. } => {
                    assert_eq!(code, "STRUCTURE_SIZE_VIOLATION");
                }
                ProcessResult::Ok { .. } => panic!("expected violation"),
            }
        });
    }

    #[test]
    fn process_depth_exceeded_blocks_in_block_mode() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            let mut cfg = truncate_char_cfg(1000);
            cfg.max_recursion_depth = 0;
            cfg.strategy = Strategy::Block;
            let d = PyDict::new(py);
            d.set_item("x", "value").unwrap();
            match process_structured_data(py, d.as_any(), &cfg, "", 1).unwrap() {
                ProcessResult::Violation { code, .. } => {
                    assert_eq!(code, "STRUCTURE_DEPTH_VIOLATION");
                }
                ProcessResult::Ok { .. } => panic!("expected violation"),
            }
        });
    }

    #[test]
    fn integers_pass_through_unchanged() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            let cfg = block_char_cfg(1);
            let n = 42_i64.into_pyobject(py).unwrap().into_any();
            match process_structured_data(py, &n, &cfg, "", 0).unwrap() {
                ProcessResult::Ok { modified, .. } => assert!(!modified),
                ProcessResult::Violation { .. } => panic!("int should pass through"),
            }
        });
    }
}
