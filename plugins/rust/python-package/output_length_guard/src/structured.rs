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

    // Use char count (not byte length) so that max_chars is enforced in Unicode
    // codepoints, matching Python's len(str) semantics. Byte length is only used
    // for token estimation, which mirrors Python's len(text) // chars_per_token.
    let char_count = text.chars().count();
    let token_count = text.len() / cfg.chars_per_token.max(1);
    let (below_min, above_max) = evaluate_text_limits(char_count, token_count, cfg);

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
                    char_count,
                    cfg.max_chars.unwrap_or(0),
                    location
                ),
                code: "OUTPUT_LENGTH_VIOLATION".to_string(),
                details: vec![
                    ("length".to_string(), serde_json::json!(char_count)),
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
                    char_count, token_count, location
                ),
                code: "OUTPUT_LENGTH_VIOLATION".to_string(),
                details: vec![
                    ("length".to_string(), serde_json::json!(char_count)),
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
        return json_dumps(data);
    }

    if data.cast::<PyList>().is_ok() {
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

    // ── recursion depth boundary ──────────────────────────────────────────
    // Kill: replace > with >= (depth == max_recursion_depth must NOT fire)
    #[test]
    fn process_depth_at_exactly_limit_does_not_block() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            let mut cfg = truncate_char_cfg(1000);
            cfg.max_recursion_depth = 5;
            cfg.strategy = Strategy::Block;
            // Pass a plain string (not a dict/list) so no recursive calls are made.
            // At depth=5, max=5: 5 > 5 is false → must NOT violate.
            let s = "hello".into_pyobject(py).unwrap().into_any();
            match process_structured_data(py, &s, &cfg, "", 5).unwrap() {
                ProcessResult::Ok { .. } => {}
                ProcessResult::Violation { code, .. } => {
                    panic!("depth == limit must not block, got code={}", code)
                }
            }
        });
    }

    // ── process_string token calculation ─────────────────────────────────
    // Kill: replace / with % or * in token_count calculation (line 105)
    #[test]
    fn process_string_token_mode_truncates_by_estimated_tokens() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            let mut cfg = OutputLengthGuardConfig {
                max_tokens: Some(2),
                limit_mode: LimitMode::Token,
                strategy: Strategy::Block,
                chars_per_token: 4,
                ellipsis: "…".to_string(),
                ..Default::default()
            };
            cfg.max_chars = None;
            // "abcdefghijklmno" = 15 chars → estimated tokens = 15/4 = 3 > 2 → violation
            let s = "abcdefghijklmno".into_pyobject(py).unwrap().into_any();
            match process_structured_data(py, &s, &cfg, "", 0).unwrap() {
                ProcessResult::Violation { code, .. } => assert_eq!(code, "OUTPUT_TOKEN_VIOLATION"),
                ProcessResult::Ok { .. } => panic!("expected token violation"),
            }
        });
    }

    // Kill: replace / with % in token_count = length / cpt.
    // length=9, cpt=4, max_tokens=1:
    //   / → 9/4=2 > 1 → violation ✓
    //   % → 9%4=1 > 1 → false → no violation ✗ (mutant survives without this test)
    #[test]
    fn process_string_token_mode_modulo_mutant_is_killed() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            let cfg = OutputLengthGuardConfig {
                max_tokens: Some(1),
                limit_mode: LimitMode::Token,
                strategy: Strategy::Block,
                chars_per_token: 4,
                max_chars: None,
                ellipsis: "…".to_string(),
                ..Default::default()
            };
            // length=9: 9/4=2 > 1 → violation; 9%4=1 is not > 1 → would pass through
            let s = "abcdefghi".into_pyobject(py).unwrap().into_any(); // 9 chars
            match process_structured_data(py, &s, &cfg, "", 0).unwrap() {
                ProcessResult::Violation { code, .. } => {
                    assert_eq!(
                        code, "OUTPUT_TOKEN_VIOLATION",
                        "9/4=2 > max_tokens=1 must violate"
                    )
                }
                ProcessResult::Ok { .. } => {
                    panic!(
                        "expected token violation: 9/4=2 > max_tokens=1; % mutant gives 9%4=1 which would pass"
                    )
                }
            }
        });
    }

    // Kill: replace / with * in token_count = length / cpt.
    // length=4, cpt=4, max_tokens=1:
    //   / → 4/4=1 > 1 → false → no violation ✓
    //   * → 4*4=16 > 1 → violation ✗ (mutant would block)
    #[test]
    fn process_string_token_mode_multiply_mutant_is_killed() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            let cfg = OutputLengthGuardConfig {
                max_tokens: Some(1),
                limit_mode: LimitMode::Token,
                strategy: Strategy::Block,
                chars_per_token: 4,
                max_chars: None,
                ellipsis: "…".to_string(),
                ..Default::default()
            };
            // length=4: 4/4=1, NOT > 1 → no violation; 4*4=16 > 1 → would block
            let s = "abcd".into_pyobject(py).unwrap().into_any(); // exactly 1 token
            match process_structured_data(py, &s, &cfg, "", 0).unwrap() {
                ProcessResult::Ok { modified, .. } => {
                    assert!(
                        !modified,
                        "4 chars = 1 token = max_tokens: must not block or modify"
                    );
                }
                ProcessResult::Violation { .. } => {
                    panic!("4/4=1 is not > max_tokens=1; * mutant gives 4*4=16 which would block");
                }
            }
        });
    }

    // Kill: delete ! in `if !below_min && !above_max` (line 108)
    #[test]
    fn process_string_within_both_limits_passes_through_unmodified() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            let mut cfg = truncate_char_cfg(100);
            cfg.min_chars = 2;
            // "hello" = 5 chars, between min=2 and max=100 → must pass through unchanged
            let s = "hello".into_pyobject(py).unwrap().into_any();
            match process_structured_data(py, &s, &cfg, "", 0).unwrap() {
                ProcessResult::Ok { modified, value } => {
                    assert!(!modified);
                    assert_eq!(value.bind(py).extract::<String>().unwrap(), "hello");
                }
                ProcessResult::Violation { .. } => panic!("string within bounds must not violate"),
            }
        });
    }

    // ── list/dict size boundary (> vs >=) ────────────────────────────────
    // Kill: replace > with >= in process_list size check (line 205)
    #[test]
    fn process_list_at_exactly_max_structure_size_is_not_oversized() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            let mut cfg = truncate_char_cfg(1000);
            cfg.max_structure_size = 3;
            cfg.strategy = Strategy::Block;
            // Exactly 3 items == max_structure_size: must NOT trigger violation
            let list = PyList::new(py, ["a", "b", "c"]).unwrap();
            match process_structured_data(py, list.as_any(), &cfg, "", 0).unwrap() {
                ProcessResult::Ok { .. } => {}
                ProcessResult::Violation { code, .. } => {
                    panic!("list.len() == max must not block, got code={}", code)
                }
            }
        });
    }

    // Kill: replace > with >= in process_dict size check (line 277)
    #[test]
    fn process_dict_at_exactly_max_structure_size_is_not_oversized() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            let mut cfg = truncate_char_cfg(1000);
            cfg.max_structure_size = 2;
            cfg.strategy = Strategy::Block;
            let d = PyDict::new(py);
            d.set_item("a", "v1").unwrap();
            d.set_item("b", "v2").unwrap();
            // Exactly 2 keys == max_structure_size: must NOT trigger violation
            match process_structured_data(py, d.as_any(), &cfg, "", 0).unwrap() {
                ProcessResult::Ok { .. } => {}
                ProcessResult::Violation { code, .. } => {
                    panic!("dict.len() == max must not block, got code={}", code)
                }
            }
        });
    }

    // ── list/dict depth increments (+ 1 vs * 1 mutation) ─────────────────
    // Kill: replace + with * in `depth + 1` recursive calls (lines 250, 323)
    #[test]
    fn process_list_recurses_correctly_into_nested_string() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            let cfg = block_char_cfg(3);
            // Nested: list containing a string that exceeds the limit
            let list = PyList::new(py, ["toolongstring"]).unwrap();
            match process_structured_data(py, list.as_any(), &cfg, "", 0).unwrap() {
                ProcessResult::Violation { code, .. } => {
                    assert_eq!(code, "OUTPUT_LENGTH_VIOLATION")
                }
                ProcessResult::Ok { .. } => panic!("expected violation from nested string"),
            }
        });
    }

    #[test]
    fn process_dict_recurses_correctly_into_nested_string() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            let cfg = block_char_cfg(3);
            let d = PyDict::new(py);
            d.set_item("k", "toolongstring").unwrap();
            match process_structured_data(py, d.as_any(), &cfg, "", 0).unwrap() {
                ProcessResult::Violation { code, .. } => {
                    assert_eq!(code, "OUTPUT_LENGTH_VIOLATION")
                }
                ProcessResult::Ok { .. } => panic!("expected violation from nested string"),
            }
        });
    }

    // ── generate_text_representation ─────────────────────────────────────
    // Kill: replace == with != in `if dict.len() == 1` (line 352)
    #[test]
    fn generate_text_representation_single_key_dict_unwraps_value() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            let d = PyDict::new(py);
            d.set_item("key", "hello").unwrap();
            let result = generate_text_representation(d.as_any(), 0).unwrap();
            assert_eq!(result, "hello");
        });
    }

    // Kill: replace == with != (multi-key dict must NOT unwrap)
    #[test]
    fn generate_text_representation_multi_key_dict_json_serialises() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            let d = PyDict::new(py);
            d.set_item("a", "v1").unwrap();
            d.set_item("b", "v2").unwrap();
            let result = generate_text_representation(d.as_any(), 0).unwrap();
            // Multi-key: serialised as JSON, not unwrapped
            assert!(result.contains("v1") && result.contains("v2"));
        });
    }

    // Kill: replace < with == / > / <= in `depth < 10` unwrap guard (line 353)
    #[test]
    fn generate_text_representation_stops_unwrapping_at_depth_10() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            // At depth=10, a single-key dict must NOT be unwrapped (depth < 10 is false)
            let d = PyDict::new(py);
            d.set_item("key", "hello").unwrap();
            let result = generate_text_representation(d.as_any(), 10).unwrap();
            // Must be JSON, not the raw "hello" string
            assert!(result.contains("key") || result.contains("hello"));
            // More importantly: it must NOT equal the bare unwrapped value when depth==10
            assert_ne!(result, "hello", "must not unwrap at depth==10");
        });
    }

    // Kill: replace + with - in `depth + 1` recursive call (line 356)
    #[test]
    fn generate_text_representation_depth_9_still_unwraps() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            // At depth=9, unwrapping is still allowed (9 < 10)
            let d = PyDict::new(py);
            d.set_item("k", "leaf").unwrap();
            let result = generate_text_representation(d.as_any(), 9).unwrap();
            assert_eq!(result, "leaf");
        });
    }

    // ── process_list depth+1 vs depth*1 (structured.rs:250) ─────────────────
    // Kill: replace + with * in `depth + 1` inside process_list recursive call.
    // With depth*1, the depth never increments, so max_recursion_depth is never reached.
    // Strategy: set max_recursion_depth=1, build list-inside-list (depth 0 → 1 → must hit 2).
    // With correct depth+1: outer call at depth=0, list processes items at depth=1.
    //   Items at depth=1 are strings → process_string at depth=1. But depth check is
    //   `if depth > max_recursion_depth` at the TOP of process_structured_data.
    //   depth=1 > max=1 → false (doesn't fire). We need depth=2 to trigger.
    // Use max_recursion_depth=1, and a list containing another list containing a string.
    // Outer list: depth=0 → items processed at depth=1.
    // Inner list: depth=1 → items processed at depth=2. depth=2 > max=1 → fires!
    // With depth*1: items always processed at depth=0 (or depth*1=depth=0 since initial depth=0).
    //   Actually depth*1 = depth. So if initial depth=0: 0*1=0, never increments.
    //   Items in inner list would be processed at depth=0, so no depth violation.
    #[test]
    fn process_list_depth_increments_catch_deeply_nested_list() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            let mut cfg = block_char_cfg(10000); // no char limit
            cfg.max_recursion_depth = 1;
            // Build: [["short_string"]] — depth 0 → list → depth 1 → list → depth 2 > 1 → violation
            let inner_list = PyList::new(py, ["short_string"]).unwrap();
            let outer_list = PyList::new(py, [inner_list]).unwrap();
            // With correct depth+1: outer processes items at depth=1; inner list at depth=1
            // processes strings at depth=2; depth=2 > max=1 → STRUCTURE_DEPTH_VIOLATION.
            // With depth*1 (depth never increments): always at depth=0, never fires.
            match process_structured_data(py, outer_list.as_any(), &cfg, "", 0).unwrap() {
                ProcessResult::Violation { code, .. } => {
                    assert_eq!(
                        code, "STRUCTURE_DEPTH_VIOLATION",
                        "expected depth violation from nested list, got: {}",
                        code
                    );
                }
                ProcessResult::Ok { .. } => {
                    panic!("nested list beyond max_recursion_depth must produce a depth violation")
                }
            }
        });
    }

    // ── process_dict depth+1 vs depth*1 (structured.rs:323) ─────────────────
    // Same as above but using nested dicts.
    #[test]
    fn process_dict_depth_increments_catch_deeply_nested_dict() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            let mut cfg = block_char_cfg(10000);
            cfg.max_recursion_depth = 1;
            // Build: {"outer": {"inner": "value"}} — depth 0 → dict → depth 1 → dict → depth 2 > 1 → violation
            let inner_dict = PyDict::new(py);
            inner_dict.set_item("inner", "value").unwrap();
            let outer_dict = PyDict::new(py);
            outer_dict.set_item("outer", inner_dict).unwrap();
            match process_structured_data(py, outer_dict.as_any(), &cfg, "", 0).unwrap() {
                ProcessResult::Violation { code, .. } => {
                    assert_eq!(
                        code, "STRUCTURE_DEPTH_VIOLATION",
                        "expected depth violation from nested dict, got: {}",
                        code
                    );
                }
                ProcessResult::Ok { .. } => {
                    panic!("nested dict beyond max_recursion_depth must produce a depth violation")
                }
            }
        });
    }

    // ── generate_text_representation depth+1 vs depth*1 (structured.rs:356) ──
    // Kill: replace + with * in the recursive `generate_text_representation(&val, depth + 1)`.
    // With depth*1: depth = 0 always (since 0*1=0). A chain of 11 single-key dicts would
    // never hit the depth<10 limit → infinite recursion or incorrect result.
    // We verify correct behaviour by using exactly 11 levels of nesting:
    //   d1 = {"k": d2}, d2 = {"k": d3}, ..., d10 = {"k": d11}, d11 = {"k": "leaf"}
    // With correct depth+1: unwrapping stops at depth=10 → json_dumps → contains "k"/"leaf".
    // With depth*1: never increments, so all 11 levels are traversed → returns "leaf".
    // BUT we verify from depth=0 that the FIRST single-key dict IS unwrapped (depth=0 < 10).
    // What matters is what happens at depth=10 inside the chain. The test at depth=10 already
    // covers that. For the +1 vs *1 mutation we need the RECURSIVE call to hit the limit.
    // Test: build chain of 10 nested dicts (depth 0-9 each unwrap), leaf at d10.
    // With +1: d0 calls d1 at depth=1, d1 calls d2 at depth=2, ..., d9 calls d10 at depth=10.
    //   At depth=10: 10 < 10 is false → json_dumps(d10) → contains "k".
    // With *1: d0 calls d1 at depth=0*1=0 (stays 0 each time) → "leaf" returned forever.
    // So at depth=0 with a 10-level chain: correct (+1) → JSON; mutant (*1) → "leaf".
    #[test]
    fn generate_text_representation_chain_of_10_stops_at_depth_limit() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            // Build a chain of 11 nested single-key dicts: each has key "k" pointing to the next.
            // The innermost (11th) is {"k": "leaf"}.
            // At depth=0, 10 dicts can be unwrapped (depths 0-9 are < 10).
            // The 11th dict is reached at depth=10 → depth < 10 is false → json_dumps → not "leaf".
            let mut current: pyo3::Py<pyo3::PyAny> = {
                let d = PyDict::new(py);
                d.set_item("k", "leaf").unwrap();
                d.into_any().unbind()
            };
            for _ in 0..10 {
                let d = PyDict::new(py);
                d.set_item("k", current.bind(py)).unwrap();
                current = d.into_any().unbind();
            }
            // current is the outermost dict (10 wrappers + 1 leaf = 11 levels total)
            let result = generate_text_representation(current.bind(py), 0).unwrap();
            // With correct +1: the 11th dict (at depth=10) is json_dumps'd → NOT "leaf".
            // With *1 mutation: always at depth=0, unwraps all → returns "leaf".
            assert_ne!(
                result, "leaf",
                "chain of 11 single-key dicts must not return bare 'leaf' (depth limit must fire at depth=10)"
            );
        });
    }
}
