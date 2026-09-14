use crate::config::*;
use crate::guard::{evaluate_text_limits, is_numeric_string, truncate};
use crate::output_length_guard::PluginViolation;
use log::{debug, error, warn};
use pyo3::types::{PyDict, PyList, PyString};
use pyo3::{IntoPyObjectExt, prelude::*};

fn path_or_root(path: &str) -> &str {
    if path.is_empty() { "root" } else { path }
}

/// Public entry point — mirrors Python's try/except wrapper.
pub fn process_structured_data(
    data: &Bound<PyAny>,
    config: &OutputLengthGuardConfig,
    context: &Bound<'_, PyAny>,
    path: &str,
    depth: u32,
) -> (Option<Py<PyAny>>, bool, Option<PluginViolation>) {
    match process_structured_data_inner(data, config, context, path, depth) {
        Ok(result) => result,
        Err(e) => {
            error!(
                "Exception in process_structured_data: {}: path={}, data_type={}",
                e,
                path,
                data.get_type().name().unwrap()
            );
            (None, false, None)
        }
    }
}

fn process_structured_data_inner(
    data: &Bound<PyAny>,
    config: &OutputLengthGuardConfig,
    context: &Bound<'_, PyAny>,
    path: &str,
    depth: u32,
) -> PyResult<(Option<Py<PyAny>>, bool, Option<PluginViolation>)> {
    let py = data.py();

    debug!(
        "Processing structured data: type={}, path={}, strategy={}",
        data.get_type().name()?,
        path_or_root(path),
        config.strategy.as_str()
    );

    // Security: Check recursion depth
    if depth > config.max_recursion_depth {
        error!(
            "Recursion depth {} exceeds maximum {} at path: {}",
            depth, config.max_recursion_depth, path
        );
        if config.strategy == Strategy::Block {
            let details = PyDict::new(py);
            details.set_item("depth", depth)?;
            details.set_item("max_depth", config.max_recursion_depth)?;
            details.set_item("location", path_or_root(path))?;

            let violation = PluginViolation {
                reason: "Recursion depth exceeds security limit".to_string(),
                description: format!(
                    "Nesting depth {} exceeds limit of {}",
                    depth, config.max_recursion_depth
                ),
                code: "STRUCTURE_DEPTH_VIOLATION".to_string(),

                details: details.unbind(),
                mcp_error_code: -32000,
                http_status_code: 422,
            };
            return Ok((None, false, Some(violation)));
        }
        return Ok((None, false, None));
    }

    // Base case: string
    if let Ok(s) = data.cast::<PyString>() {
        let text = s.to_string();

        if is_numeric_string(&text) {
            log::debug!(
                "Skipping numeric string at {}: length={}",
                path_or_root(path),
                text.len()
            );
            return Ok((None, false, None));
        }

        let length = text.chars().count();
        let token_count = length / config.chars_per_token as usize;
        let (below_min, above_max) = evaluate_text_limits(length, token_count, config);

        if below_min || above_max {
            debug!(
                "String out of bounds at {}: length={}, tokens={}, mode={}",
                path_or_root(path),
                length,
                token_count,
                config.limit_mode.as_str()
            );

            // BLOCK MODE: return violation immediately
            if config.strategy == Strategy::Block {
                let location = if !path.is_empty() {
                    format!(" at {}", path)
                } else {
                    String::new()
                };

                let violation = if above_max && config.limit_mode == LimitMode::Token {
                    warn!(
                        "Token limit violation, blocking: location={}, tokens={}, max={:?}",
                        path_or_root(path),
                        token_count,
                        config.max_tokens
                    );
                    let details = PyDict::new(py);
                    details.set_item("token_count", token_count)?;
                    details.set_item("max_tokens", config.max_tokens)?;
                    details.set_item("chars_per_token", config.chars_per_token)?;
                    details.set_item("strategy", config.strategy.as_str())?;
                    details.set_item("location", path_or_root(path))?;
                    PluginViolation {
                        reason: format!("Estimated token count out of bounds{}", location),
                        description: format!(
                            "Estimated token count {} exceeds max_tokens {:?}{}",
                            token_count, config.max_tokens, location
                        ),
                        code: "OUTPUT_TOKEN_VIOLATION".to_string(),
                        details: details.unbind(),
                        mcp_error_code: -32000,
                        http_status_code: 422,
                    }
                } else if above_max {
                    debug!(
                        "Blocking: string at {} exceeds char limits (length={})",
                        path_or_root(path),
                        length
                    );
                    let details = PyDict::new(py);
                    details.set_item("length", length)?;
                    details.set_item("max_chars", config.max_chars)?;
                    details.set_item("strategy", config.strategy.as_str())?;
                    details.set_item("location", path_or_root(path))?;

                    PluginViolation {
                        reason: format!("String length out of bounds{}", location),
                        description: format!(
                            "String length {} exceeds max_chars {:?}{}",
                            length, config.max_chars, location
                        ),
                        code: "OUTPUT_LENGTH_VIOLATION".to_string(),
                        details: details.unbind(),
                        mcp_error_code: -32000,
                        http_status_code: 422,
                    }
                } else {
                    debug!(
                        "Blocking: string at {} below minimum limits",
                        path_or_root(path)
                    );
                    let details = PyDict::new(py);
                    details.set_item("length", length)?;
                    details.set_item("min_chars", config.min_chars)?;
                    details.set_item("token_count", token_count)?;
                    details.set_item("min_tokens", config.min_tokens)?;
                    details.set_item("location", path_or_root(path))?;

                    PluginViolation {
                        reason: format!("String length/tokens below minimum{}", location),
                        description: format!(
                            "String length {} or tokens {} below minimum{}",
                            length, token_count, location
                        ),
                        code: "OUTPUT_LENGTH_VIOLATION".to_string(),
                        details: details.unbind(),
                        mcp_error_code: -32000,
                        http_status_code: 422,
                    }
                };

                return Ok((None, false, Some(violation)));
            }

            // TRUNCATE MODE: only truncate if above max
            if above_max {
                let truncated = truncate(
                    &text,
                    config.max_chars,
                    &config.ellipsis,
                    config.word_boundary,
                    config.max_tokens,
                    config.chars_per_token,
                    config.max_text_length,
                    config.limit_mode,
                );
                let was_modified = truncated != text;
                return Ok((Some(truncated.into_py_any(py)?), was_modified, None));
            }
        }

        return Ok((None, false, None));
    }

    // Recursive case: list
    if let Ok(list) = data.cast::<PyList>() {
        if list.len() > config.max_structure_size as usize {
            log::error!(
                "List size {} exceeds maximum {} at path: {}",
                list.len(),
                config.max_structure_size,
                path
            );
            if config.strategy == Strategy::Block {
                let details = PyDict::new(py);
                details.set_item("size", list.len())?;
                details.set_item("max_size", config.max_structure_size)?;
                details.set_item("location", path_or_root(path))?;

                let violation = PluginViolation {
                    reason: "Structure size exceeds security limit".to_string(),
                    description: format!(
                        "List has {} items, exceeding limit of {}",
                        list.len(),
                        config.max_structure_size
                    ),
                    code: "STRUCTURE_SIZE_VIOLATION".to_string(),
                    details: details.unbind(),
                    mcp_error_code: -32000,
                    http_status_code: 422,
                };
                return Ok((None, false, Some(violation)));
            }
            return Ok((None, false, None));
        }

        let mut modified = false;
        let result = PyList::empty(py);

        for (idx, item) in list.iter().enumerate() {
            let item_path = if !path.is_empty() {
                format!("{}[{}]", path, idx)
            } else {
                format!("[{}]", idx)
            };

            let (processed_item, item_modified, violation) =
                process_structured_data_inner(&item, config, context, &item_path, depth + 1)?;

            if let Some(violation) = violation {
                return Ok((None, false, Some(violation)));
            }

            result.append(processed_item)?;
            if item_modified {
                modified = true;
            }
        }

        return Ok((Some(result.into_py_any(py)?), modified, None));
    }

    // Recursive case: dict
    if let Ok(dict) = data.cast::<PyDict>() {
        if dict.len() > config.max_structure_size as usize {
            log::error!(
                "Dict size {} exceeds maximum {} at path: {}",
                dict.len(),
                config.max_structure_size,
                path
            );
            if config.strategy == Strategy::Block {
                let details = PyDict::new(py);
                details.set_item("size", dict.len())?;
                details.set_item("max_size", config.max_structure_size)?;
                details.set_item("location", path_or_root(path))?;

                let violation = PluginViolation {
                    reason: "Structure size exceeds security limit".to_string(),
                    description: format!(
                        "Dict has {} items, exceeding limit of {}",
                        dict.len(),
                        config.max_structure_size
                    ),
                    code: "STRUCTURE_SIZE_VIOLATION".to_string(),
                    details: details.unbind(),
                    mcp_error_code: -32000,
                    http_status_code: 422,
                };
                return Ok((None, false, Some(violation)));
            }
            return Ok((None, false, None));
        }

        let mut modified = false;
        let result = PyDict::new(py);

        for (key, value) in dict.iter() {
            let key_str: String = key
                .extract()
                .unwrap_or_else(|_| "<non-str-key>".to_string());
            let value_path = if !path.is_empty() {
                format!("{}.{}", path, key_str)
            } else {
                key_str.clone()
            };

            let (processed_value, value_modified, violation) =
                process_structured_data_inner(&value, config, context, &value_path, depth + 1)?;

            if let Some(violation) = violation {
                return Ok((None, false, Some(violation)));
            }

            result.set_item(key, processed_value)?;
            if value_modified {
                modified = true;
            }
        }

        return Ok((Some(result.into_py_any(py)?), modified, None));
    }

    // Other types (int, bool, None, etc.) — pass through unchanged
    Ok((None, false, None))
}

pub fn generate_text_representation(data: &Bound<PyAny>, depth: u32) -> String {
    match generate_text_representation_inner(data, depth) {
        Ok(s) => s,
        Err(e) => {
            error!(
                "Exception in generate_text_representation: {}: data_type={}",
                e,
                data.get_type().name().unwrap()
            );
            python_repr(data).unwrap_or_else(|_| "<unrepresentable data>".to_string())
        }
    }
}

fn generate_text_representation_inner(data: &Bound<PyAny>, depth: u32) -> PyResult<String> {
    if let Ok(s) = data.cast::<PyString>() {
        return Ok(s.to_string());
    }

    // Single-key dict unwrapping, depth-limited
    if let Ok(dict) = data.cast::<PyDict>() {
        if dict.len() == 1 && depth < 10 {
            if let Some((_, value)) = dict.iter().next() {
                return generate_text_representation_inner(&value, depth + 1);
            }
        }
    }

    if data.is_instance_of::<PyList>() || data.is_instance_of::<PyDict>() {
        let py = data.py();
        let json_module = PyModule::import(py, "json")?;
        let kwargs = PyDict::new(py);
        kwargs.set_item("ensure_ascii", false)?;
        kwargs.set_item("separators", (",", ":"))?;
        let dumped = json_module.call_method("dumps", (data,), Some(&kwargs))?;
        return dumped.extract();
    }

    python_repr(data)
}

fn python_repr(data: &Bound<PyAny>) -> PyResult<String> {
    data.repr()?.extract()
}
