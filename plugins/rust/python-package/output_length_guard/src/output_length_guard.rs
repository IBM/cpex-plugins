use log::{debug, info};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList, PyString};

use crate::config::{LimitMode, OutputLengthGuardConfig};
use crate::guard::{evaluate_text_limits, is_numeric_string, truncate};

pub struct HandleTextResult {
    pub text: String,
    pub metadata: Py<PyDict>,
    pub violation: Option<PluginViolation>,
}
#[derive(FromPyObject)]
pub struct PluginViolation {
    pub reason: String,
    pub description: String,
    pub code: String,
    pub details: Py<PyDict>,
    pub mcp_error_code: i32,
    pub http_status_code: u16,
}

pub fn handle_text(
    py: Python<'_>,
    text: &str,
    cfg: &OutputLengthGuardConfig,
) -> PyResult<HandleTextResult> {
    let meta = PyDict::new(py);
    let length = text.chars().count();

    if is_numeric_string(text) {
        meta.set_item("original_length", length)?;
        meta.set_item("numeric", true)?;
        meta.set_item("within_bounds", true)?;
        debug!("Preserving numeric string: length={}", length);
        return Ok(HandleTextResult {
            text: text.to_string(),
            metadata: meta.unbind(),
            violation: None,
        });
    }

    let token_count = length / cfg.chars_per_token as usize;
    meta.set_item("original_length", length)?;

    let (below_min, above_max) = evaluate_text_limits(length, token_count, cfg);

    if !(below_min || above_max) {
        meta.set_item("within_bounds", true)?;
        debug!(
            "Text within bounds: length={}, mode={}",
            length,
            cfg.limit_mode.as_str(),
        );
        return Ok(HandleTextResult {
            text: text.to_string(),
            metadata: meta.unbind(),
            violation: None,
        });
    }

    // Out of bounds
    meta.set_item("within_bounds", false)?;
    meta.set_item("limit_mode", cfg.limit_mode.as_str())?;
    meta.set_item("strategy", cfg.strategy.as_str())?;

    if cfg.is_blocking() {
        let details = PyDict::new(py);
        info!(
            "BLOCKING output: length={}, tokens={}, mode={}",
            length,
            token_count,
            cfg.limit_mode.as_str()
        );

        let violation = if above_max && cfg.limit_mode == LimitMode::Token {
            details.set_item("token_count", token_count)?;
            details.set_item("max_tokens", cfg.max_tokens)?;
            details.set_item("chars_per_token", cfg.chars_per_token)?;
            details.set_item("strategy", cfg.strategy.as_str())?;
            PluginViolation {
                reason: "Output estimated token count out of bounds".to_string(),
                description: format!(
                    "Estimated token count {} exceeds max_tokens {}",
                    token_count,
                    cfg.max_tokens.unwrap_or(0)
                ),
                code: "OUTPUT_TOKEN_VIOLATION".to_string(),
                details: details.unbind(),
                mcp_error_code: -32000,
                http_status_code: 422,
            }
        } else if above_max {
            details.set_item("length", length)?;
            details.set_item("max_chars", cfg.max_chars)?;
            details.set_item("strategy", cfg.strategy.as_str())?;
            PluginViolation {
                reason: "Output length out of bounds".to_string(),
                description: format!(
                    "Result length {} exceeds max_chars {}",
                    length,
                    cfg.max_chars.unwrap_or(0)
                ),
                code: "OUTPUT_LENGTH_VIOLATION".to_string(),
                details: details.unbind(),
                mcp_error_code: -32000,
                http_status_code: 422,
            }
        } else {
            details.set_item("length", length)?;
            details.set_item("min_chars", cfg.min_chars)?;
            details.set_item("token_count", token_count)?;
            details.set_item("min_tokens", cfg.min_tokens)?;
            details.set_item("strategy", cfg.strategy.as_str())?;
            PluginViolation {
                reason: "Output length below minimum".to_string(),
                description: format!(
                    "Result length {} (tokens {}) below minimum",
                    length, token_count
                ),
                code: "OUTPUT_LENGTH_VIOLATION".to_string(),
                details: details.unbind(),
                mcp_error_code: -32000,
                http_status_code: 422,
            }
        };

        return Ok(HandleTextResult {
            text: text.to_string(),
            metadata: meta.unbind(),
            violation: Some(violation),
        });
    }

    // Truncate strategy only handles over-length
    if above_max {
        info!(
            "TRUNCATING output: original_length={}, mode={}",
            length,
            cfg.limit_mode.as_str()
        );
        let new_text = truncate(
            text,
            cfg.max_chars,
            &cfg.ellipsis,
            cfg.word_boundary,
            cfg.max_tokens,
            cfg.chars_per_token,
            cfg.max_text_length,
            cfg.limit_mode,
        );
        meta.set_item("truncated", true)?;
        meta.set_item("new_length", new_text.chars().count())?;
        return Ok(HandleTextResult {
            text: new_text,
            metadata: meta.unbind(),
            violation: None,
        });
    }

    meta.set_item("truncated", false)?;
    meta.set_item("new_length", length)?;
    Ok(HandleTextResult {
        text: text.to_string(),
        metadata: meta.unbind(),
        violation: None,
    })
}

pub fn handle_list(
    py: Python<'_>,
    result: &Bound<PyList>,
    config: &OutputLengthGuardConfig,
    context: &Bound<'_, PyAny>,
    path: &str,
    depth: u32,
) -> (PyList, bool, Option<PluginViolation>) {
    let mut modified = false;
    let mcp_out = PyList::empty(py);

    for item in result.iter() {
        let Ok(dict) = item.cast::<PyDict>() else {
            mcp_out.append(&item);
            continue;
        };

        let item_type: Option<String> = dict
            .get_item("type")
            .ok()
            .and_then(|optional_value| optional_value.and_then(|value| value.extract().ok()));

        match item_type.as_deref() {
            Some("text") => {
                if dict.get_item("text").is_ok_and(|text| {
                    text.is_some_and(|text_type| text_type.is_instance_of::<PyString>())
                }) {
                    let current_text: String = dict
                        .get_item("text")?
                        .and_then(|v| v.extract().ok())
                        .unwrap();

                    let new_text = handle_text(py, &current_text, &self.config)?;
                    let mut kwargs: Vec<(&str, Py<PyAny>)> =
                        vec![("meta", new_text.metadata.into_any())];
                    if let Some(violation) = new_text.violation {
                        let violations = self.build_violation_object(py, violation)?;
                        kwargs.extend([
                            (
                                "continue_processing",
                                false.into_pyobject(py)?.to_owned().into_any().unbind(),
                            ),
                            ("violation", violations),
                        ]);
                        return build_framework_object_dyn(py, "ToolPostInvokeResult", kwargs);
                    }

                    if new_text.text != current_text {
                        modified = true;
                        let new_item = dict.copy()?;
                        new_item.set_item("text", new_text.text)?;
                        mcp_out.append(new_item)?;
                        continue;
                    }
                }
                mcp_out.append(&item)?;
            }
            Some("resource") => {
                let resource_any = dict.get_item("resource")?;
                let resource_dict = resource_any.as_ref().and_then(|r| r.cast::<PyDict>().ok());

                // item.get("resource") is not dict appened current item and continue to next
                let Some(resource) = resource_dict else {
                    mcp_out.append(&item)?;
                    continue;
                };

                let resource_text: Option<String> = resource.get_item("text")?.and_then(|v| {
                    if v.is_instance_of::<PyString>() {
                        v.extract().ok()
                    } else {
                        None
                    }
                });

                // resource.get_item("text") is not string type append current item and continue to next
                let Some(current_text) = resource_text else {
                    mcp_out.append(&item)?;
                    continue;
                };

                let new_text = handle_text(py, &current_text, &self.config)?;

                let mut kwargs: Vec<(&str, Py<PyAny>)> =
                    vec![("meta", new_text.metadata.into_any())];
                if let Some(violation) = new_text.violation {
                    let violations = self.build_violation_object(py, violation)?;
                    kwargs.extend([
                        (
                            "continue_processing",
                            false.into_pyobject(py)?.to_owned().into_any().unbind(),
                        ),
                        ("violation", violations),
                    ]);
                    return build_framework_object_dyn(py, "ToolPostInvokeResult", kwargs);
                }

                if new_text.text != current_text {
                    modified = true;
                    let new_resource = resource.copy()?;
                    new_resource.set_item("text", new_text.text)?;
                    let new_item = dict.copy()?;
                    new_item.set_item("resource", new_resource)?;
                    mcp_out.append(new_item)?;
                } else {
                    mcp_out.append(&item)?;
                }
            }
            _ => {
                mcp_out.append(&item)?;
            }
        }
    }
    todo!()
}
pub struct OutputLengthGuardPlugin {
    cfg: OutputLengthGuardConfig,
}

impl OutputLengthGuardPlugin {
    pub fn new(cfg: OutputLengthGuardConfig) -> Self {
        Self { cfg }
    }
}
