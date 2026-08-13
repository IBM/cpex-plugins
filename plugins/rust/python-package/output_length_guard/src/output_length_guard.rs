use log::{debug, info};
use pyo3::prelude::*;
use pyo3::types::PyDict;

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

pub struct OutputLengthGuardPlugin {
    cfg: OutputLengthGuardConfig,
}

impl OutputLengthGuardPlugin {
    pub fn new(cfg: OutputLengthGuardConfig) -> Self {
        Self { cfg }
    }

    /*ß pub fn tool_post_invoke(
        &self,
        py: Python<'_>,
        payload: ToolPostInvokePayload,
    ) -> PyResult<ToolPostInvokeResult> {
        let result = payload.result.bind(py);

        if let Ok(dict) = result.downcast::<PyDict>() {
            if let Ok(Some(content)) = dict.get_item("content") {
                if content.downcast::<PyList>().is_ok() {
                    return self.handle_mcp_content_dict(py, &payload, dict);
                }
            }
        }

        if let Ok(s) = result.downcast::<PyString>() {
            return self.handle_plain_string(py, &payload, s.to_str()?);
        }

        if let Ok(dict) = result.downcast::<PyDict>() {
            return self.handle_text_dict(py, &payload, dict);
        }

        if let Ok(list) = result.downcast::<PyList>() {
            if !list.is_empty() {
                if let Ok(first) = list.get_item(0)?.downcast::<PyDict>() {
                    if first.contains("type")? {
                        return self.handle_mcp_list(py, &payload, list);
                    }
                }
            }

            let all_strings = list.iter().all(|item| item.downcast::<PyString>().is_ok());
            if all_strings {
                return self.handle_string_list(py, &payload, list);
            }
        }

        let meta = PyDict::new(py);
        meta.set_item("skipped", true)?;
        meta.set_item(
            "reason",
            format!("unsupported_type_{}", result.get_type().name()?),
        )?;
        Ok(ToolPostInvokeResult {
            continue_processing: true,
            modified_payload: None,
            violation: None,
            metadata: Some(meta.unbind()),
        })
    }*/

    /*  fn handle_mcp_content_dict(
        &self,
        py: Python<'_>,
        payload: &ToolPostInvokePayload,
        result: &Bound<'_, PyDict>,
    ) -> PyResult<ToolPostInvokeResult> {
        let policy = self.cfg.to_policy();

        let struct_key = if let Ok(Some(value)) = result.get_item("structuredContent") {
            if !value.is_none() {
                Some("structuredContent")
            } else {
                None
            }
        } else if let Ok(Some(value)) = result.get_item("structured_content") {
            if !value.is_none() {
                Some("structured_content")
            } else {
                None
            }
        } else {
            None
        };

        if let Some(struct_key) = struct_key {
            let structured_value = result.get_item(struct_key)?.unwrap();
            let processed = process_structured_data(py, &structured_value, &policy, "", 0)?;

            if let Some(violation) = processed.violation {
                let meta = PyDict::new(py);
                meta.set_item("structured_content_blocked", true)?;
                meta.set_item("location", struct_key)?;
                meta.set_item("min_tokens", self.cfg.min_tokens)?;
                meta.set_item("max_tokens", self.cfg.max_tokens)?;
                meta.set_item("chars_per_token", self.cfg.chars_per_token)?;
                return Ok(ToolPostInvokeResult {
                    continue_processing: false,
                    modified_payload: None,
                    violation: Some(violation),
                    metadata: Some(meta.unbind()),
                });
            }

            if processed.modified {
                let new_result = PyDict::new(py);
                for (k, v) in result.iter() {
                    new_result.set_item(k, v)?;
                }

                new_result.set_item(struct_key, processed.data.bind(py))?;
                let new_text = generate_text_representation(py, processed.data.bind(py), 0)?;

                let content = PyList::empty(py);
                let item = PyDict::new(py);
                item.set_item("type", "text")?;
                item.set_item("text", new_text)?;
                content.append(item)?;
                new_result.set_item("content", content)?;

                let meta = PyDict::new(py);
                meta.set_item("mcp_result_processed", true)?;
                meta.set_item("items_modified", true)?;
                meta.set_item("structured_content_processed", true)?;
                meta.set_item("min_tokens", self.cfg.min_tokens)?;
                meta.set_item("max_tokens", self.cfg.max_tokens)?;
                meta.set_item("chars_per_token", self.cfg.chars_per_token)?;

                return Ok(ToolPostInvokeResult {
                    continue_processing: true,
                    modified_payload: Some(ToolPostInvokePayload {
                        name: payload.name.clone(),
                        result: new_result.into_any().unbind(),
                    }),
                    violation: None,
                    metadata: Some(meta.unbind()),
                });
            }
        }

        let content_obj = result
            .get_item("content")?
            .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("Missing content"))?;
        let content = content_obj.downcast::<PyList>()?;

        let mut modified = false;
        let content_out = PyList::empty(py);

        for item in content.iter() {
            if let Ok(item_dict) = item.downcast::<PyDict>() {
                if let Ok(Some(type_obj)) = item_dict.get_item("type") {
                    let item_type = type_obj.extract::<String>()?;

                    if item_type == "text" {
                        if let Ok(Some(text_obj)) = item_dict.get_item("text") {
                            let current_text = text_obj.extract::<String>()?;
                            let handled = handle_text(py, &current_text, &self.cfg)?;

                            if let Some(violation) = handled.violation {
                                return Ok(ToolPostInvokeResult {
                                    continue_processing: false,
                                    modified_payload: None,
                                    violation: Some(violation),
                                    metadata: Some(handled.metadata),
                                });
                            }

                            if handled.text != current_text {
                                modified = true;
                                let new_item = PyDict::new(py);
                                for (k, v) in item_dict.iter() {
                                    new_item.set_item(k, v)?;
                                }
                                new_item.set_item("text", handled.text)?;
                                content_out.append(new_item)?;
                            } else {
                                content_out.append(item)?;
                            }
                            continue;
                        }
                    }

                    if item_type == "resource" {
                        if let Ok(Some(resource_obj)) = item_dict.get_item("resource") {
                            if let Ok(resource) = resource_obj.downcast::<PyDict>() {
                                if let Ok(Some(text_obj)) = resource.get_item("text") {
                                    let current_text = text_obj.extract::<String>()?;
                                    let handled = handle_text(py, &current_text, &self.cfg)?;

                                    if let Some(violation) = handled.violation {
                                        return Ok(ToolPostInvokeResult {
                                            continue_processing: false,
                                            modified_payload: None,
                                            violation: Some(violation),
                                            metadata: Some(handled.metadata),
                                        });
                                    }

                                    if handled.text != current_text {
                                        modified = true;
                                        let new_resource = PyDict::new(py);
                                        for (k, v) in resource.iter() {
                                            new_resource.set_item(k, v)?;
                                        }
                                        new_resource.set_item("text", handled.text)?;

                                        let new_item = PyDict::new(py);
                                        for (k, v) in item_dict.iter() {
                                            new_item.set_item(k, v)?;
                                        }
                                        new_item.set_item("resource", new_resource)?;
                                        content_out.append(new_item)?;
                                    } else {
                                        content_out.append(item)?;
                                    }
                                    continue;
                                }
                            }
                        }
                    }
                }
            }

            content_out.append(item)?;
        }

        if modified {
            let new_result = PyDict::new(py);
            for (k, v) in result.iter() {
                new_result.set_item(k, v)?;
            }
            new_result.set_item("content", content_out)?;

            let meta = PyDict::new(py);
            meta.set_item("mcp_result_processed", true)?;
            meta.set_item("items_modified", true)?;
            meta.set_item("structured_content_processed", struct_key.is_some())?;

            return Ok(ToolPostInvokeResult {
                continue_processing: true,
                modified_payload: Some(ToolPostInvokePayload {
                    name: payload.name.clone(),
                    result: new_result.into_any().unbind(),
                }),
                violation: None,
                metadata: Some(meta.unbind()),
            });
        }

        let meta = PyDict::new(py);
        meta.set_item("mcp_result_processed", true)?;
        meta.set_item("items_modified", false)?;
        meta.set_item("structured_content_processed", struct_key.is_some())?;

        Ok(ToolPostInvokeResult {
            continue_processing: true,
            modified_payload: None,
            violation: None,
            metadata: Some(meta.unbind()),
        })
    } */

    /*  fn handle_plain_string(
        &self,
        py: Python<'_>,
        payload: &ToolPostInvokePayload,
        result: &str,
    ) -> PyResult<ToolPostInvokeResult> {
        let handled = handle_text(py, result, &self.cfg)?;

        if let Some(violation) = handled.violation {
            return Ok(ToolPostInvokeResult {
                continue_processing: false,
                modified_payload: None,
                violation: Some(violation),
                metadata: Some(handled.metadata),
            });
        }

        if handled.text != result {
            return Ok(ToolPostInvokeResult {
                continue_processing: true,
                modified_payload: Some(ToolPostInvokePayload {
                    name: payload.name.clone(),
                    result: PyString::new(py, &handled.text).into_any().unbind(),
                }),
                violation: None,
                metadata: Some(handled.metadata),
            });
        }

        Ok(ToolPostInvokeResult {
            continue_processing: true,
            modified_payload: None,
            violation: None,
            metadata: Some(handled.metadata),
        })
    } */

    /* fn handle_text_dict(
        &self,
        py: Python<'_>,
        payload: &ToolPostInvokePayload,
        result: &Bound<'_, PyDict>,
    ) -> PyResult<ToolPostInvokeResult> {
        if let Ok(Some(text_obj)) = result.get_item("text") {
            if let Ok(current) = text_obj.extract::<String>() {
                let handled = handle_text(py, &current, &self.cfg)?;

                if let Some(violation) = handled.violation {
                    return Ok(ToolPostInvokeResult {
                        continue_processing: false,
                        modified_payload: None,
                        violation: Some(violation),
                        metadata: Some(handled.metadata),
                    });
                }

                if handled.text != current {
                    let new_result = PyDict::new(py);
                    for (k, v) in result.iter() {
                        new_result.set_item(k, v)?;
                    }
                    new_result.set_item("text", handled.text)?;

                    return Ok(ToolPostInvokeResult {
                        continue_processing: true,
                        modified_payload: Some(ToolPostInvokePayload {
                            name: payload.name.clone(),
                            result: new_result.into_any().unbind(),
                        }),
                        violation: None,
                        metadata: Some(handled.metadata),
                    });
                }

                return Ok(ToolPostInvokeResult {
                    continue_processing: true,
                    modified_payload: None,
                    violation: None,
                    metadata: Some(handled.metadata),
                });
            }
        }

        Ok(ToolPostInvokeResult {
            continue_processing: true,
            modified_payload: None,
            violation: None,
            metadata: None,
        })
    }

    fn handle_mcp_list(
        &self,
        py: Python<'_>,
        payload: &ToolPostInvokePayload,
        result: &Bound<'_, PyList>,
    ) -> PyResult<ToolPostInvokeResult> {
        let mut modified = false;
        let output = PyList::empty(py);

        for item in result.iter() {
            if let Ok(item_dict) = item.downcast::<PyDict>() {
                if let Ok(Some(type_obj)) = item_dict.get_item("type") {
                    let item_type = type_obj.extract::<String>()?;

                    if item_type == "text" {
                        if let Ok(Some(text_obj)) = item_dict.get_item("text") {
                            let current_text = text_obj.extract::<String>()?;
                            let handled = handle_text(py, &current_text, &self.cfg)?;

                            if let Some(violation) = handled.violation {
                                return Ok(ToolPostInvokeResult {
                                    continue_processing: false,
                                    modified_payload: None,
                                    violation: Some(violation),
                                    metadata: Some(handled.metadata),
                                });
                            }

                            if handled.text != current_text {
                                modified = true;
                                let new_item = PyDict::new(py);
                                for (k, v) in item_dict.iter() {
                                    new_item.set_item(k, v)?;
                                }
                                new_item.set_item("text", handled.text)?;
                                output.append(new_item)?;
                            } else {
                                output.append(item)?;
                            }
                            continue;
                        }
                    }

                    if item_type == "resource" {
                        if let Ok(Some(resource_obj)) = item_dict.get_item("resource") {
                            if let Ok(resource) = resource_obj.downcast::<PyDict>() {
                                if let Ok(Some(text_obj)) = resource.get_item("text") {
                                    let current_text = text_obj.extract::<String>()?;
                                    let handled = handle_text(py, &current_text, &self.cfg)?;

                                    if let Some(violation) = handled.violation {
                                        return Ok(ToolPostInvokeResult {
                                            continue_processing: false,
                                            modified_payload: None,
                                            violation: Some(violation),
                                            metadata: Some(handled.metadata),
                                        });
                                    }

                                    if handled.text != current_text {
                                        modified = true;

                                        let new_resource = PyDict::new(py);
                                        for (k, v) in resource.iter() {
                                            new_resource.set_item(k, v)?;
                                        }
                                        new_resource.set_item("text", handled.text)?;

                                        let new_item = PyDict::new(py);
                                        for (k, v) in item_dict.iter() {
                                            new_item.set_item(k, v)?;
                                        }
                                        new_item.set_item("resource", new_resource)?;
                                        output.append(new_item)?;
                                    } else {
                                        output.append(item)?;
                                    }
                                    continue;
                                }
                            }
                        }
                    }
                }
            }

            output.append(item)?;
        }

        let meta = PyDict::new(py);
        meta.set_item("mcp_content_processed", true)?;

        if modified {
            return Ok(ToolPostInvokeResult {
                continue_processing: true,
                modified_payload: Some(ToolPostInvokePayload {
                    name: payload.name.clone(),
                    result: output.into_any().unbind(),
                }),
                violation: None,
                metadata: Some(meta.unbind()),
            });
        }

        Ok(ToolPostInvokeResult {
            continue_processing: true,
            modified_payload: None,
            violation: None,
            metadata: Some(meta.unbind()),
        })
    }

    fn handle_string_list(
        &self,
        py: Python<'_>,
        payload: &ToolPostInvokePayload,
        result: &Bound<'_, PyList>,
    ) -> PyResult<ToolPostInvokeResult> {
        let output = PyList::empty(py);
        let meta_items = PyList::empty(py);
        let mut modified = false;
        let total_items = result.len();

        for (idx, item) in result.iter().enumerate() {
            let text = item.extract::<String>()?;
            let handled = handle_text(py, &text, &self.cfg)?;
            meta_items.append(handled.metadata.bind(py))?;

            if let Some(violation) = handled.violation {
                let meta = PyDict::new(py);
                meta.set_item("items", meta_items)?;
                meta.set_item("violation_index", idx)?;
                meta.set_item("total_items", total_items)?;
                return Ok(ToolPostInvokeResult {
                    continue_processing: false,
                    modified_payload: None,
                    violation: Some(violation),
                    metadata: Some(meta.unbind()),
                });
            }

            if handled.text != text {
                modified = true;
            }

            output.append(handled.text)?;
        }

        let meta = PyDict::new(py);
        meta.set_item("items", meta_items)?;

        if modified {
            return Ok(ToolPostInvokeResult {
                continue_processing: true,
                modified_payload: Some(ToolPostInvokePayload {
                    name: payload.name.clone(),
                    result: output.into_any().unbind(),
                }),
                violation: None,
                metadata: Some(meta.unbind()),
            });
        }

        Ok(ToolPostInvokeResult {
            continue_processing: true,
            modified_payload: None,
            violation: None,
            metadata: Some(meta.unbind()),
        })
    } */
}
