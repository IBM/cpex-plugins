use std::usize;

// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 ContextForge Contributors
use cpex_framework_bridge::{build_framework_object, build_framework_object_dyn, default_result};
use log::{debug, info};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList, PyString};

use crate::config::OutputLengthGuardConfig;
use crate::output_length_guard::*;

/// Output Length Guard engine implementation.
#[pyclass]
pub struct OutputLengthGuardEngine {
    config: OutputLengthGuardConfig,
}

#[pymethods]
impl OutputLengthGuardEngine {
    /// Create a new OutputLengthGuardEngine instance.
    #[new]
    pub fn new(config: &Bound<'_, PyDict>) -> PyResult<Self> {
        info!("Initializing Output Length Guard engine");

        let config: OutputLengthGuardConfig = OutputLengthGuardConfig::from_pydict(config)?;

        Ok(Self { config })
    }

    /// Hook called after tool is invoked.
    pub fn tool_post_invoke(
        &self,
        py: Python<'_>,
        payload: &Bound<'_, PyAny>,
        context: &Bound<'_, PyAny>,
        extensions: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Py<PyAny>> {
        debug!("Output Length Guard: tool_post_invoke called");

        // Extract result
        let result = payload.getattr("result")?;
        // Extract tool name
        let payload_name = payload.getattr("name")?.extract::<String>()?;
        if result.is_none() {
            return default_result(py, "ToolPostInvokeResult");
        }
        let result_type = result.get_type().name()?.to_string();
        info!(
            "OutputLengthGuard processing tool with result type: {}",
            result_type,
        );

        // String result
        if result.is_instance_of::<PyString>() {
            return self.handle_plain_string(
                py,
                payload,
                &payload_name,
                result.cast::<PyString>()?.to_str()?,
            );
        }
        if result.is_instance_of::<PyDict>() {
            let text = result.cast::<PyDict>()?;

            //  Dict with text field
            if let Some(text) = text.get_item("text")? {
                if text.is_instance_of::<PyString>() {
                    return self.handle_plain_string(
                        py,
                        payload,
                        &payload_name,
                        text.cast::<PyString>()?.to_str()?,
                    );
                }
            }
            // MCP CallToolResult as dict (from model_dump with 'content' key)
            debug!(
                "OutputLengthGuard: Dict result from tool '{}' has no 'text' field, passing through unchanged",
                payload_name
            );
            return default_result(py, "ToolPostInvokeResult");
        }

        if result.is_instance_of::<PyList>() {
            if let Ok(list) = result.cast::<PyList>() {
                if !list.is_empty() {
                    // Handle if first item in list is dict
                    if list
                        .get_item(0)
                        .is_ok_and(|first| first.is_instance_of::<PyDict>())
                    {
                        if let Ok(dict) = list.get_item(0)?.cast::<PyDict>()
                            && dict.contains("type")?
                        {
                            return self.handle_mcp_list(py, payload, &payload_name, list);
                        }
                    }

                    //handle if all items in list is string
                    if list.iter().all(|item| item.is_instance_of::<PyString>()) {
                        return self.handle_string_list(py, payload, &payload_name, list);
                    }
                }
            }
        }

        // placeholder for more checks
        todo!()
    }

    fn handle_plain_string(
        &self,
        py: Python<'_>,
        _payload: &Bound<'_, PyAny>,
        payload_name: &str,
        result: &str,
    ) -> PyResult<Py<PyAny>> {
        let new_text = handle_text(py, result, &self.config)?;
        let mut kwargs: Vec<(&str, Py<PyAny>)> = vec![("meta", new_text.metadata.into_any())];
        //handle violations
        if let Some(violation) = new_text.violation {
            let violations = self.build_violation_object(py, violation)?;
            kwargs.extend([
                (
                    "continue_processing",
                    false.into_pyobject(py)?.to_owned().into_any().unbind(),
                ),
                ("violation", violations),
            ]);
        } else if new_text.text != result {
            let tool_post_invoke_payload = build_framework_object(
                py,
                "ToolPostInvokePayload",
                [
                    ("name", payload_name.into_pyobject(py)?.into_any().unbind()),
                    (
                        "result",
                        new_text.text.into_pyobject(py)?.into_any().unbind(),
                    ),
                ],
            )?;
            kwargs.push(("modified_payload", tool_post_invoke_payload));
        }
        return build_framework_object_dyn(py, "ToolPostInvokeResult", kwargs);
    }

    /// Handle MCP content array format: [{"type": "text", "text": "..."}].
    fn handle_mcp_list(
        &self,
        py: Python<'_>,
        payload: &Bound<'_, PyAny>,
        payload_name: &str,
        result: &Bound<PyList>,
    ) -> PyResult<Py<PyAny>> {
        let mut modified = false;
        let mcp_out = PyList::empty(py);

        for item in result.iter() {
            let Ok(dict) = item.cast::<PyDict>() else {
                mcp_out.append(&item)?;
                continue;
            };

            let item_type: Option<String> = dict.get_item("type")?.and_then(|v| v.extract().ok());

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
        let metadata = PyDict::new(py);
        metadata.set_item("mcp_content_processed", true)?;
        let mut kwargs: Vec<(&str, Py<PyAny>)> = vec![("meta", metadata.into_any().unbind())];
        if modified {
            let tool_post_invoke_payload = build_framework_object(
                py,
                "ToolPostInvokePayload",
                [
                    ("name", payload_name.into_pyobject(py)?.into_any().unbind()),
                    ("result", mcp_out.into_any().unbind()),
                ],
            )?;

            kwargs.push(("modified_payload", tool_post_invoke_payload));
        }
        return build_framework_object_dyn(py, "ToolPostInvokeResult", kwargs);
    }

    fn handle_string_list(
        &self,
        py: Python<'_>,
        _payload: &Bound<'_, PyAny>,
        payload_name: &str,
        result: &Bound<PyList>,
    ) -> PyResult<Py<PyAny>> {
        let texts: Vec<String> = result.extract()?;

        let mut modified = false;
        let meta_list = PyList::empty(py);
        let mut str_list_out = PyList::empty(py);

        for (idx, text) in texts.iter().enumerate() {
            let new_text = handle_text(py, text, &self.config)?;
            meta_list.append(new_text.metadata)?;

            if let Some(violation) = new_text.violation {
                let violations = self.build_violation_object(py, violation)?;
                let metadata = PyDict::new(py);
                metadata.set_item("items", &meta_list)?;
                metadata.set_item("violation_index", idx)?;
                metadata.set_item("total_items", texts.len())?;
                let kwargs: Vec<(&str, Py<PyAny>)> = vec![
                    (
                        "continue_processing",
                        false.into_pyobject(py)?.to_owned().into_any().unbind(),
                    ),
                    ("violation", violations),
                    ("metadata", metadata.into_any().unbind()),
                ];
                return build_framework_object_dyn(py, "ToolPostInvokeResult", kwargs);
            }
            if new_text.text != *text {
                modified = true;
            }
            str_list_out.append(new_text.text);
        }
        let metadata = PyDict::new(py);
        metadata.set_item("items", &meta_list)?;
        let mut kwargs: Vec<(&str, Py<PyAny>)> = vec![("metadata", metadata.into_any().unbind())];
        if modified {
            let tool_post_invoke_payload = build_framework_object(
                py,
                "ToolPostInvokePayload",
                [
                    ("name", payload_name.into_pyobject(py)?.into_any().unbind()),
                    ("result", str_list_out.into_any().unbind()),
                ],
            )?;

            kwargs.push(("modified_payload", tool_post_invoke_payload));
        }
        return build_framework_object_dyn(py, "ToolPostInvokeResult", kwargs);
    }

    fn build_violation_object(
        &self,
        py: Python<'_>,
        violation: PluginViolation,
    ) -> PyResult<Py<PyAny>> {
        return build_framework_object(
            py,
            "PluginViolation",
            [
                (
                    "reason",
                    violation.reason.into_pyobject(py)?.into_any().unbind(),
                ),
                (
                    "description",
                    violation.description.into_pyobject(py)?.into_any().unbind(),
                ),
                (
                    "code",
                    violation.code.into_pyobject(py)?.into_any().unbind(),
                ),
                ("details", violation.details.into_any()),
            ],
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pyo3::types::PyDict;

    #[test]
    fn test_engine_creation_with_defaults() {
        Python::initialize();
        Python::attach(|py| {
            let config = PyDict::new(py);
            let engine = OutputLengthGuardEngine::new(&config);
            assert!(engine.is_ok());
            let engine = engine.unwrap();
            //  assert_eq!(engine.example_option, "default_value");
        });
    }

    #[test]
    fn test_engine_creation_with_custom_config() {
        Python::initialize();
        Python::attach(|py| {
            let config = PyDict::new(py);
            config.set_item("example_option", "custom_value").unwrap();
            let engine = OutputLengthGuardEngine::new(&config);
            assert!(engine.is_ok());
            let engine = engine.unwrap();
            //assert_eq!(engine.example_option, "custom_value");
        });
    }
}
