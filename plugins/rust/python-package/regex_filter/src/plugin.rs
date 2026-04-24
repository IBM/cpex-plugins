// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
//
// Rust-owned regex filter plugin core.

use cpex_framework_bridge::{build_framework_object, default_result};
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyDict, PyList, PyModule, PyString};
use pyo3_stub_gen::derive::*;

use crate::{SearchReplacePluginRust, apply_patterns_checked};

#[gen_stub_pyclass]
#[pyclass]
pub struct RegexFilterPluginCore {
    engine: SearchReplacePluginRust,
}

#[gen_stub_pymethods]
#[pymethods]
impl RegexFilterPluginCore {
    #[new]
    pub fn new(config: &Bound<'_, PyDict>) -> PyResult<Self> {
        let engine = SearchReplacePluginRust::new(config)?;
        Ok(Self { engine })
    }

    pub fn prompt_pre_fetch(
        &self,
        py: Python<'_>,
        payload: &Bound<'_, PyAny>,
        _context: &Bound<'_, PyAny>,
    ) -> PyResult<Py<PyAny>> {
        self.process_payload_attr(py, payload, "args", "PromptPrehookResult")
    }

    pub fn prompt_post_fetch(
        &self,
        py: Python<'_>,
        payload: &Bound<'_, PyAny>,
        _context: &Bound<'_, PyAny>,
    ) -> PyResult<Py<PyAny>> {
        let result = payload.getattr("result")?;
        let messages_value = result.getattr("messages")?;
        let Ok(messages) = messages_value.cast::<PyList>() else {
            return default_result(py, "PromptPosthookResult");
        };
        if messages.len() > self.engine.config.max_collection_items {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "Collection exceeds max_collection_items ({})",
                self.engine.config.max_collection_items
            )));
        }

        let mut visited = 0usize;
        let mut input_bytes = 0usize;
        let mut output_bytes = 0usize;
        let mut updated_messages: Option<Vec<Py<PyAny>>> = None;
        for (index, message) in messages.iter().enumerate() {
            visited += 1;
            if visited > self.engine.config.max_total_items {
                return Err(pyo3::exceptions::PyValueError::new_err(format!(
                    "Traversal exceeds max_total_items ({})",
                    self.engine.config.max_total_items
                )));
            }
            let Ok(content) = message.getattr("content") else {
                if let Some(items) = updated_messages.as_mut() {
                    items.push(message.clone().unbind());
                }
                continue;
            };
            let Ok(text_obj) = content.getattr("text") else {
                if let Some(items) = updated_messages.as_mut() {
                    items.push(message.clone().unbind());
                }
                continue;
            };
            let Ok(text) = text_obj.cast::<PyString>() else {
                if let Some(items) = updated_messages.as_mut() {
                    items.push(message.clone().unbind());
                }
                continue;
            };
            input_bytes = input_bytes.saturating_add(text.to_str()?.len());
            if input_bytes > self.engine.config.max_total_text_bytes {
                return Err(pyo3::exceptions::PyValueError::new_err(format!(
                    "Input exceeds max_total_text_bytes ({})",
                    self.engine.config.max_total_text_bytes
                )));
            }
            let replaced = apply_patterns_checked(&self.engine.config, text.to_str()?)?;
            if let std::borrow::Cow::Owned(replaced) = replaced {
                output_bytes = output_bytes.saturating_add(replaced.len());
                if output_bytes > self.engine.config.max_output_bytes {
                    return Err(pyo3::exceptions::PyValueError::new_err(format!(
                        "Output exceeds max_output_bytes ({})",
                        self.engine.config.max_output_bytes
                    )));
                }
                let text_obj = replaced.into_pyobject(py)?.into_any().unbind();
                let cloned_content = clone_payload_with_attr(py, &content, "text", &text_obj)?;
                let items = updated_messages.get_or_insert_with(|| {
                    messages
                        .iter()
                        .take(index)
                        .map(|prior_message| prior_message.clone().unbind())
                        .collect()
                });
                items.push(clone_payload_with_attr(
                    py,
                    &message,
                    "content",
                    &cloned_content,
                )?);
            } else {
                output_bytes = output_bytes.saturating_add(text.to_str()?.len());
                if output_bytes > self.engine.config.max_output_bytes {
                    return Err(pyo3::exceptions::PyValueError::new_err(format!(
                        "Output exceeds max_output_bytes ({})",
                        self.engine.config.max_output_bytes
                    )));
                }
                if let Some(items) = updated_messages.as_mut() {
                    items.push(message.clone().unbind());
                }
            }
        }

        if let Some(updated_messages) = updated_messages {
            let new_messages = PyList::new(py, updated_messages.iter().map(|item| item.bind(py)))?;
            let new_result = clone_payload_with_attr(
                py,
                &result,
                "messages",
                &new_messages.into_any().unbind(),
            )?;
            let new_payload = clone_payload_with_attr(py, payload, "result", &new_result)?;
            return build_framework_object(
                py,
                "PromptPosthookResult",
                [("modified_payload", new_payload)],
            );
        }
        default_result(py, "PromptPosthookResult")
    }

    pub fn tool_pre_invoke(
        &self,
        py: Python<'_>,
        payload: &Bound<'_, PyAny>,
        _context: &Bound<'_, PyAny>,
    ) -> PyResult<Py<PyAny>> {
        self.process_payload_attr(py, payload, "args", "ToolPreInvokeResult")
    }

    pub fn tool_post_invoke(
        &self,
        py: Python<'_>,
        payload: &Bound<'_, PyAny>,
        _context: &Bound<'_, PyAny>,
    ) -> PyResult<Py<PyAny>> {
        self.process_payload_attr(py, payload, "result", "ToolPostInvokeResult")
    }
}

impl RegexFilterPluginCore {
    fn process_payload_attr(
        &self,
        py: Python<'_>,
        payload: &Bound<'_, PyAny>,
        attr: &str,
        result_class: &str,
    ) -> PyResult<Py<PyAny>> {
        let value = payload.getattr(attr)?;
        if value.is_none() {
            return default_result(py, result_class);
        }

        let (modified, new_value) = self.engine.process_nested(py, &value)?;
        if !modified {
            return default_result(py, result_class);
        }

        let new_payload = clone_payload_with_attr(py, payload, attr, &new_value)?;
        build_framework_object(py, result_class, [("modified_payload", new_payload)])
    }
}

fn clone_python_object<'py>(
    py: Python<'py>,
    object: &Bound<'py, PyAny>,
) -> PyResult<Bound<'py, PyAny>> {
    if object.hasattr("model_copy")? {
        object.call_method0("model_copy")
    } else {
        let copy = PyModule::import(py, "copy")?;
        copy.getattr("copy")?.call1((object,))
    }
}

fn clone_payload_with_attr(
    py: Python<'_>,
    payload: &Bound<'_, PyAny>,
    attr: &str,
    new_value: &Py<PyAny>,
) -> PyResult<Py<PyAny>> {
    let cloned = if payload.hasattr("model_copy")? {
        let kwargs = PyDict::new(py);
        let update = PyDict::new(py);
        update.set_item(attr, new_value.bind(py))?;
        kwargs.set_item("update", update)?;
        payload.call_method("model_copy", (), Some(&kwargs))?
    } else {
        let cloned = clone_python_object(py, payload)?;
        cloned.setattr(attr, new_value.bind(py))?;
        cloned
    };

    Ok(cloned.unbind())
}
