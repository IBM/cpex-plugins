// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
//
// Rust-owned regex filter plugin core.

use cpex_framework_bridge::{build_framework_object, default_result};
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyDict, PyList};
use pyo3_stub_gen::derive::*;

use crate::SearchReplacePluginRust;

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

        let mut changed = false;
        for message in messages.iter() {
            let Ok(content) = message.getattr("content") else {
                continue;
            };
            let Ok(text_obj) = content.getattr("text") else {
                continue;
            };
            let Ok(text) = text_obj.extract::<String>() else {
                continue;
            };
            let replaced = self.engine.apply_patterns(&text);
            if replaced != text {
                content.setattr("text", replaced)?;
                changed = true;
            }
        }

        if changed {
            return build_framework_object(
                py,
                "PromptPosthookResult",
                [("modified_payload", payload.clone().unbind())],
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

        payload.setattr(attr, new_value.bind(py))?;
        build_framework_object(
            py,
            result_class,
            [("modified_payload", payload.clone().unbind())],
        )
    }
}
