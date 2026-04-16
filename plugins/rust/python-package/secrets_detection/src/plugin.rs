// Copyright 2026
// SPDX-License-Identifier: Apache-2.0

use cpex_framework_bridge::{build_framework_object, default_result};
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyDict, PyModule};
use pyo3_stub_gen::derive::*;
use serde_json::Value;

use crate::config::SecretsDetectionConfig;
use crate::scanner::{findings_to_pylist, py_to_value, scan_value, value_to_py};

#[gen_stub_pyclass]
#[pyclass]
pub struct SecretsDetectionPluginCore {
    config: SecretsDetectionConfig,
}

#[gen_stub_pymethods]
#[pymethods]
impl SecretsDetectionPluginCore {
    #[new]
    pub fn new(config: &Bound<'_, PyAny>) -> PyResult<Self> {
        Ok(Self {
            config: SecretsDetectionConfig::from_py_any(config)?,
        })
    }

    pub fn prompt_pre_fetch(
        &self,
        py: Python<'_>,
        payload: &Bound<'_, PyAny>,
        _context: &Bound<'_, PyAny>,
    ) -> PyResult<Py<PyAny>> {
        let args = payload.getattr("args")?;
        let source = if args.is_none() {
            Value::Object(serde_json::Map::new())
        } else {
            py_to_value(&args)?
        };
        let (count, redacted, findings) = scan_value(&source, &self.config);
        let py_findings = findings_to_pylist(py, &findings)?;
        if self.should_block(count) {
            return blocked_result(
                py,
                "PromptPrehookResult",
                "Potential secrets detected in prompt arguments",
                count,
                py_findings.as_any(),
                payload.clone().unbind(),
            );
        }

        if self.config.redact && count > 0 {
            let redacted_args = value_to_py(py, &redacted)?;
            let modified_payload =
                copy_with_update(py, payload, [("args", redacted_args.unbind())])?;
            return build_framework_object(
                py,
                "PromptPrehookResult",
                [
                    ("modified_payload", modified_payload),
                    (
                        "metadata",
                        redaction_metadata(py, count)?.into_any().unbind(),
                    ),
                ],
            );
        }

        if count > 0 {
            return build_framework_object(
                py,
                "PromptPrehookResult",
                [(
                    "metadata",
                    findings_metadata(py, count, py_findings.as_any())?
                        .into_any()
                        .unbind(),
                )],
            );
        }

        default_result(py, "PromptPrehookResult")
    }

    pub fn tool_post_invoke(
        &self,
        py: Python<'_>,
        payload: &Bound<'_, PyAny>,
        _context: &Bound<'_, PyAny>,
    ) -> PyResult<Py<PyAny>> {
        let value = payload.getattr("result")?;
        let source = py_to_value(&value)?;
        let (count, redacted, findings) = scan_value(&source, &self.config);
        let py_findings = findings_to_pylist(py, &findings)?;
        if self.should_block(count) {
            return blocked_result(
                py,
                "ToolPostInvokeResult",
                "Potential secrets detected in tool result",
                count,
                py_findings.as_any(),
                payload.clone().unbind(),
            );
        }

        if self.config.redact && count > 0 {
            let redacted_result = value_to_py(py, &redacted)?;
            let modified_payload =
                copy_with_update(py, payload, [("result", redacted_result.unbind())])?;
            return build_framework_object(
                py,
                "ToolPostInvokeResult",
                [
                    ("modified_payload", modified_payload),
                    (
                        "metadata",
                        redaction_metadata(py, count)?.into_any().unbind(),
                    ),
                ],
            );
        }

        if count > 0 {
            return build_framework_object(
                py,
                "ToolPostInvokeResult",
                [(
                    "metadata",
                    findings_metadata(py, count, py_findings.as_any())?
                        .into_any()
                        .unbind(),
                )],
            );
        }

        default_result(py, "ToolPostInvokeResult")
    }

    pub fn resource_post_fetch(
        &self,
        py: Python<'_>,
        payload: &Bound<'_, PyAny>,
        _context: &Bound<'_, PyAny>,
    ) -> PyResult<Py<PyAny>> {
        let content = payload.getattr("content")?;
        let Ok(text) = content.getattr("text") else {
            return default_result(py, "ResourcePostFetchResult");
        };
        let source = py_to_value(&text)?;
        let (count, redacted, findings) = scan_value(&source, &self.config);
        let py_findings = findings_to_pylist(py, &findings)?;
        if self.should_block(count) {
            return blocked_result(
                py,
                "ResourcePostFetchResult",
                "Potential secrets detected in resource content",
                count,
                py_findings.as_any(),
                payload.clone().unbind(),
            );
        }

        if self.config.redact && count > 0 {
            let redacted_text = value_to_py(py, &redacted)?;
            let modified_content =
                copy_with_update(py, &content, [("text", redacted_text.unbind())])?;
            let modified_payload = copy_with_update(py, payload, [("content", modified_content)])?;
            return build_framework_object(
                py,
                "ResourcePostFetchResult",
                [
                    ("modified_payload", modified_payload),
                    (
                        "metadata",
                        redaction_metadata(py, count)?.into_any().unbind(),
                    ),
                ],
            );
        }

        if count > 0 {
            return build_framework_object(
                py,
                "ResourcePostFetchResult",
                [(
                    "metadata",
                    findings_metadata(py, count, py_findings.as_any())?
                        .into_any()
                        .unbind(),
                )],
            );
        }

        default_result(py, "ResourcePostFetchResult")
    }
}

impl SecretsDetectionPluginCore {
    fn should_block(&self, count: usize) -> bool {
        self.config.block_on_detection && count >= self.config.min_findings_to_block
    }
}

fn redaction_metadata(py: Python<'_>, count: usize) -> PyResult<Bound<'_, PyDict>> {
    let metadata = PyDict::new(py);
    metadata.set_item("secrets_redacted", true)?;
    metadata.set_item("count", count)?;
    Ok(metadata)
}

fn findings_metadata<'py>(
    py: Python<'py>,
    count: usize,
    findings: &Bound<'py, PyAny>,
) -> PyResult<Bound<'py, PyDict>> {
    let metadata = PyDict::new(py);
    metadata.set_item("secrets_findings", findings)?;
    metadata.set_item("count", count)?;
    Ok(metadata)
}

fn blocked_result(
    py: Python<'_>,
    result_class: &str,
    description: &str,
    count: usize,
    findings: &Bound<'_, PyAny>,
    payload: Py<PyAny>,
) -> PyResult<Py<PyAny>> {
    let details = PyDict::new(py);
    details.set_item("count", count)?;
    details.set_item("examples", findings)?;
    build_framework_object(
        py,
        result_class,
        [
            (
                "continue_processing",
                false.into_pyobject(py)?.to_owned().into_any().unbind(),
            ),
            (
                "violation",
                build_framework_object(
                    py,
                    "PluginViolation",
                    [
                        (
                            "reason",
                            "Secrets detected".into_pyobject(py)?.into_any().unbind(),
                        ),
                        (
                            "description",
                            description.into_pyobject(py)?.into_any().unbind(),
                        ),
                        (
                            "code",
                            "SECRETS_DETECTED".into_pyobject(py)?.into_any().unbind(),
                        ),
                        ("details", details.into_any().unbind()),
                    ],
                )?,
            ),
            ("modified_payload", payload),
        ],
    )
}

fn copy_with_update<const N: usize>(
    py: Python<'_>,
    obj: &Bound<'_, PyAny>,
    updates: [(&str, Py<PyAny>); N],
) -> PyResult<Py<PyAny>> {
    let update_dict = PyDict::new(py);
    for (key, value) in updates {
        update_dict.set_item(key, value.bind(py))?;
    }

    if obj.hasattr("model_copy")? {
        let kwargs = PyDict::new(py);
        kwargs.set_item("update", &update_dict)?;
        return obj
            .call_method("model_copy", (), Some(&kwargs))
            .map(|value| value.unbind());
    }

    let merged = if let Ok(model_dump) = obj.call_method0("model_dump") {
        model_dump.cast_into::<PyDict>()?
    } else if let Ok(state) = obj.getattr("__dict__") {
        state.cast_into::<PyDict>()?
    } else {
        let kwargs = PyDict::new(py);
        for (key, value) in update_dict.iter() {
            kwargs.set_item(key, value)?;
        }
        return obj
            .get_type()
            .call((), Some(&kwargs))
            .map(|value| value.unbind());
    };

    let kwargs = PyDict::new(py);
    for (key, value) in merged.iter() {
        kwargs.set_item(key, value)?;
    }
    for (key, value) in update_dict.iter() {
        kwargs.set_item(key, value)?;
    }

    obj.get_type()
        .call((), Some(&kwargs))
        .map(|value| value.unbind())
}

#[allow(dead_code)]
fn _logger_name(_py: Python<'_>) -> PyResult<Bound<'_, PyModule>> {
    PyModule::import(_py, "logging")
}
