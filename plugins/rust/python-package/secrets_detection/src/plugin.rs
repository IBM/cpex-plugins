// Copyright 2026
// SPDX-License-Identifier: Apache-2.0

use cpex_framework_bridge::{build_framework_object, default_result};
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyDict, PyModule};
use pyo3_stub_gen::derive::*;

use crate::config::SecretsDetectionConfig;
use crate::object_model::copy_object_with_updates;
use crate::scanner::scan_container;

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
        let (count, redacted_args, findings) = scan_container(py, &args, &self.config)?;
        if self.should_block(count) {
            let modified_payload = if self.config.redact && count > 0 {
                copy_with_update(py, payload, [("args", redacted_args.clone().unbind())])?
            } else {
                payload.clone().unbind()
            };
            return blocked_result(
                py,
                "PromptPrehookResult",
                "Potential secrets detected in prompt arguments",
                count,
                findings.as_any(),
                modified_payload,
            );
        }

        if self.config.redact && count > 0 {
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
                    findings_metadata(py, count, findings.as_any())?
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
        let (count, redacted_result, findings) = scan_container(py, &value, &self.config)?;
        if self.should_block(count) {
            let modified_payload = if self.config.redact && count > 0 {
                copy_with_update(py, payload, [("result", redacted_result.clone().unbind())])?
            } else {
                payload.clone().unbind()
            };
            return blocked_result(
                py,
                "ToolPostInvokeResult",
                "Potential secrets detected in tool result",
                count,
                findings.as_any(),
                modified_payload,
            );
        }

        if self.config.redact && count > 0 {
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
                    findings_metadata(py, count, findings.as_any())?
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
        let (count, redacted_text, findings) = scan_container(py, &text, &self.config)?;
        if self.should_block(count) {
            let modified_payload = if self.config.redact && count > 0 {
                let modified_content =
                    copy_with_update(py, &content, [("text", redacted_text.clone().unbind())])?;
                copy_with_update(py, payload, [("content", modified_content)])?
            } else {
                payload.clone().unbind()
            };
            return blocked_result(
                py,
                "ResourcePostFetchResult",
                "Potential secrets detected in resource content",
                count,
                findings.as_any(),
                modified_payload,
            );
        }

        if self.config.redact && count > 0 {
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
                    findings_metadata(py, count, findings.as_any())?
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
    metadata.set_item("secrets_findings", sanitized_findings(py, findings)?)?;
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
    details.set_item("examples", sanitized_findings(py, findings)?)?;
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
    copy_object_with_updates(py, obj, &update_dict)
}

fn sanitized_findings<'py>(
    py: Python<'py>,
    findings: &Bound<'py, PyAny>,
) -> PyResult<Bound<'py, PyAny>> {
    let out = pyo3::types::PyList::empty(py);
    for item in findings.try_iter()? {
        let item = item?;
        if let Ok(dict) = item.cast::<PyDict>()
            && let Some(kind) = dict.get_item("type")?
        {
            let sanitized = PyDict::new(py);
            sanitized.set_item("type", kind)?;
            out.append(sanitized)?;
        }
    }
    Ok(out.into_any())
}

#[allow(dead_code)]
fn _logger_name(_py: Python<'_>) -> PyResult<Bound<'_, PyModule>> {
    PyModule::import(_py, "logging")
}
