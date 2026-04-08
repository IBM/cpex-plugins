// Copyright 2026
// SPDX-License-Identifier: Apache-2.0

use cpex_framework_bridge::{build_framework_object, default_result};
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyDict, PyModule};
use pyo3_stub_gen::derive::*;

use crate::config::SecretsDetectionConfig;
use crate::scan_container;

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
            PyDict::new(py).into_any()
        } else {
            args
        };
        let (count, redacted, findings) = scan_container(py, &source, &self.config)?;
        if self.should_block(count) {
            return blocked_result(
                py,
                "PromptPrehookResult",
                "Potential secrets detected in prompt arguments",
                count,
                findings.as_any(),
            );
        }

        if self.config.redact && count > 0 {
            payload.setattr("args", &redacted)?;
            return build_framework_object(
                py,
                "PromptPrehookResult",
                [
                    ("modified_payload", payload.clone().unbind()),
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
        let (count, redacted, findings) = scan_container(py, &value, &self.config)?;
        if self.should_block(count) {
            return blocked_result(
                py,
                "ToolPostInvokeResult",
                "Potential secrets detected in tool result",
                count,
                findings.as_any(),
            );
        }

        if self.config.redact && count > 0 {
            payload.setattr("result", &redacted)?;
            return build_framework_object(
                py,
                "ToolPostInvokeResult",
                [
                    ("modified_payload", payload.clone().unbind()),
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
        let (count, redacted, findings) = scan_container(py, &text, &self.config)?;
        if self.should_block(count) {
            return blocked_result(
                py,
                "ResourcePostFetchResult",
                "Potential secrets detected in resource content",
                count,
                findings.as_any(),
            );
        }

        if self.config.redact && count > 0 {
            content.setattr("text", &redacted)?;
            return build_framework_object(
                py,
                "ResourcePostFetchResult",
                [
                    ("modified_payload", payload.clone().unbind()),
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
        ],
    )
}

#[allow(dead_code)]
fn _logger_name(_py: Python<'_>) -> PyResult<Bound<'_, PyModule>> {
    PyModule::import(_py, "logging")
}
