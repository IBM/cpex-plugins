// Copyright 2026
// SPDX-License-Identifier: Apache-2.0

use cpex_framework_bridge::{build_framework_object, default_result};
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyDict, PyModule};
#[cfg(feature = "stub-gen")]
use pyo3_stub_gen::derive::*;

use crate::config::SecretsDetectionConfig;
use crate::object_model::copy_object_with_updates;
use crate::scanner::{scan_container, scan_container_findings};

#[cfg_attr(feature = "stub-gen", gen_stub_pyclass)]
#[pyclass]
pub struct SecretsDetectionPluginCore {
    config: SecretsDetectionConfig,
}

#[cfg_attr(feature = "stub-gen", gen_stub_pymethods)]
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
        self.scan_payload_attr(
            py,
            payload,
            "args",
            "PromptPrehookResult",
            "Potential secrets detected in prompt arguments",
        )
    }

    pub fn tool_pre_invoke(
        &self,
        py: Python<'_>,
        payload: &Bound<'_, PyAny>,
        _context: &Bound<'_, PyAny>,
    ) -> PyResult<Py<PyAny>> {
        self.scan_payload_attr(
            py,
            payload,
            "args",
            "ToolPreInvokeResult",
            "Potential secrets detected in tool arguments",
        )
    }

    pub fn tool_post_invoke(
        &self,
        py: Python<'_>,
        payload: &Bound<'_, PyAny>,
        _context: &Bound<'_, PyAny>,
    ) -> PyResult<Py<PyAny>> {
        self.scan_payload_attr(
            py,
            payload,
            "result",
            "ToolPostInvokeResult",
            "Potential secrets detected in tool result",
        )
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
            let modified_payload = if self.config.redact {
                if has_findings(count) {
                    let modified_content =
                        copy_with_update(py, &content, [("text", redacted_text.clone().unbind())])?;
                    copy_with_update(py, payload, [("content", modified_content)])?
                } else {
                    payload.clone().unbind()
                }
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

        if self.config.redact && has_findings(count) {
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

    fn scan_payload_attr(
        &self,
        py: Python<'_>,
        payload: &Bound<'_, PyAny>,
        attr: &str,
        result_class: &str,
        block_description: &str,
    ) -> PyResult<Py<PyAny>> {
        let value = payload.getattr(attr)?;
        let (mut count, mut findings) = scan_container_findings(py, &value, &self.config)?;
        let redacted_value = if self.config.redact {
            if has_findings(count) {
                // Two-pass: avoid copy allocation on clean payloads; dirty payloads scan twice.
                let (redacted_count, redacted, redacted_findings) =
                    scan_container(py, &value, &self.config)?;
                count = redacted_count;
                findings = redacted_findings;
                Some(redacted)
            } else {
                None
            }
        } else {
            None
        };

        if self.should_block(count) {
            let modified_payload = if self.config.redact {
                if has_findings(count) {
                    let redacted = redacted_value.expect("redacted value exists");
                    copy_with_update(py, payload, [(attr, redacted.unbind())])?
                } else {
                    payload.clone().unbind()
                }
            } else {
                payload.clone().unbind()
            };
            return blocked_result(
                py,
                result_class,
                block_description,
                count,
                findings.as_any(),
                modified_payload,
            );
        }

        if self.config.redact && has_findings(count) {
            let redacted = redacted_value.expect("redacted value exists");
            let modified_payload = copy_with_update(py, payload, [(attr, redacted.unbind())])?;
            return build_framework_object(
                py,
                result_class,
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
                result_class,
                [(
                    "metadata",
                    findings_metadata(py, count, findings.as_any())?
                        .into_any()
                        .unbind(),
                )],
            );
        }

        default_result(py, result_class)
    }
}

fn redaction_metadata(py: Python<'_>, count: usize) -> PyResult<Bound<'_, PyDict>> {
    let metadata = PyDict::new(py);
    metadata.set_item("secrets_redacted", true)?;
    metadata.set_item("count", count)?;
    Ok(metadata)
}

fn has_findings(count: usize) -> bool {
    count != 0
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

#[cfg(test)]
mod tests {
    use pyo3::types::PyDict;

    use super::*;

    fn config<'py>(
        py: Python<'py>,
        block_on_detection: bool,
        redact: bool,
        min_findings_to_block: usize,
    ) -> PyResult<Bound<'py, PyDict>> {
        let config = PyDict::new(py);
        config.set_item("block_on_detection", block_on_detection)?;
        config.set_item("redact", redact)?;
        config.set_item("redaction_text", "[REDACTED]")?;
        config.set_item("min_findings_to_block", min_findings_to_block)?;
        Ok(config)
    }

    fn module<'py>(py: Python<'py>) -> PyResult<Bound<'py, PyModule>> {
        install_framework_module(py)?;
        PyModule::from_code(
            py,
            pyo3::ffi::c_str!(
                r#"
class ToolPayload:
    def __init__(self, args):
        self.name = "echo"
        self.args = args

class ResultPayload:
    def __init__(self, result):
        self.name = "echo"
        self.result = result

class Content:
    def __init__(self, text):
        self.text = text

class ResourcePayload:
    def __init__(self, text):
        self.uri = "file:///tmp/secret.txt"
        self.content = Content(text)
"#
            ),
            pyo3::ffi::c_str!("test_payloads.py"),
            pyo3::ffi::c_str!("test_payloads"),
        )
    }

    fn install_framework_module(py: Python<'_>) -> PyResult<()> {
        let framework = PyModule::from_code(
            py,
            pyo3::ffi::c_str!(
                r#"
class PluginViolation:
    def __init__(self, reason="", description="", code="", details=None):
        self.reason = reason
        self.description = description
        self.code = code
        self.details = details

class PromptPrehookResult:
    def __init__(self, continue_processing=True, violation=None, modified_payload=None, metadata=None):
        self.continue_processing = continue_processing
        self.violation = violation
        self.modified_payload = modified_payload
        self.metadata = metadata or {}

class ToolPreInvokeResult(PromptPrehookResult):
    pass

class ToolPostInvokeResult(PromptPrehookResult):
    pass

class ResourcePostFetchResult(PromptPrehookResult):
    pass
"#
            ),
            pyo3::ffi::c_str!("framework.py"),
            pyo3::ffi::c_str!("cpex.framework"),
        )?;
        let cpex = PyModule::from_code(
            py,
            pyo3::ffi::c_str!(""),
            pyo3::ffi::c_str!("cpex.py"),
            pyo3::ffi::c_str!("cpex"),
        )?;
        cpex.setattr("framework", &framework)?;
        let modules = PyModule::import(py, "sys")?
            .getattr("modules")?
            .cast_into::<PyDict>()?;
        modules.set_item("cpex", cpex)?;
        modules.set_item("cpex.framework", framework)?;
        Ok(())
    }

    #[test]
    fn tool_pre_invoke_blocks_at_threshold_and_redacts_modified_payload() {
        Python::initialize();
        Python::attach(|py| -> PyResult<()> {
            let plugin = SecretsDetectionPluginCore::new(config(py, true, true, 2)?.as_any())?;
            let module = module(py)?;
            let args = PyDict::new(py);
            args.set_item("first", "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE")?;
            args.set_item("second", "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE")?;
            let payload = module.getattr("ToolPayload")?.call1((args,))?;
            let context = PyDict::new(py);

            let result = plugin.tool_pre_invoke(py, &payload, context.as_any())?;
            let result = result.bind(py);

            assert!(!result.getattr("continue_processing")?.extract::<bool>()?);
            assert_eq!(
                result
                    .getattr("violation")?
                    .getattr("code")?
                    .extract::<String>()?,
                "SECRETS_DETECTED"
            );
            let modified_args = result
                .getattr("modified_payload")?
                .getattr("args")?
                .cast_into::<PyDict>()?;
            assert_eq!(
                modified_args
                    .get_item("first")?
                    .expect("first arg exists")
                    .extract::<String>()?,
                "AWS_ACCESS_KEY_ID=[REDACTED]"
            );

            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn tool_pre_invoke_below_threshold_reports_findings_without_blocking() {
        Python::initialize();
        Python::attach(|py| -> PyResult<()> {
            let plugin = SecretsDetectionPluginCore::new(config(py, true, false, 2)?.as_any())?;
            let module = module(py)?;
            let args = PyDict::new(py);
            args.set_item("message", "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE")?;
            let payload = module.getattr("ToolPayload")?.call1((args,))?;
            let context = PyDict::new(py);

            let result = plugin.tool_pre_invoke(py, &payload, context.as_any())?;
            let result = result.bind(py);

            assert!(result.getattr("continue_processing")?.extract::<bool>()?);
            assert!(result.getattr("violation")?.is_none());
            assert_eq!(
                result
                    .getattr("metadata")?
                    .cast_into::<PyDict>()?
                    .get_item("count")?
                    .expect("count exists")
                    .extract::<usize>()?,
                1
            );

            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn tool_pre_invoke_clean_payload_does_not_block_when_blocking_enabled() {
        Python::initialize();
        Python::attach(|py| -> PyResult<()> {
            let plugin = SecretsDetectionPluginCore::new(config(py, true, true, 1)?.as_any())?;
            let module = module(py)?;
            let args = PyDict::new(py);
            args.set_item("message", "plain text")?;
            let payload = module.getattr("ToolPayload")?.call1((args,))?;
            let context = PyDict::new(py);

            let result = plugin.tool_pre_invoke(py, &payload, context.as_any())?;
            let result = result.bind(py);

            assert!(result.getattr("continue_processing")?.extract::<bool>()?);
            assert!(result.getattr("violation")?.is_none());
            assert!(result.getattr("modified_payload")?.is_none());

            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn tool_post_invoke_redacts_without_blocking() {
        Python::initialize();
        Python::attach(|py| -> PyResult<()> {
            let plugin = SecretsDetectionPluginCore::new(config(py, false, true, 1)?.as_any())?;
            let module = module(py)?;
            let result_payload = module
                .getattr("ResultPayload")?
                .call1(("AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE",))?;
            let context = PyDict::new(py);

            let result = plugin.tool_post_invoke(py, &result_payload, context.as_any())?;
            let result = result.bind(py);

            assert!(result.getattr("continue_processing")?.extract::<bool>()?);
            assert_eq!(
                result
                    .getattr("modified_payload")?
                    .getattr("result")?
                    .extract::<String>()?,
                "AWS_ACCESS_KEY_ID=[REDACTED]"
            );

            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn resource_post_fetch_blocks_with_redacted_modified_payload() {
        Python::initialize();
        Python::attach(|py| -> PyResult<()> {
            let plugin = SecretsDetectionPluginCore::new(config(py, true, true, 1)?.as_any())?;
            let module = module(py)?;
            let payload = module
                .getattr("ResourcePayload")?
                .call1(("AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE",))?;
            let context = PyDict::new(py);

            let result = plugin.resource_post_fetch(py, &payload, context.as_any())?;
            let result = result.bind(py);

            assert!(!result.getattr("continue_processing")?.extract::<bool>()?);
            assert_eq!(
                result
                    .getattr("modified_payload")?
                    .getattr("content")?
                    .getattr("text")?
                    .extract::<String>()?,
                "AWS_ACCESS_KEY_ID=[REDACTED]"
            );

            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn resource_post_fetch_reports_findings_without_redaction_when_redact_disabled() {
        Python::initialize();
        Python::attach(|py| -> PyResult<()> {
            let plugin = SecretsDetectionPluginCore::new(config(py, false, false, 1)?.as_any())?;
            let module = module(py)?;
            let payload = module
                .getattr("ResourcePayload")?
                .call1(("AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE",))?;
            let context = PyDict::new(py);

            let result = plugin.resource_post_fetch(py, &payload, context.as_any())?;
            let result = result.bind(py);

            assert!(result.getattr("continue_processing")?.extract::<bool>()?);
            assert!(result.getattr("violation")?.is_none());
            assert!(result.getattr("modified_payload")?.is_none());
            assert_eq!(
                result
                    .getattr("metadata")?
                    .cast_into::<PyDict>()?
                    .get_item("count")?
                    .expect("count exists")
                    .extract::<usize>()?,
                1
            );

            Ok(())
        })
        .unwrap();
    }
}
