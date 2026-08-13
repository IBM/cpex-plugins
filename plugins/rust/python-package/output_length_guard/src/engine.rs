// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 ContextForge Contributors
use cpex_framework_bridge::{build_framework_object, default_result};
use log::{debug, info};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyModule, PyString};

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
    ) -> PyResult<Py<PyAny>> {
        debug!("Output Length Guard: tool_post_invoke called");
        let result = payload.getattr("result")?;
        if result.is_none() {
            return default_result(py, "ToolPostInvokeResult");
        }
        let result_type = result.get_type().name()?.to_string();
        info!(
            "OutputLengthGuard processing tool with result type: {}",
            result_type,
        );
        if result.is_instance_of::<PyString>() {
            return self.handle_plain_string(py, result.cast::<PyString>()?.to_str()?);
        }

        /*NestedStageSpec {
            source_attr: "result",
            stage: "tool_post_invoke",
            result_class: "ToolPostInvokeResult",
            subject_attr: "name",
            violation_reason: "PII detected in tool result",
            violation_description: "Sensitive information detected in tool result",
            violation_code: "PII_DETECTED_IN_TOOL_RESULT",
        }, */
        // TODO: Implement tool post-invoke logic
        /* let module = PyModule::import(py, "cpex.framework")?;
        let result_class = module.getattr("ToolPostInvokeResult")?;
        let kwargs = PyDict::new(py);
        kwargs.set_item("continue_processing", true)?;
        Ok(result_class.call((), Some(&kwargs))?.unbind()) */
        todo!()
    }

    fn handle_plain_string(&self, py: Python<'_>, result: &str) -> PyResult<Py<PyAny>> {
        let new_text = handle_text(py, result, &self.config)?;
        if let Some(violation) = new_text.violation {
            return self.build_violation_object(py, violation);
        }
        if text_result
        /*  if let Some(violation) = handled.violation {
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
        build_framework_object

                Ok(ToolPostInvokeResult {
                    continue_processing: true,
                    modified_payload: None,
                    violation: None,
                    metadata: Some(handled.metadata),
                }) */
        todo!()
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
