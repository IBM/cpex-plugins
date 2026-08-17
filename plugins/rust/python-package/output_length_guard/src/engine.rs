// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 ContextForge Contributors
use cpex_framework_bridge::{build_framework_object, build_framework_object_dyn, default_result};
use log::{debug, info};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyString};

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
        let tool_name = payload.getattr("name")?.extract::<String>()?;
        if result.is_none() {
            return default_result(py, "ToolPostInvokeResult");
        }
        let result_type = result.get_type().name()?.to_string();
        info!(
            "OutputLengthGuard processing tool with result type: {}",
            result_type,
        );
        if result.is_instance_of::<PyString>() {
            return self.handle_plain_string(
                py,
                payload,
                &tool_name,
                result.cast::<PyString>()?.to_str()?,
            );
        }

        // placeholder for more checks
        todo!()
    }

    fn handle_plain_string(
        &self,
        py: Python<'_>,
        payload: &Bound<'_, PyAny>,
        tool_name: &str,
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
                    ("name", tool_name.into_pyobject(py)?.into_any().unbind()),
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
