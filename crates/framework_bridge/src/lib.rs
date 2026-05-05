// Copyright 2026
// SPDX-License-Identifier: Apache-2.0

use pyo3::prelude::*;
use pyo3::types::{PyAny, PyDict, PyModule};

fn framework_class<'py>(py: Python<'py>, name: &str) -> PyResult<Bound<'py, PyAny>> {
    PyModule::import(py, "cpex.framework")?.getattr(name)
}

pub fn build_framework_object<'py, const N: usize>(
    py: Python<'py>,
    class_name: &str,
    kwargs: [(&str, Py<PyAny>); N],
) -> PyResult<Py<PyAny>> {
    let kwargs_dict = PyDict::new(py);
    for (key, value) in kwargs {
        kwargs_dict.set_item(key, value.bind(py))?;
    }
    Ok(framework_class(py, class_name)?
        .call((), Some(&kwargs_dict))?
        .unbind())
}

pub fn default_result(py: Python<'_>, class_name: &str) -> PyResult<Py<PyAny>> {
    framework_class(py, class_name)
        .and_then(|class| class.call0())
        .map(|result| result.unbind())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pyo3::IntoPyObjectExt;
    use pyo3::types::PyDict;

    fn install_framework_module(py: Python<'_>) -> PyResult<()> {
        let framework = PyModule::from_code(
            py,
            pyo3::ffi::c_str!(
                r#"
class HookResult:
    def __init__(self, allowed=True, reason=None):
        self.allowed = allowed
        self.reason = reason

class PluginViolation:
    def __init__(self, reason, code):
        self.reason = reason
        self.code = code
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
    fn default_result_imports_classes_from_cpex_framework() {
        Python::initialize();
        Python::attach(|py| {
            install_framework_module(py).unwrap();

            let result = default_result(py, "HookResult").unwrap();
            let result = result.bind(py);

            assert!(
                result
                    .getattr("allowed")
                    .unwrap()
                    .extract::<bool>()
                    .unwrap()
            );
            assert!(result.getattr("reason").unwrap().is_none());
        });
    }

    #[test]
    fn build_framework_object_passes_keyword_arguments() {
        Python::initialize();
        Python::attach(|py| {
            install_framework_module(py).unwrap();

            let result = build_framework_object(
                py,
                "PluginViolation",
                [
                    ("reason", "blocked".into_py_any(py).unwrap()),
                    ("code", "POLICY".into_py_any(py).unwrap()),
                ],
            )
            .unwrap();
            let result = result.bind(py);

            assert_eq!(
                result
                    .getattr("reason")
                    .unwrap()
                    .extract::<String>()
                    .unwrap(),
                "blocked"
            );
            assert_eq!(
                result.getattr("code").unwrap().extract::<String>().unwrap(),
                "POLICY"
            );
        });
    }
}
