// Copyright 2026
// SPDX-License-Identifier: Apache-2.0

use pyo3::prelude::*;
use pyo3::types::{PyAny, PyDict, PyModule};

fn framework_class<'py>(py: Python<'py>, name: &str) -> PyResult<Bound<'py, PyAny>> {
    PyModule::import(py, "mcpgateway.plugins.framework")?.getattr(name)
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
