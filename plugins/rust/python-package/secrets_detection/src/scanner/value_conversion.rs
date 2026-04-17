// Copyright 2026
// SPDX-License-Identifier: Apache-2.0

use pyo3::prelude::*;
use pyo3::types::{PyAny, PyDict, PyList, PyString, PyTuple};
use serde_json::{Map, Number, Value};

use super::Finding;

pub fn py_to_value(container: &Bound<'_, PyAny>) -> PyResult<Value> {
    if container.is_none() {
        return Ok(Value::Null);
    }

    if let Ok(text) = container.extract::<String>() {
        return Ok(Value::String(text));
    }

    if let Ok(value) = container.extract::<bool>() {
        return Ok(Value::Bool(value));
    }

    if let Ok(value) = container.extract::<i64>() {
        return Ok(Value::Number(Number::from(value)));
    }

    if let Ok(value) = container.extract::<u64>() {
        return Ok(Value::Number(Number::from(value)));
    }

    if let Ok(value) = container.extract::<f64>()
        && let Some(number) = Number::from_f64(value)
    {
        return Ok(Value::Number(number));
    }

    if let Ok(dict) = container.cast::<PyDict>() {
        let mut entries = Map::with_capacity(dict.len());
        for (key, value) in dict.iter() {
            entries.insert(key.str()?.to_str()?.to_owned(), py_to_value(&value)?);
        }
        return Ok(Value::Object(entries));
    }

    if let Ok(list) = container.cast::<PyList>() {
        let mut items = Vec::with_capacity(list.len());
        for item in list.iter() {
            items.push(py_to_value(&item)?);
        }
        return Ok(Value::Array(items));
    }

    if let Ok(tuple) = container.cast::<PyTuple>() {
        let mut items = Vec::with_capacity(tuple.len());
        for item in tuple.iter() {
            items.push(py_to_value(&item)?);
        }
        return Ok(Value::Array(items));
    }

    if let Ok(model_dump) = container.call_method0("model_dump") {
        return py_to_value(&model_dump);
    }

    if let Ok(state) = container.getattr("__dict__") {
        return py_to_value(&state);
    }

    Ok(Value::Null)
}

pub fn value_to_py<'py>(py: Python<'py>, value: &Value) -> PyResult<Bound<'py, PyAny>> {
    match value {
        Value::Null => Ok(py.None().into_bound(py)),
        Value::Bool(value) => Ok(value.into_pyobject(py)?.to_owned().into_any()),
        Value::Number(value) => {
            if let Some(value) = value.as_i64() {
                Ok(value.into_pyobject(py)?.to_owned().into_any())
            } else if let Some(value) = value.as_u64() {
                Ok(value.into_pyobject(py)?.to_owned().into_any())
            } else if let Some(value) = value.as_f64() {
                Ok(value.into_pyobject(py)?.to_owned().into_any())
            } else {
                Ok(py.None().into_bound(py))
            }
        }
        Value::String(value) => Ok(PyString::new(py, value).into_any()),
        Value::Array(items) => {
            let list = PyList::empty(py);
            for item in items {
                list.append(value_to_py(py, item)?)?;
            }
            Ok(list.into_any())
        }
        Value::Object(entries) => {
            let dict = PyDict::new(py);
            for (key, value) in entries {
                dict.set_item(key, value_to_py(py, value)?)?;
            }
            Ok(dict.into_any())
        }
    }
}

pub fn findings_to_pylist<'py>(
    py: Python<'py>,
    findings: &[Finding],
) -> PyResult<Bound<'py, PyList>> {
    let py_findings = PyList::empty(py);
    for finding in findings {
        let finding_dict = PyDict::new(py);
        finding_dict.set_item("type", &finding.pii_type)?;
        py_findings.append(finding_dict)?;
    }
    Ok(py_findings)
}
