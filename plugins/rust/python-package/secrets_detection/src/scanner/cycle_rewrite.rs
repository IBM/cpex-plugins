// Copyright 2026
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashSet;

use pyo3::prelude::*;
use pyo3::types::{PyAny, PyDict, PyFrozenSet, PyList, PySet, PyTuple};

pub fn replace_placeholder_references(
    py: Python<'_>,
    value: &Bound<'_, PyAny>,
    placeholder: &Bound<'_, PyAny>,
    replacement: &Bound<'_, PyAny>,
    seen: &mut HashSet<usize>,
) -> PyResult<bool> {
    let object_id = value.as_ptr() as usize;
    if !seen.insert(object_id) {
        return Ok(false);
    }

    if let Ok(dict) = value.cast::<PyDict>() {
        let keys: Vec<Py<PyAny>> = dict.keys().iter().map(|key| key.unbind()).collect();
        let mut replaced_any = false;
        for key in keys {
            let key = key.bind(py);
            let item = dict.get_item(key)?.expect("key exists");
            if item.is(placeholder) {
                dict.set_item(key, replacement)?;
                replaced_any = true;
            } else {
                replaced_any |=
                    replace_placeholder_references(py, &item, placeholder, replacement, seen)?;
            }
        }
        return Ok(replaced_any);
    }

    if let Ok(list) = value.cast::<PyList>() {
        let mut replaced_any = false;
        for index in 0..list.len() {
            let item = list.get_item(index)?;
            if item.is(placeholder) {
                list.set_item(index, replacement)?;
                replaced_any = true;
            } else {
                replaced_any |=
                    replace_placeholder_references(py, &item, placeholder, replacement, seen)?;
            }
        }
        return Ok(replaced_any);
    }

    if let Ok(tuple) = value.cast::<PyTuple>() {
        let mut replaced_any = false;
        for item in tuple.iter() {
            replaced_any |=
                replace_placeholder_references(py, &item, placeholder, replacement, seen)?;
        }
        return Ok(replaced_any);
    }

    replace_placeholder_in_direct_object_state(py, value, placeholder, replacement, seen)
}

fn replace_placeholder_in_direct_object_state(
    py: Python<'_>,
    value: &Bound<'_, PyAny>,
    placeholder: &Bound<'_, PyAny>,
    replacement: &Bound<'_, PyAny>,
    seen: &mut HashSet<usize>,
) -> PyResult<bool> {
    let mut replaced_any = false;

    if let Ok(dict_state) = value.getattr("__dict__")
        && let Ok(dict_state) = dict_state.cast::<PyDict>()
    {
        let keys: Vec<Py<PyAny>> = dict_state.keys().iter().map(|key| key.unbind()).collect();
        for key in keys {
            let key = key.bind(py);
            let item = dict_state.get_item(key)?.expect("key exists");
            if item.is(placeholder) {
                dict_state.set_item(key, replacement)?;
                replaced_any = true;
            } else {
                replaced_any |=
                    replace_placeholder_references(py, &item, placeholder, replacement, seen)?;
            }
        }
    }

    let builtins = py.import("builtins")?;
    let object_type = builtins.getattr("object")?;
    let slot_names = PyList::empty(py);
    if let Ok(mro) = value.get_type().getattr("__mro__")?.cast::<PyTuple>() {
        for class_obj in mro.iter() {
            let Ok(slots) = class_obj.getattr("__slots__") else {
                continue;
            };
            append_slot_names(&slot_names, &slots)?;
        }
    }

    for slot_name in slot_names.iter() {
        let slot_name = slot_name.extract::<String>()?;
        if slot_name == "__dict__" || slot_name == "__weakref__" {
            continue;
        }
        let Ok(item) = value.getattr(&slot_name) else {
            continue;
        };
        if item.is(placeholder) {
            object_type.call_method1("__setattr__", (value, slot_name.as_str(), replacement))?;
            replaced_any = true;
        } else {
            replaced_any |=
                replace_placeholder_references(py, &item, placeholder, replacement, seen)?;
        }
    }

    Ok(replaced_any)
}

fn append_slot_names(slot_names: &Bound<'_, PyList>, slots: &Bound<'_, PyAny>) -> PyResult<()> {
    if let Ok(name) = slots.extract::<String>() {
        slot_names.append(name)?;
        return Ok(());
    }

    if let Ok(mapping) = slots.cast::<PyDict>() {
        for (name, _) in mapping.iter() {
            slot_names.append(name)?;
        }
        return Ok(());
    }

    if let Ok(tuple) = slots.cast::<PyTuple>() {
        for name in tuple.iter() {
            slot_names.append(name)?;
        }
        return Ok(());
    }

    if let Ok(list) = slots.cast::<PyList>() {
        for name in list.iter() {
            slot_names.append(name)?;
        }
        return Ok(());
    }

    if let Ok(set) = slots.cast::<PySet>() {
        for name in set.iter() {
            slot_names.append(name)?;
        }
        return Ok(());
    }

    if let Ok(set) = slots.cast::<PyFrozenSet>() {
        for name in set.iter() {
            slot_names.append(name)?;
        }
        return Ok(());
    }

    if let Ok(iter) = slots.try_iter() {
        for name in iter {
            slot_names.append(name?)?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;

    use pyo3::types::{PyModule, PyString, PyTuple};

    use super::*;
    use crate::config::SecretsDetectionConfig;
    use crate::scanner::scan_container;

    #[test]
    fn tuple_rewrite_does_not_reapply_clean_object_state() {
        Python::initialize();
        Python::attach(|py| -> PyResult<()> {
            let code = CString::new(
                r#"
class CleanObject:
    calls = 0

    def __init__(self):
        self.value = "clean"

    def model_dump(self):
        type(self).calls += 1
        if type(self).calls > 1:
            raise RuntimeError("model_dump should not rerun")
        return {"value": self.value}
"#,
            )
            .unwrap();
            let module =
                PyModule::from_code(py, code.as_c_str(), c"test_module.py", c"test_module")?;
            let instance = module.getattr("CleanObject")?.call0()?;
            let tuple = PyTuple::new(
                py,
                [
                    instance.clone().into_any().unbind(),
                    PyString::new(
                        py,
                        "AWS_SECRET_ACCESS_KEY=FAKESecretAccessKeyForTestingEXAMPLE0000",
                    )
                    .into_any()
                    .unbind(),
                ],
            )?;
            let config = SecretsDetectionConfig {
                redact: true,
                redaction_text: "[REDACTED]".to_string(),
                ..Default::default()
            };

            let (count, redacted, _) = scan_container(py, &tuple.clone().into_any(), &config)?;
            let redacted_tuple = redacted.cast::<PyTuple>()?;

            assert_eq!(count, 1);
            assert_eq!(instance.get_type().getattr("calls")?.extract::<usize>()?, 1);
            assert_eq!(
                redacted_tuple
                    .get_item(0)?
                    .getattr("value")?
                    .extract::<String>()?,
                "clean"
            );
            assert_eq!(
                redacted_tuple.get_item(1)?.extract::<String>()?,
                "[REDACTED]"
            );

            Ok(())
        })
        .unwrap();
    }
}
