// Copyright 2026
// SPDX-License-Identifier: Apache-2.0

use pyo3::prelude::*;
use pyo3::types::{PyAny, PyDict, PyFrozenSet, PyList, PySet, PyString, PyTuple};

pub struct InspectedObjectState<'py> {
    pub rebuild_state: Option<Bound<'py, PyDict>>,
    pub serialized_state: Option<Bound<'py, PyAny>>,
    pub scan_state: Option<Bound<'py, PyDict>>,
}

pub fn inspect_object_state<'py>(
    py: Python<'py>,
    container: &Bound<'py, PyAny>,
) -> PyResult<InspectedObjectState<'py>> {
    inspect_object_state_inner(py, container, true)
}

pub(crate) fn inspect_object_state_without_model_dump<'py>(
    py: Python<'py>,
    container: &Bound<'py, PyAny>,
) -> PyResult<InspectedObjectState<'py>> {
    inspect_object_state_inner(py, container, false)
}

fn inspect_object_state_inner<'py>(
    py: Python<'py>,
    container: &Bound<'py, PyAny>,
    include_model_dump: bool,
) -> PyResult<InspectedObjectState<'py>> {
    let mut mappings = MappingStateAccumulator::new(py);
    let mut serialized_state = None;

    if include_model_dump && let Ok(model_dump) = container.call_method0("model_dump") {
        if let Ok(model_state) = model_dump.cast::<PyDict>() {
            serialized_state = Some(model_state.clone().into_any());
            if dict_has_only_exact_string_keys(model_state) {
                mappings.push(model_state)?;
            }
        } else if !model_dump.is(container) {
            serialized_state = Some(model_dump);
        }
    }

    let mut scan_state = None;
    if let Ok(dict_state) = container.getattr("__dict__")
        && let Ok(dict_state) = dict_state.cast::<PyDict>()
    {
        let split_state = split_dict_state(py, dict_state)?;
        if let Some(dict_state) = split_state.string_keys {
            mappings.push(&dict_state)?;
        }
        scan_state = split_state.non_string_keys;
    }

    if let Some(slot_state) = extract_slot_state(py, container)? {
        mappings.push(&slot_state)?;
    }

    Ok(InspectedObjectState {
        rebuild_state: mappings.finish(),
        serialized_state,
        scan_state,
    })
}

pub fn copy_object_with_updates(
    py: Python<'_>,
    obj: &Bound<'_, PyAny>,
    updates: &Bound<'_, PyDict>,
) -> PyResult<Py<PyAny>> {
    if obj.hasattr("model_copy")? {
        let kwargs = PyDict::new(py);
        kwargs.set_item("update", updates)?;
        return obj
            .call_method("model_copy", (), Some(&kwargs))
            .map(|value| value.unbind());
    }

    if let Some(existing_state) = inspect_object_state(py, obj)?.rebuild_state {
        let merged = PyDict::new(py);
        merge_state_into(&merged, &existing_state)?;
        merge_state_into(&merged, updates)?;
        return rebuild_object_from_state(py, obj, &merged.into_any()).map(|value| value.unbind());
    }

    let kwargs = PyDict::new(py);
    merge_state_into(&kwargs, updates)?;
    obj.get_type()
        .call((), Some(&kwargs))
        .map(|value| value.unbind())
}

pub fn rebuild_object_from_state<'py>(
    py: Python<'py>,
    container: &Bound<'py, PyAny>,
    redacted_state: &Bound<'py, PyAny>,
) -> PyResult<Bound<'py, PyAny>> {
    if container.hasattr("model_copy")? {
        let kwargs = PyDict::new(py);
        if let Ok(update_dict) = redacted_state.cast::<PyDict>() {
            kwargs.set_item("update", update_dict)?;
        } else if container.hasattr("root")? {
            let update_dict = PyDict::new(py);
            update_dict.set_item("root", redacted_state)?;
            kwargs.set_item("update", update_dict)?;
        } else {
            return Ok(redacted_state.clone());
        }
        return container.call_method("model_copy", (), Some(&kwargs));
    }

    let cloned = prepare_rebuild_target(py, container)?;
    apply_object_state(py, &cloned, redacted_state)?;
    Ok(cloned)
}

pub fn prepare_rebuild_target<'py>(
    py: Python<'py>,
    container: &Bound<'py, PyAny>,
) -> PyResult<Bound<'py, PyAny>> {
    let builtins = py.import("builtins")?;
    let object_type = builtins.getattr("object")?;
    blank_instance(&object_type, container)
}

pub fn apply_object_state(
    py: Python<'_>,
    target: &Bound<'_, PyAny>,
    redacted_state: &Bound<'_, PyAny>,
) -> PyResult<()> {
    let state = redacted_state.cast::<PyDict>()?;
    let builtins = py.import("builtins")?;
    let object_type = builtins.getattr("object")?;
    for (key, value) in state.iter() {
        set_dict_or_attr_without_hooks(&object_type, target, &key.extract::<String>()?, &value)?;
    }
    Ok(())
}

pub fn apply_extra_dict_state(
    py: Python<'_>,
    target: &Bound<'_, PyAny>,
    updates: &Bound<'_, PyDict>,
) -> PyResult<()> {
    let dict = target.getattr("__dict__")?.cast_into::<PyDict>()?;
    let builtins = py.import("builtins")?;
    let object_type = builtins.getattr("object")?;
    for (key, value) in updates.iter() {
        if key.is_exact_instance_of::<PyString>() {
            set_dict_or_attr_without_hooks(
                &object_type,
                target,
                &key.extract::<String>()?,
                &value,
            )?;
        } else {
            dict.set_item(key, value)?;
        }
    }
    Ok(())
}

fn blank_instance<'py>(
    object_type: &Bound<'py, PyAny>,
    container: &Bound<'py, PyAny>,
) -> PyResult<Bound<'py, PyAny>> {
    object_type.call_method1("__new__", (container.get_type(),))
}

fn set_attr_without_hooks(
    object_type: &Bound<'_, PyAny>,
    target: &Bound<'_, PyAny>,
    name: &str,
    value: &Bound<'_, PyAny>,
) -> PyResult<()> {
    object_type.call_method1("__setattr__", (target, name, value))?;
    Ok(())
}

fn set_dict_or_attr_without_hooks(
    object_type: &Bound<'_, PyAny>,
    target: &Bound<'_, PyAny>,
    name: &str,
    value: &Bound<'_, PyAny>,
) -> PyResult<()> {
    if name.starts_with("__")
        && name.ends_with("__")
        && let Ok(dict) = target.getattr("__dict__")
        && let Ok(dict) = dict.cast_into::<PyDict>()
    {
        // Keep dunder keys as inert instance-dict entries instead of routing
        // them through object.__setattr__ on a blank reconstructed object.
        dict.set_item(name, value)?;
        return Ok(());
    }
    set_attr_without_hooks(object_type, target, name, value)
}

fn extract_slot_state<'py>(
    py: Python<'py>,
    container: &Bound<'py, PyAny>,
) -> PyResult<Option<Bound<'py, PyDict>>> {
    let slot_names = PyList::empty(py);
    let mut saw_slots = false;

    if let Ok(mro) = container.get_type().getattr("__mro__")?.cast::<PyTuple>() {
        for class_obj in mro.iter() {
            let Ok(slots) = class_obj.getattr("__slots__") else {
                continue;
            };
            saw_slots = true;
            append_slot_names(&slot_names, &slots)?;
        }
    }

    if !saw_slots {
        return Ok(None);
    }

    let slot_state = PyDict::new(py);
    for slot_name in slot_names.iter() {
        let slot_name = slot_name.extract::<String>()?;
        if slot_name == "__dict__" || slot_name == "__weakref__" {
            continue;
        }
        if let Ok(value) = container.getattr(&slot_name) {
            slot_state.set_item(slot_name, value)?;
        }
    }

    if slot_state.is_empty() {
        Ok(None)
    } else {
        Ok(Some(slot_state))
    }
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

fn merge_state_into(target: &Bound<'_, PyDict>, source: &Bound<'_, PyDict>) -> PyResult<()> {
    for (key, value) in source.iter() {
        target.set_item(key, value)?;
    }
    Ok(())
}

pub fn dict_has_only_exact_string_keys(dict: &Bound<'_, PyDict>) -> bool {
    dict.iter()
        .all(|(key, _)| key.is_exact_instance_of::<PyString>())
}

struct SplitDictState<'py> {
    string_keys: Option<Bound<'py, PyDict>>,
    non_string_keys: Option<Bound<'py, PyDict>>,
}

fn split_dict_state<'py>(
    py: Python<'py>,
    dict: &Bound<'py, PyDict>,
) -> PyResult<SplitDictState<'py>> {
    if dict_has_only_exact_string_keys(dict) {
        return Ok(SplitDictState {
            string_keys: Some(dict.clone()),
            non_string_keys: None,
        });
    }

    let string_state = PyDict::new(py);
    let non_string_state = PyDict::new(py);
    for (key, value) in dict.iter() {
        if key.is_exact_instance_of::<PyString>() {
            string_state.set_item(key, value)?;
        } else {
            non_string_state.set_item(key, value)?;
        }
    }

    let string_state = if string_state.is_empty() {
        None
    } else {
        Some(string_state)
    };
    let non_string_state = if non_string_state.is_empty() {
        None
    } else {
        Some(non_string_state)
    };
    Ok(SplitDictState {
        string_keys: string_state,
        non_string_keys: non_string_state,
    })
}

struct MappingStateAccumulator<'py> {
    py: Python<'py>,
    state: Option<Bound<'py, PyDict>>,
    source_count: usize,
}

impl<'py> MappingStateAccumulator<'py> {
    fn new(py: Python<'py>) -> Self {
        Self {
            py,
            state: None,
            source_count: 0,
        }
    }

    fn push(&mut self, source: &Bound<'py, PyDict>) -> PyResult<()> {
        match self.source_count {
            0 => {
                self.state = Some(source.clone());
            }
            1 => {
                let merged = PyDict::new(self.py);
                merge_state_into(&merged, self.state.as_ref().expect("first source exists"))?;
                merge_state_into(&merged, source)?;
                self.state = Some(merged);
            }
            _ => {
                merge_state_into(self.state.as_ref().expect("merged state exists"), source)?;
            }
        }
        self.source_count += 1;
        Ok(())
    }

    fn finish(self) -> Option<Bound<'py, PyDict>> {
        self.state
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;

    use pyo3::types::{PyFrozenSet, PyList, PyModule, PySet, PyString, PyTuple};

    use super::*;

    #[test]
    fn inspect_object_state_merges_model_dict_regular_dict_and_slots() {
        Python::initialize();
        Python::attach(|py| -> PyResult<()> {
            let code = CString::new(
                r#"
class StateObject:
    __slots__ = ("slot_value", "__dict__")

    def __init__(self):
        self.dict_value = "dict"
        self.slot_value = "slot"

    def model_dump(self):
        return {"model_value": "model"}
"#,
            )
            .unwrap();
            let module =
                PyModule::from_code(py, code.as_c_str(), c"object_test.py", c"object_test")?;
            let instance = module.getattr("StateObject")?.call0()?;

            let inspected = inspect_object_state(py, &instance)?;
            let state = inspected.rebuild_state.expect("state exists");

            assert_eq!(
                state
                    .get_item("model_value")?
                    .unwrap()
                    .extract::<String>()?,
                "model"
            );
            assert_eq!(
                state.get_item("dict_value")?.unwrap().extract::<String>()?,
                "dict"
            );
            assert_eq!(
                state.get_item("slot_value")?.unwrap().extract::<String>()?,
                "slot"
            );
            assert!(inspected.serialized_state.is_some());
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn inspect_root_model_exposes_rebuild_and_serialized_state() {
        Python::initialize();
        Python::attach(|py| -> PyResult<()> {
            let code = CString::new(
                r#"
class RootObject:
    def __init__(self):
        self.root = ["secret"]

    def model_dump(self):
        return self.root
"#,
            )
            .unwrap();
            let module = PyModule::from_code(py, code.as_c_str(), c"root_test.py", c"root_test")?;
            let instance = module.getattr("RootObject")?.call0()?;

            let inspected = inspect_object_state(py, &instance)?;

            assert!(inspected.rebuild_state.is_some());
            assert!(inspected.serialized_state.is_some());
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn rebuild_object_from_state_uses_model_copy_root_and_passthrough_branches() {
        Python::initialize();
        Python::attach(|py| -> PyResult<()> {
            let code = CString::new(
                r#"
class CopyObject:
    def __init__(self, root=None, value=None):
        self.root = root
        self.value = value

    def model_copy(self, update=None):
        update = update or {}
        return CopyObject(update.get("root", self.root), update.get("value", self.value))

class CopyNoRoot:
    def model_copy(self, update=None):
        return self
"#,
            )
            .unwrap();
            let module = PyModule::from_code(py, code.as_c_str(), c"copy_test.py", c"copy_test")?;
            let instance = module
                .getattr("CopyObject")?
                .call((), Some(&PyDict::new(py)))?;
            instance.setattr("root", "old")?;

            let root_copy =
                rebuild_object_from_state(py, &instance, PyString::new(py, "new").as_any())?;
            assert_eq!(root_copy.getattr("root")?.extract::<String>()?, "new");

            let plain = module.getattr("CopyNoRoot")?.call0()?;
            let passthrough =
                rebuild_object_from_state(py, &plain, PyString::new(py, "raw").as_any())?;
            assert_eq!(passthrough.extract::<String>()?, "raw");
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn copy_object_with_updates_rebuilds_existing_state_and_kwargs_only_objects() {
        Python::initialize();
        Python::attach(|py| -> PyResult<()> {
            let code = CString::new(
                r#"
class ExistingState:
    def __init__(self, value):
        self.value = value

class KwargsOnly:
    def __init__(self, value):
        self.value = value

    def __getattribute__(self, name):
        if name == "__dict__":
            raise AttributeError(name)
        return object.__getattribute__(self, name)
"#,
            )
            .unwrap();
            let module =
                PyModule::from_code(py, code.as_c_str(), c"copy_update_test.py", c"copy_update")?;
            let updates = PyDict::new(py);
            updates.set_item("value", "new")?;

            let existing = module.getattr("ExistingState")?.call1(("old",))?;
            let copied = copy_object_with_updates(py, &existing, &updates)?;
            assert_eq!(
                copied.bind(py).getattr("value")?.extract::<String>()?,
                "new"
            );

            let kwargs_only = module.getattr("KwargsOnly")?.call1(("old",))?;
            let copied = copy_object_with_updates(py, &kwargs_only, &updates)?;
            assert_eq!(
                copied.bind(py).getattr("value")?.extract::<String>()?,
                "new"
            );
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn apply_state_keeps_dunder_names_in_instance_dict() {
        Python::initialize();
        Python::attach(|py| -> PyResult<()> {
            let code = CString::new(
                r#"
class DunderState:
    pass
"#,
            )
            .unwrap();
            let module =
                PyModule::from_code(py, code.as_c_str(), c"dunder_test.py", c"dunder_test")?;
            let instance = module.getattr("DunderState")?.call0()?;
            let target = prepare_rebuild_target(py, &instance)?;
            let state = PyDict::new(py);
            state.set_item("__reduce__", "safe")?;
            state.set_item("value", "normal")?;

            apply_object_state(py, &target, &state.into_any())?;

            assert_eq!(target.getattr("value")?.extract::<String>()?, "normal");
            assert_eq!(
                target
                    .getattr("__dict__")?
                    .cast_into::<PyDict>()?
                    .get_item("__reduce__")?
                    .unwrap()
                    .extract::<String>()?,
                "safe"
            );
            assert!(!target.getattr("__reduce__")?.is(&PyString::new(py, "safe")));
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn append_slot_names_accepts_collection_shapes() {
        Python::initialize();
        Python::attach(|py| -> PyResult<()> {
            let code = CString::new(
                r#"
def names():
    yield "iter_slot"
"#,
            )
            .unwrap();
            let module =
                PyModule::from_code(py, code.as_c_str(), c"object_slots.py", c"object_slots")?;
            let slot_names = PyList::empty(py);
            let dict = PyDict::new(py);
            dict.set_item("dict_slot", py.None())?;

            append_slot_names(&slot_names, PyString::new(py, "one_slot").as_any())?;
            append_slot_names(&slot_names, dict.as_any())?;
            append_slot_names(
                &slot_names,
                PyTuple::new(py, [PyString::new(py, "tuple_slot").into_any().unbind()])?.as_any(),
            )?;
            append_slot_names(&slot_names, PyList::new(py, ["list_slot"])?.as_any())?;
            append_slot_names(&slot_names, PySet::new(py, ["set_slot"])?.as_any())?;
            append_slot_names(&slot_names, PyFrozenSet::new(py, ["frozen_slot"])?.as_any())?;
            append_slot_names(&slot_names, module.getattr("names")?.call0()?.as_any())?;

            let names = slot_names.extract::<Vec<String>>()?;
            for expected in [
                "one_slot",
                "dict_slot",
                "tuple_slot",
                "list_slot",
                "set_slot",
                "frozen_slot",
                "iter_slot",
            ] {
                assert!(names.iter().any(|name| name == expected), "{expected}");
            }
            Ok(())
        })
        .unwrap();
    }
}
