// Copyright 2026
// SPDX-License-Identifier: Apache-2.0

use pyo3::prelude::*;
use pyo3::types::{PyAny, PyDict, PyFrozenSet, PyList, PySet, PyTuple};

pub struct InspectedObjectState<'py> {
    pub rebuild_state: Option<Bound<'py, PyDict>>,
    pub serialized_state: Option<Bound<'py, PyAny>>,
}

pub fn inspect_object_state<'py>(
    py: Python<'py>,
    container: &Bound<'py, PyAny>,
) -> PyResult<InspectedObjectState<'py>> {
    let mut mappings = MappingStateAccumulator::new(py);
    let mut serialized_state = None;

    if let Ok(model_dump) = container.call_method0("model_dump") {
        if let Ok(model_state) = model_dump.cast::<PyDict>() {
            mappings.push(model_state)?;
        } else {
            serialized_state = Some(model_dump);
        }
    }

    if let Ok(dict_state) = container.getattr("__dict__")
        && let Ok(dict_state) = dict_state.cast::<PyDict>()
    {
        mappings.push(dict_state)?;
    }

    if let Some(slot_state) = extract_slot_state(py, container)? {
        mappings.push(&slot_state)?;
    }

    Ok(InspectedObjectState {
        rebuild_state: mappings.finish(),
        serialized_state,
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
            return Ok(container.clone());
        }
        return container.call_method("model_copy", (), Some(&kwargs));
    }

    let state = redacted_state.cast::<PyDict>()?;
    let builtins = py.import("builtins")?;
    let object_type = builtins.getattr("object")?;
    let cloned = blank_instance(&object_type, container)?;
    for (key, value) in state.iter() {
        set_attr_without_hooks(&object_type, &cloned, &key.extract::<String>()?, &value)?;
    }
    Ok(cloned)
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
    }

    Ok(())
}

fn merge_state_into(target: &Bound<'_, PyDict>, source: &Bound<'_, PyDict>) -> PyResult<()> {
    for (key, value) in source.iter() {
        target.set_item(key, value)?;
    }
    Ok(())
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
