// Copyright 2026
// SPDX-License-Identifier: Apache-2.0

use std::collections::{HashMap, HashSet};

use pyo3::prelude::*;
use pyo3::types::{PyAny, PyBool, PyBytes, PyDict, PyFloat, PyInt, PyList, PyString, PyTuple};

use crate::config::SecretsDetectionConfig;
use crate::object_model::{
    apply_object_state, copy_object_with_updates, dict_has_only_exact_string_keys,
    inspect_object_state, prepare_rebuild_target,
};

use super::cycle_rewrite::replace_placeholder_references;
use super::text_scan::detect_and_redact;

pub fn scan_container<'py>(
    py: Python<'py>,
    container: &Bound<'py, PyAny>,
    config: &SecretsDetectionConfig,
) -> PyResult<(usize, Bound<'py, PyAny>, Bound<'py, PyList>)> {
    let mut seen = HashSet::new();
    let mut memo = HashMap::new();
    scan_container_inner(py, container, config, &mut seen, &mut memo)
}

fn scan_container_inner<'py>(
    py: Python<'py>,
    container: &Bound<'py, PyAny>,
    config: &SecretsDetectionConfig,
    seen: &mut HashSet<usize>,
    memo: &mut HashMap<usize, Py<PyAny>>,
) -> PyResult<(usize, Bound<'py, PyAny>, Bound<'py, PyList>)> {
    let findings = PyList::empty(py);

    let str_type = py.import("builtins")?.getattr("str")?;
    if container.is_instance(&str_type)? {
        let text = container.extract::<String>()?;
        let (matches, redacted) = detect_and_redact(&text, config);
        for finding in &matches {
            let finding_dict = PyDict::new(py);
            finding_dict.set_item("type", &finding.pii_type)?;
            findings.append(finding_dict)?;
        }
        return Ok((
            matches.len(),
            PyString::new(py, &redacted).into_any(),
            findings,
        ));
    }

    let object_id = container.as_ptr() as usize;
    if !seen.insert(object_id) {
        if let Some(existing) = memo.get(&object_id) {
            return Ok((0, existing.bind(py).clone(), findings));
        }
        return Ok((0, container.clone(), findings));
    }

    if let Ok(dict) = container.cast::<PyDict>() {
        let new_dict = PyDict::new(py);
        memo.insert(object_id, new_dict.clone().into_any().unbind());
        let mut total = 0usize;
        for (key, value) in dict.iter() {
            let (count, redacted_value, child_findings) =
                scan_container_inner(py, &value, config, seen, memo)?;
            total += count;
            for finding in child_findings.iter() {
                findings.append(finding)?;
            }
            new_dict.set_item(key, redacted_value)?;
        }
        seen.remove(&object_id);
        return Ok((total, new_dict.into_any(), findings));
    }

    if let Ok(list) = container.cast::<PyList>() {
        let new_list = PyList::empty(py);
        memo.insert(object_id, new_list.clone().into_any().unbind());
        let mut total = 0usize;
        for item in list.iter() {
            let (count, redacted_item, child_findings) =
                scan_container_inner(py, &item, config, seen, memo)?;
            total += count;
            for finding in child_findings.iter() {
                findings.append(finding)?;
            }
            new_list.append(redacted_item)?;
        }
        seen.remove(&object_id);
        return Ok((total, new_list.into_any(), findings));
    }

    if let Ok(tuple) = container.cast::<PyTuple>() {
        let tuple_placeholder = PyList::empty(py);
        memo.insert(object_id, tuple_placeholder.clone().into_any().unbind());
        let mut items = Vec::with_capacity(tuple.len());
        let mut total = 0usize;
        for item in tuple.iter() {
            let (count, redacted_item, child_findings) =
                scan_container_inner(py, &item, config, seen, memo)?;
            total += count;
            for finding in child_findings.iter() {
                findings.append(finding)?;
            }
            items.push(redacted_item.unbind());
        }
        let new_tuple = PyTuple::new(py, items)?;
        let mut rewrite_seen = HashSet::new();
        let _ = replace_placeholder_references(
            py,
            &new_tuple.clone().into_any(),
            &tuple_placeholder.into_any(),
            &new_tuple.clone().into_any(),
            &mut rewrite_seen,
        )?;
        seen.remove(&object_id);
        memo.remove(&object_id);
        return Ok((total, new_tuple.into_any(), findings));
    }

    let object_state = inspect_object_state(py, container)?;
    if object_state.rebuild_state.is_some() || object_state.serialized_state.is_some() {
        let mut total = 0usize;
        let mut rebuilt = None;
        let has_rebuild_state = object_state.rebuild_state.is_some();
        let rebuild_state_for_gate = object_state
            .rebuild_state
            .as_ref()
            .map(|state| state.as_any().clone());

        if let Some(state) = object_state.rebuild_state {
            let target = prepare_rebuild_target(py, container)?;
            memo.insert(object_id, target.clone().unbind());
            let state_any = state.into_any();
            let (count, redacted_state, child_findings) =
                scan_container_inner(py, &state_any, config, seen, memo)?;
            total += count;
            for finding in child_findings.iter() {
                findings.append(finding)?;
            }
            if count > 0 || !same_safe_value(&redacted_state, &state_any, &mut HashSet::new())? {
                apply_object_state(py, &target, &redacted_state)?;
                rebuilt = Some(target.into_any());
            }
        }

        if let Some(serialized_state) = object_state.serialized_state
            && should_scan_serialized_state(
                py,
                container,
                rebuild_state_for_gate.as_ref(),
                &serialized_state,
                has_rebuild_state,
            )?
        {
            let (count, redacted_state, child_findings) =
                scan_serialized_state_inner(py, container, &serialized_state, config, seen, memo)?;
            total += count;
            for finding in child_findings.iter() {
                findings.append(finding)?;
            }
            if count > 0 {
                let base = rebuilt.as_ref().unwrap_or(container);
                rebuilt = Some(serialized_result(py, base, &redacted_state)?);
            }
        }

        seen.remove(&object_id);
        let result = rebuilt.unwrap_or_else(|| container.clone());
        memo.remove(&object_id);
        return Ok((total, result, findings));
    }

    seen.remove(&object_id);
    Ok((0, container.clone(), findings))
}

fn scan_serialized_state_inner<'py>(
    py: Python<'py>,
    container: &Bound<'py, PyAny>,
    serialized_state: &Bound<'py, PyAny>,
    config: &SecretsDetectionConfig,
    seen: &mut HashSet<usize>,
    memo: &mut HashMap<usize, Py<PyAny>>,
) -> PyResult<(usize, Bound<'py, PyAny>, Bound<'py, PyList>)> {
    if serialized_state.get_type().is(container.get_type()) {
        let serialized_object_state = inspect_object_state(py, serialized_state)?;
        if let Some(state) = serialized_object_state.rebuild_state {
            return scan_container_inner(py, &state.into_any(), config, seen, memo);
        }
    }

    scan_container_inner(py, serialized_state, config, seen, memo)
}

fn should_scan_serialized_state(
    py: Python<'_>,
    container: &Bound<'_, PyAny>,
    rebuild_state: Option<&Bound<'_, PyAny>>,
    serialized_state: &Bound<'_, PyAny>,
    has_rebuild_state: bool,
) -> PyResult<bool> {
    if let Some(rebuild_state) = rebuild_state
        && serialized_duplicates_rebuild_root(serialized_state, rebuild_state)?
    {
        return Ok(false);
    }

    if serialized_state.is_exact_instance_of::<PyString>() {
        if let Some(rebuild_state) = rebuild_state
            && rebuild_state.is_exact_instance_of::<PyString>()
            && serialized_state.eq(rebuild_state)?
        {
            return Ok(false);
        }
        return Ok(true);
    }

    if serialized_state.is_exact_instance_of::<PyDict>() {
        if let Some(rebuild_state) = rebuild_state
            && serialized_dict_duplicates_rebuild_state(serialized_state, rebuild_state)?
        {
            return Ok(false);
        }
        return Ok(true);
    }

    if serialized_state.is_exact_instance_of::<PyList>() {
        return Ok(true);
    }

    if serialized_state.is_exact_instance_of::<PyTuple>() {
        return Ok(true);
    }

    if !has_rebuild_state {
        return Ok(!serialized_state.get_type().is(container.get_type()));
    }

    if !serialized_state.get_type().is(container.get_type()) {
        return Ok(true);
    }

    let serialized_object_state = inspect_object_state(py, serialized_state)?;
    let Some(serialized_rebuild_state) = serialized_object_state.rebuild_state.as_ref() else {
        return Ok(false);
    };
    let Some(rebuild_state) = rebuild_state else {
        return Ok(false);
    };
    Ok(!same_safe_value(
        serialized_rebuild_state.as_any(),
        rebuild_state,
        &mut HashSet::new(),
    )?)
}

fn serialized_duplicates_rebuild_root(
    serialized_state: &Bound<'_, PyAny>,
    rebuild_state: &Bound<'_, PyAny>,
) -> PyResult<bool> {
    let Ok(rebuild_dict) = rebuild_state.cast::<PyDict>() else {
        return Ok(false);
    };
    if !dict_has_only_exact_string_keys(rebuild_dict) {
        return Ok(false);
    }
    let Some(root) = rebuild_dict.get_item("root")? else {
        return Ok(false);
    };
    same_safe_value(serialized_state, &root, &mut HashSet::new())
}

fn serialized_dict_duplicates_rebuild_state(
    serialized_state: &Bound<'_, PyAny>,
    rebuild_state: &Bound<'_, PyAny>,
) -> PyResult<bool> {
    let serialized_dict = serialized_state.cast::<PyDict>()?;
    let Ok(rebuild_dict) = rebuild_state.cast::<PyDict>() else {
        return Ok(false);
    };

    if !dict_has_only_exact_string_keys(serialized_dict)
        || !dict_has_only_exact_string_keys(rebuild_dict)
    {
        return Ok(false);
    }

    for (key, serialized_value) in serialized_dict.iter() {
        let Some(rebuild_value) = rebuild_dict.get_item(&key)? else {
            return Ok(false);
        };
        if !same_safe_value(&serialized_value, &rebuild_value, &mut HashSet::new())? {
            return Ok(false);
        }
    }

    Ok(true)
}

fn same_safe_value(
    left: &Bound<'_, PyAny>,
    right: &Bound<'_, PyAny>,
    seen: &mut HashSet<(usize, usize)>,
) -> PyResult<bool> {
    if left.is(right) {
        return Ok(true);
    }

    if left.is_exact_instance_of::<PyString>() && right.is_exact_instance_of::<PyString>() {
        return Ok(left.extract::<String>()? == right.extract::<String>()?);
    }

    if is_exact_safe_scalar_pair(left, right) {
        return left.eq(right);
    }

    if let (Ok(left_list), Ok(right_list)) = (left.cast::<PyList>(), right.cast::<PyList>()) {
        if !seen.insert((left.as_ptr() as usize, right.as_ptr() as usize)) {
            return Ok(true);
        }
        if left_list.len() != right_list.len() {
            return Ok(false);
        }
        for (left_item, right_item) in left_list.iter().zip(right_list.iter()) {
            if !same_safe_value(&left_item, &right_item, seen)? {
                return Ok(false);
            }
        }
        return Ok(true);
    }

    if let (Ok(left_tuple), Ok(right_tuple)) = (left.cast::<PyTuple>(), right.cast::<PyTuple>()) {
        if !seen.insert((left.as_ptr() as usize, right.as_ptr() as usize)) {
            return Ok(true);
        }
        if left_tuple.len() != right_tuple.len() {
            return Ok(false);
        }
        for (left_item, right_item) in left_tuple.iter().zip(right_tuple.iter()) {
            if !same_safe_value(&left_item, &right_item, seen)? {
                return Ok(false);
            }
        }
        return Ok(true);
    }

    if let (Ok(left_dict), Ok(right_dict)) = (left.cast::<PyDict>(), right.cast::<PyDict>()) {
        if !seen.insert((left.as_ptr() as usize, right.as_ptr() as usize)) {
            return Ok(true);
        }
        if left_dict.len() != right_dict.len()
            || !dict_has_only_exact_string_keys(left_dict)
            || !dict_has_only_exact_string_keys(right_dict)
        {
            return Ok(false);
        }
        for (key, left_value) in left_dict.iter() {
            let Some(right_value) = right_dict.get_item(&key)? else {
                return Ok(false);
            };
            if !same_safe_value(&left_value, &right_value, seen)? {
                return Ok(false);
            }
        }
        return Ok(true);
    }

    Ok(false)
}

fn is_exact_safe_scalar_pair(left: &Bound<'_, PyAny>, right: &Bound<'_, PyAny>) -> bool {
    (left.is_exact_instance_of::<PyBool>() && right.is_exact_instance_of::<PyBool>())
        || (left.is_exact_instance_of::<PyInt>() && right.is_exact_instance_of::<PyInt>())
        || (left.is_exact_instance_of::<PyFloat>() && right.is_exact_instance_of::<PyFloat>())
        || (left.is_exact_instance_of::<PyBytes>() && right.is_exact_instance_of::<PyBytes>())
}

fn serialized_result<'py>(
    py: Python<'py>,
    container: &Bound<'py, PyAny>,
    redacted_state: &Bound<'py, PyAny>,
) -> PyResult<Bound<'py, PyAny>> {
    if redacted_state.get_type().is(container.get_type()) {
        return Ok(redacted_state.clone());
    }

    if redacted_state.cast::<PyDict>().is_ok() {
        let redacted_dict = redacted_state.cast::<PyDict>()?;
        if !dict_has_only_exact_string_keys(redacted_dict) {
            return Ok(redacted_state.clone());
        }
        return copy_object_with_updates(py, container, redacted_dict)
            .map(|value| value.bind(py).clone());
    }

    Ok(redacted_state.clone())
}

#[cfg(test)]
mod tests;
