// Copyright 2026
// SPDX-License-Identifier: Apache-2.0

use std::collections::{HashMap, HashSet};

use pyo3::prelude::*;
use pyo3::types::{PyAny, PyBool, PyBytes, PyDict, PyFloat, PyInt, PyList, PyString, PyTuple};

use crate::config::SecretsDetectionConfig;
use crate::object_model::{
    InspectedObjectState, apply_extra_dict_state, apply_object_state, copy_object_with_updates,
    dict_has_only_exact_string_keys, inspect_object_state, inspect_object_state_without_model_dump,
    prepare_rebuild_target,
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
    let str_type = py.import("builtins")?.getattr("str")?;
    scan_container_inner(py, container, config, &str_type, &mut seen, &mut memo)
}

fn scan_container_inner<'py>(
    py: Python<'py>,
    container: &Bound<'py, PyAny>,
    config: &SecretsDetectionConfig,
    str_type: &Bound<'py, PyAny>,
    seen: &mut HashSet<usize>,
    memo: &mut HashMap<usize, Py<PyAny>>,
) -> PyResult<(usize, Bound<'py, PyAny>, Bound<'py, PyList>)> {
    let findings = PyList::empty(py);

    if container.is_instance(str_type)? {
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
                scan_container_inner(py, &value, config, str_type, seen, memo)?;
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
                scan_container_inner(py, &item, config, str_type, seen, memo)?;
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
                scan_container_inner(py, &item, config, str_type, seen, memo)?;
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
    if object_state.rebuild_state.is_some()
        || object_state.serialized_state.is_some()
        || object_state.scan_state.is_some()
    {
        let (total, result, object_findings) =
            scan_object_state(py, container, object_state, config, str_type, seen, memo)?;
        for finding in object_findings.iter() {
            findings.append(finding)?;
        }
        seen.remove(&object_id);
        memo.remove(&object_id);
        return Ok((total, result, findings));
    }

    seen.remove(&object_id);
    Ok((0, container.clone(), findings))
}

struct SerializedScanTarget<'py> {
    state: Bound<'py, PyAny>,
    object_state: Option<InspectedObjectState<'py>>,
}

struct PendingScanState<'py> {
    state: Bound<'py, PyDict>,
    placeholder: Bound<'py, PyAny>,
}

fn scan_object_state<'py>(
    py: Python<'py>,
    container: &Bound<'py, PyAny>,
    object_state: InspectedObjectState<'py>,
    config: &SecretsDetectionConfig,
    str_type: &Bound<'py, PyAny>,
    seen: &mut HashSet<usize>,
    memo: &mut HashMap<usize, Py<PyAny>>,
) -> PyResult<(usize, Bound<'py, PyAny>, Bound<'py, PyList>)> {
    let findings = PyList::empty(py);
    let mut total = 0usize;
    let mut rebuilt = None;
    let rebuild_state_for_gate = object_state
        .rebuild_state
        .as_ref()
        .map(|state| state.as_any().clone());
    let mut rebuild_state_for_extra = object_state.rebuild_state.as_ref().cloned();
    let has_rebuild_state = object_state.rebuild_state.is_some();
    let mut pending_scan_state = None;

    if let Some(state) = object_state.rebuild_state {
        let target = prepare_rebuild_target(py, container)?;
        memo.insert(container.as_ptr() as usize, target.clone().unbind());
        let state_any = state.into_any();
        let (count, redacted_state, child_findings) =
            scan_container_inner(py, &state_any, config, str_type, seen, memo)?;
        total += count;
        for finding in child_findings.iter() {
            findings.append(finding)?;
        }
        if count > 0 || !values_equal(&redacted_state, &state_any)? {
            apply_object_state(py, &target, &redacted_state)?;
            rebuild_state_for_extra = Some(redacted_state.cast::<PyDict>()?.clone());
            rebuilt = Some(target.into_any());
        }
    }

    if let Some(scan_state) = object_state.scan_state {
        let had_rebuilt_before_scan_state = rebuilt.is_some();
        if rebuilt.is_none() {
            let target = prepare_rebuild_target(py, container)?;
            if let Some(state) = rebuild_state_for_extra.as_ref() {
                apply_object_state(py, &target, &state.clone().into_any())?;
            }
            memo.insert(container.as_ptr() as usize, target.clone().unbind());
            rebuilt = Some(target.into_any());
        }

        let scan_state_any = scan_state.clone().into_any();
        let (count, redacted_state, child_findings) =
            scan_container_inner(py, &scan_state_any, config, str_type, seen, memo)?;
        total += count;
        for finding in child_findings.iter() {
            findings.append(finding)?;
        }
        if count > 0 || had_rebuilt_before_scan_state {
            let base = rebuilt.as_ref().expect("scan_state target exists");
            apply_extra_dict_state(py, base, redacted_state.cast::<PyDict>()?)?;
        } else {
            let placeholder = rebuilt.take().expect("scan_state target exists");
            pending_scan_state = Some(PendingScanState {
                state: redacted_state.cast::<PyDict>()?.clone(),
                placeholder,
            });
            memo.remove(&(container.as_ptr() as usize));
        }
    }

    if let Some(serialized_state) = object_state.serialized_state
        && let Some(target) = serialized_scan_target(
            py,
            container,
            rebuild_state_for_gate.as_ref(),
            &serialized_state,
            has_rebuild_state,
        )?
    {
        let (count, redacted_state, child_findings) =
            scan_serialized_state_target(py, target, config, str_type, seen, memo)?;
        total += count;
        for finding in child_findings.iter() {
            findings.append(finding)?;
        }
        if count > 0 {
            let base = rebuilt.as_ref().unwrap_or(container);
            let serialized_rebuilt = serialized_result(py, base, &redacted_state)?;
            if let Some(pending) = pending_scan_state.as_ref()
                && serialized_rebuilt.get_type().is(container.get_type())
                && serialized_rebuilt.hasattr("__dict__")?
            {
                let mut rewrite_seen = HashSet::new();
                let _ = replace_placeholder_references(
                    py,
                    &pending.state.clone().into_any(),
                    &pending.placeholder,
                    &serialized_rebuilt,
                    &mut rewrite_seen,
                )?;
                apply_extra_dict_state(py, &serialized_rebuilt, &pending.state)?;
            }
            rebuilt = Some(serialized_rebuilt);
        }
    }

    Ok((
        total,
        rebuilt.unwrap_or_else(|| container.clone()),
        findings,
    ))
}

fn scan_serialized_state_target<'py>(
    py: Python<'py>,
    target: SerializedScanTarget<'py>,
    config: &SecretsDetectionConfig,
    str_type: &Bound<'py, PyAny>,
    seen: &mut HashSet<usize>,
    memo: &mut HashMap<usize, Py<PyAny>>,
) -> PyResult<(usize, Bound<'py, PyAny>, Bound<'py, PyList>)> {
    if let Some(object_state) = target.object_state {
        let object_id = target.state.as_ptr() as usize;
        if !seen.insert(object_id) {
            let findings = PyList::empty(py);
            if let Some(existing) = memo.get(&object_id) {
                return Ok((0, existing.bind(py).clone(), findings));
            }
            return Ok((0, target.state, findings));
        }
        let result = scan_object_state(
            py,
            &target.state,
            object_state,
            config,
            str_type,
            seen,
            memo,
        )?;
        seen.remove(&object_id);
        memo.remove(&object_id);
        return Ok(result);
    }

    scan_container_inner(py, &target.state, config, str_type, seen, memo)
}

#[cfg(test)]
fn should_scan_serialized_state<'py>(
    py: Python<'py>,
    container: &Bound<'py, PyAny>,
    rebuild_state: Option<&Bound<'py, PyAny>>,
    serialized_state: &Bound<'py, PyAny>,
    has_rebuild_state: bool,
) -> PyResult<bool> {
    Ok(serialized_scan_target(
        py,
        container,
        rebuild_state,
        serialized_state,
        has_rebuild_state,
    )?
    .is_some())
}

fn serialized_scan_target<'py>(
    py: Python<'py>,
    container: &Bound<'py, PyAny>,
    rebuild_state: Option<&Bound<'py, PyAny>>,
    serialized_state: &Bound<'py, PyAny>,
    has_rebuild_state: bool,
) -> PyResult<Option<SerializedScanTarget<'py>>> {
    if let Some(rebuild_state) = rebuild_state
        && serialized_duplicates_rebuild_root(serialized_state, rebuild_state)?
    {
        log::debug!(
            "duplicate gate: serialized root duplicates rebuild state; skipping serialized scan"
        );
        return Ok(None);
    }

    if serialized_state.is_exact_instance_of::<PyString>() {
        if let Some(rebuild_state) = rebuild_state
            && rebuild_state.is_exact_instance_of::<PyString>()
            && serialized_state.eq(rebuild_state)?
        {
            log::debug!(
                "duplicate gate: serialized string duplicates rebuild state; skipping serialized scan"
            );
            return Ok(None);
        }
        return Ok(Some(SerializedScanTarget {
            state: serialized_state.clone(),
            object_state: None,
        }));
    }

    if serialized_state.is_exact_instance_of::<PyDict>() {
        if let Some(rebuild_state) = rebuild_state
            && serialized_dict_duplicates_rebuild_state(serialized_state, rebuild_state)?
        {
            log::debug!(
                "duplicate gate: serialized dict duplicates rebuild state; skipping serialized scan"
            );
            return Ok(None);
        }
        return Ok(Some(SerializedScanTarget {
            state: serialized_state.clone(),
            object_state: None,
        }));
    }

    if serialized_state.is_exact_instance_of::<PyList>() {
        return Ok(Some(SerializedScanTarget {
            state: serialized_state.clone(),
            object_state: None,
        }));
    }

    if serialized_state.is_exact_instance_of::<PyTuple>() {
        return Ok(Some(SerializedScanTarget {
            state: serialized_state.clone(),
            object_state: None,
        }));
    }

    if !has_rebuild_state {
        if serialized_state.get_type().is(container.get_type()) {
            log::debug!(
                "duplicate gate: same-type serialized state without rebuild state; skipping serialized scan"
            );
            return Ok(None);
        }
        return Ok(Some(SerializedScanTarget {
            state: serialized_state.clone(),
            object_state: None,
        }));
    }

    if !serialized_state.get_type().is(container.get_type()) {
        return Ok(Some(SerializedScanTarget {
            state: serialized_state.clone(),
            object_state: None,
        }));
    }

    let serialized_object_state = if is_pydantic_model(serialized_state)? {
        inspect_object_state_without_model_dump(py, serialized_state)?
    } else {
        inspect_object_state(py, serialized_state)?
    };
    let Some(serialized_rebuild_state) = serialized_object_state.rebuild_state.as_ref() else {
        log::debug!(
            "duplicate gate: same-type serialized object has no rebuild state; skipping serialized scan"
        );
        return Ok(None);
    };
    let Some(rebuild_state) = rebuild_state else {
        log::debug!(
            "duplicate gate: same-type serialized object has no original rebuild state; skipping serialized scan"
        );
        return Ok(None);
    };
    let duplicates = values_equal(serialized_rebuild_state.as_any(), rebuild_state)?;
    if duplicates {
        if let Some(nested_serialized_state) = serialized_object_state.serialized_state.as_ref()
            && !nested_serialized_state
                .get_type()
                .is(serialized_state.get_type())
        {
            return Ok(Some(SerializedScanTarget {
                state: nested_serialized_state.clone(),
                object_state: None,
            }));
        }
        if serialized_object_state.scan_state.is_none() {
            log::debug!(
                "duplicate gate: same-type serialized rebuild state duplicates original rebuild state; skipping serialized scan"
            );
            return Ok(None);
        }
    }
    Ok(Some(SerializedScanTarget {
        state: serialized_state.clone(),
        object_state: Some(serialized_object_state),
    }))
}

fn is_pydantic_model(value: &Bound<'_, PyAny>) -> PyResult<bool> {
    value.hasattr("__pydantic_serializer__")
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
    values_equal(serialized_state, &root)
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
        if !values_equal(&serialized_value, &rebuild_value)? {
            return Ok(false);
        }
    }

    Ok(true)
}

fn values_equal(left: &Bound<'_, PyAny>, right: &Bound<'_, PyAny>) -> PyResult<bool> {
    same_safe_value(left, right, &mut HashSet::new())
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
