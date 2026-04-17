// Copyright 2026
// SPDX-License-Identifier: Apache-2.0

use std::collections::{HashMap, HashSet};

use pyo3::prelude::*;
use pyo3::types::{PyAny, PyDict, PyList, PyString, PyTuple};

use crate::config::SecretsDetectionConfig;
use crate::object_model::{
    apply_object_state, copy_object_with_updates, inspect_object_state, prepare_rebuild_target,
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

    if let Ok(text) = container.extract::<String>() {
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
            if count > 0 || !redacted_state.eq(&state_any)? {
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
                scan_container_inner(py, &serialized_state, config, seen, memo)?;
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

fn should_scan_serialized_state(
    py: Python<'_>,
    container: &Bound<'_, PyAny>,
    rebuild_state: Option<&Bound<'_, PyAny>>,
    serialized_state: &Bound<'_, PyAny>,
    has_rebuild_state: bool,
) -> PyResult<bool> {
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
    Ok(!serialized_rebuild_state.as_any().eq(rebuild_state)?)
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
        return copy_object_with_updates(py, container, redacted_dict)
            .map(|value| value.bind(py).clone());
    }

    Ok(redacted_state.clone())
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;

    use pyo3::types::PyModule;

    use super::*;

    #[test]
    fn serialized_redaction_does_not_restore_original_object_state() {
        Python::initialize();
        Python::attach(|py| -> PyResult<()> {
            let code = CString::new(
                r#"
class LeakModel:
    def __init__(self):
        self.internal = "AWS_SECRET_ACCESS_KEY=FAKESecretAccessKeyForTestingEXAMPLE0000"

    def model_dump(self):
        return {
            "external": "AWS_SECRET_ACCESS_KEY=FAKESecretAccessKeyForTestingEXAMPLE0000"
        }
"#,
            )
            .unwrap();
            let module =
                PyModule::from_code(py, code.as_c_str(), c"test_module.py", c"test_module")?;
            let instance = module.getattr("LeakModel")?.call0()?;
            let config = SecretsDetectionConfig {
                redact: true,
                redaction_text: "[REDACTED]".to_string(),
                ..Default::default()
            };

            let (_, redacted, _) = scan_container(py, &instance, &config)?;
            let internal = redacted.getattr("internal")?.extract::<String>()?;
            let external = redacted.getattr("external")?.extract::<String>()?;

            assert_eq!(internal, config.redaction_text);
            assert_eq!(external, config.redaction_text);
            assert_ne!(
                internal,
                "AWS_SECRET_ACCESS_KEY=FAKESecretAccessKeyForTestingEXAMPLE0000"
            );
            assert_ne!(
                external,
                "AWS_SECRET_ACCESS_KEY=FAKESecretAccessKeyForTestingEXAMPLE0000"
            );

            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn serialized_state_type_guard_avoids_user_defined_eq() {
        Python::initialize();
        Python::attach(|py| -> PyResult<()> {
            let code = CString::new(
                r#"
class EqBomb:
    def __eq__(self, other):
        raise RuntimeError("eq should not run")

class Model:
    def __init__(self):
        self.value = "clean"

    def model_dump(self):
        return EqBomb()
"#,
            )
            .unwrap();
            let module =
                PyModule::from_code(py, code.as_c_str(), c"test_module.py", c"test_module")?;
            let instance = module.getattr("Model")?.call0()?;
            let config = SecretsDetectionConfig::default();

            let (count, _, findings) = scan_container(py, &instance, &config)?;

            assert_eq!(count, 0);
            assert!(findings.is_empty());

            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn structured_serialized_state_shortcut_skips_nested_eq() {
        Python::initialize();
        Python::attach(|py| -> PyResult<()> {
            let code = CString::new(
                r#"
class EqBomb:
    def __eq__(self, other):
        raise RuntimeError("eq should not run")

def make_states():
    return (
        {"bomb": EqBomb()},
        {"bomb": EqBomb()},
        [EqBomb()],
        [EqBomb()],
        (EqBomb(),),
        (EqBomb(),),
    )

dummy = object()
"#,
            )
            .unwrap();
            let module =
                PyModule::from_code(py, code.as_c_str(), c"test_module.py", c"test_module")?;
            let states_value = module.getattr("make_states")?.call0()?;
            let states = states_value.cast::<PyTuple>()?;
            let dummy = module.getattr("dummy")?;

            for (rebuild_index, serialized_index) in [(0, 1), (2, 3), (4, 5)] {
                let rebuild_state = states.get_item(rebuild_index)?;
                let serialized_state = states.get_item(serialized_index)?;
                assert!(should_scan_serialized_state(
                    py,
                    &dummy,
                    Some(&rebuild_state),
                    &serialized_state,
                    true,
                )?);
            }

            Ok(())
        })
        .unwrap();
    }
}
