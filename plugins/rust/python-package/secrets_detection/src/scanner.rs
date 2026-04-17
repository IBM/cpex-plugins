// Copyright 2026
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::collections::HashSet;

use pyo3::prelude::*;
use pyo3::types::{PyAny, PyDict, PyList, PyString, PyTuple};
use serde_json::{Map, Number, Value};

use crate::config::SecretsDetectionConfig;
use crate::object_model::{
    apply_object_state, inspect_object_state, prepare_rebuild_target, rebuild_object_from_state,
};
use crate::patterns::PATTERNS;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub pii_type: String,
    pub preview: String,
}

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
        replace_placeholder_references(
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
            let (count, redacted_state, child_findings) =
                scan_container_inner(py, &state.into_any(), config, seen, memo)?;
            total += count;
            for finding in child_findings.iter() {
                findings.append(finding)?;
            }
            if count > 0 {
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
                rebuilt = Some(serialized_result(py, container, &redacted_state)?);
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
    if serialized_state.extract::<String>().is_ok()
        || serialized_state.cast::<PyDict>().is_ok()
        || serialized_state.cast::<PyList>().is_ok()
        || serialized_state.cast::<PyTuple>().is_ok()
    {
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

fn replace_placeholder_references(
    py: Python<'_>,
    value: &Bound<'_, PyAny>,
    placeholder: &Bound<'_, PyAny>,
    replacement: &Bound<'_, PyAny>,
    seen: &mut HashSet<usize>,
) -> PyResult<()> {
    let object_id = value.as_ptr() as usize;
    if !seen.insert(object_id) {
        return Ok(());
    }

    if let Ok(dict) = value.cast::<PyDict>() {
        let keys: Vec<Py<PyAny>> = dict.keys().iter().map(|key| key.unbind()).collect();
        for key in keys {
            let key = key.bind(py);
            let item = dict.get_item(key)?.expect("key exists");
            if item.is(placeholder) {
                dict.set_item(key, replacement)?;
            } else {
                replace_placeholder_references(py, &item, placeholder, replacement, seen)?;
            }
        }
        return Ok(());
    }

    if let Ok(list) = value.cast::<PyList>() {
        for index in 0..list.len() {
            let item = list.get_item(index)?;
            if item.is(placeholder) {
                list.set_item(index, replacement)?;
            } else {
                replace_placeholder_references(py, &item, placeholder, replacement, seen)?;
            }
        }
        return Ok(());
    }

    if let Ok(tuple) = value.cast::<PyTuple>() {
        for item in tuple.iter() {
            replace_placeholder_references(py, &item, placeholder, replacement, seen)?;
        }
    }

    Ok(())
}

pub fn scan_value(value: &Value, config: &SecretsDetectionConfig) -> (usize, Value, Vec<Finding>) {
    match value {
        Value::String(text) => {
            let (matches, redacted) = detect_and_redact(text, config);
            (matches.len(), Value::String(redacted), matches)
        }
        Value::Array(items) => {
            let mut total = 0usize;
            let mut redacted_items = Vec::with_capacity(items.len());
            let mut findings = Vec::new();

            for item in items {
                let (count, redacted_item, mut child_findings) = scan_value(item, config);
                total += count;
                redacted_items.push(redacted_item);
                findings.append(&mut child_findings);
            }

            (total, Value::Array(redacted_items), findings)
        }
        Value::Object(entries) => {
            let mut total = 0usize;
            let mut redacted_entries = Map::with_capacity(entries.len());
            let mut findings = Vec::new();

            for (key, value) in entries {
                let (count, redacted_value, mut child_findings) = scan_value(value, config);
                total += count;
                redacted_entries.insert(key.clone(), redacted_value);
                findings.append(&mut child_findings);
            }

            (total, Value::Object(redacted_entries), findings)
        }
        _ => (0, value.clone(), Vec::new()),
    }
}

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

fn serialized_result<'py>(
    py: Python<'py>,
    container: &Bound<'py, PyAny>,
    redacted_state: &Bound<'py, PyAny>,
) -> PyResult<Bound<'py, PyAny>> {
    if redacted_state.get_type().is(container.get_type()) {
        return Ok(redacted_state.clone());
    }

    if redacted_state.cast::<PyDict>().is_ok() {
        return rebuild_object_from_state(py, container, redacted_state);
    }

    Ok(redacted_state.clone())
}

pub fn detect_and_redact(text: &str, config: &SecretsDetectionConfig) -> (Vec<Finding>, String) {
    let mut findings = Vec::new();
    let mut redacted = text.to_string();

    for (name, pattern) in PATTERNS.iter() {
        if !config.is_enabled(name) {
            continue;
        }

        let matches = pattern.find_iter(text).collect::<Vec<_>>();
        for matched in &matches {
            let text = matched.as_str();
            let preview = if text.chars().count() > 8 {
                format!("{}…", text.chars().take(8).collect::<String>())
            } else {
                text.to_string()
            };
            findings.push(Finding {
                pii_type: name.to_string(),
                preview,
            });
        }

        if config.redact && !matches.is_empty() {
            redacted = pattern
                .replace_all(&redacted, config.redaction_text.as_str())
                .into_owned();
        }
    }

    (findings, redacted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_aws_secret_access_key() {
        let config = SecretsDetectionConfig::default();
        let (findings, _) = detect_and_redact(
            "AWS_SECRET_ACCESS_KEY=FAKESecretAccessKeyForTestingEXAMPLE0000",
            &config,
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.pii_type == "aws_secret_access_key")
        );
    }

    #[test]
    fn detects_slack_token() {
        let config = SecretsDetectionConfig::default();
        let (findings, _) = detect_and_redact(
            "xoxr-fake-000000000-fake000000000-fakefakefakefake",
            &config,
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.pii_type == "slack_token")
        );
    }

    #[test]
    fn redaction_works() {
        let config = SecretsDetectionConfig {
            redact: true,
            redaction_text: "[REDACTED]".to_string(),
            ..Default::default()
        };
        let (findings, redacted) =
            detect_and_redact("AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE", &config);
        assert_eq!(findings.len(), 1);
        assert_eq!(redacted, "AWS_ACCESS_KEY_ID=[REDACTED]");
    }

    #[test]
    fn handles_nested_structures() {
        let redact_config = SecretsDetectionConfig {
            redact: true,
            redaction_text: "[REDACTED]".to_string(),
            ..SecretsDetectionConfig::default()
        };
        let value = Value::Object(Map::from_iter([(
            "users".to_string(),
            Value::Array(vec![
                Value::Object(Map::from_iter([
                    ("name".to_string(), Value::String("Alice".to_string())),
                    (
                        "key".to_string(),
                        Value::String("AKIAFAKE12345EXAMPLE".to_string()),
                    ),
                ])),
                Value::Object(Map::from_iter([
                    ("name".to_string(), Value::String("Bob".to_string())),
                    (
                        "token".to_string(),
                        Value::String(
                            "xoxr-fake-000000000-fake000000000-fakefakefakefake".to_string(),
                        ),
                    ),
                ])),
            ]),
        )]));

        let (count, redacted, findings) = scan_value(&value, &redact_config);

        assert_eq!(count, 2);
        assert_eq!(
            redacted,
            Value::Object(Map::from_iter([(
                "users".to_string(),
                Value::Array(vec![
                    Value::Object(Map::from_iter([
                        ("name".to_string(), Value::String("Alice".to_string())),
                        ("key".to_string(), Value::String("[REDACTED]".to_string())),
                    ])),
                    Value::Object(Map::from_iter([
                        ("name".to_string(), Value::String("Bob".to_string())),
                        ("token".to_string(), Value::String("[REDACTED]".to_string())),
                    ])),
                ]),
            )]))
        );
        assert_eq!(findings.len(), 2);
        let finding_types: std::collections::HashSet<_> = findings
            .iter()
            .map(|finding| finding.pii_type.as_str())
            .collect();
        assert_eq!(
            finding_types,
            std::collections::HashSet::from(["aws_access_key_id", "slack_token"])
        );
    }

    #[test]
    fn generic_api_key_assignment_detection_is_opt_in() {
        let config = SecretsDetectionConfig {
            enabled: std::collections::HashMap::from([(
                "generic_api_key_assignment".to_string(),
                true,
            )]),
            ..Default::default()
        };
        let (findings, _) = detect_and_redact("X-API-Key: test12345678901234567890", &config);
        assert!(
            findings
                .iter()
                .any(|finding| finding.pii_type == "generic_api_key_assignment")
        );
    }

    #[test]
    fn broad_patterns_are_opt_in() {
        let config = SecretsDetectionConfig {
            redact: true,
            ..Default::default()
        };
        let (findings, redacted) =
            detect_and_redact("access_token = 'abcdefghijklmnopqrstuvwx'", &config);
        assert!(findings.is_empty());
        assert_eq!(redacted, "access_token = 'abcdefghijklmnopqrstuvwx'");
    }

    #[test]
    fn generic_api_key_assignment_ignores_short_or_prose_values() {
        let config = SecretsDetectionConfig {
            enabled: std::collections::HashMap::from([(
                "generic_api_key_assignment".to_string(),
                true,
            )]),
            ..Default::default()
        };

        for text in [
            "api_key=short",
            "api key rotation is enabled",
            "The api_key field is documented below",
        ] {
            let (findings, _) = detect_and_redact(text, &config);
            assert!(
                findings
                    .iter()
                    .all(|finding| finding.pii_type != "generic_api_key_assignment"),
                "{text}"
            );
        }
    }
}
