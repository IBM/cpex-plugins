// Copyright 2026
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashSet;

use pyo3::prelude::*;
use pyo3::types::{PyAny, PyDict, PyList, PyString, PyTuple};
use serde_json::{Map, Number, Value};

use crate::config::SecretsDetectionConfig;
use crate::object_model::{inspect_object_state, rebuild_object_from_state};
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
    scan_container_inner(py, container, config, &mut seen)
}

fn scan_container_inner<'py>(
    py: Python<'py>,
    container: &Bound<'py, PyAny>,
    config: &SecretsDetectionConfig,
    seen: &mut HashSet<usize>,
) -> PyResult<(usize, Bound<'py, PyAny>, Bound<'py, PyList>)> {
    let findings = PyList::empty(py);

    if let Ok(text) = container.extract::<String>() {
        let (matches, redacted) = detect_and_redact(&text, config);
        for finding in &matches {
            let finding_dict = PyDict::new(py);
            finding_dict.set_item("type", &finding.pii_type)?;
            finding_dict.set_item("match", &finding.preview)?;
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
        return Ok((0, container.clone(), findings));
    }

    if let Ok(dict) = container.cast::<PyDict>() {
        let new_dict = PyDict::new(py);
        let mut total = 0usize;
        for (key, value) in dict.iter() {
            let (count, redacted_value, child_findings) =
                scan_container_inner(py, &value, config, seen)?;
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
        let mut total = 0usize;
        for item in list.iter() {
            let (count, redacted_item, child_findings) =
                scan_container_inner(py, &item, config, seen)?;
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
        let mut items = Vec::with_capacity(tuple.len());
        let mut total = 0usize;
        for item in tuple.iter() {
            let (count, redacted_item, child_findings) =
                scan_container_inner(py, &item, config, seen)?;
            total += count;
            for finding in child_findings.iter() {
                findings.append(finding)?;
            }
            items.push(redacted_item.unbind());
        }
        let new_tuple = PyTuple::new(py, items)?;
        seen.remove(&object_id);
        return Ok((total, new_tuple.into_any(), findings));
    }

    let object_state = inspect_object_state(py, container)?;
    if object_state.rebuild_state.is_some() || object_state.serialized_state.is_some() {
        let mut total = 0usize;
        let mut rebuilt = None;

        if let Some(state) = object_state.rebuild_state {
            let (count, redacted_state, child_findings) =
                scan_container_inner(py, &state.into_any(), config, seen)?;
            total += count;
            for finding in child_findings.iter() {
                findings.append(finding)?;
            }
            if count > 0 {
                rebuilt = Some(rebuild_object_from_state(py, container, &redacted_state)?);
            }
        }

        if let Some(serialized_state) = object_state.serialized_state {
            let (count, redacted_state, child_findings) =
                scan_container_inner(py, &serialized_state, config, seen)?;
            total += count;
            for finding in child_findings.iter() {
                findings.append(finding)?;
            }
            if rebuilt.is_none() && count > 0 {
                rebuilt = Some(rebuild_object_from_state(py, container, &redacted_state)?);
            }
        }

        seen.remove(&object_id);
        return Ok((
            total,
            rebuilt.unwrap_or_else(|| container.clone()),
            findings,
        ));
    }

    seen.remove(&object_id);
    Ok((0, container.clone(), findings))
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
        finding_dict.set_item("match", &finding.preview)?;
        py_findings.append(finding_dict)?;
    }
    Ok(py_findings)
}

pub fn detect_and_redact(text: &str, config: &SecretsDetectionConfig) -> (Vec<Finding>, String) {
    let mut findings = Vec::new();
    let mut redacted = text.to_string();

    for (name, pattern) in PATTERNS.iter() {
        if !config.is_enabled(name) {
            continue;
        }

        for matched in pattern.find_iter(text) {
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

        if config.redact {
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
