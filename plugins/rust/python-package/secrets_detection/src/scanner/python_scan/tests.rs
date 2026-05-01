// Copyright 2026
// SPDX-License-Identifier: Apache-2.0

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
        let module = PyModule::from_code(py, code.as_c_str(), c"test_module.py", c"test_module")?;
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
        let module = PyModule::from_code(py, code.as_c_str(), c"test_module.py", c"test_module")?;
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
        let module = PyModule::from_code(py, code.as_c_str(), c"test_module.py", c"test_module")?;
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

#[test]
fn same_type_serialized_state_duplicate_gate_skips_user_defined_eq() {
    Python::initialize();
    Python::attach(|py| -> PyResult<()> {
        let code = CString::new(
            r#"
class EqBomb:
    def __eq__(self, other):
        raise RuntimeError("eq should not run")

class Model:
    dumping = True

    def __init__(self):
        self.value = EqBomb()

    def model_dump(self):
        if type(self).dumping:
            type(self).dumping = False
            return type(self)()
        return self
"#,
        )
        .unwrap();
        let module = PyModule::from_code(py, code.as_c_str(), c"test_module.py", c"test_module")?;
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
fn safe_scalar_duplicate_gate_rejects_spoofed_builtin_type() {
    Python::initialize();
    Python::attach(|py| -> PyResult<()> {
        let code = CString::new(
            r#"
def eq_bomb(self, other):
    raise RuntimeError("eq should not run")

SpoofedInt = type("int", (), {"__module__": "builtins", "__eq__": eq_bomb})

class Model:
    dumping = True

    def __init__(self):
        self.value = SpoofedInt()

    def model_dump(self):
        if type(self).dumping:
            type(self).dumping = False
            return type(self)()
        return self
"#,
        )
        .unwrap();
        let module = PyModule::from_code(py, code.as_c_str(), c"test_module.py", c"test_module")?;
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
fn root_duplicate_gate_rejects_non_string_rebuild_keys_before_lookup() {
    Python::initialize();
    Python::attach(|py| -> PyResult<()> {
        let code = CString::new(
            r#"
class BadKey:
    def __hash__(self):
        return hash("root")

    def __eq__(self, other):
        raise RuntimeError("root lookup should not compare custom keys")

class Model:
    def __init__(self):
        self.__dict__[BadKey()] = "clean"

    def model_dump(self):
        return "clean"
"#,
        )
        .unwrap();
        let module = PyModule::from_code(py, code.as_c_str(), c"test_module.py", c"test_module")?;
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
fn scan_container_scans_string_attributes_in_mixed_key_dict() {
    Python::initialize();
    Python::attach(|py| -> PyResult<()> {
        let code = CString::new(
            r#"
class BadKey:
    pass

class Model:
    def __init__(self):
        self.token = "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"
        self.__dict__[BadKey()] = "side-channel"
"#,
        )
        .unwrap();
        let module = PyModule::from_code(py, code.as_c_str(), c"test_module.py", c"test_module")?;
        let instance = module.getattr("Model")?.call0()?;
        let config = SecretsDetectionConfig {
            redact: true,
            redaction_text: "[REDACTED]".to_string(),
            ..Default::default()
        };

        let (count, redacted, findings) = scan_container(py, &instance, &config)?;

        assert_eq!(count, 1);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            redacted.getattr("token")?.extract::<String>()?,
            "AWS_ACCESS_KEY_ID=[REDACTED]"
        );

        Ok(())
    })
    .unwrap();
}

#[test]
fn scan_container_scans_secret_under_non_string_object_dict_key() {
    Python::initialize();
    Python::attach(|py| -> PyResult<()> {
        let code = CString::new(
            r#"
class BadKey:
    pass

class Model:
    def __init__(self):
        self.label = "clean"
        self.__dict__[BadKey()] = "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"
"#,
        )
        .unwrap();
        let module = PyModule::from_code(py, code.as_c_str(), c"test_module.py", c"test_module")?;
        let instance = module.getattr("Model")?.call0()?;
        let config = SecretsDetectionConfig {
            redact: true,
            redaction_text: "[REDACTED]".to_string(),
            ..Default::default()
        };

        let (count, redacted, findings) = scan_container(py, &instance, &config)?;

        assert_eq!(count, 1);
        assert_eq!(findings.len(), 1);
        assert_eq!(redacted.getattr("label")?.extract::<String>()?, "clean");
        let redacted_dict = redacted.getattr("__dict__")?.cast_into::<PyDict>()?;
        let values: Vec<String> = redacted_dict
            .values()
            .iter()
            .map(|value| value.extract::<String>())
            .collect::<PyResult<_>>()?;
        assert!(
            values
                .iter()
                .any(|value| value == "AWS_ACCESS_KEY_ID=[REDACTED]")
        );

        Ok(())
    })
    .unwrap();
}

#[test]
fn scan_container_redacts_string_and_non_string_object_dict_secrets() {
    Python::initialize();
    Python::attach(|py| -> PyResult<()> {
        let code = CString::new(
            r#"
class BadKey:
    pass

class Model:
    def __init__(self):
        self.token = "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"
        self.__dict__[BadKey()] = "AWS_SECRET_ACCESS_KEY=FAKESecretAccessKeyForTestingEXAMPLE0000"
"#,
        )
        .unwrap();
        let module = PyModule::from_code(py, code.as_c_str(), c"test_module.py", c"test_module")?;
        let instance = module.getattr("Model")?.call0()?;
        let config = SecretsDetectionConfig {
            redact: true,
            redaction_text: "[REDACTED]".to_string(),
            ..Default::default()
        };

        let (count, redacted, findings) = scan_container(py, &instance, &config)?;

        assert_eq!(count, 2);
        assert_eq!(findings.len(), 2);
        assert_eq!(
            redacted.getattr("token")?.extract::<String>()?,
            "AWS_ACCESS_KEY_ID=[REDACTED]"
        );
        let redacted_dict = redacted.getattr("__dict__")?.cast_into::<PyDict>()?;
        let values: Vec<String> = redacted_dict
            .values()
            .iter()
            .filter_map(|value| value.extract::<String>().ok())
            .collect();
        assert!(values.iter().any(|value| value == "[REDACTED]"));

        Ok(())
    })
    .unwrap();
}

#[test]
fn scan_container_preserves_clean_non_string_dict_values_when_rebuilt() {
    Python::initialize();
    Python::attach(|py| -> PyResult<()> {
        let code = CString::new(
            r#"
class BadKey:
    pass

class Model:
    def __init__(self):
        self.token = "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"
        self.__dict__[BadKey()] = "side-channel"
"#,
        )
        .unwrap();
        let module = PyModule::from_code(py, code.as_c_str(), c"test_module.py", c"test_module")?;
        let instance = module.getattr("Model")?.call0()?;
        let config = SecretsDetectionConfig {
            redact: true,
            redaction_text: "[REDACTED]".to_string(),
            ..Default::default()
        };

        let (count, redacted, findings) = scan_container(py, &instance, &config)?;

        assert_eq!(count, 1);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            redacted.getattr("token")?.extract::<String>()?,
            "AWS_ACCESS_KEY_ID=[REDACTED]"
        );
        let redacted_dict = redacted.getattr("__dict__")?.cast_into::<PyDict>()?;
        let values: Vec<String> = redacted_dict
            .values()
            .iter()
            .filter_map(|value| value.extract::<String>().ok())
            .collect();
        assert!(values.iter().any(|value| value == "side-channel"));

        Ok(())
    })
    .unwrap();
}

#[test]
fn scan_container_returns_original_for_clean_scan_state_only_object() {
    Python::initialize();
    Python::attach(|py| -> PyResult<()> {
        let code = CString::new(
            r#"
class BadKey:
    pass

class Model:
    def __init__(self):
        self.__dict__[BadKey()] = "side-channel"
"#,
        )
        .unwrap();
        let module = PyModule::from_code(py, code.as_c_str(), c"test_module.py", c"test_module")?;
        let instance = module.getattr("Model")?.call0()?;
        let config = SecretsDetectionConfig {
            redact: true,
            redaction_text: "[REDACTED]".to_string(),
            ..Default::default()
        };

        let (count, redacted, findings) = scan_container(py, &instance, &config)?;

        assert_eq!(count, 0);
        assert_eq!(findings.len(), 0);
        assert!(redacted.is(&instance));

        Ok(())
    })
    .unwrap();
}

#[test]
fn scan_container_returns_original_for_clean_scan_state_and_clean_serialized_path() {
    Python::initialize();
    Python::attach(|py| -> PyResult<()> {
        let code = CString::new(
            r#"
class BadKey:
    pass

class Model:
    def __init__(self):
        self.text = "clean"
        self.__dict__[BadKey()] = "side-channel"

    def model_dump(self):
        return {"text": "also clean"}
"#,
        )
        .unwrap();
        let module = PyModule::from_code(py, code.as_c_str(), c"test_module.py", c"test_module")?;
        let instance = module.getattr("Model")?.call0()?;
        let config = SecretsDetectionConfig {
            redact: true,
            redaction_text: "[REDACTED]".to_string(),
            ..Default::default()
        };

        let (count, redacted, findings) = scan_container(py, &instance, &config)?;

        assert_eq!(count, 0);
        assert_eq!(findings.len(), 0);
        assert!(redacted.is(&instance));

        Ok(())
    })
    .unwrap();
}

#[test]
fn scan_container_preserves_clean_scan_state_after_serialized_redaction() {
    Python::initialize();
    Python::attach(|py| -> PyResult<()> {
        let code = CString::new(
            r#"
class BadKey:
    pass

class Model:
    def __init__(self):
        self.value = "clean"
        self.__dict__[BadKey()] = "side-channel"
        self.__dict__[BadKey()] = self

    def model_dump(self):
        return {"value": "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"}
"#,
        )
        .unwrap();
        let module = PyModule::from_code(py, code.as_c_str(), c"test_module.py", c"test_module")?;
        let instance = module.getattr("Model")?.call0()?;
        let config = SecretsDetectionConfig {
            redact: true,
            redaction_text: "[REDACTED]".to_string(),
            ..Default::default()
        };

        let (count, redacted, findings) = scan_container(py, &instance, &config)?;

        assert_eq!(count, 1);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            redacted.getattr("value")?.extract::<String>()?,
            "AWS_ACCESS_KEY_ID=[REDACTED]"
        );
        let redacted_dict = redacted.getattr("__dict__")?.cast_into::<PyDict>()?;
        let mut saw_side_channel = false;
        let mut saw_back_edge = false;
        for value in redacted_dict.values().iter() {
            if value.is(&redacted) {
                saw_back_edge = true;
            }
            if value
                .extract::<String>()
                .is_ok_and(|text| text == "side-channel")
            {
                saw_side_channel = true;
            }
        }
        assert!(saw_side_channel);
        assert!(saw_back_edge);

        Ok(())
    })
    .unwrap();
}

#[test]
fn scan_container_does_not_apply_scan_state_to_different_serialized_object_type() {
    Python::initialize();
    Python::attach(|py| -> PyResult<()> {
        let code = CString::new(
            r#"
class BadKey:
    pass

class View:
    def __init__(self):
        self.secret = "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"

class Model:
    def __init__(self):
        self.__dict__[BadKey()] = "side-channel"

    def model_dump(self):
        return View()
"#,
        )
        .unwrap();
        let module = PyModule::from_code(py, code.as_c_str(), c"test_module.py", c"test_module")?;
        let instance = module.getattr("Model")?.call0()?;
        let view_type = module.getattr("View")?;
        let config = SecretsDetectionConfig {
            redact: true,
            redaction_text: "[REDACTED]".to_string(),
            ..Default::default()
        };

        let (count, redacted, findings) = scan_container(py, &instance, &config)?;

        assert_eq!(count, 1);
        assert_eq!(findings.len(), 1);
        assert!(redacted.is_instance(&view_type)?);
        assert_eq!(
            redacted.getattr("secret")?.extract::<String>()?,
            "AWS_ACCESS_KEY_ID=[REDACTED]"
        );
        let redacted_dict = redacted.getattr("__dict__")?.cast_into::<PyDict>()?;
        let values: Vec<String> = redacted_dict
            .values()
            .iter()
            .filter_map(|value| value.extract::<String>().ok())
            .collect();
        assert!(!values.iter().any(|value| value == "side-channel"));

        Ok(())
    })
    .unwrap();
}

#[test]
fn scan_container_rewrites_scan_state_only_back_edges() {
    Python::initialize();
    Python::attach(|py| -> PyResult<()> {
        let code = CString::new(
            r#"
class BadKey:
    pass

class Model:
    def __init__(self):
        self.__dict__[BadKey()] = "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"
        self.__dict__[BadKey()] = self
"#,
        )
        .unwrap();
        let module = PyModule::from_code(py, code.as_c_str(), c"test_module.py", c"test_module")?;
        let instance = module.getattr("Model")?.call0()?;
        let config = SecretsDetectionConfig {
            redact: true,
            redaction_text: "[REDACTED]".to_string(),
            ..Default::default()
        };

        let (count, redacted, findings) = scan_container(py, &instance, &config)?;

        assert_eq!(count, 1);
        assert_eq!(findings.len(), 1);
        assert!(!redacted.is(&instance));
        let redacted_dict = redacted.getattr("__dict__")?.cast_into::<PyDict>()?;
        let mut saw_redacted_secret = false;
        let mut saw_back_edge = false;
        for value in redacted_dict.values().iter() {
            if value.is(&redacted) {
                saw_back_edge = true;
            }
            if value
                .extract::<String>()
                .is_ok_and(|text| text == "AWS_ACCESS_KEY_ID=[REDACTED]")
            {
                saw_redacted_secret = true;
            }
        }
        assert!(saw_redacted_secret);
        assert!(saw_back_edge);

        Ok(())
    })
    .unwrap();
}

#[test]
fn scan_container_scans_nested_same_type_model_dump_state() {
    Python::initialize();
    Python::attach(|py| -> PyResult<()> {
        let code = CString::new(
            r#"
class Wrapper:
    def __init__(self, value, nested=False):
        self.value = value
        self.nested = nested

    def model_dump(self):
        if self.nested:
            return "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"
        return Wrapper("clean", nested=True)
"#,
        )
        .unwrap();
        let module = PyModule::from_code(py, code.as_c_str(), c"test_module.py", c"test_module")?;
        let instance = module.getattr("Wrapper")?.call1(("clean",))?;
        let config = SecretsDetectionConfig {
            redact: true,
            redaction_text: "[REDACTED]".to_string(),
            ..Default::default()
        };

        let (count, redacted, findings) = scan_container(py, &instance, &config)?;

        assert_eq!(count, 1);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            redacted.extract::<String>()?,
            "AWS_ACCESS_KEY_ID=[REDACTED]"
        );
        assert_eq!(instance.getattr("value")?.extract::<String>()?, "clean");

        Ok(())
    })
    .unwrap();
}

#[test]
fn root_duplicate_helper_rejects_non_string_rebuild_keys_before_lookup() {
    Python::initialize();
    Python::attach(|py| -> PyResult<()> {
        let code = CString::new(
            r#"
class BadKey:
    def __hash__(self):
        return hash("root")

    def __eq__(self, other):
        raise RuntimeError("root lookup should not compare custom keys")
"#,
        )
        .unwrap();
        let module = PyModule::from_code(py, code.as_c_str(), c"test_module.py", c"test_module")?;
        let bad_key = module.getattr("BadKey")?.call0()?;
        let rebuild = PyDict::new(py);
        rebuild.set_item(&bad_key, "clean")?;
        let serialized = PyString::new(py, "clean");

        let duplicates = serialized_duplicates_rebuild_root(serialized.as_any(), rebuild.as_any())?;

        assert!(!duplicates);

        Ok(())
    })
    .unwrap();
}

#[test]
fn scan_container_does_not_double_count_matching_model_dump_dict() {
    Python::initialize();
    Python::attach(|py| -> PyResult<()> {
        let code = CString::new(
            r#"
class Model:
    def __init__(self):
        self.text = "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"

    def model_dump(self):
        return {"text": self.text}
"#,
        )
        .unwrap();
        let module = PyModule::from_code(py, code.as_c_str(), c"test_module.py", c"test_module")?;
        let instance = module.getattr("Model")?.call0()?;
        let config = SecretsDetectionConfig::default();

        let (count, _, findings) = scan_container(py, &instance, &config)?;

        assert_eq!(count, 1);
        assert_eq!(findings.len(), 1);

        Ok(())
    })
    .unwrap();
}

#[test]
fn scan_container_detects_str_subclass_secret() {
    Python::initialize();
    Python::attach(|py| -> PyResult<()> {
        let code = CString::new(
            r#"
class SecretString(str):
    pass

payload = SecretString("AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE")
"#,
        )
        .unwrap();
        let module = PyModule::from_code(py, code.as_c_str(), c"test_module.py", c"test_module")?;
        let payload = module.getattr("payload")?;
        let config = SecretsDetectionConfig::default();

        let (count, _, findings) = scan_container(py, &payload, &config)?;

        assert_eq!(count, 1);
        assert_eq!(findings.len(), 1);

        Ok(())
    })
    .unwrap();
}

#[test]
fn scan_container_does_not_double_count_matching_model_dump_list() {
    Python::initialize();
    Python::attach(|py| -> PyResult<()> {
        let code = CString::new(
            r#"
class Model:
    def __init__(self):
        self.items = ["AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"]

    def model_dump(self):
        return {"items": list(self.items)}
"#,
        )
        .unwrap();
        let module = PyModule::from_code(py, code.as_c_str(), c"test_module.py", c"test_module")?;
        let instance = module.getattr("Model")?.call0()?;
        let config = SecretsDetectionConfig::default();

        let (count, _, findings) = scan_container(py, &instance, &config)?;

        assert_eq!(count, 1);
        assert_eq!(findings.len(), 1);

        Ok(())
    })
    .unwrap();
}

#[test]
fn scan_container_does_not_double_count_cyclic_model_dump_secret() {
    Python::initialize();
    Python::attach(|py| -> PyResult<()> {
        let code = CString::new(
            r#"
class Model:
    def __init__(self):
        self.items = ["AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"]
        self.items.append(self.items)

    def model_dump(self):
        items = ["AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"]
        items.append(items)
        return {"items": items}
"#,
        )
        .unwrap();
        let module = PyModule::from_code(py, code.as_c_str(), c"test_module.py", c"test_module")?;
        let instance = module.getattr("Model")?.call0()?;
        let config = SecretsDetectionConfig::default();

        let (count, _, findings) = scan_container(py, &instance, &config)?;

        assert_eq!(count, 1);
        assert_eq!(findings.len(), 1);

        Ok(())
    })
    .unwrap();
}

#[test]
fn scan_container_does_not_double_count_duplicate_root_serialized_state() {
    Python::initialize();
    Python::attach(|py| -> PyResult<()> {
        let code = CString::new(
            r#"
class RootObject:
    def __init__(self):
        self.root = "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"

    def model_dump(self):
        return str(self.root)
"#,
        )
        .unwrap();
        let module = PyModule::from_code(py, code.as_c_str(), c"test_module.py", c"test_module")?;
        let instance = module.getattr("RootObject")?.call0()?;
        let config = SecretsDetectionConfig::default();

        let (count, _, findings) = scan_container(py, &instance, &config)?;

        assert_eq!(count, 1);
        assert_eq!(findings.len(), 1);

        Ok(())
    })
    .unwrap();
}

#[test]
fn scan_container_does_not_double_count_with_copied_model_dump_scalar() {
    Python::initialize();
    Python::attach(|py| -> PyResult<()> {
        let code = CString::new(
            r#"
class Model:
    def __init__(self):
        self.text = "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"
        self.num = int("1000000000000000000000")

    def model_dump(self):
        return {"text": self.text, "num": int(str(self.num))}
"#,
        )
        .unwrap();
        let module = PyModule::from_code(py, code.as_c_str(), c"test_module.py", c"test_module")?;
        let instance = module.getattr("Model")?.call0()?;
        let config = SecretsDetectionConfig::default();

        let (count, _, findings) = scan_container(py, &instance, &config)?;

        assert_eq!(count, 1);
        assert_eq!(findings.len(), 1);

        Ok(())
    })
    .unwrap();
}

#[test]
fn scan_container_scans_cyclic_model_dump_without_duplicate_gate_recursion() {
    Python::initialize();
    Python::attach(|py| -> PyResult<()> {
        let code = CString::new(
            r#"
class Model:
    def __init__(self):
        self.items = []
        self.items.append(self.items)

    def model_dump(self):
        items = []
        items.append(items)
        return {"items": items}
"#,
        )
        .unwrap();
        let module = PyModule::from_code(py, code.as_c_str(), c"test_module.py", c"test_module")?;
        let instance = module.getattr("Model")?.call0()?;
        let config = SecretsDetectionConfig::default();

        let (count, _, findings) = scan_container(py, &instance, &config)?;

        assert_eq!(count, 0);
        assert_eq!(findings.len(), 0);

        Ok(())
    })
    .unwrap();
}

#[test]
fn duplicate_gate_ignores_non_string_model_dump_keys_without_lookup() {
    Python::initialize();
    Python::attach(|py| -> PyResult<()> {
        let code = CString::new(
            r#"
class BadKey:
    def __hash__(self):
        return hash("text")

    def __eq__(self, other):
        raise RuntimeError("duplicate gate should not compare custom keys")
"#,
        )
        .unwrap();
        let module = PyModule::from_code(py, code.as_c_str(), c"test_module.py", c"test_module")?;
        let bad_key = module.getattr("BadKey")?.call0()?;
        let serialized = PyDict::new(py);
        serialized.set_item(&bad_key, "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE")?;
        let rebuild = PyDict::new(py);
        rebuild.set_item("text", "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE")?;

        let duplicates =
            serialized_dict_duplicates_rebuild_state(serialized.as_any(), rebuild.as_any())?;

        assert!(!duplicates);

        Ok(())
    })
    .unwrap();
}

#[test]
fn scan_container_ignores_duplicate_gate_for_non_string_model_dump_keys() {
    Python::initialize();
    Python::attach(|py| -> PyResult<()> {
        let code = CString::new(
            r#"
class BadKey:
    def __hash__(self):
        return hash("text")

    def __eq__(self, other):
        raise RuntimeError("duplicate gate should not compare custom keys")

class Model:
    def __init__(self):
        self.text = "clean"

    def model_dump(self):
        return {BadKey(): "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"}
"#,
        )
        .unwrap();
        let module = PyModule::from_code(py, code.as_c_str(), c"test_module.py", c"test_module")?;
        let instance = module.getattr("Model")?.call0()?;
        let config = SecretsDetectionConfig {
            redact: true,
            redaction_text: "[REDACTED]".to_string(),
            ..Default::default()
        };

        let (count, redacted, findings) = scan_container(py, &instance, &config)?;

        assert_eq!(count, 1);
        assert_eq!(findings.len(), 1);
        assert_eq!(instance.getattr("text")?.extract::<String>()?, "clean");

        let redacted_dict = redacted.cast::<PyDict>()?;
        assert_eq!(redacted_dict.len(), 1);
        let values: Vec<String> = redacted_dict
            .values()
            .iter()
            .map(|value| value.extract::<String>())
            .collect::<PyResult<_>>()?;
        assert_eq!(values.len(), 1);
        assert!(values[0].contains(&config.redaction_text));
        assert!(!values[0].contains("AKIAFAKE12345EXAMPLE"));

        Ok(())
    })
    .unwrap();
}

#[test]
fn serialized_result_returns_non_string_key_dict_without_object_update() {
    Python::initialize();
    Python::attach(|py| -> PyResult<()> {
        let code = CString::new(
            r#"
class BadKey:
    pass

class Model:
    def __init__(self):
        self.text = "clean"

    def model_copy(self, update=None):
        raise RuntimeError("model_copy should not run for non-string-key serialized dict")
"#,
        )
        .unwrap();
        let module = PyModule::from_code(py, code.as_c_str(), c"test_module.py", c"test_module")?;
        let instance = module.getattr("Model")?.call0()?;
        let state = PyDict::new(py);
        state.set_item(module.getattr("BadKey")?.call0()?, "[REDACTED]")?;

        let result = serialized_result(py, &instance, &state.clone().into_any())?;

        assert!(result.is(&state));
        assert_eq!(instance.getattr("text")?.extract::<String>()?, "clean");

        Ok(())
    })
    .unwrap();
}
