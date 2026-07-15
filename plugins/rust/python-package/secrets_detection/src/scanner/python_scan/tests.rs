// Copyright 2026
// SPDX-License-Identifier: Apache-2.0

use std::ffi::CString;

use pyo3::types::PyModule;

use super::*;

#[test]
fn findings_scan_counts_nested_container_paths_without_rebuilding() {
    Python::initialize();
    Python::attach(|py| -> PyResult<()> {
        let config = SecretsDetectionConfig::default();
        let payload = PyDict::new(py);
        let list = PyList::new(
            py,
            [
                "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE",
                "plain",
                "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE",
            ],
        )?;
        let tuple = PyTuple::new(
            py,
            [
                "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE",
                "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE",
            ],
        )?;
        payload.set_item("list", list)?;
        payload.set_item("tuple", tuple)?;

        let (count, findings) = scan_container_findings(py, payload.as_any(), &config)?;

        assert_eq!(count, 4);
        assert_eq!(findings.len(), 4);

        Ok(())
    })
    .unwrap();
}

#[test]
fn findings_scan_counts_dict_subclass_items() {
    Python::initialize();
    Python::attach(|py| -> PyResult<()> {
        let code = CString::new(
            r#"
class CopyOnWriteDict(dict):
    def __init__(self, original):
        super().__init__()
        self._original = original

    def __getitem__(self, key):
        return super().__getitem__(key) if key in self else self._original[key]

    def __iter__(self):
        return iter(self._original)

    def __len__(self):
        return len(self._original)

    def items(self):
        return ((key, self[key]) for key in self)
"#,
        )
        .unwrap();
        let module = PyModule::from_code(py, code.as_c_str(), c"test_module.py", c"test_module")?;
        let original = PyDict::new(py);
        original.set_item("message", "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE")?;
        let payload = module.getattr("CopyOnWriteDict")?.call1((original,))?;
        let config = SecretsDetectionConfig::default();

        let (count, findings) = scan_container_findings(py, &payload, &config)?;

        assert_eq!(count, 1);
        assert_eq!(findings.len(), 1);

        Ok(())
    })
    .unwrap();
}

#[test]
fn scan_container_redacts_dict_subclass_items() {
    Python::initialize();
    Python::attach(|py| -> PyResult<()> {
        let code = CString::new(
            r#"
class CopyOnWriteDict(dict):
    def __init__(self, original):
        super().__init__()
        self._original = original

    def __getitem__(self, key):
        return super().__getitem__(key) if key in self else self._original[key]

    def __iter__(self):
        return iter(self._original)

    def __len__(self):
        return len(self._original)

    def items(self):
        return ((key, self[key]) for key in self)
"#,
        )
        .unwrap();
        let module = PyModule::from_code(py, code.as_c_str(), c"test_module.py", c"test_module")?;
        let original = PyDict::new(py);
        original.set_item("message", "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE")?;
        let payload = module.getattr("CopyOnWriteDict")?.call1((original,))?;
        let config = SecretsDetectionConfig {
            redact: true,
            redaction_text: "[REDACTED]".to_string(),
            ..Default::default()
        };

        let (count, redacted, findings) = scan_container(py, &payload, &config)?;

        assert_eq!(count, 1);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            redacted
                .cast::<PyDict>()?
                .get_item("message")?
                .expect("message exists")
                .extract::<String>()?,
            "AWS_ACCESS_KEY_ID=[REDACTED]"
        );

        Ok(())
    })
    .unwrap();
}

#[test]
fn field_filters_apply_to_plain_dicts_in_findings_and_redaction_scans() {
    Python::initialize();
    Python::attach(|py| -> PyResult<()> {
        let payload = PyDict::new(py);
        let layer1 = PyDict::new(py);
        let layer2 = PyDict::new(py);
        layer1.set_item("public", "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE")?;
        layer2.set_item("layer3", "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE")?;
        layer1.set_item("layer2", &layer2)?;
        payload.set_item("layer1", &layer1)?;
        payload.set_item("layer10", "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE")?;

        let config = config_with_field_filters(py, &["layer1"], &["layer1.layer2.layer3"], true)?;

        let (findings_count, findings) = scan_container_findings(py, payload.as_any(), &config)?;
        let (redacted_count, redacted, redacted_findings) =
            scan_container(py, payload.as_any(), &config)?;

        assert_eq!(findings_count, 1);
        assert_eq!(findings.len(), 1);
        assert_eq!(redacted_count, findings_count);
        assert_eq!(redacted_findings.len(), findings.len());
        let redacted_payload = redacted.cast::<PyDict>()?;
        let redacted_layer1 = redacted_payload
            .get_item("layer1")?
            .expect("layer1 exists")
            .cast_into::<PyDict>()?;
        assert_eq!(
            redacted_layer1
                .get_item("public")?
                .expect("public exists")
                .extract::<String>()?,
            "AWS_ACCESS_KEY_ID=[REDACTED]"
        );
        let redacted_layer2 = redacted_layer1
            .get_item("layer2")?
            .expect("layer2 exists")
            .cast_into::<PyDict>()?;
        assert_eq!(
            redacted_layer2
                .get_item("layer3")?
                .expect("layer3 exists")
                .extract::<String>()?,
            "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"
        );
        assert_eq!(
            redacted_payload
                .get_item("layer10")?
                .expect("layer10 exists")
                .extract::<String>()?,
            "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"
        );

        Ok(())
    })
    .unwrap();
}

#[test]
fn field_filters_reach_nested_allowlisted_paths_through_lists_and_tuples() {
    Python::initialize();
    Python::attach(|py| -> PyResult<()> {
        let first_user = PyDict::new(py);
        let first_credentials = PyDict::new(py);
        first_credentials.set_item("token", "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE")?;
        first_credentials.set_item("other", "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE")?;
        first_user.set_item("credentials", &first_credentials)?;

        let second_user = PyDict::new(py);
        let second_credentials = PyDict::new(py);
        second_credentials.set_item("token", "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE")?;
        second_user.set_item("credentials", &second_credentials)?;
        let tuple_item = PyTuple::new(py, [second_user.into_any().unbind()])?;

        let users = PyList::new(
            py,
            [
                first_user.into_any().unbind(),
                tuple_item.into_any().unbind(),
            ],
        )?;
        let payload = PyDict::new(py);
        payload.set_item("users", &users)?;
        payload.set_item("outside", "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE")?;

        let config = config_with_field_filters(py, &["users.credentials.token"], &[], true)?;

        let (findings_count, findings) = scan_container_findings(py, payload.as_any(), &config)?;
        let (redacted_count, redacted, redacted_findings) =
            scan_container(py, payload.as_any(), &config)?;

        assert_eq!(findings_count, 2);
        assert_eq!(findings.len(), 2);
        assert_eq!(redacted_count, findings_count);
        assert_eq!(redacted_findings.len(), findings.len());
        let redacted_payload = redacted.cast::<PyDict>()?;
        let redacted_users = redacted_payload
            .get_item("users")?
            .expect("users exists")
            .cast_into::<PyList>()?;
        let redacted_first_user = redacted_users.get_item(0)?.cast_into::<PyDict>()?;
        let redacted_first_fields = redacted_first_user
            .get_item("credentials")?
            .expect("credentials exists")
            .cast_into::<PyDict>()?;
        assert_eq!(
            redacted_first_fields
                .get_item("token")?
                .expect("token exists")
                .extract::<String>()?,
            "AWS_ACCESS_KEY_ID=[REDACTED]"
        );
        assert_eq!(
            redacted_first_fields
                .get_item("other")?
                .expect("other exists")
                .extract::<String>()?,
            "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"
        );
        let redacted_tuple = redacted_users.get_item(1)?.cast_into::<PyTuple>()?;
        let redacted_second_user = redacted_tuple.get_item(0)?.cast_into::<PyDict>()?;
        let redacted_second_fields = redacted_second_user
            .get_item("credentials")?
            .expect("credentials exists")
            .cast_into::<PyDict>()?;
        assert_eq!(
            redacted_second_fields
                .get_item("token")?
                .expect("token exists")
                .extract::<String>()?,
            "AWS_ACCESS_KEY_ID=[REDACTED]"
        );
        assert_eq!(
            redacted_payload
                .get_item("outside")?
                .expect("outside exists")
                .extract::<String>()?,
            "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"
        );

        Ok(())
    })
    .unwrap();
}

#[test]
fn field_filters_apply_to_dict_subclasses() {
    Python::initialize();
    Python::attach(|py| -> PyResult<()> {
        let code = CString::new(
            r#"
class CopyOnWriteDict(dict):
    def __init__(self, original):
        super().__init__()
        self._original = original

    def __getitem__(self, key):
        return super().__getitem__(key) if key in self else self._original[key]

    def __iter__(self):
        return iter(self._original)

    def __len__(self):
        return len(self._original)

    def items(self):
        return ((key, self[key]) for key in self)
"#,
        )
        .unwrap();
        let module = PyModule::from_code(py, code.as_c_str(), c"test_module.py", c"test_module")?;
        let original = PyDict::new(py);
        original.set_item("message", "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE")?;
        original.set_item("ignored", "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE")?;
        let payload = module.getattr("CopyOnWriteDict")?.call1((original,))?;
        let config = config_with_field_filters(py, &["message"], &[], true)?;

        let (count, redacted, findings) = scan_container(py, &payload, &config)?;

        assert_eq!(count, 1);
        assert_eq!(findings.len(), 1);
        let redacted_dict = redacted.cast::<PyDict>()?;
        assert_eq!(
            redacted_dict
                .get_item("message")?
                .expect("message exists")
                .extract::<String>()?,
            "AWS_ACCESS_KEY_ID=[REDACTED]"
        );
        assert_eq!(
            redacted_dict
                .get_item("ignored")?
                .expect("ignored exists")
                .extract::<String>()?,
            "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"
        );

        Ok(())
    })
    .unwrap();
}

#[test]
fn field_filters_apply_to_slot_object_fields() {
    Python::initialize();
    Python::attach(|py| -> PyResult<()> {
        let code = CString::new(
            r#"
class Model:
    __slots__ = ("token", "ignored")

    def __init__(self):
        self.token = "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"
        self.ignored = "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"
"#,
        )
        .unwrap();
        let module = PyModule::from_code(py, code.as_c_str(), c"test_module.py", c"test_module")?;
        let instance = module.getattr("Model")?.call0()?;
        let config = config_with_field_filters(py, &["token"], &[], true)?;

        let (count, redacted, findings) = scan_container(py, &instance, &config)?;

        assert_eq!(count, 1);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            redacted.getattr("token")?.extract::<String>()?,
            "AWS_ACCESS_KEY_ID=[REDACTED]"
        );
        assert_eq!(
            redacted.getattr("ignored")?.extract::<String>()?,
            "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"
        );

        Ok(())
    })
    .unwrap();
}

#[test]
fn field_filters_do_not_suppress_direct_scalar_roots() {
    Python::initialize();
    Python::attach(|py| -> PyResult<()> {
        let text = PyString::new(py, "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE");
        let config = config_with_field_filters(py, &["never"], &["also_never"], true)?;

        let (findings_count, findings) = scan_container_findings(py, text.as_any(), &config)?;
        let (redacted_count, redacted, redacted_findings) =
            scan_container(py, text.as_any(), &config)?;

        assert_eq!(findings_count, 1);
        assert_eq!(findings.len(), 1);
        assert_eq!(redacted_count, findings_count);
        assert_eq!(redacted_findings.len(), findings.len());
        assert_eq!(
            redacted.extract::<String>()?,
            "AWS_ACCESS_KEY_ID=[REDACTED]"
        );

        Ok(())
    })
    .unwrap();
}

#[test]
fn findings_scan_counts_object_internal_and_serialized_states_once() {
    Python::initialize();
    Python::attach(|py| -> PyResult<()> {
        let code = CString::new(
            r#"
class BadKey:
    pass

class Payload:
    def __init__(self):
        self.internal = "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"
        self.__dict__[BadKey()] = "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"

    def model_dump(self):
        return {"serialized": "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"}
"#,
        )
        .unwrap();
        let module = PyModule::from_code(py, code.as_c_str(), c"test_module.py", c"test_module")?;
        let instance = module.getattr("Payload")?.call0()?;
        let config = SecretsDetectionConfig::default();

        let (count, findings) = scan_container_findings(py, &instance, &config)?;

        assert_eq!(count, 3);
        assert_eq!(findings.len(), 3);

        Ok(())
    })
    .unwrap();
}

#[test]
fn findings_scan_counts_serialized_only_state() {
    Python::initialize();
    Python::attach(|py| -> PyResult<()> {
        let code = CString::new(
            r#"
class Payload:
    __slots__ = ()

    def model_dump(self):
        return "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"
"#,
        )
        .unwrap();
        let module = PyModule::from_code(py, code.as_c_str(), c"test_module.py", c"test_module")?;
        let instance = module.getattr("Payload")?.call0()?;
        let config = SecretsDetectionConfig::default();

        let (count, findings) = scan_container_findings(py, &instance, &config)?;

        assert_eq!(count, 1);
        assert_eq!(findings.len(), 1);

        Ok(())
    })
    .unwrap();
}

#[test]
fn findings_scan_handles_self_referential_objects_without_double_counting() {
    Python::initialize();
    Python::attach(|py| -> PyResult<()> {
        let code = CString::new(
            r#"
class Payload:
    def __init__(self):
        self.secret = "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"
        self.self_ref = self
"#,
        )
        .unwrap();
        let module = PyModule::from_code(py, code.as_c_str(), c"test_module.py", c"test_module")?;
        let instance = module.getattr("Payload")?.call0()?;
        let config = SecretsDetectionConfig::default();

        let (count, findings) = scan_container_findings(py, &instance, &config)?;

        assert_eq!(count, 1);
        assert_eq!(findings.len(), 1);

        Ok(())
    })
    .unwrap();
}

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
fn scan_container_rewrites_back_edges_inside_denied_subtrees() {
    Python::initialize();
    Python::attach(|py| -> PyResult<()> {
        let payload = PyDict::new(py);
        let denied = PyDict::new(py);
        payload.set_item("secret", "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE")?;
        payload.set_item("denied", &denied)?;
        denied.set_item("own_secret", "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE")?;
        denied.set_item("back", &payload)?;

        let config_dict = PyDict::new(py);
        config_dict.set_item("redact", true)?;
        config_dict.set_item("redaction_text", "[REDACTED]")?;
        config_dict.set_item("field_denylist", ["denied"])?;
        let config = SecretsDetectionConfig::from_py_dict(&config_dict)?;

        let (count, redacted, findings) = scan_container(py, payload.as_any(), &config)?;

        assert_eq!(count, 1);
        assert_eq!(findings.len(), 1);
        let redacted_dict = redacted.cast::<PyDict>()?;
        assert_eq!(
            redacted_dict
                .get_item("secret")?
                .expect("secret exists")
                .extract::<String>()?,
            "AWS_ACCESS_KEY_ID=[REDACTED]"
        );
        let denied_dict = redacted_dict
            .get_item("denied")?
            .expect("denied exists")
            .cast_into::<PyDict>()?;
        assert_eq!(
            denied_dict
                .get_item("own_secret")?
                .expect("own_secret exists")
                .extract::<String>()?,
            "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"
        );
        assert!(
            denied_dict
                .get_item("back")?
                .expect("back exists")
                .is(&redacted)
        );

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

fn config_with_field_filters(
    py: Python<'_>,
    allowlist: &[&str],
    denylist: &[&str],
    redact: bool,
) -> PyResult<SecretsDetectionConfig> {
    let config = PyDict::new(py);
    config.set_item("redact", redact)?;
    config.set_item("redaction_text", "[REDACTED]")?;
    config.set_item("field_allowlist", allowlist)?;
    config.set_item("field_denylist", denylist)?;
    SecretsDetectionConfig::from_py_dict(&config)
}
