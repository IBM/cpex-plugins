// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
//
// Rust-owned PII filter plugin core. Python only keeps a tiny compatibility
// shim so the gateway can continue importing a `Plugin` subclass.

use std::collections::HashMap;

use cpex_framework_bridge::{
    build_framework_object, build_framework_object_dyn, default_result as bridge_default_result,
};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList, PyModule};
#[cfg(feature = "stub-gen")]
use pyo3_stub_gen::derive::*;

use crate::config::PIIType;
use crate::detector::{Detection, PIIDetectorRust};

const LOGGER_NAME: &str = "cpex_pii_filter.pii_filter";

#[cfg_attr(feature = "stub-gen", gen_stub_pyclass)]
#[pyclass]
pub struct PIIFilterPluginCore {
    detector: PIIDetectorRust,
}

#[cfg_attr(feature = "stub-gen", gen_stub_pymethods)]
#[pymethods]
impl PIIFilterPluginCore {
    #[new]
    pub fn new(config: &Bound<'_, PyAny>) -> PyResult<Self> {
        let detector = PIIDetectorRust::new(config)?;
        Ok(Self { detector })
    }

    #[pyo3(signature = (payload, context, extensions=None))]
    pub fn prompt_pre_fetch(
        &self,
        py: Python<'_>,
        payload: &Bound<'_, PyAny>,
        context: &Bound<'_, PyAny>,
        extensions: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Py<PyAny>> {
        let _ = &context;
        let trace_id = read_trace_id(extensions);
        self.handle_nested_stage(
            py,
            payload,
            trace_id.as_deref(),
            NestedStageSpec {
                source_attr: "args",
                stage: "prompt_pre_fetch",
                result_class: "PromptPrehookResult",
                subject_attr: "prompt_id",
                violation_reason: "PII detected in prompt arguments",
                violation_description: "Sensitive information detected in prompt arguments",
                violation_code: "PII_DETECTED",
            },
        )
    }

    #[pyo3(signature = (payload, context, extensions=None))]
    pub fn prompt_post_fetch(
        &self,
        py: Python<'_>,
        payload: &Bound<'_, PyAny>,
        context: &Bound<'_, PyAny>,
        extensions: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Py<PyAny>> {
        let trace_id = read_trace_id(extensions);
        let result = payload.getattr("result")?;
        let messages_value = result.getattr("messages")?;
        let Ok(messages) = messages_value.cast::<PyList>() else {
            return default_result(py, "PromptPosthookResult");
        };

        let mut updated_messages = Vec::with_capacity(messages.len());
        let mut changed = false;
        let mut accumulated_detections: HashMap<PIIType, Vec<Detection>> = HashMap::new();

        for message in messages.iter() {
            let Ok(content) = message.getattr("content") else {
                updated_messages.push(clone_python_object(py, &message)?.unbind());
                continue;
            };
            let Ok(text_obj) = content.getattr("text") else {
                updated_messages.push(clone_payload_with_attr(
                    py,
                    &message,
                    "content",
                    &clone_python_object(py, &content)?.unbind(),
                )?);
                continue;
            };
            let Ok(text) = text_obj.extract::<String>() else {
                updated_messages.push(clone_payload_with_attr(
                    py,
                    &message,
                    "content",
                    &clone_python_object(py, &content)?.unbind(),
                )?);
                continue;
            };

            let detections = self.detector.detect_rust(&text)?;
            if detections.is_empty() {
                updated_messages.push(clone_prompt_message(py, &message, &content, &text_obj)?);
                continue;
            }

            let role = message.getattr("role")?.extract::<String>().ok();

            if self.detector.config.block_on_detection {
                self.log_detections(
                    py,
                    "prompt_post_fetch",
                    &detections,
                    "blocked",
                    role.as_deref(),
                    true,
                )?;
                let violation = self.build_violation(
                    py,
                    "PII detected in prompt messages",
                    "Sensitive information detected in prompt result",
                    "PII_DETECTED_IN_PROMPT_RESULT",
                    &detections,
                )?;
                return build_blocked_result(
                    py,
                    trace_id.as_deref(),
                    "PromptPosthookResult",
                    violation,
                    &detections,
                    "prompt_post_fetch",
                );
            }

            let masked = self.detector.mask_rust(&text, &detections)?;
            let masked_text = masked.into_pyobject(py)?.into_any().unbind();
            self.log_detections(
                py,
                "prompt_post_fetch",
                &detections,
                "masked",
                role.as_deref(),
                false,
            )?;
            updated_messages.push(clone_prompt_message(
                py,
                &message,
                &content,
                masked_text.bind(py),
            )?);
            changed = true;
            for (kind, items) in detections {
                accumulated_detections
                    .entry(kind)
                    .or_default()
                    .extend(items);
            }
        }

        let _ = &context;
        if changed {
            let cloned_messages = PyList::empty(py);
            for message in updated_messages {
                cloned_messages.append(message.bind(py))?;
            }
            let cloned_result = clone_payload_with_attr(
                py,
                &result,
                "messages",
                &cloned_messages.into_any().unbind(),
            )?;
            let mut kwargs: Vec<(&str, Py<PyAny>)> = vec![(
                "modified_payload",
                clone_payload_with_attr(py, payload, "result", &cloned_result)?,
            )];
            push_metrics_kwarg(
                py,
                trace_id.as_deref(),
                &mut kwargs,
                &accumulated_detections,
                true,
                "prompt_post_fetch",
            );
            return build_result_dyn(py, "PromptPosthookResult", kwargs);
        }

        default_result(py, "PromptPosthookResult")
    }

    #[pyo3(signature = (payload, context, extensions=None))]
    pub fn tool_pre_invoke(
        &self,
        py: Python<'_>,
        payload: &Bound<'_, PyAny>,
        context: &Bound<'_, PyAny>,
        extensions: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Py<PyAny>> {
        let _ = &context;
        let trace_id = read_trace_id(extensions);
        self.handle_nested_stage(
            py,
            payload,
            trace_id.as_deref(),
            NestedStageSpec {
                source_attr: "args",
                stage: "tool_pre_invoke",
                result_class: "ToolPreInvokeResult",
                subject_attr: "name",
                violation_reason: "PII detected in tool arguments",
                violation_description: "Sensitive information detected in tool arguments",
                violation_code: "PII_DETECTED_IN_TOOL_ARGS",
            },
        )
    }

    #[pyo3(signature = (payload, context, extensions=None))]
    pub fn tool_post_invoke(
        &self,
        py: Python<'_>,
        payload: &Bound<'_, PyAny>,
        context: &Bound<'_, PyAny>,
        extensions: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Py<PyAny>> {
        let _ = &context;
        let trace_id = read_trace_id(extensions);
        self.handle_nested_stage(
            py,
            payload,
            trace_id.as_deref(),
            NestedStageSpec {
                source_attr: "result",
                stage: "tool_post_invoke",
                result_class: "ToolPostInvokeResult",
                subject_attr: "name",
                violation_reason: "PII detected in tool result",
                violation_description: "Sensitive information detected in tool result",
                violation_code: "PII_DETECTED_IN_TOOL_RESULT",
            },
        )
    }
}

impl PIIFilterPluginCore {
    fn handle_nested_stage(
        &self,
        py: Python<'_>,
        payload: &Bound<'_, PyAny>,
        trace_id: Option<&str>,
        spec: NestedStageSpec<'_>,
    ) -> PyResult<Py<PyAny>> {
        let source_value = payload.getattr(spec.source_attr)?;
        if source_value.is_none() {
            return default_result(py, spec.result_class);
        }

        let (modified, new_value, detections) =
            self.detector
                .process_nested_rust(py, &source_value, spec.source_attr)?;
        let subject = payload.getattr(spec.subject_attr)?.extract::<String>().ok();

        if !detections.is_empty() && self.detector.config.block_on_detection {
            self.log_detections(
                py,
                spec.stage,
                &detections,
                "blocked",
                subject.as_deref(),
                true,
            )?;
            let violation = self.build_violation(
                py,
                spec.violation_reason,
                spec.violation_description,
                spec.violation_code,
                &detections,
            )?;
            return build_blocked_result(
                py,
                trace_id,
                spec.result_class,
                violation,
                &detections,
                spec.stage,
            );
        }

        if !detections.is_empty() {
            self.log_detections(
                py,
                spec.stage,
                &detections,
                "masked",
                subject.as_deref(),
                false,
            )?;
        }
        if modified {
            let mut kwargs: Vec<(&str, Py<PyAny>)> = vec![(
                "modified_payload",
                clone_payload_with_attr(py, payload, spec.source_attr, &new_value)?,
            )];
            push_metrics_kwarg(py, trace_id, &mut kwargs, &detections, true, spec.stage);
            return build_result_dyn(py, spec.result_class, kwargs);
        }

        default_result(py, spec.result_class)
    }

    fn build_violation(
        &self,
        py: Python<'_>,
        reason: &str,
        description: &str,
        code: &str,
        detections: &HashMap<PIIType, Vec<Detection>>,
    ) -> PyResult<Py<PyAny>> {
        let details = PyDict::new(py);
        details.set_item("detected_types", sorted_detection_types(detections))?;
        details.set_item("count", count_detections(detections))?;

        build_framework_object(
            py,
            "PluginViolation",
            [
                ("reason", reason.into_pyobject(py)?.into_any().unbind()),
                (
                    "description",
                    description.into_pyobject(py)?.into_any().unbind(),
                ),
                ("code", code.into_pyobject(py)?.into_any().unbind()),
                ("details", details.into_any().unbind()),
            ],
        )
    }

    fn log_detections(
        &self,
        py: Python<'_>,
        stage: &str,
        detections: &HashMap<PIIType, Vec<Detection>>,
        action: &str,
        subject: Option<&str>,
        blocked: bool,
    ) -> PyResult<()> {
        if !self.detector.config.log_detections || detections.is_empty() {
            return Ok(());
        }

        let logging = PyModule::import(py, "logging")?;
        let logger = logging.getattr("getLogger")?.call1((LOGGER_NAME,))?;
        let level = if blocked {
            logging.getattr("WARNING")?
        } else {
            logging.getattr("INFO")?
        };
        let mut message = format!(
            "PII detected during {}: action={} total={} types={}",
            stage,
            action,
            count_detections(detections),
            sorted_detection_types(detections).join(",")
        );
        if let Some(subject) = subject {
            message.push_str(&format!(" subject={}", subject));
        }
        logger.call_method1("log", (level, message))?;
        Ok(())
    }
}

struct NestedStageSpec<'a> {
    source_attr: &'a str,
    stage: &'a str,
    result_class: &'a str,
    subject_attr: &'a str,
    violation_reason: &'a str,
    violation_description: &'a str,
    violation_code: &'a str,
}

/// Builds a framework result object from a variable-length kwarg list (the
/// emitting paths conditionally append a `metadata` entry when `trace_id` is
/// present, so a fixed-size array won't work here).
fn build_result_dyn(
    py: Python<'_>,
    class_name: &str,
    kwargs: Vec<(&str, Py<PyAny>)>,
) -> PyResult<Py<PyAny>> {
    build_framework_object_dyn(py, class_name, kwargs)
}

fn default_result<'py>(py: Python<'py>, class_name: &str) -> PyResult<Py<PyAny>> {
    bridge_default_result(py, class_name)
}

const MAX_DETECTION_TYPES: usize = 32;

/// Build the namespaced metrics dict for the result.metadata channel.
/// Returns None (no work) when trace_id is absent (P-1/L3). Allowlist only:
/// counts/types/stage — never matched content (S1). Bounded (S3).
fn build_pii_metrics<'py>(
    py: Python<'py>,
    trace_id: Option<&str>,
    total_detections: i64,
    total_masked: i64,
    detection_types: &[&str],
    stage: &str,
) -> PyResult<Option<Bound<'py, PyDict>>> {
    if trace_id.is_none() {
        return Ok(None);
    }
    let inner = PyDict::new(py);
    inner.set_item("total_detections", total_detections)?;
    inner.set_item("total_masked", total_masked)?;
    let mut types: Vec<&str> = detection_types.to_vec();
    types.sort_unstable();
    types.dedup();
    types.truncate(MAX_DETECTION_TYPES);
    inner.set_item("detection_types", types)?;
    inner.set_item("stage", stage)?;
    let outer = PyDict::new(py);
    outer.set_item("pii_filter", inner)?;
    Ok(Some(outer))
}

/// Best-effort attach of the namespaced metrics dict onto `kwargs` when
/// `trace_id` is present. Never fails the caller (L2): any error from
/// `build_pii_metrics` is logged once and metrics are omitted, so the normal
/// filtering result is still returned.
///
/// Gates on `trace_id` before touching `detections` at all, so untraced
/// requests (the common case) never pay for sorting/collecting types.
fn push_metrics_kwarg(
    py: Python<'_>,
    trace_id: Option<&str>,
    kwargs: &mut Vec<(&str, Py<PyAny>)>,
    detections: &HashMap<PIIType, Vec<Detection>>,
    masked: bool,
    stage: &str,
) {
    let Some(tid) = trace_id else {
        return;
    };
    let total_detections = count_detections(detections) as i64;
    let total_masked = if masked { total_detections } else { 0 };
    let type_strings = sorted_detection_types(detections);
    let types: Vec<&str> = type_strings.iter().map(String::as_str).collect();
    match build_pii_metrics(py, Some(tid), total_detections, total_masked, &types, stage) {
        Ok(Some(md)) => kwargs.push(("metadata", md.into_any().unbind())),
        Ok(None) => {}
        Err(e) => log::warn!("pii_filter: metrics build failed, omitting: {e}"),
    }
}

/// Shared blocked-path result builder used by both `prompt_post_fetch` and
/// `handle_nested_stage` — collapses the near-identical
/// `continue_processing=false` + `violation` + metrics kwargs construction.
fn build_blocked_result(
    py: Python<'_>,
    trace_id: Option<&str>,
    result_class: &str,
    violation: Py<PyAny>,
    detections: &HashMap<PIIType, Vec<Detection>>,
    stage: &str,
) -> PyResult<Py<PyAny>> {
    let mut kwargs: Vec<(&str, Py<PyAny>)> = vec![
        (
            "continue_processing",
            false.into_pyobject(py)?.to_owned().into_any().unbind(),
        ),
        ("violation", violation),
    ];
    push_metrics_kwarg(py, trace_id, &mut kwargs, detections, false, stage);
    build_result_dyn(py, result_class, kwargs)
}

fn clone_python_object<'py>(
    py: Python<'py>,
    object: &Bound<'py, PyAny>,
) -> PyResult<Bound<'py, PyAny>> {
    if object.hasattr("model_copy")? {
        object.call_method0("model_copy")
    } else {
        let copy = PyModule::import(py, "copy")?;
        copy.getattr("copy")?.call1((object,))
    }
}

fn clone_payload_with_attr(
    py: Python<'_>,
    payload: &Bound<'_, PyAny>,
    attr: &str,
    new_value: &Py<PyAny>,
) -> PyResult<Py<PyAny>> {
    let cloned = if payload.hasattr("model_copy")? {
        let kwargs = PyDict::new(py);
        let update = PyDict::new(py);
        update.set_item(attr, new_value.bind(py))?;
        kwargs.set_item("update", update)?;
        payload.call_method("model_copy", (), Some(&kwargs))?
    } else {
        let cloned = clone_python_object(py, payload)?;
        cloned.setattr(attr, new_value.bind(py))?;
        cloned
    };

    Ok(cloned.unbind())
}

fn clone_prompt_message(
    py: Python<'_>,
    message: &Bound<'_, PyAny>,
    content: &Bound<'_, PyAny>,
    text_value: &Bound<'_, PyAny>,
) -> PyResult<Py<PyAny>> {
    let cloned_content =
        clone_payload_with_attr(py, content, "text", &text_value.clone().unbind())?;
    clone_payload_with_attr(py, message, "content", &cloned_content)
}

fn count_detections(detections: &HashMap<PIIType, Vec<Detection>>) -> usize {
    detections.values().map(Vec::len).sum()
}

fn sorted_detection_types(detections: &HashMap<PIIType, Vec<Detection>>) -> Vec<String> {
    let mut kinds: Vec<String> = detections
        .keys()
        .map(|kind| kind.as_str().to_string())
        .collect();
    kinds.sort();
    kinds
}

/// Best-effort read of `extensions.request.trace_id`. Returns `None` on any
/// missing attribute, `None` value, wrong type, or PyO3 error — never raises.
fn read_trace_id(extensions: Option<&Bound<'_, PyAny>>) -> Option<String> {
    let ext = extensions?;
    let request = ext.getattr("request").ok()?;
    if request.is_none() {
        return None;
    }
    let trace = request.getattr("trace_id").ok()?;
    if trace.is_none() {
        return None;
    }
    let s: String = trace.extract().ok()?;
    if s.is_empty() { None } else { Some(s) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pyo3::types::{PyDict, PyList, PyModule};

    /// Installs a minimal fake `cpex.framework` module (`PromptPrehookResult`,
    /// `PluginViolation`) into `sys.modules` so tests can exercise the real
    /// `#[pymethods]` entry points end to end without depending on the real
    /// `cpex` package being importable in the test environment.
    fn install_framework_module(py: Python<'_>) -> PyResult<()> {
        let framework = PyModule::from_code(
            py,
            pyo3::ffi::c_str!(
                r#"
class PromptPrehookResult:
    def __init__(self, modified_payload=None, continue_processing=True, violation=None, metadata=None):
        self.modified_payload = modified_payload
        self.continue_processing = continue_processing
        self.violation = violation
        self.metadata = metadata

class PluginViolation:
    def __init__(self, reason, code, description=None, details=None):
        self.reason = reason
        self.code = code
        self.description = description
        self.details = details
"#
            ),
            pyo3::ffi::c_str!("framework.py"),
            pyo3::ffi::c_str!("cpex.framework"),
        )?;
        let cpex = PyModule::from_code(
            py,
            pyo3::ffi::c_str!(""),
            pyo3::ffi::c_str!("cpex.py"),
            pyo3::ffi::c_str!("cpex"),
        )?;
        cpex.setattr("framework", &framework)?;
        let modules = PyModule::import(py, "sys")?
            .getattr("modules")?
            .cast_into::<PyDict>()?;
        modules.set_item("cpex", cpex)?;
        modules.set_item("cpex.framework", framework)?;
        Ok(())
    }

    #[test]
    fn metrics_emitted_only_when_trace_id_present_and_carry_no_content() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            // helper builds an emitting result and returns its .metadata dict (or None)
            let with_trace = build_pii_metrics(
                py,
                Some("t1"),
                /*total_detections*/ 2,
                /*total_masked*/ 2,
                &["email", "ssn"],
                "tool_post_invoke",
            )
            .unwrap();
            let md = with_trace.unwrap();
            let inner = md.get_item("pii_filter").unwrap().unwrap();
            assert_eq!(
                inner
                    .get_item("total_detections")
                    .unwrap()
                    .extract::<i64>()
                    .unwrap(),
                2
            );
            // S1: no key/value contains the matched email
            let dumped = format!("{:?}", inner.str().unwrap());
            assert!(!dumped.contains("alice@example.com"));
            // gate: no trace_id => None
            assert!(
                build_pii_metrics(py, None, 2, 2, &["email"], "tool_post_invoke")
                    .unwrap()
                    .is_none()
            );
        });
    }

    #[test]
    fn read_trace_id_returns_value_when_present_and_none_otherwise() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            let module = PyModule::from_code(
                py,
                pyo3::ffi::c_str!(
                    "class Req:\n    def __init__(self, t):\n        self.trace_id = t\n\
                     class Ext:\n    def __init__(self, t):\n        self.request = Req(t)\n"
                ),
                pyo3::ffi::c_str!("ext.py"),
                pyo3::ffi::c_str!("ext"),
            )
            .unwrap();
            let with_id = module.getattr("Ext").unwrap().call1(("abc123",)).unwrap();
            let without = module.getattr("Ext").unwrap().call1((py.None(),)).unwrap();
            assert_eq!(read_trace_id(Some(&with_id)), Some("abc123".to_string()));
            assert_eq!(read_trace_id(Some(&without)), None);
            assert_eq!(read_trace_id(None), None);
        });
    }

    #[test]
    fn sorted_detection_types_are_stable() {
        let detections = HashMap::from([
            (
                PIIType::Ssn,
                vec![Detection {
                    value: "123-45-6789".to_string(),
                    start: 0,
                    end: 11,
                    mask_strategy: crate::config::MaskingStrategy::Redact,
                }],
            ),
            (
                PIIType::Email,
                vec![Detection {
                    value: "alice@example.com".to_string(),
                    start: 12,
                    end: 29,
                    mask_strategy: crate::config::MaskingStrategy::Redact,
                }],
            ),
        ]);

        assert_eq!(sorted_detection_types(&detections), vec!["email", "ssn"]);
        assert_eq!(count_detections(&detections), 2);
    }

    #[test]
    fn clone_payload_with_attr_copies_non_pydantic_payload_without_mutating_original() {
        Python::initialize();
        Python::attach(|py| {
            let payload_module = PyModule::from_code(
                py,
                pyo3::ffi::c_str!(
                    r#"
class Payload:
    def __init__(self):
        self.prompt_id = "prompt-1"
        self.args = {"user": {"email": "alice@example.com"}}
"#
                ),
                pyo3::ffi::c_str!("test_payload.py"),
                pyo3::ffi::c_str!("test_payload"),
            )
            .unwrap();
            let payload = payload_module.getattr("Payload").unwrap().call0().unwrap();

            let masked_args = PyDict::new(py);
            let masked_user = PyDict::new(py);
            masked_user.set_item("email", "[REDACTED]").unwrap();
            masked_args.set_item("user", masked_user).unwrap();

            let cloned =
                clone_payload_with_attr(py, &payload, "args", &masked_args.into_any().unbind())
                    .unwrap();
            let cloned = cloned.bind(py);
            let original_args = payload
                .getattr("args")
                .unwrap()
                .cast_into::<PyDict>()
                .unwrap();
            let original_user = original_args
                .get_item("user")
                .unwrap()
                .unwrap()
                .cast_into::<PyDict>()
                .unwrap();
            let cloned_args = cloned
                .getattr("args")
                .unwrap()
                .cast_into::<PyDict>()
                .unwrap();
            let cloned_user = cloned_args
                .get_item("user")
                .unwrap()
                .unwrap()
                .cast_into::<PyDict>()
                .unwrap();

            assert_eq!(
                original_user
                    .get_item("email")
                    .unwrap()
                    .unwrap()
                    .extract::<String>()
                    .unwrap(),
                "alice@example.com"
            );
            assert_eq!(
                cloned_user
                    .get_item("email")
                    .unwrap()
                    .unwrap()
                    .extract::<String>()
                    .unwrap(),
                "[REDACTED]"
            );
            assert!(!original_args.is(&cloned_args));
        });
    }

    #[test]
    fn detection_types_are_bounded_and_deduped() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            // S3: Test that detection_types list is bounded to MAX_DETECTION_TYPES (32)
            // even when more than 32 distinct types are passed in.
            let many: Vec<String> = (0..100).map(|i| format!("t{i}")).collect();
            let refs: Vec<&str> = many.iter().map(|s| s.as_str()).collect();
            let md = build_pii_metrics(py, Some("t1"), 1, 1, &refs, "s")
                .unwrap()
                .unwrap();
            let inner = md.get_item("pii_filter").unwrap().unwrap();
            let types_bound = inner.get_item("detection_types").unwrap();

            // Verify the list is bounded
            let types_len = types_bound.len().unwrap();
            assert!(
                types_len <= MAX_DETECTION_TYPES,
                "detection_types exceeded bound: {} > {}",
                types_len,
                MAX_DETECTION_TYPES
            );
            // Verify we got exactly 32 (since we provided 100 distinct types)
            assert_eq!(types_len, MAX_DETECTION_TYPES);

            // Verify they are sorted
            let type_list: Vec<String> = types_bound
                .try_iter()
                .unwrap()
                .map(|item| item.unwrap().extract::<String>().unwrap())
                .collect();
            let mut sorted = type_list.clone();
            sorted.sort();
            assert_eq!(type_list, sorted, "detection_types not sorted");

            // Verify no duplicates (deduped)
            let mut seen = std::collections::HashSet::new();
            for t in &type_list {
                assert!(seen.insert(t), "duplicate type found: {}", t);
            }
        });
    }

    #[test]
    fn handle_nested_stage_logs_masked_detection_and_emits_metrics_when_not_blocking() {
        Python::initialize();
        Python::attach(|py| {
            install_framework_module(py).unwrap();

            // Mask (don't block) on email detection, with detection logging enabled.
            let config = PyDict::new(py);
            config.set_item("detect_email", true).unwrap();
            config.set_item("block_on_detection", false).unwrap();
            config.set_item("log_detections", true).unwrap();
            let core = PIIFilterPluginCore::new(config.as_any()).unwrap();

            let payload_module = PyModule::from_code(
                py,
                pyo3::ffi::c_str!(
                    r#"
class Payload:
    def __init__(self):
        self.prompt_id = "p1"
        self.args = {"email": "alice@example.com"}
"#
                ),
                pyo3::ffi::c_str!("payload.py"),
                pyo3::ffi::c_str!("payload"),
            )
            .unwrap();
            let payload = payload_module.getattr("Payload").unwrap().call0().unwrap();
            let context = PyDict::new(py);

            let ext_module = PyModule::from_code(
                py,
                pyo3::ffi::c_str!(
                    "class Req:\n    def __init__(self, t):\n        self.trace_id = t\n\
                     class Ext:\n    def __init__(self, t):\n        self.request = Req(t)\n"
                ),
                pyo3::ffi::c_str!("ext.py"),
                pyo3::ffi::c_str!("ext"),
            )
            .unwrap();
            let ext = ext_module.getattr("Ext").unwrap().call1(("t1",)).unwrap();

            // Capture Python-side log records emitted by the pii_filter logger.
            let handler_module = PyModule::from_code(
                py,
                pyo3::ffi::c_str!(
                    r#"
import logging

class ListHandler(logging.Handler):
    def __init__(self, records):
        super().__init__()
        self.records = records

    def emit(self, record):
        self.records.append(self.format(record))
"#
                ),
                pyo3::ffi::c_str!("handler.py"),
                pyo3::ffi::c_str!("handler"),
            )
            .unwrap();
            let records = PyList::empty(py);
            let handler = handler_module
                .getattr("ListHandler")
                .unwrap()
                .call1((&records,))
                .unwrap();
            let logging = PyModule::import(py, "logging").unwrap();
            let logger = logging
                .getattr("getLogger")
                .unwrap()
                .call1((LOGGER_NAME,))
                .unwrap();
            logger.call_method1("addHandler", (&handler,)).unwrap();
            logger
                .call_method1("setLevel", (logging.getattr("DEBUG").unwrap(),))
                .unwrap();

            let result = core
                .prompt_pre_fetch(py, &payload, context.as_any(), Some(&ext))
                .unwrap();
            let result = result.bind(py);

            // Kills "delete ! in handle_nested_stage": the masked-detection log line must
            // actually fire when a detection is found and block_on_detection is false.
            assert_eq!(records.len(), 1);
            let message: String = records.get_item(0).unwrap().extract().unwrap();
            assert!(message.contains("action=masked"), "message was: {message}");

            // Kills "replace push_metrics_kwarg with ()": metadata must be attached to the
            // result when a trace_id is present, even on the masked (non-blocking) path.
            let metadata = result.getattr("metadata").unwrap();
            assert!(!metadata.is_none());
            let metadata = metadata.cast::<PyDict>().unwrap();
            let pii_metrics = metadata.get_item("pii_filter").unwrap().unwrap();
            assert_eq!(
                pii_metrics
                    .get_item("total_detections")
                    .unwrap()
                    .extract::<i64>()
                    .unwrap(),
                1
            );
        });
    }
}
