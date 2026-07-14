// Copyright 2026
// SPDX-License-Identifier: Apache-2.0

use cpex_framework_bridge::{build_framework_object, build_framework_object_dyn, default_result};
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyDict};
#[cfg(feature = "stub-gen")]
use pyo3_stub_gen::derive::*;

use crate::config::SecretsDetectionConfig;
use crate::object_model::copy_object_with_updates;
use crate::scanner::{scan_container, scan_container_findings};

#[cfg_attr(feature = "stub-gen", gen_stub_pyclass)]
#[pyclass]
pub struct SecretsDetectionPluginCore {
    config: SecretsDetectionConfig,
}

#[cfg_attr(feature = "stub-gen", gen_stub_pymethods)]
#[pymethods]
impl SecretsDetectionPluginCore {
    #[new]
    pub fn new(config: &Bound<'_, PyAny>) -> PyResult<Self> {
        Ok(Self {
            config: SecretsDetectionConfig::from_py_any(config)?,
        })
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
        self.scan_payload_attr(
            py,
            payload,
            "args",
            "PromptPrehookResult",
            "Potential secrets detected in prompt arguments",
            trace_id.as_deref(),
        )
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
        self.scan_payload_attr(
            py,
            payload,
            "args",
            "ToolPreInvokeResult",
            "Potential secrets detected in tool arguments",
            trace_id.as_deref(),
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
        self.scan_payload_attr(
            py,
            payload,
            "result",
            "ToolPostInvokeResult",
            "Potential secrets detected in tool result",
            trace_id.as_deref(),
        )
    }

    #[pyo3(signature = (payload, context, extensions=None))]
    pub fn resource_post_fetch(
        &self,
        py: Python<'_>,
        payload: &Bound<'_, PyAny>,
        context: &Bound<'_, PyAny>,
        extensions: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Py<PyAny>> {
        let _ = &context;
        let trace_id = read_trace_id(extensions);
        let content = payload.getattr("content")?;
        let Ok(text) = content.getattr("text") else {
            return default_result(py, "ResourcePostFetchResult");
        };
        let (count, redacted_text, findings) = scan_container(py, &text, &self.config)?;
        if self.should_block(count) {
            let modified_payload = if self.config.redact {
                if has_findings(count) {
                    let modified_content =
                        copy_with_update(py, &content, [("text", redacted_text.clone().unbind())])?;
                    copy_with_update(py, payload, [("content", modified_content)])?
                } else {
                    payload.clone().unbind()
                }
            } else {
                payload.clone().unbind()
            };
            return blocked_result(
                py,
                "ResourcePostFetchResult",
                "Potential secrets detected in resource content",
                count,
                findings.as_any(),
                modified_payload,
                trace_id.as_deref(),
            );
        }

        if self.config.redact && has_findings(count) {
            let modified_content =
                copy_with_update(py, &content, [("text", redacted_text.unbind())])?;
            let modified_payload = copy_with_update(py, payload, [("content", modified_content)])?;
            let mut kwargs: Vec<(&str, Py<PyAny>)> = vec![("modified_payload", modified_payload)];
            push_metrics_kwarg(
                py,
                trace_id.as_deref(),
                &mut kwargs,
                count,
                findings.as_any(),
                DetectionOutcome::Masked,
            );
            return build_framework_object_dyn(py, "ResourcePostFetchResult", kwargs);
        }

        if count > 0 {
            let mut kwargs: Vec<(&str, Py<PyAny>)> = Vec::new();
            push_metrics_kwarg(
                py,
                trace_id.as_deref(),
                &mut kwargs,
                count,
                findings.as_any(),
                DetectionOutcome::None,
            );
            if kwargs.is_empty() {
                return default_result(py, "ResourcePostFetchResult");
            }
            return build_framework_object_dyn(py, "ResourcePostFetchResult", kwargs);
        }

        default_result(py, "ResourcePostFetchResult")
    }
}

impl SecretsDetectionPluginCore {
    fn should_block(&self, count: usize) -> bool {
        self.config.block_on_detection && count >= self.config.min_findings_to_block
    }

    fn scan_payload_attr(
        &self,
        py: Python<'_>,
        payload: &Bound<'_, PyAny>,
        attr: &str,
        result_class: &str,
        block_description: &str,
        trace_id: Option<&str>,
    ) -> PyResult<Py<PyAny>> {
        let value = payload.getattr(attr)?;
        let (mut count, mut findings) = scan_container_findings(py, &value, &self.config)?;
        let redacted_value = if self.config.redact {
            if has_findings(count) {
                // Two-pass: avoid copy allocation on clean payloads; dirty payloads scan twice.
                let (redacted_count, redacted, redacted_findings) =
                    scan_container(py, &value, &self.config)?;
                count = redacted_count;
                findings = redacted_findings;
                Some(redacted)
            } else {
                None
            }
        } else {
            None
        };

        if self.should_block(count) {
            let modified_payload = if self.config.redact {
                if has_findings(count) {
                    let redacted = redacted_value.expect("redacted value exists");
                    copy_with_update(py, payload, [(attr, redacted.unbind())])?
                } else {
                    payload.clone().unbind()
                }
            } else {
                payload.clone().unbind()
            };
            return blocked_result(
                py,
                result_class,
                block_description,
                count,
                findings.as_any(),
                modified_payload,
                trace_id,
            );
        }

        if self.config.redact && has_findings(count) {
            let redacted = redacted_value.expect("redacted value exists");
            let modified_payload = copy_with_update(py, payload, [(attr, redacted.unbind())])?;
            let mut kwargs: Vec<(&str, Py<PyAny>)> = vec![("modified_payload", modified_payload)];
            push_metrics_kwarg(
                py,
                trace_id,
                &mut kwargs,
                count,
                findings.as_any(),
                DetectionOutcome::Masked,
            );
            return build_framework_object_dyn(py, result_class, kwargs);
        }

        if count > 0 {
            let mut kwargs: Vec<(&str, Py<PyAny>)> = Vec::new();
            push_metrics_kwarg(
                py,
                trace_id,
                &mut kwargs,
                count,
                findings.as_any(),
                DetectionOutcome::None,
            );
            if kwargs.is_empty() {
                return default_result(py, result_class);
            }
            return build_framework_object_dyn(py, result_class, kwargs);
        }

        default_result(py, result_class)
    }
}

fn has_findings(count: usize) -> bool {
    count != 0
}

fn blocked_result(
    py: Python<'_>,
    result_class: &str,
    description: &str,
    count: usize,
    findings: &Bound<'_, PyAny>,
    payload: Py<PyAny>,
    trace_id: Option<&str>,
) -> PyResult<Py<PyAny>> {
    let details = PyDict::new(py);
    details.set_item("count", count)?;
    details.set_item("examples", sanitized_findings(py, findings)?)?;
    let violation = build_framework_object(
        py,
        "PluginViolation",
        [
            (
                "reason",
                "Secrets detected".into_pyobject(py)?.into_any().unbind(),
            ),
            (
                "description",
                description.into_pyobject(py)?.into_any().unbind(),
            ),
            (
                "code",
                "SECRETS_DETECTED".into_pyobject(py)?.into_any().unbind(),
            ),
            ("details", details.into_any().unbind()),
        ],
    )?;
    let mut kwargs: Vec<(&str, Py<PyAny>)> = vec![
        (
            "continue_processing",
            false.into_pyobject(py)?.to_owned().into_any().unbind(),
        ),
        ("violation", violation),
        ("modified_payload", payload),
    ];
    push_metrics_kwarg(
        py,
        trace_id,
        &mut kwargs,
        count,
        findings,
        DetectionOutcome::Blocked,
    );
    build_framework_object_dyn(py, result_class, kwargs)
}

fn copy_with_update<const N: usize>(
    py: Python<'_>,
    obj: &Bound<'_, PyAny>,
    updates: [(&str, Py<PyAny>); N],
) -> PyResult<Py<PyAny>> {
    let update_dict = PyDict::new(py);
    for (key, value) in updates {
        update_dict.set_item(key, value.bind(py))?;
    }
    copy_object_with_updates(py, obj, &update_dict)
}

fn sanitized_findings<'py>(
    py: Python<'py>,
    findings: &Bound<'py, PyAny>,
) -> PyResult<Bound<'py, PyAny>> {
    let out = pyo3::types::PyList::empty(py);
    for item in findings.try_iter()? {
        let item = item?;
        if let Ok(dict) = item.cast::<PyDict>()
            && let Some(kind) = dict.get_item("type")?
        {
            let sanitized = PyDict::new(py);
            sanitized.set_item("type", kind)?;
            out.append(sanitized)?;
        }
    }
    Ok(out.into_any())
}

const MAX_SECRET_TYPES: usize = 32;

/// Which action (if any) was taken on the findings passed to
/// [`push_metrics_kwarg`]. Determines whether the count lands in
/// `total_masked` or `total_blocked` in the emitted metrics dict.
#[derive(Clone, Copy)]
enum DetectionOutcome {
    Masked,
    Blocked,
    None,
}

/// Build the namespaced metrics dict for the `result.metadata` channel.
/// Returns `None` (no work) when `trace_id` is absent (gate: no trace means
/// no metrics, zero overhead). Allowlist only: counts and type-category
/// names — never matched secret content (S1).
fn build_secrets_metrics<'py>(
    py: Python<'py>,
    trace_id: Option<&str>,
    total_detections: usize,
    total_masked: usize,
    total_blocked: usize,
    secret_types: &[&str],
) -> PyResult<Option<Bound<'py, PyDict>>> {
    if trace_id.is_none() {
        return Ok(None);
    }
    let inner = PyDict::new(py);
    inner.set_item("total_detections", total_detections)?;
    inner.set_item("total_masked", total_masked)?;
    inner.set_item("total_blocked", total_blocked)?;
    let mut types: Vec<&str> = secret_types.to_vec();
    types.sort_unstable();
    types.dedup();
    types.truncate(MAX_SECRET_TYPES);
    inner.set_item("secret_types", types)?;
    let outer = PyDict::new(py);
    outer.set_item("secrets_detection", inner)?;
    Ok(Some(outer))
}

/// Best-effort attach of the namespaced metrics dict onto `kwargs` when
/// `trace_id` is present. Never fails the caller: any error building the
/// metrics dict is logged once and metrics are omitted, so the normal
/// scan result is still returned.
///
/// Gates on `trace_id` before touching `findings` at all, so untraced
/// requests (the common case) never pay for type collection/sorting.
fn push_metrics_kwarg(
    py: Python<'_>,
    trace_id: Option<&str>,
    kwargs: &mut Vec<(&str, Py<PyAny>)>,
    count: usize,
    findings: &Bound<'_, PyAny>,
    outcome: DetectionOutcome,
) {
    let Some(tid) = trace_id else {
        return;
    };
    let secret_types = match collect_secret_types(findings) {
        Ok(types) => types,
        Err(e) => {
            log::warn!("secrets_detection: metrics build failed, omitting: {e}");
            return;
        }
    };
    let type_refs: Vec<&str> = secret_types.iter().map(String::as_str).collect();
    let (masked, blocked) = match outcome {
        DetectionOutcome::Masked => (count, 0),
        DetectionOutcome::Blocked => (0, count),
        DetectionOutcome::None => (0, 0),
    };
    match build_secrets_metrics(py, Some(tid), count, masked, blocked, &type_refs) {
        Ok(Some(md)) => kwargs.push(("metadata", md.into_any().unbind())),
        Ok(None) => {}
        Err(e) => log::warn!("secrets_detection: metrics build failed, omitting: {e}"),
    }
}

/// Extracts the `"type"` field (finding category, e.g. `"aws_access_key_id"`)
/// from each finding dict. Never includes matched secret values (S1) — the
/// finding dicts themselves are already sanitized to carry only `"type"`.
fn collect_secret_types(findings: &Bound<'_, PyAny>) -> PyResult<Vec<String>> {
    let mut types = Vec::new();
    for item in findings.try_iter()? {
        let item = item?;
        if let Ok(dict) = item.cast::<PyDict>()
            && let Some(kind) = dict.get_item("type")?
        {
            types.push(kind.extract::<String>()?);
        }
    }
    Ok(types)
}

/// Best-effort read of `extensions.request.trace_id`. Returns `None` on any
/// missing attribute, `None` value, wrong type, or PyO3 error — never raises.
/// Mirrors `pii_filter::plugin::read_trace_id`.
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
    use pyo3::types::{PyDict, PyModule};

    use super::*;

    fn config<'py>(
        py: Python<'py>,
        block_on_detection: bool,
        redact: bool,
        min_findings_to_block: usize,
    ) -> PyResult<Bound<'py, PyDict>> {
        let config = PyDict::new(py);
        config.set_item("block_on_detection", block_on_detection)?;
        config.set_item("redact", redact)?;
        config.set_item("redaction_text", "[REDACTED]")?;
        config.set_item("min_findings_to_block", min_findings_to_block)?;
        Ok(config)
    }

    fn module<'py>(py: Python<'py>) -> PyResult<Bound<'py, PyModule>> {
        install_framework_module(py)?;
        PyModule::from_code(
            py,
            pyo3::ffi::c_str!(
                r#"
class ToolPayload:
    def __init__(self, args):
        self.name = "echo"
        self.args = args

class ResultPayload:
    def __init__(self, result):
        self.name = "echo"
        self.result = result

class Content:
    def __init__(self, text):
        self.text = text

class ResourcePayload:
    def __init__(self, text):
        self.uri = "file:///tmp/secret.txt"
        self.content = Content(text)
"#
            ),
            pyo3::ffi::c_str!("test_payloads.py"),
            pyo3::ffi::c_str!("test_payloads"),
        )
    }

    fn install_framework_module(py: Python<'_>) -> PyResult<()> {
        let framework = PyModule::from_code(
            py,
            pyo3::ffi::c_str!(
                r#"
class PluginViolation:
    def __init__(self, reason="", description="", code="", details=None):
        self.reason = reason
        self.description = description
        self.code = code
        self.details = details

class PromptPrehookResult:
    def __init__(self, continue_processing=True, violation=None, modified_payload=None, metadata=None):
        self.continue_processing = continue_processing
        self.violation = violation
        self.modified_payload = modified_payload
        self.metadata = metadata or {}

class ToolPreInvokeResult(PromptPrehookResult):
    pass

class ToolPostInvokeResult(PromptPrehookResult):
    pass

class ResourcePostFetchResult(PromptPrehookResult):
    pass
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

    fn extensions_with_trace<'py>(py: Python<'py>, trace_id: &str) -> PyResult<Bound<'py, PyAny>> {
        let ext_module = PyModule::from_code(
            py,
            pyo3::ffi::c_str!(
                "class Req:\n    def __init__(self, t):\n        self.trace_id = t\n\
                 class Ext:\n    def __init__(self, t):\n        self.request = Req(t)\n"
            ),
            pyo3::ffi::c_str!("ext.py"),
            pyo3::ffi::c_str!("ext"),
        )?;
        ext_module.getattr("Ext")?.call1((trace_id,))
    }

    #[test]
    fn tool_pre_invoke_blocks_at_threshold_and_redacts_modified_payload() {
        Python::initialize();
        Python::attach(|py| -> PyResult<()> {
            let plugin = SecretsDetectionPluginCore::new(config(py, true, true, 2)?.as_any())?;
            let module = module(py)?;
            let args = PyDict::new(py);
            args.set_item("first", "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE")?;
            args.set_item("second", "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE")?;
            let payload = module.getattr("ToolPayload")?.call1((args,))?;
            let context = PyDict::new(py);

            let result = plugin.tool_pre_invoke(py, &payload, context.as_any(), None)?;
            let result = result.bind(py);

            assert!(!result.getattr("continue_processing")?.extract::<bool>()?);
            assert_eq!(
                result
                    .getattr("violation")?
                    .getattr("code")?
                    .extract::<String>()?,
                "SECRETS_DETECTED"
            );
            let modified_args = result
                .getattr("modified_payload")?
                .getattr("args")?
                .cast_into::<PyDict>()?;
            assert_eq!(
                modified_args
                    .get_item("first")?
                    .expect("first arg exists")
                    .extract::<String>()?,
                "AWS_ACCESS_KEY_ID=[REDACTED]"
            );

            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn tool_pre_invoke_below_threshold_reports_findings_without_metadata() {
        Python::initialize();
        Python::attach(|py| -> PyResult<()> {
            let plugin = SecretsDetectionPluginCore::new(config(py, true, false, 2)?.as_any())?;
            let module = module(py)?;
            let args = PyDict::new(py);
            args.set_item("message", "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE")?;
            let payload = module.getattr("ToolPayload")?.call1((args,))?;
            let context = PyDict::new(py);

            let result = plugin.tool_pre_invoke(py, &payload, context.as_any(), None)?;
            let result = result.bind(py);

            assert!(result.getattr("continue_processing")?.extract::<bool>()?);
            assert!(result.getattr("violation")?.is_none());
            // No trace_id supplied here => no metadata write at all (gate),
            // even though findings were detected. See the dedicated
            // `tool_pre_invoke_emits_namespaced_metrics_when_trace_id_present`
            // test below for the in-scope, trace_id-present case.
            let metadata = result.getattr("metadata")?.cast_into::<PyDict>()?;
            assert_eq!(metadata.len(), 0);

            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn tool_pre_invoke_emits_namespaced_metrics_when_trace_id_present() {
        // Regression test for issue #129 finding 4: tool_pre_invoke now
        // accepts `extensions` and reads trace_id from it, same contract as
        // the other 3 hooks — it must emit result.metadata["secrets_detection"]
        // when a valid trace_id is present and findings exist.
        Python::initialize();
        Python::attach(|py| -> PyResult<()> {
            let plugin = SecretsDetectionPluginCore::new(config(py, false, true, 1)?.as_any())?;
            let module = module(py)?;
            let args = PyDict::new(py);
            args.set_item("message", "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE")?;
            let payload = module.getattr("ToolPayload")?.call1((args,))?;
            let context = PyDict::new(py);
            let ext = extensions_with_trace(py, "t1")?;

            let result = plugin.tool_pre_invoke(py, &payload, context.as_any(), Some(&ext))?;
            let result = result.bind(py);

            let metadata = result.getattr("metadata")?.cast_into::<PyDict>()?;
            let metrics = metadata
                .get_item("secrets_detection")?
                .expect("namespaced metrics present");
            assert_eq!(metrics.get_item("total_detections")?.extract::<i64>()?, 1);
            assert_eq!(metrics.get_item("total_masked")?.extract::<i64>()?, 1);
            assert_eq!(metrics.get_item("total_blocked")?.extract::<i64>()?, 0);
            assert_eq!(
                metrics.get_item("secret_types")?.extract::<Vec<String>>()?,
                vec!["aws_access_key_id".to_string()]
            );

            // S1: no raw secret value anywhere in the metadata dump.
            let dumped = metadata.str()?.to_string();
            assert!(!dumped.contains("AKIAFAKE12345EXAMPLE"));

            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn tool_pre_invoke_clean_payload_does_not_block_when_blocking_enabled() {
        Python::initialize();
        Python::attach(|py| -> PyResult<()> {
            let plugin = SecretsDetectionPluginCore::new(config(py, true, true, 1)?.as_any())?;
            let module = module(py)?;
            let args = PyDict::new(py);
            args.set_item("message", "plain text")?;
            let payload = module.getattr("ToolPayload")?.call1((args,))?;
            let context = PyDict::new(py);

            let result = plugin.tool_pre_invoke(py, &payload, context.as_any(), None)?;
            let result = result.bind(py);

            assert!(result.getattr("continue_processing")?.extract::<bool>()?);
            assert!(result.getattr("violation")?.is_none());
            assert!(result.getattr("modified_payload")?.is_none());

            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn tool_post_invoke_redacts_without_blocking() {
        Python::initialize();
        Python::attach(|py| -> PyResult<()> {
            let plugin = SecretsDetectionPluginCore::new(config(py, false, true, 1)?.as_any())?;
            let module = module(py)?;
            let result_payload = module
                .getattr("ResultPayload")?
                .call1(("AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE",))?;
            let context = PyDict::new(py);

            let result = plugin.tool_post_invoke(py, &result_payload, context.as_any(), None)?;
            let result = result.bind(py);

            assert!(result.getattr("continue_processing")?.extract::<bool>()?);
            assert_eq!(
                result
                    .getattr("modified_payload")?
                    .getattr("result")?
                    .extract::<String>()?,
                "AWS_ACCESS_KEY_ID=[REDACTED]"
            );

            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn tool_post_invoke_emits_namespaced_metrics_when_trace_id_present() {
        Python::initialize();
        Python::attach(|py| -> PyResult<()> {
            let plugin = SecretsDetectionPluginCore::new(config(py, false, true, 1)?.as_any())?;
            let module = module(py)?;
            let result_payload = module
                .getattr("ResultPayload")?
                .call1(("AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE",))?;
            let context = PyDict::new(py);
            let ext = extensions_with_trace(py, "t1")?;

            let result =
                plugin.tool_post_invoke(py, &result_payload, context.as_any(), Some(&ext))?;
            let result = result.bind(py);

            let metadata = result.getattr("metadata")?.cast_into::<PyDict>()?;
            let metrics = metadata
                .get_item("secrets_detection")?
                .expect("namespaced metrics present");
            assert_eq!(metrics.get_item("total_detections")?.extract::<i64>()?, 1);
            assert_eq!(metrics.get_item("total_masked")?.extract::<i64>()?, 1);
            assert_eq!(metrics.get_item("total_blocked")?.extract::<i64>()?, 0);
            assert_eq!(
                metrics.get_item("secret_types")?.extract::<Vec<String>>()?,
                vec!["aws_access_key_id".to_string()]
            );

            // S1: no raw secret value anywhere in the metadata dump.
            let dumped = metadata.str()?.to_string();
            assert!(!dumped.contains("AKIAFAKE12345EXAMPLE"));

            // Regression: legacy flat keys must never reappear.
            assert!(metadata.get_item("secrets_redacted")?.is_none());
            assert!(metadata.get_item("secrets_findings")?.is_none());
            assert!(metadata.get_item("count")?.is_none());

            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn tool_post_invoke_without_trace_id_emits_no_metadata() {
        Python::initialize();
        Python::attach(|py| -> PyResult<()> {
            let plugin = SecretsDetectionPluginCore::new(config(py, false, false, 1)?.as_any())?;
            let module = module(py)?;
            let result_payload = module
                .getattr("ResultPayload")?
                .call1(("AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE",))?;
            let context = PyDict::new(py);

            // Back-compat: calling with `extensions=None` (no trace context)
            // must not error, and must emit zero metadata (P-1/L3 gate).
            let result = plugin.tool_post_invoke(py, &result_payload, context.as_any(), None)?;
            let result = result.bind(py);

            assert!(result.getattr("continue_processing")?.extract::<bool>()?);
            let metadata = result.getattr("metadata")?.cast_into::<PyDict>()?;
            assert_eq!(metadata.len(), 0);

            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn tool_post_invoke_reports_findings_with_metadata_when_not_blocked_or_redacted() {
        Python::initialize();
        Python::attach(|py| -> PyResult<()> {
            // block_on_detection=false, redact=false: neither the blocking
            // path nor the redact-and-emit path can trigger, so a detection
            // with a trace_id present must fall through to the `count > 0`
            // branch in `scan_payload_attr` and still emit namespaced
            // metrics (regression guard for the `count > 0` condition).
            let plugin = SecretsDetectionPluginCore::new(config(py, false, false, 1)?.as_any())?;
            let module = module(py)?;
            let result_payload = module
                .getattr("ResultPayload")?
                .call1(("AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE",))?;
            let context = PyDict::new(py);
            let ext = extensions_with_trace(py, "t1")?;

            let result =
                plugin.tool_post_invoke(py, &result_payload, context.as_any(), Some(&ext))?;
            let result = result.bind(py);

            assert!(result.getattr("continue_processing")?.extract::<bool>()?);
            assert!(result.getattr("violation")?.is_none());
            assert!(result.getattr("modified_payload")?.is_none());

            let metadata = result.getattr("metadata")?.cast_into::<PyDict>()?;
            let metrics = metadata
                .get_item("secrets_detection")?
                .expect("namespaced metrics present");
            assert_eq!(metrics.get_item("total_detections")?.extract::<i64>()?, 1);
            assert_eq!(metrics.get_item("total_masked")?.extract::<i64>()?, 0);
            assert_eq!(metrics.get_item("total_blocked")?.extract::<i64>()?, 0);
            assert_eq!(
                metrics.get_item("secret_types")?.extract::<Vec<String>>()?,
                vec!["aws_access_key_id".to_string()]
            );

            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn tool_post_invoke_clean_result_with_trace_id_emits_no_metadata() {
        Python::initialize();
        Python::attach(|py| -> PyResult<()> {
            // A clean payload (count == 0) with a trace_id present must
            // still emit zero metadata: only a genuine detection should
            // populate `result.metadata` (regression guard for the
            // `count > 0` condition degrading to an always-true mutant).
            let plugin = SecretsDetectionPluginCore::new(config(py, false, false, 1)?.as_any())?;
            let module = module(py)?;
            let result_payload = module.getattr("ResultPayload")?.call1(("plain text",))?;
            let context = PyDict::new(py);
            let ext = extensions_with_trace(py, "t1")?;

            let result =
                plugin.tool_post_invoke(py, &result_payload, context.as_any(), Some(&ext))?;
            let result = result.bind(py);

            assert!(result.getattr("continue_processing")?.extract::<bool>()?);
            let metadata = result.getattr("metadata")?.cast_into::<PyDict>()?;
            assert_eq!(metadata.len(), 0);

            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn resource_post_fetch_blocks_with_redacted_modified_payload() {
        Python::initialize();
        Python::attach(|py| -> PyResult<()> {
            let plugin = SecretsDetectionPluginCore::new(config(py, true, true, 1)?.as_any())?;
            let module = module(py)?;
            let payload = module
                .getattr("ResourcePayload")?
                .call1(("AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE",))?;
            let context = PyDict::new(py);

            let result = plugin.resource_post_fetch(py, &payload, context.as_any(), None)?;
            let result = result.bind(py);

            assert!(!result.getattr("continue_processing")?.extract::<bool>()?);
            assert_eq!(
                result
                    .getattr("modified_payload")?
                    .getattr("content")?
                    .getattr("text")?
                    .extract::<String>()?,
                "AWS_ACCESS_KEY_ID=[REDACTED]"
            );

            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn resource_post_fetch_blocks_and_emits_total_blocked_when_trace_id_present() {
        Python::initialize();
        Python::attach(|py| -> PyResult<()> {
            let plugin = SecretsDetectionPluginCore::new(config(py, true, true, 1)?.as_any())?;
            let module = module(py)?;
            let payload = module
                .getattr("ResourcePayload")?
                .call1(("AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE",))?;
            let context = PyDict::new(py);
            let ext = extensions_with_trace(py, "t1")?;

            let result = plugin.resource_post_fetch(py, &payload, context.as_any(), Some(&ext))?;
            let result = result.bind(py);

            let metadata = result.getattr("metadata")?.cast_into::<PyDict>()?;
            let metrics = metadata
                .get_item("secrets_detection")?
                .expect("namespaced metrics present");
            assert_eq!(metrics.get_item("total_blocked")?.extract::<i64>()?, 1);
            assert_eq!(metrics.get_item("total_masked")?.extract::<i64>()?, 0);

            let dumped = metadata.str()?.to_string();
            assert!(!dumped.contains("AKIAFAKE12345EXAMPLE"));

            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn resource_post_fetch_reports_findings_without_redaction_when_redact_disabled() {
        Python::initialize();
        Python::attach(|py| -> PyResult<()> {
            let plugin = SecretsDetectionPluginCore::new(config(py, false, false, 1)?.as_any())?;
            let module = module(py)?;
            let payload = module
                .getattr("ResourcePayload")?
                .call1(("AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE",))?;
            let context = PyDict::new(py);

            let result = plugin.resource_post_fetch(py, &payload, context.as_any(), None)?;
            let result = result.bind(py);

            assert!(result.getattr("continue_processing")?.extract::<bool>()?);
            assert!(result.getattr("violation")?.is_none());
            assert!(result.getattr("modified_payload")?.is_none());
            // No trace_id => no metadata write at all (gate), even though
            // findings were detected.
            let metadata = result.getattr("metadata")?.cast_into::<PyDict>()?;
            assert_eq!(metadata.len(), 0);

            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn resource_post_fetch_reports_findings_with_metadata_when_not_blocked_or_redacted() {
        Python::initialize();
        Python::attach(|py| -> PyResult<()> {
            // block_on_detection=false, redact=false: neither the blocking
            // path nor the redact-and-emit path can trigger, so a detection
            // with a trace_id present must fall through to the `count > 0`
            // branch in `resource_post_fetch` and still emit namespaced
            // metrics (regression guard for the `count > 0` condition).
            let plugin = SecretsDetectionPluginCore::new(config(py, false, false, 1)?.as_any())?;
            let module = module(py)?;
            let payload = module
                .getattr("ResourcePayload")?
                .call1(("AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE",))?;
            let context = PyDict::new(py);
            let ext = extensions_with_trace(py, "t1")?;

            let result = plugin.resource_post_fetch(py, &payload, context.as_any(), Some(&ext))?;
            let result = result.bind(py);

            assert!(result.getattr("continue_processing")?.extract::<bool>()?);
            assert!(result.getattr("violation")?.is_none());
            assert!(result.getattr("modified_payload")?.is_none());

            let metadata = result.getattr("metadata")?.cast_into::<PyDict>()?;
            let metrics = metadata
                .get_item("secrets_detection")?
                .expect("namespaced metrics present");
            assert_eq!(metrics.get_item("total_detections")?.extract::<i64>()?, 1);
            assert_eq!(metrics.get_item("total_masked")?.extract::<i64>()?, 0);
            assert_eq!(metrics.get_item("total_blocked")?.extract::<i64>()?, 0);
            assert_eq!(
                metrics.get_item("secret_types")?.extract::<Vec<String>>()?,
                vec!["aws_access_key_id".to_string()]
            );

            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn resource_post_fetch_clean_payload_with_trace_id_emits_no_metadata() {
        Python::initialize();
        Python::attach(|py| -> PyResult<()> {
            // A clean payload (count == 0) with a trace_id present must
            // still emit zero metadata: only a genuine detection should
            // populate `result.metadata` (regression guard for the
            // `count > 0` condition degrading to an always-true mutant).
            let plugin = SecretsDetectionPluginCore::new(config(py, false, false, 1)?.as_any())?;
            let module = module(py)?;
            let payload = module.getattr("ResourcePayload")?.call1(("plain text",))?;
            let context = PyDict::new(py);
            let ext = extensions_with_trace(py, "t1")?;

            let result = plugin.resource_post_fetch(py, &payload, context.as_any(), Some(&ext))?;
            let result = result.bind(py);

            assert!(result.getattr("continue_processing")?.extract::<bool>()?);
            let metadata = result.getattr("metadata")?.cast_into::<PyDict>()?;
            assert_eq!(metadata.len(), 0);

            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn read_trace_id_returns_value_when_present_and_none_otherwise() {
        Python::initialize();
        Python::attach(|py| {
            let with_id = extensions_with_trace(py, "abc123").unwrap();
            let without = extensions_with_trace(py, "").unwrap();
            assert_eq!(read_trace_id(Some(&with_id)), Some("abc123".to_string()));
            assert_eq!(read_trace_id(Some(&without)), None);
            assert_eq!(read_trace_id(None), None);
        });
    }

    #[test]
    fn build_secrets_metrics_gates_on_trace_id_and_bounds_types() {
        Python::initialize();
        Python::attach(|py| {
            assert!(
                build_secrets_metrics(py, None, 1, 1, 0, &["aws_access_key_id"])
                    .unwrap()
                    .is_none()
            );

            let many: Vec<String> = (0..100).map(|i| format!("t{i}")).collect();
            let refs: Vec<&str> = many.iter().map(String::as_str).collect();
            let md = build_secrets_metrics(py, Some("t1"), 100, 100, 0, &refs)
                .unwrap()
                .unwrap();
            let inner = md.get_item("secrets_detection").unwrap().unwrap();
            let types = inner.get_item("secret_types").unwrap();
            assert_eq!(types.len().unwrap(), MAX_SECRET_TYPES);
        });
    }
}
