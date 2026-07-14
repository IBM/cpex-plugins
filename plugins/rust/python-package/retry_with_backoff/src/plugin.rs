// Copyright 2026
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};

use crate::delay::compute_delay_ms;
use crate::state::{ToolRetryState, maybe_evict_stale, monotonic_secs};
use cpex_framework_bridge::{build_framework_object, build_framework_object_dyn};
use log::{debug, warn};
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyDict, PyList};
#[cfg(feature = "stub-gen")]
use pyo3_stub_gen::derive::*;
use serde_json::Value;

use crate::config::RetryConfig;

static PLUGIN_LAST_EVICTION_MS: AtomicU64 = AtomicU64::new(0);

#[cfg_attr(feature = "stub-gen", gen_stub_pyclass)]
#[pyclass]
pub struct RetryWithBackoffPluginCore {
    config: RetryConfig,
    state_manager: Arc<Mutex<HashMap<String, ToolRetryState>>>,
}

#[cfg_attr(feature = "stub-gen", gen_stub_pymethods)]
#[pymethods]
impl RetryWithBackoffPluginCore {
    #[new]
    pub fn new(config: &Bound<'_, PyAny>) -> PyResult<Self> {
        let config_dict = if config.is_none() {
            PyDict::new(config.py())
        } else {
            config.cast::<PyDict>()?.clone()
        };

        let config = RetryConfig::from_py_dict(&config_dict)?;

        debug!(
            "RetryWithBackoffPluginCore initialized: max_retries={} base_ms={} max_ms={} jitter={}",
            config.max_retries, config.backoff_base_ms, config.max_backoff_ms, config.jitter
        );

        Ok(Self {
            config,
            state_manager: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    #[pyo3(signature = (payload, context, extensions=None))]
    pub fn tool_post_invoke(
        &self,
        py: Python<'_>,
        payload: &Bound<'_, PyAny>,
        context: &Bound<'_, PyAny>,
        extensions: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Py<PyAny>> {
        let trace_id = read_trace_id(extensions);

        // Extract tool name
        let tool_name = payload.getattr("name")?.extract::<String>()?;

        // Get tool-specific config
        let config = self.config.get_tool_config(&tool_name)?;

        // Extract request_id from context
        let global_context = context.getattr("global_context")?;
        let request_id = global_context.getattr("request_id")?.extract::<String>()?;

        // Extract result
        let result = payload.getattr("result")?;

        // Check if this is a failure
        let is_failure = self.is_failure(py, &result, &config)?;

        if !is_failure {
            // Success - clear state. No retry happened this call, so the
            // namespaced metrics (when emitted) report zero on both counters.
            self.clear_state(&tool_name, &request_id);
            let mut kwargs: Vec<(&str, Py<PyAny>)> = vec![(
                "retry_delay_ms",
                0u64.into_pyobject(py)?.into_any().unbind(),
            )];
            push_retry_with_backoff_metrics_kwarg(py, trace_id.as_deref(), &mut kwargs, 0, 0);
            return build_framework_object_dyn(py, "ToolPostInvokeResult", kwargs);
        }

        // Failure - update state and check retry budget
        let mut state_map = self.state_manager.lock().unwrap();
        self.evict_stale(&mut state_map);

        let key = format!("{}:{}", tool_name, request_id);
        let state = state_map.entry(key.clone()).or_default();

        state.consecutive_failures += 1;
        state.last_failure_at = monotonic_secs();
        // Copy out before further borrows/mutations of `state_map` below.
        let retry_count = state.consecutive_failures;

        if retry_count <= config.max_retries {
            // Within retry budget - calculate delay
            let attempt = retry_count.saturating_sub(1);
            let delay_ms = compute_delay_ms(
                attempt,
                config.backoff_base_ms,
                config.max_backoff_ms,
                config.jitter,
            );

            debug!(
                "tool_post_invoke: tool={} request_id={} failure={}/{} delay_ms={}",
                tool_name, request_id, retry_count, config.max_retries, delay_ms
            );

            let mut kwargs: Vec<(&str, Py<PyAny>)> = vec![(
                "retry_delay_ms",
                delay_ms.into_pyobject(py)?.into_any().unbind(),
            )];
            push_retry_with_backoff_metrics_kwarg(
                py,
                trace_id.as_deref(),
                &mut kwargs,
                retry_count,
                delay_ms,
            );
            return build_framework_object_dyn(py, "ToolPostInvokeResult", kwargs);
        }

        // Exhausted retry budget - remove state
        warn!(
            "tool_post_invoke: tool={} request_id={} exhausted after {} failure(s)",
            tool_name, request_id, retry_count
        );
        state_map.remove(&key);

        let mut kwargs: Vec<(&str, Py<PyAny>)> = vec![(
            "retry_delay_ms",
            0u64.into_pyobject(py)?.into_any().unbind(),
        )];
        push_retry_with_backoff_metrics_kwarg(py, trace_id.as_deref(), &mut kwargs, retry_count, 0);
        build_framework_object_dyn(py, "ToolPostInvokeResult", kwargs)
    }

    pub fn resource_post_fetch(
        &self,
        py: Python<'_>,
        _payload: &Bound<'_, PyAny>,
        _context: &Bound<'_, PyAny>,
    ) -> PyResult<Py<PyAny>> {
        let metadata = self.build_metadata(py, &self.config)?;

        build_framework_object(py, "ResourcePostFetchResult", [("metadata", metadata)])
    }
}

/// Read `obj[key]` through the Python mapping protocol (`PyObject_GetItem`,
/// i.e. `__getitem__`), returning `None` for a missing key or any
/// non-subscriptable/error case. Never raises.
///
/// Unlike [`pyo3::types::PyDict::get_item`], which reads the C-level dict
/// storage directly, this respects `dict` subclasses that keep their data in a
/// Python-level overlay rather than the C-level storage. The gateway wraps tool
/// results in exactly such a subclass (the framework's `CopyOnWriteDict`, whose
/// C-level storage is empty), so `PyDict::get_item` silently misses every key —
/// a failing tool result then looks like a success and no retry is signalled.
fn mapping_get<'py>(obj: &Bound<'py, PyAny>, key: &str) -> Option<Bound<'py, PyAny>> {
    obj.get_item(key).ok()
}

/// True when `obj[key]` exists and extracts to `true`. Never raises.
fn mapping_get_bool(obj: &Bound<'_, PyAny>, key: &str) -> bool {
    mapping_get(obj, key)
        .and_then(|v| v.extract::<bool>().ok())
        .unwrap_or(false)
}

impl RetryWithBackoffPluginCore {
    fn is_failure(
        &self,
        _py: Python<'_>,
        result: &Bound<'_, PyAny>,
        config: &RetryConfig,
    ) -> PyResult<bool> {
        // Read every key through the Python mapping protocol (see `mapping_get`):
        // the gateway wraps tool results in dict subclasses (e.g. CopyOnWriteDict)
        // whose data lives in a Python-level overlay, so the C-level
        // `PyDict::get_item` would observe an empty dict and miss `isError`.

        // Top-level isError flag
        if mapping_get_bool(result, "isError") {
            // status_code (when present) lives under structuredContent
            if let Some(structured) = mapping_get(result, "structuredContent")
                && let Some(status) = mapping_get(&structured, "status_code")
                && let Ok(status_code) = status.extract::<i32>()
            {
                return Ok(config.retry_on_status.contains(&status_code));
            }
            return Ok(true);
        }

        // Check structuredContent; track presence to gate text content check.
        // Treat `"structuredContent": None` as absent (matches original Python semantics).
        let structured = mapping_get(result, "structuredContent").filter(|v| !v.is_none());
        let has_structured_content = structured.is_some();
        if let Some(ref structured_dict) = structured {
            if mapping_get_bool(structured_dict, "isError") {
                return Ok(true);
            }
            if let Some(status) = mapping_get(structured_dict, "status_code")
                && let Ok(status_code) = status.extract::<i32>()
                && config.retry_on_status.contains(&status_code)
            {
                return Ok(true);
            }
        }

        // Check text content only when enabled and structuredContent is absent
        if config.check_text_content
            && !has_structured_content
            && let Some(content) = mapping_get(result, "content")
            && let Ok(content_list) = content.cast::<PyList>()
        {
            for item in content_list.iter() {
                // Only process items explicitly marked as type "text"
                let is_text = mapping_get(&item, "type")
                    .and_then(|v| v.extract::<String>().ok())
                    .as_deref()
                    == Some("text");
                if !is_text {
                    continue;
                }
                // Try to parse text as JSON
                if let Some(text) = mapping_get(&item, "text")
                    && let Ok(text_str) = text.extract::<String>()
                    && let Ok(parsed) = serde_json::from_str::<Value>(&text_str)
                    && let Some(obj) = parsed.as_object()
                {
                    // Check isError in parsed JSON
                    if obj.get("isError").and_then(|v| v.as_bool()) == Some(true) {
                        return Ok(true);
                    }
                    // Check status_code in parsed JSON
                    if let Some(status) = obj.get("status_code").and_then(|v| v.as_i64())
                        && config.retry_on_status.contains(&(status as i32))
                    {
                        return Ok(true);
                    }
                }
            }
        }

        Ok(false)
    }

    fn build_metadata(&self, py: Python<'_>, config: &RetryConfig) -> PyResult<Py<PyAny>> {
        let metadata = PyDict::new(py);
        let retry_policy = PyDict::new(py);

        retry_policy.set_item("max_retries", config.max_retries)?;
        retry_policy.set_item("backoff_base_ms", config.backoff_base_ms)?;
        retry_policy.set_item("max_backoff_ms", config.max_backoff_ms)?;
        retry_policy.set_item("retry_on_status", config.retry_on_status.clone())?;

        metadata.set_item("retry_policy", retry_policy)?;
        Ok(metadata.into_any().unbind())
    }

    fn clear_state(&self, tool: &str, request_id: &str) {
        let mut state_map = self.state_manager.lock().unwrap();
        let key = format!("{}:{}", tool, request_id);
        state_map.remove(&key);
    }

    #[mutants::skip] // TTL eviction cannot be verified without clock injection
    fn evict_stale(&self, map: &mut HashMap<String, ToolRetryState>) {
        maybe_evict_stale(map, &PLUGIN_LAST_EVICTION_MS);
    }
}

/// Build the namespaced metrics dict for the `result.metadata` channel.
/// Returns `None` (no work) when `trace_id` is absent (gate: no trace means
/// no metrics). Emits exactly the two per-call counters decided for this
/// plugin: `retry_count` (`ToolRetryState::consecutive_failures` after this
/// call's outcome was recorded — 0 on success) and `retry_delay_ms` (the
/// per-attempt delay `compute_delay_ms` just computed for this call — 0 on
/// success and once the retry budget is exhausted). There is deliberately no
/// cumulative `total_backoff_ms`: no new state accumulator is added.
///
/// This replaces (does not sit alongside) the old un-namespaced, un-gated
/// `retry_policy` config echo for `tool_post_invoke` — that write violated
/// "zero overhead when untraced" and duplicated static config rather than
/// per-call observability data. `resource_post_fetch` is untouched and keeps
/// emitting `retry_policy` via `build_metadata`.
fn build_retry_with_backoff_metrics<'py>(
    py: Python<'py>,
    trace_id: Option<&str>,
    retry_count: u32,
    retry_delay_ms: u64,
) -> PyResult<Option<Bound<'py, PyDict>>> {
    if trace_id.is_none() {
        return Ok(None);
    }
    let inner = PyDict::new(py);
    inner.set_item("retry_count", retry_count)?;
    inner.set_item("retry_delay_ms", retry_delay_ms)?;
    let outer = PyDict::new(py);
    outer.set_item("retry_with_backoff", inner)?;
    Ok(Some(outer))
}

/// Best-effort attach of the namespaced metrics dict onto `kwargs` when
/// `trace_id` is present. Never fails the caller: any error building the
/// metrics dict is logged once and metrics are omitted, so the normal
/// retry result is still returned.
///
/// Gates on `trace_id` before building anything, so untraced calls (the
/// common case) never pay for the dict construction.
fn push_retry_with_backoff_metrics_kwarg(
    py: Python<'_>,
    trace_id: Option<&str>,
    kwargs: &mut Vec<(&str, Py<PyAny>)>,
    retry_count: u32,
    retry_delay_ms: u64,
) {
    let Some(tid) = trace_id else {
        return;
    };
    match build_retry_with_backoff_metrics(py, Some(tid), retry_count, retry_delay_ms) {
        Ok(Some(md)) => kwargs.push(("metadata", md.into_any().unbind())),
        Ok(None) => {}
        Err(e) => log::warn!("retry_with_backoff: metrics build failed, omitting: {e}"),
    }
}

/// Best-effort read of `extensions.request.trace_id`. Returns `None` on any
/// missing attribute, `None` value, wrong type, or PyO3 error — never raises.
/// Mirrors `pii_filter::plugin::read_trace_id` / `secrets_detection::plugin::read_trace_id`
/// / `rate_limiter::plugin::read_trace_id`.
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
    use crate::config::RetryConfig;
    use pyo3::ffi::c_str;
    use pyo3::types::{PyDict, PyList, PyModule};
    use std::collections::HashMap;

    // ── helpers ──────────────────────────────────────────────────────────────

    fn setup_cpex_framework(py: Python<'_>) {
        let framework = PyModule::from_code(
            py,
            c_str!(
                r#"
from dataclasses import dataclass, field
from typing import Any

@dataclass
class ToolPostInvokeResult:
    retry_delay_ms: int = 0
    metadata: dict = field(default_factory=dict)
    continue_processing: bool = True

@dataclass
class ResourcePostFetchResult:
    metadata: dict = field(default_factory=dict)
    continue_processing: bool = True
"#
            ),
            c_str!("cpex_fw_shim.py"),
            c_str!("cpex.framework"),
        )
        .unwrap();
        let cpex = PyModule::from_code(py, c_str!(""), c_str!("cpex.py"), c_str!("cpex")).unwrap();
        cpex.setattr("framework", &framework).unwrap();
        let modules = PyModule::import(py, "sys")
            .unwrap()
            .getattr("modules")
            .unwrap()
            .cast_into::<PyDict>()
            .unwrap();
        modules.set_item("cpex", cpex).unwrap();
        modules.set_item("cpex.framework", framework).unwrap();
    }

    fn make_plugin() -> RetryWithBackoffPluginCore {
        RetryWithBackoffPluginCore {
            config: RetryConfig {
                max_retries: 2,
                backoff_base_ms: 100,
                max_backoff_ms: 10_000,
                retry_on_status: vec![500, 503],
                jitter: false,
                check_text_content: false,
                tool_overrides: HashMap::new(),
            },
            state_manager: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn make_payload_and_context<'py>(
        py: Python<'py>,
        tool: &str,
        is_error: bool,
    ) -> PyResult<(Bound<'py, PyAny>, Bound<'py, PyAny>)> {
        let types = py.import("types")?;
        let sn = types.getattr("SimpleNamespace")?;

        let result_dict = PyDict::new(py);
        result_dict.set_item("isError", is_error)?;
        let payload = sn.call0()?;
        payload.setattr("name", tool)?;
        payload.setattr("result", &result_dict)?;

        let gc = sn.call0()?;
        gc.setattr("request_id", "test-req-123")?;
        let ctx = sn.call0()?;
        ctx.setattr("global_context", &gc)?;

        Ok((payload, ctx))
    }

    fn extract_delay(py: Python<'_>, result: &Py<PyAny>) -> u64 {
        result
            .bind(py)
            .getattr("retry_delay_ms")
            .unwrap()
            .extract()
            .unwrap()
    }

    /// Builds an `extensions`-shaped object carrying `request.trace_id`.
    /// Mirrors the equivalent helper in `rate_limiter::plugin::tests`.
    fn extensions_with_trace<'py>(py: Python<'py>, trace_id: &str) -> PyResult<Bound<'py, PyAny>> {
        let ext_module = PyModule::from_code(
            py,
            c_str!(
                "class Req:\n    def __init__(self, t):\n        self.trace_id = t\n\
                 class Ext:\n    def __init__(self, t):\n        self.request = Req(t)\n"
            ),
            c_str!("rwb_ext.py"),
            c_str!("rwb_ext"),
        )?;
        ext_module.getattr("Ext")?.call1((trace_id,))
    }

    // ── pure-Rust tests ───────────────────────────────────────────────────────

    #[test]
    fn test_compute_delay_ms_no_jitter() {
        assert_eq!(compute_delay_ms(0, 100, 10_000, false), 100);
        assert_eq!(compute_delay_ms(1, 100, 10_000, false), 200);
        assert_eq!(compute_delay_ms(2, 100, 10_000, false), 400);
        assert_eq!(compute_delay_ms(3, 100, 10_000, false), 800);
    }

    #[test]
    fn test_compute_delay_ms_capped() {
        assert_eq!(compute_delay_ms(10, 100, 500, false), 500);
    }

    #[test]
    fn test_compute_delay_ms_no_overflow() {
        let d = compute_delay_ms(63, 100, 5_000, false);
        assert_eq!(d, 5_000);
    }

    #[test]
    fn test_compute_delay_ms_with_jitter() {
        let delay = compute_delay_ms(1, 100, 10_000, true);
        assert!(delay <= 200);
    }

    #[test]
    fn test_tool_retry_state_new() {
        let state = ToolRetryState::new();
        assert_eq!(state.consecutive_failures, 0);
        assert_eq!(state.last_failure_at, 0.0);
    }

    #[test]
    fn test_monotonic_secs_increases() {
        let t1 = monotonic_secs();
        std::thread::sleep(std::time::Duration::from_millis(10));
        let t2 = monotonic_secs();
        assert!(t2 > t1);
    }

    #[test]
    fn test_clear_state_removes_entry() {
        // Kills mutant: `replace clear_state with ()`
        let plugin = make_plugin();
        {
            let mut map = plugin.state_manager.lock().unwrap();
            map.insert(
                "tool:req".to_string(),
                ToolRetryState {
                    consecutive_failures: 3,
                    last_failure_at: monotonic_secs(),
                },
            );
        }
        plugin.clear_state("tool", "req");
        assert!(
            !plugin
                .state_manager
                .lock()
                .unwrap()
                .contains_key("tool:req"),
            "clear_state must remove the entry"
        );
    }

    #[test]
    fn test_evict_stale_retains_uninitialized_and_recent_entries() {
        let plugin = make_plugin();
        let mut map = HashMap::new();
        // last_failure_at = 0.0 (never recorded) → always retained
        map.insert("k1".to_string(), ToolRetryState::new());
        // recent timestamp → retained
        map.insert(
            "k2".to_string(),
            ToolRetryState {
                consecutive_failures: 1,
                last_failure_at: monotonic_secs(),
            },
        );
        plugin.evict_stale(&mut map);
        assert!(
            map.contains_key("k1"),
            "uninitialized entry must be retained"
        );
        assert!(map.contains_key("k2"), "recent entry must be retained");
    }

    // ── PyO3 tests: tool_post_invoke ─────────────────────────────────────────

    #[test]
    fn test_success_returns_zero_delay() {
        // Kills mutant: `delete ! in tool_post_invoke` (L98)
        Python::initialize();
        Python::attach(|py| {
            setup_cpex_framework(py);
            let core = make_plugin();
            let (payload, ctx) = make_payload_and_context(py, "tool_a", false).unwrap();
            let result = core.tool_post_invoke(py, &payload, &ctx, None).unwrap();
            assert_eq!(extract_delay(py, &result), 0, "success must return 0 delay");
        });
    }

    #[test]
    fn test_first_failure_returns_base_delay() {
        // Kills mutant: `delete ! in tool_post_invoke` (L98) and `replace += with *=` (L123)
        Python::initialize();
        Python::attach(|py| {
            setup_cpex_framework(py);
            let core = make_plugin(); // base_ms = 100
            let (payload, ctx) = make_payload_and_context(py, "tool_b", true).unwrap();
            let result = core.tool_post_invoke(py, &payload, &ctx, None).unwrap();
            assert_eq!(
                extract_delay(py, &result),
                100,
                "first failure must return base_ms delay"
            );
        });
    }

    #[test]
    fn test_counter_increments_on_successive_failures() {
        // Kills mutant: `replace += with *= or -=` (L123)
        Python::initialize();
        Python::attach(|py| {
            setup_cpex_framework(py);
            let core = make_plugin(); // base_ms = 100, jitter = false
            let (payload, ctx) = make_payload_and_context(py, "tool_c", true).unwrap();
            let d1 = extract_delay(
                py,
                &core.tool_post_invoke(py, &payload, &ctx, None).unwrap(),
            );
            let d2 = extract_delay(
                py,
                &core.tool_post_invoke(py, &payload, &ctx, None).unwrap(),
            );
            // attempt 0 → 100ms, attempt 1 → 200ms
            assert_eq!(d1, 100, "first failure delay");
            assert_eq!(
                d2, 200,
                "second failure delay must double (counter incremented)"
            );
        });
    }

    #[test]
    fn test_exhausted_budget_returns_zero_delay() {
        // Kills mutant: `replace <= with >` (L126)
        Python::initialize();
        Python::attach(|py| {
            setup_cpex_framework(py);
            let core = make_plugin(); // max_retries = 2
            let (payload, ctx) = make_payload_and_context(py, "tool_d", true).unwrap();
            let _ = core.tool_post_invoke(py, &payload, &ctx, None).unwrap(); // failure 1
            let _ = core.tool_post_invoke(py, &payload, &ctx, None).unwrap(); // failure 2
            let result = core.tool_post_invoke(py, &payload, &ctx, None).unwrap(); // exhausted
            assert_eq!(
                extract_delay(py, &result),
                0,
                "exhausted budget must return 0"
            );
        });
    }

    #[test]
    fn test_success_clears_state_and_resets_counter() {
        // Kills mutant: `replace clear_state with ()` (L283) — if clear_state is a noop,
        // the 3rd call (after a success reset) would see consecutive_failures = 2
        // and return 200ms instead of 100ms.
        Python::initialize();
        Python::attach(|py| {
            setup_cpex_framework(py);
            let core = make_plugin(); // max_retries = 2, base_ms = 100, jitter = false
            let (fail_p, ctx) = make_payload_and_context(py, "tool_e", true).unwrap();
            let (ok_p, _) = make_payload_and_context(py, "tool_e", false).unwrap();
            let _ = core.tool_post_invoke(py, &fail_p, &ctx, None).unwrap(); // failure 1
            let _ = core.tool_post_invoke(py, &ok_p, &ctx, None).unwrap(); // success → clear state
            let d = extract_delay(py, &core.tool_post_invoke(py, &fail_p, &ctx, None).unwrap());
            assert_eq!(
                d, 100,
                "after success reset, next failure must be attempt 0 (base delay)"
            );
        });
    }

    // ── PyO3 tests: tool_post_invoke namespaced metrics (trace_id gating) ────

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
    fn tool_post_invoke_no_trace_id_omits_metadata_on_all_branches() {
        // Kills mutants around the trace_id gate: without a trace_id, no
        // branch (success / within-budget / exhausted) may attach any
        // `result.metadata` at all — not even an empty `retry_with_backoff`
        // key.
        Python::initialize();
        Python::attach(|py| {
            setup_cpex_framework(py);
            let core = make_plugin(); // max_retries = 2, base_ms = 100
            let (fail_p, ctx) = make_payload_and_context(py, "tool_notrace", true).unwrap();
            let (ok_p, _) = make_payload_and_context(py, "tool_notrace", false).unwrap();

            // success branch
            let result = core.tool_post_invoke(py, &ok_p, &ctx, None).unwrap();
            let metadata = result
                .bind(py)
                .getattr("metadata")
                .unwrap()
                .cast_into::<PyDict>()
                .unwrap();
            assert_eq!(metadata.len(), 0, "success branch must omit metadata");

            // within-budget branch
            let result = core.tool_post_invoke(py, &fail_p, &ctx, None).unwrap();
            let metadata = result
                .bind(py)
                .getattr("metadata")
                .unwrap()
                .cast_into::<PyDict>()
                .unwrap();
            assert_eq!(metadata.len(), 0, "within-budget branch must omit metadata");

            // exhausted branch
            let result = core.tool_post_invoke(py, &fail_p, &ctx, None).unwrap();
            let metadata = result
                .bind(py)
                .getattr("metadata")
                .unwrap()
                .cast_into::<PyDict>()
                .unwrap();
            assert_eq!(metadata.len(), 0, "exhausted branch must omit metadata");
        });
    }

    #[test]
    fn tool_post_invoke_success_with_trace_id_emits_zero_valued_metrics() {
        Python::initialize();
        Python::attach(|py| {
            setup_cpex_framework(py);
            let core = make_plugin();
            let ext = extensions_with_trace(py, "trace-success").unwrap();
            let (ok_p, ctx) = make_payload_and_context(py, "tool_succ", false).unwrap();

            let result = core.tool_post_invoke(py, &ok_p, &ctx, Some(&ext)).unwrap();
            assert_eq!(extract_delay(py, &result), 0);

            let metadata = result
                .bind(py)
                .getattr("metadata")
                .unwrap()
                .cast_into::<PyDict>()
                .unwrap();
            let metrics = metadata
                .get_item("retry_with_backoff")
                .unwrap()
                .expect("namespaced metrics present when trace_id is set");
            assert_eq!(
                metrics
                    .get_item("retry_count")
                    .unwrap()
                    .extract::<u32>()
                    .unwrap(),
                0
            );
            assert_eq!(
                metrics
                    .get_item("retry_delay_ms")
                    .unwrap()
                    .extract::<u64>()
                    .unwrap(),
                0
            );
            // Regression: the old un-namespaced config echo must be gone.
            assert!(metadata.get_item("retry_policy").unwrap().is_none());
        });
    }

    #[test]
    fn tool_post_invoke_within_budget_with_trace_id_emits_count_and_positive_delay() {
        Python::initialize();
        Python::attach(|py| {
            setup_cpex_framework(py);
            let core = make_plugin(); // max_retries = 2, base_ms = 100, jitter = false
            let ext = extensions_with_trace(py, "trace-retry").unwrap();
            let (fail_p, ctx) = make_payload_and_context(py, "tool_retry", true).unwrap();

            let result = core
                .tool_post_invoke(py, &fail_p, &ctx, Some(&ext))
                .unwrap();
            assert_eq!(extract_delay(py, &result), 100, "first attempt = base_ms");

            let metadata = result
                .bind(py)
                .getattr("metadata")
                .unwrap()
                .cast_into::<PyDict>()
                .unwrap();
            let metrics = metadata
                .get_item("retry_with_backoff")
                .unwrap()
                .expect("namespaced metrics present when trace_id is set");
            assert_eq!(
                metrics
                    .get_item("retry_count")
                    .unwrap()
                    .extract::<u32>()
                    .unwrap(),
                1,
                "retry_count must be consecutive_failures after this failure"
            );
            assert_eq!(
                metrics
                    .get_item("retry_delay_ms")
                    .unwrap()
                    .extract::<u64>()
                    .unwrap(),
                100,
                "retry_delay_ms must equal the per-attempt delay just computed"
            );
            assert!(metadata.get_item("retry_policy").unwrap().is_none());

            // Second failure: count increments, delay doubles.
            let result = core
                .tool_post_invoke(py, &fail_p, &ctx, Some(&ext))
                .unwrap();
            assert_eq!(extract_delay(py, &result), 200);
            let metadata = result
                .bind(py)
                .getattr("metadata")
                .unwrap()
                .cast_into::<PyDict>()
                .unwrap();
            let metrics = metadata.get_item("retry_with_backoff").unwrap().unwrap();
            assert_eq!(
                metrics
                    .get_item("retry_count")
                    .unwrap()
                    .extract::<u32>()
                    .unwrap(),
                2
            );
            assert_eq!(
                metrics
                    .get_item("retry_delay_ms")
                    .unwrap()
                    .extract::<u64>()
                    .unwrap(),
                200
            );
        });
    }

    #[test]
    fn tool_post_invoke_exhausted_with_trace_id_emits_final_count_and_zero_delay() {
        Python::initialize();
        Python::attach(|py| {
            setup_cpex_framework(py);
            let core = make_plugin(); // max_retries = 2
            let ext = extensions_with_trace(py, "trace-exhausted").unwrap();
            let (fail_p, ctx) = make_payload_and_context(py, "tool_exhaust", true).unwrap();

            let _ = core
                .tool_post_invoke(py, &fail_p, &ctx, Some(&ext))
                .unwrap(); // failure 1 (within budget)
            let _ = core
                .tool_post_invoke(py, &fail_p, &ctx, Some(&ext))
                .unwrap(); // failure 2 (within budget)
            let result = core
                .tool_post_invoke(py, &fail_p, &ctx, Some(&ext))
                .unwrap(); // failure 3 — exhausted (max_retries = 2)

            assert_eq!(
                extract_delay(py, &result),
                0,
                "exhausted must return 0 delay"
            );

            let metadata = result
                .bind(py)
                .getattr("metadata")
                .unwrap()
                .cast_into::<PyDict>()
                .unwrap();
            let metrics = metadata
                .get_item("retry_with_backoff")
                .unwrap()
                .expect("namespaced metrics present when trace_id is set");
            assert_eq!(
                metrics
                    .get_item("retry_count")
                    .unwrap()
                    .extract::<u32>()
                    .unwrap(),
                3,
                "retry_count must reflect the final (exhausting) failure count"
            );
            assert_eq!(
                metrics
                    .get_item("retry_delay_ms")
                    .unwrap()
                    .extract::<u64>()
                    .unwrap(),
                0,
                "exhausted budget must report zero delay (no new delay computed)"
            );
            assert!(metadata.get_item("retry_policy").unwrap().is_none());
        });
    }

    // ── PyO3 tests: is_failure (check_text_content path) ────────────────────

    #[test]
    fn test_is_failure_detects_is_error_in_text_content() {
        // Kills mutants: `replace != with ==` (L241) and `replace == with !=` (L252)
        Python::initialize();
        Python::attach(|py| {
            setup_cpex_framework(py);
            let config = RetryConfig {
                max_retries: 2,
                backoff_base_ms: 100,
                max_backoff_ms: 10_000,
                retry_on_status: vec![500],
                jitter: false,
                check_text_content: true,
                tool_overrides: HashMap::new(),
            };
            let core = RetryWithBackoffPluginCore {
                config: config.clone(),
                state_manager: Arc::new(Mutex::new(HashMap::new())),
            };
            let item = PyDict::new(py);
            item.set_item("type", "text").unwrap();
            item.set_item("text", r#"{"isError": true}"#).unwrap();
            let content = PyList::empty(py);
            content.append(item.as_any()).unwrap();
            let result_dict = PyDict::new(py);
            result_dict.set_item("content", content).unwrap();

            let is_fail = core.is_failure(py, result_dict.as_any(), &config).unwrap();
            assert!(
                is_fail,
                "isError:true in JSON text content must trigger failure"
            );
        });
    }

    #[test]
    fn test_is_failure_reads_dict_subclass_overlay_storage() {
        // Regression (gateway CopyOnWriteDict): the gateway wraps tool results in
        // a `dict` subclass that keeps its data in a Python-level overlay, leaving
        // the C-level dict storage empty. Reading via `PyDict::get_item` (C-level)
        // misses `isError`, so a failing result looked like a success and no retry
        // was ever signalled. `is_failure` must read through the mapping protocol.
        Python::initialize();
        Python::attach(|py| {
            setup_cpex_framework(py);
            let config = RetryConfig {
                max_retries: 2,
                backoff_base_ms: 100,
                max_backoff_ms: 10_000,
                retry_on_status: vec![500],
                jitter: false,
                check_text_content: false,
                tool_overrides: HashMap::new(),
            };
            let core = RetryWithBackoffPluginCore {
                config: config.clone(),
                state_manager: Arc::new(Mutex::new(HashMap::new())),
            };
            // A `dict` subclass whose data lives in a Python-level overlay while
            // the C-level dict storage stays empty (mirrors CopyOnWriteDict).
            let module = PyModule::from_code(
                py,
                c_str!(
                    "class CowDict(dict):\n    def __init__(self, data):\n        super().__init__()\n        self._overlay = dict(data)\n    def __getitem__(self, k):\n        return self._overlay[k]\n    def get(self, k, default=None):\n        return self._overlay.get(k, default)\n    def __contains__(self, k):\n        return k in self._overlay\n"
                ),
                c_str!("cow.py"),
                c_str!("cow"),
            )
            .unwrap();
            let inner = PyDict::new(py);
            inner.set_item("isError", true).unwrap();
            inner.set_item("structuredContent", py.None()).unwrap();
            let cow = module.getattr("CowDict").unwrap().call1((inner,)).unwrap();

            // Sanity: C-level dict storage is empty, so the old PyDict::get_item
            // path would observe nothing and (wrongly) report no failure.
            assert_eq!(cow.cast::<PyDict>().unwrap().len(), 0);

            let is_fail = core.is_failure(py, &cow, &config).unwrap();
            assert!(
                is_fail,
                "isError:true stored in a dict-subclass overlay must trigger failure"
            );
        });
    }

    #[test]
    fn test_is_failure_skips_non_text_type_items() {
        // Kills mutant: `replace != with ==` (L241) — if != is flipped to ==,
        // non-"text" items would be processed instead of skipped.
        Python::initialize();
        Python::attach(|py| {
            setup_cpex_framework(py);
            let config = RetryConfig {
                max_retries: 2,
                backoff_base_ms: 100,
                max_backoff_ms: 10_000,
                retry_on_status: vec![500],
                jitter: false,
                check_text_content: true,
                tool_overrides: HashMap::new(),
            };
            let core = RetryWithBackoffPluginCore {
                config: config.clone(),
                state_manager: Arc::new(Mutex::new(HashMap::new())),
            };
            let item = PyDict::new(py);
            item.set_item("type", "image").unwrap();
            item.set_item("text", r#"{"isError": true}"#).unwrap();
            let content = PyList::empty(py);
            content.append(item.as_any()).unwrap();
            let result_dict = PyDict::new(py);
            result_dict.set_item("content", content).unwrap();

            let is_fail = core.is_failure(py, result_dict.as_any(), &config).unwrap();
            assert!(!is_fail, "non-text content items must be skipped");
        });
    }

    #[test]
    fn test_is_failure_structured_content_none_allows_text_parsing() {
        // Kills mutant: `delete ! in is_failure` — if `!v.is_none()` becomes
        // `v.is_none()`, structuredContent:None would be treated as present
        // and check_text_content would be suppressed.
        Python::initialize();
        Python::attach(|py| {
            setup_cpex_framework(py);
            let config = RetryConfig {
                max_retries: 2,
                backoff_base_ms: 100,
                max_backoff_ms: 10_000,
                retry_on_status: vec![500],
                jitter: false,
                check_text_content: true,
                tool_overrides: HashMap::new(),
            };
            let core = RetryWithBackoffPluginCore {
                config: config.clone(),
                state_manager: Arc::new(Mutex::new(HashMap::new())),
            };

            // structuredContent is explicitly None — text parsing must still run
            let item = PyDict::new(py);
            item.set_item("type", "text").unwrap();
            item.set_item("text", r#"{"isError": true}"#).unwrap();
            let content = PyList::empty(py);
            content.append(item.as_any()).unwrap();
            let result_dict = PyDict::new(py);
            result_dict
                .set_item("structuredContent", py.None())
                .unwrap();
            result_dict.set_item("content", content).unwrap();

            let is_fail = core.is_failure(py, result_dict.as_any(), &config).unwrap();
            assert!(
                is_fail,
                "structuredContent:None must not suppress check_text_content"
            );
        });
    }

    #[test]
    fn test_is_failure_non_null_structured_content_suppresses_text_parsing() {
        // Companion to the above: non-null structuredContent must suppress text parsing.
        Python::initialize();
        Python::attach(|py| {
            setup_cpex_framework(py);
            let config = RetryConfig {
                max_retries: 2,
                backoff_base_ms: 100,
                max_backoff_ms: 10_000,
                retry_on_status: vec![500],
                jitter: false,
                check_text_content: true,
                tool_overrides: HashMap::new(),
            };
            let core = RetryWithBackoffPluginCore {
                config: config.clone(),
                state_manager: Arc::new(Mutex::new(HashMap::new())),
            };

            // Non-null structuredContent with no error signals — text must not be parsed
            let item = PyDict::new(py);
            item.set_item("type", "text").unwrap();
            item.set_item("text", r#"{"isError": true}"#).unwrap();
            let content = PyList::empty(py);
            content.append(item.as_any()).unwrap();
            let result_dict = PyDict::new(py);
            result_dict
                .set_item("structuredContent", PyDict::new(py))
                .unwrap();
            result_dict.set_item("content", content).unwrap();

            let is_fail = core.is_failure(py, result_dict.as_any(), &config).unwrap();
            assert!(
                !is_fail,
                "non-null structuredContent must suppress check_text_content"
            );
        });
    }
}
