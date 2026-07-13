// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
//
// Rust-owned rate limiter plugin core. Python only keeps a tiny compatibility
// shell so the gateway can continue importing a `Plugin` subclass.

use std::sync::{Arc, OnceLock};

use cpex_framework_bridge::{build_framework_object, build_framework_object_dyn, default_result};
use log::warn;
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyDict, PyModule, PyTuple};
use pyo3_async_runtimes::tokio::{future_into_py, into_future};
#[cfg(feature = "stub-gen")]
use pyo3_stub_gen::derive::*;

use crate::engine::RateLimiterEngine;

const LOGGER_NAME: &str = "cpex_rate_limiter.rate_limiter";

/// Process-global guard: installs the rustls ring crypto provider exactly
/// once. rustls 0.23 dropped its implicit default crypto provider, so any
/// caller that wants TLS must install one before first use. The redis
/// crate's `tls-rustls` feature does not pick a provider, so without this
/// the first `rediss://` operation panics with
/// "Call CryptoProvider::install_default() before this point...".
///
/// `install_default` returns Err if a provider is already installed (e.g.
/// by another caller in the same process); that's a no-op for us, so we
/// discard the result.
static CRYPTO_PROVIDER_INSTALLED: OnceLock<()> = OnceLock::new();

fn ensure_crypto_provider() {
    CRYPTO_PROVIDER_INSTALLED.get_or_init(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

#[cfg_attr(feature = "stub-gen", gen_stub_pyclass)]
#[pyclass]
pub struct RateLimiterPluginCore {
    engine: Arc<RateLimiterEngine>,
    use_async: bool,
    /// When true, backend failures produce a BACKEND_UNAVAILABLE violation
    /// (fail-closed) instead of the default allow result (fail-open). Read
    /// from the `fail_mode` config key at init time.
    fail_closed: bool,
}

#[cfg_attr(feature = "stub-gen", gen_stub_pymethods)]
#[pymethods]
impl RateLimiterPluginCore {
    #[new]
    pub fn new(config: &Bound<'_, PyDict>) -> PyResult<Self> {
        // Install the rustls crypto provider before any redis client is
        // constructed — required for `rediss://` URLs to work past the
        // first TLS handshake. See `ensure_crypto_provider` doc above.
        ensure_crypto_provider();
        let engine = Arc::new(RateLimiterEngine::new(config)?);
        let fail_closed = parse_fail_mode(config)?;
        Ok(Self {
            use_async: engine.uses_async_backend(),
            engine,
            fail_closed,
        })
    }

    /// Release backend-held resources (e.g. the cached Redis multiplexed
    /// connection). Called by the Python shim's `shutdown()` when the plugin
    /// framework tears the plugin down.
    pub fn shutdown(&self) {
        self.engine.shutdown();
    }

    #[pyo3(signature = (payload, context, extensions=None))]
    pub fn prompt_pre_fetch<'py>(
        &self,
        py: Python<'py>,
        payload: &Bound<'_, PyAny>,
        context: &Bound<'_, PyAny>,
        extensions: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let trace_id = read_trace_id(extensions);
        let backend = self.backend_label();
        let prompt = payload
            .getattr("prompt_id")?
            .extract::<String>()?
            .trim()
            .to_ascii_lowercase();
        let (user, tenant) = extract_request_context(context)?;
        // Use tenant_id as the context prefix so that each team's rate limit
        // counters are isolated in Redis. Without this, all teams share keys.
        let context_prefix = tenant.as_deref();
        let fail_closed = self.fail_closed;
        if !self.use_async {
            return match evaluate_sync_request(
                &self.engine,
                &user,
                tenant.as_deref(),
                &prompt,
                context_prefix,
            ) {
                Ok((allowed, headers, meta)) => Ok(build_prehook_result(
                    py,
                    "PromptPrehookResult",
                    allowed,
                    headers.bind(py),
                    meta.bind(py),
                    trace_id.as_deref(),
                    backend,
                )?
                .into_bound(py)),
                Err(_err) => {
                    log_exception(py, error_log_message("prompt_pre_fetch", fail_closed))?;
                    Ok(
                        backend_error_result(py, "PromptPrehookResult", fail_closed)?
                            .into_bound(py),
                    )
                }
            };
        }

        let engine = Arc::clone(&self.engine);
        let context_prefix_owned = context_prefix.map(|s| s.to_string());
        let trace_id_owned = trace_id.clone();
        future_into_py(py, async move {
            match evaluate_async_request(
                &engine,
                &user,
                tenant.as_deref(),
                &prompt,
                context_prefix_owned.as_deref(),
            )
            .await
            {
                Ok((allowed, headers, meta)) => Python::attach(|py| {
                    build_prehook_result(
                        py,
                        "PromptPrehookResult",
                        allowed,
                        headers.bind(py),
                        meta.bind(py),
                        trace_id_owned.as_deref(),
                        backend,
                    )
                }),
                Err(_err) => Python::attach(|py| {
                    log_exception(py, error_log_message("prompt_pre_fetch", fail_closed))?;
                    backend_error_result(py, "PromptPrehookResult", fail_closed)
                }),
            }
        })
    }

    #[pyo3(signature = (payload, context, extensions=None))]
    pub fn tool_pre_invoke<'py>(
        &self,
        py: Python<'py>,
        payload: &Bound<'_, PyAny>,
        context: &Bound<'_, PyAny>,
        extensions: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let trace_id = read_trace_id(extensions);
        let backend = self.backend_label();
        let tool = payload
            .getattr("name")?
            .extract::<String>()?
            .trim()
            .to_ascii_lowercase();
        let (user, tenant) = extract_request_context(context)?;
        let context_prefix = tenant.as_deref();
        let fail_closed = self.fail_closed;
        if !self.use_async {
            return match evaluate_sync_request(
                &self.engine,
                &user,
                tenant.as_deref(),
                &tool,
                context_prefix,
            ) {
                Ok((allowed, headers, meta)) => Ok(build_prehook_result(
                    py,
                    "ToolPreInvokeResult",
                    allowed,
                    headers.bind(py),
                    meta.bind(py),
                    trace_id.as_deref(),
                    backend,
                )?
                .into_bound(py)),
                Err(_err) => {
                    log_exception(py, error_log_message("tool_pre_invoke", fail_closed))?;
                    Ok(
                        backend_error_result(py, "ToolPreInvokeResult", fail_closed)?
                            .into_bound(py),
                    )
                }
            };
        }

        let engine = Arc::clone(&self.engine);
        let context_prefix_owned = context_prefix.map(|s| s.to_string());
        let trace_id_owned = trace_id.clone();
        future_into_py(py, async move {
            match evaluate_async_request(
                &engine,
                &user,
                tenant.as_deref(),
                &tool,
                context_prefix_owned.as_deref(),
            )
            .await
            {
                Ok((allowed, headers, meta)) => Python::attach(|py| {
                    build_prehook_result(
                        py,
                        "ToolPreInvokeResult",
                        allowed,
                        headers.bind(py),
                        meta.bind(py),
                        trace_id_owned.as_deref(),
                        backend,
                    )
                }),
                Err(_err) => Python::attach(|py| {
                    log_exception(py, error_log_message("tool_pre_invoke", fail_closed))?;
                    backend_error_result(py, "ToolPreInvokeResult", fail_closed)
                }),
            }
        })
    }
}

impl RateLimiterPluginCore {
    /// `"redis"` or `"memory"` — mirrors `engine.uses_async_backend()`
    /// (Redis is the only async backend today). Used only to label the
    /// `backend` field in the namespaced metrics dict; never on the
    /// no-trace-id path since callers gate before formatting it in.
    fn backend_label(&self) -> &'static str {
        if self.use_async { "redis" } else { "memory" }
    }
}

/// Parse the ``fail_mode`` config key into a ``fail_closed`` bool.
///
/// Accepted values (case-insensitive, trimmed): ``"open"`` and ``"closed"``.
/// An absent key, an explicit ``None``, or an empty string all resolve to
/// fail-open (the safe default for backwards compatibility). Any other
/// value — including typos like ``"clsoed"`` and non-string types — is
/// logged at WARN and falls through to fail-open rather than silently
/// disabling the fail-closed hardening the operator asked for.
fn parse_fail_mode(config: &Bound<'_, PyDict>) -> PyResult<bool> {
    let item = match config.get_item("fail_mode")? {
        None => return Ok(false),
        Some(v) if v.is_none() => return Ok(false),
        Some(v) => v,
    };

    match item.extract::<String>() {
        Ok(s) => {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                return Ok(false);
            }
            match trimmed.to_ascii_lowercase().as_str() {
                "open" => Ok(false),
                "closed" => Ok(true),
                _ => {
                    warn!(
                        "rate limiter: unknown fail_mode={:?}; expected \"open\" or \"closed\"; defaulting to \"open\"",
                        trimmed,
                    );
                    Ok(false)
                }
            }
        }
        Err(_) => {
            // Non-string value (dict, int, list, ...). Stringify for the log
            // so the operator sees what was actually passed.
            let repr = item
                .repr()
                .map(|r| r.to_string())
                .unwrap_or_else(|_| "<unrepresentable>".into());
            warn!(
                "rate limiter: fail_mode must be a string (\"open\" or \"closed\"); got {}; defaulting to \"open\"",
                repr,
            );
            Ok(false)
        }
    }
}

fn error_log_message(hook: &str, fail_closed: bool) -> &'static str {
    match (hook, fail_closed) {
        ("prompt_pre_fetch", false) => {
            "RateLimiterPlugin.prompt_pre_fetch error; allowing request (fail_mode=open)"
        }
        ("prompt_pre_fetch", true) => {
            "RateLimiterPlugin.prompt_pre_fetch error; blocking request (fail_mode=closed)"
        }
        ("tool_pre_invoke", false) => {
            "RateLimiterPlugin.tool_pre_invoke error; allowing request (fail_mode=open)"
        }
        ("tool_pre_invoke", true) => {
            "RateLimiterPlugin.tool_pre_invoke error; blocking request (fail_mode=closed)"
        }
        _ => "RateLimiterPlugin hook error",
    }
}

fn backend_error_result(
    py: Python<'_>,
    class_name: &str,
    fail_closed: bool,
) -> PyResult<Py<PyAny>> {
    if fail_closed {
        build_backend_unavailable_result(py, class_name)
    } else {
        default_result(py, class_name)
    }
}

fn evaluate_sync_request(
    engine: &RateLimiterEngine,
    user: &str,
    tenant: Option<&str>,
    tool_or_prompt: &str,
    context_prefix: Option<&str>,
) -> PyResult<(bool, Py<PyDict>, Py<PyDict>)> {
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?
        .as_secs() as i64;

    Python::attach(|py| {
        let (allowed, headers, meta) = engine.check(
            py,
            user,
            tenant,
            tool_or_prompt,
            now_unix,
            true,
            context_prefix,
        )?;
        Ok((allowed, headers.unbind(), meta.unbind()))
    })
}

async fn evaluate_async_request(
    engine: &RateLimiterEngine,
    user: &str,
    tenant: Option<&str>,
    tool_or_prompt: &str,
    context_prefix: Option<&str>,
) -> PyResult<(bool, Py<PyDict>, Py<PyDict>)> {
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?
        .as_secs() as i64;
    let awaitable = Python::attach(|py| {
        engine
            .check_async(
                py,
                user,
                tenant,
                tool_or_prompt,
                now_unix,
                true,
                context_prefix,
            )
            .map(|awaitable| awaitable.unbind())
    })?;
    await_async_tuple(awaitable).await
}

async fn await_async_tuple(awaitable: Py<PyAny>) -> PyResult<(bool, Py<PyDict>, Py<PyDict>)> {
    let result = Python::attach(|py| into_future(awaitable.bind(py).clone()))?.await?;
    Python::attach(|py| parse_check_tuple(result.bind(py)))
}

fn parse_check_tuple(result: &Bound<'_, PyAny>) -> PyResult<(bool, Py<PyDict>, Py<PyDict>)> {
    let tuple = result.cast::<PyTuple>()?;
    let allowed: bool = tuple.get_item(0)?.extract()?;
    let headers_item = tuple.get_item(1)?;
    let headers = headers_item.cast::<PyDict>()?;
    let meta_item = tuple.get_item(2)?;
    let meta = meta_item.cast::<PyDict>()?;
    Ok((allowed, headers.clone().unbind(), meta.clone().unbind()))
}

fn build_prehook_result(
    py: Python<'_>,
    class_name: &str,
    allowed: bool,
    headers: &Bound<'_, PyDict>,
    meta: &Bound<'_, PyDict>,
    trace_id: Option<&str>,
    backend: &str,
) -> PyResult<Py<PyAny>> {
    if meta
        .get_item("limited")?
        .and_then(|value| value.extract::<bool>().ok())
        == Some(false)
    {
        // No rate limit configured for this dimension: always allowed.
        let mut kwargs: Vec<(&str, Py<PyAny>)> = Vec::new();
        push_rate_limiter_metrics_kwarg(py, trace_id, &mut kwargs, true, backend, meta);
        if kwargs.is_empty() {
            return default_result(py, class_name);
        }
        return build_framework_object_dyn(py, class_name, kwargs);
    }

    if !allowed {
        let mut kwargs: Vec<(&str, Py<PyAny>)> = vec![
            (
                "continue_processing",
                false.into_pyobject(py)?.to_owned().into_any().unbind(),
            ),
            ("violation", build_violation(py, meta, headers)?),
        ];
        // Throttled: this is exactly the event the metric exists to count,
        // so it must be emitted here too, not only on the allowed path.
        push_rate_limiter_metrics_kwarg(py, trace_id, &mut kwargs, false, backend, meta);
        return build_framework_object_dyn(py, class_name, kwargs);
    }

    headers.del_item("Retry-After").ok();
    let mut kwargs: Vec<(&str, Py<PyAny>)> =
        vec![("http_headers", headers.clone().into_any().unbind())];
    push_rate_limiter_metrics_kwarg(py, trace_id, &mut kwargs, true, backend, meta);
    build_framework_object_dyn(py, class_name, kwargs)
}

/// `meta` fields (built by `engine::build_meta_dict`) that are safe to fold
/// into the namespaced metrics dict: aggregate rate-limit state only.
/// Deliberately excludes `user_id`/`tenant_id` — `build_meta_dict` only sets
/// those on the not-allowed path (G7, for `PluginViolation.details`
/// debugging), and a metrics/telemetry channel is not the place for identity
/// (S1: no identifiers in metrics, mirrors "no raw content").
const META_METRIC_KEYS: &[&str] = &["limited", "remaining", "reset_in", "dimensions"];

/// Build the namespaced metrics dict for the `result.metadata` channel.
/// Returns `None` (no work) when `trace_id` is absent (gate: no trace means
/// no metrics). Folds the engine's own operational `meta` fields (allowlisted
/// via `META_METRIC_KEYS`) together with the new per-call counters into ONE
/// dict — there is exactly one `result.metadata` write per hook call, and it
/// replaces the old un-namespaced flat write of the whole `meta` dict.
///
/// `allowed`/`throttled` are per-call 0/1, not cumulative totals: the engine
/// evaluates a single request per call with no running counter, so these
/// describe only the current call's outcome (the gateway aggregates counts
/// across spans/time).
fn build_rate_limiter_metrics<'py>(
    py: Python<'py>,
    trace_id: Option<&str>,
    allowed: bool,
    backend: &str,
    meta: &Bound<'py, PyDict>,
) -> PyResult<Option<Bound<'py, PyDict>>> {
    if trace_id.is_none() {
        return Ok(None);
    }
    let inner = PyDict::new(py);
    for key in META_METRIC_KEYS {
        if let Some(value) = meta.get_item(key)? {
            inner.set_item(*key, value)?;
        }
    }
    inner.set_item("allowed", if allowed { 1 } else { 0 })?;
    inner.set_item("throttled", if allowed { 0 } else { 1 })?;
    inner.set_item("backend", backend)?;
    let outer = PyDict::new(py);
    outer.set_item("rate_limiter", inner)?;
    Ok(Some(outer))
}

/// Best-effort attach of the namespaced metrics dict onto `kwargs` when
/// `trace_id` is present. Never fails the caller: any error building the
/// metrics dict is logged once and metrics are omitted, so the normal
/// rate-limit result is still returned.
///
/// Gates on `trace_id` before touching `meta` at all, so untraced requests
/// (the common case) never pay for the allowlist copy.
fn push_rate_limiter_metrics_kwarg(
    py: Python<'_>,
    trace_id: Option<&str>,
    kwargs: &mut Vec<(&str, Py<PyAny>)>,
    allowed: bool,
    backend: &str,
    meta: &Bound<'_, PyDict>,
) {
    let Some(tid) = trace_id else {
        return;
    };
    match build_rate_limiter_metrics(py, Some(tid), allowed, backend, meta) {
        Ok(Some(md)) => kwargs.push(("metadata", md.into_any().unbind())),
        Ok(None) => {}
        Err(e) => log::warn!("rate_limiter: metrics build failed, omitting: {e}"),
    }
}

/// Best-effort read of `extensions.request.trace_id`. Returns `None` on any
/// missing attribute, `None` value, wrong type, or PyO3 error — never raises.
/// Mirrors `pii_filter::plugin::read_trace_id` / `secrets_detection::plugin::read_trace_id`.
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

/// Build a prehook/tool result that carries a BACKEND_UNAVAILABLE violation.
/// Used when `fail_mode=closed` and the Rust engine could not evaluate the
/// rate limit (e.g. Redis unreachable). The result blocks the request with
/// HTTP 503 and a Retry-After hint.
fn build_backend_unavailable_result(py: Python<'_>, class_name: &str) -> PyResult<Py<PyAny>> {
    let headers = PyDict::new(py);
    headers.set_item("Retry-After", "1")?;
    let violation = build_framework_object(
        py,
        "PluginViolation",
        [
            (
                "reason",
                "Rate limiter backend unavailable"
                    .into_pyobject(py)?
                    .into_any()
                    .unbind(),
            ),
            (
                "description",
                "Rate limiter backend unavailable; failing closed per fail_mode=closed"
                    .into_pyobject(py)?
                    .into_any()
                    .unbind(),
            ),
            (
                "code",
                "BACKEND_UNAVAILABLE".into_pyobject(py)?.into_any().unbind(),
            ),
            ("details", PyDict::new(py).into_any().unbind()),
            (
                "http_status_code",
                503i32.into_pyobject(py)?.into_any().unbind(),
            ),
            ("http_headers", headers.into_any().unbind()),
        ],
    )?;
    build_framework_object(
        py,
        class_name,
        [
            (
                "continue_processing",
                false.into_pyobject(py)?.to_owned().into_any().unbind(),
            ),
            ("violation", violation),
        ],
    )
}

fn build_violation(
    py: Python<'_>,
    meta: &Bound<'_, PyDict>,
    headers: &Bound<'_, PyDict>,
) -> PyResult<Py<PyAny>> {
    build_framework_object(
        py,
        "PluginViolation",
        [
            (
                "reason",
                "Rate limit exceeded".into_pyobject(py)?.into_any().unbind(),
            ),
            (
                "description",
                "Rate limit exceeded".into_pyobject(py)?.into_any().unbind(),
            ),
            ("code", "RATE_LIMIT".into_pyobject(py)?.into_any().unbind()),
            ("details", meta.clone().into_any().unbind()),
            (
                "http_status_code",
                429i32.into_pyobject(py)?.into_any().unbind(),
            ),
            ("http_headers", headers.clone().into_any().unbind()),
        ],
    )
}

fn extract_request_context(context: &Bound<'_, PyAny>) -> PyResult<(String, Option<String>)> {
    let global_context = context.getattr("global_context")?;
    let user = extract_user_identity(&global_context.getattr("user")?)?;
    let tenant = match global_context.getattr("tenant_id") {
        Ok(value) if !value.is_none() => {
            let trimmed = value.extract::<String>()?.trim().to_string();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            }
        }
        _ => None,
    };
    Ok((user, tenant))
}

fn extract_user_identity(user: &Bound<'_, PyAny>) -> PyResult<String> {
    if let Ok(dict) = user.cast::<PyDict>() {
        for key in ["email", "id", "sub"] {
            if let Some(value) = dict.get_item(key)? {
                if value.is_none() {
                    continue;
                }
                let trimmed = normalize_identity(value.as_any())?;
                if !trimmed.is_empty() {
                    return Ok(trimmed);
                }
            }
        }
        return Ok("anonymous".to_string());
    }

    if user.is_none() {
        return Ok("anonymous".to_string());
    }

    let trimmed = normalize_identity(user)?;
    if trimmed.is_empty() {
        Ok("anonymous".to_string())
    } else {
        Ok(trimmed)
    }
}

fn normalize_identity(value: &Bound<'_, PyAny>) -> PyResult<String> {
    Ok(value.str()?.to_str()?.trim().to_string())
}

fn log_exception(py: Python<'_>, message: &str) -> PyResult<()> {
    let logging = PyModule::import(py, "logging")?;
    let logger = logging.getattr("getLogger")?.call1((LOGGER_NAME,))?;
    logger.call_method1("exception", (message,))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::await_async_tuple;
    use super::ensure_crypto_provider;
    use super::{RateLimiterPluginCore, read_trace_id};
    use pyo3::prelude::*;
    use pyo3::types::{PyAnyMethods, PyDict, PyDictMethods, PyModule};

    /// Installs a minimal fake `cpex.framework` module so tests can exercise
    /// the real `#[pymethods]` entry points end to end without depending on
    /// the real `cpex` package being importable in the test environment.
    /// Mirrors the equivalent helper in `pii_filter`/`secrets_detection`.
    fn install_framework_module(py: Python<'_>) -> PyResult<()> {
        let framework = PyModule::from_code(
            py,
            pyo3::ffi::c_str!(
                r#"
class PluginViolation:
    def __init__(self, reason="", description="", code="", details=None, http_status_code=None, http_headers=None):
        self.reason = reason
        self.description = description
        self.code = code
        self.details = details
        self.http_status_code = http_status_code
        self.http_headers = http_headers

class PromptPrehookResult:
    def __init__(self, continue_processing=True, violation=None, modified_payload=None, metadata=None, http_headers=None):
        self.continue_processing = continue_processing
        self.violation = violation
        self.modified_payload = modified_payload
        self.metadata = metadata or {}
        self.http_headers = http_headers

class ToolPreInvokeResult(PromptPrehookResult):
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

    /// Builds fake `ToolPreInvokePayload`/`PromptPrehookPayload`-shaped
    /// objects and a `PluginContext`-shaped object carrying `global_context`,
    /// enough to satisfy `extract_request_context`.
    fn payload_module(py: Python<'_>) -> PyResult<Bound<'_, PyModule>> {
        PyModule::from_code(
            py,
            pyo3::ffi::c_str!(
                r#"
class ToolPayload:
    def __init__(self, name):
        self.name = name

class PromptPayload:
    def __init__(self, prompt_id):
        self.prompt_id = prompt_id

class GlobalContext:
    def __init__(self, user):
        self.user = user
        self.tenant_id = None

class Context:
    def __init__(self, user):
        self.global_context = GlobalContext(user)
"#
            ),
            pyo3::ffi::c_str!("rl_test_payloads.py"),
            pyo3::ffi::c_str!("rl_test_payloads"),
        )
    }

    fn extensions_with_trace<'py>(py: Python<'py>, trace_id: &str) -> PyResult<Bound<'py, PyAny>> {
        let ext_module = PyModule::from_code(
            py,
            pyo3::ffi::c_str!(
                "class Req:\n    def __init__(self, t):\n        self.trace_id = t\n\
                 class Ext:\n    def __init__(self, t):\n        self.request = Req(t)\n"
            ),
            pyo3::ffi::c_str!("rl_ext.py"),
            pyo3::ffi::c_str!("rl_ext"),
        )?;
        ext_module.getattr("Ext")?.call1((trace_id,))
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
    fn plugin_core_backend_label_reflects_config_backend() {
        Python::initialize();
        Python::attach(|py| -> PyResult<()> {
            let memory_cfg = PyDict::new(py);
            memory_cfg.set_item("backend", "memory")?;
            let memory_plugin = RateLimiterPluginCore::new(&memory_cfg)?;
            assert_eq!(memory_plugin.backend_label(), "memory");

            // redis::Client::open() only validates the URL shape; it does not
            // connect, so this constructs without a live Redis server.
            let redis_cfg = PyDict::new(py);
            redis_cfg.set_item("backend", "redis")?;
            redis_cfg.set_item("redis_url", "redis://127.0.0.1:1/0")?;
            let redis_plugin = RateLimiterPluginCore::new(&redis_cfg)?;
            assert_eq!(redis_plugin.backend_label(), "redis");
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn tool_pre_invoke_no_limits_configured_gates_metrics_on_trace_id() {
        Python::initialize();
        Python::attach(|py| -> PyResult<()> {
            install_framework_module(py)?;
            let module = payload_module(py)?;

            let config = PyDict::new(py);
            config.set_item("backend", "memory")?;
            let plugin = RateLimiterPluginCore::new(&config)?;

            let payload = module.getattr("ToolPayload")?.call1(("search",))?;
            let context = module.getattr("Context")?.call1(("alice",))?;

            // No trace_id: the early-return-not-limited branch must not write
            // any metadata at all, even though the call is (trivially) allowed.
            let result = plugin.tool_pre_invoke(py, &payload, &context, None)?;
            let metadata = result.getattr("metadata")?.cast_into::<PyDict>()?;
            assert_eq!(metadata.len(), 0);

            // With trace_id: namespaced metrics show allowed=1/throttled=0 and
            // the configured backend, folded together with the engine's own
            // `limited: false` field.
            let ext = extensions_with_trace(py, "t1")?;
            let result = plugin.tool_pre_invoke(py, &payload, &context, Some(&ext))?;
            let metadata = result.getattr("metadata")?.cast_into::<PyDict>()?;
            let metrics = metadata
                .get_item("rate_limiter")?
                .expect("namespaced metrics present");
            assert_eq!(metrics.get_item("allowed")?.extract::<i64>()?, 1);
            assert_eq!(metrics.get_item("throttled")?.extract::<i64>()?, 0);
            assert_eq!(metrics.get_item("backend")?.extract::<String>()?, "memory");
            assert!(!metrics.get_item("limited")?.extract::<bool>()?);

            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn tool_pre_invoke_allowed_emits_metrics_and_headers_with_trace_id_present() {
        Python::initialize();
        Python::attach(|py| -> PyResult<()> {
            install_framework_module(py)?;
            let module = payload_module(py)?;

            let config = PyDict::new(py);
            config.set_item("by_user", "5/s")?;
            config.set_item("backend", "memory")?;
            let plugin = RateLimiterPluginCore::new(&config)?;

            let payload = module.getattr("ToolPayload")?.call1(("search",))?;
            let context = module.getattr("Context")?.call1(("bob",))?;

            // No trace_id: http_headers still returned (unrelated to metrics
            // gating), but metadata is empty.
            let result = plugin.tool_pre_invoke(py, &payload, &context, None)?;
            assert!(!result.getattr("http_headers")?.is_none());
            let metadata = result.getattr("metadata")?.cast_into::<PyDict>()?;
            assert_eq!(metadata.len(), 0);

            // With trace_id: allowed branch folds `limited`/`remaining`/
            // `reset_in` alongside the new allowed/throttled/backend fields
            // into ONE namespaced write.
            let ext = extensions_with_trace(py, "t1")?;
            let payload2 = module.getattr("ToolPayload")?.call1(("search",))?;
            let context2 = module.getattr("Context")?.call1(("carol",))?;
            let result = plugin.tool_pre_invoke(py, &payload2, &context2, Some(&ext))?;
            assert!(!result.getattr("http_headers")?.is_none());
            let metadata = result.getattr("metadata")?.cast_into::<PyDict>()?;
            let metrics = metadata
                .get_item("rate_limiter")?
                .expect("namespaced metrics present");
            assert_eq!(metrics.get_item("allowed")?.extract::<i64>()?, 1);
            assert_eq!(metrics.get_item("throttled")?.extract::<i64>()?, 0);
            assert_eq!(metrics.get_item("backend")?.extract::<String>()?, "memory");
            assert!(metrics.get_item("limited")?.extract::<bool>()?);
            assert!(metrics.get_item("remaining").is_ok());
            assert!(metrics.get_item("reset_in").is_ok());

            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn tool_pre_invoke_throttled_emits_metrics_without_identifiers_when_trace_id_present() {
        Python::initialize();
        Python::attach(|py| -> PyResult<()> {
            install_framework_module(py)?;
            let module = payload_module(py)?;

            let config = PyDict::new(py);
            config.set_item("by_user", "1/s")?;
            config.set_item("backend", "memory")?;
            let plugin = RateLimiterPluginCore::new(&config)?;

            let ext = extensions_with_trace(py, "t1")?;
            let payload = module.getattr("ToolPayload")?.call1(("search",))?;
            let context = module.getattr("Context")?.call1(("dave",))?;

            // First call: allowed (exhausts the 1/s limit).
            let first = plugin.tool_pre_invoke(py, &payload, &context, Some(&ext))?;
            assert!(first.getattr("continue_processing")?.extract::<bool>()?);

            // Second call: throttled. This branch previously returned only a
            // `violation` with no metadata at all — now it must also emit
            // namespaced metrics (allowed=0/throttled=1), and must NOT leak
            // `user_id`/`tenant_id` (present in `violation.details`, i.e. the
            // `meta` dict) into the metrics dict (S1: no identifiers in
            // metrics).
            let second = plugin.tool_pre_invoke(py, &payload, &context, Some(&ext))?;
            assert!(!second.getattr("continue_processing")?.extract::<bool>()?);
            let violation = second.getattr("violation")?;
            assert!(!violation.is_none());
            assert_eq!(
                violation.getattr("code")?.extract::<String>()?,
                "RATE_LIMIT"
            );
            // Sanity: the violation's own `details` (echoing `meta`) does
            // carry user_id — proving the exclusion below is deliberate, not
            // accidental (build_meta_dict never set it).
            let details = violation.getattr("details")?.cast_into::<PyDict>()?;
            assert!(details.get_item("user_id")?.is_some());

            let metadata = second.getattr("metadata")?.cast_into::<PyDict>()?;
            let metrics = metadata
                .get_item("rate_limiter")?
                .expect("namespaced metrics present");
            assert_eq!(metrics.get_item("allowed")?.extract::<i64>()?, 0);
            assert_eq!(metrics.get_item("throttled")?.extract::<i64>()?, 1);
            assert_eq!(metrics.get_item("backend")?.extract::<String>()?, "memory");
            assert!(metrics.get_item("user_id").is_err());
            assert!(metrics.get_item("tenant_id").is_err());

            // Without trace_id: throttled branch must still block, but must
            // not attach any metadata.
            let context_no_trace = module.getattr("Context")?.call1(("erin",))?;
            let _ = plugin.tool_pre_invoke(py, &payload, &context_no_trace, None)?;
            let blocked_no_trace = plugin.tool_pre_invoke(py, &payload, &context_no_trace, None)?;
            assert!(
                !blocked_no_trace
                    .getattr("continue_processing")?
                    .extract::<bool>()?
            );
            let metadata = blocked_no_trace
                .getattr("metadata")?
                .cast_into::<PyDict>()?;
            assert_eq!(metadata.len(), 0);

            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn ensure_crypto_provider_installs_a_default() {
        // Mutation guard: cargo-mutants tries replacing the body of
        // `ensure_crypto_provider` with `()`. Under that mutation no rustls
        // crypto provider is installed by us, and (since no other code path
        // in this crate installs one) `CryptoProvider::get_default()` returns
        // None — surfacing the runtime-time signature
        // ("Call CryptoProvider::install_default() before this point...")
        // the function exists to prevent.
        //
        // OnceLock makes the call idempotent; this test is safe to run in
        // any order alongside other tests in the same process.
        ensure_crypto_provider();
        assert!(
            rustls::crypto::CryptoProvider::get_default().is_some(),
            "ensure_crypto_provider() must leave a default rustls crypto provider installed",
        );
    }

    #[test]
    fn await_async_tuple_parses_successful_result() -> PyResult<()> {
        // Ensure the embedded interpreter is initialized for this test process.
        // `cargo-nextest` runs tests in separate processes, so this cannot rely
        // on another test having already touched Python.
        Python::initialize();
        Python::attach(|py| -> PyResult<()> {
            let sys = py.import("sys")?;
            let asyncio = py.import("asyncio")?;
            if sys.getattr("platform")?.extract::<String>()? == "win32" {
                let policy = asyncio.getattr("WindowsSelectorEventLoopPolicy")?.call0()?;
                asyncio.call_method1("set_event_loop_policy", (&policy,))?;
            }
            let event_loop = asyncio.call_method0("new_event_loop")?;
            asyncio.call_method1("set_event_loop", (&event_loop,))?;

            pyo3_async_runtimes::tokio::run_until_complete(event_loop, async move {
                let awaitable = Python::attach(|py| -> PyResult<Py<PyAny>> {
                    let module = PyModule::from_code(
                        py,
                        pyo3::ffi::c_str!(
                            "async def make_result():\n    return (True, {'X-RateLimit-Limit': '1'}, {'limited': True, 'remaining': 0})\n"
                        ),
                        pyo3::ffi::c_str!("bridge_test.py"),
                        pyo3::ffi::c_str!("bridge_test"),
                    )?;
                    Ok(module.getattr("make_result")?.call0()?.unbind())
                })?;

                let (allowed, headers, meta) = await_async_tuple(awaitable).await?;
                assert!(allowed);
                Python::attach(|py| {
                    assert_eq!(
                        headers
                            .bind(py)
                            .get_item("X-RateLimit-Limit")
                            .expect("dict lookup should succeed")
                            .expect("header should exist")
                            .extract::<String>()
                            .expect("header should be a string"),
                        "1",
                    );
                    assert!(
                        meta.bind(py)
                            .get_item("limited")
                            .expect("dict lookup should succeed")
                            .expect("key should exist")
                            .extract::<bool>()
                            .expect("value should be bool")
                    );
                    Ok(())
                })
            })
        })
    }
}
