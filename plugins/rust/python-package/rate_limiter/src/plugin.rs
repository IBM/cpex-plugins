// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
//
// Rust-owned rate limiter plugin core. Python only keeps a tiny compatibility
// shell so the gateway can continue importing a `Plugin` subclass.

use std::sync::Arc;

use cpex_framework_bridge::{build_framework_object, default_result};
use log::warn;
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyDict, PyModule, PyTuple};
use pyo3_async_runtimes::tokio::{future_into_py, into_future};
use pyo3_stub_gen::derive::*;

use crate::engine::RateLimiterEngine;

const LOGGER_NAME: &str = "cpex_rate_limiter.rate_limiter";

#[gen_stub_pyclass]
#[pyclass]
pub struct RateLimiterPluginCore {
    engine: Arc<RateLimiterEngine>,
    use_async: bool,
    /// When true, backend failures produce a BACKEND_UNAVAILABLE violation
    /// (fail-closed) instead of the default allow result (fail-open). Read
    /// from the `fail_mode` config key at init time.
    fail_closed: bool,
}

#[gen_stub_pymethods]
#[pymethods]
impl RateLimiterPluginCore {
    #[new]
    pub fn new(config: &Bound<'_, PyDict>) -> PyResult<Self> {
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

    pub fn prompt_pre_fetch<'py>(
        &self,
        py: Python<'py>,
        payload: &Bound<'_, PyAny>,
        context: &Bound<'_, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
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
                    )
                }),
                Err(_err) => Python::attach(|py| {
                    log_exception(py, error_log_message("prompt_pre_fetch", fail_closed))?;
                    backend_error_result(py, "PromptPrehookResult", fail_closed)
                }),
            }
        })
    }

    pub fn tool_pre_invoke<'py>(
        &self,
        py: Python<'py>,
        payload: &Bound<'_, PyAny>,
        context: &Bound<'_, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
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
) -> PyResult<Py<PyAny>> {
    if meta
        .get_item("limited")?
        .and_then(|value| value.extract::<bool>().ok())
        == Some(false)
    {
        return build_framework_object(
            py,
            class_name,
            [("metadata", meta.clone().into_any().unbind())],
        );
    }

    if !allowed {
        return build_framework_object(
            py,
            class_name,
            [
                (
                    "continue_processing",
                    false.into_pyobject(py)?.to_owned().into_any().unbind(),
                ),
                ("violation", build_violation(py, meta, headers)?),
            ],
        );
    }

    headers.del_item("Retry-After").ok();
    build_framework_object(
        py,
        class_name,
        [
            ("metadata", meta.clone().into_any().unbind()),
            ("http_headers", headers.clone().into_any().unbind()),
        ],
    )
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
    use pyo3::prelude::*;
    use pyo3::types::{PyAnyMethods, PyDictMethods, PyModule};

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
