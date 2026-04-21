// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
//
// `RateLimiterEngine` — the single PyO3-exposed class (IFACE-02).
//
// Python calls `check(user, tenant, tool, now_unix)` once per hook
// invocation (ARCH-01).  The engine builds dimension keys, evaluates,
// aggregates, and returns pre-built header/meta dicts (ARCH-02).
// The Python wrapper is policy-only and never does rate math (ARCH-03).
//
// The older `evaluate_many()` entry point is retained for Rust-side tests
// only (cfg(test)) and is not exposed to Python.

use std::collections::HashMap;
use std::sync::Arc;

use log::warn;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

use pyo3_async_runtimes::tokio::future_into_py;
use pyo3_stub_gen::derive::*;

use crate::clock::{Clock, SystemClock};
use crate::config::{ConfigError, EngineConfig};
use crate::memory::MemoryStore;
use crate::redis_backend::RedisRateLimiter;
use crate::types::{DimResult, EvalResult};

// ---------------------------------------------------------------------------
// Backend selection
// ---------------------------------------------------------------------------

#[derive(Clone)]
enum EngineBackend {
    Memory(Arc<MemoryStore>),
    Redis(Arc<RedisRateLimiter>),
}

// ---------------------------------------------------------------------------
// Check descriptor — one entry per active dimension
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

/// High-performance rate limiter engine.
///
/// Construct once per plugin instance (`__init__`), then call
/// `check()` / `check_async()` on every hook invocation.
///
/// Backend is selected at init time from the config dict:
/// - `backend: "memory"` (default) — in-process counting via `MemoryStore`
/// - `backend: "redis"` — Rust owns the Redis connection; same batch Lua
///   scripts as the Python `RedisBackend`, one EVAL per hook invocation
#[derive(Clone)]
#[gen_stub_pyclass]
#[pyclass(skip_from_py_object)]
pub struct RateLimiterEngine {
    config: EngineConfig,
    backend: EngineBackend,
    clock: Arc<dyn Clock>,
}

impl RateLimiterEngine {
    /// Internal constructor — always uses the memory backend.
    /// Used by tests and benchmarks where clock injection is required.
    pub fn new_with_clock(config: EngineConfig, clock: Arc<dyn Clock>) -> Self {
        Self {
            backend: EngineBackend::Memory(Arc::new(MemoryStore::new())),
            config,
            clock,
        }
    }

    pub fn uses_async_backend(&self) -> bool {
        matches!(self.backend, EngineBackend::Redis(_))
    }

    /// Release backend-held resources. For Redis, this drops the cached
    /// multiplexed connection so the server can close the socket; in-flight
    /// requests that already cloned the handle remain valid. Memory backend
    /// has no external resources and is a no-op.
    pub fn shutdown(&self) {
        if let EngineBackend::Redis(redis) = &self.backend {
            redis.shutdown();
        }
    }
}

#[gen_stub_pymethods]
#[pymethods]
impl RateLimiterEngine {
    /// Construct from the Python config dict.
    ///
    /// Parses all rate strings and normalises `by_tool` keys at init time —
    /// never on the request path (IFACE-01, IFACE-05).
    ///
    /// Extra keys consumed here (not part of `EngineConfig`):
    /// - `backend`: `"memory"` (default) or `"redis"`
    /// - `redis_url`: required when `backend = "redis"`
    /// - `redis_key_prefix`: key namespace prefix (default `"rl"`)
    /// - `fail_mode`: `"open"` (default) or `"closed"` — handled by the
    ///   plugin shim, but accepted here so it doesn't trip the unknown-key
    ///   warning below.
    ///
    /// Any other key in the dict is logged at WARN so misspellings (e.g.
    /// `redis_ur` instead of `redis_url`) surface visibly instead of being
    /// silently ignored.
    #[new]
    pub fn new(config: &Bound<'_, PyDict>) -> PyResult<Self> {
        warn_on_unknown_config_keys(config);

        let by_user: Option<String> = config.get_item("by_user")?.and_then(|v| v.extract().ok());
        let by_tenant: Option<String> =
            config.get_item("by_tenant")?.and_then(|v| v.extract().ok());
        let algorithm: String = config
            .get_item("algorithm")?
            .and_then(|v| v.extract().ok())
            .unwrap_or_else(|| "fixed_window".to_string());

        let by_tool: HashMap<String, String> = config
            .get_item("by_tool")?
            .and_then(|v| v.extract().ok())
            .unwrap_or_default();

        let engine_config = EngineConfig::new(
            by_user.as_deref(),
            by_tenant.as_deref(),
            by_tool,
            &algorithm,
        )
        .map_err(|e: ConfigError| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;

        let backend_str: String = config
            .get_item("backend")?
            .and_then(|v| v.extract().ok())
            .unwrap_or_else(|| "memory".to_string());

        let backend = if backend_str == "redis" {
            let redis_url: String = config
                .get_item("redis_url")?
                .and_then(|v| v.extract().ok())
                .ok_or_else(|| {
                    pyo3::exceptions::PyValueError::new_err(
                        "redis_url is required when backend=redis",
                    )
                })?;
            let prefix: String = config
                .get_item("redis_key_prefix")?
                .and_then(|v| v.extract().ok())
                .unwrap_or_else(|| "rl".to_string());
            let redis_limiter = RedisRateLimiter::new(&redis_url, engine_config.algorithm, prefix)
                .map_err(|e| {
                    warn!("Rust rate limiter: Redis backend init failed: {}", e);
                    pyo3::exceptions::PyRuntimeError::new_err(e.to_string())
                })?;
            EngineBackend::Redis(Arc::new(redis_limiter))
        } else if backend_str == "memory" {
            EngineBackend::Memory(Arc::new(MemoryStore::new()))
        } else {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "backend={backend_str:?}: must be 'memory' or 'redis'"
            )));
        };

        Ok(Self {
            config: engine_config,
            backend,
            clock: Arc::new(SystemClock),
        })
    }

    /// High-level check: builds dimension keys internally, evaluates, and
    /// returns pre-built Python dicts for headers and metadata.
    ///
    /// This eliminates all per-attribute PyO3 accesses on the Python side.
    /// The Python wrapper calls this once per hook invocation.
    ///
    /// Returns `(allowed, headers_dict, meta_dict)`.
    ///
    /// When `context_prefix` is provided (e.g. a team/tenant ID), it is
    /// prepended to every dimension key so that separate plugin instances
    /// for different tenants use isolated Redis counters instead of sharing
    /// a single key namespace.
    ///
    /// **Note:** The Redis backend arm uses `block_on()` on a dedicated Tokio
    /// runtime, which would deadlock if called from within a Tokio context.
    /// The Python wrapper routes Redis to `check_async()` instead; this sync
    /// path is intended for the memory backend.  The `debug_assert` below
    /// guards against accidental misuse.
    #[allow(clippy::too_many_arguments)]
    pub fn check<'py>(
        &self,
        py: Python<'py>,
        user: &str,
        tenant: Option<&str>,
        tool: &str,
        now_unix: i64,
        include_retry_after: bool,
        context_prefix: Option<&str>,
    ) -> PyResult<(bool, Bound<'py, PyDict>, Bound<'py, PyDict>)> {
        if matches!(self.backend, EngineBackend::Redis(_)) {
            return Err(pyo3::exceptions::PyRuntimeError::new_err(
                "check() must not be called with the Redis backend — use check_async() instead",
            ));
        }
        let checks = self.build_checks(user, tenant, tool, context_prefix);
        if checks.is_empty() {
            let headers = PyDict::new(py);
            let meta = PyDict::new(py);
            meta.set_item("limited", false)?;
            return Ok((true, headers, meta));
        }

        let dim_results: Vec<DimResult> = py
            .detach(|| -> Result<Vec<DimResult>, String> {
                match &self.backend {
                    EngineBackend::Memory(store) => {
                        let now_mono = self.clock.now_monotonic();
                        Ok(checks
                            .into_iter()
                            .map(|(key, limit_count, window_nanos)| {
                                store.check_and_increment(
                                    &key,
                                    limit_count,
                                    window_nanos,
                                    self.config.algorithm,
                                    now_mono,
                                    now_unix,
                                )
                            })
                            .collect())
                    }
                    EngineBackend::Redis(redis) => redis
                        .evaluate_many(&checks, now_unix)
                        .map_err(|e| e.to_string()),
                }
            })
            .map_err(pyo3::exceptions::PyRuntimeError::new_err)?;

        let eval = EvalResult::from_dims(&dim_results);
        let headers = build_headers_dict(py, &eval, include_retry_after)?;
        let meta = build_meta_dict(py, &eval, now_unix, Some(user), tenant)?;
        Ok((eval.allowed, headers, meta))
    }

    /// Async variant of `check()` for Redis-backed deployments.
    ///
    /// Returns an awaitable that resolves to `(allowed, headers_dict, meta_dict)`.
    #[allow(clippy::too_many_arguments)]
    pub fn check_async<'py>(
        &self,
        py: Python<'py>,
        user: &str,
        tenant: Option<&str>,
        tool: &str,
        now_unix: i64,
        include_retry_after: bool,
        context_prefix: Option<&str>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let checks = self.build_checks(user, tenant, tool, context_prefix);
        if checks.is_empty() {
            return future_into_py(py, async move {
                Python::attach(|py| -> PyResult<Py<PyAny>> {
                    let headers = PyDict::new(py);
                    let meta = PyDict::new(py);
                    meta.set_item("limited", false)?;
                    let tup = pyo3::types::PyTuple::new(
                        py,
                        [
                            true.into_pyobject(py)?.to_owned().into_any(),
                            headers.into_any(),
                            meta.into_any(),
                        ],
                    )?;
                    Ok(tup.into())
                })
            });
        }

        let backend = self.backend.clone();
        let algorithm = self.config.algorithm;
        let clock = Arc::clone(&self.clock);
        // Capture identity as owned for the async move so build_meta_dict
        // can surface tenant_id/user_id in violation details (G7).
        let user_owned = user.to_string();
        let tenant_owned = tenant.map(|s| s.to_string());

        future_into_py(py, async move {
            let dim_results: Vec<DimResult> =
                match backend {
                    EngineBackend::Memory(store) => {
                        let now_mono = clock.now_monotonic();
                        checks
                            .into_iter()
                            .map(|(key, limit_count, window_nanos)| {
                                store.check_and_increment(
                                    &key,
                                    limit_count,
                                    window_nanos,
                                    algorithm,
                                    now_mono,
                                    now_unix,
                                )
                            })
                            .collect()
                    }
                    EngineBackend::Redis(redis) => redis
                        .evaluate_many_async(&checks, now_unix)
                        .await
                        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?,
                };

            let eval = EvalResult::from_dims(&dim_results);
            Python::attach(|py| -> PyResult<Py<PyAny>> {
                let headers = build_headers_dict(py, &eval, include_retry_after)?;
                let meta = build_meta_dict(
                    py,
                    &eval,
                    now_unix,
                    Some(user_owned.as_str()),
                    tenant_owned.as_deref(),
                )?;
                let tup = pyo3::types::PyTuple::new(
                    py,
                    [
                        eval.allowed.into_pyobject(py)?.to_owned().into_any(),
                        headers.into_any(),
                        meta.into_any(),
                    ],
                )?;
                Ok(tup.into())
            })
        })
    }
}

// ---------------------------------------------------------------------------
// Private helpers — dimension key building and dict construction
// ---------------------------------------------------------------------------

impl RateLimiterEngine {
    /// Build dimension checks from engine config.
    /// Mirrors Python `_build_rust_checks()` but runs in Rust.
    ///
    /// When `context_prefix` is `Some("team_a")` the keys become
    /// `team_a:user:alice`, `team_a:tenant:team_a`, `team_a:tool:search`
    /// instead of the unprefixed versions. This prevents counter collisions
    /// across plugin-manager contexts (teams) that share the same Redis.
    fn build_checks(
        &self,
        user: &str,
        tenant: Option<&str>,
        tool: &str,
        context_prefix: Option<&str>,
    ) -> Vec<(String, u64, u64)> {
        let mut checks = Vec::with_capacity(3);
        let pfx = context_prefix.unwrap_or("");
        if let Some(ref rl) = self.config.by_user {
            let key = if pfx.is_empty() {
                format!("user:{}", user)
            } else {
                format!("{}:user:{}", pfx, user)
            };
            checks.push((key, rl.count, rl.window_nanos));
        }
        if let (Some(t), Some(rl)) = (tenant, &self.config.by_tenant) {
            let key = if pfx.is_empty() {
                format!("tenant:{}", t)
            } else {
                format!("{}:tenant:{}", pfx, t)
            };
            checks.push((key, rl.count, rl.window_nanos));
        }
        // Tool names are already normalised (lowercase) in EngineConfig at init time.
        // The caller passes the already-lowercased tool name from Python.
        if let Some(rl) = self.config.by_tool.get(tool) {
            let key = if pfx.is_empty() {
                format!("tool:{}", tool)
            } else {
                format!("{}:tool:{}", pfx, tool)
            };
            checks.push((key, rl.count, rl.window_nanos));
        }
        checks
    }
}

/// Emit a single WARN-level log listing config keys we don't recognise.
/// Catches misspellings (e.g. ``redis_ur`` instead of ``redis_url``) that
/// would otherwise silently default and surprise the operator at runtime.
fn warn_on_unknown_config_keys(config: &Bound<'_, PyDict>) {
    const KNOWN: &[&str] = &[
        "by_user",
        "by_tenant",
        "by_tool",
        "algorithm",
        "backend",
        "redis_url",
        "redis_key_prefix",
        "fail_mode",
    ];
    let mut unknown: Vec<String> = Vec::new();
    for (key, _) in config.iter() {
        let Ok(name) = key.extract::<String>() else {
            continue;
        };
        if !KNOWN.contains(&name.as_str()) {
            unknown.push(name);
        }
    }
    if !unknown.is_empty() {
        unknown.sort();
        warn!(
            "rate limiter: unknown config key(s): {}; expected one of: {}",
            unknown.join(", "),
            KNOWN.join(", "),
        );
    }
}

/// Build HTTP rate-limit headers dict — mirrors Python `_make_headers()`.
fn build_headers_dict<'py>(
    py: Python<'py>,
    eval: &EvalResult,
    include_retry_after: bool,
) -> PyResult<Bound<'py, PyDict>> {
    let headers = PyDict::new(py);
    if eval.limit == u64::MAX {
        return Ok(headers);
    }
    headers.set_item("X-RateLimit-Limit", eval.limit.to_string())?;
    headers.set_item("X-RateLimit-Remaining", eval.remaining.to_string())?;
    headers.set_item("X-RateLimit-Reset", eval.reset_timestamp.to_string())?;
    if include_retry_after {
        let retry = eval.retry_after.unwrap_or(0);
        headers.set_item("Retry-After", retry.to_string())?;
    }
    Ok(headers)
}

/// Build metadata dict — mirrors Python `_rust_to_plugin_meta()`.
///
/// When a request is blocked, identity (`user_id` / `tenant_id`) is
/// surfaced in the meta dict so the resulting `PluginViolation.details`
/// carries enough context for downstream debugging (G7). Identity is
/// intentionally NOT attached on allowed responses to avoid widening
/// identity exposure to every metadata consumer on the hot path.
fn build_meta_dict<'py>(
    py: Python<'py>,
    eval: &EvalResult,
    now_unix: i64,
    user: Option<&str>,
    tenant: Option<&str>,
) -> PyResult<Bound<'py, PyDict>> {
    let meta = PyDict::new(py);
    let reset_in = eval
        .retry_after
        .unwrap_or_else(|| (eval.reset_timestamp - now_unix).max(0));
    meta.set_item("limited", true)?;
    meta.set_item("remaining", eval.remaining)?;
    meta.set_item("reset_in", reset_in)?;
    if !eval.allowed {
        if let Some(u) = user.filter(|s| !s.is_empty()) {
            meta.set_item("user_id", u)?;
        }
        if let Some(t) = tenant.filter(|s| !s.is_empty()) {
            meta.set_item("tenant_id", t)?;
        }
    }

    let has_violated = !eval.violated_dimensions.is_empty();
    let has_allowed = !eval.allowed_dimensions.is_empty();

    if has_violated || has_allowed {
        let dims = PyDict::new(py);
        if has_violated {
            let violated_list = PyList::empty(py);
            for dim in &eval.violated_dimensions {
                let d = PyDict::new(py);
                let dim_reset_in = dim
                    .retry_after
                    .unwrap_or_else(|| (dim.reset_timestamp - now_unix).max(0));
                d.set_item("limited", true)?;
                d.set_item("remaining", dim.remaining)?;
                d.set_item("reset_in", dim_reset_in)?;
                violated_list.append(d)?;
            }
            dims.set_item("violated", violated_list)?;
        }
        if has_allowed {
            let allowed_list = PyList::empty(py);
            for dim in &eval.allowed_dimensions {
                let d = PyDict::new(py);
                let dim_reset_in = (dim.reset_timestamp - now_unix).max(0);
                d.set_item("limited", true)?;
                d.set_item("remaining", dim.remaining)?;
                d.set_item("reset_in", dim_reset_in)?;
                allowed_list.append(d)?;
            }
            dims.set_item("allowed", allowed_list)?;
        }
        meta.set_item("dimensions", dims)?;
    }

    Ok(meta)
}

#[cfg(test)]
impl RateLimiterEngine {
    /// Test-only entry point that evaluates pre-built dimension checks.
    ///
    /// Production code uses `check()` / `check_async()` which build
    /// dimension keys internally.
    pub fn evaluate_many(
        &self,
        checks: Vec<(String, u64, u64)>,
        now_unix: i64,
    ) -> PyResult<EvalResult> {
        Python::attach(|_py| {
            let dim_results: Vec<DimResult> = match &self.backend {
                EngineBackend::Memory(store) => {
                    let now_mono = self.clock.now_monotonic();
                    checks
                        .into_iter()
                        .map(|(key, limit_count, window_nanos)| {
                            store.check_and_increment(
                                &key,
                                limit_count,
                                window_nanos,
                                self.config.algorithm,
                                now_mono,
                                now_unix,
                            )
                        })
                        .collect()
                }
                EngineBackend::Redis(redis) => redis
                    .evaluate_many(&checks, now_unix)
                    .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?,
            };
            Ok(EvalResult::from_dims(&dim_results))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::FakeClock;
    use crate::config::Algorithm;

    fn init_python() {
        Python::initialize();
    }

    fn engine_with_fake_clock(
        by_user: Option<&str>,
        algorithm: Algorithm,
    ) -> (RateLimiterEngine, crate::clock::FakeClockHandle) {
        init_python();
        let (clock, handle) = FakeClock::new(1_000_000);
        let mut by_tool = HashMap::new();
        let cfg = EngineConfig {
            by_user: by_user.map(|s| crate::config::parse_rate(s).unwrap()),
            by_tenant: None,
            by_tool: {
                by_tool.insert(
                    "search".to_string(),
                    crate::config::parse_rate("5/m").unwrap(),
                );
                by_tool
            },
            algorithm,
        };
        let engine = RateLimiterEngine::new_with_clock(cfg, Arc::new(clock));
        (engine, handle)
    }

    // --- IFACE-01: config parsed at init ---

    #[test]
    fn config_parsed_at_init_by_tool_normalised() {
        let cfg = EngineConfig::new(
            Some("10/s"),
            None,
            {
                let mut m = HashMap::new();
                m.insert("Search".to_string(), "5/m".to_string());
                m
            },
            "fixed_window",
        )
        .unwrap();
        // Key must be lowercase
        assert!(cfg.by_tool.contains_key("search"));
        assert!(!cfg.by_tool.contains_key("Search"));
    }

    // --- IFACE-02: evaluate_many returns EvalResult ---

    #[test]
    fn evaluate_many_returns_eval_result_shape() {
        let (engine, handle) = engine_with_fake_clock(Some("10/s"), Algorithm::FixedWindow);
        let checks = vec![("user:alice".to_string(), 10, 1_000_000_000)];
        let result = engine.evaluate_many(checks, handle.unix_secs()).unwrap();
        // Shape: all fields present, first call always allowed
        assert!(result.allowed);
        assert_eq!(result.limit, 10);
        assert!(result.remaining > 0);
        assert!(result.retry_after.is_none());
    }

    // --- ARCH-01: evaluate_many is the only hot-path call ---
    // (Structural — enforced by the interface: Python has no other method to call)

    // --- CORR-03: reset_timestamp > now on allowed requests ---

    #[test]
    fn reset_timestamp_strictly_greater_than_now_on_allowed() {
        let (engine, handle) = engine_with_fake_clock(Some("10/s"), Algorithm::FixedWindow);
        let now_unix = handle.unix_secs();
        let checks = vec![("user:bob".to_string(), 10, 1_000_000_000)];
        let result = engine.evaluate_many(checks, now_unix).unwrap();
        assert!(result.allowed);
        assert!(
            result.reset_timestamp > now_unix,
            "reset_timestamp {} must be > now {}",
            result.reset_timestamp,
            now_unix
        );
    }

    // --- CORR-04: None tenant means no tenant check ---
    // (Structural — Python wrapper never adds a tenant check when tenant_id is None)

    // --- CORR-07: multi-dimension aggregation picks most restrictive ---

    #[test]
    fn evaluate_many_blocked_dimension_blocks_result() {
        let (engine, _handle) = engine_with_fake_clock(Some("2/s"), Algorithm::FixedWindow);
        // Exhaust the limit
        let checks = || vec![("user:carol".to_string(), 2, 1_000_000_000)];
        let _ = engine.evaluate_many(checks(), 1_000_000).unwrap(); // 1
        let _ = engine.evaluate_many(checks(), 1_000_000).unwrap(); // 2
        let result = engine.evaluate_many(checks(), 1_000_000).unwrap(); // 3 — must be blocked
        assert!(!result.allowed);
        assert_eq!(result.remaining, 0);
        assert!(result.retry_after.is_some());
    }

    #[test]
    fn evaluate_many_multiple_dims_picks_most_restrictive() {
        let (engine, _handle) = engine_with_fake_clock(None, Algorithm::FixedWindow);
        // user has 10/s, tenant has 2/s — after 2 requests tenant is exhausted
        let user_key = "user:dave".to_string();
        let tenant_key = "tenant:acme".to_string();
        let checks = || {
            vec![
                (user_key.clone(), 10, 1_000_000_000),
                (tenant_key.clone(), 2, 1_000_000_000),
            ]
        };
        let _ = engine.evaluate_many(checks(), 1_000_000).unwrap();
        let _ = engine.evaluate_many(checks(), 1_000_000).unwrap();
        let result = engine.evaluate_many(checks(), 1_000_000).unwrap();
        assert!(!result.allowed); // tenant exhausted → blocked
    }

    // --- Context prefix: tenant-scoped key isolation ---

    #[test]
    fn build_checks_without_prefix_produces_unprefixed_keys() {
        let (engine, _handle) = engine_with_fake_clock(Some("10/s"), Algorithm::FixedWindow);
        let checks = engine.build_checks("alice", Some("acme"), "search", None);
        let keys: Vec<&str> = checks.iter().map(|(k, _, _)| k.as_str()).collect();
        assert!(keys.contains(&"user:alice"));
        assert!(keys.contains(&"tool:search"));
    }

    #[test]
    fn build_checks_with_prefix_prepends_to_all_keys() {
        let (engine, _handle) = engine_with_fake_clock(Some("10/s"), Algorithm::FixedWindow);
        let checks = engine.build_checks("alice", Some("acme"), "search", Some("team_a"));
        let keys: Vec<&str> = checks.iter().map(|(k, _, _)| k.as_str()).collect();
        assert!(keys.contains(&"team_a:user:alice"), "keys: {:?}", keys);
        assert!(keys.contains(&"team_a:tool:search"), "keys: {:?}", keys);
    }

    #[test]
    fn build_checks_with_prefix_includes_tenant_dimension() {
        init_python();
        let (clock, _handle) = FakeClock::new(1_000_000);
        let cfg = EngineConfig {
            by_user: Some(crate::config::parse_rate("10/s").unwrap()),
            by_tenant: Some(crate::config::parse_rate("100/s").unwrap()),
            by_tool: HashMap::new(),
            algorithm: Algorithm::FixedWindow,
        };
        let engine = RateLimiterEngine::new_with_clock(cfg, Arc::new(clock));
        let checks = engine.build_checks("alice", Some("acme"), "search", Some("team_a"));
        let keys: Vec<&str> = checks.iter().map(|(k, _, _)| k.as_str()).collect();
        assert!(keys.contains(&"team_a:user:alice"), "keys: {:?}", keys);
        assert!(keys.contains(&"team_a:tenant:acme"), "keys: {:?}", keys);
    }

    #[test]
    fn different_prefixes_produce_isolated_counters() {
        let (engine, _handle) = engine_with_fake_clock(Some("2/s"), Algorithm::FixedWindow);
        // Exhaust limit for team_a
        let checks_a = || engine.build_checks("alice", None, "search", Some("team_a"));
        let _ = engine.evaluate_many(checks_a(), 1_000_000).unwrap();
        let _ = engine.evaluate_many(checks_a(), 1_000_000).unwrap();
        let result_a = engine.evaluate_many(checks_a(), 1_000_000).unwrap();
        assert!(
            !result_a.allowed,
            "team_a should be blocked after 2 requests"
        );

        // team_b should still be allowed — different prefix, different counters
        let checks_b = || engine.build_checks("alice", None, "search", Some("team_b"));
        let result_b = engine.evaluate_many(checks_b(), 1_000_000).unwrap();
        assert!(
            result_b.allowed,
            "team_b should be allowed — isolated counter"
        );
    }

    #[test]
    fn empty_prefix_matches_no_prefix_behavior() {
        let (engine, _handle) = engine_with_fake_clock(Some("10/s"), Algorithm::FixedWindow);
        let checks_none = engine.build_checks("alice", None, "search", None);
        let checks_empty = engine.build_checks("alice", None, "search", Some(""));
        // Both should produce the same unprefixed keys
        assert_eq!(checks_none.len(), checks_empty.len());
        for ((k1, _, _), (k2, _, _)) in checks_none.iter().zip(checks_empty.iter()) {
            assert_eq!(k1, k2);
        }
    }
}
