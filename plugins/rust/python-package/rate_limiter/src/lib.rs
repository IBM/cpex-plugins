// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
//
// Rate Limiter Engine — Rust implementation.
//
// Exposed to Python via PyO3. One public class: `RateLimiterEngine`.
// Hot-path methods: `check()` / `check_async()` (ARCH-01, IFACE-02).

use pyo3::prelude::*;
use pyo3::types::PyDict;
use pyo3_stub_gen::define_stub_info_gatherer;

pub mod clock;
pub mod config;
pub mod engine;
pub mod memory;
pub mod plugin;
pub mod redis_backend;
pub mod types;

pub use engine::RateLimiterEngine;
pub use types::{EvalDimension, EvalResult};

#[pyfunction]
fn compat_default_config(py: Python<'_>) -> PyResult<Py<PyDict>> {
    let defaults = PyDict::new(py);
    defaults.set_item("by_user", py.None())?;
    defaults.set_item("by_tenant", py.None())?;
    defaults.set_item("by_tool", py.None())?;
    defaults.set_item("algorithm", "fixed_window")?;
    defaults.set_item("backend", "memory")?;
    defaults.set_item("redis_url", py.None())?;
    defaults.set_item("redis_key_prefix", "rl")?;
    Ok(defaults.unbind())
}

#[pyfunction]
fn compat_parse_rate(rate: &str) -> PyResult<(u64, u64)> {
    let parsed = config::parse_rate(rate)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
    Ok((parsed.count, parsed.window_secs()))
}

/// Python module definition.
#[pymodule]
fn rate_limiter_rust(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Bridge Rust `log` macros into Python's `logging` module so Rust
    // engine messages appear in the same log stream as the Python plugin.
    pyo3_log::init();

    m.add_class::<RateLimiterEngine>()?;
    m.add_class::<plugin::RateLimiterPluginCore>()?;
    m.add_class::<EvalResult>()?;
    m.add_class::<EvalDimension>()?;
    m.add_function(wrap_pyfunction!(compat_default_config, m)?)?;
    m.add_function(wrap_pyfunction!(compat_parse_rate, m)?)?;
    Ok(())
}

// Generate Python type stubs (.pyi files).
define_stub_info_gatherer!(stub_info);
