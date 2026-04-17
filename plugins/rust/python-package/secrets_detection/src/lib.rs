// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
//
// Secrets Detection Plugin - Rust Implementation

use std::sync::Once;

use log::debug;
use pyo3::prelude::*;
use pyo3_stub_gen::define_stub_info_gatherer;
use pyo3_stub_gen::derive::*;

pub mod config;
pub mod object_model;
pub mod patterns;
pub mod plugin;
mod scanner;

pub use config::SecretsDetectionConfig;
pub use scanner::{detect_and_redact, scan_container};

#[gen_stub_pyfunction]
#[pyfunction]
fn py_scan_container<'py>(
    py: Python<'py>,
    container: Bound<'py, PyAny>,
    config: Bound<'py, PyAny>,
) -> PyResult<(usize, Bound<'py, PyAny>, Bound<'py, pyo3::types::PyList>)> {
    let config = SecretsDetectionConfig::from_py_any(&config)?;
    scan_container(py, &container, &config)
}

fn init_logging() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        pyo3_log::init();
    });
}

#[pymodule]
fn secrets_detection_rust(m: &Bound<'_, PyModule>) -> PyResult<()> {
    init_logging();
    debug!("Initialized secrets_detection Rust module");
    m.add_function(wrap_pyfunction!(py_scan_container, m)?)?;
    m.add_class::<plugin::SecretsDetectionPluginCore>()?;
    Ok(())
}

define_stub_info_gatherer!(stub_info);

#[cfg(test)]
mod tests {
    use pyo3::Python;

    #[test]
    fn init_logging_is_idempotent() {
        Python::initialize();
        super::init_logging();
        super::init_logging();
    }
}
