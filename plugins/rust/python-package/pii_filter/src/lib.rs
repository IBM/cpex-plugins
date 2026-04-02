// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
//
// PII Filter Plugin - Rust Implementation
//
// High-performance PII detection and masking using:
// - RegexSet for parallel pattern matching (5-10x faster)
// - Copy-on-write strings for zero-copy operations
// - Zero-copy JSON traversal with serde_json

use std::sync::Once;

use log::debug;
use pyo3::prelude::*;
use pyo3_stub_gen::define_stub_info_gatherer;

pub mod config;
pub mod detector;
pub mod masking;
pub mod patterns;
pub mod plugin;

pub use detector::PIIDetectorRust;

fn init_logging() {
    static INIT: Once = Once::new();

    INIT.call_once(|| {
        pyo3_log::init();
    });
}

/// Python module definition
#[pymodule]
fn pii_filter_rust(m: &Bound<'_, PyModule>) -> PyResult<()> {
    init_logging();
    debug!("Initialized pii_filter Rust module");
    m.add_class::<PIIDetectorRust>()?;
    m.add_class::<plugin::PIIFilterPluginCore>()?;
    Ok(())
}

// Define stub info gatherer for generating Python type stubs
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
