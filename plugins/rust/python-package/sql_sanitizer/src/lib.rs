// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
//
// SQL Sanitizer Plugin — Rust Implementation
//
// High-performance SQL analysis using:
// - Per-statement splitting to avoid WHERE-clause false-negatives
// - Lazy-compiled static Regex instances for zero-cost repeat matching
// - PyO3 bridging with zero-copy string extraction

use std::sync::Once;

use log::debug;
use pyo3::prelude::*;
#[cfg(feature = "stub-gen")]
use pyo3_stub_gen::define_stub_info_gatherer;

pub mod comments;
pub mod config;
pub mod issues;
pub mod plugin;
pub mod scanner;

fn init_logging() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        pyo3_log::init();
    });
}

/// Python module definition
#[pymodule]
fn sql_sanitizer_rust(m: &Bound<'_, PyModule>) -> PyResult<()> {
    init_logging();
    debug!("Initialized sql_sanitizer Rust module");
    m.add_class::<plugin::SqlSanitizerPluginCore>()?;
    Ok(())
}

#[cfg(feature = "stub-gen")]
define_stub_info_gatherer!(stub_info);
