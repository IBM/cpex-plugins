// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
//
// Output Length Guard Plugin - Rust Implementation

use std::sync::Once;

use log::debug;
use pyo3::prelude::*;
#[cfg(feature = "stub-gen")]
use pyo3_stub_gen::define_stub_info_gatherer;

pub mod config;
pub mod guards;
pub mod plugin;
pub mod structured;

pub use plugin::OutputLengthGuardPluginCore;

fn init_logging() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        pyo3_log::init();
    });
}

/// Python module definition
#[pymodule]
fn output_length_guard_rust(m: &Bound<'_, PyModule>) -> PyResult<()> {
    init_logging();
    debug!("Initialized output_length_guard Rust module");
    m.add_class::<OutputLengthGuardPluginCore>()?;
    Ok(())
}

#[cfg(feature = "stub-gen")]
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
