// Copyright 2026
// SPDX-License-Identifier: Apache-2.0

use pyo3::prelude::*;

#[pymodule]
fn url_reputation_rust(_m: &Bound<'_, PyModule>) -> PyResult<()> {
    pyo3_log::init();
    Ok(())
}
