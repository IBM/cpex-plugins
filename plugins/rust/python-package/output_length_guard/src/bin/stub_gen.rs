// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 ContextForge Contributors
use pyo3_stub_gen::Result;

fn main() -> Result<()> {
    let stub = output_length_guard_rust::stub_info()?;
    stub.generate()?;
    Ok(())
}
