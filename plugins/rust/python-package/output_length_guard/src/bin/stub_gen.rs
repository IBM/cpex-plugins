// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
//
// Stub generator binary for output_length_guard

#[cfg(feature = "stub-gen")]
fn main() {
    use output_length_guard_rust::stub_info;
    use pyo3_stub_gen::generate;

    let stub = stub_info();
    generate(&stub).unwrap();
}

#[cfg(not(feature = "stub-gen"))]
fn main() {
    panic!("stub-gen feature is required");
}
