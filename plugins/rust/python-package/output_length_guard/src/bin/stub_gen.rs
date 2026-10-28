// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
//
// Stub generator binary for output_length_guard

#[cfg(feature = "stub-gen")]
fn main() {
    use output_length_guard_rust::stub_info;

    let stub = stub_info().expect("Failed to get stub info");
    stub.generate().expect("Failed to generate stub file");
}

#[cfg(not(feature = "stub-gen"))]
fn main() {
    panic!("stub-gen feature is required");
}
