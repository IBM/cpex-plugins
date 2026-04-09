// Copyright 2026
// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::Path;

use retry_with_backoff_rust::stub_info;

fn trim_trailing_blank_lines(path: &str) {
    let stub_path = Path::new(path);
    let content = fs::read_to_string(stub_path).expect("Failed to read generated stub file");
    let content = content.trim_end().to_string() + "\n";
    fs::write(stub_path, content).expect("Failed to write curated stub file");
}

fn main() {
    let stub_info = stub_info().expect("Failed to get stub info");
    stub_info.generate().expect("Failed to generate stub file");
    trim_trailing_blank_lines("cpex_retry_with_backoff/__init__.pyi");
    trim_trailing_blank_lines("cpex_retry_with_backoff/retry_with_backoff_rust/__init__.pyi");
    println!("Generated stub files successfully");
}
