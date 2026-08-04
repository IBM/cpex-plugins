use std::mem::discriminant;

// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
//
// Configuration for output length guard plugin
use pyo3::prelude::*;
use pyo3::types::PyDict;
pub struct OutputLengthGuardConfig {
    pub min_chars: u32,
    pub max_chars: Option<u32>,
    pub min_tokens: u32,
    pub max_tokens: Option<u32>,
    pub chars_per_token: Option<u8>,
    pub limit_mode: LimitMode,
    pub strategy: Strategy,
    pub ellipsis: String,
    pub word_boundary: bool,
    pub max_text_length: Option<u32>,
    pub max_structure_size: Option<u16>,
    pub max_recursion_depth: Option<u8>,
}

pub enum LimitMode {
    Character,
    Token,
}
pub enum Strategy {
    Truncate,
    Block,
}

impl Default for OutputLengthGuardConfig {
    fn default() -> Self {
        Self {
            min_chars: 0,
            max_chars: None,
            min_tokens: 0,
            max_tokens: None,
            chars_per_token: None,
            limit_mode: LimitMode::Character,
            strategy: Strategy::Truncate,
            ellipsis: String::from("..."),
            word_boundary: false,
            max_recursion_depth: None,
            max_structure_size: None,
            max_text_length: None,
        }
    }
}

impl OutputLengthGuardConfig {
    pub fn from_py_dict(py_config: &Bound<'_, PyDict>) -> PyResult<Self> {
        let mut config: OutputLengthGuardConfig = Self::default();
        return Ok(config);
    }
}
