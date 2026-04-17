// Copyright 2026
// SPDX-License-Identifier: Apache-2.0

use crate::config::SecretsDetectionConfig;
use crate::patterns::PATTERNS;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub pii_type: String,
    pub preview: String,
}

pub fn detect_and_redact(text: &str, config: &SecretsDetectionConfig) -> (Vec<Finding>, String) {
    let mut findings = Vec::new();
    let mut redacted = text.to_string();

    for (name, pattern) in PATTERNS.iter() {
        if !config.is_enabled(name) {
            continue;
        }

        let matches = pattern.find_iter(text).collect::<Vec<_>>();
        for matched in &matches {
            let text = matched.as_str();
            let preview = if text.chars().count() > 8 {
                format!("{}…", text.chars().take(8).collect::<String>())
            } else {
                text.to_string()
            };
            findings.push(Finding {
                pii_type: name.to_string(),
                preview,
            });
        }

        if config.redact && !matches.is_empty() {
            redacted = pattern
                .replace_all(&redacted, config.redaction_text.as_str())
                .into_owned();
        }
    }

    (findings, redacted)
}
