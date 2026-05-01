// Copyright 2026
// SPDX-License-Identifier: Apache-2.0

use crate::config::SecretsDetectionConfig;
use crate::patterns::PATTERNS;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub pii_type: String,
    pub preview: String,
}

struct MatchCandidate<'a> {
    name: &'static str,
    start: usize,
    end: usize,
    text: &'a str,
}

pub fn detect_and_redact(text: &str, config: &SecretsDetectionConfig) -> (Vec<Finding>, String) {
    let mut candidates = Vec::new();

    for (name, pattern) in PATTERNS.iter() {
        if !config.is_enabled(name) {
            continue;
        }

        for matched in pattern.find_iter(text) {
            candidates.push(MatchCandidate {
                name,
                start: matched.start(),
                end: matched.end(),
                text: matched.as_str(),
            });
        }
    }

    candidates.sort_by(|left, right| {
        left.start
            .cmp(&right.start)
            .then_with(|| pattern_specificity(left.name).cmp(&pattern_specificity(right.name)))
            .then_with(|| (right.end - right.start).cmp(&(left.end - left.start)))
            .then_with(|| left.name.cmp(right.name))
    });

    let mut selected = Vec::new();
    for candidate in candidates {
        let Some(current) = selected.last_mut() else {
            selected.push(candidate);
            continue;
        };

        if candidate.start >= current.end {
            selected.push(candidate);
            continue;
        }

        let candidate_specificity = pattern_specificity(candidate.name);
        let current_specificity = pattern_specificity(current.name);
        let candidate_len = candidate.end - candidate.start;
        let current_len = current.end - current.start;
        if candidate_specificity < current_specificity
            || (candidate_specificity == current_specificity && candidate_len > current_len)
        {
            current.name = candidate.name;
            current.text = candidate.text;
        }

        if candidate.end > current.end {
            current.end = candidate.end;
        }
    }

    let findings = selected
        .iter()
        .map(|matched| {
            let preview = if matched.text.chars().count() > 8 {
                format!("{}…", matched.text.chars().take(8).collect::<String>())
            } else {
                matched.text.to_string()
            };
            Finding {
                pii_type: matched.name.to_string(),
                preview,
            }
        })
        .collect::<Vec<_>>();

    let redacted = if config.redact && !selected.is_empty() {
        let mut redacted = String::with_capacity(text.len());
        let mut cursor = 0usize;
        for matched in &selected {
            redacted.push_str(&text[cursor..matched.start]);
            redacted.push_str(&config.redaction_text);
            cursor = matched.end;
        }
        redacted.push_str(&text[cursor..]);
        redacted
    } else {
        text.to_string()
    };

    (findings, redacted)
}

fn pattern_specificity(name: &str) -> usize {
    match name {
        "generic_api_key_assignment" | "jwt_like" => 1,
        "hex_secret_32" => 2,
        "base64_24" => 3,
        _ => 0,
    }
}
