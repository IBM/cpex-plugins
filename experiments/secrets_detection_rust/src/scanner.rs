// Copyright 2026
// SPDX-License-Identifier: Apache-2.0

use serde_json::{Map, Value};

use crate::config::SecretsDetectionConfig;
use crate::patterns::{CAPTURE_PATTERNS, PATTERNS};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub pii_type: String,
    pub preview: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanReport {
    pub count: usize,
    pub redacted: Value,
    pub findings: Vec<Finding>,
}

struct MatchCandidate<'a> {
    name: &'static str,
    start: usize,
    end: usize,
    text: &'a str,
}

pub fn scan_json_value(value: &Value, config: &SecretsDetectionConfig) -> ScanReport {
    let mut path = Vec::new();
    scan_json_value_inner(value, config, &mut path, true)
}

pub fn scan_direct_text(text: &str, config: &SecretsDetectionConfig) -> ScanReport {
    let (findings, redacted) = detect_and_redact(text, config);
    ScanReport {
        count: findings.len(),
        redacted: Value::String(redacted),
        findings,
    }
}

pub fn detect_and_redact(text: &str, config: &SecretsDetectionConfig) -> (Vec<Finding>, String) {
    let mut candidates = Vec::new();

    for (name, pattern) in PATTERNS.iter() {
        if !config.is_enabled(name) {
            continue;
        }

        if CAPTURE_PATTERNS.contains(name) {
            for captures in pattern.captures_iter(text) {
                let Some(matched) = captures.get(1) else {
                    continue;
                };
                if is_base64_boundary_char(text[matched.end()..].chars().next()) {
                    continue;
                }
                candidates.push(MatchCandidate {
                    name,
                    start: matched.start(),
                    end: matched.end(),
                    text: matched.as_str(),
                });
            }
        } else {
            for matched in pattern.find_iter(text) {
                candidates.push(MatchCandidate {
                    name,
                    start: matched.start(),
                    end: matched.end(),
                    text: matched.as_str(),
                });
            }
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
                format!("{}...", matched.text.chars().take(8).collect::<String>())
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

fn scan_json_value_inner(
    value: &Value,
    config: &SecretsDetectionConfig,
    path: &mut Vec<String>,
    direct_scalar_root: bool,
) -> ScanReport {
    match value {
        Value::String(text) => {
            if !config.should_scan_field_path(path, direct_scalar_root) {
                return clean_report(value);
            }
            let (findings, redacted) = detect_and_redact(text, config);
            ScanReport {
                count: findings.len(),
                redacted: Value::String(redacted),
                findings,
            }
        }
        Value::Array(items) => {
            if !config.should_traverse_field_path(path) {
                return clean_report(value);
            }
            let mut total = 0usize;
            let mut redacted_items = Vec::with_capacity(items.len());
            let mut findings = Vec::new();

            for item in items {
                let mut child = scan_json_value_inner(item, config, path, false);
                total += child.count;
                redacted_items.push(child.redacted);
                findings.append(&mut child.findings);
            }

            ScanReport {
                count: total,
                redacted: Value::Array(redacted_items),
                findings,
            }
        }
        Value::Object(entries) => {
            if !config.should_traverse_field_path(path) {
                return clean_report(value);
            }
            let mut total = 0usize;
            let mut redacted_entries = Map::with_capacity(entries.len());
            let mut findings = Vec::new();

            for (key, value) in entries {
                path.push(key.clone());
                let mut child = scan_json_value_inner(value, config, path, false);
                path.pop();
                total += child.count;
                redacted_entries.insert(key.clone(), child.redacted);
                findings.append(&mut child.findings);
            }

            ScanReport {
                count: total,
                redacted: Value::Object(redacted_entries),
                findings,
            }
        }
        _ => clean_report(value),
    }
}

fn clean_report(value: &Value) -> ScanReport {
    ScanReport {
        count: 0,
        redacted: value.clone(),
        findings: Vec::new(),
    }
}

fn pattern_specificity(name: &str) -> usize {
    match name {
        "generic_api_key_assignment" | "jwt_like" => 1,
        "hex_secret_32" => 2,
        "base64_24" => 3,
        _ => 0,
    }
}

fn is_base64_boundary_char(ch: Option<char>) -> bool {
    ch.is_some_and(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '+' | '/' | '='))
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};

    use serde_json::json;

    use super::*;
    use crate::config::FieldPath;

    const SECRET_FIXTURE: &str = "FAKESecretAccessKeyForTestingEXAMPLE0000";

    #[test]
    fn detects_aws_secret_access_key() {
        let config = SecretsDetectionConfig::default();
        let (findings, _) = detect_and_redact(
            "AWS_SECRET_ACCESS_KEY=FAKESecretAccessKeyForTestingEXAMPLE0000",
            &config,
        );
        assert!(findings
            .iter()
            .any(|finding| finding.pii_type == "aws_secret_access_key"));
    }

    #[test]
    fn detects_aws_secret_access_key_assignment_formats() {
        let config = SecretsDetectionConfig {
            redact: true,
            redaction_text: "[REDACTED]".to_string(),
            ..Default::default()
        };

        let cases = [
            (
                "equals-unquoted",
                format!("AWS_SECRET_ACCESS_KEY={SECRET_FIXTURE}"),
            ),
            (
                "equals-double-quoted",
                format!("aws_secret_access_key = \"{SECRET_FIXTURE}\""),
            ),
            (
                "equals-single-quoted",
                format!("aws_secret_access_key = '{SECRET_FIXTURE}'"),
            ),
            (
                "yaml-unquoted",
                format!("aws_secret_access_key: {SECRET_FIXTURE}"),
            ),
            (
                "yaml-double-quoted",
                format!("aws_secret_access_key: \"{SECRET_FIXTURE}\""),
            ),
            (
                "yaml-single-quoted",
                format!("aws_secret_access_key: '{SECRET_FIXTURE}'"),
            ),
            (
                "json-spaced",
                format!(r#""aws_secret_access_key": "{SECRET_FIXTURE}""#),
            ),
            (
                "json-compact",
                format!(r#""aws_secret_access_key":"{SECRET_FIXTURE}""#),
            ),
            (
                "mixed-case",
                format!("AwsSecretAccessKey: \"{SECRET_FIXTURE}\""),
            ),
        ];

        for (name, text) in cases {
            let (findings, redacted) = detect_and_redact(&text, &config);

            assert_eq!(findings.len(), 1, "{name}: {findings:?}");
            assert_eq!(findings[0].pii_type, "aws_secret_access_key", "{name}");
            assert!(!redacted.contains(SECRET_FIXTURE), "{name}: {redacted}");
            assert!(
                redacted.contains(&config.redaction_text),
                "{name}: {redacted}"
            );
        }
    }

    #[test]
    fn redaction_works() {
        let config = SecretsDetectionConfig {
            redact: true,
            redaction_text: "[REDACTED]".to_string(),
            ..Default::default()
        };
        let (findings, redacted) =
            detect_and_redact("AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE", &config);
        assert_eq!(findings.len(), 1);
        assert_eq!(redacted, "AWS_ACCESS_KEY_ID=[REDACTED]");
    }

    #[test]
    fn redacts_each_supported_secret_as_one_replacement_with_all_patterns_enabled() {
        let config = SecretsDetectionConfig {
            enabled: crate::patterns::PATTERNS
                .keys()
                .map(|&name| (name.to_string(), true))
                .collect(),
            redact: true,
            redaction_text: "[TESTING-REDACTED]".to_string(),
            ..Default::default()
        };

        for (name, secret) in [
            ("aws_access_key_id", "AKIAFAKE12345EXAMPLE".to_string()),
            (
                "aws_secret_access_key",
                "AWS_SECRET_ACCESS_KEY=FAKESecretAccessKeyForTestingEXAMPLE0000".to_string(),
            ),
            (
                "google_api_key",
                "AIzaAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
            ),
            (
                "github_token",
                "ghp_abcdefghijklmnopqrstuvwxyz0123456789".to_string(),
            ),
            (
                "stripe_secret_key",
                "sk_test_abcdefghijklmnopqrstuvwxyz".to_string(),
            ),
            (
                "generic_api_key_assignment",
                "api_key=test12345678901234567890".to_string(),
            ),
            (
                "slack_token",
                [
                    "xoxb",
                    "123456789012",
                    "123456789012",
                    "abcdefghijklmnopqrstuvwx",
                ]
                .join("-"),
            ),
            (
                "private_key_block",
                "-----BEGIN RSA PRIVATE KEY-----".to_string(),
            ),
            (
                "jwt_like",
                "eyJaaaaaaaaaaa.eyJbbbbbbbbbbb.cccccccccccccc".to_string(),
            ),
            (
                "hex_secret_32",
                "0123456789abcdef0123456789abcdef".to_string(),
            ),
            ("base64_24", "QUJDREVGR0hJSktMTU5PUFFSU1RVVldY".to_string()),
        ] {
            let (findings, redacted) = detect_and_redact(&secret, &config);
            assert_eq!(findings.len(), 1, "{name}: {findings:?}");
            assert_eq!(findings[0].pii_type, name, "{name}: {findings:?}");
            assert_eq!(redacted, config.redaction_text, "{name}");
        }
    }

    #[test]
    fn overlapping_broad_match_keeps_specific_finding_type() {
        let config = SecretsDetectionConfig {
            enabled: crate::patterns::PATTERNS
                .keys()
                .map(|&name| (name.to_string(), true))
                .collect(),
            redact: true,
            redaction_text: "[TESTING-REDACTED]".to_string(),
            ..Default::default()
        };
        let secret = "AIzaAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/BBBBBBBB";

        let (findings, redacted) = detect_and_redact(secret, &config);

        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].pii_type, "google_api_key", "{findings:?}");
        assert_eq!(redacted, config.redaction_text);
    }

    #[test]
    fn json_scan_handles_nested_structures() {
        let redact_config = SecretsDetectionConfig {
            redact: true,
            redaction_text: "[REDACTED]".to_string(),
            ..Default::default()
        };
        let value = json!({
            "users": [
                {
                    "name": "Alice",
                    "key": "AKIAFAKE12345EXAMPLE"
                },
                {
                    "name": "Bob",
                    "token": "xoxr-fake-000000000-fake000000000-fakefakefakefake"
                }
            ]
        });

        let report = scan_json_value(&value, &redact_config);

        assert_eq!(report.count, 2);
        assert_eq!(
            report.redacted,
            json!({
                "users": [
                    {
                        "name": "Alice",
                        "key": "[REDACTED]"
                    },
                    {
                        "name": "Bob",
                        "token": "[REDACTED]"
                    }
                ]
            })
        );
        assert_eq!(report.findings.len(), 2);
        let finding_types: HashSet<_> = report
            .findings
            .iter()
            .map(|finding| finding.pii_type.as_str())
            .collect();
        assert_eq!(
            finding_types,
            HashSet::from(["aws_access_key_id", "slack_token"])
        );
    }

    #[test]
    fn field_filters_apply_to_json_objects() {
        let payload = json!({
            "layer1": {
                "public": "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE",
                "layer2": {
                    "layer3": "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"
                }
            },
            "layer10": "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"
        });

        let config = config_with_field_filters(&["layer1"], &["layer1.layer2.layer3"], true);
        let report = scan_json_value(&payload, &config);

        assert_eq!(report.count, 1);
        assert_eq!(
            report.redacted["layer1"]["public"],
            json!("AWS_ACCESS_KEY_ID=[REDACTED]")
        );
        assert_eq!(
            report.redacted["layer1"]["layer2"]["layer3"],
            json!("AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE")
        );
        assert_eq!(
            report.redacted["layer10"],
            json!("AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE")
        );
    }

    #[test]
    fn field_filters_reach_nested_allowlisted_paths_through_lists() {
        let payload = json!({
            "users": [
                {
                    "credentials": {
                        "token": "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE",
                        "other": "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"
                    }
                },
                {
                    "credentials": {
                        "token": "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"
                    }
                }
            ],
            "outside": "AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE"
        });

        let config = config_with_field_filters(&["users.credentials.token"], &[], true);
        let report = scan_json_value(&payload, &config);

        assert_eq!(report.count, 2);
        assert_eq!(
            report.redacted["users"][0]["credentials"]["token"],
            json!("AWS_ACCESS_KEY_ID=[REDACTED]")
        );
        assert_eq!(
            report.redacted["users"][0]["credentials"]["other"],
            json!("AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE")
        );
        assert_eq!(
            report.redacted["users"][1]["credentials"]["token"],
            json!("AWS_ACCESS_KEY_ID=[REDACTED]")
        );
        assert_eq!(
            report.redacted["outside"],
            json!("AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE")
        );
    }

    #[test]
    fn generic_api_key_assignment_detection_is_opt_in() {
        let config = SecretsDetectionConfig {
            enabled: HashMap::from([("generic_api_key_assignment".to_string(), true)]),
            ..Default::default()
        };
        let (findings, _) = detect_and_redact("X-API-Key: test12345678901234567890", &config);
        assert!(findings
            .iter()
            .any(|finding| finding.pii_type == "generic_api_key_assignment"));
    }

    #[test]
    fn broad_patterns_are_opt_in() {
        let config = SecretsDetectionConfig {
            redact: true,
            ..Default::default()
        };
        let (findings, redacted) =
            detect_and_redact("access_token = 'abcdefghijklmnopqrstuvwx'", &config);
        assert!(findings.is_empty());
        assert_eq!(redacted, "access_token = 'abcdefghijklmnopqrstuvwx'");
    }

    #[test]
    fn redacts_padded_base64_secret_without_leaving_padding() {
        let config = SecretsDetectionConfig {
            enabled: HashMap::from([("base64_24".to_string(), true)]),
            redact: true,
            redaction_text: "[REDACTED]".to_string(),
            ..Default::default()
        };

        let sample = "mZ8qL2vYwT1pNc4Rb6HxUg==";
        let (findings, redacted) = detect_and_redact(&format!("token={sample}"), &config);

        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].pii_type, "base64_24");
        assert_eq!(redacted, "token=[REDACTED]");
    }

    fn config_with_field_filters(
        allowlist: &[&str],
        denylist: &[&str],
        redact: bool,
    ) -> SecretsDetectionConfig {
        SecretsDetectionConfig {
            redact,
            redaction_text: "[REDACTED]".to_string(),
            field_allowlist: allowlist
                .iter()
                .map(|path| FieldPath::parse((*path).to_string(), "field_allowlist").unwrap())
                .collect(),
            field_denylist: denylist
                .iter()
                .map(|path| FieldPath::parse((*path).to_string(), "field_denylist").unwrap())
                .collect(),
            ..Default::default()
        }
    }
}
