// Copyright 2026
// SPDX-License-Identifier: Apache-2.0

#[cfg(test)]
use serde_json::{Map, Value};

#[cfg(test)]
use crate::config::SecretsDetectionConfig;

mod cycle_rewrite;
mod python_scan;
mod text_scan;

pub use python_scan::scan_container;
pub use text_scan::detect_and_redact;

#[cfg(test)]
use text_scan::Finding;

#[cfg(test)]
fn scan_value(value: &Value, config: &SecretsDetectionConfig) -> (usize, Value, Vec<Finding>) {
    match value {
        Value::String(text) => {
            let (matches, redacted) = detect_and_redact(text, config);
            (matches.len(), Value::String(redacted), matches)
        }
        Value::Array(items) => {
            let mut total = 0usize;
            let mut redacted_items = Vec::with_capacity(items.len());
            let mut findings = Vec::new();

            for item in items {
                let (count, redacted_item, mut child_findings) = scan_value(item, config);
                total += count;
                redacted_items.push(redacted_item);
                findings.append(&mut child_findings);
            }

            (total, Value::Array(redacted_items), findings)
        }
        Value::Object(entries) => {
            let mut total = 0usize;
            let mut redacted_entries = Map::with_capacity(entries.len());
            let mut findings = Vec::new();

            for (key, value) in entries {
                let (count, redacted_value, mut child_findings) = scan_value(value, config);
                total += count;
                redacted_entries.insert(key.clone(), redacted_value);
                findings.append(&mut child_findings);
            }

            (total, Value::Object(redacted_entries), findings)
        }
        _ => (0, value.clone(), Vec::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_aws_secret_access_key() {
        let config = SecretsDetectionConfig::default();
        let (findings, _) = detect_and_redact(
            "AWS_SECRET_ACCESS_KEY=FAKESecretAccessKeyForTestingEXAMPLE0000",
            &config,
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.pii_type == "aws_secret_access_key")
        );
    }

    #[test]
    fn detects_slack_token() {
        let config = SecretsDetectionConfig::default();
        let (findings, _) = detect_and_redact(
            "xoxr-fake-000000000-fake000000000-fakefakefakefake",
            &config,
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.pii_type == "slack_token")
        );
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
    fn handles_nested_structures() {
        let redact_config = SecretsDetectionConfig {
            redact: true,
            redaction_text: "[REDACTED]".to_string(),
            ..SecretsDetectionConfig::default()
        };
        let value = Value::Object(Map::from_iter([(
            "users".to_string(),
            Value::Array(vec![
                Value::Object(Map::from_iter([
                    ("name".to_string(), Value::String("Alice".to_string())),
                    (
                        "key".to_string(),
                        Value::String("AKIAFAKE12345EXAMPLE".to_string()),
                    ),
                ])),
                Value::Object(Map::from_iter([
                    ("name".to_string(), Value::String("Bob".to_string())),
                    (
                        "token".to_string(),
                        Value::String(
                            "xoxr-fake-000000000-fake000000000-fakefakefakefake".to_string(),
                        ),
                    ),
                ])),
            ]),
        )]));

        let (count, redacted, findings) = scan_value(&value, &redact_config);

        assert_eq!(count, 2);
        assert_eq!(
            redacted,
            Value::Object(Map::from_iter([(
                "users".to_string(),
                Value::Array(vec![
                    Value::Object(Map::from_iter([
                        ("name".to_string(), Value::String("Alice".to_string())),
                        ("key".to_string(), Value::String("[REDACTED]".to_string())),
                    ])),
                    Value::Object(Map::from_iter([
                        ("name".to_string(), Value::String("Bob".to_string())),
                        ("token".to_string(), Value::String("[REDACTED]".to_string())),
                    ])),
                ]),
            )]))
        );
        assert_eq!(findings.len(), 2);
        let finding_types: std::collections::HashSet<_> = findings
            .iter()
            .map(|finding| finding.pii_type.as_str())
            .collect();
        assert_eq!(
            finding_types,
            std::collections::HashSet::from(["aws_access_key_id", "slack_token"])
        );
    }

    #[test]
    fn generic_api_key_assignment_detection_is_opt_in() {
        let config = SecretsDetectionConfig {
            enabled: std::collections::HashMap::from([(
                "generic_api_key_assignment".to_string(),
                true,
            )]),
            ..Default::default()
        };
        let (findings, _) = detect_and_redact("X-API-Key: test12345678901234567890", &config);
        assert!(
            findings
                .iter()
                .any(|finding| finding.pii_type == "generic_api_key_assignment")
        );
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
    fn generic_api_key_assignment_ignores_short_or_prose_values() {
        let config = SecretsDetectionConfig {
            enabled: std::collections::HashMap::from([(
                "generic_api_key_assignment".to_string(),
                true,
            )]),
            ..Default::default()
        };

        for text in [
            "api_key=short",
            "api key rotation is enabled",
            "The api_key field is documented below",
        ] {
            let (findings, _) = detect_and_redact(text, &config);
            assert!(
                findings
                    .iter()
                    .all(|finding| finding.pii_type != "generic_api_key_assignment"),
                "{text}"
            );
        }
    }
}
