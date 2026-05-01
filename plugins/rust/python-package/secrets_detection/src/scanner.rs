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
    fn detects_slack_tokens_around_legacy_length_boundary() {
        let config = SecretsDetectionConfig::default();
        for body_len in [48, 49] {
            let token = format!("{}{}", "xoxb-", "a".repeat(body_len));
            let (findings, redacted) = detect_and_redact(&token, &config);

            assert!(
                findings
                    .iter()
                    .any(|finding| finding.pii_type == "slack_token"),
                "{body_len}: {findings:?}"
            );
            assert_eq!(redacted, token);
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
