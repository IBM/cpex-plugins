// Copyright 2026
// SPDX-License-Identifier: Apache-2.0

use regex::Regex;
use std::collections::HashMap;
use std::sync::LazyLock;

pub static PATTERNS: LazyLock<HashMap<&'static str, Regex>> = LazyLock::new(|| {
    let mut patterns = HashMap::new();
    patterns.insert(
        "aws_access_key_id",
        Regex::new(r"\bAKIA[0-9A-Z]{16}\b").expect("valid aws_access_key_id regex"),
    );
    patterns.insert(
        "aws_secret_access_key",
        Regex::new(r"(?i)aws.{0,20}(?:secret|access).{0,20}=\s*([A-Za-z0-9/+=]{40})")
            .expect("valid aws_secret_access_key regex"),
    );
    patterns.insert(
        "google_api_key",
        Regex::new(r"\bAIza[0-9A-Za-z\-_]{35}\b").expect("valid google_api_key regex"),
    );
    patterns.insert(
        "github_token",
        Regex::new(r"\b(?:gh[opusr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{20,})\b")
            .expect("valid github_token regex"),
    );
    patterns.insert(
        "stripe_secret_key",
        Regex::new(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b")
            .expect("valid stripe_secret_key regex"),
    );
    patterns.insert(
        "generic_api_key_assignment",
        Regex::new(
            r#"(?ix)\b(?:(?:x[-_])?api[-_]?key|apikey|api[_-]?token|access[_-]?token|bearer[_-]?token|auth[_-]?token)\b\s*[:=]\s*['"]?[A-Za-z0-9_\-]{20,}['"]?"#,
        )
        .expect("valid generic_api_key_assignment regex"),
    );
    patterns.insert(
        "slack_token",
        // Slack documents token prefixes such as `xoxb-` and warns that token
        // lengths are not fixed:
        // https://docs.slack.dev/changelog/2016/08/23/token-lengthening/
        Regex::new(r"\bxox[abpqr]-[0-9A-Za-z\-]{10,80}\b").expect("valid slack_token regex"),
    );
    patterns.insert(
        "private_key_block",
        Regex::new(r"-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----")
            .expect("valid private_key_block regex"),
    );
    patterns.insert(
        "jwt_like",
        Regex::new(r"\beyJ[a-zA-Z0-9_\-]{10,}\.eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\b")
            .expect("valid jwt_like regex"),
    );
    patterns.insert(
        "hex_secret_32",
        Regex::new(r"(?i)\b[a-f0-9]{32,}\b").expect("valid hex_secret_32 regex"),
    );
    patterns.insert(
        "base64_24",
        Regex::new(r"\b[A-Za-z0-9+/]{24,}={0,2}\b").expect("valid base64_24 regex"),
    );
    patterns
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_all_patterns() {
        assert_eq!(PATTERNS.len(), 11);
        assert!(PATTERNS.contains_key("aws_access_key_id"));
        assert!(PATTERNS.contains_key("generic_api_key_assignment"));
    }
}
