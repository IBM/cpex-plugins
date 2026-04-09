# Secrets Detection (Rust)

High-performance secrets detection and redaction for ContextForge and MCP Gateway.

## Features

- Rust-owned recursive scanning for strings, dicts, lists, and MCP payload containers
- Built-in detection for high-signal credential formats such as AWS access keys and Slack tokens
- Optional redaction or hard blocking on detection
- Hook coverage for prompt input, tool output, and fetched resource content
- Opt-in broad patterns for lower-confidence generic token assignments
- Structured findings metadata with redacted match previews

## Build

```bash
make install
```

## Usage

The plugin scans data at these hook points:

- `prompt_pre_fetch`
- `tool_post_invoke`
- `resource_post_fetch`

Typical uses:

- redact secrets before they leave the gateway
- block tool or resource payloads that contain leaked credentials
- add lightweight findings metadata for downstream auditing

## Configuration

Key settings include:

- `redact`: replace detected secret values in the payload
- `redaction_text`: replacement string for detected values
- `block_on_detection`: stop processing instead of modifying payloads
- `min_findings_to_block`: threshold before hard blocking
- `enabled`: enable optional lower-confidence detectors when needed

## Detection Notes

- High-signal built-in patterns are enabled by default.
- Broader generic assignment-style patterns are opt-in to avoid noisy false positives.
- Findings include secret type labels such as `aws_access_key_id` or `slack_token`.
- Redaction preserves surrounding structure when possible, for example replacing only the secret value inside a larger assignment string.

## Returned Metadata

When detections occur, the plugin can return metadata such as:

- `count`
- `secrets_redacted`

Blocking responses use the `SECRETS_DETECTED` violation code.

## Testing

```bash
make ci
```

## Security Notes

- Default detectors are intentionally biased toward high-confidence secret formats.
- Broad token-like patterns should only be enabled when your environment benefits from higher recall and can tolerate extra review.
