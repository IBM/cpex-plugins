# Secrets Detection (Rust)

Rust-backed secrets detection and redaction for ContextForge and MCP Gateway.

## Features

- Detects likely credentials in prompt arguments, tool inputs, tool outputs, and resource content
- Built-in detectors for AWS keys, Google API keys, GitHub tokens, Stripe keys, Slack tokens, and private key blocks
- Optional broad detectors for generic API key assignments, JWT-like strings, long hex strings, and base64-like secrets
- Blocking, redaction, or metadata-only reporting modes
- Recursive scanning for nested dicts, lists, tuples, Pydantic-style objects, `__dict__`, and `__slots__`
- Sanitized outward metadata that reports finding types and counts, not original secret values

## Build

```bash
make install
```

## Runtime Requirements

This plugin depends on `cpex>=0.1.0,<0.2` and imports hook models from `cpex.framework`. The compiled Rust extension is mandatory; there is no Python fallback implementation.

## Usage

The plugin scans these hooks:

- `prompt_pre_fetch`: scans `payload.args`
- `tool_pre_invoke`: scans tool invocation payloads before execution
- `tool_post_invoke`: scans `payload.result`
- `resource_post_fetch`: scans `payload.content.text`

Typical uses:

- block requests that contain likely credentials before they reach tools or prompts
- redact secrets from returned tool or resource payloads
- surface sanitized findings metadata for observability and tuning

## Detection Coverage

Enabled by default:

- `aws_access_key_id`
- `aws_secret_access_key`
- `google_api_key`
- `github_token`
- `stripe_secret_key`
- `slack_token`
- `private_key_block`

Disabled by default because they are broader and more false-positive-prone:

- `generic_api_key_assignment`
- `jwt_like`
- `hex_secret_32`
- `base64_24`

The detectors are regex-based. They do not verify whether a credential is real, active, or revoked.

## Configuration

```yaml
config:
  enabled:
    aws_access_key_id: true
    aws_secret_access_key: true
    google_api_key: true
    github_token: true
    stripe_secret_key: true
    slack_token: true
    private_key_block: true
    generic_api_key_assignment: false
    jwt_like: false
    hex_secret_32: false
    base64_24: false
  redact: false
  redaction_text: "***REDACTED***"
  block_on_detection: true
  min_findings_to_block: 1
```

| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | dict | built-in defaults | Per-detector enable flags; unspecified detectors inherit defaults |
| `redact` | bool | `false` | Replace matched secret values in returned payloads |
| `redaction_text` | string | `"***REDACTED***"` | Replacement text used when `redact=true` |
| `block_on_detection` | bool | `true` | Return a violation when enough findings are present |
| `min_findings_to_block` | integer | `1` | Minimum finding count required before blocking |

## Behavior Notes

- Redaction preserves payload shape where possible instead of flattening everything to plain dicts.
- `base64_24` uses capture-group redaction so leading non-base64 boundary characters are preserved.
- Broad detectors remain opt-in to reduce noisy matches on ordinary identifiers.
- Binary resource bodies are not scanned; `resource_post_fetch` only scans text content exposed as `payload.content.text`.
- The plugin does not decode archives, compressed data, or arbitrary encoded blobs before scanning.

## Returned Metadata

When detections occur, the plugin can emit:

- `metadata.count`
- `metadata.secrets_redacted=true` when redaction happened
- `metadata.secrets_findings=[{"type": "..."}]` when reporting findings without redaction

Blocking responses use the `SECRETS_DETECTED` violation code.

## Security Notes

- Outward-facing findings metadata and violation examples do not include original matched secret values.
- Enable broad detectors only after testing against representative payloads.
- The detector is best-effort pattern matching and should complement, not replace, upstream secret management controls.

## Testing

```bash
make ci
```
