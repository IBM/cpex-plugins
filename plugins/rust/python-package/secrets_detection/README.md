# cpex-secrets-detection

Rust-backed secrets detection plugin for MCP Gateway / CPEX.

## What it does

This plugin scans hook payloads for likely secrets and can either:

- block processing when a secret is found
- redact matched values in the returned payload
- attach findings metadata to the hook result

Supported hooks:

- `prompt_pre_fetch`: scans `payload.args`
- `tool_post_invoke`: scans `payload.result`
- `resource_post_fetch`: scans `payload.content.text`

It walks nested values, not just top-level strings. Coverage includes:

- plain strings
- `dict`
- `list`
- `tuple`
- custom Python objects with `__dict__`
- slot-based objects with `__slots__`
- Pydantic-style objects that expose `model_dump()` and `model_copy()`

When redaction is enabled, the plugin preserves payload shape as much as possible instead of flattening everything to plain dicts.

## Exact detector coverage

The plugin ships these regex-based detectors:

- `aws_access_key_id`
- `aws_secret_access_key`
- `google_api_key`
- `github_token`
- `stripe_secret_key`
- `slack_token`
- `private_key_block`
- `generic_api_key_assignment`
- `jwt_like`
- `hex_secret_32`
- `base64_24`

Default behavior:

- enabled by default:
  - `aws_access_key_id`
  - `aws_secret_access_key`
  - `google_api_key`
  - `github_token`
  - `stripe_secret_key`
  - `slack_token`
  - `private_key_block`
- disabled by default because they are broader and more false-positive-prone:
  - `generic_api_key_assignment`
  - `jwt_like`
  - `hex_secret_32`
  - `base64_24`

## What it does not do

This plugin is intentionally narrow. It does not:

- verify whether a matched credential is real, active, or revoked
- call external services
- decode or unpack data before scanning
  - no base64 decode pass
  - no hex decode pass
  - no gzip, zip, or archive inspection
- scan binary resource bodies
  - `resource_post_fetch` only scans `content.text`
- inspect arbitrary object internals unless they are exposed through supported Python state surfaces such as `model_dump()`, `__dict__`, or `__slots__`
- guarantee detection of every secret format
  - coverage is limited to the listed regex patterns
- use entropy scoring, ML classification, or semantic analysis
- infer secret validity from surrounding prose

It also does not emit the original matched secret in outward-facing findings metadata or violation examples. Those surfaces contain secret types only.

## Config

Available config keys:

- `enabled`: map of detector name to `true` or `false`
- `redact`: whether to replace matches in returned payloads
- `redaction_text`: replacement text used when `redact=true`
- `block_on_detection`: whether to stop processing on detection
- `min_findings_to_block`: threshold for blocking

Defaults:

```yaml
enabled:
  aws_access_key_id: true
  aws_secret_access_key: true
  google_api_key: true
  github_token: true
  stripe_secret_key: true
  generic_api_key_assignment: false
  slack_token: true
  private_key_block: true
  jwt_like: false
  hex_secret_32: false
  base64_24: false
redact: false
redaction_text: "***REDACTED***"
block_on_detection: true
min_findings_to_block: 1
```

## Result shape

On detection, the plugin may return:

- `modified_payload` with redacted values when `redact=true`
- `metadata.count`
- `metadata.secrets_redacted=true` when redaction happened
- `metadata.secrets_findings=[{"type": "..."}]` when reporting findings without redaction
- a `PluginViolation` with `code="SECRETS_DETECTED"` when blocking

## Build

```bash
uv sync --dev
make install
make test-all
```
