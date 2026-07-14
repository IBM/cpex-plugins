# Secrets Detection (Rust)

Rust-backed secrets detection and redaction for ContextForge and MCP Gateway.

## Features

- Detects likely credentials in prompt arguments, tool inputs, tool outputs, and resource content
- Built-in detectors for AWS keys, Google API keys, GitHub tokens, Stripe keys, Slack tokens, and private key blocks
- Optional broad detectors for generic API key assignments, JWT-like strings, long hex strings, and base64-like secrets
- Blocking, redaction, or metadata-only reporting modes
- Recursive scanning for nested dicts, lists, tuples, Pydantic-style objects, `__dict__`, and `__slots__`
- Optional dotted field allowlist and denylist controls for structured payload scanning
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
  field_allowlist: []
  field_denylist: []
```

| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | dict | built-in defaults | Per-detector enable flags; unspecified detectors inherit defaults |
| `redact` | bool | `false` | Replace matched secret values in returned payloads |
| `redaction_text` | string | `"***REDACTED***"` | Replacement text used when `redact=true` |
| `block_on_detection` | bool | `true` | Return a violation when enough findings are present |
| `min_findings_to_block` | integer | `1` | Minimum finding count required before blocking |
| `field_allowlist` | list[string] | `[]` | Dotted field paths eligible for scanning; empty means all structured fields are eligible |
| `field_denylist` | list[string] | `[]` | Dotted field paths excluded from scanning; denylist entries take precedence over allowlist entries |

### Field Filtering

`field_allowlist` and `field_denylist` apply to structured scan targets:

- `prompt_pre_fetch`: paths are relative to `payload.args`
- `tool_pre_invoke`: paths are relative to `payload.args`
- `tool_post_invoke`: paths are relative to `payload.result`

For example, `accounts.credentials.token` matches `payload.args.accounts.credentials.token` in pre-hooks and `payload.result.accounts.credentials.token` in `tool_post_invoke`.

Rules:

- An empty `field_allowlist` scans all structured fields.
- A non-empty `field_allowlist` scans only the listed paths and their descendants.
- A `field_denylist` entry excludes that path and all descendants.
- When both lists match, `field_denylist` wins.
- Parent containers are still traversed to reach nested allowlisted paths.
- Matching is segment-aware: `layer1` does not match `layer10`.
- Lists and tuples are transparent to field matching; numeric indices are not used.
- Mapping keys themselves are not scanned.
- Direct scalar scan targets, including `payload.content.text` in `resource_post_fetch`, retain current behavior and are not filtered by field paths.

Valid field paths use non-empty dot-separated segments. Empty paths, whitespace-only paths, leading or trailing dots, and empty segments such as `layer1..token` are rejected during plugin initialization.

Example:

```yaml
config:
  field_allowlist:
    - "layer1"
    - "accounts.credentials"
  field_denylist:
    - "layer1.layer2.layer3"
    - "accounts.credentials.test_token"
```

## Behavior Notes

- Redaction preserves payload shape where possible instead of flattening everything to plain dicts.
- `aws_secret_access_key` recognizes `=` and `:` assignments with optional single or double quotes around the value.
- `base64_24` uses capture-group redaction so leading non-base64 boundary characters are preserved.
- Broad detectors remain opt-in to reduce noisy matches on ordinary identifiers.
- Binary resource bodies are not scanned; `resource_post_fetch` only scans text content exposed as `payload.content.text`.
- The plugin does not decode archives, compressed data, or arbitrary encoded blobs before scanning.

## Returned Metadata

`prompt_pre_fetch`, `tool_pre_invoke`, `tool_post_invoke`, and `resource_post_fetch` accept an optional `extensions` parameter carrying OpenTelemetry trace context. When a trace context is present (via `extensions.request.trace_id`), the plugin emits operational metrics on `result.metadata["secrets_detection"]` with the following schema:

```python
result.metadata["secrets_detection"] = {
    "total_detections": 2,   # int — total number of findings in this call
    "total_masked": 2,       # int — number redacted (masking action taken)
    "total_blocked": 0,      # int — number that caused a block (blocking action taken)
    "secret_types": ["aws_access_key_id", "slack_token"],  # list[str] — distinct type names, sorted, deduped
}
```

`total_masked` and `total_blocked` are mutually exclusive per call: exactly one of them carries the finding count (the other is `0`), depending on whether the redaction branch or the blocking branch executed. If neither redaction nor blocking is configured, both are `0` and only `total_detections`/`secret_types` are non-zero (findings-only reporting mode).

**Gating:** Metrics are only emitted when a valid `trace_id` is present in the trace context (`extensions.request.trace_id`). No trace context means no `result.metadata` write at all, regardless of any config flag — this keeps the untraced path byte-for-byte identical to before metrics existed.

**Security Note (S1):** The plugin **never includes raw secret values** in `result.metadata`, logs, or any other output. Only counts and type-category names (e.g. `"aws_access_key_id"`) are reported.

`tool_pre_invoke` is in scope for this metrics contract on the same terms as the other 3 hooks: it accepts `extensions` and emits `result.metadata["secrets_detection"]` under the identical gating/schema once a valid `trace_id` is present.

Blocking responses use the `SECRETS_DETECTED` violation code.

## Migration Note

Version `0.3.8` adds optional field filtering:

- `field_allowlist` and `field_denylist` default to empty lists, so existing configurations keep scanning the same fields as before.
- When configured, field filters affect detection counts, metadata, redaction, `min_findings_to_block`, and blocking decisions.
- `field_denylist` entries take precedence over `field_allowlist` entries.

Version `0.3.7` is a **breaking change** for any existing consumer reading detection metadata:

- The old flat `result.metadata` keys — `secrets_redacted`, `count` (redaction path) and `secrets_findings`, `count` (findings-only path) — have been removed entirely. There is no compatibility shim; code reading those keys will silently stop receiving data.
- Detection/redaction/blocking metrics are now emitted on `result.metadata["secrets_detection"]` instead, with keys `total_detections`, `total_masked`, `total_blocked`, and `secret_types` (see [Returned Metadata](#returned-metadata) above for the full schema).
- All 4 hooks — `prompt_pre_fetch`, `tool_pre_invoke`, `tool_post_invoke`, and `resource_post_fetch` — now accept a new optional `extensions` parameter carrying OpenTelemetry trace context. Emission to `result.metadata["secrets_detection"]` is gated solely on `extensions.request.trace_id` being present and valid — if no trace context is supplied, no metrics are written at all, regardless of any config flag.
- Consumers that previously read `result.metadata["secrets_redacted"]` / `result.metadata["secrets_findings"]` unconditionally must migrate to reading `result.metadata["secrets_detection"]` and must pass a `trace_id` via `extensions` to receive metrics.
- `tool_pre_invoke` previously never received `extensions` and could never emit metrics (a regression introduced earlier on this branch, since fixed) — it now follows the exact same contract as the other 3 hooks.

## Security Notes

- Outward-facing findings metadata and violation examples do not include original matched secret values.
- Enable broad detectors only after testing against representative payloads.
- The detector is best-effort pattern matching and should complement, not replace, upstream secret management controls.

## Testing

```bash
make ci
```
