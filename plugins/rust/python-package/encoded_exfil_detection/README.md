# Encoded Exfiltration Detection (Rust)

High-performance encoded exfiltration detection for ContextForge and MCP Gateway.

## Features

- Detects suspicious encoded payloads in prompt args, tool outputs, and resource content
- Scans common exfil encodings:
  - base64
  - base64url
  - hex
  - percent-encoding
  - escaped hex
- Scores candidates using decoded length, entropy, printable ratio, sensitive keywords, and egress hints
- Optional redaction instead of hard blocking
- Recursive scanning of nested dicts, lists, and JSON-like string payloads
- Allowlist regex support for known-safe encoded strings
- Decode-depth and recursion-depth guardrails

## Build

```bash
make install
```

## Runtime Requirements

This plugin depends on `cpex>=0.1.0,<0.2` and imports hook models from `cpex.framework`. The compiled Rust extension is mandatory; there is no Python fallback implementation.

## Usage

The plugin scans these hooks:

- `prompt_pre_fetch`
- `tool_post_invoke`
- `resource_post_fetch`

Typical uses:

- block suspicious encoded payloads before they leave the gateway
- redact encoded secrets or staged exfil fragments from tool results
- surface findings metadata for review and tuning

## Detection Model

Each candidate encoded segment is decoded and scored. The detector looks for combinations of:

- sufficient decoded length
- suspicious entropy
- printable decoded content
- sensitive markers such as `password`, `secret`, `token`, `authorization`, or `private key`
- egress hints such as `curl`, `wget`, `webhook`, `upload`, `socket`, or `pastebin`

The plugin can also inspect JSON strings recursively so encoded content nested inside serialized blobs is still visible to the detector.

## Configuration

Important settings include:

- `enabled`: per-encoding enable flags
- `min_encoded_length`
- `min_decoded_length`
- `min_entropy`
- `min_printable_ratio`
- `min_suspicion_score`
- `max_scan_string_length`
- `max_findings_per_value`
- `redact`
- `redaction_text`
- `block_on_detection`
- `min_findings_to_block`
- `allowlist_patterns`
- `extra_sensitive_keywords`
- `extra_egress_hints`
- `max_decode_depth`
- `max_recursion_depth`
- `parse_json_strings`

## Returned Metadata

`prompt_pre_fetch`, `tool_post_invoke`, and `resource_post_fetch` accept an optional `extensions` parameter carrying OpenTelemetry trace context. When a trace context is present (via `extensions.request.trace_id`) **and** at least one detection occurred, the plugin emits operational metrics on `result.metadata["encoded_exfil_detection"]` with the following schema:

```python
result.metadata["encoded_exfil_detection"] = {
    "total_detections": 2,                      # int — total number of findings in this call
    "encoding_types": ["base64", "hex"],         # list[str] — distinct encoding names, sorted, deduped
    "redacted": True,                            # bool — present only when the redact branch fired
}
```

`redacted` is only included when `redact=true` is configured and the payload was actually rewritten in this call; it is omitted otherwise (its absence means "not redacted this call", not "false").

**Gating:** Metrics are only emitted when a valid `trace_id` is present in the trace context (`extensions.request.trace_id`) **and** the scan produced at least one detection. No trace context, or a clean payload, means no `result.metadata` write at all, regardless of any config flag — this keeps the untraced/clean path byte-for-byte identical to before metrics existed.

**Security Note (S1):** The plugin **never includes raw finding content, matched/decoded payload text, or per-finding `path`/`score` detail** in `result.metadata`. Only the total count and the distinct encoding names are reported.

Blocking responses use the `ENCODED_EXFIL_DETECTED` violation code.

## Migration Note

Version `0.3.6` is a **breaking change** for any existing consumer reading detection metadata:

- The old flat `result.metadata` keys — `encoded_exfil_count`, `encoded_exfil_findings`, `encoded_exfil_redacted`, and `implementation` — have been removed entirely. There is no compatibility shim; code reading those keys will silently stop receiving data. (These keys were already dropped at the gateway before this change, since the gateway's metadata sanitizer treats each top-level `result.metadata` key as a plugin namespace expecting a dict value, and `encoded_exfil_count`/`implementation` are scalars — so this migration removes a write that was already dead-on-arrival downstream.)
- Detection metrics are now emitted on `result.metadata["encoded_exfil_detection"]` instead, with keys `total_detections`, `encoding_types`, and (conditionally) `redacted` — see [Returned Metadata](#returned-metadata) above for the full schema.
- `prompt_pre_fetch`, `tool_post_invoke`, and `resource_post_fetch` now accept a new optional `extensions` parameter carrying OpenTelemetry trace context. Emission to `result.metadata["encoded_exfil_detection"]` is gated on `extensions.request.trace_id` being present and valid, and requires at least one detection — if no trace context is supplied, or the payload is clean, no metrics are written at all, regardless of any config flag.
- Consumers that previously read `result.metadata["encoded_exfil_count"]` / `result.metadata["encoded_exfil_findings"]` / `result.metadata["encoded_exfil_redacted"]` unconditionally must migrate to reading `result.metadata["encoded_exfil_detection"]` and must pass a `trace_id` via `extensions` to receive metrics.
- The `include_detection_details` config flag no longer has any influence over `result.metadata` (it never leaks per-finding detail into metrics regardless of its value); it continues to affect only the `examples` field of `PluginViolation.details` on the blocking path, which is unaffected by this migration.

## Security Notes

- Guardrails reject Rust-incompatible allowlist regexes at engine initialization time (during plugin construction). Features such as lookaround and backreferences are not supported.
- Scan and recursion caps exist to keep detection bounded on large payloads.
- Detailed findings can be reduced or sanitized before metadata emission depending on configuration.

## Testing

```bash
make ci
```
