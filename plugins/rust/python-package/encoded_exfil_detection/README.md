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

This plugin depends on `cpex>=0.1.0rc1,<0.2` and imports hook models from `cpex.framework`. The compiled Rust extension is mandatory; there is no Python fallback implementation.

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

When detections occur, the plugin can emit:

- `encoded_exfil_count`
- `encoded_exfil_findings`
- `encoded_exfil_redacted`
- `implementation`

Blocking responses use the `ENCODED_EXFIL_DETECTED` violation code.

## Security Notes

- Guardrails reject Rust-incompatible allowlist regexes at engine initialization time (during plugin construction). Features such as lookaround and backreferences are not supported.
- Scan and recursion caps exist to keep detection bounded on large payloads.
- Detailed findings can be reduced or sanitized before metadata emission depending on configuration.

## Testing

```bash
make ci
```
