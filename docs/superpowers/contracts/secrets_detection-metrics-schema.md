# Secrets Detection Metrics Schema Contract (D1)

## Overview

This document formalizes the contract for metrics emitted by the `secrets_detection` CPEX Rust plugin via the `result.metadata` channel when a trace_id is present in the request extensions.

## Namespace

All metrics are emitted under the `secrets_detection` namespace key:

```python
result.metadata = {
    "secrets_detection": { <metrics dict> }
}
```

## Allow-List (S2)

The following fields are the **only fields** permitted in the metrics dict. Gateway validation (G1) must reject any deviation:

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `total_detections` | `int` | Total count of secrets detected across all patterns in this hook invocation | `1` |
| `total_masked` | `int` | Count of detections masked in-place this call (only non-zero when redaction was applied) | `1` |
| `total_blocked` | `int` | Count of detections that caused this call to block (only non-zero on the blocking path) | `0` |
| `secret_types` | `list[str]` | Sorted, deduplicated list of secret pattern type names detected. See bounds (S3). | `["aws_access_key_id"]` |

### Semantics

- **total_detections**: Incremented for each distinct secret match found in this hook invocation (`prompt_pre_fetch`, `tool_post_invoke`, `resource_post_fetch`).
- **total_masked** / **total_blocked**: Mutually exclusive per call — the plugin classifies each invocation into exactly one outcome (masked, blocked, or neither) and sets the corresponding counter to `total_detections`, leaving the other at `0`. Neither is set when detections occurred but were neither masked nor blocked (e.g. redact disabled and not blocking).
- **secret_types**: Contains the canonical string type name of each finding (e.g., `"aws_access_key_id"`, `"slack_token"`), sorted alphabetically, deduplicated, and bounded to 32 types.
- **Scope**: Only `prompt_pre_fetch`, `tool_post_invoke`, and `resource_post_fetch` participate in this contract. `tool_pre_invoke` is out of scope for issue #129 — it never receives `extensions`, so it can never carry a `trace_id`, and its `result.metadata` is now always empty (the legacy flat write was removed from it too).

## Deny-List (S1): Content-Bearing Fields

The following fields **MUST NOT** appear in the metrics dict, even in part. This prevents leakage of sensitive information:

| Field | Reason |
|-------|--------|
| Matched secret values | Any field containing the actual detected secret (e.g., an AWS access key, a Slack token) |
| Raw payloads or excerpts | Substrings of the input that contained a secret |
| Masking instructions or patterns | Details of where or how masking was applied that would reveal the original content |
| Source field names or paths | Full paths to input fields that contained a secret — only the pattern type is safe |

### Validation

- No string dump of the metrics dict may contain any matched value that was input to the detector.
- No field must include regex patterns, character counts (of masked segments), or other information that could be used to infer the original content.

## Bounds (S3)

### Secret Types List

The `secret_types` list is bounded to **32 entries maximum** (`MAX_SECRET_TYPES` in the Rust plugin). Enforcement:

1. The plugin sorts and deduplicates the collected type list.
2. The list is truncated to the first 32 entries (alphabetically) if more than 32 distinct types are detected.
3. The gateway validation (G1) must reject any `secret_types` field exceeding 32 entries.

### Field Sizes

- `total_detections`, `total_masked`, `total_blocked`: standard unsigned integers (no practical upper bound).
- `secret_types`: each entry is a short canonical type-name string; total list is ≤ 32 entries.

## Emission Criteria

Metrics are **only emitted** when:

1. A trace_id is present in `extensions.request.trace_id`.
2. At least one secret detection occurred during the hook invocation (`count > 0`).

When either condition fails, the `result.metadata` dict is omitted entirely (or does not contain the `secrets_detection` key) — this includes the legacy 2-arg call path (no `extensions` passed), which must remain backward compatible and never raise.

## Example

### Input

```
payload.result = {
    "content": [{"type": "text", "text": "AWS_ACCESS_KEY_ID=AKIA-FAKE12345-EXAMPLE"}],
    "isError": False
}
extensions.request.trace_id = "t1"
```

### Detector Output

- Detections: 1 item (aws_access_key_id)
- Types: ["aws_access_key_id"]
- Action: Masked in-place (total_masked = 1)

### Emitted Metrics

```python
result.metadata = {
    "secrets_detection": {
        "total_detections": 1,
        "total_masked": 1,
        "total_blocked": 0,
        "secret_types": ["aws_access_key_id"]
    }
}
```

**NOT emitted:**
- `"secrets_redacted": True` / `"count": 1` (removed legacy flat keys)
- `"secrets_findings": [{"type": "aws_access_key_id"}]` (removed legacy flat key; per-finding detail is not part of the metrics contract)
- `"AKIA-FAKE12345-EXAMPLE"` (matched secret value)

## References

- **A3**: Implementation of `build_secrets_metrics` / `push_metrics_kwarg` in Rust plugin (`src/plugin.rs`).
- **G1**: Gateway validation of metric contracts (cross-repo).
- **S1, S2, S3**: Security (leakage), structural (allow-list), and scale (bounds) guarantees.
