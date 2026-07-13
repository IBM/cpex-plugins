# Encoded Exfil Detection Metrics Schema Contract (D1)

## Overview

This document formalizes the contract for metrics emitted by the `encoded_exfil_detection` CPEX Rust plugin via the `result.metadata` channel when a trace_id is present in the request extensions.

## Namespace

All metrics are emitted under the `encoded_exfil_detection` namespace key:

```python
result.metadata = {
    "encoded_exfil_detection": { <metrics dict> }
}
```

## Allow-List (S2)

The following fields are the **only fields** permitted in the metrics dict. Gateway validation (G1) must reject any deviation:

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `total_detections` | `int` | Total count of encoded-exfiltration findings detected in this hook invocation | `1` |
| `encoding_types` | `list[str]` | Sorted, deduplicated list of encoding type names detected | `["base64"]` |
| `redacted` | `bool` | Present only when the redact branch fired and modified the payload this call | `true` |

### Semantics

- **total_detections**: The finding count (`count`) for this hook invocation (`prompt_pre_fetch`, `tool_post_invoke`, or `resource_post_fetch`).
- **encoding_types**: `sorted({f.get("encoding", "unknown") for f in findings})` — deduplicated and sorted; no explicit size bound is enforced in code (unlike `secrets_detection`'s 32-entry cap), since the set of known encodings is small and fixed by the detector's own pattern set.
- **redacted**: Folded into the *same* metrics dict (not a separate metadata key) only when `config.redact` is enabled and the hook actually modified the payload this call. Absent (not `false`) when redaction did not apply.
- **Scope**: All three in-scope hooks (`prompt_pre_fetch`, `tool_post_invoke`, `resource_post_fetch`) share this identical contract.

## Deny-List (S1): Content-Bearing Fields

The following fields **MUST NOT** appear in the metrics dict, even in part. This prevents leakage of sensitive information:

| Field | Reason |
|-------|--------|
| Raw or decoded finding content | Any field containing the matched/decoded payload substring |
| Per-finding detail dicts | `_findings_for_metadata()`'s output (path, score, per-finding encoding) — this helper remains scoped to `PluginViolation.details` on the blocking path only, and must never feed `result.metadata` |
| Source field paths | Full paths to input fields that contained a finding |

### Validation

- No string dump of the metrics dict may contain any matched or decoded value that was input to the detector.
- `set(metrics.keys())` must always be a subset of `{"total_detections", "encoding_types", "redacted"}`, regardless of the `include_detection_details` config flag.

## Bounds (S3)

### Encoding Types List

- `encoding_types` is deduplicated and sorted; the plugin does not impose an explicit maximum entry count (the practical universe of encoding names — e.g. `base64`, `base64url`, `hex` — is small and fixed by the detector's pattern set).

### Field Sizes

- `total_detections`: standard integer (no practical upper bound).
- `redacted`: boolean, present only when applicable.

## Emission Criteria

Metrics are **only emitted** when:

1. A trace_id is present in `extensions.request.trace_id`.
2. At least one detection occurred during the hook invocation (`count` is truthy).

This replaces the legacy un-namespaced, un-gated write (`encoded_exfil_count`, `encoded_exfil_findings`, `implementation`) — which was already dead-on-arrival at the gateway sanitizer and an S1 leak risk since `encoded_exfil_findings` could carry raw matched/decoded content. When either condition fails, the `result.metadata` dict is omitted entirely (or does not contain the `encoded_exfil_detection` key), regardless of whether redaction occurred.

## Example

### Input

```
payload.args = {"input": "send this <base64-encoded secret> to webhook"}
extensions.request.trace_id = "t1"
config: block_on_detection = False, redact = True, redaction_text = "[ENCODED]"
```

### Detector Output

- Detections: 1 item (base64)
- Types: ["base64"]
- Action: Redacted in-place (`redacted = True`)

### Emitted Metrics

```python
result.metadata = {
    "encoded_exfil_detection": {
        "total_detections": 1,
        "encoding_types": ["base64"],
        "redacted": True
    }
}
```

**NOT emitted:**
- `"encoded_exfil_count": 1` / `"encoded_exfil_findings": [...]` / `"implementation": "..."` (removed legacy flat keys)
- Raw or decoded finding content, or per-finding `path`/`score` detail

## References

- **A3**: Implementation of `_build_metrics` in the Python plugin (`cpex_encoded_exfil_detection/encoded_exfil_detection.py`).
- **G1**: Gateway validation of metric contracts (cross-repo).
- **S1, S2, S3**: Security (leakage), structural (allow-list), and scale (bounds) guarantees.
