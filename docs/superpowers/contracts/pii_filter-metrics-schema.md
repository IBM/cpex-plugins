# PII Filter Metrics Schema Contract (D1)

## Overview

This document formalizes the contract for metrics emitted by the `pii_filter` CPEX Rust plugin via the `result.metadata` channel when a trace_id is present in the request extensions.

## Namespace

All metrics are emitted under the `pii_filter` namespace key:

```python
result.metadata = {
    "pii_filter": { <metrics dict> }
}
```

## Allow-List (S2)

The following fields are the **only fields** permitted in the metrics dict. Gateway validation (G1) must reject any deviation:

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `total_detections` | `int` | Total count of PII items detected across all patterns in this hook invocation | `5` |
| `total_masked` | `int` | Total count of PII items successfully masked (only populated when masking is applied) | `5` |
| `detection_types` | `list[str]` | Sorted, deduplicated list of PII pattern type names detected. See bounds (S3). | `["email", "ssn"]` |
| `stage` | `str` | The plugin hook stage that produced this metric | `"tool_post_invoke"` |

### Semantics

- **total_detections**: Incremented for each distinct PII match found, regardless of masking outcome.
- **total_masked**: Set to `total_detections` when PII is masked in-place; set to `0` when detection blocks the payload without masking.
- **detection_types**: Contains the canonical string name of each pattern type (e.g., `"email"`, `"ssn"`, `"credit_card"`), sorted alphabetically, deduplicated, and bounded to 32 types.
- **stage**: One of `"prompt_pre_fetch"`, `"prompt_post_fetch"`, `"tool_pre_invoke"`, or `"tool_post_invoke"`.

## Deny-List (S1): Content-Bearing Fields

The following fields **MUST NOT** appear in the metrics dict, even in part. This prevents leakage of sensitive information:

| Field | Reason |
|-------|--------|
| Matched PII values | Any field containing the actual detected secret (e.g., email address, SSN, credit card number) |
| Raw payloads or excerpts | Substrings of the input that contained PII |
| Masking instructions or patterns | Details of where or how masking was applied that would reveal the original content |
| Source field names or paths | Full paths to input fields that contained PII (e.g., `user.email.address`) — only the pattern type is safe |

### Validation

- No string dump of the metrics dict may contain any matched value that was input to the detector.
- No field must include regex patterns, character counts (of masked segments), or other information that could be used to infer the original content.

## Bounds (S3)

### Detection Types List

The `detection_types` list is bounded to **32 entries maximum**. Enforcement:

1. The plugin truncates the sorted, deduplicated type list to the first 32 entries.
2. If more than 32 distinct types are detected, only the first 32 (alphabetically) are retained.
3. The gateway validation (G1) must reject any `detection_types` field exceeding 32 entries.

### Field Sizes

- `total_detections` and `total_masked`: standard 64-bit signed integers (no practical upper bound).
- `detection_types`: each entry is a string ≤ 32 characters; total list is ≤ 32 entries.
- `stage`: fixed to one of 4 known values (see Semantics).

## Emission Criteria

Metrics are **only emitted** when:

1. A trace_id is present in `extensions.request.trace_id`.
2. At least one PII detection occurred during the hook invocation.

When trace_id is absent or no detections occur, the `result.metadata` dict is omitted entirely (or does not contain the `pii_filter` key).

## Example

### Input

```
payload.result = {
    "user_email": "alice@example.com",
    "account_id": "acc-123",
    "ssn": "123-45-6789"
}
extensions.request.trace_id = "trace-xyz"
```

### Detector Output

- Detections: 2 items (email, ssn)
- Types: ["email", "ssn"]
- Action: Masked in-place (total_masked = 2)

### Emitted Metrics

```python
result.metadata = {
    "pii_filter": {
        "total_detections": 2,
        "total_masked": 2,
        "detection_types": ["email", "ssn"],
        "stage": "tool_post_invoke"
    }
}
```

**NOT emitted:**
- `"user_email": "alice@example.com"` (matched value)
- `"matched_fields": ["user_email", "ssn"]` (field names)
- `"mask_applied_at": ["user_email"]` (location details)

## References

- **A3**: Implementation of `build_pii_metrics` in Rust plugin (`src/plugin.rs`).
- **G1**: Gateway validation of metric contracts (cross-repo).
- **S1, S2, S3**: Security (leakage), structural (allow-list), and scale (bounds) guarantees.
