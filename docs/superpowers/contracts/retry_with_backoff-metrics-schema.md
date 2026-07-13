# Retry With Backoff Metrics Schema Contract (D1)

## Overview

This document formalizes the contract for metrics emitted by the `retry_with_backoff` CPEX Rust plugin via the `result.metadata` channel when a trace_id is present in the request extensions.

## Namespace

All metrics are emitted under the `retry_with_backoff` namespace key:

```python
result.metadata = {
    "retry_with_backoff": { <metrics dict> }
}
```

## Allow-List (S2)

The following fields are the **only fields** permitted in the metrics dict. Gateway validation (G1) must reject any deviation:

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `retry_count` | `int` | `ToolRetryState::consecutive_failures` after this call's outcome is recorded | `1` |
| `retry_delay_ms` | `int` | The per-attempt delay `compute_delay_ms` computed for this call | `100` |

### Semantics

- **retry_count**: The running consecutive-failure count for this `(tool, request_id)` key after this call's outcome is recorded. `0` on a successful call (state is cleared). On a within-budget retry, this is the current failure count. On the exhausted branch, this is the failure count that triggered exhaustion (captured before the state entry is removed).
- **retry_delay_ms**: The same value already returned as the top-level (non-namespaced) `retry_delay_ms` field on the hook result — `0` on success and `0` again once the retry budget is exhausted; a positive backoff delay only on a within-budget retry.
- **No cumulative total**: There is deliberately **no** `total_backoff_ms` (or similarly named cumulative field). No new state accumulator was added for this contract — this was a resolved plan decision, not an oversight. Only these two per-call counters are emitted.
- **Scope**: Only `tool_post_invoke` is in scope for issue #129. `resource_post_fetch` is untouched — it never receives `extensions`, and it keeps emitting its pre-existing, un-namespaced `retry_policy` config echo via `build_metadata`, which is unrelated to this contract.

## Deny-List (S1): Content-Bearing Fields

This plugin's inputs and metrics carry no user content or identifiers by construction — there are no matched values, payload excerpts, or field paths in scope for redaction. For consistency with the other plugin contracts, the same discipline still applies:

| Field | Reason |
|-------|--------|
| Tool arguments or results | Never read into the metrics dict — only the internal retry counters are |
| Request/user/tenant identifiers | Never folded into the metrics dict, even though `request_id` is used internally as part of the state-map key |

### Validation

- The metrics dict must contain only `retry_count` and `retry_delay_ms` — no tool name, request id, or other contextual data.

## Bounds (S3)

### Field Values

- `retry_count`: a `u32`, bounded in practice by `config.max_retries + 1` (the plugin removes state once the budget is exhausted, and the value only ever reflects the current run's consecutive-failure count).
- `retry_delay_ms`: a `u64`, bounded by the plugin's backoff configuration (`backoff_base_ms` and the configured maximum); no additional truncation is applied beyond what `compute_delay_ms` computes.

## Emission Criteria

Metrics are **only emitted** when:

1. A trace_id is present in `extensions.request.trace_id`.

Unlike `pii_filter`/`secrets_detection`/`encoded_exfil_detection`, there is no additional "something happened" gate: every `tool_post_invoke` call (success, within-budget retry, or exhausted) has a meaningful `retry_count`/`retry_delay_ms` outcome to report, including the all-zero success case. When trace_id is absent, the `result.metadata` dict is omitted entirely (or does not contain the `retry_with_backoff` key) on all three branches.

## Example

### Input

```
config: max_retries = 2, backoff_base_ms = 100
Call 1: payload.name = "writer", tool result = failure, extensions.request.trace_id = "t1"
Call 2 (same tool/request_id): tool result = success, extensions.request.trace_id = "t1"
```

### Retry State

- Call 1: first failure recorded (`consecutive_failures = 1`), within budget → delay computed for attempt 0
- Call 2: success → state cleared

### Emitted Metrics

```python
# Call 1 (within-budget retry)
result.metadata = {
    "retry_with_backoff": {
        "retry_count": 1,
        "retry_delay_ms": 100
    }
}

# Call 2 (success)
result.metadata = {
    "retry_with_backoff": {
        "retry_count": 0,
        "retry_delay_ms": 0
    }
}
```

**NOT emitted:**
- `"retry_policy": {...}` (the legacy un-namespaced config echo, removed from `tool_post_invoke`; still present, unchanged, on `resource_post_fetch`)
- `"total_backoff_ms"` (no cumulative counter is tracked or emitted)

## References

- **A3**: Implementation of `build_retry_with_backoff_metrics` / `push_retry_with_backoff_metrics_kwarg` in Rust plugin (`src/plugin.rs`).
- **G1**: Gateway validation of metric contracts (cross-repo).
- **S1, S2, S3**: Security (leakage), structural (allow-list), and scale (bounds) guarantees.
