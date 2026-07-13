# Rate Limiter Metrics Schema Contract (D1)

## Overview

This document formalizes the contract for metrics emitted by the `rate_limiter` CPEX Rust plugin via the `result.metadata` channel when a trace_id is present in the request extensions.

## Namespace

All metrics are emitted under the `rate_limiter` namespace key:

```python
result.metadata = {
    "rate_limiter": { <metrics dict> }
}
```

## Allow-List (S2)

The following fields are the **only fields** permitted in the metrics dict. Gateway validation (G1) must reject any deviation:

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `allowed` | `int` (`0`/`1`) | Whether this call's request was allowed | `1` |
| `throttled` | `int` (`0`/`1`) | Whether this call's request was throttled (mutually exclusive with `allowed`) | `0` |
| `backend` | `str` | Rate-limit backend used for this evaluation | `"memory"` |
| `limited` | `bool` | Whether a rate-limit configuration applies to this dimension/request | `true` |
| `remaining` | `int` | Remaining calls in the current window (present only when `limited` is `true`) | `4` |
| `reset_in` | `int` | Seconds until the current window resets (present only when `limited` is `true`) | `1` |
| `dimensions` | `dict` | Per-dimension `violated`/`allowed` breakdown (present whenever `limited` is `true`, i.e. whenever one or more dimensions were evaluated — not only when there are 2+) | `{"allowed": [...]}` or `{"violated": [...]}` |

### Semantics

- **allowed** / **throttled**: Per-call (not cumulative) `0`/`1` outcome flags. The engine evaluates a single request per call with no running counter, so these describe only the current call's outcome — the gateway is expected to aggregate counts across spans/time.
- **backend**: Fixed to `"redis"` or `"memory"`, mirroring `engine.uses_async_backend()` (Redis is the only async backend today).
- **limited**, **remaining**, **reset_in**, **dimensions**: Folded in verbatim (allow-listed passthrough) from the engine's own operational `meta` dict (`engine::build_meta_dict`), via the fixed key list `["limited", "remaining", "reset_in", "dimensions"]`. Each key is included only if the underlying `meta` dict set it — e.g. `remaining`/`reset_in` are absent on the early-return "not limited" branch (no rate limit configured for this dimension).
- **dimensions**: `build_meta_dict` sets `dimensions` whenever `has_violated || has_allowed` is true (`src/engine.rs:502-533`). `EvalResult::from_dims` (`src/types.rs:105-159`) partitions **every** dimension it was given into either `violated_dimensions` or `allowed_dimensions`, so as soon as at least **one** dimension is evaluated, one of those two lists is non-empty and `dimensions` is set — it is present whenever `limited` is `true` (i.e. for any request with rate-limit configuration at all, including a single-dimension config like `by_user` alone), not only when 2+ dimensions are configured. It is absent only on the early-return "not limited" branch, where `dims.is_empty()` short-circuits to `EvalResult::unlimited(0)` and `build_meta_dict` is never called. When only one dimension is checked, `dimensions` duplicates the top-level `remaining`/`reset_in` values inside a single-entry `allowed` or `violated` list.
- All three result-building branches (early-return-not-limited, allowed, throttled/not-allowed) emit metrics identically when a trace_id is present — the throttled branch previously emitted no metadata at all under the legacy behavior; it now carries the same metrics as the other branches, since throttling is exactly the event this metric exists to count.

## Deny-List (S1): Content-Bearing Fields

The following fields **MUST NOT** appear in the metrics dict, even in part. This prevents leakage of user/tenant identity:

| Field | Reason |
|-------|--------|
| `user_id` | Identifies the calling user; `build_meta_dict` attaches this only on the not-allowed path for `PluginViolation.details` debugging — never for the metrics/telemetry channel |
| `tenant_id` | Identifies the calling tenant; same exclusion rationale as `user_id` |

### Validation

- No string dump of the metrics dict may contain `user_id` or `tenant_id`, even when the corresponding `PluginViolation.details` (a separate channel) does carry them.
- The gateway validation (G1) must reject any metrics dict containing keys outside the allow-list above.

## Bounds (S3)

### Field Values

- `allowed`, `throttled`: constrained to `0` or `1`; exactly one is `1` per call outcome (except the early-return "not limited" branch, which always reports `allowed = 1`, `throttled = 0`).
- `backend`: fixed to one of 2 known values (`"redis"`, `"memory"`).
- `limited`: boolean.
- `remaining`, `reset_in`: standard signed integers (no practical upper bound); present only when `limited` is `true`.
- `dimensions`: nested `violated`/`allowed` lists of per-dimension `{limited, remaining, reset_in}` dicts; present whenever at least one dimension was evaluated (see Semantics above), sized by the number of configured dimensions for the request (no additional truncation is applied beyond the engine's own dimension set).

## Emission Criteria

Metrics are **only emitted** when:

1. A trace_id is present in `extensions.request.trace_id`.

Unlike `pii_filter`/`secrets_detection`, there is no additional "something happened" gate: `rate_limiter` evaluates exactly one meaningful outcome (allowed or throttled) per call, so every call with a trace_id emits metrics, regardless of outcome. Only `prompt_pre_fetch` and `tool_pre_invoke` are in scope. When trace_id is absent, the `result.metadata` dict is omitted entirely (or does not contain the `rate_limiter` key) on all branches — matching the legacy always-on flat write's removal byte-for-byte.

## Example

### Input

```
config: by_user = "1/s"
Call 1: payload.name = "search", context.user = "carol", extensions.request.trace_id = "t1"
Call 2 (same second): payload.name = "search", context.user = "carol", extensions.request.trace_id = "t1"
```

### Evaluator Output

- Call 1: allowed (limit not yet reached)
- Call 2: throttled (limit reached); `PluginViolation.details.user_id == "carol"`

### Emitted Metrics

```python
# Call 1 (allowed) — even a single-dimension config (`by_user` alone) populates
# `dimensions`, since `build_meta_dict` sets it whenever any dimension was
# evaluated, not only when there are 2+ dimensions. Here it duplicates the
# top-level remaining/reset_in inside a single-entry "allowed" list.
result.metadata = {
    "rate_limiter": {
        "limited": True,
        "remaining": 0,
        "reset_in": 1,
        "dimensions": {"allowed": [{"limited": True, "remaining": 0, "reset_in": 1}]},
        "allowed": 1,
        "throttled": 0,
        "backend": "memory"
    }
}

# Call 2 (throttled) — the same single dimension is now in the "violated" list.
result.metadata = {
    "rate_limiter": {
        "limited": True,
        "remaining": 0,
        "reset_in": 1,
        "dimensions": {"violated": [{"limited": True, "remaining": 0, "reset_in": 1}]},
        "allowed": 0,
        "throttled": 1,
        "backend": "memory"
    }
}
```

**NOT emitted:**
- `"user_id": "carol"` (identity, kept confined to `PluginViolation.details`)
- `"tenant_id": "acme"` (identity, kept confined to `PluginViolation.details`)

## References

- **A3**: Implementation of `build_rate_limiter_metrics` / `push_rate_limiter_metrics_kwarg` in Rust plugin (`src/plugin.rs`), folding `engine::build_meta_dict`'s allow-listed fields (`src/engine.rs`).
- **G1**: Gateway validation of metric contracts (cross-repo).
- **G7**: Identity surfaced in `PluginViolation.details` on the not-allowed path for downstream debugging (separate from this metrics contract).
- **S1, S2, S3**: Security (leakage), structural (allow-list), and scale (bounds) guarantees.
