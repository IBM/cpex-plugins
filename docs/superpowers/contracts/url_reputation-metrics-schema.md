# URL Reputation Metrics Schema Contract (D1)

## Overview

This document formalizes the contract for metrics emitted by the `url_reputation` CPEX Rust plugin via the `result.metadata` channel when a trace_id is present in the request extensions. `url_reputation` wrote no `result.metadata` prior to this contract, so this is a pure additive contract, not a migration — there are no legacy keys to reconcile.

## Namespace

All metrics are emitted under the `url_reputation` namespace key:

```python
result.metadata = {
    "url_reputation": { <metrics dict> }
}
```

## Allow-List (S2)

The following fields are the **only fields** permitted in the metrics dict. Gateway validation (G1) must reject any deviation:

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `total_checked` | `int` | Always `1` — this plugin checks exactly one URL per `resource_pre_fetch` call | `1` |
| `total_blocked` | `int` (`0`/`1`) | Whether this call's URL was blocked | `1` |
| `reputation_categories` | `list[str]` | Empty when allowed; otherwise exactly one category slug | `["blocked_domain"]` |

### Semantics

- **total_checked**: Constant `1` per call — `resource_pre_fetch` validates a single URL per invocation, with no batching and no running counter.
- **total_blocked**: `0` when `continue_processing` is `True`; `1` when the call is blocked, whether by the rule engine or the generic internal-error/exception path (which blocks for safety and reports `reason = "Rust validation failure"`).
- **reputation_categories**: Empty list when allowed. When blocked, a list containing exactly one category slug, derived from the plugin's static, hardcoded `PluginViolation.reason` string via a fixed mapping (`_CATEGORY_BY_REASON`):

  | Reason string | Slug |
  |---|---|
  | `Could not parse url` | `malformed_url` |
  | `Could not parse domain` | `malformed_domain` |
  | `Blocked non secure http url` | `insecure_scheme` |
  | `Domain in blocked set` | `blocked_domain` |
  | `Blocked pattern` | `blocked_pattern` |
  | `High entropy domain` | `high_entropy_domain` |
  | `Illegal TLD` | `illegal_tld` |
  | `Domain unicode is not secure` | `unicode_spoofing` |
  | `Rust validation failure` | `internal_error` |

  Any reason string not in this table maps to the fallback slug `other`.

## Deny-List (S1): Content-Bearing Fields

The following fields **MUST NOT** appear in the metrics dict, even in part. This prevents leakage of the checked URL:

| Field | Reason |
|-------|--------|
| The checked URL | Never read for metrics purposes; confined to `PluginViolation.details` on the blocking path |
| The checked domain | Same exclusion rationale as the full URL |
| Query parameters or tokens embedded in the URL | Substrings of the URL that could reveal sensitive request data |

### Validation

- No string dump of the metrics dict may contain the checked URL, its domain, or any substring thereof.
- `set(metrics.keys())` must always equal `{"total_checked", "total_blocked", "reputation_categories"}`.

## Bounds (S3)

### Reputation Categories List

- `reputation_categories` is structurally bounded to **0 or 1 entries** — one URL is checked per call, so at most one violation reason (and therefore at most one slug) can apply.
- The category slug vocabulary is fixed to **10 known values**: the 9 mapped slugs in the table above, plus the `other` fallback.

### Field Sizes

- `total_checked`, `total_blocked`: constrained to `0` or `1` (in practice `total_checked` is always `1`).

## Emission Criteria

Metrics are **only emitted** when:

1. A trace_id is present in `extensions.request.trace_id`.

There is no additional "something happened" gate: mirroring `rate_limiter`'s per-call semantics, every `resource_pre_fetch` call has a meaningful checked/blocked outcome to report, so metrics are gated on `trace_id` alone. When trace_id is absent, the `result.metadata` dict is omitted entirely (or does not contain the `url_reputation` key), regardless of whether the URL was allowed or blocked — matching the pre-metrics behavior byte-for-byte.

## Example

### Input

```
config: blocked_domains = ["malicious.example"]
payload.uri = "https://malicious.example/path"
extensions.request.trace_id = "t1"
```

### Validator Output

- `continue_processing = False`
- `violation.reason = "Domain in blocked set"`

### Emitted Metrics

```python
result.metadata = {
    "url_reputation": {
        "total_checked": 1,
        "total_blocked": 1,
        "reputation_categories": ["blocked_domain"]
    }
}
```

**NOT emitted:**
- `"https://malicious.example/path"` (raw URL)
- `"malicious.example"` (raw domain)
- `"malware"` / `"phishing"` (illustrative category names from the original plan — not part of the plugin's actual, hardcoded reason vocabulary)

## References

- **A3**: Implementation of `_build_metrics` and `_CATEGORY_BY_REASON` in the Python plugin (`cpex_url_reputation/url_reputation.py`).
- **G1**: Gateway validation of metric contracts (cross-repo).
- **S1, S2, S3**: Security (leakage), structural (allow-list), and scale (bounds) guarantees.
