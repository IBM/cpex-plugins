# Retry With Backoff (Rust)

High-performance retry and backoff policy engine for ContextForge and MCP Gateway.

## Features

- Rust-backed retry state tracking for tool invocations
- Exponential backoff with optional jitter
- Per-tool policy overrides without duplicating whole plugin configs
- Retry decisions based on `isError`, structured `status_code`, or optional parsed text payloads
- Automatic state eviction for stale request entries
- Gateway ceiling enforcement for `max_retries`
- Retry policy metadata returned on tool and resource hooks

## Build

```bash
make install
```

## Runtime Requirements

This plugin depends on `cpex>=0.1.0,<0.2` and imports hook models from `cpex.framework`. The compiled Rust extension is mandatory; there is no Python fallback implementation.

## Usage

The plugin runs on `tool_post_invoke` and `resource_post_fetch`.

Typical uses:

- Retry transient upstream failures such as `429`, `500`, `502`, `503`, and `504`
- Clamp aggressive plugin settings to the gateway-wide retry ceiling
- Apply stricter retry budgets to fragile or expensive tools

## Configuration

### Core settings

- `max_retries`: maximum retry attempts before giving up
- `backoff_base_ms`: base delay for exponential backoff
- `max_backoff_ms`: upper bound for computed retry delays
- `retry_on_status`: HTTP or structured status codes treated as retriable
- `jitter`: randomize delay within the current exponential ceiling
- `check_text_content`: inspect text content for JSON-encoded error payloads when structured content is absent

### Per-tool overrides

Use `tool_overrides` to change retry behavior for a specific tool:

- `max_retries`
- `backoff_base_ms`
- `max_backoff_ms`
- `retry_on_status`
- `jitter`

## Behavior Notes

- Successful responses clear retry state for the `(tool, request_id)` pair.
- Retry state expires after a short TTL so abandoned request state does not accumulate indefinitely.
- If `check_text_content` is disabled, the hot path uses the Rust state manager directly.
- If `check_text_content` is enabled, Python-side payload inspection supplements the Rust state manager before applying retry policy.

## Returned Metadata

### `tool_post_invoke` — OpenTelemetry metrics

`tool_post_invoke` accepts an optional `extensions` parameter carrying OpenTelemetry trace context. When a trace context is present (via `extensions.request.trace_id`), the plugin emits operational metrics on `result.metadata["retry_with_backoff"]` with the following schema:

```python
result.metadata["retry_with_backoff"] = {
    "retry_count": 1,      # int — consecutive_failures after this call's outcome is recorded; 0 on success
    "retry_delay_ms": 100, # int — the per-attempt delay computed for this call; 0 on success or once exhausted
}
```

Every call (success, within-budget retry, or exhausted) has a meaningful outcome to report, including the all-zero success case — there is deliberately no `total_backoff_ms` cumulative counter, only these two per-call fields.

**Gating:** Metrics are only emitted when a valid `trace_id` is present in the trace context (`extensions.request.trace_id`). No trace context means no `result.metadata` write at all, regardless of any config flag.

### `resource_post_fetch` — unchanged config echo

`resource_post_fetch` is **out of scope** for the OTel metrics contract above — it never receives `extensions` and continues to unconditionally emit the plugin's active retry policy configuration (not per-call outcome data) on `result.metadata`:

- `max_retries`
- `backoff_base_ms`
- `max_backoff_ms`
- `retry_on_status`

## Migration Note

Version `0.3.6` is a **breaking change** for `tool_post_invoke` consumers only (`resource_post_fetch` is unaffected):

- `tool_post_invoke` no longer emits the flat, unconditional `retry_policy` config echo (`max_retries`, `backoff_base_ms`, `max_backoff_ms`, `retry_on_status`). That echo is replaced by the namespaced, trace-gated `result.metadata["retry_with_backoff"]` schema above (`retry_count`, `retry_delay_ms`).
- `tool_post_invoke` now accepts a new optional `extensions` parameter carrying OpenTelemetry trace context. Emission is gated solely on `extensions.request.trace_id` being present and valid — if no trace context is supplied, no metrics are written at all.
- Consumers that previously read the config echo from `tool_post_invoke` unconditionally must migrate to reading `result.metadata["retry_with_backoff"]` and must pass a `trace_id` via `extensions` to receive metrics.
- `resource_post_fetch` keeps its pre-existing, un-namespaced config echo byte-for-byte unchanged — it is a different contract, not covered by this migration.

## Testing

```bash
# Full plugin CI
make ci
```

## Performance

The retry state manager is implemented in Rust so the common retry decision path avoids Python bookkeeping overhead for normal structured tool results.
