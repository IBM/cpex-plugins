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
- If `check_text_content` is enabled, the plugin falls back to Python-side payload inspection before applying retry policy.

## Returned Metadata

Both tool and resource hooks emit retry policy metadata so downstream systems can observe the active policy:

- `max_retries`
- `backoff_base_ms`
- `max_backoff_ms`
- `retry_on_status`

## Testing

```bash
# Full plugin CI
make ci
```

## Performance

The retry state manager is implemented in Rust so the common retry decision path avoids Python bookkeeping overhead for normal structured tool results.
