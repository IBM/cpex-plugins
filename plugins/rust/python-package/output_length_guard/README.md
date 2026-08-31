# cpex-output-length-guard

Rust-backed output length guard plugin for MCP Gateway. Guards tool outputs by enforcing configurable minimum/maximum character or token limits, with either truncation or blocking strategies.

## Features

- **Character mode** (`limit_mode: "character"`): enforce min/max character counts
- **Token mode** (`limit_mode: "token"`): enforce min/max estimated token counts (using configurable `chars_per_token` ratio)
- **Truncate strategy**: shorten over-limit output, optionally at word boundaries, with configurable ellipsis
- **Block strategy**: return a `PluginViolation` to halt processing when limits are exceeded
- **Supported input shapes**:
  - Plain `str`
  - `dict` with a `text` field
  - `list[str]`
  - MCP content array: `[{"type": "text", "text": "..."}]`
  - MCP `CallToolResult` dict with `content` list (and optional `structuredContent`)
- **Numeric string preservation**: numeric values (integers, floats, scientific notation) pass through without modification
- **Security limits**: `max_text_length`, `max_structure_size`, `max_recursion_depth` prevent DoS from oversized inputs

## Configuration

```yaml
kind: "cpex_output_length_guard.output_length_guard.OutputLengthGuardPlugin"
available_hooks:
  - "tool_post_invoke"
config:
  min_chars: 0           # Minimum characters (0 = disabled)
  max_chars: 15000       # Maximum characters (null = disabled)
  min_tokens: 0          # Minimum estimated tokens (0 = disabled)
  max_tokens: null       # Maximum estimated tokens (null = disabled)
  chars_per_token: 4     # Characters per token estimate (1–10)
  limit_mode: "character"  # "character" or "token"
  strategy: "truncate"    # "truncate" or "block"
  ellipsis: "…"          # Appended on truncation (empty = none)
  word_boundary: false   # Truncate at word boundary
  max_text_length: 1000000    # Security: max bytes to process (1KB–10MB)
  max_structure_size: 10000   # Security: max items in list/dict (10–100K)
  max_recursion_depth: 100    # Security: max nesting depth (10–1000)
```

## Observability

When an OpenTelemetry trace is active (via `extensions.request.trace_id`), the plugin emits metrics to `result.metadata["output_length_guard"]`:

```python
result.metadata["output_length_guard"] = {
    "chars_seen": 42000,       # characters in the oversized content
    "truncated_count": 1,      # number of items truncated
    "blocked": False,          # True if blocked, False if truncated
    "limit_mode": "character", # enforcement mode used
    "strategy": "truncate",    # strategy applied
    "stage": "tool_post_invoke",
}
```

Metrics never contain raw output content — only counts, labels, and status indicators.

## Violation Codes

| Code | Description |
|------|-------------|
| `OUTPUT_LENGTH_VIOLATION` | String length outside configured bounds |
| `OUTPUT_TOKEN_VIOLATION`  | Estimated token count outside configured bounds |
| `STRUCTURE_SIZE_VIOLATION` | List/dict too large (security limit) |
| `STRUCTURE_DEPTH_VIOLATION` | Nesting too deep (security limit) |

## Development

```bash
uv sync --dev
make install          # Build Rust extension and install
make test-all         # Run Rust + Python tests
make test-integration # Run plugin-framework integration tests
make check-all        # fmt-check + clippy + Rust tests
```

## License

Apache-2.0
