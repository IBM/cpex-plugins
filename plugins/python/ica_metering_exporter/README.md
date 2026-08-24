# ICA Metering Exporter

Pure-Python CPEX plugin that exports MCP tool pre/post invocation metering to the ICA core-services endpoint. Ported from [IBM/mcp-context-forge PR #5696](https://github.com/IBM/mcp-context-forge/pull/5696).

## Features

- Records tool latency, result status, token counts, gateway identity, and transport.
- Resolves model attribution through a deterministic seven-level cascade.
- Attributes app, MCP client user agent, assistant, agent, and digital-IBMer context from inbound HTTP extensions.
- Authenticates with an HS256 service JWT, falling back to a static metering token.
- Awaits each export sequentially and treats export failures as best effort so tool execution continues.
- Is disabled by default.

## Configuration

| Key | Meaning |
|---|---|
| `enabled` | Enables client creation and export. Defaults to `false`. |
| `metering_url` | ICA metering endpoint URL. |
| `metering_token` | Static fallback token sent as `X-MCP-Metering-Token`. |
| `jwt_secret` | HS256 secret used to issue a one-day service JWT. Takes precedence over the static token. |
| `gateways[].id` | Gateway identifier for a per-gateway model fallback. |
| `gateways[].default_model` | Model fallback for the matching gateway identifier. |
| `global_default_model` | Last configured model fallback. |
| `include_model_source` | Adds the selected model-source label to the ICA payload. |

```yaml
plugins:
  - name: ica_metering_exporter
    kind: cpex_ica_metering_exporter.plugin.IcaMeteringExporterPlugin
    hooks: [tool_pre_invoke, tool_post_invoke]
    mode: sequential
    priority: 200
    config:
      enabled: false
      metering_url: "https://metering.example.invalid/events"
```

Supply tokens and JWT secrets through deployment environment/configuration secret injection; never commit them.

## Inbound headers and capability

Caller attribution reads only `extensions.http.headers`, using case-insensitive names. It never reads payload headers and never invents app or persona values when attribution headers are absent. Unit tests pass `Extensions` directly and therefore intentionally bypass gateway capability filtering.

Gateway registration **must grant `read_headers`** to this plugin. CPEX guards `HttpExtension`; without the capability the gateway strips inbound headers and attribution remains empty.

Recognized identity headers include `X-OpenWebUI-Model-Id`, `X-App-Id`, `X-MCP-Client-Name`, `X-MCP-Client-Version`, `X-Forwarded-User-Agent`, `User-Agent`, and the nine persona headers used by ICA/Open WebUI.

## Model precedence

The first available source wins:

1. `X-OpenWebUI-Model-Id` captured during pre-invoke
2. session `global_context.metadata.model_name`
3. `MCP_DEFAULT_MODEL`
4. tool-call `meta_data.model`
5. configured gateway `default_model`
6. configured `global_default_model`
7. unknown (`None`)

## OpenTelemetry metadata

When `extensions.request.trace_id` is non-empty, post-invoke returns:

```python
result.metadata["ica_metering_exporter"] = {
    "export_status": "sent",
    "latency_ms": 12,
    "model_source": "transport_header",
    "stage": "tool_post_invoke",
}
```

The trace ID is an input gate only and is never emitted. Metadata contains aggregated operational fields only—never tokens, headers, payloads, app IDs, user agents, persona data, arguments, or output.

## Registration mode

The export is awaited and best effort. Register the plugin in the framework's default `SEQUENTIAL` mode. `FIRE_AND_FORGET` discards hook return values and would therefore discard the returned OpenTelemetry metadata.

## Development

```bash
make sync
make check-all
make test
make build
```
