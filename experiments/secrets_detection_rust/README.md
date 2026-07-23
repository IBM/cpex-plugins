# secrets_detection_rust Spike

Experimental Rust-native CPEX 0.2.2 port of the secrets detection plugin.

This crate is intentionally isolated with its own `[workspace]` and
`rust-toolchain.toml`, so it does not inherit the root workspace dependency
policy or toolchain while we test the integration model.

## What This Proves

- A plugin factory can register one `HookHandler<CmfHook>` implementation under
  multiple `cmf.*` hook names by returning stage-bound handler entries.
- `ToolCall.arguments` and `PromptRequest.arguments` are JSON maps and can reuse
  the existing dotted field-filter semantics.
- `ToolResult.content` is `serde_json::Value`, so `tool_post_invoke` can use the
  same recursive JSON scanner.
- `Resource.content` is `Option<String>`, so `resource_post_fetch` maps to the
  old direct-text behavior where field filters are ignored.
- Native config parsing can deserialize `PluginConfig.config` into a Rust config
  struct and translate validation failures into `PluginError::Config`.

## CPEX 0.2.2 Gaps Found

- `PluginResult.metadata` is not propagated through `PluginManager`. In
  `cpex-core 0.2.2`, `erase_result` omits the metadata field when converting a
  typed result into the executor's erased result.
- A denied result cannot surface a redacted payload through `PluginManager`.
  The sequential executor handles denial before accepting modifications, and
  `PipelineResult::denied` sets `modified_payload` to `None`.

The direct handler can return both metadata and a redacted payload on block, but
those fields are lost at the manager/executor boundary in 0.2.2. Full parity
with the current Python-facing plugin needs framework support for those fields.

## Verification

```bash
cargo test
```

Current result: 45 tests pass.

## Manual Probe

The spike crate does not expose a CLI or Python entry point. To inspect it
manually, run the included example host. It registers the plugin factory, loads
CPEX YAML config, invokes one CMF hook, and prints the resulting
`PipelineResult`.

```bash
cargo run --example manual_probe
```

The default scenario is `tool-redact`. Available scenarios:

```bash
cargo run --example manual_probe -- tool-redact
cargo run --example manual_probe -- tool-block
cargo run --example manual_probe -- prompt-filter
cargo run --example manual_probe -- tool-result-filter
cargo run --example manual_probe -- resource-block
```

Use the printed `continue_processing`, `violation`, `metadata`, and payload
content to inspect the manager-level behavior. In CPEX 0.2.2, `metadata` is
expected to print as `None` through `PluginManager`, and denied results are
expected to print `modified_payload: none`.
