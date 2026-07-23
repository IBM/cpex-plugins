# Crate Consumer Smoke Test

This is the Rust crate-level equivalent of the Python wheel-level smoke test.
It runs from a separate Cargo package and depends on the spike crate by relative
path:

```toml
secrets_detection_rust = { path = "../.." }
```

Run it from this directory:

```bash
cargo run
```

The smoke test uses only the crate's public exports:

```rust
use secrets_detection_rust::{SecretsDetectionFactory, KIND};
```

It verifies:

- an external Cargo consumer can compile against the spike crate
- invalid `field_allowlist` config is rejected at plugin load
- `cmf.tool_pre_invoke` can redact tool arguments
- `cmf.tool_pre_invoke` can block tool arguments
- `cmf.prompt_pre_fetch` applies field filters to prompt arguments
- `field_allowlist = ["accounts"]` scans and redacts `accounts.keep`
- `field_denylist = ["accounts.skip"]` excludes `accounts.skip`
- `cmf.tool_post_invoke` applies field filters to tool result JSON
- `cmf.resource_post_fetch` can block direct resource text
- fields outside the allowlist remain unchanged
- redaction does not mutate the original CMF payload
