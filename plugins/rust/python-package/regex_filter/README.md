# Regex Filter Plugin for CPEX

Rust-backed regex search and replace for prompt arguments, prompt messages, tool arguments, and tool results.

This package follows the same layout as the other Rust+Python CPEX plugins in this repository:

- Rust owns the matching and recursive data traversal
- Python keeps a minimal gateway-facing `Plugin` shim
- Tests cover both the Rust engine and the gateway hook surface

## Configuration

```yaml
config:
  words:
    - search: "\\bsecret\\b"
      replace: "[REDACTED]"
    - search: "\\d{3}-\\d{2}-\\d{4}"
      replace: "XXX-XX-XXXX"
```

## Development

From this plugin directory:

```bash
uv sync --dev
make install
make test-all
make check-all
```
