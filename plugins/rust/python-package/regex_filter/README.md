# Regex Filter Plugin for CPEX

Rust-backed regex search and replace for prompt arguments, prompt messages, tool arguments, and tool results.
Patterns use Rust `regex` syntax, which does not support look-around or backreferences.
Replacement strings use Rust `regex` expansion syntax (`$0`, `$1`, `$name`, `${name}`, and `$$` for a literal dollar).
Recursive filtering covers strings inside dicts and lists, plus Python tuples and sets; custom object attributes are left unchanged.

This package follows the same layout as the other Rust+Python CPEX plugins in this repository:

- Rust owns the matching and recursive data traversal
- Python keeps a minimal gateway-facing `Plugin` shim
- Tests cover both the Rust engine and the gateway hook surface

## Configuration

```yaml
plugins:
  - name: regex_filter
    kind: cpex_regex_filter.regex_filter.SearchReplacePlugin
    hooks:
      - prompt_pre_fetch
      - prompt_post_fetch
      - tool_pre_invoke
      - tool_post_invoke
    mode: enforce
    config:
      words:
        - search: "\\bsecret\\b"
          replace: "[REDACTED]"
        - search: "\\d{3}-\\d{2}-\\d{4}"
          replace: "XXX-XX-XXXX"
      max_text_bytes: 10485760
      max_total_text_bytes: 10485760
      max_nested_depth: 64
      max_collection_items: 4096
      max_total_items: 65536
      max_patterns: 1024
      max_search_bytes: 1048576
      max_replace_bytes: 1048576
      max_output_bytes: 10485760
```

## Development

From this plugin directory:

```bash
uv sync --dev
make install
make test-all
make check-all
```
