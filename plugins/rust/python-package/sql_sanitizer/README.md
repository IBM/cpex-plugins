# SQL Sanitizer (Rust)

SQL security analysis plugin for ContextForge.

## Features

- Per-statement analysis: SQL payloads are split on `;` and each statement is
  checked independently so a `WHERE` clause in one statement cannot suppress a
  violation in another
- Blocked statement patterns: `DROP`, `TRUNCATE`, `ALTER`, `GRANT`, `REVOKE`
  (configurable)
- `DELETE FROM` and `UPDATE` without a `WHERE` clause detection
- Comment stripping: `--` line comments and `/* */` block comments are removed
  before analysis
- Field filtering: scan only named argument keys, or all string values when
  `fields` is unset
- Monitoring mode: pass through with `metadata.sql_issues` populated instead of
  blocking
- Interpolation heuristic: optional detection of `+`, `%.`, and `{…}` patterns

## Build

```bash
make install
```

## Runtime Requirements

This plugin depends on `cpex>=0.1.0,<0.2` and imports hook models from
`cpex.framework`. The compiled Rust extension is mandatory; there is no Python
fallback implementation.

## Usage

```python
from cpex_sql_sanitizer import SQLSanitizerPlugin
```

The plugin is automatically discovered by the gateway via the
`cpex.plugins` entry point registered in `pyproject.toml`.

### Configuration

| Key | Type | Default | Description |
|---|---|---|---|
| `fields` | `list[str] \| null` | `null` | Field names to scan; `null` scans all strings |
| `blocked_statements` | `list[str]` | `[]` | Additional regex patterns to block |
| `block_delete_without_where` | `bool` | `true` | Block `DELETE FROM` without `WHERE` |
| `block_update_without_where` | `bool` | `true` | Block `UPDATE` without `WHERE` |
| `strip_comments` | `bool` | `true` | Strip SQL comments before analysis |
| `require_parameterization` | `bool` | `false` | Flag non-parameterized SQL interpolation |
| `block_on_violation` | `bool` | `true` | Block request on violation; `false` = monitoring mode |

### Hook Signatures

```python
async def prompt_pre_fetch(
    self,
    payload: typing.Any,
    context: typing.Any,
    extensions: typing.Any = None,
) -> typing.Any: ...

async def tool_pre_invoke(
    self,
    payload: typing.Any,
    context: typing.Any,
    extensions: typing.Any = None,
) -> typing.Any: ...
```
