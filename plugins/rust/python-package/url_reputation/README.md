# URL Reputation (Rust)

Static URL policy checks for ContextForge and MCP Gateway resource fetches.

## Features

- Blocks resource fetches before execution with the `resource_pre_fetch` hook
- Allows trusted domains or URL regex patterns to bypass later checks
- Blocks configured domains, subdomains, or URL regex patterns
- Blocks non-HTTPS URLs by default
- Optional domain heuristics for high entropy, static IANA TLD validity, and Unicode security
- Case-insensitive domain normalization for allowlist and blocklist entries
- Pure static policy checks; no external reputation provider or threat-intel feed calls

## Build

```bash
make install
```

## Runtime Requirements

This plugin depends on `cpex>=0.1.0,<0.2` and imports hook models from `cpex.framework`. The compiled Rust extension is mandatory; there is no Python fallback implementation.

## Usage

The plugin runs on `resource_pre_fetch` before a resource URI is fetched.

Typical uses:

- block known bad domains and subdomains
- allow trusted internal URL patterns before enforcing HTTPS
- reject insecure `http://` resource fetches
- enable lightweight domain heuristics for suspicious generated or Unicode domains

## Configuration

```yaml
config:
  whitelist_domains:
    - "example.com"
  allowed_patterns:
    - "^https://trusted\\.internal/.*"
  blocked_domains:
    - "malicious.example.com"
  blocked_patterns:
    - "casino"
    - "crypto"
  use_heuristic_check: false
  entropy_threshold: 3.65
  block_non_secure_http: true
```

| Field | Type | Default | Description |
|---|---|---|---|
| `whitelist_domains` | set | `[]` | Domains and subdomains that bypass remaining checks |
| `allowed_patterns` | list | `[]` | Regexes matched against the full trimmed URL; a match bypasses remaining checks |
| `blocked_domains` | set | `[]` | Domains and subdomains that are always blocked unless allowlisted first |
| `blocked_patterns` | list | `[]` | Regexes matched against the full trimmed URL; a match blocks the request |
| `use_heuristic_check` | bool | `false` | Enable entropy, TLD, and Unicode domain checks for non-IP hosts |
| `entropy_threshold` | float | `3.65` | Maximum allowed Shannon entropy for the domain |
| `block_non_secure_http` | bool | `true` | Block URLs whose scheme is not `https` |

## Logic Workflow

1. Trim and parse the URL.
2. Extract the host/domain.
3. Detect IPv4 or IPv6 hosts so domain heuristics can be skipped.
4. Allow exact or parent-domain matches in `whitelist_domains`.
5. Allow matches in `allowed_patterns`; this also bypasses HTTPS enforcement.
6. Block non-HTTPS schemes when `block_non_secure_http=true`.
7. Block exact or parent-domain matches in `blocked_domains`.
8. Block matches in `blocked_patterns`.
9. If heuristics are enabled for a non-IP host, block high-entropy domains, illegal static TLDs, or unsafe Unicode domains.

## Returned Metadata

Allowed URLs return `continue_processing=true`.

Blocked URLs return `continue_processing=false` with a `PluginViolation` using code `URL_REPUTATION_BLOCK`. Violation details include the URL or domain involved in the decision.

## Limitations

- Reputation data is static configuration only; there are no external provider lookups.
- The IANA TLD list is compiled into the plugin and can lag newly delegated TLDs.
- `allowed_patterns` intentionally runs before HTTPS enforcement, so trusted patterns can allow `http://` URLs.
- IP addresses skip domain heuristics.

## Testing

```bash
make ci
```
