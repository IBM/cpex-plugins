# URL Reputation (Rust)

High-performance URL reputation and phishing detection for ContextForge and MCP Gateway.

## Features

- Domain allowlists and blocklists
- Regex allow and block patterns for path-level control
- Optional heuristic phishing checks for suspicious domains
- Entropy-based screening for machine-generated or deceptive hostnames
- Optional blocking of non-secure `http://` URLs
- Resource pre-fetch enforcement with fail-safe blocking on internal validation errors

## Build

```bash
make install
```

## Usage

The plugin validates URLs during `resource_pre_fetch`.

Typical uses:

- block known bad domains before fetch
- permit trusted domains even when broader rules would block them
- catch suspicious lookalike or high-entropy hostnames
- reject non-TLS HTTP fetches by default

## Configuration

- `whitelist_domains`: trusted domains and parent domains that should always pass
- `blocked_domains`: domains that should always fail
- `allowed_patterns`: regexes that bypass broader blocking rules
- `blocked_patterns`: regexes that force rejection
- `use_heuristic_check`: enable phishing-style hostname heuristics
- `entropy_threshold`: threshold for heuristic blocking of random-looking hostnames
- `block_non_secure_http`: reject plain HTTP URLs

## Validation Notes

- Domain matching is normalized to lowercase.
- Whitelist entries win over blocked-domain rules.
- Invalid regex patterns fail fast during configuration.
- Invalid URLs are blocked.
- If the Rust core throws unexpectedly, the plugin blocks the URL rather than allowing it through silently.

## Returned Violations

Blocked URLs use `URL_REPUTATION_BLOCK` and include basic context such as the URL being rejected.

## Testing

```bash
make ci
```

## Security Notes

- Heuristic checks are intentionally conservative and should complement explicit allow/block rules rather than replace them.
- IDN and lookalike-domain scenarios are best handled with a whitelist for critical providers plus heuristic checks for the long tail.
