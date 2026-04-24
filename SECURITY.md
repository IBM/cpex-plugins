# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest release | Yes |
| Older releases | No — update to the latest version |

Security fixes are applied to the latest release only. There are no backports to older versions.

## Reporting a Vulnerability

**Do not open a public issue for security vulnerabilities.**

Use GitHub's [private vulnerability reporting](https://github.com/IBM/cpex-plugins/security/advisories/new) to report security issues. This ensures the vulnerability can be assessed and addressed before public disclosure.

When reporting, please include:

- A description of the vulnerability and its potential impact.
- Steps to reproduce the issue.
- The affected plugin(s) and version(s).
- Any suggested mitigation or fix.

## Security Practices

### Supply Chain

- Rust dependencies are audited with [`cargo deny`](https://github.com/EmbarkStudios/cargo-deny). Rust+Python plugins share the workspace-level `deny.toml` configuration.
- Python dependencies are managed with `uv` and locked via `uv.lock`.
- GitHub Actions workflows use pinned action versions.

### Code Quality

- Rust code is checked with `clippy` (warnings treated as errors) and formatted with `rustfmt`.
- Python code is linted with Ruff and formatted with Black.
- All plugins include a test suite that runs on every PR.

### Build and Distribution

- Wheels are built in CI on GitHub-hosted runners and published to PyPI via trusted publishing (OIDC — no stored API tokens).
- Rust extensions use PyO3's `abi3` stable ABI to minimize binary compatibility issues.
- Release builds use `lto = "fat"`, `codegen-units = 1`, and `strip = true` for optimized, minimal binaries.

### Runtime

- Plugins are designed with fail-open semantics where appropriate (e.g., the rate limiter allows requests through on internal errors rather than blocking legitimate traffic). This is a deliberate trade-off documented in each plugin's source.
- Input validation is performed at plugin boundaries using Pydantic models.
- Rate strings and configuration are validated at startup; malformed config raises errors immediately rather than failing silently at runtime.

## Security Checklist for Plugin Authors

When contributing a new plugin:

- [ ] Validate all configuration at startup, not at request time.
- [ ] Do not store secrets in source code or configuration files.
- [ ] Use Pydantic models for configuration validation.
- [ ] Use the workspace-level `deny.toml` for Rust dependency auditing.
- [ ] Document any fail-open behavior and its trade-offs.
- [ ] Include security-relevant test cases (e.g., malformed input, boundary conditions).
- [ ] Ensure error messages do not leak internal state or sensitive information.

## Security Update Process

- Security patches are released as new versions as quickly as possible.
- Critical and high-severity issues: target fix within 1 week.
- Medium-severity issues: target fix within 2 weeks.
- Low-severity issues: addressed in the next regular release.

These are best-effort targets, not SLAs.
