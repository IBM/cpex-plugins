# CLAUDE.md

## Git

- All commits must include a DCO sign-off line. Always use `git commit -s` (or pass `-s` when committing).

## Repository Structure

This is a monorepo of standalone plugin packages for the ContextForge Plugin Extensibility (CPEX) Framework. Each plugin lives in its own top-level directory with independent build configuration.

- Plugins are Rust+Python (PyO3/maturin) or pure Python.
- Each plugin has its own `pyproject.toml`, `Cargo.toml`, `Makefile`, and `tests/`.
- Package names follow the pattern `cpex-<plugin-name>` (e.g., `cpex-rate-limiter`).
- `mcpgateway` is a runtime dependency provided by the host gateway — never declare it in `pyproject.toml`.

## Build & Test

From within a plugin directory (e.g., `rate_limiter/`):

```bash
uv sync --dev              # Install Python dependencies
make install               # Build Rust extension and install into venv
make test-all              # Run Rust + Python tests
make check-all             # fmt-check + clippy + Rust tests
```

## Conventions

- Python: 3.11+, type hints, snake_case, Pydantic for config validation.
- Rust: stable toolchain, `cargo fmt`, `clippy -- -D warnings`.
- All source files must include Apache-2.0 SPDX license headers.
- Versions are defined in `Cargo.toml` and pulled dynamically by maturin (`dynamic = ["version"]`).

## Versioning

When bumping a plugin version, update all of these:

1. `Cargo.toml` — the single source of truth for the version number.
2. `cpex_<plugin>/plugin-manifest.yaml` — the `version` field.
3. `Cargo.lock` — updates automatically on the next build.

Tag releases as `<plugin>-v<version>` (e.g., `rate-limiter-v0.0.2`) on `main` to trigger the PyPI publish workflow.
