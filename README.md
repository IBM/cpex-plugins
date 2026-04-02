# cpex-plugins

Monorepo for managed CPEX plugins that are implemented in Rust and published as Python packages.

## Layout

Managed plugins live under `plugins/rust/python-package/<slug>/`.

Current plugins:

- `rate_limiter`
- `pii_filter`

Each managed plugin must include:

- `pyproject.toml`
- `Cargo.toml`
- `Makefile`
- `README.md`
- `tests/`
- `cpex_<slug>/__init__.py`
- `cpex_<slug>/plugin-manifest.yaml`

Rust crates are owned by the top-level workspace in `Cargo.toml`. Python package names follow `cpex-<slug>`, Python modules follow `cpex_<slug>`, and release tags use the hyphenated slug form `<slug-with-hyphens>-v<version>`, for example `rate-limiter-v0.0.2`.

## Helper Commands

```bash
make plugins-list
make plugins-validate
make plugin-test PLUGIN=rate_limiter
```

The catalog and validator used by CI live in `tools/plugin_catalog.py`.
