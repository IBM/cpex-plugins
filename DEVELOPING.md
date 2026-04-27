# Developing cpex-plugins

## Repository Model

This repository currently manages one plugin class: Rust plugins that are built with PyO3/maturin and published to PyPI as Python packages.

Managed plugin path:

```text
plugins/rust/python-package/<slug>/
```

Every managed plugin must satisfy the catalog contract enforced by `tools/plugin_catalog.py`:

- distribution name: `cpex-<slug>`
- Python module: `cpex_<slug>`
- `Cargo.toml` is the version source of truth
- `cpex_<slug>/plugin-manifest.yaml` version matches `Cargo.toml`
- `cpex_<slug>/plugin-manifest.yaml` defines top-level `kind` in `module.object` form
- `pyproject.toml` publishes the matching plugin class reference under `[project.entry-points."cpex.plugins"]` in `module:object` form
- plugin `Cargo.toml` repository metadata points to `https://github.com/IBM/cpex-plugins`
- plugin crate is listed in the top-level workspace `Cargo.toml`

## Working on One Plugin

```bash
cd plugins/rust/python-package/rate_limiter
uv sync --dev
make install
make test-all
```

Swap `rate_limiter` for any other managed plugin slug.

## Repo-Level Commands

```bash
make plugins-list
make plugins-validate
make plugin-test PLUGIN=pii_filter
```

`make plugins-validate` runs the same convention checks that the repo contract CI workflow runs.
It runs the catalog validator plus the shared repo contract test modules:
`tests/test_plugin_catalog.py` and `tests/test_install_built_wheel.py`.

## Adding a New Managed Plugin

1. Create `plugins/rust/python-package/<slug>/`.
2. Add the required files and package/module names that match the slug conventions.
3. Add the crate path to the workspace `members` list in the top-level `Cargo.toml`.
4. Run `make plugins-validate`.
5. Run `make plugin-test PLUGIN=<slug>` to execute the plugin's full `make ci` flow.

## Releasing

Releases are per plugin and tag-driven:

Release tags must use the hyphenated plugin slug, not the directory/module underscore form:

```bash
git tag rate-limiter-v0.0.2
git tag pii-filter-v0.1.0
```

The release workflow resolves the tag back to the managed plugin path, validates metadata and versions, then builds and publishes only that plugin.
