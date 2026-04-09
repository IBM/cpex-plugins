# Testing cpex-plugins

Testing is split into two layers:

## 1. Repo Contract Tests

These validate monorepo conventions and are enforced in CI before plugin builds run.

```bash
python3 -m unittest tests/test_plugin_catalog.py tests/test_install_built_wheel.py
python3 tools/plugin_catalog.py validate .
```

They verify:

- managed plugin location under `plugins/rust/python-package/`
- plugin manifests do not exist outside the managed root
- required files and package/module naming
- workspace membership in the top-level `Cargo.toml`
- version consistency between `Cargo.toml` and `plugin-manifest.yaml`
- manifest `kind` consistency (`module.object`) with `[project.entry-points."cpex.plugins"]` targets (`module:object`)
- repository metadata consistency
- changed-plugin detection for CI
- canonical release tag resolution

## 2. Plugin Tests

Each plugin has its own Rust and Python test suite.

```bash
cd plugins/rust/python-package/rate_limiter
uv sync --dev
make install
make test-all
```

Equivalent repo-level helper:

```bash
make plugin-test PLUGIN=rate_limiter
```

`make plugin-test` runs the selected plugin's `make ci` target, including stub verification, build, bench compilation without execution, install, and Python tests.

## CI Behavior

Whenever the Rust plugin CI workflow is triggered, it runs the repo contract tests before any plugin build jobs.

Per-plugin build/test jobs are then scoped by the plugin catalog:

- plugin-only changes run only the affected plugin jobs
- shared workflow, workspace, root orchestration, docs, test, and tool changes run all managed plugin jobs

Release CI validates the tag and plugin metadata before any artifact is published.
