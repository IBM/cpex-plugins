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

`make plugin-test` runs the selected plugin's `make ci` target, including stub verification, build, bench compilation where configured, install, and Python tests.

## 3. Rust Coverage

CI enforces at least 90% line coverage for each Rust plugin selected by the plugin catalog. The coverage job instruments Rust, runs Rust unit tests, then runs each plugin's repo-level Python integration tests so PyO3 paths are counted.

To run the same coverage check locally for all managed Rust plugins:

```bash
rustup component add llvm-tools-preview
cargo install cargo-llvm-cov --version 0.8.4 --locked
mkdir -p coverage
CARGO_PACKAGES="$(python3 tools/plugin_catalog.py ci-selection-field . all '' '' cargo_packages)"
PLUGINS="$(python3 tools/plugin_catalog.py ci-selection-field . all '' '' plugins)"
mapfile -t cargo_packages < <(python3 -c 'import json, os; [print(package) for package in json.loads(os.environ["CARGO_PACKAGES"])]')
mapfile -t plugins < <(python3 -c 'import json, os; [print(plugin) for plugin in json.loads(os.environ["PLUGINS"])]')
cargo_args=()
for package in "${cargo_packages[@]}"; do
  cargo_args+=("-p" "${package}")
done
cargo llvm-cov clean --workspace
eval "$(cargo llvm-cov show-env --sh)"
export CARGO_TARGET_DIR="${CARGO_LLVM_COV_TARGET_DIR}/llvm-cov-target"
export CARGO_LLVM_COV_BUILD_DIR="${CARGO_TARGET_DIR}"
export LLVM_PROFILE_FILE="${CARGO_TARGET_DIR}/cpex-plugins-%p-%10m.profraw"
mkdir -p "${CARGO_TARGET_DIR}"
for plugin in "${plugins[@]}"; do
  (cd "plugins/rust/python-package/${plugin}" && make sync && uv run maturin develop)
done
cargo test "${cargo_args[@]}"
for plugin in "${plugins[@]}"; do
  (cd "plugins/rust/python-package/${plugin}" && make test-integration)
done
env -u CARGO_TARGET_DIR -u CARGO_LLVM_COV_BUILD_DIR -u CARGO_LLVM_COV_TARGET_DIR -u LLVM_PROFILE_FILE cargo llvm-cov report "${cargo_args[@]}" --cobertura --output-path coverage/cobertura.xml
python3 tools/plugin_catalog.py coverage-check . coverage/cobertura.xml 90.00 "${PLUGINS}"
```

## CI Behavior

Repo contract tests run in their own CI workflow. The Rust plugin CI workflow uses the same plugin catalog to select affected plugin build, integration, and coverage jobs.

Per-plugin build/test jobs are then scoped by the plugin catalog:

- plugin-only changes run only the affected plugin jobs
- shared workflow, workspace, root orchestration, docs, test, and tool changes run all managed plugin jobs

Release CI validates the tag and plugin metadata before any artifact is published.
