# Testing cpex-plugins

## Testing Architecture

Testing spans two repositories. `cpex-plugins` owns unit tests and plugin-framework integration tests; `mcp-context-forge` owns gateway integration and E2E tests.

### Unit Tests (cpex-plugins)

**Location**: Within each plugin's own directory
- Python: `plugins/rust/python-package/<slug>/tests/` (current hybrid) or `plugins/python/<slug>/tests/` (pure Python)
- Rust: inline `mod tests` within source files (e.g., `src/lib.rs`)

**Scope**:
- Individual plugin functionality in isolation
- Rust core logic and functions
- Python bindings and entry points
- Plugin configuration validation
- Fast, deterministic tests

**Purpose**:
- Provide fast feedback during plugin development
- Validate plugin logic independently of the gateway
- Ensure plugin contracts are met
- Test edge cases and error handling

**Run Locally**:
```bash
cd plugins/rust/python-package/<slug>
make test-all  # Runs both Rust and Python unit tests
```

### Plugin-Framework Integration Tests (cpex-plugins)

**Location**: `cpex-plugins/tests/` (plugin-specific `tests/` directories)

**Scope**:
- PyO3 entry points and Python ↔ Rust interface
- Plugin loading by the Python plugin framework
- Hook dispatch through the framework layer
- Coverage of PyO3 paths (run as part of Rust coverage)

**Purpose**:
- Validate that the Rust implementation is correctly exposed through PyO3 bindings
- Ensure the plugin framework can discover, load, and invoke the plugin
- Keep PyO3 code paths covered without requiring a full gateway

**Run Locally**:
```bash
cd plugins/rust/python-package/<slug>
make test-integration  # Runs plugin-framework integration tests
```

### Gateway Integration Tests (mcp-context-forge)

**Location**: `mcp-context-forge/tests/integration/`

**Scope**:
- Plugin integration with the full gateway
- Plugin loading and initialization in gateway context
- Hook execution within the gateway framework
- Cross-plugin interactions
- Plugin lifecycle management

**Purpose**:
- Validate plugin behavior within the gateway
- Test framework-plugin contracts at the gateway level
- Ensure plugins work together correctly
- Test plugin configuration and registration

**Run Locally**:
```bash
cd mcp-context-forge
pytest tests/integration/
```

### E2E Tests (mcp-context-forge)

**Location**: `mcp-context-forge/tests/e2e/`

**Scope**:
- Complete request/response workflows
- Realistic usage scenarios
- Multi-gateway plugin coordination
- Performance and load testing with plugins

**Purpose**:
- Validate end-to-end functionality
- Test real-world usage patterns
- Ensure system-level correctness
- Catch integration issues

**Run Locally**:
```bash
cd mcp-context-forge
pytest tests/e2e/
```

## Testing Layers

`cpex-plugins` has three local testing layers. Gateway integration and E2E tests live in `mcp-context-forge`.

### 1. Repo Contract Tests

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

### 2. Plugin Unit Tests

Each plugin has its own Rust and Python unit test suite.

```bash
cd plugins/rust/python-package/rate_limiter
uv sync --dev
cargo install cargo-nextest --version 0.9.133 --locked
make install
make test-all
```

Set `NEXTEST_PROFILE=ci` to use the repository CI profile locally. The CI profile is defined in `.config/nextest.toml`; it disables fail-fast so all Rust test failures are reported in one run.

Equivalent repo-level helper:

```bash
make plugin-test PLUGIN=rate_limiter
```

`make plugin-test` runs the selected plugin's `make ci` target, including stub verification, build, bench compilation where configured, install, and Python tests.

### 3. Plugin-Framework Integration Tests

Each plugin also has integration tests between the plugin and the Python plugin framework. These live in the plugin's `tests/` directory alongside unit tests and test the PyO3 interface — ensuring the Rust implementation is correctly exposed through Python bindings and that the framework can discover, load, and invoke the plugin.

```bash
cd plugins/rust/python-package/rate_limiter
make test-integration
```

These tests are distinct from gateway integration tests in `mcp-context-forge`: they exercise the plugin ↔ framework boundary within this repository, without requiring a running gateway.

## 4. Rust Coverage

CI enforces at least 90% line coverage for each Rust plugin selected by the plugin catalog. The coverage job instruments Rust, runs Rust unit tests, then runs each plugin's repo-level Python integration tests so PyO3 paths are counted.

To run the same coverage check locally for all managed Rust plugins:

```bash
rustup component add llvm-tools-preview
cargo install cargo-llvm-cov --version 0.8.4 --locked
cargo install cargo-nextest --version 0.9.133 --locked
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
cargo llvm-cov nextest --no-report "${cargo_args[@]}" -P ci
eval "$(cargo llvm-cov show-env --sh)"
export CARGO_TARGET_DIR="${CARGO_LLVM_COV_TARGET_DIR}/llvm-cov-target"
export CARGO_LLVM_COV_BUILD_DIR="${CARGO_TARGET_DIR}"
export LLVM_PROFILE_FILE="${CARGO_TARGET_DIR}/cpex-plugins-%p-%10m.profraw"
mkdir -p "${CARGO_TARGET_DIR}"
for plugin in "${plugins[@]}"; do
  (cd "plugins/rust/python-package/${plugin}" && make sync && uv run maturin develop)
done
for plugin in "${plugins[@]}"; do
  (cd "plugins/rust/python-package/${plugin}" && make test-integration)
done
env -u CARGO_TARGET_DIR -u CARGO_LLVM_COV_BUILD_DIR -u CARGO_LLVM_COV_TARGET_DIR -u LLVM_PROFILE_FILE cargo llvm-cov report "${cargo_args[@]}" --cobertura --output-path coverage/cobertura.xml
python3 tools/plugin_catalog.py coverage-check . coverage/cobertura.xml 90.00 "${PLUGINS}"
```

Rust unit tests use `cargo nextest run`. Coverage uses `cargo llvm-cov nextest --no-report` for the Rust test phase, then runs pytest before generating the final report so PyO3 paths stay covered. CI uses the `ci` nextest profile, which disables fail-fast and prints failure output immediately and again at the end. Nextest does not run Rust doctests; this repo currently has no Rust doctest code blocks, so there is no separate doctest step.

Criterion benchmarks are verified in CI with `cargo nextest run --benches -E 'kind(bench)' --no-run`, which compiles benchmark test targets without rerunning normal unit tests or collecting noisy performance measurements on shared CI runners.

## 5. Mutation Testing

Mutation testing runs in PR CI on Ubuntu for Rust code touched by the pull request diff. It is also available locally through cargo-mutants and runs Rust tests with nextest.

```bash
cargo install cargo-nextest --version 0.9.133 --locked
cargo install cargo-mutants --version 27.0.0 --locked
make plugin-mutants-list PLUGIN=retry_with_backoff
make plugin-mutants PLUGIN=retry_with_backoff
```

`.cargo/mutants.toml` sets `test_tool = "nextest"`, selects the `mutants` nextest profile, and keeps `cap_lints = false` so Rust warnings are not downgraded during mutant builds. The `mutants` profile keeps fail-fast enabled because cargo-mutants only needs one failing test to mark a mutant as caught. CI installs `cargo-mutants` with `cargo install cargo-mutants --version 27.0.0 --locked` and runs `cargo mutants "${cargo_args[@]}"`, using `--in-diff cargo-mutants.diff` for Rust source changes and full-package mutation for mutation-tooling config changes.

## Cross-Repository Testing Workflow

### Development Workflow

1. **Develop Plugin in cpex-plugins**:
   ```bash
   cd cpex-plugins/plugins/rust/python-package/<slug>
   # Implement plugin logic
   # Write unit tests in tests/
   # Write plugin-framework integration tests in tests/
   make test-all          # Run unit tests
   make test-integration  # Run plugin-framework integration tests
   ```

2. **Create PR in cpex-plugins**:
   - Include unit tests and plugin-framework integration tests
   - Ensure `make ci` passes
   - Get PR reviewed and merged

3. **Coordinate with mcp-context-forge**:
   - Notify mcp-context-forge team of new plugin
   - Discuss integration test requirements
   - Plan E2E test scenarios

4. **Write Integration Tests in mcp-context-forge**:
   ```bash
   cd mcp-context-forge
   # Install plugin: pip install cpex-<slug>
   # Configure in plugins/config.yaml
   # Write tests in tests/integration/
   pytest tests/integration/
   ```

5. **Write E2E Tests in mcp-context-forge**:
   ```bash
   cd mcp-context-forge
   # Write tests in tests/e2e/
   pytest tests/e2e/
   ```

6. **Create PR in mcp-context-forge**:
   - Include integration and E2E tests
   - Ensure all tests pass
   - Get PR reviewed and merged

7. **Release**:
   - Tag plugin in cpex-plugins: `<slug>-v<version>`
   - Update mcp-context-forge dependencies
   - Deploy with new plugin version

### Testing Coordination Guidelines

**When to Write Unit Tests (cpex-plugins)**:
- Testing plugin logic in isolation
- Testing Rust functions and algorithms
- Testing Python bindings
- Testing configuration validation
- Testing error handling and edge cases

**When to Write Plugin-Framework Integration Tests (cpex-plugins)**:
- Testing PyO3 entry points end-to-end
- Testing plugin loading by the Python framework
- Testing hook dispatch through the framework layer
- Ensuring PyO3 paths are covered in Rust coverage

**When to Write Gateway Integration Tests (mcp-context-forge)**:
- Testing plugin loading and initialization in the gateway
- Testing hook execution in the full gateway framework
- Testing plugin interactions with gateway services
- Testing cross-plugin behavior
- Testing plugin lifecycle (enable/disable/reload)

**When to Write E2E Tests (mcp-context-forge)**:
- Testing complete request/response flows
- Testing realistic usage scenarios
- Testing performance with plugins enabled
- Testing multi-gateway coordination
- Testing production-like configurations

### CI Coordination

**cpex-plugins CI**:
- Runs repo contract tests
- Runs plugin unit tests
- Runs plugin-framework integration tests (`make test-integration`)
- Builds and packages plugins
- Publishes to PyPI on release tags

**mcp-context-forge CI**:
- Runs integration tests with latest plugin versions
- Runs E2E tests with plugins enabled
- Validates plugin compatibility
- Tests plugin upgrades

### Test Coverage Expectations

**Unit Tests (cpex-plugins)**:
- Aim for >90% code coverage of plugin logic
- Cover all public APIs and entry points
- Test error paths and edge cases
- Fast execution (<1 second per test)

**Integration Tests (mcp-context-forge)**:
- Cover all plugin hooks
- Test plugin configuration variations
- Test plugin interactions
- Moderate execution time (<5 seconds per test)

**E2E Tests (mcp-context-forge)**:
- Cover critical user workflows
- Test realistic scenarios
- Test performance characteristics
- Slower execution acceptable (seconds to minutes)

## CI Behavior

Repo contract tests run in their own CI workflow. The Rust plugin CI workflow uses the same plugin catalog to select affected plugin build, integration, and coverage jobs.

Per-plugin build/test jobs are then scoped by the plugin catalog:

- plugin-only changes run only the affected plugin jobs
- shared workflow, workspace, root orchestration, docs, test, and tool changes run all managed plugin jobs

Release CI validates the tag and plugin metadata before any artifact is published.

## Testing Best Practices

### Unit Tests

- **Fast**: Each test should complete in milliseconds
- **Isolated**: No external dependencies (network, filesystem, database)
- **Deterministic**: Same input always produces same output
- **Focused**: Test one thing per test
- **Clear**: Test names describe what is being tested

### Integration Tests

- **Realistic**: Use actual gateway framework components
- **Scoped**: Test specific integration points
- **Stable**: Use test fixtures and mocks for external services
- **Documented**: Explain what integration is being tested

### E2E Tests

- **Complete**: Test full workflows from start to finish
- **Representative**: Use realistic data and scenarios
- **Robust**: Handle timing and async operations correctly
- **Maintainable**: Use page objects and test helpers

## Running Tests

### Local Development

```bash
# In cpex-plugins
cd plugins/rust/python-package/<slug>
make test-all              # Run unit tests (Rust + Python)
make test-integration      # Run plugin-framework integration tests

# In mcp-context-forge
cd mcp-context-forge
pytest tests/integration/  # Run gateway integration tests
pytest tests/e2e/          # Run E2E tests
```

### CI Pipeline

```bash
# cpex-plugins CI
make plugins-validate           # Validate repo structure
make plugin-test PLUGIN=<slug>  # Run unit tests for specific plugin
# make test-integration is run as part of the coverage job

# mcp-context-forge CI
make test                  # Run unit tests
pytest tests/integration/  # Run gateway integration tests
pytest tests/e2e/          # Run E2E tests
```

## Debugging Test Failures

### Unit Test Failures (cpex-plugins)

1. Run tests locally: `make test-all`
2. Check Rust test output: `cargo test -- --nocapture`
3. Check Python test output: `pytest -v`
4. Use debugger: `rust-gdb` or `pdb`

### Plugin-Framework Integration Test Failures (cpex-plugins)

1. Run tests locally: `make test-integration`
2. Check PyO3 binding output: `pytest -v tests/`
3. Verify Rust extension is built: `make install`
4. Check framework loading: `pytest -vv tests/`

### Gateway Integration Test Failures (mcp-context-forge)

1. Check plugin installation: `pip list | grep cpex`
2. Verify plugin configuration: `cat plugins/config.yaml`
3. Check gateway logs: `tail -f logs/gateway.log`
4. Run with verbose output: `pytest -vv tests/integration/`

### E2E Test Failures (mcp-context-forge)

1. Check full system logs
2. Verify all services are running
3. Check network connectivity
4. Run with debug logging: `LOG_LEVEL=DEBUG pytest tests/e2e/`

## Test Documentation

For detailed testing conventions in mcp-context-forge, see:
- `mcp-context-forge/tests/AGENTS.md` - Testing conventions and workflows
- `mcp-context-forge/plugins/AGENTS.md` - Plugin framework testing

## Future: Pure Rust Testing

After the plugin framework is migrated to Rust:

### Unit Tests (cpex-plugins)

```bash
cd plugins/rust/<slug>
cargo test                 # Run Rust tests
cargo test -- --nocapture  # With output
```

### Integration Tests (mcp-context-forge)

```bash
cd mcp-context-forge
cargo test --test integration  # Run integration tests
```

### E2E Tests (mcp-context-forge)

```bash
cd mcp-context-forge
cargo test --test e2e      # Run E2E tests
```

Python test infrastructure will be removed after framework migration.