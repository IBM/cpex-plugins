# Testing cpex-plugins

## Testing Architecture

Testing is split across two repositories to maintain clear separation of concerns:

### Unit Tests (cpex-plugins)

**Location**: `cpex-plugins/tests/` and plugin-specific `tests/` directories

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
make test-all  # Runs both Rust and Python tests
```

### Integration Tests (mcp-context-forge)

**Location**: `mcp-context-forge/tests/integration/`

**Scope**:
- Plugin integration with gateway framework
- Plugin loading and initialization
- Hook execution within framework
- Cross-plugin interactions
- Plugin lifecycle management

**Purpose**:
- Validate plugin behavior within the gateway
- Test framework-plugin contracts
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

Testing is split into two layers:

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

### 2. Plugin Tests

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

## Cross-Repository Testing Workflow

### Development Workflow

1. **Develop Plugin in cpex-plugins**:
   ```bash
   cd cpex-plugins/plugins/rust/python-package/<slug>
   # Implement plugin logic
   # Write unit tests in tests/
   make test-all
   ```

2. **Create PR in cpex-plugins**:
   - Include comprehensive unit tests
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

**When to Write Integration Tests (mcp-context-forge)**:
- Testing plugin loading and initialization
- Testing hook execution in framework
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

Whenever the Rust plugin CI workflow is triggered, it runs the repo contract tests before any plugin build jobs.

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
make test-all              # Run all plugin tests

# In mcp-context-forge
cd mcp-context-forge
pytest tests/integration/  # Run integration tests
pytest tests/e2e/          # Run E2E tests
```

### CI Pipeline

```bash
# cpex-plugins CI
make plugins-validate      # Validate repo structure
make plugin-test PLUGIN=<slug>  # Test specific plugin

# mcp-context-forge CI
make test                  # Run unit tests
pytest tests/integration/  # Run integration tests
pytest tests/e2e/          # Run E2E tests
```

## Debugging Test Failures

### Unit Test Failures (cpex-plugins)

1. Run tests locally: `make test-all`
2. Check Rust test output: `cargo test -- --nocapture`
3. Check Python test output: `pytest -v`
4. Use debugger: `rust-gdb` or `pdb`

### Integration Test Failures (mcp-context-forge)

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