# AGENTS.md

## Git

- All commits must include a DCO sign-off line. Always use `git commit -s` (or pass `-s` when committing).

## Repository Structure

This is a monorepo of standalone plugin packages for the ContextForge Plugin Extensibility (CPEX) Framework. Each plugin lives in its own top-level directory with independent build configuration.

- Plugins are Rust+Python (PyO3/maturin) or pure Python.
- Each plugin has its own `pyproject.toml`, `Cargo.toml`, `Makefile`, and `tests/`.
- Package names follow the pattern `cpex-<plugin-name>` (e.g., `cpex-rate-limiter`).
- `mcpgateway` is a runtime dependency provided by the host gateway — never declare it in `pyproject.toml`.

## Testing Strategy

### Test Location by Type

- **Unit tests**: Located in `cpex-plugins/tests/`
  - Test individual plugin functionality in isolation
  - Fast, deterministic tests
  - Run during plugin development and CI
  - Scope: Plugin logic, Rust functions, Python bindings

- **Integration tests**: Located in `mcp-context-forge/tests/integration/`
  - Test plugin integration with the gateway framework
  - Test cross-plugin interactions
  - Test plugin lifecycle management
  - Scope: Plugin loading, hook execution, framework interaction

- **E2E tests**: Located in `mcp-context-forge/tests/e2e/`
  - Test complete workflows with plugins enabled
  - Test plugin behavior in realistic scenarios
  - Test multi-gateway plugin coordination
  - Scope: Full request/response cycles, real-world usage patterns

### Cross-Repository Testing Coordination

When developing a plugin:

1. Write unit tests in `cpex-plugins/tests/` alongside plugin code
2. Run local tests: `make test-all` from plugin directory
3. After plugin PR is merged, coordinate with `mcp-context-forge` team
4. Write integration/E2E tests in `mcp-context-forge/tests/`
5. Ensure both repositories' CI passes before release

See `mcp-context-forge/tests/AGENTS.md` for integration/E2E test conventions.

## Plugin Development Workflows

### Current Workflow: Rust + Python Hybrid

**Architecture:**
- Plugins implemented in Rust (core logic)
- Python entry point via PyO3/maturin bindings
- Published as Python packages to PyPI
- Loaded by Python-based plugin framework in gateway

**Why Python Entry Points?**
The plugin framework is currently implemented in Python (`mcpgateway/plugins/framework/`). Python entry points allow the framework to discover and load plugins dynamically. This is a transitional architecture.

**Development Steps:**

1. **Create Plugin** (in `cpex-plugins`):
   ```bash
   cd cpex-plugins
   make plugin-scaffold  # Interactive plugin generator
   ```

2. **Implement Plugin** (in `cpex-plugins/plugins/rust/python-package/<slug>/`):
   - Write Rust core logic in `src/`
   - Implement Python bindings in `cpex_<slug>/plugin.py`
   - Update `plugin-manifest.yaml`

3. **Write Unit Tests** (in `cpex-plugins/tests/`):
   ```bash
   cd plugins/rust/python-package/<slug>
   # Add Rust tests in src/
   # Add Python tests in tests/
   make test-all  # Run both Rust and Python tests
   ```

4. **Build and Install**:
   ```bash
   uv sync --dev
   make install  # Build Rust extension and install
   ```

5. **Create PR in cpex-plugins**:
   - Include unit tests
   - Ensure `make ci` passes
   - Tag release: `<slug>-v<version>`

6. **Integration Testing** (in `mcp-context-forge`):
   - Install plugin: `pip install cpex-<slug>`
   - Configure in `plugins/config.yaml`
   - Write integration tests in `tests/integration/`
   - Write E2E tests in `tests/e2e/`

7. **Release**:
   - Tag in cpex-plugins triggers PyPI publish
   - Update mcp-context-forge dependencies
   - Deploy with new plugin version

### Future Workflow: Pure Rust

**Architecture (Post-Framework Migration):**
- Plugins implemented in pure Rust
- Plugin framework migrated to Rust
- No Python entry points needed
- Direct Rust-to-Rust plugin loading
- Published to Cargo registry

**What Changes:**
- Remove `pyproject.toml` and maturin configuration
- Remove Python entry points (`cpex_<slug>/plugin.py`)
- Remove PyO3 bindings
- Pure Rust crate structure: `plugins/rust/<slug>/`
- Cargo-based dependency management

**Development Steps (Future):**

1. **Create Plugin** (in `cpex-plugins`):
   ```bash
   cd cpex-plugins
   cargo new --lib plugins/rust/<slug>
   ```

2. **Implement Plugin** (in `cpex-plugins/plugins/rust/<slug>/`):
   - Write Rust plugin in `src/lib.rs`
   - Implement plugin traits from Rust framework
   - Update `Cargo.toml`

3. **Write Unit Tests** (in `cpex-plugins/tests/`):
   ```bash
   cd plugins/rust/<slug>
   cargo test  # Run Rust tests
   ```

4. **Build**:
   ```bash
   cargo build --release
   ```

5. **Create PR in cpex-plugins**:
   - Include unit tests
   - Ensure `cargo test` passes
   - Version in `Cargo.toml`

6. **Integration Testing** (in `mcp-context-forge`):
   - Add plugin as Cargo dependency
   - Configure in Rust plugin framework
   - Write integration tests in `tests/integration/`
   - Write E2E tests in `tests/e2e/`

7. **Release**:
   - Publish to Cargo registry
   - Update mcp-context-forge `Cargo.toml`
   - Deploy with new plugin version

**Migration Timeline:**
- Current: Hybrid Rust + Python (transitional)
- Future: Pure Rust (after framework migration)
- Python components will be removed in future releases

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