# AGENTS.md

## Git

- All commits must include a DCO sign-off line. Always use `git commit -s` (or pass `-s` when committing).

## Repository Structure

This is a monorepo of standalone plugin packages for the ContextForge Plugin Extensibility (CPEX) Framework. Each plugin lives in its own top-level directory with independent build configuration.

- Plugins are implemented as **pure Python** or **pure Rust**. Each plugin uses one language for its core logic — there is no dual-path where a plugin ships both Rust and Python implementations with a Rust fallback. For Rust plugins, Python entry points (PyO3/maturin) are a packaging and distribution layer only, not a parallel implementation.
- Each plugin has its own `pyproject.toml`, `Cargo.toml`, `Makefile`, and `tests/`.
- Package names follow the pattern `cpex-<plugin-name>` (e.g., `cpex-rate-limiter`).
- `mcpgateway` is a runtime dependency provided by the host gateway — never declare it in `pyproject.toml`.

## Testing Strategy

### Test Location by Type

- **Unit tests**: Located within each plugin's own directory
  - Python: `plugins/rust/python-package/<slug>/tests/` (current hybrid) or `plugins/python/<slug>/tests/` (pure Python)
  - Rust: inline `mod tests` within source files (e.g., `src/lib.rs`)
  - Test individual plugin functionality in isolation
  - Fast, deterministic tests
  - Run during plugin development and CI
  - Scope: Plugin logic, Rust functions, Python bindings

- **Plugin-framework integration tests**: Located in `plugins/rust/python-package/<slug>/tests/`
  - Test plugin integration with the local plugin framework (PyO3 bindings, Python ↔ Rust interface)
  - Run via `make test-integration` within the plugin directory
  - Scope: PyO3 entry points, plugin loading by the Python framework, hook dispatch

- **Gateway integration tests**: Located in `mcp-context-forge/tests/integration/`
  - Test plugin integration with the full gateway
  - Test cross-plugin interactions
  - Test plugin lifecycle management
  - Scope: Plugin loading in gateway context, hook execution, framework interaction

- **E2E tests**: Located in `mcp-context-forge/tests/e2e/`
  - Test complete workflows with plugins enabled
  - Test plugin behavior in realistic scenarios
  - Test multi-gateway plugin coordination
  - Scope: Full request/response cycles, real-world usage patterns

### Cross-Repository Testing Coordination

When developing a plugin:

1. Write unit tests in the plugin's own directory (Rust: inline `mod tests`; Python: `plugins/rust/python-package/<slug>/tests/`) and plugin-framework integration tests in `plugins/rust/python-package/<slug>/tests/`
2. Run local tests: `make test-all` and `make test-integration` from plugin directory
3. After plugin PR is merged, coordinate with `mcp-context-forge` team
4. Write gateway integration/E2E tests in `mcp-context-forge/tests/`
5. Ensure both repositories' CI passes before release

See `mcp-context-forge/tests/AGENTS.md` for integration/E2E test conventions.

## Plugin Development Workflows

### Current Workflow: Rust + Python Hybrid

**Architecture:**
- Plugin logic implemented entirely in Rust — no Python fallback implementation
- Python entry points (PyO3/maturin) are a packaging and distribution layer only
- Published as Python packages to PyPI
- Loaded by Python-based plugin framework in gateway

**Why Python Entry Points?**
The plugin framework is currently implemented in Python (`mcpgateway/plugins/framework/`). Python entry points allow the framework to discover and load plugins dynamically. This is a transitional packaging layer — all plugin logic remains in Rust. This is not a dual-path architecture.

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

3. **Write Tests**:
   ```bash
   cd plugins/rust/python-package/<slug>
   # Add Rust unit tests inline in src/ using mod tests
   # Add Python unit tests in tests/
   # Add plugin-framework integration tests in tests/ (run via make test-integration)
   make test-all          # Run Rust + Python unit tests
   make test-integration  # Run plugin-framework integration tests
   ```

4. **Build and Install**:
   ```bash
   uv sync --dev
   make install  # Build Rust extension and install
   ```

5. **Create PR in cpex-plugins**:
   - Include unit tests and plugin-framework integration tests
   - Ensure `make ci` passes
   - Tag release: `<slug>-v<version>`

6. **Gateway Integration Testing** (in `mcp-context-forge`):
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

3. **Write Unit Tests** (inline `mod tests` in source files):
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

Every change to a core plugin must include a plugin version bump.

When bumping a plugin version, update all of these:

1. `Cargo.toml` — the single source of truth for the version number.
2. `cpex_<plugin>/plugin-manifest.yaml` — the `version` field.
3. `Cargo.lock` — updates automatically on the next build.

Tag releases as `<plugin>-v<version>` (e.g., `rate-limiter-v0.0.2`) on `main` to trigger the PyPI publish workflow.