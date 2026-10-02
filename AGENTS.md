# AGENTS.md

## Git

- All commits must include a DCO sign-off line. Always use `git commit -s` (or pass `-s` when committing).

## Repository Structure

This is a monorepo of standalone plugin packages for the ContextForge Plugin Extensibility (CPEX) Framework. Each plugin lives in its own top-level directory with independent build configuration.

- Plugins are implemented as **pure Python** or **pure Rust**. Each plugin uses one language for its core logic — there is no dual-path where a plugin ships both Rust and Python implementations with a Rust fallback. For Rust plugins, Python entry points (PyO3/maturin) are a packaging and distribution layer only, not a parallel implementation.
- Rust plugins live in `plugins/rust/python-package/<slug>/`; realized pure-Python plugins live in `plugins/python/<slug>/`.
- Every plugin has its own `pyproject.toml`, `Makefile`, package directory, and unit tests. Rust plugins additionally have `Cargo.toml` and Rust source files.
- Package names follow the pattern `cpex-<plugin-name>` (e.g., `cpex-rate-limiter`).
- `cpex` is the framework runtime dependency; declare it in plugin `pyproject.toml`.

## Testing Strategy

Keep a test when it protects an observable plugin decision, a language/framework
boundary, a release contract, a security policy, or a concrete regression.
Before adding one, identify the failure it should catch and check whether an
existing test already catches it. Test behavior at the lowest layer that owns it.

- Rust algorithms and policy decisions: inline Rust tests in the plugin crate.
- Pure-Python logic: `plugins/python/<slug>/tests/`.
- Python/Rust binding and hook behavior: `plugins/tests/<slug>/`. Existing
  plugins use this shared harness; it supplies controlled hook models and is
  not a full gateway. The scaffolder emits plugin-local Python hook smoke tests.
- Catalog and wheel tooling behavior: `tests/`, using temporary fixture repos.
- Repository security policies: `tests/test_repository_policy.py`.
- Built-package installation: release workflows, outside the source tree.
- Full gateway and cross-plugin workflows: `mcp-context-forge/tests/integration/`
  and `mcp-context-forge/tests/e2e/`.

Do not add tests for exact workflow/Makefile text, documentation wording,
private module layout, generated stub formatting, standard-library behavior,
or generic Pydantic serialization. Build, lint, type-check, and artifact jobs
own those checks. Never commit tests whose only outcome is `pass`, `hasattr`,
or a constructor returning a non-null object.

Use table-driven cases for distinct input classes and failure policies. Avoid
replaying a Rust algorithm's whole input matrix through Python; Python tests
should catch conversion, payload isolation, hook results, and error mapping.
Retain Redis failure/TLS tests and detection/redaction/privacy regressions:
these exercise real operational and security behavior.

Run `make plugins-validate` for repository tooling. For plugin changes, run
`make test-all`, `make test-integration`, and the plugin's `make ci` target as
appropriate. See [TESTING.md](TESTING.md) for commands and the keep/remove decisions.

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
   # Add Python boundary tests in plugins/tests/<slug>/
   # Extend existing tests for changed behavior
   make test-all          # Run Rust tests and Python hook tests
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

### Current Workflow: Pure Python

Pure-Python plugins implement their logic directly in Python under `plugins/python/<slug>/`; they are independent implementations, not fallbacks for Rust plugins.

1. Create the plugin directory and required package files under `plugins/python/<slug>/`.
2. Implement the plugin in `cpex_<slug>/` and keep `plugin-manifest.yaml` aligned with the package entry point.
3. Add unit tests under `plugins/python/<slug>/tests/` and plugin-framework integration tests under `plugins/tests/<slug>/`.
4. Run the local workflow:
   ```bash
   cd plugins/python/<slug>
   uv sync --dev
   make test-all
   make test-integration
   ```
5. Run `make ci`, then release with the standard `<slug>-v<version>` tag after review.

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

From within a Rust plugin directory (e.g., `rate_limiter/`):

```bash
uv sync --dev              # Install Python dependencies
make install               # Build Rust extension and install into venv
make test-all              # Run Rust + Python tests
make check-all             # fmt-check + clippy + Rust tests
```

From within a pure-Python plugin directory:

```bash
uv sync --dev
make test-all              # Run unit and plugin-framework integration tests
make check-all             # Run formatting, lint, and type checks
```

## Conventions

- Python: 3.11+, type hints, snake_case, Pydantic for config validation.
- Rust: stable toolchain, `cargo fmt`, `clippy -- -D warnings`.
- All source files must include Apache-2.0 SPDX license headers.
- Rust versions are defined in `Cargo.toml` and pulled dynamically by maturin (`dynamic = ["version"]`); pure-Python versions are defined in the plugin's `pyproject.toml`.

## Versioning

Every change to a core plugin must include a plugin version bump.

The version source and lockfile depend on the implementation language:

- **Rust**: `Cargo.toml` is the single source of truth; update `Cargo.lock` and make the `cpex_<plugin>/plugin-manifest.yaml` version match.
- **Pure Python**: the plugin's `pyproject.toml` is the single source of truth; regenerate the root `uv.lock` and make the `cpex_<plugin>/plugin-manifest.yaml` version match. Pure-Python workspace members do not have member-local `uv.lock` files.

Tag releases as `<plugin>-v<version>` on `main` to trigger the language-appropriate PyPI publish workflow. Examples are `rate-limiter-v0.0.2` and `ica-metering-exporter-v0.1.0`.

## OpenTelemetry Integration and Trace Context

### Trace-In / Metrics-Out Convention

Plugins can accept and respond to OpenTelemetry trace context through the optional `extensions` parameter on all hook signatures:

**Hook Signature Convention:**
```python
def my_hook(
    self,
    payload: typing.Any,
    context: typing.Any,
    extensions: typing.Any = None
) -> typing.Any: ...
```

**Trace Context Input (`extensions` parameter):**
- The `extensions` parameter carries OpenTelemetry trace context, including `extensions.request.trace_id` for associating operations with the current request trace.
- Other fields such as `span_id` may be available on the Extensions object but are not currently consumed by the pii_filter plugin.
- The parameter is optional and defaults to `None` for backward compatibility.

**Metrics Output (`result.metadata` namespacing):**
- Plugins emit operational metrics and observability data via `result.metadata[<plugin-name>]` using a namespaced key (e.g., `result.metadata["pii_filter"]`).
- Metrics are **gated on the presence of a valid `trace_id`**: metrics are only populated when OpenTelemetry trace context is available.
- All metrics must be non-sensitive: they contain only counts, type labels, and status indicators — **never raw sensitive data or personally identifiable information**.

**Example (pii_filter plugin):**
```python
result.metadata["pii_filter"] = {
    "total_detections": 2,       # total number of PII detections in this call
    "total_masked": 2,           # total number masked/redacted
    "detection_types": ["email", "ssn"],  # distinct type names, sorted, deduped
    "stage": "tool_post_invoke", # which hook stage emitted this
}
```
Note: `trace_id` is an input only (read from `extensions.request.trace_id`) and is never emitted as part of the output metrics.

**When Implementing Trace Context Support:**
1. Update your hook signatures to accept the optional `extensions` parameter.
2. Read `trace_id` from `extensions` when available.
3. Emit metrics to `result.metadata[<plugin-name>]` only when a valid `trace_id` is present.
4. Ensure all emitted data is non-sensitive and aggregated (counts, not individual values).
5. Document the metadata keys and values in your plugin's README.
