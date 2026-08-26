# cpex-plugins

Monorepo for managed CPEX plugins implemented in pure Python or Rust and published as Python packages.

## Runtime Requirements

These packages target the CPEX 0.1 framework API and intentionally depend on `cpex>=0.1.0,<0.2`.

Rust plugin packages require their compiled PyO3 extension at import/runtime. They do not ship Python fallback implementations for missing Rust extensions.

## Layout

Managed plugins live under two language-specific roots:

- Rust plugins packaged for Python: `plugins/rust/python-package/<slug>/`
- Pure-Python plugins: `plugins/python/<slug>/`

Current plugins:

| Plugin | Package | Purpose |
|---|---|---|
| `encoded_exfil_detection` | `cpex-encoded-exfil-detection` | Detect suspicious encoded payload exfiltration patterns in prompt arguments, tool output, and resource content |
| `pii_filter` | `cpex-pii-filter` | Detect and mask PII in nested payloads |
| `rate_limiter` | `cpex-rate-limiter` | Enforce per-user, per-tenant, and per-tool rate limits |
| `retry_with_backoff` | `cpex-retry-with-backoff` | Apply retry policy and exponential backoff metadata to transient failures |
| `secrets_detection` | `cpex-secrets-detection` | Detect and redact likely credentials in prompt arguments, tool inputs and outputs, and resource content |
| `sql_sanitizer` | `cpex-sql-sanitizer` | Analyze SQL for blocked statements, unsafe mutations, and interpolation patterns |
| `url_reputation` | `cpex-url-reputation` | Apply static URL allowlist, blocklist, pattern, and heuristic checks before resource fetches |
| `ica_metering_exporter` | `cpex-ica-metering-exporter` | Export MCP tool invocation metrics to an ICA core-services metering endpoint |

Every managed plugin includes:

- `pyproject.toml`
- `Makefile`
- `README.md`
- `cpex_<slug>/__init__.py`
- `cpex_<slug>/plugin-manifest.yaml`

Rust plugins additionally include `Cargo.toml` and Rust source files. Pure-Python plugins do not include `Cargo.toml`; their implementation and unit tests live in the Python package directory.

Pure-Python unit tests live under `plugins/python/<slug>/tests/`, shared plugin-framework integration tests live under `plugins/tests/<slug>/`, and Rust unit tests live in the plugin crate.

Rust crates are owned by the top-level workspace in `Cargo.toml`; all Python distributions are members of the root uv workspace. Python package names follow `cpex-<slug>`, Python modules follow `cpex_<slug>`, plugin manifests must declare a top-level `kind` in `module.object` form, and `pyproject.toml` must publish the matching `module:object` reference under `[project.entry-points."cpex.plugins"]`. Rust plugin versions come from `Cargo.toml` and update `Cargo.lock`; pure-Python plugin versions come from `pyproject.toml` and update the root `uv.lock`. The plugin manifest version must match the language-specific source in both cases. Release tags use the hyphenated slug form `<slug-with-hyphens>-v<version>`, for example `rate-limiter-v0.0.2`.

## Testing Strategy

Testing spans two repositories:

- **Unit tests**: within each plugin's own directory — pure Python in `plugins/python/<slug>/tests/`, Rust inline via `mod tests`, and Python binding tests for Rust packages under their plugin directory
- **Plugin-framework integration tests**: `plugins/tests/<slug>/` for pure-Python plugins and the Rust plugin's own `tests/` directory — test framework discovery, loading, and hook dispatch (`make test-integration`)
- **Gateway integration tests**: `mcp-context-forge/tests/integration/` — test plugin integration with the full gateway
- **E2E tests**: `mcp-context-forge/tests/e2e/` — test complete workflows with plugins

Unit tests live in each plugin's own directory. Plugin-framework integration tests live under `plugins/tests/<slug>/` for pure-Python plugins and in the plugin-local `tests/` directory for Rust plugins. Gateway integration and E2E tests live in `mcp-context-forge`.

See [TESTING.md](TESTING.md) for detailed testing guidelines and cross-repository coordination.

## Plugin Development

### Current Architecture (Transitional)

Plugins are implemented as **pure Python** or **pure Rust** — each plugin uses one language for its logic. There is no dual-path where a plugin ships both Rust and Python implementations with a Python fallback for a missing Rust extension.

For Rust plugins, the current approach wraps the Rust implementation with PyO3/maturin bindings as a packaging layer:
- Plugin logic implemented entirely in Rust
- Python entry points (PyO3/maturin) are a packaging and distribution layer only, not a parallel implementation
- Published as Python packages to PyPI
- Loaded by Python-based plugin framework in `mcp-context-forge`

### Future Architecture

After the plugin framework is migrated to Rust:
- Plugins will be **pure Rust** implementations
- No Python entry points needed
- Direct Rust-to-Rust plugin loading
- Published to Cargo registry

See [DEVELOPING.md](DEVELOPING.md) for detailed workflows for both current and future development.


## Creating a New Rust Plugin

The current plugin scaffold generator is Rust-only. Use it to create a Rust plugin with its PyO3/maturin packaging layer; create pure-Python plugins manually under `plugins/python/<slug>/`.

```bash
make plugin-scaffold
```

This interactive tool will:
- Prompt for plugin name, description, author, and version
- Let you select from 12 available hooks across 5 categories:
  - **Prompt hooks**: `prompt_pre_fetch`, `prompt_post_fetch`
  - **Tool hooks**: `tool_pre_invoke`, `tool_post_invoke`
  - **Resource hooks**: `resource_pre_fetch`, `resource_post_fetch`
  - **Agent hooks**: `agent_pre_invoke`, `agent_post_invoke`
  - **HTTP hooks**: `http_pre_request`, `http_post_request`, `http_auth_resolve_user`, `http_auth_check_permission`
- Generate complete plugin structure with:
  - Rust source files (`lib.rs`, `engine.rs`, `stub_gen.rs`)
  - Python package files (`__init__.py`, `plugin.py`)
  - Build configuration (`Cargo.toml`, `pyproject.toml`, `Makefile`)
  - Documentation (`README.md`)
  - Comprehensive unit tests (Python and Rust)
  - Benchmark scaffolding

For non-interactive mode:

```bash
python3 tools/scaffold_plugin.py --non-interactive \
  --name my_plugin \
  --description "My plugin description" \
  --author "Your Name" \
  --hooks prompt_pre_fetch,tool_pre_invoke
```

## Helper Commands

```bash
make plugins-list              # List all plugins
make plugins-validate          # Validate plugin structure
make plugin-test PLUGIN=rate_limiter  # Test specific plugin
make plugin-scaffold           # Create new plugin (interactive)
```

The catalog and validator used by CI live in `tools/plugin_catalog.py`.

## Quick Start

### Develop a Rust Plugin

```bash
cd plugins/rust/python-package/<slug>
uv sync --dev              # Install dependencies
make install               # Build Rust extension
make test-all              # Run unit tests
```

### Develop a Pure-Python Plugin

```bash
cd plugins/python/<slug>
make sync                  # Install dependencies
make test-all              # Run unit and plugin-framework integration tests
```

### Plugin-Framework Integration Testing

After unit tests pass, run plugin-framework integration tests within `cpex-plugins`:

```bash
cd plugins/rust/python-package/<slug>
make test-integration  # Test PyO3 bindings and framework loading
```

### Gateway Integration Testing

After the plugin PR is merged, coordinate with `mcp-context-forge`:

```bash
cd mcp-context-forge
pip install /path/to/cpex-plugins/plugins/rust/python-package/<slug>
# Configure plugin in plugins/config.yaml
pytest tests/integration/  # Run gateway integration tests
pytest tests/e2e/          # Run E2E tests
```

See [TESTING.md](TESTING.md) for cross-repository testing workflow.

## Documentation

- [AGENTS.md](AGENTS.md) - AI coding assistant guidelines
- [DEVELOPING.md](DEVELOPING.md) - Plugin development workflows
- [TESTING.md](TESTING.md) - Testing strategy and guidelines
- [CONTRIBUTING.md](CONTRIBUTING.md) - Contribution guidelines
- [SECURITY.md](SECURITY.md) - Security policy
