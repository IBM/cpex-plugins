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

Rust crates are owned by the top-level workspace in `Cargo.toml`. Python package names follow `cpex-<slug>`, Python modules follow `cpex_<slug>`, plugin manifests must declare a top-level `kind` in `module.object` form, and `pyproject.toml` must publish the matching `module:object` reference under `[project.entry-points."cpex.plugins"]`. Release tags use the hyphenated slug form `<slug-with-hyphens>-v<version>`, for example `rate-limiter-v0.0.2`.

## Testing Strategy

Testing is split across two repositories:

- **Unit tests**: Located in `cpex-plugins/tests/` - Test plugin logic in isolation
- **Integration tests**: Located in `mcp-context-forge/tests/integration/` - Test plugin integration with gateway
- **E2E tests**: Located in `mcp-context-forge/tests/e2e/` - Test complete workflows with plugins

This separation allows fast feedback during plugin development while ensuring system-level validation.

See [TESTING.md](TESTING.md) for detailed testing guidelines and cross-repository coordination.

## Plugin Development

### Current Architecture (Transitional)

Plugins are currently developed using a **Rust + Python hybrid** approach:
- Core logic implemented in Rust
- Python entry point via PyO3/maturin bindings
- Published as Python packages to PyPI
- Loaded by Python-based plugin framework in `mcp-context-forge`

### Future Architecture

After the plugin framework is migrated to Rust:
- Plugins will be **pure Rust** implementations
- No Python entry points needed
- Direct Rust-to-Rust plugin loading
- Published to Cargo registry

See [DEVELOPING.md](DEVELOPING.md) for detailed workflows for both current and future development.

## Creating a New Plugin

Use the plugin scaffold generator to create a new plugin with all required files and structure:

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
  --hooks prompt_pre_fetch tool_pre_invoke
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

### Develop a Plugin

```bash
cd plugins/rust/python-package/<slug>
uv sync --dev              # Install dependencies
make install               # Build Rust extension
make test-all              # Run unit tests
```

### Integration Testing

After unit tests pass, coordinate with `mcp-context-forge`:

```bash
cd mcp-context-forge
pip install /path/to/cpex-plugins/plugins/rust/python-package/<slug>
# Configure plugin in plugins/config.yaml
pytest tests/integration/  # Run integration tests
pytest tests/e2e/          # Run E2E tests
```

See [TESTING.md](TESTING.md) for cross-repository testing workflow.

## Documentation

- [AGENTS.md](AGENTS.md) - AI coding assistant guidelines
- [DEVELOPING.md](DEVELOPING.md) - Plugin development workflows
- [TESTING.md](TESTING.md) - Testing strategy and guidelines
- [CONTRIBUTING.md](CONTRIBUTING.md) - Contribution guidelines
- [SECURITY.md](SECURITY.md) - Security policy