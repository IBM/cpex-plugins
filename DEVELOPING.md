# Developing cpex-plugins

## Repository Model

This repository currently manages one plugin class: Rust plugins that are built with PyO3/maturin and published to PyPI as Python packages.

**Current Architecture (Transitional):**
- Plugins implemented in Rust (core logic)
- Python entry point via PyO3/maturin bindings
- Published as Python packages to PyPI
- Loaded by Python-based plugin framework in `mcp-context-forge`

**Future Architecture (Post-Framework Migration):**
- Plugins implemented in pure Rust
- Plugin framework migrated to Rust
- No Python entry points needed
- Direct Rust-to-Rust plugin loading

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

## Plugin Development Workflow

### Current Workflow: Rust + Python Hybrid

This is the current development workflow while the plugin framework remains in Python.

#### 1. Create Plugin Structure

Use the scaffold generator (recommended):

```bash
make plugin-scaffold
```

Or manually create the plugin structure in `plugins/rust/python-package/<slug>/`.

#### 2. Implement Plugin Logic

**Rust Core Logic** (`src/lib.rs`, `src/engine.rs`):
- Implement plugin functionality in Rust
- Use PyO3 for Python bindings
- Follow Rust conventions: `cargo fmt`, `clippy -- -D warnings`

**Python Entry Point** (`cpex_<slug>/plugin.py`):
- Implement Python plugin class
- Import and wrap Rust functions
- Implement plugin framework hooks

**Plugin Manifest** (`cpex_<slug>/plugin-manifest.yaml`):
- Define plugin metadata
- Specify hooks and configuration schema
- Version must match `Cargo.toml`

#### 3. Write Unit Tests

**Location**: `cpex-plugins/tests/` and plugin-specific `tests/` directory

**Rust Tests** (in `src/`):
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_logic() {
        // Test Rust functions
    }
}
```

**Python Tests** (in `tests/`):
```python
import pytest
from cpex_<slug> import MyPlugin

def test_plugin_behavior():
    # Test Python interface
    pass
```

Run tests:
```bash
cd plugins/rust/python-package/<slug>
make test-all  # Runs both Rust and Python tests
```

#### 4. Build and Install Locally

```bash
uv sync --dev              # Install Python dependencies
make install               # Build Rust extension and install into venv
```

#### 5. Integration Testing

**Location**: `mcp-context-forge/tests/integration/` and `tests/e2e/`

After unit tests pass in `cpex-plugins`:

1. Install plugin in `mcp-context-forge`:
   ```bash
   cd mcp-context-forge
   pip install /path/to/cpex-plugins/plugins/rust/python-package/<slug>
   ```

2. Configure plugin in `plugins/config.yaml`:
   ```yaml
   plugins:
     - name: "MyPlugin"
       kind: "cpex_<slug>.plugin.MyPlugin"
       hooks: ["prompt_pre_fetch"]
       mode: "enforce"
       priority: 100
   ```

3. Write integration tests in `mcp-context-forge/tests/integration/`:
   ```python
   # Test plugin integration with gateway framework
   async def test_plugin_loads():
       # Test plugin loading and initialization
       pass
   
   async def test_plugin_hook_execution():
       # Test hook execution in framework
       pass
   ```

4. Write E2E tests in `mcp-context-forge/tests/e2e/`:
   ```python
   # Test complete workflows with plugin enabled
   async def test_plugin_in_request_flow():
       # Test plugin behavior in real request/response cycle
       pass
   ```

See `mcp-context-forge/tests/AGENTS.md` for integration/E2E test conventions.

#### 6. Create Pull Request

**In cpex-plugins**:
- Include unit tests
- Ensure `make ci` passes
- Update `CHANGELOG.md` if applicable
- Sign commits: `git commit -s`

**In mcp-context-forge** (after cpex-plugins PR merged):
- Add integration/E2E tests
- Update plugin configuration if needed
- Ensure all tests pass

#### 7. Release

Tag release in `cpex-plugins`:
```bash
git tag <slug>-v<version>  # e.g., rate-limiter-v0.0.2
git push origin <slug>-v<version>
```

This triggers PyPI publish workflow.

Update `mcp-context-forge` dependencies:
```bash
cd mcp-context-forge
pip install --upgrade cpex-<slug>
```

### Future Workflow: Pure Rust

This workflow will be used after the plugin framework is migrated to Rust.

#### 1. Create Plugin Structure

```bash
cd cpex-plugins
cargo new --lib plugins/rust/<slug>
```

Add to workspace in top-level `Cargo.toml`:
```toml
[workspace]
members = [
    "plugins/rust/<slug>",
    # ... other plugins
]
```

#### 2. Implement Plugin Logic

**Pure Rust** (`src/lib.rs`):
```rust
use cpex_framework::{Plugin, PluginContext, HookResult};

pub struct MyPlugin {
    config: MyConfig,
}

impl Plugin for MyPlugin {
    fn prompt_pre_fetch(&self, ctx: &PluginContext) -> HookResult {
        // Implement hook logic
    }
}
```

**No Python Entry Points Needed** - Direct Rust-to-Rust loading.

#### 3. Write Unit Tests

**Location**: `cpex-plugins/tests/` and plugin-specific `tests/` directory

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_logic() {
        let plugin = MyPlugin::new(config);
        let result = plugin.prompt_pre_fetch(&ctx);
        assert!(result.is_ok());
    }
}
```

Run tests:
```bash
cd plugins/rust/<slug>
cargo test
```

#### 4. Build

```bash
cargo build --release
```

#### 5. Integration Testing

**Location**: `mcp-context-forge/tests/integration/` and `tests/e2e/`

1. Add plugin as dependency in `mcp-context-forge/Cargo.toml`:
   ```toml
   [dependencies]
   cpex-<slug> = { path = "../cpex-plugins/plugins/rust/<slug>" }
   ```

2. Configure plugin in Rust framework configuration

3. Write integration tests in `mcp-context-forge/tests/integration/`

4. Write E2E tests in `mcp-context-forge/tests/e2e/`

#### 6. Create Pull Request

**In cpex-plugins**:
- Include unit tests
- Ensure `cargo test` passes
- Update version in `Cargo.toml`
- Sign commits: `git commit -s`

**In mcp-context-forge** (after cpex-plugins PR merged):
- Add integration/E2E tests
- Update Cargo dependencies
- Ensure all tests pass

#### 7. Release

Publish to Cargo registry:
```bash
cd plugins/rust/<slug>
cargo publish
```

Update `mcp-context-forge/Cargo.toml`:
```toml
[dependencies]
cpex-<slug> = "0.1.0"
```

### Migration Path

**Removing Python Components:**

When migrating from hybrid to pure Rust:

1. Remove `pyproject.toml`
2. Remove `cpex_<slug>/plugin.py` (Python entry point)
3. Remove PyO3 bindings from `src/lib.rs`
4. Remove maturin build configuration
5. Update `Cargo.toml` to pure Rust crate
6. Move from `plugins/rust/python-package/<slug>/` to `plugins/rust/<slug>/`
7. Update workspace `Cargo.toml` members list

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

### Using the Plugin Scaffold Generator (Recommended)

The easiest way to create a new plugin is using the scaffold generator:

```bash
make plugin-scaffold
```

This interactive tool will:
- Prompt for plugin name, description, author, and version
- Let you select from 12 available hooks across 5 categories
- Generate complete plugin structure with all required files
- Create comprehensive unit tests (Python and Rust)
- Set up build configuration and documentation

For non-interactive mode:

```bash
python3 tools/scaffold_plugin.py --non-interactive \
  --name my_plugin \
  --description "My plugin description" \
  --author "Your Name" \
  --hooks prompt_pre_fetch tool_pre_invoke
```

After scaffolding:

1. Review and customize the generated code in `plugins/rust/python-package/<slug>/`
2. The crate is automatically added to the workspace `Cargo.toml`
3. Run `make plugins-validate` to verify structure
4. Run `make plugin-test PLUGIN=<slug>` to execute the plugin's full `make ci` flow

### Manual Plugin Creation

If you prefer to create a plugin manually:

1. Create `plugins/rust/python-package/<slug>/`.
2. Add the required files and package/module names that match the slug conventions.
3. Add the crate path to the workspace `members` list in the top-level `Cargo.toml`.
4. Run `make plugins-validate`.
5. Run `make plugin-test PLUGIN=<slug>` to execute the plugin's full `make ci` flow.

## Testing Coordination

### Unit Tests (cpex-plugins)

- **Location**: `cpex-plugins/tests/` and plugin-specific `tests/` directories
- **Scope**: Plugin logic, Rust functions, Python bindings
- **Run**: `make test-all` from plugin directory
- **CI**: Runs on every PR in cpex-plugins

### Integration Tests (mcp-context-forge)

- **Location**: `mcp-context-forge/tests/integration/`
- **Scope**: Plugin integration with gateway framework, cross-plugin interactions
- **Run**: `pytest tests/integration/` in mcp-context-forge
- **CI**: Runs on every PR in mcp-context-forge

### E2E Tests (mcp-context-forge)

- **Location**: `mcp-context-forge/tests/e2e/`
- **Scope**: Complete workflows, realistic scenarios, multi-gateway coordination
- **Run**: `pytest tests/e2e/` in mcp-context-forge
- **CI**: Runs on every PR in mcp-context-forge

### Cross-Repository Workflow

1. Develop plugin in `cpex-plugins` with unit tests
2. Create PR in `cpex-plugins`, ensure CI passes
3. After merge, coordinate with `mcp-context-forge` team
4. Write integration/E2E tests in `mcp-context-forge`
5. Create PR in `mcp-context-forge`, ensure CI passes
6. Release plugin when both repositories are ready

See `TESTING.md` for detailed testing guidelines.

## Releasing

Releases are per plugin and tag-driven:

Release tags must use the hyphenated plugin slug, not the directory/module underscore form:

```bash
git tag rate-limiter-v0.0.2
git tag pii-filter-v0.1.0
```

The release workflow resolves the tag back to the managed plugin path, validates metadata and versions, then builds and publishes only that plugin.