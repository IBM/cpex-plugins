# Developing cpex-plugins

This guide covers how to set up a development environment and work on plugins in this repository.

## Prerequisites

- **Python 3.11+**
- **Rust toolchain** (stable) — install via [rustup](https://rustup.rs/)
- **uv** — Python package manager ([install](https://docs.astral.sh/uv/getting-started/installation/))
- **Make**
- **Git** with commit signing configured

## Repository Structure

This is a monorepo of standalone plugin packages for the ContextForge Plugin Extensibility Framework. Each plugin lives in its own top-level directory with independent build configuration:

```
cpex-plugins/
  rate_limiter/          # Rate limiter plugin (Rust + Python)
    Cargo.toml           # Rust crate configuration
    pyproject.toml       # Python package + maturin build config
    Makefile             # Build, test, and development targets
    src/                 # Rust source
    cpex_rate_limiter/   # Python package
    tests/               # Python tests
    benches/             # Rust benchmarks
```

## Quick Start

Clone the repository and set up a plugin for development:

```bash
git clone git@github.com:IBM/cpex-plugins.git
cd cpex-plugins/rate_limiter

# Install dependencies and build the Rust extension
uv sync --dev
make install

# Run all tests
make test-all

# Verify the installation
make verify
```

## Plugin Development Workflow

### Building

Each plugin has a `Makefile` with standard targets:

```bash
make build        # Build release wheel (output in dist/)
make install      # Build and install into the local venv
make stub-gen     # Generate Python type stubs (.pyi)
make clean        # Remove build artifacts
```

For Rust+Python plugins, `maturin` handles the build. The `pyproject.toml` configures maturin as the PEP 517 build backend, and `Cargo.toml` defines the Rust crate.

### Code Formatting and Linting

```bash
# Rust
make fmt          # Format with rustfmt
make fmt-check    # Check formatting (CI)
make clippy       # Run clippy lints

# Python
uv run ruff check .
uv run ruff format .
```

### Running Tests

```bash
make test         # Rust unit tests only
make test-python  # Python tests only
make test-all     # Both Rust and Python tests
make check-all    # fmt-check + clippy + Rust tests
```

### Benchmarks

For plugins with Rust components:

```bash
make bench            # Run Criterion benchmarks
make bench-baseline   # Save a baseline for comparison
make bench-compare    # Compare against saved baseline
```

## Adding a New Plugin

1. Create a new top-level directory named after the plugin (use `snake_case`).
2. Add a `pyproject.toml` with the appropriate build backend:
   - For Rust+Python plugins: use `maturin` as the build backend with `module-name` and `python-source` configured.
   - For pure Python plugins: use `setuptools` or `hatchling`.
3. Name the distribution package `cpex-<plugin-name>` (e.g., `cpex-rate-limiter`).
4. Create a Python package directory (e.g., `cpex_rate_limiter/`) with `__init__.py` and the plugin module.
5. Include a `plugin-manifest.yaml` inside the Python package.
6. Add a `Makefile` following the pattern in `rate_limiter/Makefile`.
7. Add a `tests/` directory. If the plugin imports from `mcpgateway`, create a mock framework in `tests/mcpgateway_mock/` (see `rate_limiter/tests/` for the pattern).
8. Add a `README.md` documenting the plugin's configuration, hooks, algorithms, and limitations.
9. Add a GitHub Actions workflow at `.github/workflows/pypi-<plugin-name>.yaml` for CI and publishing.

## Plugin Architecture

Plugins in this repository are designed to be loaded by the [ContextForge MCP Gateway](https://github.com/IBM/mcp-context-forge). They implement hook interfaces defined in `mcpgateway.plugins.framework`, but do not declare `mcpgateway` as a dependency — it is provided by the host gateway process at runtime.

### Key Interfaces

Plugins typically implement one or more hook methods:

- `prompt_pre_fetch` — runs before a prompt is fetched
- `tool_pre_invoke` — runs before a tool is invoked

Each hook receives a payload and a `PluginContext`, and returns a result that may include violations, metadata, or HTTP headers.

### Testing Without the Gateway

Since `mcpgateway` is a runtime dependency (not declared in `pyproject.toml`), tests use a mock framework. The pattern is:

1. Create `tests/mcpgateway_mock/plugins/framework.py` with dataclass stubs matching the gateway's types.
2. In `tests/conftest.py`, inject the mock into `sys.modules` before the plugin is imported.
3. Configure `pythonpath = ["tests"]` in `pyproject.toml` under `[tool.pytest.ini_options]`.

See `rate_limiter/tests/` for a working example.

## Configuration

### pyproject.toml

Key settings for a maturin-based plugin:

```toml
[build-system]
requires = ["maturin>=1.4,<2.0"]
build-backend = "maturin"

[project]
name = "cpex-<plugin-name>"
dynamic = ["version"]          # Version pulled from Cargo.toml

[tool.maturin]
module-name = "cpex_<plugin>.<rust_module>"
python-source = "."
features = ["pyo3/extension-module"]
```

Setting `dynamic = ["version"]` makes `Cargo.toml` the single source of truth for versioning.

### Cargo.toml

For Rust+Python plugins using PyO3:

```toml
[dependencies]
pyo3 = { version = "0.28", features = ["abi3-py311"] }
```

The `abi3-py311` feature builds a single wheel that works across Python 3.11+.

## CI/CD

Each plugin has a GitHub Actions workflow that:

1. Builds wheels on multiple platforms (Linux x86_64/aarch64/s390x/ppc64le, macOS arm64, Windows x86_64).
2. Runs the test suite on each platform after building.
3. Publishes to Test PyPI on normal pushes.
4. Publishes to production PyPI on version tags (e.g., `rate-limiter-v0.1.0`).

## Troubleshooting

### `ImportError: rate_limiter_rust`

The Rust extension isn't built. Run `make install` in the plugin directory.

### `ModuleNotFoundError: mcpgateway`

This is expected when running the plugin standalone. Tests use the mock framework; see the Testing Without the Gateway section above.

### maturin build fails

Ensure both Rust and Python are available:

```bash
rustc --version
python3 --version
uv run maturin --version
```
