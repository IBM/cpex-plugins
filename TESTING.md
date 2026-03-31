# Testing cpex-plugins

Each plugin in this repository has its own test suite. This document describes the testing patterns, how to run tests, and how to write tests for new plugins.

## Quick Start

```bash
cd rate_limiter

# Run everything
make test-all

# Run only Rust tests
make test

# Run only Python tests
make test-python
```

## Test Categories

### Rust Unit Tests

Located in the Rust source files (`src/*.rs`) as inline `#[cfg(test)]` modules. These test the core engine logic — algorithms, data structures, and backend implementations.

```bash
make test             # Run all Rust tests
make test-verbose     # Run with stdout output (--nocapture)
```

### Python Tests

Located in `tests/` within each plugin directory. These test the Python plugin layer end-to-end, exercising the full path from hook entry point through the Rust engine.

```bash
make test-python      # Run with pytest
```

Python tests are organized by concern:

| File | What it tests |
|------|---------------|
| `test_parse_rate.py` | Rate string parsing (`_parse_rate` helper) |
| `test_extract_user_identity.py` | User identity normalisation |
| `test_config.py` | Pydantic configuration model |
| `test_plugin.py` | End-to-end plugin behavior (construction, hooks, algorithms, fail-open) |

### Integration Tests

Tests that require external services (e.g., Redis) are tagged and run separately:

```bash
make test-integration   # Requires a running Redis instance
```

### Rust Benchmarks

Performance benchmarks using Criterion:

```bash
make bench              # Run benchmarks
make bench-baseline     # Save a baseline
make bench-compare      # Compare against baseline
```

## Test Infrastructure

### mcpgateway Mock Framework

Plugins import types from `mcpgateway.plugins.framework`, but `mcpgateway` is not a declared dependency — it is provided by the host gateway at runtime. For testing, each plugin provides a mock framework.

The mock lives in `tests/mcpgateway_mock/plugins/framework.py` and provides minimal dataclass stubs for:

- `Plugin` — base class
- `PluginConfig` — configuration envelope
- `PluginContext` / `GlobalContext` — request context
- `PluginViolation` — rate limit violation
- `PromptPrehookPayload` / `PromptPrehookResult` — prompt hook types
- `ToolPreInvokePayload` / `ToolPreInvokeResult` — tool hook types

### conftest.py

The `tests/conftest.py` injects the mock into `sys.modules` before the plugin module is imported:

```python
import sys
import mcpgateway_mock
import mcpgateway_mock.plugins
import mcpgateway_mock.plugins.framework

sys.modules.setdefault("mcpgateway", mcpgateway_mock)
sys.modules.setdefault("mcpgateway.plugins", mcpgateway_mock.plugins)
sys.modules.setdefault("mcpgateway.plugins.framework", mcpgateway_mock.plugins.framework)
```

### pytest Configuration

Each plugin's `pyproject.toml` includes pytest settings:

```toml
[tool.pytest.ini_options]
testpaths = ["tests"]
pythonpath = ["tests"]       # So conftest.py can import mcpgateway_mock
asyncio_mode = "auto"        # Async tests run without @pytest.mark.asyncio
```

## Writing Tests

### Test Structure

Follow the existing pattern:

```python
class TestFeatureName:
    """One-line description of what this class tests."""

    @pytest.fixture
    def plugin(self):
        return RateLimiterPlugin(_make_config(by_user="5/s"))

    async def test_allowed_under_limit(self, plugin):
        payload = ToolPreInvokePayload(name="search")
        context = _make_context()
        result = await plugin.tool_pre_invoke(payload, context)
        assert result.continue_processing is True
```

### Key Patterns

- **Use helper functions** like `_make_config()` and `_make_context()` to construct test fixtures with sensible defaults.
- **Test the real Rust engine** where possible — the end-to-end tests in `test_plugin.py` exercise the actual compiled extension, not mocks.
- **Test fail-open behavior** — verify that engine errors result in allowed requests, not crashes.
- **Use `pytest.mark.parametrize`** for testing multiple algorithm variants or input formats.
- **Async tests** — plugin hooks are async. With `asyncio_mode = "auto"`, just define tests as `async def`.

### What to Test

For a new plugin, cover at minimum:

- [ ] Plugin construction with valid config.
- [ ] Plugin construction with invalid config (expect `ValueError`).
- [ ] Each hook method — allowed and blocked paths.
- [ ] Independence between dimensions (e.g., different users, tenants).
- [ ] Fail-open behavior when the engine errors.
- [ ] Edge cases in helper functions.

## CI

Tests run automatically on every PR via GitHub Actions. Each platform build (Linux x86_64/aarch64/s390x/ppc64le, macOS arm64, Windows x86_64) installs the built wheel and runs the full pytest suite, ensuring the compiled extension works correctly on each architecture.

## Troubleshooting

### `ImportError: cannot import name 'RateLimiterEngine'`

The Rust extension is not built. Run `make install` in the plugin directory.

### `ModuleNotFoundError: No module named 'mcpgateway'`

The conftest mock injection isn't running. Ensure:
- `pythonpath = ["tests"]` is set in `pyproject.toml`.
- You're running pytest from the plugin directory, not the repo root.

### Async test hangs

Ensure `asyncio_mode = "auto"` is set in `pyproject.toml` and `pytest-asyncio` is installed as a dev dependency.

### Tests pass locally but fail in CI

Check that the test doesn't depend on timing (e.g., rate limits based on wall-clock seconds). Use deterministic inputs where possible.
