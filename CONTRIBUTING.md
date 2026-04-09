# Contributing to cpex-plugins

Thank you for your interest in contributing to the ContextForge Plugin Extensibility Framework Plugins. This document describes how to contribute effectively.

## How to Contribute

### General

- All contributions are made via pull requests against the `main` branch.
- Use the [GitHub issue tracker](https://github.com/IBM/cpex-plugins/issues) to report bugs and propose features.
- All commits must be signed (DCO sign-off).

### Feature Proposals

Before implementing a new feature or adding a new plugin, open an issue to discuss the design. This avoids wasted effort and ensures alignment with project goals.

### Bug Fixes

Raise an issue describing the bug before submitting a PR. Reference the issue number in your PR.

### New Plugins

Each plugin lives in its own top-level directory (e.g., `rate_limiter/`). New plugins should follow the established pattern:

- A `pyproject.toml` with maturin as the build backend (for Rust+Python plugins) or setuptools (for pure Python plugins).
- A `Makefile` with standard targets: `build`, `install`, `test`, `test-python`, `test-all`, `fmt`, `clippy`, `check-all`, `clean`.
- A `README.md` documenting configuration, usage, and limitations.
- A `plugin-manifest.yaml` inside the Python package directory with an explicit `kind` in `module.object` form.
- A matching plugin entry point in `pyproject.toml` under `[project.entry-points."cpex.plugins"]` in `module:object` form.
- A `tests/` directory with pytest tests.

### Merge Approval

Pull requests require review and approval from at least one maintainer before merging.

## Legal

### License

This project is licensed under the Apache License 2.0. All source files must include the SPDX license header:

```
# Copyright <year>
# SPDX-License-Identifier: Apache-2.0
```

For Rust files:

```
// Copyright <year>
// SPDX-License-Identifier: Apache-2.0
```

### Developer's Certificate of Origin (DCO)

All commits must be signed off to certify that you have the right to submit the contribution under the project's license. Use `git commit -s` to add the sign-off line automatically.

## Communication

Use [GitHub Issues](https://github.com/IBM/cpex-plugins/issues) for bug reports, feature requests, and general discussion.

## Coding Style

### Python

- Python 3.11+ with type hints.
- Use `snake_case` for functions and variables, `PascalCase` for classes, `UPPER_CASE` for constants.
- Format with Black (line length 200) and isort.
- Lint with Ruff.

### Rust

- Follow standard Rust conventions (`rustfmt`, `clippy`).
- Use `cargo fmt` before committing.
- All clippy warnings must be resolved (`clippy -- -D warnings`).

### File Headers

All source files should include a copyright notice and SPDX license identifier. See existing files for the format.
