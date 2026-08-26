# Developing cpex-plugins

## Repository Model

This repository manages Rust plugins built with PyO3/maturin and pure-Python plugins. Both are published to PyPI as Python packages, but each plugin has only one implementation language.

Managed plugin paths:

```text
plugins/rust/python-package/<slug>/  # Rust implementation with Python packaging
plugins/python/<slug>/               # Pure-Python implementation
```

`tools/plugin_catalog.py` discovers both roots and records each plugin's language. Every managed plugin must satisfy these shared catalog contracts:

- distribution name: `cpex-<slug>`
- Python module: `cpex_<slug>`
- `cpex_<slug>/plugin-manifest.yaml` defines top-level `kind` in `module.object` form
- `pyproject.toml` publishes the matching plugin class reference under `[project.entry-points."cpex.plugins"]` in `module:object` form
- the manifest version matches the language-specific source: `Cargo.toml` for Rust or `pyproject.toml` for pure Python
- every plugin is a root uv-workspace member; only Rust plugin crates are top-level Cargo-workspace members
- Rust plugin `Cargo.toml` repository metadata points to `https://github.com/IBM/cpex-plugins`

## Working on One Plugin

```bash
cd plugins/rust/python-package/rate_limiter
uv sync --dev
make install
make test-all
```

Swap `rate_limiter` for any other managed Rust plugin slug.

For a pure-Python plugin:

```bash
cd plugins/python/ica_metering_exporter
make sync
make test-all
make check-all
```

Pure-Python unit tests run from `plugins/python/<slug>/tests/`; `make test-integration` runs the matching framework suite from `plugins/tests/<slug>/`.

## Secrets Detection Count Semantics

`secrets_detection` reports one finding per non-overlapping secret span. When
multiple enabled patterns match the same bytes, or overlapping bytes, the scanner
redacts the merged span once and reports the most specific matching detector
type. Distinct non-overlapping secrets in the same payload still count
separately.

This changed older behavior that could count overlapping broad and specific
pattern matches as multiple findings. Operators using `min_findings_to_block`
values greater than `1` should audit thresholds when upgrading.

## Repo-Level Commands

```bash
make plugins-list
make plugins-validate
make plugin-test PLUGIN=pii_filter
```

`make plugins-validate` runs the same convention checks that the repo contract CI workflow runs.
It runs the catalog validator plus the shared repo contract test modules:
`tests/test_plugin_catalog.py` and `tests/test_install_built_wheel.py`.

## Secret Detection

IBM detect-secrets helps prevent accidental credential commits.

**Scan and audit:**
```bash
make detect-secrets-scan
make detect-secrets-audit
```

**Local check:**
```bash
pre-commit run detect-secrets --all-files
# or
make detect-secrets-check
```

**CI:** Pull request checks fail on unaudited secrets. Audit findings locally before pushing.

**Baseline:** `.secrets.baseline` stores audited findings and must be committed after baseline changes.

## Adding a New Managed Plugin

### Using the Rust Plugin Scaffold Generator

**Rust-only:** the scaffold generator creates Rust plugins with PyO3/maturin packaging. It must not be used to generate pure-Python plugins.

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
  --hooks prompt_pre_fetch,tool_pre_invoke
```

After scaffolding:

1. Review and customize the generated code in `plugins/rust/python-package/<slug>/`
2. The crate is automatically added to the workspace `Cargo.toml`
3. Run `make plugins-validate` to verify structure
4. Run `make plugin-test PLUGIN=<slug>` to execute the plugin's full `make ci` flow

### Manual Rust Plugin Creation

If you prefer to create a plugin manually:

1. Create `plugins/rust/python-package/<slug>/`.
2. Add the required files and package/module names that match the slug conventions.
3. Add the crate path to the workspace `members` list in the top-level `Cargo.toml`.
4. Run `make plugins-validate`.
5. Run `make plugin-test PLUGIN=<slug>` to execute the plugin's full `make ci` flow.

### Manual Pure-Python Plugin Creation

1. Create `plugins/python/<slug>/` with `pyproject.toml`, `Makefile`, `README.md`, `cpex_<slug>/`, and `tests/`; do not add a `Cargo.toml`.
2. Register the distribution as a root uv-workspace member and publish the manifest's plugin class under `[project.entry-points."cpex.plugins"]`.
3. Keep the version in the plugin's `pyproject.toml`, match it in `cpex_<slug>/plugin-manifest.yaml`, and regenerate the root `uv.lock`.
4. Add plugin-framework integration tests under `plugins/tests/<slug>/`.
5. Run `make plugins-validate`, then run `make sync`, `make test-all`, and `make ci` from the plugin directory.

The catalog exposes separate Rust and Python selections to CI. `.github/workflows/ci-rust-python-package.yaml` builds selected Rust plugins, while `.github/workflows/ci-python-package.yaml` builds selected pure-Python plugins. Shared changes can select plugins from both roots without treating a Python implementation as a Rust fallback.

## Releasing

Releases are per plugin and version-bump driven. Use this process to publish a
new version of an existing managed plugin to PyPI.

1. Pick the plugin slug and new version.

   The plugin slug is the directory name under its managed root, for example
   `plugins/rust/python-package/rate_limiter/` or
   `plugins/python/ica_metering_exporter/`. The tag slug is the hyphenated
   form, for example `rate-limiter` or `ica-metering-exporter`.

2. Update the version files.

   `Cargo.toml` is the Rust version source of truth and updates `Cargo.lock`.
   A pure-Python plugin's `pyproject.toml` is its version source of truth and
   updates the root `uv.lock`. The plugin manifest must match in both cases.

   ```bash
   $EDITOR plugins/rust/python-package/rate_limiter/Cargo.toml
   $EDITOR plugins/rust/python-package/rate_limiter/cpex_rate_limiter/plugin-manifest.yaml
   cargo update -p rate_limiter --precise 0.0.5
   ```

   For a pure-Python plugin, edit its `pyproject.toml` and manifest, then run
   `uv lock` at the repository root.

3. Run local validation.

   ```bash
   make plugins-validate
   make plugin-test PLUGIN=rate_limiter
   ```

4. Merge the version bump to `main`.

5. Let CI create the release tag and publish.

   On a `main` push, `.github/workflows/ci-rust-python-package.yaml` detects Rust
   `Cargo.toml` version bumps and `.github/workflows/ci-python-package.yaml`
   detects pure-Python `pyproject.toml` version bumps. After each language's
   required checks are green, the matching CI workflow creates the release tag
   at the merge commit and invokes `release-rust-python-package.yaml` or
   `release-python-package.yaml` with PyPI publishing enabled.

   The workflow uses `GITHUB_TOKEN` to push release tags. Repository tag
   protection or rulesets for release tag patterns must allow that token, or
   the workflow must be updated to use an approved GitHub App or PAT token.

   Release tags use the hyphenated plugin slug, not the directory/module
   underscore form. CI creates tags in this form:

   ```bash
   rate-limiter-v0.0.5
   ```

   Examples:

   - `rate_limiter` -> `rate-limiter-v0.0.5`
   - `secrets_detection` -> `secrets-detection-v0.2.2`
   - `ica_metering_exporter` -> `ica-metering-exporter-v0.1.0`

   Use `make plugins-list` to inspect the current managed plugin slugs and
   package names. Do not create the tag manually for ordinary releases; manual
   tag pushes are reserved for recovery or explicit release-maintainer action.

6. Watch the release workflow and confirm publish success.

   ```bash
   gh run list --workflow ci-rust-python-package.yaml --branch main --limit 5
   gh run list --workflow release-rust-python-package.yaml --limit 5
   gh run list --workflow ci-python-package.yaml --branch main --limit 5
   gh run list --workflow release-python-package.yaml --limit 5
   gh run watch <run-id> --exit-status
   ```

7. Verify the package exists on PyPI at the new version.

   ```bash
   uv run python -m pip index versions cpex-rate-limiter
   ```

   The release page should also exist at
   `https://pypi.org/project/cpex-rate-limiter/0.0.5/`.

The CI workflows create tags only after their required checks pass. They call
the matching release workflow directly for publishing rather than relying on a
bot-created tag push. Both release workflows resolve every catalog tag, then
language guards skip all post-resolution jobs in the wrong-language workflow.
The matching workflow validates metadata and versions, builds and tests the
plugin's artifacts, and publishes only that plugin. PyPI publishing is allowed
only for release tags that point at `main`.

Dependency refresh work is separate from the release process. Track broader
dependency or ContextForge updates outside a plugin release PR.
