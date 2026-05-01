# Developing cpex-plugins

## Repository Model

This repository currently manages one plugin class: Rust plugins that are built with PyO3/maturin and published to PyPI as Python packages.

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

## Working on One Plugin

```bash
cd plugins/rust/python-package/rate_limiter
uv sync --dev
make install
make test-all
```

Swap `rate_limiter` for any other managed plugin slug.

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
  --hooks prompt_pre_fetch,tool_pre_invoke
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

## Releasing

Releases are per plugin and tag-driven:

Release tags must use the hyphenated plugin slug, not the directory/module underscore form:

```bash
git tag rate-limiter-v0.0.2
git tag pii-filter-v0.1.0
```

The release workflow resolves the tag back to the managed plugin path, validates metadata and versions, then builds and publishes only that plugin.
