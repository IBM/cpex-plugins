# Testing cpex-plugins

A test earns its place by catching a meaningful failure: an incorrect plugin
decision, a broken boundary, an unsafe release, or a known regression. Start
with the behavior and its owner. More test cases and higher coverage are not
independent goals.

## Ownership

| Layer | Location | What it protects |
| --- | --- | --- |
| Rust core | Inline tests in each plugin crate | Detection, redaction, limits, retries, policy decisions, and failure handling |
| Pure-Python core | `plugins/python/<slug>/tests/` | Plugin decisions, request attribution, transport behavior, and privacy |
| Python/Rust and hook boundary | `plugins/tests/<slug>/` | Config conversion, binding calls, payload isolation, hook results, and error mapping |
| Repository tooling | `tests/` | Catalog discovery, CI selection, release validation, coverage aggregation, and wheel selection/installation |
| Repository security policy | `tests/test_repository_policy.py` | Action SHA pinning and expiry of Cargo advisory exceptions |
| Distribution | Release workflow artifact jobs | Installation and execution of built wheels and sdists outside the source tree |
| Full gateway | `mcp-context-forge/tests/integration/` and `tests/e2e/` | Gateway lifecycle, cross-plugin interactions, and complete request flows |

Existing plugin hook suites use `plugins/tests/conftest.py` and its controlled
hook-model shims. Real-CPEX import smoke tests check that the packages also
import with the installed framework. Passing the shim suites does not prove
full gateway compatibility. Generated plugins have local Python hook smoke
tests that run the wrapper and compiled Rust hooks against CPEX.

## What stays, what goes

| Keep | Remove or consolidate |
| --- | --- |
| Security detection, false-positive, redaction, and privacy regressions | Assertions about private Rust module declarations or source layout |
| Rate-limit concurrency, Redis errors, fail-open/fail-closed behavior, and TLS | Generic constructor and field-presence tests with no behavioral assertion |
| Hook dispatch, conversion, payload isolation, and observability contracts | Repeating a core algorithm's entire matrix through every wrapper layer |
| Catalog packaging invariants, mixed-language routing, canonical release tags, and coverage report validation | Hardcoded lists/counts of the current real plugins and every spelling of the same invalid input |
| Wheel platform compatibility and actual install-command behavior | Exact argparse help wording |
| Action pinning and dated advisory exception policy | Exact CI job names, step ordering, shell recipes, tool versions, or YAML whitespace |
| Building, linting, type checking, and installing actual artifacts | Reading Makefiles, stubs, templates, or documentation to assert expected text |
| One generated hook smoke case per selected hook | Empty TODO tests and tests of Pydantic's ordinary setters/serialization |

For each new test, describe the defect that would make it fail. Extend an
existing case when it already owns that behavior. Use representative success,
failure, and boundary cases; add more inputs when they exercise a different
policy or a concrete regression. Assertions should survive an internal
refactor that preserves behavior.

The catalog suite uses one small mixed-language fixture, direct public function
calls for policy, and a few real Git/CLI tests for I/O. It does not parse the
repository's workflow scripts or plugin source. Actual repository layout is
checked by `plugin_catalog.py validate .` in local validation and catalog CI.

## Commands

Repository tooling uses the standard library and needs no plugin builds:

```bash
make plugins-validate
# Equivalent:
python3 tools/plugin_catalog.py validate .
python3 -m unittest discover -s tests
```

For a plugin, use its existing targets:

```bash
cd plugins/rust/python-package/rate_limiter  # Or plugins/python/<slug>
make sync
make install
make test-all
make test-integration
make ci
```

The repo helper runs the selected plugin's CI target:

```bash
make plugin-test PLUGIN=rate_limiter
```

Rust tests use nextest. The `ci` profile in `.config/nextest.toml` disables
fail-fast. Benchmarks are compiled with `cargo nextest run --benches
-E 'kind(bench)' --no-run`; shared CI runners do not provide stable performance
measurements. Gateway suites run from the `mcp-context-forge` repository.

## Coverage and mutation checks

The existing Rust CI coverage gate remains 90% per selected plugin. It runs
Rust tests and the Python hook suites against instrumented PyO3 extensions.
Use coverage to find missing behavior, then add assertions that catch a real
failure. A test that only executes a line adds no useful protection.

To reproduce the coverage job, install `llvm-tools-preview`,
`cargo-llvm-cov` 0.8.4, and `cargo-nextest` 0.9.133, then run this in Bash from
the repository root:

```bash
mkdir -p coverage
CARGO_PACKAGES="$(python3 tools/plugin_catalog.py ci-selection-field . all '' '' cargo_packages)"
RUST_PLUGINS="$(python3 tools/plugin_catalog.py ci-selection-field . all '' '' rust_plugins)"
export CARGO_PACKAGES RUST_PLUGINS
mapfile -t cargo_packages < <(python3 -c 'import json, os; [print(p) for p in json.loads(os.environ["CARGO_PACKAGES"])]')
mapfile -t rust_plugins < <(python3 -c 'import json, os; [print(p) for p in json.loads(os.environ["RUST_PLUGINS"])]')
cargo_args=()
for package in "${cargo_packages[@]}"; do
  cargo_args+=("-p" "${package}")
done
cargo llvm-cov clean --workspace
cargo llvm-cov nextest --no-report "${cargo_args[@]}" -P ci
eval "$(cargo llvm-cov show-env --sh)"
export CARGO_TARGET_DIR="${CARGO_LLVM_COV_TARGET_DIR}/llvm-cov-target"
export CARGO_LLVM_COV_BUILD_DIR="${CARGO_TARGET_DIR}"
export LLVM_PROFILE_FILE="${CARGO_TARGET_DIR}/cpex-plugins-%p-%10m.profraw"
mkdir -p "${CARGO_TARGET_DIR}"
for plugin in "${rust_plugins[@]}"; do
  (cd "plugins/rust/python-package/${plugin}" && make sync && uv run maturin develop)
  (cd "plugins/rust/python-package/${plugin}" && make test-integration)
done
env -u CARGO_TARGET_DIR -u CARGO_LLVM_COV_BUILD_DIR -u CARGO_LLVM_COV_TARGET_DIR -u LLVM_PROFILE_FILE cargo llvm-cov report "${cargo_args[@]}" --cobertura --output-path coverage/cobertura.xml
python3 tools/plugin_catalog.py coverage-check . coverage/cobertura.xml 90.00 "${RUST_PLUGINS}"
```

Mutation CI checks changed Rust source, including relevant dependents of the
framework bridge. It uses `cargo-mutants` 27.0.0 with nextest and the `mutants`
profile. Tooling-only changes do not select mutation jobs. Local commands:

```bash
make plugin-mutants-list PLUGIN=retry_with_backoff
make plugin-mutants PLUGIN=retry_with_backoff
```

## CI and releases

The catalog selects affected plugins and splits Rust and Python jobs. Plugin
changes stay scoped; shared workspace, tooling, and harness changes select all
plugins. Repository test-only changes run the tooling suite.

Plugin CI retains formatting, linting, type checks, Rust tests, hook suites,
security checks, coverage, and artifact builds. Version bumps on PRs invoke the
matching release workflow with publishing disabled. On `main`, release tags
are created after required checks pass. Release workflows validate catalog
metadata and exercise built distributions before publishing.
