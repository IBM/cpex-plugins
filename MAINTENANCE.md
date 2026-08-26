# Plugin Maintenance Playbook

Tracks the ongoing maintenance cadence for all plugins in this repository.

---

## Cadence

| Cycle | Mechanism | Scope |
|---|---|---|
| **Weekly** | Dependabot (`.github/dependabot.yml`) | Individual package bumps — Rust, Python, GitHub Actions |
| **Monthly** | Scheduled workflow (`dep-update-cadence.yaml`) | Full lock file refresh + all-plugin test run + consolidated PR |
| **On demand** | `workflow_dispatch` on `dep-update-cadence.yaml` | Pre-release or emergency update |

---

## Ownership

| Role | Responsibility |
|---|---|
| **Cycle owner** | Runs or monitors the monthly automated PR; reviews and merges or defers |
| **Backup** | Takes over if cycle owner is unavailable |
| **Current cycle owner** | @madhu-mohan-jaishankar |
| **Backup** | @lucarlig |

The cycle owner rotates quarterly. Update this table when ownership changes.

---

## Monthly Cycle — Step-by-Step Checklist

The monthly workflow runs automatically on the 1st of each month and opens a PR. If no lock file changes occurred, no PR is opened — note this in the cycle log below.

### When the PR is opened

1. **Review the lock file diffs**
   - `Cargo.lock` — check for any crate jumping a major version unexpectedly
   - Root `uv.lock` — check every Rust-packaged and pure-Python workspace member for packages bumping past the constraint bounds in `pyproject.toml`

2. **Verify gateway compatibility constraints are still satisfied**
   - Open `pyproject.toml` → `[tool.uv] constraint-dependencies`
   - Confirm each pinned range (`cpex`, `pydantic`, `maturin`, etc.) still holds after the bump
   - Review `httpx` and `PyJWT` compatibility for the ICA Metering Exporter; the root uv lock spans all workspace members

3. **Check `deny.toml` advisory suppressions**
   - If `cargo deny check advisories` introduced new RUSTSEC advisories in the workflow log, evaluate and either update the suppress list with a justification comment or fix the dependency

4. **Merge or defer**
   - If all checks pass: approve and merge the PR
   - If a dependency needs deferral: close the PR, note the deferred package and reason in the **Compat Table** below, and open a follow-up issue

5. **Record the cycle outcome** in the **Cycle Log** below

---

## Pre-Release / Emergency Update

When a release is imminent and a dependency bump is needed:

```bash
# Trigger manually from the Actions tab → "Monthly Dependency Update" → Run workflow
# OR run locally:
cargo update
uv lock --upgrade
cargo deny --all-features check advisories --config deny.toml
# Run tests for all plugins through dual-root routing:
for plugin in encoded_exfil_detection pii_filter rate_limiter retry_with_backoff secrets_detection sql_sanitizer url_reputation ica_metering_exporter; do
  make plugin-test PLUGIN="$plugin"
done
```

The maintenance workflow keeps explicit `rust_plugins` and `python_plugins` arrays because their test commands run from different roots. The Python loop runs each slug from `plugins/python/${plugin}`. Add every future Rust slug to `rust_plugins` and every future pure-Python slug to `python_plugins` in `.github/workflows/plugin-maintenance.yaml`.

---

## Gateway Compatibility Table

Records known constraints between plugin dependencies and the gateway (`cpex`/`mcp-context-forge`). Update this when a dependency cannot be bumped due to gateway compatibility.

| Plugin | Constrained dependency | Pinned range | Gateway version | Notes | Last reviewed |
|---|---|---|---|---|---|
| all | `cpex` | `>=0.1.0,<0.2` | gateway 0.1.x | ABI boundary — major bump requires gateway coordination | 2026-07 |
| all | `pydantic` | `>=2.13.4,<3` | gateway 0.1.x | Pydantic v3 not yet validated against gateway models | 2026-07 |
| all | `maturin` | `>=1.13.3,<2.0` | build toolchain | Major maturin bumps may change wheel ABI tagging | 2026-07 |
| all | `redis` | `>=7.4.0` | gateway 0.1.x | Lower bound — no upper constraint yet | 2026-07 |
| `ica_metering_exporter` | `httpx` | `>=0.27,<1` | gateway 0.1.x | HTTP client is resolved in the root uv workspace; validate transport behavior when bumping | 2026-08 |
| `ica_metering_exporter` | `PyJWT` | `>=2.8,<3` | gateway 0.1.x | HS256 service JWT behavior is resolved in the root uv workspace; validate token generation when bumping | 2026-08 |
| `pii_filter` | `pyo3` | `0.29.0` (workspace) | — | ABI3-py311; bump with cross-plugin coordination | 2026-07 |
| `secrets_detection` | `regex` | `1.12.3` (workspace) | — | No constraint; update freely | 2026-07 |

---

## Cycle Log

Record each completed cycle here. One row per month.

| Month | PR / Issue | Lock changes? | CVEs found | Deferrals | Merged by |
|---|---|---|---|---|---|
| 2026-07 | _first automated cycle pending_ | — | — | — | — |

---

## Dependabot PRs — Triage Guide

Dependabot opens individual PRs weekly for new package releases. Triage criteria:

- **Patch** (`x.y.Z`): merge if CI passes, no gateway constraint hit
- **Minor** (`x.Y.z`): review changelog; merge if no breaking API changes and CI passes
- **Major** (`X.y.z`): evaluate manually; update the compat table; coordinate with gateway team if the dep is in `constraint-dependencies`
- **RUSTSEC advisory**: treat as P1 — either bump the dep or suppress with a justification in `deny.toml`
