# Cargo Workspace Dependency Consolidation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Centralize shared Rust plugin dependencies in the root workspace `Cargo.toml` and make plugin manifests consume them via `workspace = true`.

**Architecture:** Extend the repository validator so shared Cargo dependencies are enforced as workspace-owned, then update the root workspace manifest and each plugin manifest to satisfy that rule. Verification relies on the validator test plus Cargo metadata/check commands.

**Tech Stack:** Python 3, `unittest`, Cargo workspaces, TOML manifests

---

### Task 1: Add a failing repository test for shared workspace dependencies

**Files:**
- Modify: `tests/test_plugin_catalog.py`
- Test: `tests/test_plugin_catalog.py`

- [ ] **Step 1: Write the failing test**

```python
    def test_repo_centralizes_shared_cargo_dependencies(self) -> None:
        result = run_catalog("validate", str(REPO_ROOT))
        self.assertEqual(result.returncode, 0, result.stderr)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest tests.test_plugin_catalog.PluginCatalogTests.test_repo_centralizes_shared_cargo_dependencies`
Expected: FAIL with a new validator error because the repository still duplicates shared Cargo dependency declarations locally.

- [ ] **Step 3: Write minimal implementation**

```python
def _validate_workspace_dependencies(root: Path, plugins: list[PluginRecord]) -> None:
    ...
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m unittest tests.test_plugin_catalog.PluginCatalogTests.test_repo_centralizes_shared_cargo_dependencies`
Expected: PASS after the validator and manifests agree.

- [ ] **Step 5: Commit**

```bash
git add tests/test_plugin_catalog.py tools/plugin_catalog.py Cargo.toml plugins/rust/python-package/*/Cargo.toml Cargo.lock
git commit -s -m "build: centralize cargo workspace dependencies"
```

### Task 2: Enforce shared dependency ownership in the catalog validator

**Files:**
- Modify: `tools/plugin_catalog.py`
- Test: `tests/test_plugin_catalog.py`

- [ ] **Step 1: Add dependency ownership rules**

```python
REQUIRED_WORKSPACE_DEPENDENCIES = {
    "dependencies": {...},
    "dev-dependencies": {...},
}
```

- [ ] **Step 2: Validate workspace manifest ownership**

Run: `python3 -m unittest tests.test_plugin_catalog.PluginCatalogTests.test_repo_centralizes_shared_cargo_dependencies`
Expected: FAIL until root `Cargo.toml` includes each required workspace dependency.

- [ ] **Step 3: Validate plugin manifests use `workspace = true`**

```python
if dependency_value != {"workspace": True}:
    raise CatalogError(...)
```

- [ ] **Step 4: Re-run targeted test**

Run: `python3 -m unittest tests.test_plugin_catalog.PluginCatalogTests.test_repo_centralizes_shared_cargo_dependencies`
Expected: still FAIL until manifest updates are made, but now with validator coverage for both root and plugin manifests.

### Task 3: Centralize shared dependencies in Cargo manifests

**Files:**
- Modify: `Cargo.toml`
- Modify: `plugins/rust/python-package/encoded_exfil_detection/Cargo.toml`
- Modify: `plugins/rust/python-package/pii_filter/Cargo.toml`
- Modify: `plugins/rust/python-package/rate_limiter/Cargo.toml`
- Modify: `plugins/rust/python-package/retry_with_backoff/Cargo.toml`
- Modify: `plugins/rust/python-package/secrets_detection/Cargo.toml`
- Modify: `plugins/rust/python-package/url_reputation/Cargo.toml`
- Modify: `Cargo.lock`

- [ ] **Step 1: Add shared dependency entries to root workspace**

```toml
[workspace.dependencies]
cpex_framework_bridge = { path = "crates/framework_bridge" }
criterion = { version = "0.8", features = ["html_reports"] }
regex = "1.12"
serde_json = "1.0"
```

- [ ] **Step 2: Update plugin manifests to consume shared dependencies**

```toml
[dependencies]
cpex_framework_bridge.workspace = true
regex.workspace = true
serde_json.workspace = true

[dev-dependencies]
criterion.workspace = true
```

- [ ] **Step 3: Refresh lockfile if needed**

Run: `cargo metadata --format-version 1 >/dev/null`
Expected: exit 0 and `Cargo.lock` updated only if Cargo needs a lockfile normalization.

- [ ] **Step 4: Run targeted validator test**

Run: `python3 -m unittest tests.test_plugin_catalog.PluginCatalogTests.test_repo_centralizes_shared_cargo_dependencies`
Expected: PASS.

### Task 4: Verify full repository behavior

**Files:**
- Test: `tests/test_plugin_catalog.py`

- [ ] **Step 1: Run full catalog test module**

Run: `python3 -m unittest tests.test_plugin_catalog`
Expected: PASS.

- [ ] **Step 2: Run Cargo workspace metadata**

Run: `cargo metadata --format-version 1 >/dev/null`
Expected: exit 0.

- [ ] **Step 3: Run Cargo workspace check**

Run: `cargo check --workspace`
Expected: exit 0.
