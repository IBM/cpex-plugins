# OpenTelemetry at the Rust Plugin Boundary (metadata channel) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire CPEX Rust plugins into the gateway's existing OpenTelemetry/metrics infrastructure: plugins accept distributed trace context (`trace_id`/`span_id`) at the hook boundary and return per-plugin metrics on `PluginResult.metadata["<plugin>"]`; the gateway builds the trace context, passes it in, and consumes the returned metrics into `ObservabilityService`.

**Architecture:** Two repos, two PRs (PRs are NOT created in this effort — see constraints). Plugin side (`IBM/cpex-plugins`, pilot `pii_filter`, closes #27): hook signatures gain an optional `extensions` param; the Rust core reads `trace_id`, and when present, builds a counts/types-only metrics dict and sets it on `result.metadata["pii_filter"]`. The CPEX executor already accumulates `result.metadata` across the hook chain (`manager.py:939-942`), so distinct plugin namespaces coexist with no merge code. Gateway side (`IBM/mcp-context-forge`, new issue): G0 builds `Extensions(request=RequestExtension(trace_id, span_id))` and passes `extensions=` into the already-supporting `invoke_hook`; G1 reads `result.metadata["<plugin>"]` and attaches it as span attributes / records it via `ObservabilityService`.

**Tech Stack:** Rust (PyO3/maturin), Python 3.11+ (cpex framework, FastAPI gateway), pytest, cargo nextest, `gh` CLI.

**CPEX extension framework usage (no new types — normative):** This work uses the **existing** CPEX extension framework end-to-end; it does NOT define, subclass, or invent any new extension type, and does NOT add a separate telemetry transport.
- **Trace IN** rides the existing CPEX `Extensions` / `RequestExtension` classes: the gateway *imports and instantiates* them — `from cpex.framework.extensions import Extensions, RequestExtension` → `Extensions(request=RequestExtension(trace_id=..., span_id=...))` — and the plugin reads `extensions.request.trace_id`. These are existing cpex classes (verified: `cpex/framework/extensions/request.py:53-54` `trace_id`/`span_id`, doc'd "Distributed tracing ID (OpenTelemetry)", frozen; `extensions.py:84` `request` slot; both re-exported in `extensions/__init__.py` `__all__`). This satisfies issue #27's "use the CPEX extension framework rather than inventing a separate plugin-side telemetry transport."
- **Metrics OUT** rides the existing `PluginResult.metadata` field (verified: `cpex/framework/models.py:1858`), one of the channels issue #27 explicitly sanctions. It is **not** `Extensions.custom` (rejected — see the rejected spec banner) and **not** a new `MetricsExtension` (that typed slot is a *future* upgrade owned by `contextforge-org/cpex#43`, out of scope here).
- **What this effort creates:** only plain helper functions and tests (`read_trace_id`, `build_pii_metrics`, `build_request_extensions`, `record_plugin_metrics`) — none of which is an extension class. No file under `cpex/framework/extensions/` is added or modified (that package lives in a separate repo and is out of scope).

**Source specs:**
- CHOSEN: `cpex-plugins/docs/superpowers/specs/2026-06-29-otel-plugin-boundary-metadata-design.md`
- REJECTED (retained): `cpex-plugins/docs/superpowers/specs/2026-06-29-otel-plugin-boundary-design.md` (`Extensions.custom` — multi-plugin lossy, see its banner)

## Global Constraints

These apply to **every** task. Each task's requirements implicitly include this section.

- **Branching:** Do all work on a NEW feature branch in EACH repo. `main` is READ-ONLY — never commit to or merge into `main`. Branch names: `feat/issue-27-otel-metadata` (cpex-plugins), `feat/gateway-otel-plugin-metadata` (mcp-context-forge).
- **No merge / no PRs:** Do NOT merge to main and do NOT open pull requests in this effort. Stop after implementation + local e2e verification.
- **Commits:** DCO sign-off required — always `git commit -s`. Do **NOT** add a `Co-Authored-By` trailer to any commit.
- **Blocker rule:** If any step hits a true blocker (a prerequisite that does not exist, a failing assumption that invalidates the approach, a destructive action, or an external dependency you cannot satisfy), STOP immediately and notify the user with the exact blocker — do not improvise around it.
- **Licensing:** All new source files carry the repo's Apache-2.0 SPDX header. Rust: `// Copyright 2026` / `// SPDX-License-Identifier: Apache-2.0`. Python: add the same as `#` comments.
- **Versioning (cpex-plugins):** Every changed plugin bumps its version in lockstep — `Cargo.toml` (source of truth), `cpex_<plugin>/plugin-manifest.yaml` `version`, and `Cargo.lock` (auto on build).
- **No double-write:** The new `result.metadata` path is authoritative. Remove the legacy `context.metadata` stat writes when the new path lands (P-4). Never keep both.
- **Security (S1, normative):** Metrics carry **counts/types/categories only — never matched content** (no raw PII/secret/token/full URL), and the same rule applies to logs. Each plugin has an explicit allow-list of emitted keys; everything else is denied.
- **CI gate:** `make ci` (cpex-plugins, per plugin dir) and the gateway's `make pre-commit` / test suite must be green before a task is considered done.
- **Scope of pilot:** Implement and fully validate `pii_filter` end-to-end first. Replication to the other five plugins is a documented follow-up (Task A7), not part of the pilot's done-bar.

---

## File Structure

**cpex-plugins (plugin side):**
- Modify `plugins/rust/python-package/pii_filter/cpex_pii_filter/pii_filter.py` — 4 hook signatures gain `extensions=None`, forward to Rust. Add SPDX header.
- Modify `plugins/rust/python-package/pii_filter/src/plugin.rs` — 4 `#[pymethods]` accept `extensions`; read `trace_id`; build metrics dict; set `result.metadata["pii_filter"]`; remove `context.metadata` writes.
- Modify `plugins/rust/python-package/pii_filter/src/bin/stub_gen.rs` — update hardcoded `PLUGIN_CORE_CLASS_DEF` (line ~19) for the new 4-param signatures.
- Modify `plugins/tests/pii_filter/test_integration.py` — migrate 5 `context.metadata` assertions to `result.metadata["pii_filter"]`; add trace-in/metrics-out, no-extensions back-compat, S1 leakage tests.
- Modify `plugins/rust/python-package/pii_filter/Cargo.toml` (version) + `cpex_pii_filter/plugin-manifest.yaml` (version).
- Create `cpex-plugins/docs/superpowers/contracts/pii_filter-metrics-schema.md` — D1 metric-schema contract (allow/deny list).
- Modify `plugins/rust/python-package/pii_filter/README.md` (D2) + repo `CLAUDE.md`/dev guide (D3) + plugin changelog (D5).

**mcp-context-forge (gateway side):**
- Modify `mcpgateway/middleware/observability_middleware.py` — bridge the request `span_id` into `request.state` (resolve the span_id gap) [G0].
- Modify the pilot's invoke_hook call sites for the tool + prompt paths — build + pass `extensions=` [G0]. Pilot subset: `mcpgateway/services/tool_service.py` (pre/post invoke), `mcpgateway/services/prompt_service.py:2012,2100`.
- Modify `mcpgateway/plugins/observability_adapter.py` — add metric/attribute consumption method [G1].
- Create the G1 consumer hook in the plugin-execution path that reads `result.metadata["<plugin>"]`, validates (S4), batches (P-3), and records.
- Add gateway unit/integration tests under `tests/unit/mcpgateway/` and `tests/integration/`.
- Create `tests/e2e/test_otel_plugin_metadata_e2e.py` (or a standalone script) — real HTTP request → `/observability` shows plugin metrics [Phase C].

---

## Phase 0 — Setup, branches, and tracking issues

### Task 0: Branches + new gateway issue

**Files:** none (git + GitHub only)

**Interfaces:**
- Produces: two feature branches; one new gateway tracking issue number (referenced by gateway commits).

- [ ] **Step 1: Confirm both repos are on a clean `main` and create feature branches**

```bash
cd /home/suresh/dev/issue_cpex_27/cpex-plugins && git status && git checkout -b feat/issue-27-otel-metadata
cd /home/suresh/dev/issue_cpex_27/mcp-context-forge && git status && git checkout -b feat/gateway-otel-plugin-metadata
```
Expected: each repo reports the new branch checked out. If `git status` shows the working tree is NOT clean or the repo is not on `main`, STOP and notify (blocker rule).

- [ ] **Step 2: Create the gateway G0+G1 tracking issue**

Issue research confirmed: `IBM/cpex-plugins#27` (plugin side) and `contextforge-org/cpex#43` (framework contract) already exist; the only matching gateway tracker `IBM/mcp-context-forge#4225` is CLOSED/COMPLETED and predates the Extensions framing and does not cover G1. So create ONE new gateway issue.

```bash
gh issue create --repo IBM/mcp-context-forge \
  --title "[FEATURE]: Build and consume CPEX plugin trace context + metrics at the gateway boundary (G0+G1)" \
  --label enhancement --label observability --label triage \
  --body "$(cat <<'EOF'
## Summary
Companion gateway work for IBM/cpex-plugins#27. Two phases:

- **G0** — The gateway builds `Extensions(request=RequestExtension(trace_id, span_id))` from the active trace and passes `extensions=` into plugin execution. `cpex.framework.manager.invoke_hook` already accepts and forwards `extensions=` (no framework change); the ~17 gateway call sites currently pass nothing. Also bridge the request `span_id` into `request.state` (today only `trace_id` is bridged).
- **G1** — After the executor returns, read `PluginResult.metadata["<plugin>"]`, validate as untrusted output (type/size only), batch DB writes, and attach as span attributes (primary) / `ObservabilityService.record_metric` (secondary).

## Out of scope
- Plugin-side changes (tracked in IBM/cpex-plugins#27).
- A separate telemetry transport or external OTel collector requirement.

## Related
- Plugin side: IBM/cpex-plugins#27
- Framework contract: contextforge-org/cpex#43 (trace/metrics protocol)
- Prior (closed): IBM/mcp-context-forge#4225 (partial trace-context handoff), #4220 (per-plugin spans)
- Adjacent (open): IBM/mcp-context-forge#3736 (observability hardening)
EOF
)"
```
Expected: prints the new issue URL. Record the number as `<GATEWAY_ISSUE>` — gateway commit messages reference it (`Refs #<GATEWAY_ISSUE>`).

- [ ] **Step 3: (no commit)** — branch + issue creation needs no commit. Proceed to Phase A.

---

## Phase A — Plugin pilot: `pii_filter` (cpex-plugins, closes #27)

Working dir for this phase: `/home/suresh/dev/issue_cpex_27/cpex-plugins/plugins/rust/python-package/pii_filter`

### Task A1: Rust core accepts `extensions` and reads `trace_id` (gate)

**Files:**
- Modify: `src/plugin.rs` (the 4 `#[pymethods]` at lines ~35-234; add a trace-context reader helper)
- Test: `src/plugin.rs` `mod tests` (inline, ~line 517)

**Interfaces:**
- Consumes: PyO3 `Bound<'_, PyAny>` for the new optional `extensions` arg.
- Produces: a helper `fn read_trace_id(extensions: Option<&Bound<'_, PyAny>>) -> Option<String>` returning `Some(trace_id)` only when `extensions.request.trace_id` is a non-empty string; `None` (never an error) otherwise. Each hook's `#[pymethods]` signature becomes `(&self, py, payload, context, extensions=None)`.

- [ ] **Step 1: Write the failing Rust unit test for `read_trace_id`**

Add to `mod tests` in `src/plugin.rs`. Build a fake extensions object with PyO3 (mirror the `clone_payload_with_attr` test style at line 549 which uses `Python::attach` + `PyModule::from_code`):

```rust
#[test]
fn read_trace_id_returns_value_when_present_and_none_otherwise() {
    pyo3::Python::initialize();
    Python::attach(|py| {
        let module = PyModule::from_code(
            py,
            c_str!(
                "class Req:\n    def __init__(self, t):\n        self.trace_id = t\n\
                 class Ext:\n    def __init__(self, t):\n        self.request = Req(t)\n"
            ),
            c_str!("ext.py"),
            c_str!("ext"),
        )
        .unwrap();
        let with_id = module.getattr("Ext").unwrap().call1(("abc123",)).unwrap();
        let without = module.getattr("Ext").unwrap().call1((py.None(),)).unwrap();
        assert_eq!(read_trace_id(Some(&with_id)), Some("abc123".to_string()));
        assert_eq!(read_trace_id(Some(&without)), None);
        assert_eq!(read_trace_id(None), None);
    });
}
```

- [ ] **Step 2: Run it — verify it fails to compile (function not defined)**

Run: `cargo nextest run -p pii_filter read_trace_id 2>&1 | tail -20`
Expected: compile error `cannot find function read_trace_id`.

- [ ] **Step 3: Implement `read_trace_id` (best-effort, never raises)**

Add near the other free helpers in `src/plugin.rs`. It must swallow every PyO3 error and treat missing/None/wrong-type as absent (L1):

```rust
/// Best-effort read of `extensions.request.trace_id`. Returns `None` on any
/// missing attribute, `None` value, wrong type, or PyO3 error — never raises.
fn read_trace_id(extensions: Option<&Bound<'_, PyAny>>) -> Option<String> {
    let ext = extensions?;
    let request = ext.getattr("request").ok()?;
    if request.is_none() {
        return None;
    }
    let trace = request.getattr("trace_id").ok()?;
    if trace.is_none() {
        return None;
    }
    let s: String = trace.extract().ok()?;
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}
```

- [ ] **Step 4: Add the `extensions` param to the 4 `#[pymethods]` signatures**

For each of `prompt_pre_fetch` (line ~35), `prompt_post_fetch` (~58), `tool_pre_invoke` (~190), `tool_post_invoke` (~213), change the signature to accept an optional extensions arg and add the PyO3 default. Use `#[pyo3(signature = (...))]` so the default is `None`:

```rust
#[cfg_attr(feature = "stub-gen", gen_stub_pymethods)]
#[pyo3(signature = (payload, context, extensions=None))]
fn tool_post_invoke(
    &self,
    py: Python<'_>,
    payload: &Bound<'_, PyAny>,
    context: &Bound<'_, PyAny>,
    extensions: Option<&Bound<'_, PyAny>>,
) -> PyResult<Py<PyAny>> {
    let trace_id = read_trace_id(extensions);
    // existing body unchanged for now; trace_id consumed in Task A3.
    let _ = &trace_id;
    // ...existing delegation...
}
```
Apply the same `#[pyo3(signature = ...)]` + `extensions: Option<&Bound<'_, PyAny>>` + `let trace_id = read_trace_id(extensions);` to all four. Pass `trace_id` down into `handle_nested_stage` / the post-fetch body (add a `trace_id: Option<&str>` param to `handle_nested_stage`, threaded but unused until A3).

- [ ] **Step 5: Run the unit test + full Rust unit suite — verify pass**

Run: `cargo nextest run -p pii_filter 2>&1 | tail -20`
Expected: PASS, including `read_trace_id_returns_value_when_present_and_none_otherwise` and the two existing tests.

- [ ] **Step 6: Commit**

```bash
git add src/plugin.rs
git commit -s -m "feat(pii_filter): accept extensions and read trace_id at the Rust hook boundary

Refs #27"
```

### Task A2: Python shim forwards `extensions` (pass-through)

**Files:**
- Modify: `cpex_pii_filter/pii_filter.py` (4 hooks, lines 17-27; add SPDX header at top)
- Test: `plugins/tests/pii_filter/test_integration.py`

**Interfaces:**
- Consumes: the Rust `#[pymethods]` from A1 (now 3 user params + self).
- Produces: 4 async shim hooks `async def <hook>(self, payload, context, extensions=None)` that call `self._core.<hook>(payload, context, extensions)`.

- [ ] **Step 1: Write the failing back-compat + forwarding test**

Add to `plugins/tests/pii_filter/test_integration.py`. Reuse `_make_config`/`_make_context` (lines 55-72) and the real cpex `Extensions`/`RequestExtension`:

```python
from cpex.framework.extensions import Extensions, RequestExtension

@pytest.mark.asyncio
async def test_hook_accepts_and_forwards_extensions():
    plugin = PIIFilterPlugin(_make_config())
    ext = Extensions(request=RequestExtension(trace_id="trace-xyz"))
    payload = ToolPostInvokePayload(name="t", result={"email": "alice@example.com"})
    result = await plugin.tool_post_invoke(payload, _make_context(), ext)
    assert result is not None  # forwarding works; metrics asserted in A3

@pytest.mark.asyncio
async def test_hook_without_extensions_is_backward_compatible():
    plugin = PIIFilterPlugin(_make_config())
    payload = ToolPostInvokePayload(name="t", result={"email": "alice@example.com"})
    result = await plugin.tool_post_invoke(payload, _make_context())  # 2-arg call
    assert result is not None
```

- [ ] **Step 2: Run — verify it fails**

Run: `make test-integration 2>&1 | tail -30` (target runs `CPEX_TEST_PLUGIN_HOOKS=1 uv run pytest ../../../tests/pii_filter/test_integration.py -v -rs`)
Expected: FAIL — `tool_post_invoke() takes 3 positional arguments but 4 were given` (shim not yet updated).

- [ ] **Step 3: Update the 4 shim signatures + add SPDX header**

Top of `cpex_pii_filter/pii_filter.py` (currently missing SPDX, line 1 is the coding comment):

```python
# -*- coding: utf-8 -*-
# Copyright 2026
# SPDX-License-Identifier: Apache-2.0
```
Then each hook (4 of them):

```python
async def tool_post_invoke(self, payload, context, extensions=None):
    return self._core.tool_post_invoke(payload, context, extensions)
```
Apply to `prompt_pre_fetch`, `prompt_post_fetch`, `tool_pre_invoke`, `tool_post_invoke`.

- [ ] **Step 4: Rebuild the extension + run tests — verify pass**

Run: `make install && make test-integration 2>&1 | tail -30`
Expected: PASS for both new tests. (Note: `make install` runs `maturin develop --release`; the Rust change from A1 must be rebuilt for the shim to call the new arity.)

- [ ] **Step 5: Commit**

```bash
git add cpex_pii_filter/pii_filter.py plugins/tests/pii_filter/test_integration.py
git commit -s -m "feat(pii_filter): forward optional extensions through the Python shim

Refs #27"
```

### Task A3: Rust core builds gated metrics + sets `result.metadata["pii_filter"]`; remove `context.metadata` writes

**Files:**
- Modify: `src/plugin.rs` — `record_stats` (387-400) and `record_metadata_summary` (357-385) become metrics-dict builders; result-build calls (`build_result` at 118, 177, 264, 300; the emitting paths) gain a `("metadata", <PyDict>)` kwarg. The `default_result` no-op paths (187, 311, 67, 247) emit NOTHING (stay unchanged).
- Test: `src/plugin.rs` `mod tests`

**Interfaces:**
- Consumes: `trace_id: Option<&str>` threaded from A1; existing detection stats.
- Produces: when `trace_id` is `Some`, a `metadata` kwarg of shape `{"pii_filter": {<allowlisted keys>}}` on every EMITTING result (masked/blocked). When `trace_id` is `None`, no metrics dict is built and no `metadata` kwarg is added (P-1/L3). Allowlisted keys (D1, see Task A4): `total_detections:int`, `total_masked:int`, `detection_types:list[str]`, `stage:str`. **Never** the matched value (S1).

- [ ] **Step 1: Write the failing Rust unit test (gate + content)**

```rust
#[test]
fn metrics_emitted_only_when_trace_id_present_and_carry_no_content() {
    pyo3::Python::initialize();
    Python::attach(|py| {
        // helper builds an emitting result and returns its .metadata dict (or None)
        let with_trace = build_pii_metrics(py, Some("t1"), /*total_detections*/ 2,
            /*total_masked*/ 2, &["email", "ssn"], "tool_post_invoke").unwrap();
        let md = with_trace.unwrap();
        let inner = md.get_item("pii_filter").unwrap().unwrap();
        assert_eq!(inner.get_item("total_detections").unwrap().unwrap()
            .extract::<i64>().unwrap(), 2);
        // S1: no key/value contains the matched email
        let dumped = format!("{:?}", inner.str().unwrap());
        assert!(!dumped.contains("alice@example.com"));
        // gate: no trace_id => None
        assert!(build_pii_metrics(py, None, 2, 2, &["email"], "tool_post_invoke")
            .unwrap().is_none());
    });
}
```

- [ ] **Step 2: Run — verify it fails to compile**

Run: `cargo nextest run -p pii_filter metrics_emitted 2>&1 | tail -20`
Expected: compile error `cannot find function build_pii_metrics`.

- [ ] **Step 3: Implement `build_pii_metrics` (the single metrics builder)**

Add to `src/plugin.rs`. It returns `PyResult<Option<Bound<'_, PyDict>>>` — `Ok(None)` when `trace_id` is absent (gate), otherwise an allowlisted, bounded dict namespaced under `"pii_filter"`:

```rust
const MAX_DETECTION_TYPES: usize = 32;

/// Build the namespaced metrics dict for the result.metadata channel.
/// Returns None (no work) when trace_id is absent (P-1/L3). Allowlist only:
/// counts/types/stage — never matched content (S1). Bounded (S3).
fn build_pii_metrics<'py>(
    py: Python<'py>,
    trace_id: Option<&str>,
    total_detections: i64,
    total_masked: i64,
    detection_types: &[&str],
    stage: &str,
) -> PyResult<Option<Bound<'py, PyDict>>> {
    if trace_id.is_none() {
        return Ok(None);
    }
    let inner = PyDict::new(py);
    inner.set_item("total_detections", total_detections)?;
    inner.set_item("total_masked", total_masked)?;
    let mut types: Vec<&str> = detection_types.to_vec();
    types.sort_unstable();
    types.dedup();
    types.truncate(MAX_DETECTION_TYPES);
    inner.set_item("detection_types", types)?;
    inner.set_item("stage", stage)?;
    let outer = PyDict::new(py);
    outer.set_item("pii_filter", inner)?;
    Ok(Some(outer))
}
```

- [ ] **Step 4: Wire metrics onto emitting result-build calls; remove `context.metadata` writes**

At each EMITTING return path, append a `metadata` kwarg when `build_pii_metrics` returns `Some`. Wrap in a best-effort closure so any failure is caught, logged once, and the normal filtering result is returned WITHOUT metrics (L2 — no `?`/`unwrap`/`panic` on the metrics branch). Example for the masked path (`handle_nested_stage`, lines ~300-309):

```rust
let mut kwargs: Vec<(&str, Py<PyAny>)> =
    vec![("modified_payload", clone_payload_with_attr(py, payload, ...)?.into())];
if let Some(tid) = trace_id {
    match build_pii_metrics(py, Some(tid), total_detections, total_masked, &types, stage) {
        Ok(Some(md)) => kwargs.push(("metadata", md.into())),
        Ok(None) => {}
        Err(e) => log::warn!("pii_filter: metrics build failed, omitting: {e}"),
    }
}
// build via the variadic-friendly path (build_framework_object takes a fixed array;
// use a small Vec->array adapter or a dedicated build_result_with_metadata helper).
```
Then DELETE the legacy writes: `record_stats` body that sets `context.metadata["pii_filter_stats"]` (393-398) and `record_metadata_summary`'s `context.metadata["pii_detections"]` writes (369-383). Repurpose those functions to RETURN the values feeding `build_pii_metrics` (P-4: single authoritative path, no double-write). Leave `default_result` no-op paths untouched — they emit nothing.

> NOTE on `build_framework_object`: it takes a const-generic fixed array `[(&str, Py<PyAny>); N]`. Because the emitting paths now have a variable kwarg count (with/without `metadata`), add a sibling helper in `crates/framework_bridge/src/lib.rs` — `build_framework_object_dyn(py, class_name, kwargs: Vec<(&str, Py<PyAny>)>)` — OR construct the two fixed arrays per branch. Prefer the `_dyn` helper (one place, reused by replication). If you add it, that is a `framework_bridge` change → bump framework_bridge + rebuild dependents (see Versioning) and add a `mod tests` case mirroring `build_framework_object_passes_keyword_arguments` (lib.rs:91).

- [ ] **Step 5: Run Rust unit suite — verify pass**

Run: `cargo nextest run -p pii_filter 2>&1 | tail -20`
Expected: PASS including `metrics_emitted_only_when_trace_id_present_and_carry_no_content`.

- [ ] **Step 6: Commit**

```bash
git add src/plugin.rs ../../../../crates/framework_bridge/src/lib.rs
git commit -s -m "feat(pii_filter): emit gated counts/types metrics on result.metadata; drop context.metadata writes

Refs #27"
```

### Task A4: Metric-schema contract (D1) + S1 leakage test + S3 bounds test

**Files:**
- Create: `docs/superpowers/contracts/pii_filter-metrics-schema.md`
- Test: `plugins/tests/pii_filter/test_integration.py` (S1) and `src/plugin.rs` `mod tests` (S3 bounds)

**Interfaces:**
- Consumes: `build_pii_metrics` output shape from A3.
- Produces: the cross-repo contract doc G1 consumes (allow-list + deny-list).

- [ ] **Step 1: Write the D1 contract doc**

Create `docs/superpowers/contracts/pii_filter-metrics-schema.md` with: namespace key `pii_filter`; ALLOW-LIST (the only keys emitted) `total_detections:int`, `total_masked:int`, `detection_types:list[str]` (≤32, sorted, deduped), `stage:str`; bounds (S3); and a DENY-LIST of content-bearing fields that MUST NOT be emitted (matched values, raw payloads). Note this is the contract the gateway G1 validates against.

- [ ] **Step 2: Write the failing S1 leakage test (Python integration)**

```python
@pytest.mark.asyncio
async def test_no_sensitive_content_in_metrics_or_logs(caplog):
    plugin = PIIFilterPlugin(_make_config())
    ext = Extensions(request=RequestExtension(trace_id="t1"))
    secret = "alice@example.com"
    payload = ToolPostInvokePayload(name="t", result={"email": secret})
    with caplog.at_level("DEBUG"):
        result = await plugin.tool_post_invoke(payload, _make_context(), ext)
    metrics = result.metadata["pii_filter"]
    flat = str(metrics)
    assert secret not in flat
    assert set(metrics) <= {"total_detections", "total_masked", "detection_types", "stage"}
    assert secret not in caplog.text
```

- [ ] **Step 3: Run — verify it passes (A3 already enforces allow-list)**

Run: `make test-integration 2>&1 | tail -30`
Expected: PASS. If `secret` appears, A3's builder is leaking — fix the builder, not the test (blocker if structural).

- [ ] **Step 4: Add the S3 bounds Rust unit test**

```rust
#[test]
fn detection_types_are_bounded_and_deduped() {
    pyo3::Python::initialize();
    Python::attach(|py| {
        let many: Vec<String> = (0..100).map(|i| format!("t{i}")).collect();
        let refs: Vec<&str> = many.iter().map(|s| s.as_str()).collect();
        let md = build_pii_metrics(py, Some("t1"), 1, 1, &refs, "s").unwrap().unwrap();
        let inner = md.get_item("pii_filter").unwrap().unwrap();
        let types = inner.get_item("detection_types").unwrap().unwrap();
        assert!(types.len().unwrap() <= MAX_DETECTION_TYPES);
    });
}
```

- [ ] **Step 5: Run Rust + Python suites — verify pass**

Run: `cargo nextest run -p pii_filter 2>&1 | tail -10 && make test-integration 2>&1 | tail -10`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add docs/superpowers/contracts/pii_filter-metrics-schema.md plugins/tests/pii_filter/test_integration.py src/plugin.rs
git commit -s -m "feat(pii_filter): add metric-schema contract; S1 leakage + S3 bounds tests

Refs #27"
```

### Task A5: Migrate existing `context.metadata` assertions to `result.metadata`

**Files:**
- Modify: `plugins/tests/pii_filter/test_integration.py` (5 sites: lines ~111, ~131, ~297-300, ~386, ~489-496)

**Interfaces:**
- Consumes: the new `result.metadata["pii_filter"]` channel.

- [ ] **Step 1: Update the assertions (pass `extensions` so metrics emit, then assert on the result)**

For each migrated test, add `ext = Extensions(request=RequestExtension(trace_id="t1"))`, call the hook with it, and replace `context.metadata[...]` reads. Examples:
- line ~131 `context.metadata["pii_detections"]["prompt_pre_fetch"]["total_count"] == 2` → assert `result.metadata["pii_filter"]["total_detections"] == 2` (adjust to the contract keys).
- lines ~297-300 `context.metadata["pii_filter_stats"] == {"total_detections":1,"total_masked":1}` → `result.metadata["pii_filter"]["total_detections"] == 1` and `["total_masked"] == 1`.
- line ~111 / ~386 "not in context.metadata" / "is None" (no-detection / blocked) → assert `"pii_filter" not in (result.metadata or {})` for the no-emit cases, OR that the metrics key is absent. Keep one authoritative assertion per case (no double-write).

- [ ] **Step 2: Run the full plugin test suite — verify pass**

Run: `make test-all 2>&1 | tail -40`
Expected: PASS (Rust unit + Python unit + integration), no remaining `context.metadata["pii_*"]` references.

- [ ] **Step 3: Grep to confirm no legacy references remain**

Run: `rg -n "context.metadata\[.(pii_filter_stats|pii_detections)" plugins/tests/pii_filter src/ || echo CLEAN`
Expected: `CLEAN`.

- [ ] **Step 4: Commit**

```bash
git add plugins/tests/pii_filter/test_integration.py
git commit -s -m "test(pii_filter): migrate metadata assertions to result.metadata channel

Refs #27"
```

### Task A6: Stubs, version bump, docs, CI green

**Files:**
- Modify: `src/bin/stub_gen.rs` (`PLUGIN_CORE_CLASS_DEF`, ~line 19)
- Modify: `Cargo.toml` (version), `cpex_pii_filter/plugin-manifest.yaml` (version)
- Modify: `README.md` (D2), repo `CLAUDE.md` dev guide (D3), changelog (D5)

**Interfaces:** none downstream.

- [ ] **Step 1: Update the hardcoded stub class def for the new signatures**

In `src/bin/stub_gen.rs`, edit `PLUGIN_CORE_CLASS_DEF` so each of the 4 hooks reads `(self, payload: typing.Any, context: typing.Any, extensions: typing.Any = None) -> typing.Any`.

- [ ] **Step 2: Regenerate stubs + verify**

Run: `make stub-gen && make verify-stubs`
Expected: both `.pyi` files exist and `verify-stubs` passes; `git diff` shows the `extensions` param in `cpex_pii_filter/pii_filter_rust/__init__.pyi`.

- [ ] **Step 3: Bump version in lockstep (0.3.5 → 0.3.6)**

Edit `Cargo.toml:3` `version = "0.3.6"` and `cpex_pii_filter/plugin-manifest.yaml:3` `version: "0.3.6"`. `Cargo.lock` updates on the next build.

- [ ] **Step 4: Write docs**

- `README.md` (D2): document the optional `extensions` hook param and what `pii_filter` emits on `result.metadata["pii_filter"]`; state the no-sensitive-content guarantee (S1).
- repo `CLAUDE.md` / "Creating a New Plugin" (D3): the trace-in / metrics-out convention (namespaced `result.metadata` key, gated on `trace_id`).
- changelog (D5): hook-signature change (added optional `extensions`, backward-compatible) + stats relocation `context.metadata` → `result.metadata`.

- [ ] **Step 5: Full CI — verify green**

Run: `make ci 2>&1 | tail -40`
Expected: PASS (`ci-build` = check-all + verify-stubs + build + bench-no-run + install-wheel, then `test-integration`).

- [ ] **Step 6: Commit**

```bash
git add src/bin/stub_gen.rs Cargo.toml Cargo.lock cpex_pii_filter/plugin-manifest.yaml README.md ../../../../CLAUDE.md
git commit -s -m "chore(pii_filter): regen stubs, bump to 0.3.6, document extensions/metrics

Closes #27"
```

### Task A7: Replication scaffold for the other five plugins (documented follow-up, NOT in pilot done-bar)

**Files:** Modify: this plan + the dev guide.

- [ ] **Step 1: Record the replication checklist (no code)**

Document that each of `rate_limiter`, `secrets_detection`, `url_reputation`, `encoded_exfil_detection`, `retry_with_backoff` repeats A1-A6 under its own `result.metadata["<plugin>"]` key, with its own D1 allow/deny-list written and S1 leakage test passing BEFORE that plugin is replicated. Note: NO plugin needs a new `framework_bridge` dependency in this variant (the executor does the merge) — including `url_reputation`, which lacks the dep but does not need it. Deny-list per the spec: `encoded_exfil_detection` deny `match`/`matched_preview`; `url_reputation` deny `url`/`details.url`/`path`; `secrets_detection` derive from counts/types only, never a pre-redaction value.

- [ ] **Step 2: Commit**

```bash
git add docs/superpowers/plans/2026-06-30-otel-plugin-boundary-metadata.md
git commit -s -m "docs: record replication checklist for remaining plugins

Refs #27"
```

---

## Phase B — Gateway companion: G0 + G1 (mcp-context-forge, Refs #<GATEWAY_ISSUE>)

Working dir: `/home/suresh/dev/issue_cpex_27/mcp-context-forge`

### Task B0: Bridge `span_id` into `request.state` (resolve the G0 span_id gap)

**Files:**
- Modify: `mcpgateway/middleware/observability_middleware.py` (around the `start_span` call ~line 191 and the contextvar set at 180-183)
- Test: `tests/unit/mcpgateway/middleware/` (observability middleware test)

**Interfaces:**
- Produces: `request.state.span_id` (str | None) available at hook-invocation time, alongside the existing `request.state.trace_id` (line 180).

- [ ] **Step 1: Write the failing test** — assert that after the middleware runs a traced request, `request.state.span_id` is set when a span is created. Mirror the existing observability middleware unit test setup.

- [ ] **Step 2: Run — verify it fails.** `cd mcpgateway && python -m pytest tests/unit/mcpgateway/middleware/...span... -v` → FAIL (`span_id` not on state).

- [ ] **Step 3: Implement** — capture the span_id returned by `observability_service.start_span(...)` (~line 191) into `request.state.span_id = span_id`. Do NOT add a new contextvar unless needed; `request.state` is sufficient for the call sites.

- [ ] **Step 4: Run — verify pass.**

- [ ] **Step 5: Commit** — `git commit -s -m "feat(observability): expose request span_id on request.state for plugin trace context\n\nRefs #<GATEWAY_ISSUE>"`

### Task B1: G0 — build and pass `Extensions` at the pilot call sites

**Files:**
- Modify: `mcpgateway/services/tool_service.py` (tool pre/post invoke invoke_hook calls — pilot fires here), `mcpgateway/services/prompt_service.py:2012,2100`
- Test: `tests/unit/mcpgateway/services/test_a2a_agent_invoke_hooks.py`-style new test for the tool/prompt path

**Interfaces:**
- Consumes: `request.state.trace_id` (line 180) and `request.state.span_id` (B0); `from cpex.framework.extensions import Extensions, RequestExtension`.
- Produces: every pilot `invoke_hook(...)` call passes `extensions=Extensions(request=RequestExtension(trace_id=..., span_id=...))` (both may be None — emission gates on trace_id presence).

- [ ] **Step 1: Write the failing G0 unit test** — mock `invoke_hook` (AsyncMock) and assert `invoke_hook.await_args_list[0].kwargs["extensions"].request.trace_id` equals the active trace. Pattern from `test_a2a_agent_invoke_hooks.py:95,244-246`.

- [ ] **Step 2: Run — verify it fails** (`extensions` absent / KeyError).

- [ ] **Step 3: Implement** — add a small helper (e.g. in `mcpgateway/plugins/__init__.py` or a util) `build_request_extensions() -> Optional[Extensions]` that reads the active trace_id/span_id (from the contextvar `mcpgateway.services.observability_service.current_trace_id` or `request.state`) and returns `Extensions(request=RequestExtension(trace_id=tid, span_id=sid))` or `None` when no trace is active. Pass `extensions=build_request_extensions()` at each pilot `invoke_hook` call site. Keep it best-effort (never raise into the request path).

- [ ] **Step 4: Run — verify pass.**

- [ ] **Step 5: Commit** — `git commit -s -m "feat(plugins): pass CPEX trace Extensions into plugin execution (G0)\n\nRefs #<GATEWAY_ISSUE>"`

### Task B2: G1 — consume `result.metadata["<plugin>"]` into observability

**Files:**
- Modify: `mcpgateway/plugins/observability_adapter.py` (add a metric/attribute consumption method)
- Modify: the plugin-execution path that owns the `invoke_hook` result (the same pilot call sites in tool/prompt service) to call the consumer
- Test: `tests/unit/mcpgateway/services/test_observability_service.py`-style (record_metric mock) + `tests/unit/mcpgateway/plugins/test_observability_adapter.py`-style (S4/L4 swallow) + `tests/integration/plugins/test_span_attribute_customizer_integration.py`-style (real-DB span attributes)

**Interfaces:**
- Consumes: `result.metadata` from `invoke_hook`; the D1 contract (`docs/superpowers/contracts/pii_filter-metrics-schema.md`) for valid keys/types.
- Produces: a consumer `record_plugin_metrics(trace_id, span_id, metadata: dict) -> None` that, for each `metadata[<plugin>]`, validates (S4: only `str|int|float|bool`, bounded length/key count; drop/truncate else; never log dropped values), batches (P-3: one session/call), and attaches as span attributes (primary) + optional `record_metric` (secondary). Best-effort/swallow all failures (L4).

- [ ] **Step 1: Write the failing G1 unit test** — given a fake `result.metadata = {"pii_filter": {"total_detections": 2, ...}}`, assert the consumer calls `record_metric`/span-attribute attach with the expected names; assert a non-scalar/oversized value is dropped (S4); assert a recording exception is swallowed (L4). Patterns: `test_observability_service.py:113-126`, `test_observability_adapter.py:93-125`.

- [ ] **Step 2: Run — verify it fails.**

- [ ] **Step 3: Implement** the S4 validator + the consumer method on `ObservabilityServiceAdapter` (or a standalone function calling `ObservabilityService.record_metric` / `start_span(attributes=...)`). Wire it after each pilot `invoke_hook` returns. Reuse the `start_span(..., context=...)`/`custom_span_attributes` precedent from `SpanAttributeCustomizerPlugin` if attaching to the hook-chain span.

- [ ] **Step 4: Run — verify pass.**

- [ ] **Step 5: Add the real-DB integration test** — load the pilot under `PLUGINS_ENABLED`, fire the hook with trace context, assert the plugin metrics reach `ObservabilityService` (span attributes / metric rows). Mirror `tests/integration/plugins/test_span_attribute_customizer_integration.py:30,110-133`. P-3: assert a single session/call for all plugin metrics of a request.

- [ ] **Step 6: Run gateway test suite — verify pass** (`make pre-commit` or targeted `python -m pytest tests/unit/mcpgateway/... tests/integration/plugins/... -v`).

- [ ] **Step 7: Commit** — `git commit -s -m "feat(plugins): consume plugin result.metadata into observability (G1)\n\nRefs #<GATEWAY_ISSUE>"`

---

## Phase C — Local end-to-end verification (close to real usage)

### Task C1: E2E script — traced HTTP request shows plugin metrics in `/observability`

**Files:**
- Create: `mcp-context-forge/tests/e2e/test_otel_plugin_metadata_e2e.py` (pytest e2e) AND a runnable shell wrapper `mcp-context-forge/scripts/verify_otel_plugin_e2e.sh` for manual real-usage verification.

**Interfaces:**
- Consumes: the fully implemented Phase A (installed pilot) + Phase B (G0+G1).

- [ ] **Step 1: Install the pilot into the gateway env**

```bash
cd /home/suresh/dev/issue_cpex_27/mcp-context-forge
uv pip install -e ../cpex-plugins/plugins/rust/python-package/pii_filter   # builds the Rust ext
```
Expected: install succeeds (maturin builds). If the build fails, STOP and notify (blocker).

- [ ] **Step 2: Add the pilot to `plugins/config.yaml`**

Append a `pii_filter` entry under `plugins:` (kind = the pilot's dotted class path, `mode: "enforce"` or `"permissive"`, hooks = the 4, priority set). Mirror the `SpanAttributeCustomizer` entry style (`plugins/config.yaml:19`).

- [ ] **Step 3: Write the e2e script (real HTTP, as close to real usage as possible)**

`scripts/verify_otel_plugin_e2e.sh`: start the gateway with `PLUGINS_ENABLED=true OBSERVABILITY_ENABLED=true` (e.g. `make dev` / `make serve` with env), mint an admin JWT (`python -m mcpgateway.utils.create_jwt_token --username admin@example.com --secret $JWT_SECRET_KEY`), issue a REAL traced tool call over HTTP that contains PII (so `pii_filter` fires), capture the `X-Trace-Id`, then `GET /observability/traces/{trace_id}` with the admin JWT and assert the response `spans[].attributes` (or metrics by `trace_id`) contain the `pii_filter` counts — and that NO matched PII value appears anywhere in the trace (S1 end-to-end). The pytest version uses `TestClient` and the real `ObservabilityService` fixture; the `.sh` version hits a live server for true real-usage fidelity.

- [ ] **Step 4: Run the e2e — verify the issue is resolved locally**

Run: `bash scripts/verify_otel_plugin_e2e.sh` (and/or `python -m pytest tests/e2e/test_otel_plugin_metadata_e2e.py -v`)
Expected: the trace shows `pii_filter` metrics (counts/types) and contains NO raw PII. This is the concrete "issue verified locally" gate. If metrics do not appear, debug the G0→executor→plugin→G1 chain (use systematic-debugging); if raw PII appears, that is a security blocker — STOP and notify.

- [ ] **Step 5: Commit** — `git commit -s -m "test(e2e): verify plugin trace metrics reach /observability with no PII leak\n\nRefs #<GATEWAY_ISSUE>"`

---

## Phase D — Review and cross-checks

### Task D1: Code review of the full diff (both repos), then fix findings

**Files:** all changed files in both repos.

- [ ] **Step 1: Run a code review** on each repo's branch diff (use the `/code-review` skill or `superpowers:requesting-code-review`). Cover correctness, S1 leakage, S4 validation, L1/L2 exception isolation, P-1 gating, P-3 batching, no double-write (P-4), and that no `Co-Authored-By` slipped into any commit.

- [ ] **Step 2: Triage findings** with `superpowers:receiving-code-review` (verify before applying; push back on wrong suggestions).

- [ ] **Step 3: Fix confirmed issues**, re-running the relevant test suites after each fix (TDD). Commit fixes with `-s`, no `Co-Authored-By`.

- [ ] **Step 4: Re-run full suites** — cpex-plugins `make ci`; gateway targeted tests + e2e — verify all green.

### Task D2: Cross-check against spec AND plan

**Files:** the spec + this plan.

- [ ] **Step 1: Check implementation vs the chosen spec** (`2026-06-29-otel-plugin-boundary-metadata-design.md`). Walk every section (Summary, P1-P5, G0/G1, S1-S4, P-1..P-4, L1-L4, D1-D5, Versioning, Success criteria) and confirm a corresponding change exists. List any gap.

- [ ] **Step 2: Check implementation vs this plan** — every task's deliverable present and its tests green.

- [ ] **Step 3: Report** a short conformance summary (spec section → evidence). For any gap, either fix it (loop back) or record it explicitly with justification.

- [ ] **Step 4: STOP — do not open PRs.** Per constraints, the effort ends here. Notify the user that both branches are ready, tests + e2e green, and PRs are intentionally NOT created.

---

## Notes, gaps, and blockers to watch

- **span_id gap (gateway):** the middleware never stored `span_id` (only `trace_id`). Task B0 fixes this. If B0 proves infeasible, fall back to `span_id=None` (RequestExtension allows it; emission still gates on `trace_id`) — but note correlation-by-parent-span is then weaker. Decide in B0; if it forces a larger middleware refactor, STOP and notify.
- **framework_bridge `_dyn` helper (plugin):** A3 may add `build_framework_object_dyn` to support a variable kwarg count. That is a `framework_bridge` change → version it and rebuild all dependents (5 plugins). If you instead build two fixed arrays per branch, no bridge change is needed — prefer whichever keeps the diff smallest; the `_dyn` helper is better for replication.
- **cpex#43 "Blocks #27":** the framework-side protocol issue is marked as blocking #27, but issue #27 explicitly states cpex#43 is informative, NOT a hard blocker. Proceed; do not wait on cpex#43.
- **invoke_hook call-site breadth:** there are ~17 call sites; the pilot only needs the tool + prompt paths. Full G0 rollout to all sites is part of the gateway issue's later scope, not the pilot.
- **verify-stubs is existence-only:** it does not diff regenerated content, so a stale `PLUGIN_CORE_CLASS_DEF` would pass CI — Task A6 Step 1 updates it manually; double-check the diff.

## Self-review (author checklist — completed at plan-creation time)

- Spec coverage: P1→A2, P2→A1, P3+P4→A3, B1(merge)→N/A (executor accumulates; metadata variant), P5→A1/A3/A4/A5 tests, D1→A4, D2/D3/D5→A6, D4(stubs)→A6, Versioning→A6, G0→B0/B1, G1→B2, S1→A4+global, S2→executor (verified manager.py:939), S3→A3/A4, S4→B2, P-1→A3 gate, P-3→B2, P-4→A3/A5, L1/L2→A1/A3, L4→B2, e2e→C1, replication→A7. No spec section left without a task.
- Placeholder scan: no TBD/TODO; code shown for code steps.
- Type consistency: `build_pii_metrics`, `read_trace_id`, `build_request_extensions`, `record_plugin_metrics` names used consistently across tasks; metric keys match the D1 allow-list everywhere.
