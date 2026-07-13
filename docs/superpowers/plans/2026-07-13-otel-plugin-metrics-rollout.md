# Roll Out `result.metadata` Plugin Metrics to 5 Remaining Plugins — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend the `result.metadata["<plugin_name>"]` metrics contract — already shipped for `pii_filter` (0.3.6) via `IBM/cpex-plugins#27` / `#128` — to the 5 remaining bundled plugins, so the gateway's G1 observability pipeline (`IBM/mcp-context-forge#5470`) has something to record for them. Closes `IBM/cpex-plugins#129`. Companion gateway-side issue: `IBM/mcp-context-forge#5554` (separate plan, other repo).

**Architecture:** Same contract as `pii_filter`, five independent ports. **Three implementation shapes, not one** — verified by reading each plugin's source, not assumed:

- **Rust-core plugins** (`secrets_detection`, `rate_limiter`, `retry_with_backoff`): hook logic lives in `src/plugin.rs` behind PyO3 `#[pymethods]`, with a thin Python wrapper (`cpex_<plugin>/*.py`) that just forwards `(payload, context, extensions)` to `self._core.<hook>(...)`. Port `pii_filter`'s Rust pattern directly: add `extensions=None` to the `#[pyo3(signature = ...)]`, call `read_trace_id(extensions)`, gate a `build_<plugin>_metrics()` dict on `trace_id.is_some()`, attach via `result.metadata`. (Reference helper names, verified in `pii_filter/src/plugin.rs`: `build_pii_metrics` (:403) and `push_metrics_kwarg` (:437), both early-return when `trace_id.is_none()`. `build_framework_object_dyn` is the result *constructor*, not a metrics helper — don't copy it as one.)
- **Python-native plugin, clean** (`url_reputation`): hook is pure Python in `cpex_url_reputation/url_reputation.py` and writes **no** `result.metadata` today (verified: returns bare `ResourcePreFetchResult(...)` at lines 60/62/75). Add `extensions: Extensions | None = None` to the hook signature, read `extensions.request.trace_id` in Python (import `from cpex.framework.extensions import Extensions, RequestExtension` — same import `pii_filter`'s test suite already uses), build the allow-listed metrics dict, set `result.metadata["<namespace>"]` only when `trace_id` present. No Rust change (the Rust core already returns the counts/categories the Python layer needs for its block decision).
- **Python-native plugin with a legacy metadata write to MIGRATE** (`encoded_exfil_detection`): same Python-layer approach, BUT this plugin **already writes `result.metadata` today** in a shape that conflicts with the namespaced contract, and that legacy write must be migrated, not left alongside a new one (P-4: no double-write, one authoritative channel — same rule the `pii_filter` pilot applied to its legacy `context.metadata` writes). See Task 4 for specifics.

**Tech Stack:** Rust (PyO3/maturin) for 3 plugins, pure Python for 2, pytest, cargo nextest, `gh` CLI.

**⚠️ CROSS-CUTTING FINDING — 4 of 5 plugins ALREADY write `result.metadata` today (deep source review).** This is NOT the greenfield "port pii_filter's clean pattern" it looks like. Only `url_reputation` writes nothing. Every other in-scope plugin already emits a *flat, non-namespaced, trace-un-gated* `result.metadata` dict that must be consciously reconciled with the new namespaced contract (P-4: one authoritative channel — never leave a double-write). Verified writes:

| Plugin | Existing flat `result.metadata` keys | Source |
|---|---|---|
| `secrets_detection` | `secrets_redacted`, `count` (redaction path); `secrets_findings`, `count` (findings path) | `src/plugin.rs` `redaction_metadata()` :226, `findings_metadata()` :238 |
| `rate_limiter` | the whole `meta` dict — `limited` (+ rate-limit fields from `build_meta_dict`) set as `result.metadata` | `src/plugin.rs` `build_prehook_result()` :375-378; `src/engine.rs` :479 |
| `retry_with_backoff` | `retry_policy` (dict of `max_retries`/`backoff_base_ms`/…) | `src/plugin.rs` `build_metadata()` :253 |
| `encoded_exfil_detection` | `encoded_exfil_count`, `encoded_exfil_findings`, `implementation` | `encoded_exfil_detection.py` :214/247/280 |
| `url_reputation` | **none — clean** | returns bare `ResourcePreFetchResult` |

How the gateway sees these today: `_sanitize_plugin_metrics()` treats each **top-level** `result.metadata` key as a *plugin namespace* whose value must be a dict of allow-listed scalar fields. A flat key like `count` (int) or `retry_policy` (nested dict) is therefore dropped as an invalid namespace — harmless now, but (a) it's a real write that a naive param-add double-writes against, and (b) each junk top-level key still counts toward the gateway's `_MAX_PLUGINS_PER_CALL=16` namespace budget. **Per-plugin decision required (do NOT skip):** for each plugin, either (i) restructure the existing write to live *under* the plugin's namespace key `result.metadata["<plugin>"]` and fold the new metrics into it, or (ii) if the legacy flat keys have downstream readers, keep them but add the namespaced metrics dict as a separate key and document the double-namespace in the README, or (iii) remove the legacy flat keys outright (preferred, matches pii_filter's P-4) with a README migration note. Pick one explicitly per plugin — silence here reproduces the encoded_exfil bug across all four.

**Source specs:** Reference implementation — `pii_filter`'s existing `plugins/rust/python-package/pii_filter/src/plugin.rs` (helpers `read_trace_id`, `build_pii_metrics`, `push_metrics_kwarg`) and `docs/superpowers/contracts/pii_filter-metrics-schema.md` (the allow/deny-list contract shape to copy per plugin). Prior plan: `docs/superpowers/plans/2026-06-30-otel-plugin-boundary-metadata.md` (the `pii_filter` pilot — Task A7 there explicitly deferred this rollout).

## Global Constraints

- **Branching:** New feature branch off `main` — already created: `feature/cpex-27-plugin-metrics`. `main` stays read-only.
- **Commits:** DCO sign-off required (`git commit -s`). No `Co-Authored-By` trailer.
- **Blocker rule:** True blocker (missing prerequisite, invalidated assumption, destructive action, unsatisfiable external dep) → STOP and notify, don't improvise around it.
- **Licensing:** New files get the repo's Apache-2.0 SPDX header (Rust `//`, Python `#`).
- **Versioning:** Every changed plugin bumps `Cargo.toml` (source of truth) + `cpex_<plugin>/plugin-manifest.yaml` `version` + lets `Cargo.lock` auto-update. Current versions (verified): `secrets_detection` 0.3.6, `encoded_exfil_detection` 0.3.5, `url_reputation` 0.3.4, `rate_limiter` 0.1.6, `retry_with_backoff` 0.3.5. Bump each by one patch/minor when metrics emission lands, even if the number already satisfies the gateway's current floor pin — the *content* at that version today does not emit metrics yet, so reusing the same version string would be a lie to consumers who pinned it.
- **Security (S1, normative):** Counts/types/categories only, never matched/raw content (no secret values, no full URLs, no raw tool args). Each plugin gets an explicit allow-list; everything else denied.
- **No new channel:** Reuse `result.metadata`, not `Extensions.custom` — same reasoning as the pilot (multi-plugin lossy, "last writer wins").
- **Gate on trace:** No `trace_id` → no metadata write, zero overhead when tracing is off. Untraced calls must be byte-for-byte behavior-identical to before this change.
- **CI gate:** `make ci` per changed plugin dir must be green before a task is done.
- **Scope discipline:** Only the hooks each plugin already implements per the issue — do not add metrics to hooks outside the issue's list even if the plugin implements more hooks internally (e.g. `secrets_detection` also has `tool_pre_invoke` in code but issue #129 only asks for `prompt_pre_fetch`/`tool_post_invoke`/`resource_post_fetch`; `retry_with_backoff` also has `resource_post_fetch` in code but issue only asks for `tool_post_invoke`).

---

## File Structure

**Per Rust-core plugin** (`secrets_detection`, `rate_limiter`, `retry_with_backoff`):
- Modify `plugins/rust/python-package/<plugin>/src/plugin.rs` — add `extensions=None` to each in-scope hook's `#[pyo3(signature = ...)]`; add `read_trace_id`/metrics-dict helpers (copy shape from `pii_filter/src/plugin.rs`); gate on `trace_id`.
- Modify `plugins/rust/python-package/<plugin>/cpex_<plugin>/*.py` — thin wrapper forwards new `extensions` param.
- Modify `plugins/rust/python-package/<plugin>/src/bin/stub_gen.rs` if present (hardcoded signature constants, same gotcha the pilot hit).
- Modify `plugins/rust/python-package/<plugin>/Cargo.toml` + `plugin-manifest.yaml` (version bump).
- Modify `plugins/tests/<plugin>/test_integration.py` (or equivalent) — trace-in/metrics-out test, no-extensions back-compat test, S1 leakage test.

**Per Python-native plugin** (`encoded_exfil_detection`, `url_reputation`):
- Modify `plugins/rust/python-package/<plugin>/cpex_<plugin>/*.py` — add `extensions: Extensions | None = None` param to each in-scope hook method; `from cpex.framework.extensions import Extensions, RequestExtension`; read `extensions.request.trace_id`; build allow-listed metrics dict; set `result.metadata["<plugin_name>"]` only when `trace_id` present. **`encoded_exfil_detection` additionally REMOVES its existing legacy flat `result.metadata` write** (lines 214/247/280 — `encoded_exfil_count`/`encoded_exfil_findings`/`implementation`) as part of the same change; `url_reputation` has no such legacy write. See Tasks 4/5.
- Modify `Cargo.toml` + `plugin-manifest.yaml` (version bump) — versioning stays in lockstep with Rust-core plugins even though this change is pure Python, since the shipped package version is what the gateway pins.
- Modify `plugins/tests/<plugin>/test_integration.py` — same 3 test cases as above, plus (encoded_exfil only) a regression test that the old flat keys are gone.

**Shared:**
- Create `docs/superpowers/contracts/<plugin>-metrics-schema.md` per plugin (mirror `pii_filter-metrics-schema.md`) documenting the allow-list.
- Update each plugin's `README.md` with the metrics contract + migration note if any legacy `context.metadata` write is being removed.

---

## Per-Plugin Metrics Contracts (from issue #129, as allow-lists)

| Plugin | Hooks in scope | Metrics fields |
|---|---|---|
| `cpex-secrets-detection` (`SecretsDetectionPlugin`) | `prompt_pre_fetch`, `tool_post_invoke`, `resource_post_fetch` | `total_detections` (int), `total_masked`/`total_blocked` (int), `secret_types` (list[str], category names only — e.g. `["aws_key","api_token"]`, never the matched value) |
| `cpex-encoded-exfil-detection` (`EncodedExfilDetectorPlugin`) | `prompt_pre_fetch`, `tool_post_invoke`, `resource_post_fetch` | `total_detections` (int), `encoding_types` (list[str], e.g. `["base64","hex"]`) |
| `cpex-url-reputation` (`URLReputationPlugin`) | `resource_pre_fetch` | `total_checked` (int), `total_blocked` (int), `reputation_categories` (list[str], no raw URLs/domains) |
| `cpex-rate-limiter` (`RateLimiterPlugin`) | `prompt_pre_fetch`, `tool_pre_invoke` | `allowed` (int, per-call 0/1), `throttled` (int, per-call 0/1), `backend` (str: `redis`/`memory`) |
| `cpex-retry-with-backoff` (`RetryWithBackoffPlugin`) | `tool_post_invoke` | `retry_count` (int, = `consecutive_failures`), `retry_delay_ms` (int, per-attempt — no cumulative accumulator added; see Task 3) |

---

## Phase 0 — Setup

### Task 0: Confirm branch state

- [ ] **Step 1:** Confirm `feature/cpex-27-plugin-metrics` is checked out and based on latest `main` (already done: branch created off freshly-pulled `main`, 130-file fast-forward applied). `git log --oneline -1` should show the merge of `#128`/pii_filter work as an ancestor.

---

## Phase 1 — `secrets_detection` (Rust-core)

### Task 1: Port pii_filter's metrics pattern

- [ ] **Step 1:** Read `pii_filter/src/plugin.rs` in full (helpers: `read_trace_id`, `build_framework_object_dyn`, the per-hook `push_metrics_kwarg` call sites) as the template.
- [ ] **Step 2:** Add `extensions=None` to `#[pyo3(signature = ...)]` for `prompt_pre_fetch`, `tool_post_invoke`, `resource_post_fetch` in `secrets_detection/src/plugin.rs` (leave `tool_pre_invoke` untouched — out of issue scope).
- [ ] **Step 3:** Add a `build_secrets_metrics(trace_id, detections, masked_or_blocked)` helper emitting the allow-listed fields above; gate on `trace_id.is_some()`. **Data is available:** each finding dict already carries a `"type"` field (= `finding.pii_type`, `src/scanner/python_scan.rs:59,196`), so `secret_types` = the deduped/sorted set of those `type` values — no new scanner work. `total_detections` = `count`; `total_masked`/`total_blocked` come from the redaction/block branch taken.
- [ ] **Step 3b (RECONCILE existing write):** This plugin already writes flat `secrets_redacted`/`count`/`secrets_findings` (see cross-cutting finding). Decide per the three options above — recommended: move counts under `result.metadata["secrets_detection"]` and drop the flat keys (README migration note). Confirm `sanitized_findings()` (`findings_metadata`) never carried a raw secret before removing it — if `secrets_findings` was already leak-safe it's fine to drop; the point is one authoritative namespaced channel.
- [ ] **Step 4:** Wire the Python wrapper (`cpex_secrets_detection/secrets_detection.py`) to forward `extensions` — note the current wrapper hooks take only `(payload, context)` with NO `**kwargs`, so `extensions` must be added explicitly to all in-scope hook signatures AND the `self._core.<hook>(...)` forwarding calls (else the gateway, which already passes `extensions=` to every call site, TypeErrors the moment this plugin is enabled).
- [ ] **Step 5:** Update `stub_gen.rs` if it hardcodes the old signature.
- [ ] **Step 6:** Bump `Cargo.toml` version (0.3.6 → 0.3.7) + `plugin-manifest.yaml`.
- [ ] **Step 7:** Tests: trace-in/metrics-out, no-extensions back-compat (legacy 2-arg callers still work), S1 leak check (assert no raw secret value ever appears in `result.metadata`), and a regression test that any removed legacy flat keys are gone.
- [ ] **Step 8:** `make ci` green in `plugins/rust/python-package/secrets_detection/`.

---

## Phase 2 — `rate_limiter` (Rust-core)

### Task 2: Port pattern

- [ ] Same steps as Task 1, scoped to `prompt_pre_fetch` + `tool_pre_invoke`, fields `allowed`/`throttled`/`backend`. Version 0.1.6 → 0.1.7.
- [ ] **Metric semantics (verified):** rate_limiter runs a **per-request** check — `engine.check()` returns a single `(allowed, headers, meta)` per call, with no running counter. So `allowed`/`throttled` are **per-call 0/1** (`allowed = 1 if allowed else 0`, `throttled = 1 - allowed`), not cumulative totals — the gateway aggregates across spans. Document this so the metric isn't misread as a lifetime count. `backend` is knowable (`cfg.get("backend","memory")` in the wrapper `rate_limiter.py:57`, or `engine.uses_async_backend()` → redis vs memory in Rust).
- [ ] **RECONCILE existing write:** rate_limiter already sets the whole `meta` dict (`{"limited": ...}` + rate-limit fields) as `result.metadata` (`build_prehook_result` :375-378). Fold the new `allowed`/`throttled`/`backend` under `result.metadata["rate_limiter"]` rather than adding a second flat top-level key; confirm the `meta` fields don't already carry anything that should be namespaced too. **Care:** the not-allowed branch (:382) returns a `violation` and no metadata — decide whether throttled requests should still emit metrics (they should: a throttle is exactly the event worth counting) and wire the metrics dict into that branch as well as the allowed branch.

---

## Phase 3 — `retry_with_backoff` (Rust-core)

### Task 3: Port pattern

- [ ] Same steps as Task 1, scoped to `tool_post_invoke` ONLY (plugin also has `resource_post_fetch` in code at `src/plugin.rs:152` — leave it alone, out of issue scope). Version 0.3.5 → 0.3.6.
- [ ] **DATA-AVAILABILITY (resolved — emit per-attempt `retry_delay_ms`):** `retry_count` is free — it's `state.consecutive_failures` (`ToolRetryState`, `src/state.rs:24-26`). `total_backoff_ms` as a cumulative sum does NOT exist in state and is **deliberately NOT added** (decision: no new accumulator). Instead emit the already-computed per-attempt `delay_ms` (`compute_delay_ms`, :103 — the same value returned as `retry_delay_ms`) under the metric field name **`retry_delay_ms`**. Gateway allowlists `retry_delay_ms` (not `total_backoff_ms`). Emit `retry_count` + `retry_delay_ms` only.
- [ ] **RECONCILE existing write:** already writes flat `result.metadata["retry_policy"]` (config echo) on both `tool_post_invoke` and `resource_post_fetch`, un-gated (`build_metadata` :253). Fold retry metrics under `result.metadata["retry_with_backoff"]`; decide whether the `retry_policy` echo stays (it's config, low-value for observability, and un-gated so it violates the "zero overhead when tracing off" rule — recommend removing or gating it).
- [ ] **Gateway pin note:** gateway's `pyproject.toml` pins `cpex-retry-with-backoff>=0.3.1,<0.3.2` (a deliberate CI-compat cap from gateway PR #5332, per `git log -S`), below the current 0.3.5. This plugin repo's job is only to publish the correctly-bumped version; widening/re-validating that pin is the gateway-side plan's Task 6.

---

## Phase 4 — `encoded_exfil_detection` (Python-native, MIGRATE legacy write)

### Task 4: Migrate legacy metadata write to the namespaced, gated contract

> **This is not a greenfield param-add. The plugin already writes `result.metadata` today, in the wrong shape, un-gated, with an S1 risk. All three must be fixed in the same change (P-4: one authoritative channel).** Verified in `cpex_encoded_exfil_detection/encoded_exfil_detection.py`:
> - Lines 214/247/280 each write `metadata = {"encoded_exfil_count": count, "encoded_exfil_findings": self._findings_for_metadata(findings), "implementation": ...}` — **flat keys at `result.metadata` root, not namespaced under `result.metadata["encoded_exfil_detection"]`**. The gateway's `_sanitize_plugin_metrics()` treats each root key as a *plugin namespace* whose value must be a dict, so `encoded_exfil_count` (an int) is dropped — the current write is dead-on-arrival at the gateway but is still a real pre-existing write that a naive param-add would leave in place, producing a double-write.
> - The write is **not gated on `trace_id`** — it fires on every detection (`if count`), violating the "zero overhead when observability off" contract.
> - `_findings_for_metadata` (line 170) returns raw `findings[:10]` when `include_detection_details=True` (line 172-174) — **carries matched encoded content (S1 leak)** — and even with details off still emits per-finding `path`/`score`.

- [ ] **Step 1:** Confirm the hook orchestration is pure Python (already done: zero `extensions`/`trace_id` in `src/lib.rs`; hooks at lines ~193/223/254 take only `(payload, context)`). The Rust core (`_rust_engine.scan`) already returns `(count, redacted, findings)` with `findings` carrying an `encoding` key per item — so `encoding_types` is derivable in Python with **no Rust change**. Note the code already computes exactly this in `_log_detection` (line 189): `encoding_types = sorted({f.get("encoding", "unknown") for f in findings})` — reuse that derivation.
- [ ] **Step 2:** Add `extensions: Extensions | None = None` to `prompt_pre_fetch`, `tool_post_invoke`, `resource_post_fetch`; import `from cpex.framework.extensions import Extensions, RequestExtension` (same import the pii_filter test suite already uses).
- [ ] **Step 3 (the migration):** Replace the legacy flat write. Build the allow-listed namespaced dict `{"total_detections": count, "encoding_types": [...]}`, gate it on `extensions.request.trace_id`, and set `result.metadata["encoded_exfil_detection"]` (namespaced). **Do not keep the old `encoded_exfil_count`/`encoded_exfil_findings`/`implementation` flat keys** — they are the double-write P-4 forbids and `encoded_exfil_findings` is the S1 leak. If any downstream reader depends on the old flat keys, document a breaking-change migration note in the README (as the pii_filter 0.3.6 change did for its removed legacy keys). Confirm the namespace key string (`"encoded_exfil_detection"` vs some other short-name) against what the gateway's config/tests expect — the sanitizer keys the *field* allowlist by field name, not namespace, so the namespace only needs to be identifier-safe and consistent with the gateway config's plugin naming.
- [ ] **Step 4:** Version bump 0.3.5 → 0.3.6, `plugin-manifest.yaml` in lockstep.
- [ ] **Step 5:** Tests: trace-in/metrics-out (namespaced dict present), no-extensions back-compat, S1 leak check (assert no raw finding content / no `encoding`-value-bearing free text ever reaches `result.metadata`), and a **migration/regression test** asserting the old flat keys are gone.

---

## Phase 5 — `url_reputation` (Python-native, CLEAN)

### Task 5: Add extensions param in Python (no legacy write)

> Unlike `encoded_exfil_detection`, this plugin writes **no** `result.metadata` today (verified: `cpex_url_reputation/url_reputation.py` returns bare `ResourcePreFetchResult(...)` at lines 60/62/75). So this is the straightforward greenfield param-add — no migration.

- [ ] **Step 1:** Add `extensions: Extensions | None = None` to `resource_pre_fetch`; import `Extensions`/`RequestExtension` as in Task 4.
- [ ] **Step 2:** Build `{"total_checked": ..., "total_blocked": ..., "reputation_categories": [...]}` (categories only — **no raw URLs/domains**, S1), gate on `extensions.request.trace_id`, set `result.metadata["url_reputation"]`.
- [ ] **Step 3:** Version bump 0.3.4 → 0.3.5, `plugin-manifest.yaml` in lockstep.
- [ ] **Step 4:** Tests: trace-in/metrics-out, no-extensions back-compat, S1 leak check (no URL/domain in metadata).

---

## Phase 6 — Wrap-up

### Task 6: Cross-plugin consistency pass

- [ ] **Step 1:** Diff all 5 new metrics-schema contract docs against `pii_filter-metrics-schema.md` for consistent structure (allow-list table, S1 banner, example JSON).
- [ ] **Step 2:** Run full `make ci` across all 5 changed plugin dirs.
- [ ] **Step 3:** Do NOT open a PR or merge — stop here per the no-PR-in-planning convention (create the PR only when the user explicitly asks, same as the pilot).
