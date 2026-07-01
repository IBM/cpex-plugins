# OpenTelemetry support at the Rust plugin boundary — metadata-channel variant (Issue #27)

Date: 2026-06-29
Repo: `IBM/cpex-plugins`
Tracking: [IBM/cpex-plugins#27](https://github.com/IBM/cpex-plugins/issues/27)
Companion (out of this repo's scope): IBM/mcp-context-forge PR #4069, #3754; contextforge-org/cpex #43

> **Variant note.** This is an alternative design to
> `2026-06-29-otel-plugin-boundary-design.md` (the `Extensions.custom` variant).
> It is identical on **trace-IN** and differs only on **metrics-OUT**: metrics ride
> `PluginResult.metadata` (a channel the issue explicitly sanctions) instead of
> `Extensions.custom`. Chosen because the CPEX executor already accumulates
> per-plugin `result.metadata` across the hook chain, which removes the merge
> helper, the PyO3 `model_copy`, the tier reasoning, and the `url_reputation`
> dependency retrofit — and avoids a verified multi-plugin metric-loss bug in the
> `custom` path (see "Why this channel").

## Summary

Wire CPEX Rust plugins into the gateway's **existing** OpenTelemetry/metrics
infrastructure using the CPEX extension framework. Plugins accept distributed
trace context (`trace_id`/`span_id`) at the hook boundary and return plugin-side
metrics on **`PluginResult.metadata`** under a per-plugin namespace key. The
gateway consumes those metrics with infrastructure it already owns.

**Hard constraint:** the plugin side creates **no** telemetry infrastructure — no
OpenTelemetry SDK, no exporter, no collector dependency. It only *carries* data
through framework-provided channels. All recording/exporting happens in the
gateway with infrastructure that already exists.

**Delivery — two PRs, both owned by this effort.**
1. **Plugin PR** (`IBM/cpex-plugins`, closes #27): P1–P5. Self-contained,
   reviewable and shippable on its own.
2. **Gateway PR** (`IBM/mcp-context-forge`, companion): G0 + G1 + the end-to-end
   test. Makes the feature live.
Gateway changes are "out of scope" only w.r.t. **issue #27's boundary** (separate
PR for clean review) — they are **in scope for this overall effort**.

## Why this channel (`PluginResult.metadata` vs `Extensions.custom`)

The issue sanctions both. This variant picks `metadata` because, verified in code:

- **The executor already accumulates it.** `cpex/framework/manager.py:939-942`:
  `combined_metadata.update({k:v for k,v in result.metadata.items() if k not in
  RESERVED_INTERNAL_METADATA_KEYS})` — a persistent shared dict merged across the
  whole hook chain and returned as `PluginResult(metadata=combined_metadata)`. No
  plugin-side merge code is needed.
- **`Extensions.custom` is multi-plugin lossy.** `manager.py:614-616` accumulates
  `modified_extensions` by **wholesale replace** (`current_extensions =
  result.modified_extensions`, "last writer wins"), and each plugin is handed
  `filter_extensions(<original extensions>)` (custom usually `None`) rather than the
  accumulated one. So with >1 plugin emitting on the same hook, a sibling's
  `custom` (built from empty) **silently overwrites** the earlier plugin's metrics
  unless a fold-at-end-of-chain workaround is added. The `metadata` accumulator has
  no such loss — namespaced keys coexist.
- **The gateway read-path already exists.** Gateway code already reads
  `result.metadata` as a flat dict (`mcpgateway/auth.py:1512-1513`,
  `mcpgateway/middleware/rbac.py:748`). The `modified_extensions` path is read by
  nobody today.
- **Reserved keys are narrow.** `manager.py:77-78` reserves only
  `_decision_plugin` (`RESERVED_INTERNAL_METADATA_KEYS`). A namespace key like
  `"pii_filter"` passes the filter cleanly and cannot collide with framework
  internals.

Trade-off accepted: `metadata` is an untyped dict with no single-writer chokepoint
and no tier governance — mitigated by per-plugin namespacing + tests (see S2).
Note the `custom` variant's chokepoint/tier guarantees are themselves weak in this
cpex build: `validate_tier_constraints` has **zero runtime call sites**, so its
tier guardrail is unit-testable only, not enforced.

## Background — what already exists (verified)

**Gateway (`mcp-context-forge`) — infrastructure present, no plugin-metrics consumer:**
- `mcpgateway/services/observability_service.py` — `ObservabilityService` with
  `start_span` / `end_span` / `record_metric` / `record_token_usage`, each using
  independent DB sessions (Issue #3883 separate-session pattern).
- `mcpgateway/plugins/observability_adapter.py` — `ObservabilityServiceAdapter`,
  a duck-typed implementation of CPEX's `ObservabilityProvider` protocol.
- `mcpgateway/plugins/gateway_plugin_manager.py` — already accepts/exposes an
  `observability: Optional[ObservabilityProvider]`.
- No gateway code reads plugin-returned metrics into `ObservabilityService` yet
  (infra ready but un-subscribed). It already reads `result.metadata` as a dict
  for other purposes (`auth.py:1512`, `rbac.py:748`).

**CPEX framework (`cpex` package) — relevant plumbing:**
- `cpex.framework.extensions.request.RequestExtension` — frozen model with
  `trace_id` and `span_id` (the typed trace-IN carrier).
- `cpex.framework.base.HookRef` validates the hook signature strictly: exactly
  **2 (`payload, context`) or 3 (`payload, context, extensions`)** parameters and
  the method **must be `async`** — else `PluginError` at load.
  `_accepts_extensions = (param_count == 3)`. The executor forwards `extensions`
  only to 3-param hooks; otherwise the hook never receives trace context.
- `cpex.framework.manager` `PluginExecutor` — reads `current_trace_id` contextvar
  and starts the hook-chain span via the observability provider when a trace is
  active. **Accumulates each `result.metadata` into a shared `combined_metadata`
  and returns it** (`manager.py:939-942`, returned at `:435/:800/:982/:1012`).
- `cpex.framework.models.PluginResult` — `metadata: Optional[dict]` (default
  `{}`); `ConfigDict(arbitrary_types_allowed=True)`, **not frozen**.

**Gateway request path — verified gaps:**
- `observability_middleware.py:181-183` sets **both** the gateway and the cpex
  (`plugins_trace_id`) `current_trace_id` contextvars — so the executor's
  hook-chain span fires.
- **No gateway call site passes `extensions=` into plugin execution** (grep:
  zero). Plugins are invoked via `plugin_manager.invoke_hook(...)`; the executor's
  `extensions` defaults to `None`. So today a 3-param hook still receives `None`
  and gets no trace context — the plugin-side change is **inert end-to-end until
  the gateway builds and passes `Extensions`** (G0).

**Pilot plugin (`pii_filter`) — current state:**
- Python shim `plugins/rust/python-package/pii_filter/cpex_pii_filter/pii_filter.py`
  delegates the 4 hooks (`prompt_pre_fetch`, `prompt_post_fetch`,
  `tool_pre_invoke`, `tool_post_invoke`) to the Rust core. Hooks are
  `(payload, context)` — no `extensions` param, so no trace context today.
- Rust core `plugins/rust/python-package/pii_filter/src/plugin.rs` already computes
  stats and writes `pii_filter_stats` / `pii_detections` into **`context.metadata`**
  (a `PyDict`). **Important:** `context.metadata` does NOT flow into
  `combined_metadata` — only `result.metadata` does (`manager.py:939`). So the
  stats must be moved onto the returned result.

## Decisions

- **Rollout:** pilot `pii_filter` end-to-end first; then replicate to the other
  five Rust plugins (`rate_limiter`, `secrets_detection`, `url_reputation`,
  `encoded_exfil_detection`, `retry_with_backoff`).
- **Metrics channel:** `PluginResult.metadata["<plugin>"]` (namespaced dict).
  The Rust core computes metrics (gated on `trace_id`) and sets them on the built
  result's `metadata` field; the CPEX executor accumulates them across the chain
  for free. No `Extensions.custom`, no `modified_extensions`, no merge helper, no
  PyO3 `model_copy`, no tier reasoning, no `framework_bridge` change.
- **No shared merge crate needed.** Because the executor accumulates `metadata`,
  there is no `merge_custom`/B1 and no `url_reputation` dependency retrofit. An
  optional tiny shared helper may centralize *building* the namespaced dict (see
  P4), but it is not required for correctness.
- **Gateway phases (G0, G1):** delivered as a **second, coordinated PR** in the
  `mcp-context-forge` repo (same author, this effort). **G0** (build + pass
  `Extensions`) is the hard prerequisite for live behaviour; **G1** consumes the
  emitted metrics. The plugin PR is tested independently of both (direct
  `Extensions` injection in tests).

## Data flow (target)

```
gateway request
  → current_trace_id + plugins_trace_id contextvars set          [exists]
  → gateway BUILDS Extensions{request:{trace_id, span_id}} and
       passes it into invoke_hook → executor.execute(extensions=) [G0, gateway repo — PREREQUISITE]
  → executor filters + forwards `extensions` to 3-param hooks     [exists, gated by G0]
  → Python shim (3-param hook) forwards `extensions` object into Rust [P1+P2]
  → Rust reads request.trace_id; if present, computes metrics       [P3]
  → Rust sets result.metadata["<plugin>"] = metrics (namespaced)    [P4]
  → executor accumulates result.metadata into combined_metadata
       and returns it (manager.py:939)                              [exists]
  → gateway reads result.metadata["<plugin>"] → ObservabilityService
       span attributes (primary) / record_metric (secondary)        [G1, gateway repo]
```

**Without G0 the plugin emits nothing in the real gateway** (extensions=None →
no metrics by L1/P-1). The plugin-side pilot (P1–P5) is independently testable by
injecting an `Extensions` directly in unit/plugin-framework tests; G0 makes it
live end-to-end.

## Components and changes

### Plugin side — `cpex-plugins` (issue #27 scope)

**P1 — Opt the hook boundary into `extensions` (shim, pass-through).**
In `pii_filter.py`, change the 4 hook signatures to exactly
`async def <hook>(self, payload, context, extensions=None)` — **exactly three
parameters, async** (HookRef rejects any other arity or a sync method at load) —
and forward the `extensions` object into the Rust core. Defaulting to `None`
keeps the plugin working when the host passes no extensions (pre-G0 gateway, or
other hosts). The shim does no merging.

**P2 — PyO3: accept the `extensions` object in the Rust hooks (and the gate).**
Extend the Rust hook entry points in `plugin.rs` to accept the `extensions`
argument (optional `Bound<'_, PyAny>`). The Rust core reads
`extensions.request.trace_id`/`span_id` for (a) the emission gate — **if
`trace_id` is absent, do no metrics work** (P-1/L3) — and (b) DEBUG log
correlation. It does **not** embed `trace_id`/`span_id` as a metric value/label
(cardinality — see S3); correlation is via span parentage. No OpenTelemetry crate,
no exporter.

**P3 — Rust core computes metrics (gated).**
When `trace_id` is present, reuse the already-computed `pii_filter_stats`/
detection summaries to build a metrics map. This **replaces** the current
`context.metadata` stat writes (which never reach the gateway — see Background);
the result-metadata path is the single authoritative one (no double-write —
see P-4). Metrics carry **counts/types/categories only, never matched content**
(S1), bounded in key count and value length (S3). Attach metrics on **every
emitting return path** (masked/blocked builds); the `default_result` no-op early
return emits nothing.

**P4 — Rust sets `result.metadata["<plugin>"]`.**
The Rust core sets a single namespaced key on the built result's `metadata` field:
`result.metadata["pii_filter"] = {counts/types…}`. The result builder
(`crates/framework_bridge/src/lib.rs` `build_framework_object`) already constructs
the `*Result` object from kwargs, so adding a `metadata=` kwarg is purely
additive — **no new bridge API and no `merge_custom`**. The executor's
`combined_metadata.update(...)` (`manager.py:939`) then merges this across the
chain; distinct plugin namespaces coexist. When `extensions` is `None` or
`trace_id` absent, no metrics are built and the `metadata` key is omitted (P-1).
*Optional:* a tiny shared helper (e.g. in `framework_bridge`) that takes
`(result, namespace, metrics)` and sets the key can centralize the namespacing
convention across plugins, but it is not required for correctness (the executor,
not the plugin, does the cross-plugin merge).

**P5 — Tests.** Placement per repo test strategy (CLAUDE.md): Rust unit inline as
`mod tests`; Python unit + plugin-framework integration in
`plugins/rust/python-package/pii_filter/tests/` (`make test-all` /
`make test-integration`); gateway unit + integration + e2e in `mcp-context-forge`
(companion).

**Feasibility — verified, both repos have direct templates (no new harness):**
- *Plugin unit/integration:* `pii_filter/tests/test_integration.py` already
  constructs real cpex payloads/`PluginContext` and `await`s the hooks directly —
  add an `Extensions` arg and assert `result.metadata["pii_filter"]`. The existing
  `context.metadata["pii_filter_stats"]` / `["pii_detections"]` assertions (e.g.
  lines ~131, ~297, ~489) **migrate** to `result.metadata["pii_filter"]` when
  P3/P4 land — update them, don't leave both.
- *Gateway unit:* `invoke_hook` mock + `await_args.kwargs` assertion
  (`test_a2a_agent_invoke_hooks.py`) for G0; `record_metric = MagicMock()` +
  metric-name inspection (`test_observability_service.py`) for G1;
  `test_observability_adapter.py` exception-path style for S4/L4.
- *Gateway integration:* `test_resource_plugin_integration.py` (real DB +
  PluginManager) and `test_span_attribute_customizer_integration.py`
  (plugin→observability).

*Rust unit (`mod tests` in `plugin.rs`):*
- `trace_id` present → `result.metadata["pii_filter"]` populated with the expected
  keys; `span_id` read for correlation, not embedded;
- **`trace_id` absent → gate fires:** no metrics work, `metadata` key omitted
  (P-1/L3);
- **malformed/missing extensions** (wrong type, `None`) → no panic, core PII result
  still returned (no `.unwrap()`/`expect`/`panic` on the metrics path);
- **metrics-build failure is isolated** — filtering still completes and a result
  without the metrics key is returned (see L2);
- **S3 bounds** — oversized/too-many-key metrics are capped/truncated;
- metrics attached on every emitting return path; `default_result` no-op emits
  nothing.

*Python unit / plugin-framework integration (`tests/`, via `make test-integration`):*
- hook with `extensions` returns `result.metadata["pii_filter"]` populated;
- **multi-plugin accumulation** — two plugins with distinct namespaces both survive
  in the executor's `combined_metadata` (no clobber); same-namespace collision is
  prevented by unique per-plugin keys (S2);
- hook **without** `extensions` (legacy host) still works, returns no metrics key;
  back-compat: existing `test_integration.py` passes unchanged — no regression;
- **exception isolation** — when metrics emission raises, the hook still returns a
  valid `PluginResult` with filtering applied (L2);
- **S1** — known-sensitive input (PII/secret/URL) does **not** appear in
  `result.metadata` **nor in logs** — only counts/types/categories;
- **P-1** — no-`extensions` / no-`trace_id` path performs no metrics work.

*Gateway unit (companion, `mcp-context-forge/tests/unit/mcpgateway/`):*
- **G0** — the gateway builds `Extensions(request=RequestExtension(trace_id,
  span_id))` and passes it on the plugin call (assert via the `invoke_hook` mock +
  `await_args.kwargs` pattern).
- **G1** — given a returned `result.metadata["pii_filter"]`, the consumer attaches
  it as span attributes (primary) and optionally calls `record_metric` with the
  expected names (`record_metric = MagicMock()` + inspect `call.kwargs["name"]`).
- **S4** — non-scalar / oversized values rejected/truncated before recording;
  **L4** — a recording failure is swallowed (mirror `test_observability_adapter.py`).

*Gateway integration (companion, `mcp-context-forge/tests/integration/`):*
- Plugin loaded under `PLUGINS_ENABLED`, hook fired with trace context, metrics in
  `result.metadata` reach `ObservabilityService`. Template:
  `test_resource_plugin_integration.py` + `test_span_attribute_customizer_integration.py`.
- **P-3** — all plugin metrics for a request recorded in a single session/call.

*End-to-end (companion only, `mcp-context-forge/tests/e2e/`):*
- **No plugin-side e2e** — e2e lives only in the gateway repo (CLAUDE.md), and the
  plugin alone cannot exercise the full chain.
- Requires **G0 + G1**. Full path: real HTTP request with `PLUGINS_ENABLED` +
  `OBSERVABILITY_ENABLED` and the pilot installed → traced tool call →
  `GET /observability/traces` shows the plugin's metrics. Closest precedents:
  `tests/e2e/test_baggage_tracing.py` + `test_span_attribute_customizer_integration.py`.
  (`trace_generator.py` is a manual Phoenix script, not a pytest fixture.)
- Cost drivers: install pilot into gateway env (+ Rust build), config wiring,
  flush/poll before querying (best-effort separate-session writes), admin JWT for
  `/observability`. Medium–high, bounded by precedents.

**Replication.** After the pilot is green, apply P1–P5 to the other five Rust
plugins, each emitting under its own `result.metadata["<plugin>"]` key. **No
plugin needs a new `framework_bridge` dependency** (the merge is the executor's
job — this is a concrete advantage over the `custom` variant, which requires
`url_reputation` to add the dep). Before replicating a content-handling plugin,
complete its D1 allow/deny-list and per-plugin S1 leakage test.

### Gateway side — `mcp-context-forge` (companion phases, out of issue #27)

**G0 — Build and pass `Extensions` (hard prerequisite for end-to-end).**
The gateway sets the trace contextvars but never constructs/passes an `Extensions`
object to plugin execution. In its plugin-invocation path
(`plugin_manager.invoke_hook` → `executor.execute`): build
`Extensions(request=RequestExtension(trace_id=..., span_id=...))` from the active
trace and plumb an `extensions=` argument through `invoke_hook` to `execute`.
Until G0 lands, plugin-side changes are inert in the running gateway (verified: no
`extensions=` call site exists). Gateway-repo work, gating dependency.

**G1 — Consume plugin metrics with existing infrastructure.**
After the executor returns, read `result.metadata["<plugin>"]` for each emitting
plugin. **Primary (required): attach metrics as span attributes on the hook-chain
span via `ObservabilityServiceAdapter`** — the load-bearing path that lets an
operator drill from a specific trace (`GET /observability/traces/{trace_id}`) into
the responsible plugin. **Secondary (optional):** also feed
`ObservabilityService.record_metric` for aggregate/searchable metrics. Reuses the
existing `result.metadata` read-path (`auth.py:1512`, `rbac.py:748`). Creates no
new infrastructure. Separate, clearly-labelled change so #27's plugin PR stays
scoped.

Constraints:
- **Validate before recording (S4):** treat `result.metadata["<plugin>"]` as
  untrusted plugin output. Accept only `str | int | float | bool` values,
  length/key bounded; drop/truncate else. Keep values out of unsanitised
  query/search paths. **S4 is a type/size guard, not a content filter** — it
  cannot catch a leaked well-formed string; that is S1's job. **Do not log the
  rejected value** (S1-applies-to-logs holds on the gateway side too).
- **Batch writes (P-3):** record all plugin metrics for a request through a single
  `record_metric`/session, not one per plugin/key (connection-pool pressure).
- **Best-effort:** failures swallowed — telemetry never breaks the request.

## Security

Normative — apply to the pilot and every replicated plugin.

- **S1 — No sensitive content in metrics (critical).** Several plugins
  (`pii_filter`, `secrets_detection`, `url_reputation`, `encoded_exfil_detection`)
  inspect sensitive material. Metrics on `result.metadata` flow to the gateway and
  become queryable through the `/observability` API (`attribute_search` free-text,
  admin-scoped — and per gateway CLAUDE.md, observability writes are **platform-wide,
  not RBAC-scoped**, so any leaked value is visible to all admins). Emit **counts,
  types, and categories only — never the matched value**. Each plugin defines an
  explicit **allowlist** of metric keys; anything not on it is not emitted. Add a
  per-plugin test asserting known-sensitive inputs do not appear in
  `result.metadata` **nor in logs** — run it for **every** plugin, not just the
  pilot.
  - **S1 is the sole semantic guarantee.** S4 (gateway) only checks type/size — a
    leaked full URL or `match` preview is a bounded `str` and passes S4 cleanly.
  - **Replication danger fields (verified in code) — explicit deny-list:**
    `encoded_exfil_detection` `match` / `matched_preview` (`src/lib.rs`);
    `url_reputation` `url` / `details.url` / `path` (`src/engine.rs`);
    `pii_filter` already emits only counts/types (clean baseline).
  - **`secrets_detection` redaction is config-gated** (`redact` flag /
    `redaction_text`). Metrics MUST derive from counts/types only and never read a
    pre-redaction raw value, even when `redact=false`.
- **S2 — Namespaced metadata, never collide.** The executor merges via flat
  `combined_metadata.update(result.metadata)` (`manager.py:939-942`): distinct
  plugin namespace keys **coexist**; only an identical key would clobber. Each
  plugin writes under a single unique key (`"<plugin>"`) and **never writes
  reserved keys** (`_decision_plugin`). Unlike the `custom` variant there is no
  single-writer chokepoint — enforce the convention with a per-plugin test (and
  optionally the shared dict-builder helper in P4). Note: this channel does **not**
  suffer the `custom` variant's wholesale-replace loss (`manager.py:615`), so
  multi-plugin emission is correct by construction.
- **S3 — Bound cardinality and size.** Do **not** use `trace_id`/`span_id` (or any
  unbounded value) as a metric label/attribute — correlation is via span parentage.
  High-cardinality values blow up DB rows and the metrics-aggregation indexes
  (storage DoS). Cap the metrics dict to a small fixed key set and bounded value
  lengths in the Rust core.
- **S4 — Untrusted output at the gateway boundary (G1).** As above: type/size guard
  only, not a content filter; never log the rejected value.

## Performance

- **P-1 — Gate emission on trace context.** `OBSERVABILITY_ENABLED` defaults off.
  No `extensions` / no `trace_id` ⇒ **zero** metrics work (no dict build, no
  metadata key). Hot path for the no-observability case is unchanged.
- **P-2 — Cheap by construction.** No `Extensions.model_copy`, no frozen-model
  reconstruct — the Rust core sets one dict on the result it already builds, and
  the executor's `combined_metadata.update()` is a shallow dict update. This is
  strictly cheaper than the `custom` variant's per-hook pydantic copy.
- **P-3 — Batch gateway metric writes (G1).** The separate-session pattern already
  opens 4–6 DB sessions per traced request; record all plugin metrics in one
  session/call to avoid "QueuePool limit exceeded".
- **P-4 — No double-write.** Do not keep both the legacy `context.metadata` stat
  writes and the new `result.metadata` path. The result path is authoritative;
  remove the `context.metadata` writes when it lands (see P3).

## Error handling, logging, and exceptions

**Exception isolation (normative).**
- **L1 — Input tolerance.** Missing/`None` `extensions`, malformed `extensions`
  (wrong type), or wrong-typed `trace_id`/`span_id` → treated as absent, **never
  raised**; plugin behaves exactly as today (no metrics key).
- **L2 — Telemetry never breaks the plugin.** The metrics path is strictly
  best-effort and isolated from filtering. The current Rust hooks propagate errors
  with `?`; metrics assembly MUST NOT use that path — catch any failure, log once,
  return the normal filtering result **without** the metrics key. No
  `.unwrap()`/`expect`/`panic`, no new `?`-propagation on the metrics branch.
- **L3 — Missing trace context = no emission.** No `trace_id` → no metrics work,
  even if `extensions` is present (same gate as P-1). (`span_id` may be absent
  while `trace_id` is present — still emits, just without a parent span id.)
- **L4 — Gateway consumer (G1)** failures are best-effort and swallowed, matching
  the existing separate-session observability pattern.

**Logging (normative).**
- Use the existing Rust logger (`LOGGER_NAME = "cpex_pii_filter.pii_filter"`,
  bridged to Python `logging`); no new logging stack.
- **DEBUG:** trace context received (presence only) / absent; metrics emitted (key
  names + counts, never values).
- **WARNING (throttled):** malformed `extensions`, metrics-build failure (L2),
  bounds truncation (S3). One-line, rate-limited.
- **No sensitive content in logs (S1 applies to logs too).** Never log matched
  PII/secret/URL values or full payloads — only counts/types/categories. Covered
  by the S1 test.

## Documentation

- **D1 — Metric schema contract (cross-repo source of truth).** Document the
  `result.metadata["<plugin>"]` payload — exact keys, value types, units, bound
  limits (S3). The contract G1 consumes; the gateway companion references the same
  doc. **Per plugin, D1 enumerates an explicit allow-list (the only keys emitted)
  and a deny-list of known content-bearing fields** (e.g. `encoded_exfil_detection`:
  deny `match`, `matched_preview`; `url_reputation`: deny `url`, `path`;
  `secrets_detection`: deny any pre-redaction value). Written/reviewed **before**
  that plugin is replicated (gates the S1 leakage test).
- **D2 — Plugin README / docstrings.** Document the new optional `extensions` hook
  parameter and what the plugin emits on `result.metadata`. State the
  no-sensitive-content guarantee (S1).
- **D3 — Repo dev docs.** Update `cpex-plugins` plugin-development guidance
  (CLAUDE.md / README "Creating a New Plugin") with the trace-in / metrics-out
  convention (namespaced `result.metadata` key, gated on `trace_id`), plus the
  optional shared dict-builder helper, so new plugins follow the pattern.
- **D4 — PyO3 stubs.** Regenerate `.pyi` type stubs (`stub_gen`) for the changed
  hook signatures; CI stub-check stays green.
- **D5 — Changelog / migration note.** Record the hook-signature change (added
  optional `extensions`) as backward-compatible, and the stats relocation from
  `context.metadata` to `result.metadata` in the plugin changelog.

## Versioning

Per repo policy (CLAUDE.md), each changed plugin bumps its version in lockstep:
`Cargo.toml` (source of truth), `cpex_<plugin>/plugin-manifest.yaml` `version`,
`Cargo.lock` (auto). New code carries Apache-2.0 SPDX headers. `make ci` must pass
before PR. **No shared-crate version cascade** in this variant unless the optional
P4 helper is added to `framework_bridge` (if it is, version it and rebuild
dependents — otherwise each plugin changes independently).

## Dependencies and sequencing

- **G0 is the gating dependency** for live end-to-end behaviour: the gateway must
  build and pass `Extensions` into plugin execution. Gateway-repo work, shipped in
  the **companion gateway PR** (this effort) — separate from #27 for review, not
  deferred. Cross-link the two PRs.
- **Pilot is independently shippable and testable** before G0: P1–P5 verified by
  injecting an `Extensions` object directly in unit/plugin-framework tests.
- **Recommended order:** P1–P5 pilot (cpex-plugins PR; no shared-crate work
  required) → G0 + G1 (gateway PR, validated against the installed pilot) →
  replicate P1–P5 to the other five plugins (each just sets its namespaced
  `result.metadata` key; no new dependency for any plugin, including
  `url_reputation`). The D1 metric-schema contract is written during the pilot.

### Unblock order for gateway e2e

E2E is not externally blocked — every prerequisite is in this workspace; it is a
**sequencing** dependency. Do, in order:
1. **Ship plugin pilot (#27):** P1–P4 + D1, verified by plugin-side unit +
   framework-integration tests (injected `Extensions`). No e2e here.
2. **Gateway PR — implement G0:** build `Extensions(request=RequestExtension(
   trace_id, span_id))` and plumb `extensions=` through `invoke_hook` →
   `executor.execute`.
3. **Gateway PR — implement G1:** read `result.metadata["<plugin>"]`, validate
   (S4), batch (P-3), attach as span attributes (primary) / `record_metric`
   (secondary).
4. **Install the pilot** into the gateway env (pip/path install + Rust build);
   enable `PLUGINS_ENABLED` + `OBSERVABILITY_ENABLED`; add to `plugins/config.yaml`.
5. **Write the gateway e2e:** traced HTTP request → `GET /observability/traces`
   shows `result.metadata["pii_filter"]` metrics.

Steps 2–5 live in the **same gateway PR** (e2e validates G0/G1). The e2e may be
written first (red) and turned green as G0/G1 land. The pilot ships independently.

## Out of scope

- Gateway/runtime changes are out of the **plugin PR (#27)** — they ship in the
  companion gateway PR (G0+G1).
- Defining a separate telemetry transport in this repo.
- Requiring an external OpenTelemetry server/collector for plugin functionality.
- Adding new extension types to the `cpex` framework package (separate repo) —
  including a typed `MetricsExtension`, which is the natural *future* upgrade once
  `contextforge-org/cpex #43` lands a first-class metrics slot (plugins would then
  migrate `result.metadata` → the typed slot).
- **Per-plugin latency/duration timing.** Emitted metrics are **behavioral**
  (counts / types / categories), not timing. The hook-chain span is a single
  aggregate span; no per-plugin child span or duration metric is added here.

## Success criteria

- `pii_filter` hooks accept trace context and return metrics on
  `result.metadata["pii_filter"]` with no plugin-side OTel infrastructure.
- Metrics carry counts/types/categories only — no matched content (S1); a per-plugin
  leakage test passes (logs included).
- Multi-plugin emission is correct — distinct namespaces coexist in the executor's
  `combined_metadata` (S2); no `framework_bridge` dependency added to any plugin.
- No-observability hot path does zero metrics work (P-1); no `context.metadata`
  double-write (P-4).
- Telemetry path is isolated: metrics failure never breaks filtering (L2);
  malformed extensions tolerated (L1); no sensitive content in logs (L1/S1).
- Tests cover, by suite: trace-in/metrics-out, multi-plugin accumulation,
  no-extensions back-compat (no regression), exception isolation, S1 leakage, S3
  bounds, P-1 gating. **No plugin-side e2e**; companion gateway tests cover G0
  (extensions passed), G1 (metadata→span attributes/record_metric), S4 validation,
  P-3 batching, and the full HTTP e2e (requires G0+G1).
- Docs delivered: metric-schema contract with allow/deny-list (D1), plugin
  README/docstrings (D2), dev-guide convention (D3), regenerated stubs (D4),
  changelog note (D5).
- Version bumped per changed plugin; SPDX headers present; `make ci` green.
- Pattern documented and replicated across the other five Rust plugins.
- (Companion **G0**) gateway builds and passes `Extensions(request=...)`.
- (Companion **G1**) gateway consumes `result.metadata` through existing
  `ObservabilityService`, validating untrusted output (S4) and batching writes
  (P-3); span attributes are the primary path.
- Pilot ships and is fully tested independently of G0/G1 via direct `Extensions`
  injection.
