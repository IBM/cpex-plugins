# OpenTelemetry support at the Rust plugin boundary (Issue #27)

> **STATUS: REJECTED ALTERNATIVE (retained for the record).**
> This `Extensions.custom` design was **not** selected. The chosen design is
> `2026-06-29-otel-plugin-boundary-metadata-design.md` (the `PluginResult.metadata`
> variant). Reason: verified in `cpex/framework/manager.py`, the `custom` channel
> is **multi-plugin lossy** — each plugin is handed the *original* `extensions`
> (`manager.py:586`), and `modified_extensions` is accumulated by wholesale
> replace, "last writer wins" (`manager.py:614-616`), so with >1 plugin emitting
> on the same hook only the last plugin's metrics survive. It also requires a
> shared `merge_custom` crate, a per-emit PyO3 `model_copy`, tier reasoning whose
> guard (`validate_tier_constraints`) has **zero runtime call sites**, and a
> `framework_bridge` dependency retrofit on `url_reputation`. The `metadata`
> variant avoids all of this: the executor already accumulates `result.metadata`
> across the chain (`manager.py:939-942`) with namespaced keys coexisting. See the
> metadata spec's "Why this channel" section for the full comparison.

Date: 2026-06-29
Repo: `IBM/cpex-plugins`
Tracking: [IBM/cpex-plugins#27](https://github.com/IBM/cpex-plugins/issues/27)
Companion (out of this repo's scope): IBM/mcp-context-forge PR #4069, #3754; contextforge-org/cpex #43

## Summary

Wire CPEX Rust plugins into the gateway's **existing** OpenTelemetry/metrics
infrastructure using the CPEX extension framework. Plugins accept distributed
trace context (`trace_id`/`span_id`) at the hook boundary and return plugin-side
metrics through `Extensions.custom` (`PluginResult.modified_extensions`). The
gateway consumes those metrics with infrastructure it already owns.

**Hard constraint:** the plugin side creates **no** telemetry infrastructure — no
OpenTelemetry SDK, no exporter, no collector dependency. It only *carries* data
through the framework-provided channels. All recording/exporting happens in the
gateway with infrastructure that already exists.

**Delivery — two PRs, both owned by this effort.** The work spans both repos and
is delivered as **two coordinated PRs by the same author**:
1. **Plugin PR** (`IBM/cpex-plugins`, closes #27): B1 + P1–P5. Self-contained,
   reviewable and shippable on its own.
2. **Gateway PR** (`IBM/mcp-context-forge`, companion): G0 + G1 + the end-to-end
   test. Makes the feature live.
Gateway changes are "out of scope" only with respect to **issue #27's boundary**
(kept in a separate PR for clean review) — they are **in scope for this overall
effort**, not deferred to another team. See Dependencies and sequencing for the
order.

## Background — what already exists (verified)

**Gateway (`mcp-context-forge`) — infrastructure present, no plugin-metrics consumer:**
- `mcpgateway/services/observability_service.py` — `ObservabilityService` with
  `start_span` / `end_span` / `record_metric` / `record_token_usage`, each using
  independent DB sessions (Issue #3883 separate-session pattern).
- `mcpgateway/plugins/observability_adapter.py` — `ObservabilityServiceAdapter`,
  a duck-typed implementation of CPEX's `ObservabilityProvider` protocol.
- `mcpgateway/plugins/gateway_plugin_manager.py` — already accepts/exposes an
  `observability: Optional[ObservabilityProvider]`.
- No gateway code currently reads `result.modified_extensions` to feed metrics
  back into `ObservabilityService` (confirmed by grep). The infra is ready but
  un-subscribed.

**CPEX framework (`cpex` package) — extension plumbing present:**
- `cpex.framework.extensions.request.RequestExtension` — frozen model with
  `trace_id` and `span_id`.
- `cpex.framework.extensions.extensions.Extensions` — frozen container with the
  typed `request` slot plus a **mutable `custom`** dict slot; modified via
  `model_copy(update={...})`.
- `cpex.framework.manager` `PluginExecutor` — reads `current_trace_id`
  contextvar and starts the hook-chain span via the observability provider when a
  trace is active. It passes `extensions` **only to hooks whose signature
  declares the parameter**, and accumulates `modified_extensions` across plugins
  (last-writer-wins). **The executor does NOT build `Extensions` — it only
  filters and forwards whatever the caller passes to `execute(extensions=...)`;
  when the caller passes nothing, hooks receive `None`** (see Critical dependency
  G0).
- `cpex.framework.base.HookRef` validates the hook signature strictly: exactly
  **2 (`payload, context`) or 3 (`payload, context, extensions`)** parameters and
  the method **must be `async`** — anything else raises `PluginError` at load.
  `_accepts_extensions = (param_count == 3)`.
- `cpex.framework.extensions.tiers` — `SlotName.CUSTOM` is `MutabilityTier.MUTABLE`
  with **no capability gate**; `filter_extensions` always forwards `custom`, and
  `validate_tier_constraints` **raises `TierViolationError`** if a plugin mutates
  an immutable slot (e.g. `request`). So `custom` is a safe write channel for any
  plugin; `request` is read-only.
- `cpex.framework.models.PluginResult` — `modified_extensions: Optional[Extensions]`
  and `metadata: Optional[dict]`; `ConfigDict(arbitrary_types_allowed=True)`, **not
  frozen** (the shim can set `modified_extensions` on the Rust-returned result).

**Gateway request path — verified gaps:**
- `observability_middleware.py:181-183` sets **both** the gateway and the cpex
  (`plugins_trace_id`) `current_trace_id` contextvars — so the executor's
  hook-chain span fires. Good.
- **No gateway call site passes `extensions=` into plugin execution** (grep:
  zero). Plugins are invoked via `plugin_manager.invoke_hook(...)`; the executor's
  `extensions` defaults to `None`. So today, even a 3-param hook receives `None`
  and produces no `modified_extensions` — the plugin-side change is **inert
  end-to-end until the gateway builds and passes `Extensions`** (G0).

**Pilot plugin (`pii_filter`) — current state:**
- Python shim `plugins/rust/python-package/pii_filter/cpex_pii_filter/pii_filter.py`
  delegates the 4 hooks (`prompt_pre_fetch`, `prompt_post_fetch`,
  `tool_pre_invoke`, `tool_post_invoke`) to the Rust core. Hook signatures are
  `(payload, context)` — they do **not** declare `extensions`, so the executor
  never hands them trace context today.
- Rust core `plugins/rust/python-package/pii_filter/src/plugin.rs` already
  computes stats and writes `pii_filter_stats` / `pii_detections` into
  `context.metadata` (a `PyDict`). It never sees `trace_id`/`span_id`.

## Decisions

- **Rollout:** pilot `pii_filter` end-to-end first; then replicate to the other
  five Rust plugins (`rate_limiter`, `secrets_detection`, `url_reputation`,
  `encoded_exfil_detection`, `retry_with_backoff`).
- **Metrics channel:** `Extensions.custom` via `PluginResult.modified_extensions`.
- **Merge location:** the merge-into-`custom` logic lives in the **shared
  `crates/framework_bridge` Rust crate** — a single `merge_custom` implementation
  (B1) enforces the namespaced, merge-not-replace contract (S2) by construction.
  **5 of the 6 plugins already depend on `framework_bridge`** (`pii_filter`,
  `rate_limiter`, `secrets_detection`, `retry_with_backoff`,
  `encoded_exfil_detection`); **`url_reputation` does NOT** — it must add the
  `cpex_framework_bridge` dependency to its `Cargo.toml` before it can call B1. The Rust hook receives the `extensions`
  object, reads `request.trace_id`, computes metrics, and calls the bridge helper
  to set `modified_extensions` on the result. **The Python shim is a pass-through**
  (it only adds the `extensions` parameter and forwards it into Rust). This
  revises the earlier "shim merges / keep Rust clean" idea: one shared Rust
  implementation is preferred over per-package Python copies, and it removes the
  `_otel_metrics` metadata relay entirely.
- **Gateway phases (G0, G1):** delivered as a **second, coordinated PR** in the
  `mcp-context-forge` repo (same author, this effort) — separated from the plugin
  PR for review cleanliness, **not** deferred elsewhere. **G0** (build + pass
  `Extensions` into plugin execution) is the hard prerequisite for live
  end-to-end behaviour; **G1** consumes the emitted metrics. The cpex-plugins PR
  stays scoped and is tested independently of both (direct `Extensions`
  injection).

## Data flow (target)

```
gateway request
  → current_trace_id + plugins_trace_id contextvars set          [exists]
  → gateway BUILDS Extensions{request:{trace_id, span_id}} and
       passes it into invoke_hook → executor.execute(extensions=) [G0, gateway repo — PREREQUISITE]
  → executor filters + forwards `extensions` to hooks that
       declare the param                                          [exists, gated by G0]
  → Python shim (3-param hook) forwards `extensions` object into Rust [P1+P2]
  → Rust reads request.trace_id; if present, computes metrics       [P3]
  → bridge merge_custom builds Extensions.model_copy(custom+=…) and
       sets result.modified_extensions (MUTABLE slot only)          [P4 / B1]
  → executor accumulates modified_extensions                      [exists]
  → gateway consumer reads .custom → ObservabilityService
       record_metric / span attributes                           [G1, gateway repo]
```

**Without G0 the plugin emits nothing in the real gateway** (extensions=None →
no metrics by L1/P-1). The plugin-side pilot (P1–P5) is still independently
testable by injecting an `Extensions` directly in unit/integration tests; G0 is
what makes it live end-to-end.

## Components and changes

### Plugin side — `cpex-plugins` (issue #27 scope)

**P1 — Opt the hook boundary into `extensions` (shim, pass-through).**
In `pii_filter.py`, change the 4 hook signatures to exactly
`async def <hook>(self, payload, context, extensions=None)` — **exactly three
parameters, async** (HookRef rejects any other arity or a sync method at load) —
and forward the `extensions` object into the Rust core. The framework supplies
`extensions` only when the third parameter is present; defaulting to `None` keeps
the plugin working when the host passes no extensions (pre-G0 gateway, or other
hosts). The shim does no merging — it is a pass-through.

**P2 — PyO3: accept the `extensions` object in the Rust hooks.**
Extend the Rust hook entry points in `plugin.rs` to accept the `extensions`
argument (an optional `Bound<'_, PyAny>`). The Rust core reads
`extensions.request.trace_id`/`span_id` from it for (a) the emission gate —
**if `trace_id` is absent, the core does no metrics work** (P-1/L3) — and
(b) DEBUG log correlation. It does **not** embed `trace_id`/`span_id` as a metric
value or label (cardinality — see S3); correlation is via span parentage. No
OpenTelemetry crate, no exporter.

**P3 — Rust core computes metrics (gated).**
When `trace_id` is present, reuse the already-computed `pii_filter_stats`/
detection summaries to build a metrics map. This replaces the current
`context.metadata` stat writes, which are **removed** (single authoritative path,
no double-write — see P-4). Metrics carry **counts/types/categories only, never
matched content** (see S1), bounded in key count and value length (see S3).
Metrics must be attached on **every emitting return path** of the hook (the
masked/blocked builds; the `default_result` no-op early return emits nothing).

**P4 — Bridge `merge_custom` sets `modified_extensions` (Rust, shared).**
The Rust core calls the shared bridge helper (B1):
`merge_custom(py, extensions, "pii_filter", metrics)`, which performs
`extensions.model_copy(update={"custom": {**(extensions.custom or {}), "pii_filter": metrics}})`
via PyO3 and sets it as `modified_extensions` on the built result (the hook
Result type's field; `PluginResult` is not frozen). Only `custom` is touched
(tier-safe — see below). When `extensions` is `None` or `trace_id` absent, no
metrics are built and `modified_extensions` is left unset (P-1). The merge is
**best-effort**: any PyO3/model_copy failure is caught and logged, and the hook
returns its normal filtering result without `modified_extensions` (L2) — no
`?`-propagation on this branch.

**B1 — `merge_custom` in `crates/framework_bridge`.**
Add a single `merge_custom(py, extensions, namespace, metrics) -> PyResult<…>`
to the shared bridge crate. It is the **only** code that writes `custom`,
enforcing the namespaced merge-not-replace contract (S2) for all six plugins from
one implementation. Mechanism (standard PyO3, matching the crate's existing
`getattr`/construct style): read `extensions.getattr("custom")` (may be `None`),
convert the Rust `metrics` map to a `PyDict`, build `{**existing, namespace:
metrics}`, then call `extensions.call_method("model_copy", (), Some(update={"custom":
merged}))` — valid on the frozen model (cpex's own docstring uses this) — and set
the returned object as `modified_extensions` on the built result. Verified
feasible: every hook Result type is a `PluginResult[…]` alias and inherits the
`modified_extensions` field. Unit-tested in the bridge crate's `mod tests`.

**Tier safety (verified):** `custom` is the `MUTABLE`, un-gated slot — writing it
passes `validate_tier_constraints`. `merge_custom` (B1) MUST modify **only**
`custom` and leave `request` (and every other slot) untouched; mutating an
immutable slot raises `TierViolationError` and aborts the hook. It builds
`modified_extensions` from the received (filtered) extensions via
`model_copy(update={"custom": ...})` so the only diff is `custom`.

**P5 — Tests.** Placement follows the repo test strategy (CLAUDE.md): Rust unit
tests inline as `mod tests`; Python unit + plugin-framework integration in
`plugins/rust/python-package/pii_filter/tests/` (run via `make test-all` /
`make test-integration`); gateway unit + integration + e2e in `mcp-context-forge`
(companion).

**Feasibility — verified, both repos have direct templates (no new harness):**
- *Plugin unit/integration:* `pii_filter/tests/test_integration.py` already
  constructs real cpex payloads/`PluginContext` and `await`s the hooks directly —
  add an `Extensions` arg and assert `modified_extensions.custom`. Note the
  existing `context.metadata["pii_filter_stats"]` / `["pii_detections"]`
  assertions (e.g. lines ~131, ~297, ~489) **migrate** to `modified_extensions.
  custom` when P3/P4 land — update them, don't leave both.
- *Bridge unit:* `crates/framework_bridge` already has `mod tests` exercising the
  PyO3 build path — add `merge_custom` cases alongside.
- *Gateway unit:* `invoke_hook` mock + `await_args.kwargs` assertion
  (`test_a2a_agent_invoke_hooks.py`) for G0; `record_metric = MagicMock()` +
  metric-name inspection (`test_observability_service.py`) for G1;
  `test_observability_adapter.py` exception-path style for S4/L4.
- *Gateway integration:* `test_resource_plugin_integration.py` (real DB +
  PluginManager) and `test_span_attribute_customizer_integration.py`
  (plugin→observability).

*Bridge crate unit (`mod tests` in `crates/framework_bridge`):*
- **`merge_custom`** — preserves existing namespaces, writes only under its own
  key, never replaces `custom` (**S2**); two namespaces coexist;
- **tier safety** — output differs from input only in `custom` (`request`
  untouched); a deliberate immutable-slot mutation surfaces `TierViolationError`;
- **best-effort** — a `model_copy`/PyO3 failure returns no `modified_extensions`
  rather than propagating (L2).

*Rust unit (`mod tests` in `plugin.rs`):*
- `trace_id` present → `modified_extensions.custom["pii_filter"]` populated with
  the expected keys; `span_id` read for correlation, not embedded;
- **`trace_id` absent → gate fires:** no metrics work, `modified_extensions`
  unset (P-1/L3);
- **malformed/missing extensions** (wrong type, `None`) → no panic, core PII
  result still returned (no `.unwrap()`/`expect`/`panic` on the metrics path);
- **metrics-build failure is isolated** — filtering still completes and a result
  without `modified_extensions` is returned (see L2);
- **S3 bounds** — oversized/too-many-key metrics are capped/truncated;
- metrics attached on every emitting return path (masked/blocked); `default_result`
  no-op path emits nothing.

*Python unit / plugin-framework integration (`tests/`, via `make test-integration`):*
- hook with `extensions` returns `modified_extensions.custom["pii_filter"]`
  populated;
- hook **without** `extensions` (legacy host) still works, returns no
  `modified_extensions`; back-compat: existing `test_integration.py` passes
  unchanged — no regression;
- **S1** — known-sensitive input (PII/secret/URL) does **not** appear in
  `modified_extensions.custom` **nor in logs** — only counts/types/categories;
- **P-1** — no-`extensions` / no-`trace_id` path performs no metrics work and
  allocates no `modified_extensions`.

*Gateway unit (companion, `mcp-context-forge/tests/unit/mcpgateway/`):*
- **G0** — the gateway builds `Extensions(request=RequestExtension(trace_id,
  span_id))` and passes it on the plugin call. Reuse the existing pattern of
  mocking `invoke_hook` and asserting on `await_args.kwargs` (e.g.
  `test_a2a_agent_invoke_hooks.py`): assert `extensions` is present and carries
  the active `trace_id`.
- **G1** — given a plugin result with `modified_extensions.custom["pii_filter"]`,
  the consumer calls `record_metric` with the expected metric names. Reuse the
  `service.record_metric = MagicMock()` + inspect-`call.kwargs["name"]` pattern
  from `test_observability_service.py`.
- **S4** — non-scalar / oversized `custom` values are rejected/truncated before
  `record_metric`; **L4** — a `record_metric` failure is swallowed (mirror the
  `test_observability_adapter.py` exception-path tests).

*Gateway integration (companion, `mcp-context-forge/tests/integration/`):*
- Plugin loaded under `PLUGINS_ENABLED`, hook fired with trace context, metrics
  reach `ObservabilityService`. Template: `test_resource_plugin_integration.py`
  (real `test_db` fixture + PluginManager) and
  `tests/integration/plugins/test_span_attribute_customizer_integration.py`
  (plugin → observability).
- **P-3** — all plugin metrics for a request recorded in a single session/call.

*End-to-end (companion only, `mcp-context-forge/tests/e2e/`):*
- **No plugin-side e2e** — per repo test strategy (CLAUDE.md), e2e lives only in
  the gateway repo, and the plugin alone cannot exercise the full chain (no
  gateway/HTTP/`/observability` DB).
- Requires **G0 + G1** present. Full path: real HTTP request with
  `PLUGINS_ENABLED` + `OBSERVABILITY_ENABLED` and the pilot installed → fire a
  traced tool call → `GET /observability/traces` shows the plugin's
  `custom["pii_filter"]` metrics. Closest precedent:
  `tests/e2e/test_baggage_tracing.py` (HTTP trace propagation) +
  `tests/integration/plugins/test_span_attribute_customizer_integration.py`
  (plugin→observability). (Note: `tests/integration/helpers/trace_generator.py`
  is a manual Phoenix/OTLP script, not a reusable pytest fixture — not a template
  here.)
- Cost drivers: install pilot into gateway env (+ Rust build), config wiring,
  flush/poll before querying (best-effort separate-session writes), admin JWT for
  `/observability`. Medium–high, but bounded by the above precedents.

**Replication.** After the pilot is green, apply P1–P5 to the other five Rust
plugins, each emitting under its own `Extensions.custom["<plugin>"]` key. Most
just call B1 (no new merge code); **`url_reputation` first adds the
`cpex_framework_bridge` dependency** (see Decisions). Before replicating to a
content-handling plugin, complete its D1 allow/deny-list and per-plugin S1 leakage
test (see Documentation and Security) — these are higher-risk than the pilot.

### Gateway side — `mcp-context-forge` (companion phases, out of issue #27)

**G0 — Build and pass `Extensions` (hard prerequisite for end-to-end).**
The gateway currently sets the trace contextvars but never constructs or passes
an `Extensions` object to plugin execution. To make trace context reach plugins,
the gateway must, in its plugin-invocation path (`plugin_manager.invoke_hook` →
`executor.execute`): build `Extensions(request=RequestExtension(trace_id=...,
span_id=...))` from the active trace and plumb an `extensions=` argument through
`invoke_hook` to `execute`. Until G0 lands, plugin-side changes are inert in the
running gateway (verified: no `extensions=` call site exists). G0 is gateway-repo
work and out of issue #27 scope, but it is the gating dependency for the feature
to function outside tests.

**G1 — Consume plugin metrics with existing infrastructure.**
In the gateway plugin-execution path, after the executor returns accumulated
`modified_extensions`, read `modified_extensions.custom`. **Primary (required):
attach each plugin's metrics as span attributes on the hook-chain span via
`ObservabilityServiceAdapter`** — this is the load-bearing path that lets an
operator drill from a specific trace in `GET /observability/traces/{trace_id}`
into the responsible plugin (the observability "why"). **Secondary (optional):**
also feed `ObservabilityService.record_metric` for aggregate/searchable metrics.
Span attributes are not optional; `record_metric` is the add-on. Creates no new
infrastructure; only subscribes the existing one to the new data. Delivered as a
separate, clearly-labelled change so issue #27's plugin PR stays scoped.

Constraints (see Security/Performance below):
- **Validate before recording (S4):** treat `custom` as untrusted plugin output.
  Accept only `str | int | float | bool` values with bounded length/key count;
  drop or truncate anything else. Never pass values into free-text attribute
  search paths unsanitised.
- **Batch writes (P-3):** record all plugin metrics for a request through a
  **single** `record_metric`/session, not one session per plugin or per key, to
  avoid connection-pool exhaustion under the separate-session pattern.
- **Best-effort:** failures swallowed, matching the existing observability
  pattern — telemetry never breaks the request.

## Security

These constraints are normative — apply to the pilot and every replicated plugin.

- **S1 — No sensitive content in metrics (critical).** Several plugins
  (`pii_filter`, `secrets_detection`, `url_reputation`, `encoded_exfil_detection`)
  inspect sensitive material. Metrics emitted into `Extensions.custom` flow to the
  gateway and become queryable through the `/observability` API
  (`attribute_search` free-text, admin-scoped — and per gateway CLAUDE.md,
  observability writes are **platform-wide, not RBAC-scoped**, so any leaked value
  is visible to all admins). Emit **counts, types, and categories only — never the
  matched value** (no raw PII, secret, token, or full URL). Each plugin defines an
  explicit **allowlist** of metric keys; anything not on it is not emitted. Add a
  per-plugin test asserting known-sensitive inputs do not appear in
  `modified_extensions.custom` **nor in logs** — run it for **every** plugin, not
  just the pilot.
  - **S1 is the sole semantic guarantee.** S4 (gateway) only checks type/size — a
    leaked full URL or `match` preview is a bounded `str` and passes S4 cleanly.
    Nothing downstream filters content, so the per-plugin allowlist is load-bearing.
  - **Replication danger fields (verified in code) — explicit deny-list.** These
    existing finding fields carry content and MUST be excluded from metrics:
    `encoded_exfil_detection` `match` / `matched_preview` (`src/lib.rs`);
    `url_reputation` `url` / `details.url` / `path` (`src/engine.rs`);
    `pii_filter` already emits only counts/types (clean baseline).
  - **`secrets_detection` redaction is config-gated** (`redact` flag /
    `redaction_text`). Metrics MUST derive from counts/types only and never read a
    pre-redaction raw value, even when `redact=false`.
- **S2 — Namespaced merge, never replace.** `Extensions` is frozen, but
  `model_copy(update={"custom": ...})` replaces the whole `custom` dict and the
  executor is last-writer-wins. Replacing `custom` silently drops sibling plugins'
  metrics. Enforced by construction: the **only** code that writes `custom` is the
  shared `merge_custom` helper in `crates/framework_bridge` (B1), which preserves
  existing keys and writes only under the plugin's namespace. No plugin (Rust or
  Python) writes `custom` directly.
- **S3 — Bound cardinality and size.** Do **not** use `trace_id`/`span_id` (or any
  unbounded value) as a metric label/attribute — correlation is via span
  parentage, not labels. High-cardinality labels blow up DB rows and the existing
  metrics-aggregation indexes (storage DoS). Cap the metrics dict to a small fixed
  set of keys and bounded value lengths in the shim.
- **S4 — Untrusted output at the gateway boundary (G1).** The gateway consumer
  treats `custom` as untrusted: type-check and length-bound every value before
  `record_metric`, and keep values out of any unsanitised query/search path.
  **S4 is a type/size guard, not a content filter** — it cannot catch a leaked
  value that is a well-formed bounded string; that is S1's job. When G1 rejects or
  truncates a value, it MUST NOT log the rejected value (S1-applies-to-logs holds
  on the gateway side too — a WARNING echoing the dropped `custom` re-opens the
  exfil channel).

## Performance

- **P-1 — Gate emission on trace context.** `OBSERVABILITY_ENABLED` defaults off.
  When the hook receives no `extensions` or no `trace_id`, do **zero** metrics
  work — no dict build, no `model_copy`, no `modified_extensions`. The hot path
  for the no-observability case is unchanged from today.
- **P-2 — Minimise frozen-model copies.** A single request fires one hook type
  across the subscribed plugins (up to ~6); `merge_custom` calls
  `Extensions.model_copy` (via PyO3) once per emitting plugin, reconstructing a
  pydantic model each time. Do at most one copy per hook. If profiling shows this
  hot, fold all plugins' metrics into `custom` once at end of the hook chain
  instead of per plugin. Benchmark before and after on the pilot.
- **P-3 — Batch gateway metric writes (G1).** The separate-session pattern already
  opens 4–6 DB sessions per traced request; a naive `record_metric` per plugin or
  per key multiplies sessions and risks "QueuePool limit exceeded". Record all
  plugin metrics for a request in one session/call.
- **P-4 — No double-write.** Do not keep both the legacy `context.metadata` stat
  writes and the new returned-dict path. The returned dict is authoritative;
  remove the `context.metadata` writes when the Rust metrics path lands (see P3).

## Error handling, logging, and exceptions

**Exception isolation (normative).**
- **L1 — Input tolerance.** Missing/`None` `extensions` → plugin behaves exactly
  as today (no trace, no `modified_extensions`); no hard dependency on a host that
  supplies extensions. A malformed `extensions` (wrong type) or wrong-typed
  `trace_id`/`span_id` is treated as absent — **never raised**.
- **L2 — Telemetry never breaks the plugin.** The metrics/trace path is strictly
  best-effort and isolated from the plugin's primary function. The current Rust
  hooks propagate errors with `?`; metrics assembly MUST NOT use that path —
  wrap it so any failure is caught, logged once, and the hook returns its normal
  filtering result **without** metrics. No `.unwrap()`/`expect`/`panic` and no
  new `?`-propagated error on the metrics branch.
- **L3 — Missing trace context = no emission.** No `trace_id` (observability
  effectively off) → the Rust core does no metrics work and emits nothing, even if
  `extensions` is present. This is the same gate as P-1 and avoids uncorrelated,
  un-attachable metrics. (`span_id` may be absent while `trace_id` is present —
  that still emits, just without a parent span id.)
- **L4 — Gateway consumer (G1)** failures are best-effort and swallowed, matching
  the existing separate-session observability pattern — telemetry never breaks the
  request.

**Logging (normative).**
- Use the existing Rust logger (`LOGGER_NAME = "cpex_pii_filter.pii_filter"`,
  bridged to Python `logging`); no new logging stack.
- **DEBUG:** trace context received (presence only) / absent; metrics emitted
  (key names + counts, never values).
- **WARNING (throttled):** malformed `extensions`, metrics-build failure (L2),
  bounds truncation (S3). One-line, rate-limited to avoid log flooding on the hot
  path.
- **No sensitive content in logs (S1 applies to logs too).** Logs are an exfil
  channel — never log matched PII/secret/URL values or full payloads, only
  counts/types/categories. Covered by the S1 test.

## Documentation

Treat docs as deliverables, not afterthoughts. Per pilot plugin and on
replication:

- **D1 — Metric schema contract (cross-repo source of truth).** Document the
  `Extensions.custom["<plugin>"]` payload — exact keys, value types, units, and
  the bound limits (S3). This is the contract G1 consumes; the gateway companion
  references the same doc so both sides agree. Place in this spec's directory and
  link from each plugin. **Per plugin, D1 enumerates both an explicit allow-list
  (the only keys emitted) and a deny-list of known content-bearing fields that
  MUST NOT be emitted** (e.g. `encoded_exfil_detection`: deny `match`,
  `matched_preview`; `url_reputation`: deny `url`, `path`; `secrets_detection`:
  deny any pre-redaction value). The allow/deny-list for a plugin is written and
  reviewed **before** that plugin is replicated (gates the S1 leakage test).
- **D2 — Plugin README / docstrings.** Each plugin's README and hook docstrings
  document the new optional `extensions` hook parameter and what the plugin emits.
  State the no-sensitive-content guarantee (S1).
- **D3 — Repo dev docs.** Update `cpex-plugins` plugin-development guidance
  (CLAUDE.md / README "Creating a New Plugin") with the trace-in/metrics-out
  convention and the shared `crates/framework_bridge::merge_custom` helper, so new
  plugins call it rather than touching `custom` themselves.
- **D4 — PyO3 stubs.** Regenerate `.pyi` type stubs (`stub_gen`) for the changed
  hook signatures; CI stub-check stays green.
- **D5 — Changelog / migration note.** Record the hook-signature change
  (added optional `extensions`) as backward-compatible in the plugin changelog.

## Versioning

Per repo policy (CLAUDE.md), each changed plugin bumps its version in lockstep:
`Cargo.toml` (source of truth), `cpex_<plugin>/plugin-manifest.yaml` `version`,
and `Cargo.lock` (auto). The shared `crates/framework_bridge` change (B1) is a
common dependency — version it and rebuild/republish every dependent plugin that
adopts the feature. New code (the `merge_custom` helper) carries Apache-2.0 SPDX
headers. `make ci` must pass before PR.

## Dependencies and sequencing

- **G0 is the gating dependency** for live end-to-end behaviour: the gateway must
  build and pass `Extensions` into plugin execution. It is gateway-repo work,
  shipped in the **companion gateway PR** (this effort, same author) — separate
  from #27 for review, not deferred. Cross-link the two PRs.
- **Pilot is independently shippable and testable** before G0: P1–P5 are verified
  by injecting an `Extensions` object directly in unit/plugin-framework tests.
  This decouples the cpex-plugins PR from gateway timing.
- **Recommended order:** B1 shared `merge_custom` helper first → P1–P5 pilot
  (same cpex-plugins PR) → G0 + G1 (gateway PR, validated against the installed
  pilot) → replicate P1–P5 to the other five plugins (each calls B1, no new merge
  code — `url_reputation` first adds the `cpex_framework_bridge` dependency). The
  D1 metric-schema contract is written during the pilot and is
  the shared reference G0/G1 build against.

### Unblock order for gateway e2e

E2E is not externally blocked — every prerequisite is in this workspace. It is a
**sequencing** dependency: the full chain must exist before the e2e can pass.
There are no missing-infra blockers (observability service, trace middleware,
`/observability` API, and the `test_baggage_tracing` / `span_attribute_customizer`
test precedents all already exist).

Do, in order:

1. **Ship plugin pilot (#27):** B1 (`merge_custom` in `framework_bridge`) +
   P1–P4, with D1 metric-schema contract. Verified by plugin-side unit +
   framework-integration tests (injected `Extensions`). No e2e here.
2. **Gateway PR — implement G0:** build `Extensions(request=RequestExtension(
   trace_id, span_id))` from the active trace and plumb `extensions=` through
   `invoke_hook` → `executor.execute`.
3. **Gateway PR — implement G1:** read `modified_extensions.custom`, validate
   (S4), batch (P-3), and feed `ObservabilityService.record_metric` / span
   attributes.
4. **Install the pilot** into the gateway env (pip/path install + Rust build);
   enable `PLUGINS_ENABLED` + `OBSERVABILITY_ENABLED` and add the plugin to
   `plugins/config.yaml`.
5. **Write the gateway e2e** (`mcp-context-forge/tests/e2e/`): traced HTTP request
   → `GET /observability/traces` shows `custom["pii_filter"]` metrics.

Steps 2–5 live in the **same gateway PR** (the e2e validates G0/G1, so they ship
together). The e2e may be written first (red) and turned green as G0/G1 land
(TDD-style). The pilot (step 1) ships independently of all of this.

## Out of scope

- Gateway/runtime changes are out of the **plugin PR (#27)** — they ship in the
  companion gateway PR (G0+G1), not in the cpex-plugins change.
- Defining a separate telemetry transport in this repo.
- Requiring an external OpenTelemetry server/collector for plugin functionality.
- Adding new extension types to the `cpex` framework package (separate repo).
- **Per-plugin latency/duration timing.** Emitted metrics are **behavioral**
  (counts / types / categories), not timing. The executor's hook-chain span is a
  single aggregate span (counts only), and there is no per-plugin child span or
  duration metric — adding one is a separate enhancement, not part of this work.

## Success criteria

- `pii_filter` hooks accept trace context and return metrics via
  `Extensions.custom` with no plugin-side OTel infrastructure.
- Metrics carry counts/types/categories only — no matched content (S1); a
  leakage test passes.
- All plugins merge under their own namespace via the shared `merge_custom`
  helper — no clobber (S2); no unbounded labels (S3).
- No-observability hot path does zero metrics work (P-1); no `context.metadata`
  double-write (P-4).
- Telemetry path is isolated: metrics/trace failure never breaks filtering (L2);
  malformed extensions tolerated (L1); no sensitive content in logs (L1/S1).
- Tests cover, by suite: trace-in/metrics-out, no-extensions back-compat (no
  regression), exception isolation, S1 leakage, S2 merge helper, S3 bounds, P-1
  gating. **No plugin-side e2e**; companion gateway tests cover S4 validation,
  P-3 batching, and the full HTTP e2e (request → `/observability` shows metrics),
  which requires G0+G1.
- Docs delivered: metric-schema contract (D1), plugin README/docstrings (D2),
  dev-guide convention (D3), regenerated stubs (D4), changelog note (D5).
- Version bumped per changed plugin; SPDX headers present; `make ci` green.
- Pattern documented and replicated across the other five Rust plugins.
- (Companion **G0**) gateway builds and passes `Extensions(request=...)` into
  plugin execution — the prerequisite that makes trace context reach plugins.
- (Companion **G1**) gateway consumes plugin metrics through existing
  `ObservabilityService`, validating untrusted output (S4) and batching writes
  (P-3).
- Pilot ships and is fully tested independently of G0/G1 via direct `Extensions`
  injection in tests.
