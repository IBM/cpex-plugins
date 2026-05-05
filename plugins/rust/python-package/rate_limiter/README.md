# Rate Limiter Plugin

> Author: ContextForge Contributors

Enforces rate limits per user, tenant, and tool across `tool_pre_invoke` and `prompt_pre_fetch` hooks. Supports pluggable counting algorithms (fixed window, sliding window, token bucket), an in-process memory backend (single-instance), and a Redis backend (shared across all gateway instances).

## Runtime Requirements

This plugin depends on `cpex>=0.1.0rc1,<0.2` and imports hook models from `cpex.framework`. The compiled Rust extension is mandatory; there is no Python fallback implementation.

## Hooks

| Hook | When it runs |
|---|---|
| `tool_pre_invoke` | Before every tool call — checks `by_user`, `by_tenant`, `by_tool` |
| `prompt_pre_fetch` | Before every prompt fetch — checks `by_user`, `by_tenant`, `by_tool` |

If any configured dimension is exceeded, the plugin returns a violation with HTTP 429. All requests include `X-RateLimit-*` headers. The most restrictive active dimension is surfaced (e.g. if both user and tenant limits are active, the one closest to exhaustion is reported).

## Configuration

```yaml
- name: RateLimiterPlugin
  kind: cpex_rate_limiter.rate_limiter.RateLimiterPlugin
  hooks:
    - prompt_pre_fetch
    - tool_pre_invoke
  mode: enforce          # enforce | permissive | disabled
  config:
    by_user: "30/m"      # per-user limit across all tools
    by_tenant: "300/m"   # shared limit across all users in a tenant
    by_tool:             # per-tool overrides (applied on top of by_user)
      search: "10/m"
      summarise: "5/m"

    # Algorithm — choose one (default: fixed_window)
    algorithm: "fixed_window"    # fixed_window | sliding_window | token_bucket

    # Backend — choose one
    backend: "memory"    # default: single-process, resets on restart
    # backend: "redis"   # shared across all gateway instances

    # Redis options (required when backend: redis)
    redis_url: "redis://redis:6379/0"
    redis_key_prefix: "rl"

    # Backend failure policy (default: "open" — fail-open)
    # "closed" — return HTTP 503 BACKEND_UNAVAILABLE violation when the
    # backend can't be reached (correctness over availability)
    fail_mode: "open"
```

### Configuration reference

| Field | Type | Default | Description |
|---|---|---|---|
| `by_user` | string | `null` | Per-user rate limit, e.g. `"60/m"` |
| `by_tenant` | string | `null` | Per-tenant rate limit, e.g. `"600/m"` |
| `by_tool` | dict | `{}` | Per-tool overrides, e.g. `{"search": "10/m"}` |
| `algorithm` | string | `"fixed_window"` | Counting algorithm: `"fixed_window"`, `"sliding_window"`, or `"token_bucket"` |
| `backend` | string | `"memory"` | `"memory"` or `"redis"` |
| `redis_url` | string | `null` | Redis connection URL (required when `backend: redis`) |
| `redis_key_prefix` | string | `"rl"` | Prefix for all Redis keys |
| `fail_mode` | string | `"open"` | Behaviour when the backend can't be reached: `"open"` allows the request through, `"closed"` blocks with a 503 `BACKEND_UNAVAILABLE` violation |

**Rate string format:** `"<count>/<unit>"` where unit is `s`/`sec`/`second`, `m`/`min`/`minute`, or `h`/`hr`/`hour`. Malformed strings raise `ValueError` at startup. Counts above `1_000_000` are rejected as a sanity ceiling — anything higher is almost certainly a misconfig or a denial-of-service vector against the memory backend.

**Unknown config keys** (e.g. a typo like `redis_ur`) are logged at `WARN` at engine init alongside the accepted-key list, instead of being silently ignored.

**Invalid `fail_mode` values** (e.g. `"clsoed"`) are logged at `WARN` and fall back to `"open"` so an operator's typo surfaces instead of silently disabling the hardening they asked for.

**Omitting a dimension** (e.g. no `by_tenant`) means that dimension is unlimited — no counter is tracked for it.

## Response headers

Every request (allowed or blocked) includes:

| Header | Description |
|---|---|
| `X-RateLimit-Limit` | Configured limit for the most restrictive active dimension |
| `X-RateLimit-Remaining` | Requests remaining in the current window |
| `X-RateLimit-Reset` | Unix timestamp when the current window resets |
| `Retry-After` | Seconds until the window resets (blocked requests only) |

## Algorithms

Three counting algorithms are available, selected via the `algorithm` config field.

| Algorithm | Config value | Best for | Trade-off |
|---|---|---|---|
| Fixed window | `fixed_window` | General use, lowest overhead | Up to 2× the limit at window boundaries |
| Sliding window | `sliding_window` | Smooth enforcement, no boundary burst | Higher memory: stores one timestamp per request per key |
| Token bucket | `token_bucket` | Bursty workloads — allows short spikes up to capacity | Slightly higher Redis overhead: stores `{tokens, last_refill}` hash per key |

### Fixed window (default)

Counts requests in a fixed time slot (e.g. "minute 14:03"). Resets at the slot boundary. Simple and fast. The 2× burst at a boundary (N requests at the end of slot T, N requests at the start of T+1) is a known trade-off; use `by_user` with headroom if this matters.

### Sliding window

Stores a timestamp for every request in the current window. At each check, expired timestamps are discarded and the remaining count is compared against the limit. Prevents boundary bursts entirely. Memory usage grows with request volume — roughly one float per request per active key.

### Token bucket

Each identity (user, tenant, tool) has a bucket that holds up to `count` tokens. Tokens refill at a steady rate of `count/window`. A request consumes one token. Bursts up to the bucket capacity are allowed; sustained rate above `count/window` is rejected. Useful for APIs where short spikes are acceptable but sustained overload is not.

**Redis support:** `token_bucket` with `backend: redis` is fully supported. The plugin stores `{tokens, last_refill}` in a Redis hash per key and uses an atomic Lua script to refill and consume tokens in a single round-trip — the same pattern as the other two algorithms. This means `token_bucket` enforces a true cluster-wide limit in multi-instance deployments.

## Backends

### Memory backend (default, single-instance only)

- Counters are stored in a process-local `MemoryStore` (Rust, per-key `RwLock` — no single global lock)
- An amortized sweep evicts expired keys every ~128 calls — for `fixed_window`, keys are evicted once the window elapses; for `sliding_window`, keys with empty timestamp deques are evicted; for `token_bucket`, keys inactive for >1 hour are evicted
- **Limitation:** state is not shared across processes or hosts. In a multi-instance deployment (e.g. 3 gateway instances behind nginx), each instance tracks its own counter — the effective limit is `N × configured_limit`

### Redis backend

- `fixed_window`: atomic Lua `INCR`+`EXPIRE` — one Redis round-trip per check, no race condition
- `sliding_window`: atomic Lua `ZADD`+`ZREMRANGEBYSCORE`+`ZCARD`+`EXPIRE` — one round-trip, no race condition
- `token_bucket`: atomic Lua script — reads `{tokens, last_refill}` hash, refills proportionally, consumes 1 token, writes back — one round-trip, no race condition
- All gateway instances share the same counter — the configured limit is the true cluster-wide limit
- Requires `redis_url` to be set
- **Backend failure policy** is governed by `fail_mode`:
  - `"open"` (default) — the request is allowed through without rate limiting. Availability over correctness; an infrastructure failure must never block legitimate traffic. Operators should monitor for rate-limiter error logs and treat them as high-priority alerts.
  - `"closed"` — the request is blocked with a `PluginViolation` (code `BACKEND_UNAVAILABLE`, HTTP 503, `Retry-After: 1`). Correctness over availability; pick this when a failed rate-limit check is less acceptable than a brief outage.

**Multi-instance deployment (important):** The `memory` backend is local to a single gateway instance — rate limit counters are not shared across replicas. For multi-instance deployments (e.g., behind nginx or on OpenShift with multiple gateway pods), always use `backend: redis` to ensure rate limits are enforced correctly across all instances.

### Tenant-scoped Redis key layout

When the plugin context carries a `tenant_id`, every dimension key is prefixed with it so counters are isolated per tenant:

```
rl:{tenant_id}:user:{email}:{window_seconds}
rl:{tenant_id}:tenant:{tenant_id}:{window_seconds}
rl:{tenant_id}:tool:{tool_name}:{window_seconds}
```

When `tenant_id` is absent (single-tenant deployments), the prefix is omitted and keys revert to the pre-tenant-scoping layout (`rl:user:{email}:{window}`), so single-tenant behaviour is unchanged.

**Upgrade note:** the first deploy of the tenant-scoping change causes counters under `rl:user:*` / `rl:tool:*` to be orphaned while new writes land at `rl:{tenant}:user:*`. Counters effectively reset once for all in-flight windows — non-event for typical second/minute windows.

## Examples

### Single-instance (default config)

```yaml
config:
  by_user: "60/m"
  by_tenant: "600/m"
```

### Multi-instance with Redis

```yaml
config:
  backend: "redis"
  redis_url: "redis://redis:6379/0"
  by_user: "30/m"
  by_tenant: "3000/m"
  by_tool:
    search: "10/m"
```

### Sliding window (no boundary bursts)

```yaml
config:
  algorithm: "sliding_window"
  by_user: "30/m"
  by_tenant: "300/m"
```

### Token bucket — memory backend (default)

```yaml
config:
  algorithm: "token_bucket"
  by_user: "30/m"   # bucket holds 30 tokens, refills at 30/min
```

### Token bucket — Redis backend (multi-instance)

```yaml
config:
  algorithm: "token_bucket"
  backend: "redis"
  redis_url: "redis://redis:6379/0"
  by_user: "30/m"
```

### Permissive mode (observe without blocking)

```yaml
mode: permissive
config:
  by_user: "60/m"
```

In `permissive` mode the plugin records violations and emits `X-RateLimit-*` headers but does not block requests. Useful for baselining traffic before switching to `enforce`.

## Lifecycle

The plugin participates in the plugin manager's lifecycle contract:

- `async def initialize(self)` — invoked once when the plugin manager constructs the plugin. Logs one `INFO` record naming the active backend (`memory` / `redis`).
- `async def shutdown(self)` — invoked when the plugin manager tears the plugin down (runtime disable, re-instantiation after a config change). Releases backend-held resources — specifically, drops the Rust core's cached Redis multiplexed connection and the SCRIPT LOAD SHA cache. In-flight requests already hold their own clones of the connection and remain valid; the cached reference is replaced on the next request.

Without `shutdown`, the cached Redis connection would leak across plugin re-instantiation, producing connection churn on the server.

## Limitations

| Limitation | Severity | Status |
|---|---|---|
| Memory backend not shared across processes | HIGH | Use Redis backend for multi-instance deployments |
| Fixed window allows up to 2× limit at window boundary | LOW | Use `sliding_window` algorithm, or use `by_user` with headroom |
| `by_tool` matching is case-sensitive | LOW | Fixed — tool names are normalised with `.strip().lower()` |
| Whitespace-only user identity bypasses anonymous bucket | LOW | Fixed — `_extract_user_identity` strips whitespace and falls back to `'anonymous'` |
| No per-server limits (`server_id` dimension missing) | LOW | Not implemented |
| No config hot-reload — rate string changes require restart | LOW | Not implemented |
