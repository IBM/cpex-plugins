# Rate-limiter TLS plugin-level smoke test

Verifies the three new TLS code paths added to `cpex-rate-limiter` on the
`feat/rate-limiter-tls-cert-path-trial` branch:

| Combo | What it exercises |
|---|---|
| 1 plain `redis://` | Regression check — `Client::open` still works |
| 2 CA-only `rediss://` | New `redis_ca_path` config key → `Client::build_with_tls` with `root_cert` |
| 4 full mTLS | `redis_ca_path` + `redis_client_cert_path` + `redis_client_key_path` → full `TlsCertificates` |

Mirrors the structure of mcp-context-forge PR #4809's Option A — run a
TLS-enabled Redis locally, run the plugin directly, observe success. No
gateway image needed.

## Prerequisites

- Docker
- `openssl` on PATH (already on macOS / Linux)
- The plugin built + installed into the local venv (`make install` from the
  plugin's directory)

## Step 0 — generate certs (one-time)

```bash
./.tls-smoke/gen-certs.sh
```

Generates everything under `.tls-smoke/certs/`:

```
ca.crt, ca.key                  self-signed CA (4096-bit RSA, 365 days)
redis.crt, redis.key            server cert  (SAN: localhost, 127.0.0.1)
client.crt, client.key          client cert  (EKU: clientAuth)
```

The whole `certs/` directory is gitignored — private keys never leave
your local checkout. Re-run the script anytime to regenerate (e.g.
when certs expire after 365 days).

## Step 1 — start TLS Redis

In one terminal:

```bash
./.tls-smoke/run-redis.sh
```

This starts a Docker `redis:7` container on TLS port 6390 with
`--tls-auth-clients optional` so one server handles both Combo 2 (no
client cert) and Combo 4 (with client cert). Ctrl-C to stop; the
container auto-removes.

## Step 2 — run the smoke test

In another terminal:

```bash
env -u VIRTUAL_ENV uv run python .tls-smoke/smoke.py
```

Expected output:

```
  [PASS] 1-plain  -- redis:// (no TLS, regression check)
         allowed=3 blocked=2
  [PASS] 2-ca-only  -- rediss:// + explicit redis_ca_path
         allowed=3 blocked=2
  [PASS] 4-full-mtls  -- rediss:// + CA + client cert + client key
         allowed=3 blocked=2

All combos passed.
```

Each combo fires 5 `tool_pre_invoke` calls against a `3/s` per-user
limit; the `allowed=3 blocked=2` shape proves rate-limit accounting
fired correctly through that code path. If a TLS combo silently
failed-open (e.g., TLS handshake actually failed but the error was
swallowed), it would show `allowed=5 blocked=0`.

Combo 1 skips cleanly with `[SKIP]` if no Redis is listening on port
6379 — only the TLS combos are required for new-code coverage.

## Step 3 — (optional) verify counter keys in TLS Redis

```bash
docker exec rl-smoke-tls-redis redis-cli --tls -p 6390 \
    --cacert /certs/ca.crt --cert /certs/redis.crt --key /certs/redis.key \
    --insecure --scan --pattern 'smoke-*'
```

Should list `smoke-2-ca-only-*` and `smoke-4-full-mtls-*` counter
keys — proves writes landed in TLS Redis through the new code paths.

(`--insecure` on `redis-cli` skips hostname verification on the CLI
side only — cert chain still verified against the CA.)

## What's deliberately not tested here

- Hostname verification toggle — not exposed via redis 1.2's
  `build_with_tls`, deferred to a separate ticket if needed.
- Combo 3 (mTLS without explicit CA) — requires the CA in the host OS
  trust store, which would make the smoke stack non-self-contained.
- Gateway-end-to-end verification — that's Part 2 (local-wheel-in-
  gateway-image) on the `test/tls-redis-smoke-test` branch in
  mcp-context-forge.

## Teardown

```bash
docker rm -f rl-smoke-tls-redis 2>/dev/null
```

The `.tls-smoke/` directory is gitignored.
