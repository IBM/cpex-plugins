# SPDX-License-Identifier: Apache-2.0
"""
Plugin-level smoke test for the rate-limiter's new TLS code paths.

Exercises three of the four supported (ca_path, client_cert+key) combinations
against a single TLS-enabled Redis running on localhost:6390 (per the
sibling script ``run-redis.sh``).  Combo 3 (mTLS without explicit CA) is
skipped because it requires the CA to live in the host OS trust store --
the existing tls-certs/ca.crt is intentionally not installed system-wide
to keep this stack self-contained.

For each combo we:

  1. Instantiate ``RateLimiterPlugin`` with a dimension-specific
     redis_key_prefix so counters don't collide across combos.
  2. Fire ``tool_pre_invoke`` 5 times with the same user/tenant.
  3. Assert at least one call is allowed (proves the plugin reached
     Redis and the rate-limit accounting fired) and that the configured
     limit (3/s) actually kicks in by the 4th call (proves the plugin
     wasn't silently failing-open at TLS init).

A successful run prints a per-combo OK line and exits 0.  Any failure
prints the offending combo + exception.

Run from the plugin directory after ``make install`` and after Redis is
running on TLS port 6390:

    env -u VIRTUAL_ENV uv run python .tls-smoke/smoke.py
"""

import asyncio
import pathlib
import socket
import sys
import uuid

from cpex.framework.hooks.tools import ToolPreInvokePayload
from cpex.framework.models import GlobalContext, PluginConfig, PluginContext, PluginMode

from cpex_rate_limiter.rate_limiter import RateLimiterPlugin


_CERTS = pathlib.Path(__file__).resolve().parent / "certs"
_CA = str(_CERTS / "ca.crt")
_CLIENT_CRT = str(_CERTS / "client.crt")
_CLIENT_KEY = str(_CERTS / "client.key")

_PLAIN_REDIS_URL = "redis://127.0.0.1:6379/0"
_TLS_REDIS_URL = "rediss://localhost:6390/0"


def _is_listening(host: str, port: int, timeout: float = 0.3) -> bool:
    """Return True if a plain TCP connection to host:port succeeds.

    Used to decide whether to attempt Combo 1 -- a plain ``redis://`` listener
    isn't required for the smoke test (TLS combos are the meaningful new
    coverage), so we skip cleanly when port 6379 isn't a Redis we can use.
    """
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False

# 3/s burst → assert ≥1 allowed AND ≥1 blocked when we fire 5 requests
_BURST = 5
_LIMIT_PER_SEC = 3


def _make_plugin(label: str, extra_config: dict) -> RateLimiterPlugin:
    return RateLimiterPlugin(
        PluginConfig(
            name=f"RL-{label}",
            kind="cpex_rate_limiter.rate_limiter.RateLimiterPlugin",
            hooks=["tool_pre_invoke"],
            priority=100,
            mode=PluginMode.SEQUENTIAL,
            config={
                "by_user": f"{_LIMIT_PER_SEC}/s",
                "backend": "redis",
                "algorithm": "fixed_window",
                "redis_key_prefix": f"smoke-{label}-{uuid.uuid4().hex[:6]}",
                "fail_mode": "open",
                **extra_config,
            },
        )
    )


async def _fire_burst(plugin: RateLimiterPlugin) -> dict[str, int]:
    counters = {"allowed": 0, "blocked": 0}
    for _ in range(_BURST):
        ctx = PluginContext(
            global_context=GlobalContext(request_id=str(uuid.uuid4()), user="alice"),
        )
        payload = ToolPreInvokePayload(name="any_tool", args={})
        result = await plugin.tool_pre_invoke(payload, ctx)
        if result.continue_processing:
            counters["allowed"] += 1
        else:
            counters["blocked"] += 1
    return counters


async def _run_combo(label: str, extra_config: dict) -> tuple[bool, str]:
    """Returns (passed, detail)."""
    try:
        plugin = _make_plugin(label, extra_config)
    except Exception as exc:
        return False, f"plugin init failed: {type(exc).__name__}: {exc}"

    try:
        counters = await _fire_burst(plugin)
    except Exception as exc:
        return False, f"burst failed: {type(exc).__name__}: {exc}"

    if counters["allowed"] == 0:
        return False, f"no allowed calls (TLS handshake probably failed): {counters}"
    if counters["blocked"] == 0:
        return False, f"no blocked calls (rate-limit accounting didn't fire): {counters}"

    return True, f"allowed={counters['allowed']} blocked={counters['blocked']}"


async def main() -> int:
    combos = [
        (
            "1-plain",
            "redis:// (no TLS, regression check)",
            {"redis_url": _PLAIN_REDIS_URL},
        ),
        (
            "2-ca-only",
            "rediss:// + explicit redis_ca_path",
            {"redis_url": _TLS_REDIS_URL, "redis_ca_path": _CA},
        ),
        (
            "4-full-mtls",
            "rediss:// + CA + client cert + client key",
            {
                "redis_url": _TLS_REDIS_URL,
                "redis_ca_path": _CA,
                "redis_client_cert_path": _CLIENT_CRT,
                "redis_client_key_path": _CLIENT_KEY,
            },
        ),
    ]

    failures = []
    for label, description, extra_config in combos:
        if label == "1-plain" and not _is_listening("127.0.0.1", 6379):
            print(f"  [SKIP] {label}  -- {description}")
            print("         no listener on 127.0.0.1:6379")
            continue
        passed, detail = await _run_combo(label, extra_config)
        status = "PASS" if passed else "FAIL"
        print(f"  [{status}] {label}  -- {description}")
        print(f"         {detail}")
        if not passed:
            failures.append(label)

    print()
    if failures:
        print(f"FAILED: {failures}")
        return 1
    print("All combos passed.")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
