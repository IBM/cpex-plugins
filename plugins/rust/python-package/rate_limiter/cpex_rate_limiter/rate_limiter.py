# -*- coding: utf-8 -*-
"""Thin compatibility shim for the Rust-owned rate limiter plugin."""

from __future__ import annotations

import logging

try:
    from mcpgateway.plugins.framework import Plugin, PromptPrehookResult, ToolPreInvokeResult
except ModuleNotFoundError:
    class Plugin:  # type: ignore[no-redef]
        def __init__(self, config) -> None:
            self.config = config

    class PromptPrehookResult:  # type: ignore[no-redef]
        def __init__(self, continue_processing=True, violation=None, metadata=None, http_headers=None):
            self.continue_processing = continue_processing
            self.violation = violation
            self.metadata = metadata
            self.http_headers = http_headers

    class ToolPreInvokeResult:  # type: ignore[no-redef]
        def __init__(self, continue_processing=True, violation=None, metadata=None, http_headers=None):
            self.continue_processing = continue_processing
            self.violation = violation
            self.metadata = metadata
            self.http_headers = http_headers

from cpex_rate_limiter.rate_limiter_rust import (
    RateLimiterPluginCore,
    compat_default_config as _compat_default_config,
    compat_parse_rate as _compat_parse_rate,
)


def _parse_rate(rate: str) -> tuple[int, int]:
    count, window = _compat_parse_rate(rate)
    return int(count), int(window)


class RateLimiterConfig:
    __slots__ = (
        "by_user",
        "by_tenant",
        "by_tool",
        "algorithm",
        "backend",
        "redis_url",
        "redis_key_prefix",
        "fail_mode",
    )

    def __init__(self, **overrides) -> None:
        config = dict(_compat_default_config())
        config.update(overrides)
        for field in self.__slots__:
            setattr(self, field, config.get(field))


_logger = logging.getLogger(__name__)

# Single-flight wipe lock TTL. Comfortably longer than any reasonable
# wipe-on-disable should take; bounds worst-case starvation if the
# lock-holder dies mid-wipe.
_WIPE_LOCK_TTL_SECONDS = 30


class RateLimiterPlugin(Plugin):
    """Gateway-facing Plugin subclass that delegates behavior to Rust."""

    def __init__(self, config) -> None:
        super().__init__(config)
        self._core = RateLimiterPluginCore(config.config or {})

    async def initialize(self) -> None:
        """Lifecycle hook: called once when the plugin manager constructs us."""
        cfg = self.config.config or {}
        backend = cfg.get("backend", "memory")
        _logger.info("rate limiter initialized: backend=%s", backend)

    async def shutdown(self) -> None:
        """Lifecycle hook: wipe counters if mode just transitioned to disabled,
        then release Rust-held resources (e.g. Redis connection).

        The plugin manager calls this on disable and on re-instantiation.
        Without core.shutdown() the cached Redis connection leaks until the
        plugin instance is garbage-collected.

        Wipe behaviour: if the operator has just set this plugin's mode to
        "disabled" via the admin mode API, every rate-limit counter for this
        plugin's configured key prefix is deleted from Redis before shutdown
        completes. Re-enabling then starts every user with a fresh window.
        See README "Disabling resets counters" for the contract details and
        the binding-API limitation.
        """
        try:
            if await self._mode_in_redis_says_disabled():
                # Single-flight guard: in a fleet (N replicas × M workers),
                # all instances see the same `mode=disabled` signal. Without
                # this guard, every worker independently runs SCAN+DEL,
                # producing N*M times the Redis work and competing on the
                # same keyspace. The lock ensures exactly one worker per
                # disable cycle performs the wipe; the rest skip cleanly.
                if await self._acquire_wipe_lock():
                    try:
                        await self._wipe_my_counters()
                    finally:
                        await self._release_wipe_lock()
        except Exception:
            _logger.exception("rate limiter shutdown: wipe-on-disable check failed")
        finally:
            try:
                self._core.shutdown()
            except Exception:
                _logger.exception("rate limiter shutdown: core.shutdown() raised")

    async def _mode_in_redis_says_disabled(self) -> bool:
        """Return True only when the admin mode API has set this plugin's
        mode to "disabled".

        ``publish_plugin_mode_change`` (in mcp-context-forge) writes
        ``plugin:<name>:mode`` to Redis *before* broadcasting the pub/sub
        invalidation. By the time this method runs in response to that
        invalidation, the Redis key authoritatively reflects the new mode
        — there is no race window where the key still says ``enforce``.

        Any error (Redis unreachable, key absent, value not "disabled")
        returns False so the wipe never fires accidentally. This is the
        graceful-shutdown safety property: a pod restart leaves the Redis
        mode key untouched (it stays at whatever the operator last set,
        almost always not "disabled"), so counters survive restarts.
        """
        cfg = self.config.config or {}
        if cfg.get("backend") != "redis":
            return False
        redis_url = cfg.get("redis_url")
        if not redis_url:
            return False
        try:
            import redis.asyncio as aioredis  # noqa: PLC0415
        except Exception:
            return False
        try:
            client = aioredis.from_url(redis_url, decode_responses=True)
        except Exception:
            return False
        try:
            try:
                value = await client.get(f"plugin:{self.config.name}:mode")
            except Exception:
                return False
        finally:
            try:
                await client.aclose()
            except Exception:
                pass
        return value == "disabled"

    def _wipe_lock_key(self) -> str:
        """Return the Redis key used to single-flight the wipe.

        Uses a dash separator so the lock key is *outside* the wipe SCAN's
        glob pattern (``<prefix>:*``). Otherwise the wipe would delete its
        own lock mid-pass.
        """
        cfg = self.config.config or {}
        prefix = cfg.get("redis_key_prefix", "rl")
        return f"{prefix}-wipe-lock"

    async def _acquire_wipe_lock(self) -> bool:
        """Atomically claim the right to perform the wipe.

        Uses ``SET key 1 NX EX <ttl>``: only one caller can succeed within
        the TTL window. The TTL bounds starvation if the lock-holder dies
        mid-wipe — the next disable cycle reclaims the lock.

        Any error (Redis unreachable, client construction fails) returns
        False so we err on "skip the wipe" rather than racing without
        protection.
        """
        cfg = self.config.config or {}
        if cfg.get("backend") != "redis":
            return False
        redis_url = cfg.get("redis_url")
        if not redis_url:
            return False
        try:
            import redis.asyncio as aioredis  # noqa: PLC0415
        except Exception:
            return False
        try:
            client = aioredis.from_url(redis_url, decode_responses=True)
        except Exception:
            return False
        try:
            try:
                acquired = await client.set(
                    self._wipe_lock_key(),
                    "1",
                    nx=True,
                    ex=_WIPE_LOCK_TTL_SECONDS,
                )
            except Exception:
                return False
        finally:
            try:
                await client.aclose()
            except Exception:
                pass
        return bool(acquired)

    async def _release_wipe_lock(self) -> None:
        """Drop the wipe lock so the next disable cycle is responsive.

        The TTL is the safety net; this is just an optimization to avoid
        waiting up to ``_WIPE_LOCK_TTL_SECONDS`` for the next legitimate
        wipe to proceed. Best-effort: any error is swallowed.
        """
        cfg = self.config.config or {}
        redis_url = cfg.get("redis_url")
        if not redis_url:
            return
        try:
            import redis.asyncio as aioredis  # noqa: PLC0415
        except Exception:
            return
        try:
            client = aioredis.from_url(redis_url, decode_responses=True)
        except Exception:
            return
        try:
            try:
                await client.delete(self._wipe_lock_key())
            except Exception:
                pass
        finally:
            try:
                await client.aclose()
            except Exception:
                pass

    async def _wipe_my_counters(self) -> None:
        """Delete every Redis key matching this plugin's configured prefix.

        Uses SCAN (non-blocking, cursor-paged) rather than KEYS so this is
        safe to run against production Redis with large keyspaces. Deletions
        are batched so each round-trip drops up to 500 keys at once — large
        enough to keep round-trip count low, small enough that a single
        UNLINK/DEL command never grows pathologically.

        Prefers UNLINK (Redis 4.0+) over DEL: UNLINK frees value memory on a
        background thread, so dropping a batch of sliding-window sorted
        sets does not stutter Redis' main-thread serving other clients.
        Falls back to DEL on Redis < 4.0 (rare in practice — ElastiCache,
        Redis Cloud, and every modern self-hosted deployment supports
        UNLINK).

        Idempotent under multi-worker races: when several workers all flip
        to disabled simultaneously, every worker calls this; UNLINK / DEL
        of an already-absent key is a no-op, so the duplicated work is
        harmless. (In practice the single-flight guard in shutdown() means
        only one worker reaches here per disable cycle.)
        """
        cfg = self.config.config or {}
        redis_url = cfg.get("redis_url")
        if not redis_url:
            return
        prefix = cfg.get("redis_key_prefix", "rl")
        pattern = f"{prefix}:*"
        try:
            import redis.asyncio as aioredis  # noqa: PLC0415
            from redis.exceptions import ResponseError  # noqa: PLC0415
        except Exception:
            return
        try:
            client = aioredis.from_url(redis_url)
        except Exception:
            return

        async def _drop(keys: list) -> int:
            """UNLINK with DEL fallback for pre-4.0 Redis."""
            try:
                return await client.unlink(*keys)
            except ResponseError:
                # ERR unknown command 'UNLINK' on Redis < 4.0 — fall back.
                return await client.delete(*keys)

        try:
            batch: list = []
            deleted = 0
            async for key in client.scan_iter(match=pattern, count=500):
                batch.append(key)
                if len(batch) >= 500:
                    deleted += await _drop(batch)
                    batch.clear()
            if batch:
                deleted += await _drop(batch)
            _logger.info(
                "rate limiter wipe-on-disable: deleted %d keys matching %s",
                deleted,
                pattern,
            )
        except Exception:
            _logger.exception(
                "rate limiter wipe-on-disable: scan/delete failed for pattern %s",
                pattern,
            )
        finally:
            try:
                await client.aclose()
            except Exception:
                pass

    async def prompt_pre_fetch(self, payload, context):
        # The Rust core handles fail_mode policy internally (open vs closed)
        # and logs backend errors via log_exception. The except here is a
        # final safety net for the unlikely case that a non-backend bug in
        # the core escapes as a Python exception.
        try:
            result = self._core.prompt_pre_fetch(payload, context)
            if hasattr(result, "__await__"):
                return await result
            return result
        except Exception:
            _logger.warning("rate limiter prompt_pre_fetch: unexpected core error; allowing request", exc_info=True)
            return PromptPrehookResult()

    async def tool_pre_invoke(self, payload, context):
        try:
            result = self._core.tool_pre_invoke(payload, context)
            if hasattr(result, "__await__"):
                return await result
            return result
        except Exception:
            _logger.warning("rate limiter tool_pre_invoke: unexpected core error; allowing request", exc_info=True)
            return ToolPreInvokeResult()


__all__ = ["RateLimiterConfig", "RateLimiterPlugin", "_parse_rate"]
