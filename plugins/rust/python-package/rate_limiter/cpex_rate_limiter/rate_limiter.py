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
        """Lifecycle hook: release Rust-held resources (e.g. Redis connection).

        The plugin manager calls this on disable and on re-instantiation.
        Without it, the cached Redis connection leaks until the plugin
        instance is garbage-collected.
        """
        try:
            self._core.shutdown()
        except Exception:
            _logger.exception("rate limiter shutdown: core.shutdown() raised")

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
