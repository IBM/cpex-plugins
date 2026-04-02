# -*- coding: utf-8 -*-
"""Thin compatibility shim for the Rust-owned rate limiter plugin."""

from __future__ import annotations

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
    )

    def __init__(self, **overrides) -> None:
        config = dict(_compat_default_config())
        config.update(overrides)
        for field in self.__slots__:
            setattr(self, field, config.get(field))


class RateLimiterPlugin(Plugin):
    """Gateway-facing Plugin subclass that delegates behavior to Rust."""

    def __init__(self, config) -> None:
        super().__init__(config)
        self._core = RateLimiterPluginCore(config.config or {})

    async def prompt_pre_fetch(self, payload, context):
        try:
            result = self._core.prompt_pre_fetch(payload, context)
            if hasattr(result, "__await__"):
                return await result
            return result
        except Exception:
            return PromptPrehookResult()

    async def tool_pre_invoke(self, payload, context):
        try:
            result = self._core.tool_pre_invoke(payload, context)
            if hasattr(result, "__await__"):
                return await result
            return result
        except Exception:
            return ToolPreInvokeResult()


__all__ = ["RateLimiterConfig", "RateLimiterPlugin", "_parse_rate"]
