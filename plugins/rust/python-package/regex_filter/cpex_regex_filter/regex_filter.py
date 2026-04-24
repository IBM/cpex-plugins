# -*- coding: utf-8 -*-
"""Thin compatibility shim for the Rust-owned regex filter plugin."""

from __future__ import annotations

try:
    from mcpgateway.plugins.framework import Plugin
except ModuleNotFoundError:
    class Plugin:  # type: ignore[no-redef]
        def __init__(self, config) -> None:
            self._config = config

from cpex_regex_filter.regex_filter_rust import RegexFilterPluginCore, SearchReplacePluginRust

_RUST_AVAILABLE = True


class SearchReplacePlugin(Plugin):
    """Gateway-facing Plugin subclass that delegates behavior to Rust."""

    def __init__(self, config) -> None:
        super().__init__(config)
        self._core = RegexFilterPluginCore(config.config or {})

    async def prompt_pre_fetch(self, payload, context):
        result = self._core.prompt_pre_fetch(payload, context)
        if hasattr(result, "__await__"):
            return await result
        return result

    async def prompt_post_fetch(self, payload, context):
        result = self._core.prompt_post_fetch(payload, context)
        if hasattr(result, "__await__"):
            return await result
        return result

    async def tool_pre_invoke(self, payload, context):
        result = self._core.tool_pre_invoke(payload, context)
        if hasattr(result, "__await__"):
            return await result
        return result

    async def tool_post_invoke(self, payload, context):
        result = self._core.tool_post_invoke(payload, context)
        if hasattr(result, "__await__"):
            return await result
        return result


__all__ = ["SearchReplacePlugin", "SearchReplacePluginRust", "_RUST_AVAILABLE"]
