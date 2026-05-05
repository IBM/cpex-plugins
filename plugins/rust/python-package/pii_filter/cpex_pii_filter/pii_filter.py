# -*- coding: utf-8 -*-
"""Thin compatibility shim for the Rust-owned PII filter plugin."""

from __future__ import annotations

from cpex.framework import Plugin
from cpex_pii_filter.pii_filter_rust import PIIDetectorRust, PIIFilterPluginCore


class PIIFilterPlugin(Plugin):
    """Gateway-facing Plugin subclass that delegates behavior to Rust."""

    def __init__(self, config) -> None:
        super().__init__(config)
        self._core = PIIFilterPluginCore(config.config or {})

    async def prompt_pre_fetch(self, payload, context):
        return self._core.prompt_pre_fetch(payload, context)

    async def prompt_post_fetch(self, payload, context):
        return self._core.prompt_post_fetch(payload, context)

    async def tool_pre_invoke(self, payload, context):
        return self._core.tool_pre_invoke(payload, context)

    async def tool_post_invoke(self, payload, context):
        return self._core.tool_post_invoke(payload, context)


__all__ = ["PIIDetectorRust", "PIIFilterPlugin"]
