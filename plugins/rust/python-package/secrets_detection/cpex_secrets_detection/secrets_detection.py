# -*- coding: utf-8 -*-
"""Thin compatibility shim for the Rust-owned secrets detection plugin."""

from __future__ import annotations

try:
    from mcpgateway.plugins.framework import Plugin
except ModuleNotFoundError:
    class Plugin:  # type: ignore[no-redef]
        def __init__(self, config) -> None:
            self._config = config

from cpex_secrets_detection.secrets_detection_rust import (
    SecretsDetectionPluginCore,
    py_scan_container,
)


class SecretsDetectionPlugin(Plugin):
    """Gateway-facing Plugin subclass that delegates behavior to Rust."""

    def __init__(self, config) -> None:
        super().__init__(config)
        self._core = SecretsDetectionPluginCore(config.config or {})

    async def prompt_pre_fetch(self, payload, context):
        return self._core.prompt_pre_fetch(payload, context)

    async def tool_post_invoke(self, payload, context):
        return self._core.tool_post_invoke(payload, context)

    async def resource_post_fetch(self, payload, context):
        return self._core.resource_post_fetch(payload, context)


__all__ = ["SecretsDetectionPlugin", "py_scan_container"]
