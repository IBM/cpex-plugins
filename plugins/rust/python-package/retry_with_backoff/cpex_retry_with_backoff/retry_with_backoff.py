# -*- coding: utf-8 -*-
"""Gateway-facing retry-with-backoff plugin - pure Rust delegation."""

from __future__ import annotations

import logging

try:
    from mcpgateway.plugins.framework import (
        Plugin,
        PluginConfig,
        PluginContext,
        ResourcePostFetchPayload,
        ResourcePostFetchResult,
        ToolPostInvokePayload,
        ToolPostInvokeResult,
    )
except ModuleNotFoundError:
    # Fallback for testing without mcpgateway
    class Plugin:  # type: ignore[no-redef]
        def __init__(self, config) -> None:
            self.config = config
    
    class PluginConfig:  # type: ignore[no-redef]
        def __init__(self, **kwargs) -> None:
            for k, v in kwargs.items():
                setattr(self, k, v)
    
    PluginContext = object  # type: ignore[misc,assignment]
    ToolPostInvokePayload = object  # type: ignore[misc,assignment]
    ToolPostInvokeResult = object  # type: ignore[misc,assignment]
    ResourcePostFetchPayload = object  # type: ignore[misc,assignment]
    ResourcePostFetchResult = object  # type: ignore[misc,assignment]

from cpex_retry_with_backoff.retry_with_backoff_rust import RetryWithBackoffPluginCore

log = logging.getLogger(__name__)


class RetryWithBackoffPlugin(Plugin):
    """Gateway-facing Plugin that delegates all behavior to Rust core."""

    def __init__(self, config: PluginConfig) -> None:
        super().__init__(config)
        self._core = RetryWithBackoffPluginCore(config.config or {})
        log.info("retry_with_backoff: Initialized with Rust core (v0.3.0)")

    async def tool_post_invoke(
        self,
        payload: ToolPostInvokePayload,
        context: PluginContext,
    ) -> ToolPostInvokeResult:
        """Delegate to Rust core for tool post-invoke processing."""
        return self._core.tool_post_invoke(payload, context)

    async def resource_post_fetch(
        self,
        payload: ResourcePostFetchPayload,
        context: PluginContext,
    ) -> ResourcePostFetchResult:
        """Delegate to Rust core for resource post-fetch processing."""
        return self._core.resource_post_fetch(payload, context)


__all__ = ["RetryWithBackoffPlugin"]