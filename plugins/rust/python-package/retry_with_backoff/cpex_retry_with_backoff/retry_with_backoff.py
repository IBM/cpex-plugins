# -*- coding: utf-8 -*-
"""Gateway-facing retry-with-backoff plugin - pure Rust delegation."""

from __future__ import annotations

import logging

from cpex.framework import (
    Plugin,
    PluginConfig,
    PluginContext,
    ResourcePostFetchPayload,
    ResourcePostFetchResult,
    ToolPostInvokePayload,
    ToolPostInvokeResult,
)
from cpex.framework.settings import get_settings

from cpex_retry_with_backoff.retry_with_backoff_rust import RetryWithBackoffPluginCore

log = logging.getLogger(__name__)


class RetryWithBackoffPlugin(Plugin):
    """Gateway-facing Plugin that delegates all behavior to Rust core."""

    def __init__(self, config: PluginConfig) -> None:
        super().__init__(config)
        raw_cfg: dict = dict(config.config or {})

        # Enforce the gateway-level ceiling on max_retries so that no plugin
        # config (global or per-tool override) can exceed the operator limit.
        ceiling = getattr(get_settings(), "max_tool_retries", None)
        if ceiling is not None:
            if raw_cfg.get("max_retries", 0) > ceiling:
                log.warning(
                    "retry_with_backoff: max_retries=%d exceeds gateway ceiling=%d, clamping",
                    raw_cfg["max_retries"],
                    ceiling,
                )
                raw_cfg["max_retries"] = ceiling
            for tool_name, override in raw_cfg.get("tool_overrides", {}).items():
                if override.get("max_retries", 0) > ceiling:
                    log.warning(
                        "retry_with_backoff: tool_overrides[%s].max_retries=%d exceeds ceiling=%d, clamping",
                        tool_name,
                        override["max_retries"],
                        ceiling,
                    )
                    override["max_retries"] = ceiling

        self._core = RetryWithBackoffPluginCore(raw_cfg)
        log.info("retry_with_backoff: Initialized with Rust core (v0.3.7)")

    async def tool_post_invoke(
        self,
        payload: ToolPostInvokePayload,
        context: PluginContext,
        extensions=None,
    ) -> ToolPostInvokeResult:
        """Delegate to Rust core for tool post-invoke processing."""
        return self._core.tool_post_invoke(payload, context, extensions)

    async def resource_post_fetch(
        self,
        payload: ResourcePostFetchPayload,
        context: PluginContext,
    ) -> ResourcePostFetchResult:
        """Delegate to Rust core for resource post-fetch processing."""
        return self._core.resource_post_fetch(payload, context)


__all__ = ["RetryWithBackoffPlugin"]