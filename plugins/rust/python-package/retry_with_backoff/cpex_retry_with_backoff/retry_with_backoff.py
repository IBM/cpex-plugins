# -*- coding: utf-8 -*-
"""Gateway-facing retry-with-backoff plugin shim."""

from __future__ import annotations

import json
import logging
import math
import random
import time
from dataclasses import dataclass
from typing import Any, Optional

from pydantic import BaseModel, Field

from cpex.framework.settings import get_settings
from cpex.framework import (
    Plugin,
    PluginConfig,
    PluginContext,
    ResourcePostFetchPayload,
    ResourcePostFetchResult,
    ToolPostInvokePayload,
    ToolPostInvokeResult,
)

from cpex_retry_with_backoff.retry_with_backoff_rust import RetryStateManager

log = logging.getLogger(__name__)


@dataclass
class _ToolRetryState:
    consecutive_failures: int = 0
    last_failure_at: float = 0.0


_STATE: dict[str, _ToolRetryState] = {}
_STATE_TTL_SECONDS: float = 300.0


def _evict_stale_entries() -> None:
    cutoff = time.monotonic() - _STATE_TTL_SECONDS
    stale = [k for k, v in _STATE.items() if v.last_failure_at > 0 and v.last_failure_at < cutoff]
    for key in stale:
        del _STATE[key]


def _get_state(tool: str, request_id: str) -> _ToolRetryState:
    _evict_stale_entries()
    key = f"{tool}:{request_id}"
    if key not in _STATE:
        _STATE[key] = _ToolRetryState()
    return _STATE[key]


def _del_state(tool: str, request_id: str) -> None:
    _STATE.pop(f"{tool}:{request_id}", None)


class RetryConfig(BaseModel):
    max_retries: int = Field(default=2, ge=0)
    backoff_base_ms: int = Field(default=200, ge=1)
    max_backoff_ms: int = Field(default=5000, ge=1)
    retry_on_status: list[int] = Field(default_factory=lambda: [429, 500, 502, 503, 504])
    jitter: bool = Field(default=True)
    check_text_content: bool = Field(default=False)
    tool_overrides: dict[str, dict[str, Any]] = Field(default_factory=dict)


def _cfg_for(cfg: RetryConfig, tool: str) -> RetryConfig:
    overrides = cfg.tool_overrides.get(tool)
    if not overrides:
        return cfg
    merged = cfg.model_dump()
    merged.update(overrides)
    merged.pop("tool_overrides", None)
    return RetryConfig(**merged)


def _compute_delay_ms(attempt: int, cfg: RetryConfig) -> int:
    ceiling = min(cfg.max_backoff_ms, cfg.backoff_base_ms * (2**attempt))
    if cfg.jitter:
        return math.ceil(random.uniform(0, ceiling))
    return ceiling


def _is_failure(result: Any, cfg: RetryConfig) -> bool:
    if not isinstance(result, dict):
        return False

    if result.get("isError") is True:
        structured = result.get("structuredContent")
        if isinstance(structured, dict):
            status = structured.get("status_code")
            if isinstance(status, int):
                return status in cfg.retry_on_status
        return True

    structured = result.get("structuredContent")
    if isinstance(structured, dict):
        if structured.get("isError") is True:
            return True
        status = structured.get("status_code")
        if isinstance(status, int) and status in cfg.retry_on_status:
            return True

    if cfg.check_text_content and structured is None:
        for item in result.get("content", []):
            if not isinstance(item, dict) or item.get("type") != "text":
                continue
            try:
                parsed = json.loads(item["text"])
            except (json.JSONDecodeError, KeyError, TypeError):
                continue
            if not isinstance(parsed, dict):
                continue
            if parsed.get("isError") is True:
                return True
            status = parsed.get("status_code")
            if isinstance(status, int) and status in cfg.retry_on_status:
                return True

    return False


class RetryWithBackoffPlugin(Plugin):
    def __init__(self, config: PluginConfig) -> None:
        super().__init__(config)
        raw_cfg = RetryConfig(**(config.config or {}))

        ceiling = getattr(get_settings(), "max_tool_retries", raw_cfg.max_retries)
        if raw_cfg.max_retries > ceiling:
            log.warning(
                "retry_with_backoff: max_retries=%d exceeds gateway ceiling=%d, clamping",
                raw_cfg.max_retries,
                ceiling,
            )
            raw_cfg = raw_cfg.model_copy(update={"max_retries": ceiling})

        for tool_name, overrides in raw_cfg.tool_overrides.items():
            if overrides.get("max_retries", 0) > ceiling:
                log.warning(
                    "retry_with_backoff: tool_overrides[%s].max_retries=%d exceeds ceiling=%d, clamping",
                    tool_name,
                    overrides["max_retries"],
                    ceiling,
                )
                overrides["max_retries"] = ceiling

        self._cfg = raw_cfg
        self._rust = RetryStateManager(
            self._cfg.max_retries,
            self._cfg.backoff_base_ms,
            self._cfg.max_backoff_ms,
            self._cfg.jitter,
            self._cfg.retry_on_status,
        )
        self._rust_overrides = {
            tool_name: RetryStateManager(
                overrides.get("max_retries", self._cfg.max_retries),
                overrides.get("backoff_base_ms", self._cfg.backoff_base_ms),
                overrides.get("max_backoff_ms", self._cfg.max_backoff_ms),
                overrides.get("jitter", self._cfg.jitter),
                overrides.get("retry_on_status", self._cfg.retry_on_status),
            )
            for tool_name, overrides in self._cfg.tool_overrides.items()
        }

    def to_rust_native_policy(self, tool_name: str, ceiling: int) -> Optional[dict[str, Any]]:
        raw_cfg = RetryConfig(**(self.config.config or {}))
        cfg = _cfg_for(raw_cfg, tool_name)
        if cfg.max_retries > ceiling:
            cfg = cfg.model_copy(update={"max_retries": ceiling})

        if cfg.check_text_content:
            return None

        return {
            "kind": "retry_with_backoff",
            "maxRetries": int(cfg.max_retries),
            "backoffBaseMs": int(cfg.backoff_base_ms),
            "maxBackoffMs": int(cfg.max_backoff_ms),
            "retryOnStatus": list(cfg.retry_on_status),
            "jitter": bool(cfg.jitter),
        }

    async def tool_post_invoke(
        self,
        payload: ToolPostInvokePayload,
        context: PluginContext,
    ) -> ToolPostInvokeResult:
        tool = payload.name
        cfg = _cfg_for(self._cfg, tool)
        request_id = context.global_context.request_id
        result = payload.result

        retry_policy_meta = {
            "retry_policy": {
                "max_retries": cfg.max_retries,
                "backoff_base_ms": cfg.backoff_base_ms,
                "max_backoff_ms": cfg.max_backoff_ms,
                "retry_on_status": cfg.retry_on_status,
            }
        }

        if not cfg.check_text_content:
            is_error = isinstance(result, dict) and result.get("isError") is True
            status_code: int | None = None
            if isinstance(result, dict):
                structured = result.get("structuredContent")
                if isinstance(structured, dict):
                    if structured.get("isError") is True:
                        is_error = True
                    status = structured.get("status_code")
                    if isinstance(status, int):
                        status_code = status
            rust_inst = self._rust_overrides.get(tool, self._rust)
            should_retry, delay_ms = rust_inst.check_and_update(
                tool,
                request_id,
                is_error,
                status_code,
            )
            return ToolPostInvokeResult(
                retry_delay_ms=delay_ms if should_retry else 0,
                metadata=retry_policy_meta,
            )

        state = _get_state(tool, request_id)
        if _is_failure(result, cfg):
            state.consecutive_failures += 1
            state.last_failure_at = time.monotonic()
            if state.consecutive_failures <= cfg.max_retries:
                return ToolPostInvokeResult(
                    retry_delay_ms=_compute_delay_ms(state.consecutive_failures - 1, cfg),
                    metadata=retry_policy_meta,
                )
            _del_state(tool, request_id)
            return ToolPostInvokeResult(retry_delay_ms=0, metadata=retry_policy_meta)

        _del_state(tool, request_id)
        return ToolPostInvokeResult(retry_delay_ms=0, metadata=retry_policy_meta)

    async def resource_post_fetch(
        self,
        payload: ResourcePostFetchPayload,
        context: PluginContext,
    ) -> ResourcePostFetchResult:
        del payload, context
        return ResourcePostFetchResult(
            metadata={
                "retry_policy": {
                    "max_retries": self._cfg.max_retries,
                    "backoff_base_ms": self._cfg.backoff_base_ms,
                    "max_backoff_ms": self._cfg.max_backoff_ms,
                    "retry_on_status": self._cfg.retry_on_status,
                }
            }
        )


__all__ = [
    "RetryConfig",
    "RetryWithBackoffPlugin",
    "RetryStateManager",
    "_STATE",
    "_STATE_TTL_SECONDS",
    "_ToolRetryState",
    "_cfg_for",
    "_compute_delay_ms",
    "_del_state",
    "_get_state",
    "_is_failure",
]
