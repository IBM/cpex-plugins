# -*- coding: utf-8 -*-
"""Thin compatibility shim for the URL reputation plugin package."""

from __future__ import annotations

import logging
from typing import Any

from pydantic import BaseModel, Field, field_validator

try:
    from mcpgateway.plugins.framework import Plugin, PluginViolation, ResourcePreFetchResult
except ModuleNotFoundError:
    class Plugin:  # type: ignore[no-redef]
        def __init__(self, config) -> None:
            self.config = config

    class PluginViolation:  # type: ignore[no-redef]
        def __init__(
            self,
            reason: str = "",
            description: str = "",
            code: str = "",
            details: dict[str, Any] | None = None,
            http_status_code: int = 400,
            http_headers: dict[str, str] | None = None,
        ) -> None:
            self.reason = reason
            self.description = description
            self.code = code
            self.details = details
            self.http_status_code = http_status_code
            self.http_headers = http_headers

    class ResourcePreFetchResult:  # type: ignore[no-redef]
        def __init__(
            self,
            continue_processing: bool = True,
            violation: PluginViolation | None = None,
            metadata: dict[str, Any] | None = None,
            http_headers: dict[str, str] | None = None,
        ) -> None:
            self.continue_processing = continue_processing
            self.violation = violation
            self.metadata = metadata
            self.http_headers = http_headers

from cpex_url_reputation.url_reputation_rust import URLReputationEngine, URLReputationPluginCore

logger = logging.getLogger(__name__)


class URLReputationConfig(BaseModel):
    """Configuration for URL reputation checks."""

    whitelist_domains: set[str] = Field(default_factory=set)
    allowed_patterns: list[str] = Field(default_factory=list)
    blocked_domains: set[str] = Field(default_factory=set)
    blocked_patterns: list[str] = Field(default_factory=list)
    use_heuristic_check: bool = Field(default=False)
    entropy_threshold: float = Field(default=3.65)
    block_non_secure_http: bool = Field(default=True)

    @field_validator("whitelist_domains", "blocked_domains", mode="before")
    @classmethod
    def normalize_domains(cls, value: Any) -> set[str]:
        if not value:
            return set()
        return {str(domain).lower() for domain in value}


class URLReputationPlugin(Plugin):
    """Gateway-facing Plugin subclass that delegates behavior to the engine."""

    def __init__(self, config) -> None:
        super().__init__(config)
        self._cfg = URLReputationConfig(**(config.config or {}))
        self._core = URLReputationPluginCore(self._cfg.model_dump())

    async def resource_pre_fetch(self, payload, context):
        try:
            result = self._core.resource_pre_fetch(payload, context)
            if hasattr(result, "__await__"):
                return await result
            return result
        except Exception as exc:
            logger.warning("URL reputation validation failed; blocking for safety: %s", exc)
            return ResourcePreFetchResult(
                continue_processing=False,
                violation=PluginViolation(
                    reason="Rust validation failure",
                    description=f"URL {payload.uri} blocked due to internal error",
                    code="URL_REPUTATION_BLOCK",
                    details={"url": payload.uri},
                ),
            )


__all__ = [
    "URLReputationConfig",
    "URLReputationEngine",
    "URLReputationPlugin",
    "URLReputationPluginCore",
]
