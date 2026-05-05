# -*- coding: utf-8 -*-
"""Thin compatibility shim for the URL reputation plugin package."""

from __future__ import annotations

import logging
import re
from types import SimpleNamespace
from typing import Any

from pydantic import BaseModel, Field, field_validator

from cpex.framework import Plugin, PluginViolation, ResourcePreFetchResult
from cpex_url_reputation.url_reputation_rust import URLReputationPlugin as RustURLReputationPlugin

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

    @field_validator("allowed_patterns", "blocked_patterns")
    @classmethod
    def validate_patterns(cls, value: list[str]) -> list[str]:
        for pattern in value:
            try:
                re.compile(str(pattern))
            except re.error as exc:
                raise ValueError(f"Pattern compilation failed for {pattern!r}") from exc
        return value


class URLReputationPlugin(Plugin):
    """Gateway-facing Plugin subclass that delegates behavior to the Rust engine."""

    def __init__(self, config) -> None:
        super().__init__(config)
        self._cfg = URLReputationConfig(**(config.config or {}))
        self._core = RustURLReputationPlugin(SimpleNamespace(**self._cfg.model_dump()))

    async def resource_pre_fetch(self, payload, context):
        try:
            result = self._core.validate_url(payload.uri)
            if result.continue_processing:
                return ResourcePreFetchResult(continue_processing=True)
            violation = result.violation
            return ResourcePreFetchResult(
                continue_processing=False,
                violation=PluginViolation(
                    reason=violation.reason,
                    description=violation.description,
                    code=violation.code,
                    details=violation.details,
                )
                if violation is not None
                else None,
            )
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
    "URLReputationPlugin",
]
