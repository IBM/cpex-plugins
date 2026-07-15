# -*- coding: utf-8 -*-
"""Thin compatibility shim for the URL reputation plugin package."""

from __future__ import annotations

import logging
import re
from types import SimpleNamespace
from typing import Any

from pydantic import BaseModel, Field, field_validator

from cpex.framework import Plugin, PluginViolation, ResourcePreFetchResult
from cpex.framework.extensions import Extensions
from cpex_url_reputation.url_reputation_rust import URLReputationPlugin as RustURLReputationPlugin

logger = logging.getLogger(__name__)

# Maps this plugin's static `PluginViolation.reason` strings (from the Rust
# engine's `validate_url`, and the Python-side wrapper below) to stable,
# non-identifying category slugs for the `reputation_categories` metric.
# These reason strings are hardcoded and never contain the checked URL or
# domain (that content lives only in `violation.details`, which is never
# read for metrics purposes), so slugifying `reason` is S1-safe.
_CATEGORY_BY_REASON: dict[str, str] = {
    "Could not parse url": "malformed_url",
    "Could not parse domain": "malformed_domain",
    "Blocked non secure http url": "insecure_scheme",
    "Domain in blocked set": "blocked_domain",
    "Blocked pattern": "blocked_pattern",
    "High entropy domain": "high_entropy_domain",
    "Illegal TLD": "illegal_tld",
    "Domain unicode is not secure": "unicode_spoofing",
    "Rust validation failure": "internal_error",
}


def _build_metrics(
    extensions: Extensions | None,
    continue_processing: bool,
    reason: str | None,
) -> dict[str, Any] | None:
    """Build the namespaced, allow-listed metrics dict for observability.

    Returns ``None`` when no trace context was supplied (gate: no
    ``extensions.request.trace_id`` means no metrics).

    ``resource_pre_fetch`` checks exactly one URL per call with no running
    counter — mirroring `rate_limiter`'s per-call ``allowed``/``throttled``
    semantics, ``total_checked`` is always ``1`` and ``total_blocked`` is a
    ``0``/``1`` outcome for *this* call, not a cumulative total (the gateway
    aggregates counts across spans/time). ``reputation_categories`` is empty
    when the URL was allowed, otherwise a single category slug — never raw
    URLs or domains (S1).
    """
    trace_id = extensions.request.trace_id if extensions and extensions.request else None
    if not trace_id:
        return None
    categories: list[str] = []
    if not continue_processing and reason:
        categories = [_CATEGORY_BY_REASON.get(reason, "other")]
    return {
        "total_checked": 1,
        "total_blocked": 0 if continue_processing else 1,
        "reputation_categories": categories,
    }


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

    async def resource_pre_fetch(
        self,
        payload,
        context,
        extensions: Extensions | None = None,
    ) -> ResourcePreFetchResult:
        try:
            result = self._core.validate_url(payload.uri)
            violation = result.violation
            metrics = _build_metrics(
                extensions,
                result.continue_processing,
                violation.reason if violation is not None else None,
            )
            metadata = {"url_reputation": metrics} if metrics is not None else {}

            if result.continue_processing:
                return ResourcePreFetchResult(continue_processing=True, metadata=metadata)
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
                metadata=metadata,
            )
        except Exception as exc:
            logger.warning("URL reputation validation failed; blocking for safety: %s", exc)
            reason = "Rust validation failure"
            metrics = _build_metrics(extensions, False, reason)
            metadata = {"url_reputation": metrics} if metrics is not None else {}
            return ResourcePreFetchResult(
                continue_processing=False,
                violation=PluginViolation(
                    reason=reason,
                    description=f"URL {payload.uri} blocked due to internal error",
                    code="URL_REPUTATION_BLOCK",
                    details={"url": payload.uri},
                ),
                metadata=metadata,
            )


__all__ = [
    "URLReputationConfig",
    "URLReputationPlugin",
]
