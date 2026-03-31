# -*- coding: utf-8 -*-
"""Location: ./plugins/rate_limiter/rate_limiter.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Mihai Criveti

Rate Limiter Plugin — Rust-backed execution engine.
Enforces rate limits by user, tenant, and/or tool using a pluggable algorithm:
  - fixed_window  : simple counter per time bucket (default)
  - sliding_window: rolling timestamp log, prevents burst at window boundary
  - token_bucket  : token refill model, allows short controlled bursts

All rate evaluation is performed by the Rust engine via PyO3 bindings.
The engine supports both memory and Redis backends.

Security contract — fail-open on error:
  Both hook methods (prompt_pre_fetch, tool_pre_invoke) catch all unexpected
  exceptions and allow the request through.  This is a deliberate design
  choice: an internal engine failure (Rust panic, Redis timeout, config bug)
  must never block legitimate traffic.  The trade-off is that a sustained
  engine failure silently disables rate limiting until the error is resolved.
  Operators should monitor for rate-limiter error logs and treat them as
  high-priority alerts.
"""

# Future
from __future__ import annotations

# Standard
import logging
import time
from typing import Any, Dict, Optional, Tuple

# Third-Party
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Rust engine (required)
# ---------------------------------------------------------------------------

try:
    # Third-Party
    from cpex_rate_limiter.rate_limiter_rust import RateLimiterEngine as _RateLimiterEngine

    _RUST_AVAILABLE = True
except ImportError:
    _RateLimiterEngine = None  # type: ignore[assignment,misc]
    _RUST_AVAILABLE = False


class RustRateLimiterEngine:
    """Thin wrapper so tests can mock PyO3 methods (read-only on C extensions)."""

    def __init__(self, config: dict) -> None:
        """Initialise the Rust engine with the given config dict.

        Args:
            config: Engine configuration dictionary with keys ``by_user``,
                ``by_tenant``, ``by_tool``, ``algorithm``, ``backend``, and
                optionally ``redis_url`` / ``redis_key_prefix``.
        """
        self._engine = _RateLimiterEngine(config)

    def check(self, user: str, tenant: Optional[str], tool: str, now_unix: int, include_retry_after: bool) -> Tuple[bool, dict, dict]:
        """Evaluate rate limits for a request (synchronous, memory backend).

        Args:
            user: Normalised user identity string.
            tenant: Tenant identifier, or None to skip by_tenant checks.
            tool: Tool or prompt name (lowercased) for by_tool lookup.
            now_unix: Current Unix timestamp in whole seconds.
            include_retry_after: Whether to include Retry-After in response headers.

        Returns:
            Tuple of (allowed, headers_dict, meta_dict).
        """
        return self._engine.check(user, tenant, tool, now_unix, include_retry_after)

    async def check_async(self, user: str, tenant: Optional[str], tool: str, now_unix: int, include_retry_after: bool) -> Tuple[bool, dict, dict]:
        """Evaluate rate limits for a request (async, Redis backend).

        Args:
            user: Normalised user identity string.
            tenant: Tenant identifier, or None to skip by_tenant checks.
            tool: Tool or prompt name (lowercased) for by_tool lookup.
            now_unix: Current Unix timestamp in whole seconds.
            include_retry_after: Whether to include Retry-After in response headers.

        Returns:
            Tuple of (allowed, headers_dict, meta_dict).
        """
        return await self._engine.check_async(user, tenant, tool, now_unix, include_retry_after)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ALGORITHM_FIXED_WINDOW = "fixed_window"
ALGORITHM_SLIDING_WINDOW = "sliding_window"
ALGORITHM_TOKEN_BUCKET = "token_bucket"  # nosec B105 - algorithm name, not a password
VALID_ALGORITHMS = (ALGORITHM_FIXED_WINDOW, ALGORITHM_SLIDING_WINDOW, ALGORITHM_TOKEN_BUCKET)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse_rate(rate: str) -> tuple[int, int]:
    """Parse rate like '60/m', '10/s', '100/h' -> (count, window_seconds).

    Args:
        rate: Rate string in format 'count/unit' (e.g., '60/m', '10/s', '100/h').

    Returns:
        Tuple of (count, window_seconds) for the rate limit.

    Raises:
        ValueError: If the rate string is malformed or the unit is not supported.
    """
    try:
        count_str, per = rate.split("/", maxsplit=1)
        count = int(count_str)
    except (ValueError, AttributeError):
        raise ValueError(f"Invalid rate string {rate!r}: expected '<count>/<unit>' e.g. '60/m'")
    if count <= 0:
        raise ValueError(f"Invalid rate string {rate!r}: count must be > 0, got {count}")
    per = per.strip().lower()
    if per in ("s", "sec", "second"):
        return count, 1
    if per in ("m", "min", "minute"):
        return count, 60
    if per in ("h", "hr", "hour"):
        return count, 3600
    raise ValueError(f"Invalid rate string {rate!r}: unsupported unit {per!r}, expected s/m/h")


def _extract_user_identity(user: Any) -> str:
    """Return a stable, normalised string identity from a user context value.

    Handles three cases:
    - dict (production JWT context): extract ``email`` → ``id`` → ``sub`` fallback
    - string: strip whitespace; empty/whitespace-only falls back to 'anonymous'
    - None / falsy: 'anonymous'

    Args:
        user: User identity from ``context.global_context.user`` — may be a dict
            with ``email``/``id``/``sub`` keys, a plain string, or ``None``.

    Returns:
        Normalised non-empty identity string, or ``'anonymous'`` as fallback.
    """
    if isinstance(user, dict):
        identity = user.get("email") or user.get("id") or user.get("sub") or ""
        identity = str(identity).strip()
    elif user is None:
        identity = ""
    else:
        identity = str(user).strip()
    return identity if identity else "anonymous"


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


class RateLimiterConfig(BaseModel):
    """Configuration for the rate limiter plugin.

    Attributes:
        by_user: Rate limit per user (e.g., '60/m').
        by_tenant: Rate limit per tenant (e.g., '600/m').
        by_tool: Per-tool rate limits (e.g., {'search': '10/m'}).
        algorithm: Counting algorithm — 'fixed_window', 'sliding_window', or 'token_bucket'.
        backend: Storage backend — 'memory' (default) or 'redis'.
        redis_url: Redis connection URL, required when backend='redis'.
        redis_key_prefix: Prefix for all Redis keys (default 'rl').
    """

    by_user: Optional[str] = Field(default=None, description="e.g. '60/m'")
    by_tenant: Optional[str] = Field(default=None, description="e.g. '600/m'. Skipped for API-token requests (no team association).")
    by_tool: Optional[Dict[str, str]] = Field(default=None, description="per-tool rates, e.g. {'search': '10/m'}")
    algorithm: str = Field(default=ALGORITHM_FIXED_WINDOW, description="'fixed_window', 'sliding_window', or 'token_bucket'")
    backend: str = Field(default="memory", description="'memory' or 'redis'")
    redis_url: Optional[str] = Field(default=None, description="Redis URL, e.g. 'redis://localhost:6379/0'")
    redis_key_prefix: str = Field(default="rl", description="Prefix for Redis keys")


# ---------------------------------------------------------------------------
# Plugin
# ---------------------------------------------------------------------------


# mcpgateway is not declared as a dependency — it is provided by the
# host gateway process that loads this plugin at runtime.
from mcpgateway.plugins.framework import (  # noqa: E402
    Plugin,
    PluginConfig,
    PluginContext,
    PluginViolation,
    PromptPrehookPayload,
    PromptPrehookResult,
    ToolPreInvokePayload,
    ToolPreInvokeResult,
)


class RateLimiterPlugin(Plugin):
    """Rate limiter with pluggable algorithm — delegates to Rust engine."""

    def __init__(self, config: PluginConfig) -> None:
        """Initialise the plugin, validate config, and construct the Rust engine.

        Args:
            config: Plugin configuration including algorithm, backend, and rate strings.

        Raises:
            ImportError: If the ``rate_limiter_rust`` PyO3 extension is not installed.
        """
        if not _RUST_AVAILABLE:
            raise ImportError(
                "The rate_limiter_rust extension is required. "
                "Build it with: make install"
            )
        super().__init__(config)
        self._cfg = RateLimiterConfig(**(config.config or {}))
        self._validate_config()

        rust_config: dict[str, Any] = {
            "by_user": self._cfg.by_user,
            "by_tenant": self._cfg.by_tenant,
            "by_tool": self._cfg.by_tool or {},
            "algorithm": self._cfg.algorithm,
            "backend": self._cfg.backend,
        }
        if self._cfg.backend == "redis":
            rust_config["redis_url"] = self._cfg.redis_url
            rust_config["redis_key_prefix"] = self._cfg.redis_key_prefix
        self._engine = RustRateLimiterEngine(rust_config)
        self._use_async = self._cfg.backend == "redis"

    def _validate_config(self) -> None:
        """Validate rate strings and algorithm/backend settings; raise ValueError on error.

        Raises:
            ValueError: If any rate string is malformed, the algorithm is unknown,
                or the backend is not ``'memory'`` or ``'redis'``.
        """
        errors: list[str] = []

        if self._cfg.algorithm not in VALID_ALGORITHMS:
            errors.append(f"algorithm={self._cfg.algorithm!r}: must be one of {VALID_ALGORITHMS}")

        if self._cfg.backend not in ("memory", "redis"):
            errors.append(f"backend={self._cfg.backend!r}: must be 'memory' or 'redis'")

        if self._cfg.backend == "redis" and not self._cfg.redis_url:
            errors.append("redis_url is required when backend='redis'")

        for field_name, value in [("by_user", self._cfg.by_user), ("by_tenant", self._cfg.by_tenant)]:
            if value is not None:
                try:
                    _parse_rate(value)
                except ValueError as exc:
                    errors.append(f"{field_name}={value!r}: {exc}")

        if self._cfg.by_tool:
            for tool_name, rate in self._cfg.by_tool.items():
                try:
                    _parse_rate(rate)
                except ValueError as exc:
                    errors.append(f"by_tool[{tool_name!r}]={rate!r}: {exc}")

        if errors:
            raise ValueError("RateLimiterPlugin config errors: " + "; ".join(errors))

    async def _evaluate(self, tool_or_prompt: str, user: str, tenant: Optional[str]) -> Tuple[bool, dict, dict]:
        """Run the Rust engine and return (allowed, headers_dict, meta_dict).

        Args:
            tool_or_prompt: Lowercased tool or prompt name for ``by_tool`` lookup.
            user: Normalised user identity string.
            tenant: Tenant identifier, or ``None`` to skip ``by_tenant`` checks.

        Returns:
            Tuple of ``(allowed, headers_dict, meta_dict)``.
        """
        now_unix = int(time.time())
        if self._use_async:
            return await self._engine.check_async(user, tenant, tool_or_prompt, now_unix, True)
        return self._engine.check(user, tenant, tool_or_prompt, now_unix, True)

    async def prompt_pre_fetch(self, payload: PromptPrehookPayload, context: PluginContext) -> PromptPrehookResult:
        """Enforce rate limits before a prompt is fetched.

        Args:
            payload: Prompt hook payload containing the ``prompt_id``.
            context: Plugin context with ``global_context.user`` and ``tenant_id``.

        Returns:
            Hook result — pass-through on success, violation with HTTP 429 on limit breach.
        """
        try:
            prompt = payload.prompt_id.strip().lower()
            user = _extract_user_identity(context.global_context.user)
            tenant = str(context.global_context.tenant_id).strip() if context.global_context.tenant_id else None

            allowed, headers, meta = await self._evaluate(prompt, user, tenant)

            if meta.get("limited") is False:
                return PromptPrehookResult(metadata=meta)
            if not allowed:
                return PromptPrehookResult(
                    continue_processing=False,
                    violation=PluginViolation(
                        reason="Rate limit exceeded",
                        description="Rate limit exceeded",
                        code="RATE_LIMIT",
                        details=meta,
                        http_status_code=429,
                        http_headers=headers,
                    ),
                )
            headers.pop("Retry-After", None)
            return PromptPrehookResult(metadata=meta, http_headers=headers)
        except Exception:
            logger.exception("RateLimiterPlugin.prompt_pre_fetch error; allowing request")
            return PromptPrehookResult()

    async def tool_pre_invoke(self, payload: ToolPreInvokePayload, context: PluginContext) -> ToolPreInvokeResult:
        """Enforce rate limits before a tool is invoked.

        Args:
            payload: Tool hook payload containing the tool ``name``.
            context: Plugin context with ``global_context.user`` and ``tenant_id``.

        Returns:
            Hook result — pass-through on success, violation with HTTP 429 on limit breach.
        """
        try:
            tool = payload.name.strip().lower()
            user = _extract_user_identity(context.global_context.user)
            tenant = str(context.global_context.tenant_id).strip() if context.global_context.tenant_id else None

            allowed, headers, meta = await self._evaluate(tool, user, tenant)

            if meta.get("limited") is False:
                return ToolPreInvokeResult(metadata=meta)
            if not allowed:
                return ToolPreInvokeResult(
                    continue_processing=False,
                    violation=PluginViolation(
                        reason="Rate limit exceeded",
                        description="Rate limit exceeded",
                        code="RATE_LIMIT",
                        details=meta,
                        http_status_code=429,
                        http_headers=headers,
                    ),
                )
            headers.pop("Retry-After", None)
            return ToolPreInvokeResult(metadata=meta, http_headers=headers)
        except Exception:
            logger.exception("RateLimiterPlugin.tool_pre_invoke error; allowing request")
            return ToolPreInvokeResult()
