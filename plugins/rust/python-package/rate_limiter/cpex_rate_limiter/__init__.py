# -*- coding: utf-8 -*-
"""Rate Limiter Plugin.

Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Mihai Criveti

Provides a Rust-backed rate limiter plugin that supports multiple algorithms
and backends, including in-memory and Redis, for per-user, per-tenant, and/or
per-tool rate limiting. See the plugin documentation for configuration details.
"""

from __future__ import annotations


def __getattr__(name: str):
    if name in {"RateLimiterConfig", "RateLimiterPlugin", "_parse_rate"}:
        from cpex_rate_limiter.rate_limiter import (
            RateLimiterConfig,
            RateLimiterPlugin,
            _parse_rate,
        )

        exports = {
            "RateLimiterConfig": RateLimiterConfig,
            "RateLimiterPlugin": RateLimiterPlugin,
            "_parse_rate": _parse_rate,
        }
        return exports[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

__all__ = ["RateLimiterConfig", "RateLimiterPlugin", "_parse_rate"]
