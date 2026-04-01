# -*- coding: utf-8 -*-
"""Rate Limiter Plugin.

Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Mihai Criveti

Provides a Rust-backed rate limiter plugin that supports multiple algorithms
and backends, including in-memory and Redis, for per-user, per-tenant, and/or
per-tool rate limiting. See the plugin documentation for configuration details.
"""

from cpex_rate_limiter.rate_limiter import RateLimiterPlugin

__all__ = ["RateLimiterPlugin"]
