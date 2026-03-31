"""Tests for RateLimiterConfig validation."""

import pytest

from cpex_rate_limiter.rate_limiter import RateLimiterConfig


class TestRateLimiterConfig:
    """Validate pydantic config model defaults and constraints."""

    def test_defaults(self):
        cfg = RateLimiterConfig()
        assert cfg.by_user is None
        assert cfg.by_tenant is None
        assert cfg.by_tool is None
        assert cfg.algorithm == "fixed_window"
        assert cfg.backend == "memory"
        assert cfg.redis_url is None
        assert cfg.redis_key_prefix == "rl"

    def test_all_fields_set(self):
        cfg = RateLimiterConfig(
            by_user="60/m",
            by_tenant="600/m",
            by_tool={"search": "10/s"},
            algorithm="sliding_window",
            backend="redis",
            redis_url="redis://localhost:6379/0",
            redis_key_prefix="test",
        )
        assert cfg.by_user == "60/m"
        assert cfg.by_tenant == "600/m"
        assert cfg.by_tool == {"search": "10/s"}
        assert cfg.algorithm == "sliding_window"
        assert cfg.backend == "redis"
        assert cfg.redis_url == "redis://localhost:6379/0"
        assert cfg.redis_key_prefix == "test"
