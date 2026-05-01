"""Public-surface config validation tests for the Rust-backed plugin."""

import subprocess
import sys

import pytest

from mcpgateway.plugins.framework import PluginConfig

from cpex_rate_limiter import RateLimiterConfig as PackageRateLimiterConfig
from cpex_rate_limiter import RateLimiterPlugin as PackageRateLimiterPlugin
from cpex_rate_limiter import _parse_rate as package_parse_rate
from cpex_rate_limiter.rate_limiter import RateLimiterConfig, RateLimiterPlugin


def _config(**overrides) -> PluginConfig:
    config = {
        "algorithm": "fixed_window",
        "backend": "memory",
    }
    config.update(overrides)
    return PluginConfig(name="rate_limiter", config=config)


class TestRateLimiterPluginConfig:
    """Validate defaults and config enforcement through the plugin constructor."""

    def test_module_level_config_defaults_remain_importable(self):
        config = RateLimiterConfig()
        assert config.by_user is None
        assert config.by_tenant is None
        assert config.by_tool is None
        assert config.algorithm == "fixed_window"
        assert config.backend == "memory"
        assert config.redis_url is None
        assert config.redis_key_prefix == "rl"

    def test_top_level_package_reexports_public_compatibility_names(self):
        config = PackageRateLimiterConfig()
        assert PackageRateLimiterPlugin is RateLimiterPlugin
        assert config.algorithm == "fixed_window"
        assert package_parse_rate("60/sec") == (60, 1)

    def test_top_level_package_imports_cleanly_in_subprocess(self):
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                (
                    "from cpex_rate_limiter import RateLimiterConfig, RateLimiterPlugin, _parse_rate; "
                    "config = RateLimiterConfig(); "
                    "assert config.algorithm == 'fixed_window'; "
                    "assert _parse_rate('60/sec') == (60, 1); "
                    "print(RateLimiterPlugin.__name__)"
                ),
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == "RateLimiterPlugin"

    def test_defaults_construct_successfully(self):
        plugin = RateLimiterPlugin(_config())
        assert plugin is not None

    def test_all_fields_construct_successfully(self):
        plugin = RateLimiterPlugin(_config(
            by_user="60/m",
            by_tenant="600/m",
            by_tool={"search": "10/s"},
            algorithm="sliding_window",
            backend="memory",
            redis_key_prefix="test",
        ))
        assert plugin is not None

    def test_invalid_algorithm_rejected(self):
        with pytest.raises(ValueError, match="algorithm"):
            RateLimiterPlugin(_config(algorithm="bogus"))

    def test_invalid_backend_rejected(self):
        with pytest.raises(ValueError, match="backend"):
            RateLimiterPlugin(_config(backend="memcached"))

    def test_invalid_by_user_rate_rejected(self):
        with pytest.raises(ValueError, match="by_user"):
            RateLimiterPlugin(_config(by_user="not-a-rate"))

    def test_invalid_by_tenant_rate_rejected(self):
        with pytest.raises(ValueError, match="by_tenant"):
            RateLimiterPlugin(_config(by_tenant="bad"))

    def test_invalid_by_tool_rate_rejected(self):
        with pytest.raises(ValueError, match="by_tool"):
            RateLimiterPlugin(_config(by_tool={"search": "bad"}))

    def test_redis_requires_url(self):
        with pytest.raises(ValueError, match="redis_url"):
            RateLimiterPlugin(_config(backend="redis"))

    def test_redis_with_url_constructs_successfully(self):
        plugin = RateLimiterPlugin(_config(
            backend="redis",
            redis_url="redis://localhost:6379/0",
        ))
        assert plugin is not None


class TestFailModePublicSurface:
    """fail_mode must be reachable through the advertised Python compat API.

    G6 of the review feedback: the Rust core supports fail_mode, but the
    public compat layer was dropping it, so callers following the
    RateLimiterConfig helper pattern couldn't actually enable fail-closed
    behaviour.
    """

    def test_compat_default_config_includes_fail_mode(self):
        """compat_default_config() must list fail_mode among its keys."""
        from cpex_rate_limiter.rate_limiter_rust import compat_default_config  # noqa: PLC0415

        defaults = compat_default_config()
        assert "fail_mode" in defaults, (
            f"compat_default_config() must include 'fail_mode'; got keys={sorted(defaults.keys())}"
        )

    def test_rate_limiter_config_preserves_fail_mode(self):
        """RateLimiterConfig(fail_mode=...) must round-trip through the __slots__."""
        cfg = RateLimiterConfig(fail_mode="closed")
        assert getattr(cfg, "fail_mode", None) == "closed", (
            "RateLimiterConfig must expose fail_mode via its attribute surface"
        )

    def test_rate_limiter_config_fail_mode_defaults_to_open(self):
        """When fail_mode is not passed, RateLimiterConfig exposes the safe default."""
        cfg = RateLimiterConfig()
        # Default should be the string "open" (mirroring the Rust-side fallback),
        # not None — this is what operators read when inspecting the config object.
        assert getattr(cfg, "fail_mode", "__missing__") == "open", (
            "RateLimiterConfig.fail_mode must default to 'open' for fail-open behaviour"
        )
