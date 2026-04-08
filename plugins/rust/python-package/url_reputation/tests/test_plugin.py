from __future__ import annotations

import importlib
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from mcpgateway_mock.plugins.framework import (
    PluginConfig,
    ResourceHookType,
    ResourcePreFetchPayload,
)

from cpex_url_reputation.url_reputation import URLReputationConfig, URLReputationPlugin
from cpex_url_reputation.url_reputation_rust import URLReputationEngine


def _make_plugin_config(**overrides) -> PluginConfig:
    config = {
        "whitelist_domains": [],
        "allowed_patterns": [],
        "blocked_domains": [],
        "blocked_patterns": [],
        "use_heuristic_check": False,
        "entropy_threshold": 3.5,
        "block_non_secure_http": True,
    }
    config.update(overrides)
    return PluginConfig(
        name="urlrep",
        kind="cpex_url_reputation.url_reputation.URLReputationPlugin",
        version="0.1.0",
        hooks=[ResourceHookType.RESOURCE_PRE_FETCH],
        config=config,
    )


class TestRustEngine:
    def test_import_does_not_require_test_mocks(self, monkeypatch) -> None:
        tests_dir = Path(__file__).resolve().parent
        monkeypatch.setattr(
            sys,
            "path",
            [entry for entry in sys.path if Path(entry).resolve() != tests_dir],
        )
        for module_name in (
            "mcpgateway_mock",
            "mcpgateway_mock.plugins",
            "mcpgateway_mock.plugins.framework",
            "cpex_url_reputation.url_reputation_rust",
        ):
            sys.modules.pop(module_name, None)

        module = importlib.import_module("cpex_url_reputation.url_reputation_rust")

        assert hasattr(module, "URLReputationEngine")

    def test_whitelisted_subdomain_allowed(self) -> None:
        engine = URLReputationEngine({"whitelist_domains": ["example.com"]})
        result = engine.validate_url("https://sub.example.com/login")
        assert result.continue_processing is True
        assert result.violation is None

    def test_phishing_like_domain_blocked(self) -> None:
        engine = URLReputationEngine(
            {
                "whitelist_domains": ["paypal.com"],
                "use_heuristic_check": True,
            }
        )
        result = engine.validate_url("https://pаypal.com/login")
        assert result.continue_processing is False
        assert result.violation is not None

    def test_high_entropy_domain_blocked(self) -> None:
        engine = URLReputationEngine(
            {
                "use_heuristic_check": True,
                "entropy_threshold": 2.5,
            }
        )
        result = engine.validate_url("https://ajsd9a8sd7a98sda7sd9.com")
        assert result.continue_processing is False
        assert result.violation is not None

    def test_http_blocked_but_https_allowed(self) -> None:
        engine = URLReputationEngine({"block_non_secure_http": True})
        blocked = engine.validate_url("http://safe.com")
        allowed = engine.validate_url("https://safe.com")
        assert blocked.continue_processing is False
        assert allowed.continue_processing is True

    def test_allowed_pattern_bypasses_blocked_pattern(self) -> None:
        engine = URLReputationEngine(
            {
                "allowed_patterns": [r"^https://trusted\.example/.*$"],
                "blocked_patterns": [r".*trusted.*"],
                "use_heuristic_check": True,
            }
        )
        result = engine.validate_url("https://trusted.example/path")
        assert result.continue_processing is True

    def test_blocked_pattern_url(self) -> None:
        engine = URLReputationEngine(
            {
                "blocked_patterns": [r".*admin.*", r".*login.*"],
                "block_non_secure_http": False,
            }
        )
        result = engine.validate_url("https://example.com/admin/dashboard")
        assert result.continue_processing is False
        assert result.violation is not None
        assert result.violation.reason == "Blocked pattern"

    def test_invalid_blocked_pattern_raises(self) -> None:
        with pytest.raises(ValueError, match="Pattern compilation failed"):
            URLReputationEngine({"blocked_patterns": ["["]})

    def test_internationalized_domain_allowed(self) -> None:
        engine = URLReputationEngine({"use_heuristic_check": True})
        result = engine.validate_url("https://xn--fsq.com")
        assert result.continue_processing is True

    def test_mixed_case_whitelist_wins_over_blocked_domain(self) -> None:
        engine = URLReputationEngine(
            {
                "whitelist_domains": ["Example.COM"],
                "blocked_domains": ["example.com"],
                "block_non_secure_http": False,
            }
        )
        result = engine.validate_url("https://example.com/path")
        assert result.continue_processing is True

    def test_url_with_port_allowed(self) -> None:
        engine = URLReputationEngine(
            {
                "use_heuristic_check": True,
                "block_non_secure_http": True,
            }
        )
        result = engine.validate_url("https://example.com:8080/path")
        assert result.continue_processing is True

    def test_invalid_url_blocked(self) -> None:
        engine = URLReputationEngine({})
        result = engine.validate_url("not a url")
        assert result.continue_processing is False
        assert result.violation is not None
        assert result.violation.code == "URL_REPUTATION_BLOCK"


class TestPluginShim:
    @pytest.mark.asyncio
    async def test_resource_pre_fetch_allows_clean_url(self) -> None:
        plugin = URLReputationPlugin(_make_plugin_config(blocked_domains=["evil.com"]))
        result = await plugin.resource_pre_fetch(
            ResourcePreFetchPayload(uri="https://safe.example.com/path"),
            None,
        )
        assert result.continue_processing is True
        assert result.violation is None

    @pytest.mark.asyncio
    async def test_resource_pre_fetch_blocks_domain(self) -> None:
        plugin = URLReputationPlugin(_make_plugin_config(blocked_domains=["bad.com"]))
        result = await plugin.resource_pre_fetch(
            ResourcePreFetchPayload(uri="https://api.bad.com/v1"),
            None,
        )
        assert result.continue_processing is False
        assert result.violation is not None

    @pytest.mark.asyncio
    async def test_resource_pre_fetch_blocks_when_rust_core_errors(self) -> None:
        config = _make_plugin_config(block_non_secure_http=False)
        mock_core = MagicMock()
        mock_core.resource_pre_fetch.side_effect = RuntimeError("boom")
        with patch(
            "cpex_url_reputation.url_reputation.URLReputationPluginCore",
            return_value=mock_core,
        ):
            plugin = URLReputationPlugin(config)
            result = await plugin.resource_pre_fetch(
                ResourcePreFetchPayload(uri="https://example.com"),
                None,
            )
        assert result.continue_processing is False
        assert result.violation is not None
        assert result.violation.reason == "Rust validation failure"


class TestConfig:
    def test_normalize_domains_none_to_empty(self) -> None:
        cfg = URLReputationConfig(whitelist_domains=None, blocked_domains=None)
        assert cfg.whitelist_domains == set()
        assert cfg.blocked_domains == set()

    def test_normalize_domains_lowercase(self) -> None:
        cfg = URLReputationConfig(
            whitelist_domains={"EXAMPLE.COM", "Test.ORG"},
            blocked_domains={"BAD.com"},
        )
        assert cfg.whitelist_domains == {"example.com", "test.org"}
        assert cfg.blocked_domains == {"bad.com"}
