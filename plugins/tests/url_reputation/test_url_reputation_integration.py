# -*- coding: utf-8 -*-
"""Location: ./tests/unit/cpex/framework/plugins/url_reputation/test_url_reputation.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Mihai Criveti

Tests for URLReputationPlugin.
"""

from types import SimpleNamespace

import pytest

from cpex.framework import (
    PluginConfig,
    ResourceHookType,
    ResourcePreFetchPayload,
)
from cpex.framework.extensions import Extensions, RequestExtension

from cpex_url_reputation.url_reputation import URLReputationPlugin, URLReputationConfig
import cpex_url_reputation.url_reputation_rust  # noqa: F401


def _trace(trace_id: str = "t1") -> Extensions:
    """Build an Extensions instance carrying a trace_id, for metrics-gating tests."""
    return Extensions(request=RequestExtension(trace_id=trace_id))


def _plugin(config: dict) -> URLReputationPlugin:
    return URLReputationPlugin(
        PluginConfig(
            name="urlrep",
            kind="cpex_url_reputation.url_reputation.URLReputationPlugin",
            hooks=[ResourceHookType.RESOURCE_PRE_FETCH],
            config=config,
        )
    )


_DEFAULT_CONFIG = {
    "whitelist_domains": [],
    "allowed_patterns": [],
    "blocked_domains": [],
    "blocked_patterns": [],
    "use_heuristic_check": False,
    "entropy_threshold": 3.65,
    "block_non_secure_http": True,
}


@pytest.mark.asyncio
async def test_whitelisted_subdomain():
    """Subdomains of a whitelisted domain should be allowed."""
    config = PluginConfig(
        name="urlrep",
        kind="cpex_url_reputation.url_reputation.URLReputationPlugin",
        hooks=[ResourceHookType.RESOURCE_PRE_FETCH],
        config={
            "whitelist_domains": ["example.com"],
            "allowed_patterns": [],
            "blocked_domains": [],
            "blocked_patterns": [],
            "use_heuristic_check": True,
            "entropy_threshold": 3.5,
            "block_non_secure_http": True,
        },
    )
    plugin = URLReputationPlugin(config)

    res = await plugin.resource_pre_fetch(ResourcePreFetchPayload(uri="https://sub.example.com/login"), None)
    assert res.violation is None


@pytest.mark.asyncio
async def test_phishing_like_domain_blocked():
    """Domains mimicking popular sites but not whitelisted are blocked."""
    config = PluginConfig(
        name="urlrep",
        kind="cpex_url_reputation.url_reputation.URLReputationPlugin",
        hooks=[ResourceHookType.RESOURCE_PRE_FETCH],
        config={
            "whitelist_domains": ["paypal.com"],
            "allowed_patterns": [],
            "blocked_domains": [],
            "blocked_patterns": [],
            "use_heuristic_check": True,
            "entropy_threshold": 3.5,
            "block_non_secure_http": True,
        },
    )
    plugin = URLReputationPlugin(config)

    url = "https://pаypal.com/login"  # Cyrillic 'а'
    res = await plugin.resource_pre_fetch(ResourcePreFetchPayload(uri=url), None)
    assert not res.continue_processing



@pytest.mark.asyncio
async def test_high_entropy_domain_blocked():
    """Random-looking high-entropy domains should be blocked."""
    config = PluginConfig(
        name="urlrep",
        kind="cpex_url_reputation.url_reputation.URLReputationPlugin",
        hooks=[ResourceHookType.RESOURCE_PRE_FETCH],
        config={
            "whitelist_domains": [],
            "allowed_patterns": [],
            "blocked_domains": [],
            "blocked_patterns": [],
            "use_heuristic_check": True,
            "entropy_threshold": 3.5,
            "block_non_secure_http": True,
        },
    )
    plugin = URLReputationPlugin(config)

    url = "https://h7f893jkld90-234.com"
    res = await plugin.resource_pre_fetch(ResourcePreFetchPayload(uri=url), None)
    assert not res.continue_processing


@pytest.mark.asyncio
async def test_unicode_homograph_blocked():
    """URLs with unicode homograph attacks should be blocked."""
    config = PluginConfig(
        name="urlrep",
        kind="cpex_url_reputation.url_reputation.URLReputationPlugin",
        hooks=[ResourceHookType.RESOURCE_PRE_FETCH],
        config={
            "whitelist_domains": ["paypal.com"],
            "allowed_patterns": [],
            "blocked_domains": [],
            "blocked_patterns": [],
            "use_heuristic_check": True,
            "entropy_threshold": 3.5,
            "block_non_secure_http": True,
        },
    )
    plugin = URLReputationPlugin(config)

    url = "https://pаypal.com/login"  # Cyrillic 'а'
    res = await plugin.resource_pre_fetch(ResourcePreFetchPayload(uri=url), None)
    assert not res.continue_processing


@pytest.mark.asyncio
async def test_http_blocked_but_https_allowed_python():
    """Non-HTTPS URLs should be blocked; HTTPS allowed."""
    config = PluginConfig(
        name="urlrep",
        kind="cpex_url_reputation.url_reputation.URLReputationPlugin",
        hooks=[ResourceHookType.RESOURCE_PRE_FETCH],
        config={
            "whitelist_domains": [],
            "allowed_patterns": [],
            "blocked_domains": [],
            "blocked_patterns": [],
            "use_heuristic_check": False,
            "entropy_threshold": 3.5,
            "block_non_secure_http": True,
        },
    )
    plugin = URLReputationPlugin(config)

    res_http = await plugin.resource_pre_fetch(ResourcePreFetchPayload(uri="http://safe.com"), None)
    res_https = await plugin.resource_pre_fetch(ResourcePreFetchPayload(uri="https://safe.com"), None)

    assert not res_http.continue_processing
    assert res_https.continue_processing


@pytest.mark.asyncio
async def test_high_entropy_domain_blocked_heuristic():
    """Random-looking high-entropy domains should be blocked (requires Rust heuristics)."""
    config = PluginConfig(
        name="urlrep",
        kind="cpex_url_reputation.url_reputation.URLReputationPlugin",
        hooks=[ResourceHookType.RESOURCE_PRE_FETCH],
        config={
            "whitelist_domains": [],
            "allowed_patterns": [],
            "blocked_domains": [],
            "blocked_patterns": [],
            "use_heuristic_check": True,
            "entropy_threshold": 2.5,
            "block_non_secure_http": True,
        },
    )
    plugin = URLReputationPlugin(config)

    url = "https://ajsd9a8sd7a98sda7sd9.com"
    res = await plugin.resource_pre_fetch(ResourcePreFetchPayload(uri=url), None)
    assert not res.continue_processing


@pytest.mark.asyncio
async def test_allowed_pattern_url():
    """URLs matching allowed patterns bypass checks."""
    config = PluginConfig(
        name="urlrep",
        kind="cpex_url_reputation.url_reputation.URLReputationPlugin",
        hooks=[ResourceHookType.RESOURCE_PRE_FETCH],
        config={
            "whitelist_domains": [],
            "allowed_patterns": [r"^https://trusted\.example/.*$"],
            "blocked_domains": ["malicious.com"],
            "blocked_patterns": [r".*login.*"],
            "use_heuristic_check": True,
            "entropy_threshold": 3.5,
            "block_non_secure_http": True,
        },
    )
    plugin = URLReputationPlugin(config)

    url = "https://trusted.example/path"
    res = await plugin.resource_pre_fetch(ResourcePreFetchPayload(uri=url), None)
    assert res.continue_processing


@pytest.mark.asyncio
async def test_blocked_pattern_url():
    """URLs matching blocked patterns are rejected."""
    config = PluginConfig(
        name="urlrep",
        kind="cpex_url_reputation.url_reputation.URLReputationPlugin",
        hooks=[ResourceHookType.RESOURCE_PRE_FETCH],
        config={
            "whitelist_domains": [],
            "allowed_patterns": [],
            "blocked_domains": [],
            "blocked_patterns": ["admin", "login"],
            "use_heuristic_check": False,
            "entropy_threshold": 3.5,
            "block_non_secure_http": False,
        },
    )
    plugin = URLReputationPlugin(config)

    url = "https://example.com/admin/dashboard"
    res = await plugin.resource_pre_fetch(ResourcePreFetchPayload(uri=url), None)
    assert not res.continue_processing
    assert res.violation.reason == "Blocked pattern"


@pytest.mark.asyncio
async def test_internationalized_domain():
    """Test that Punycode domains are correctly handled."""
    config = PluginConfig(
        name="urlrep",
        kind="cpex_url_reputation.url_reputation.URLReputationPlugin",
        hooks=[ResourceHookType.RESOURCE_PRE_FETCH],
        config={
            "whitelist_domains": [],
            "allowed_patterns": [],
            "blocked_domains": [],
            "blocked_patterns": [],
            "use_heuristic_check": True,
            "entropy_threshold": 3.5,
            "block_non_secure_http": True,
        },
    )
    plugin = URLReputationPlugin(config)

    url = "https://xn--fsq.com"  # punycode representation
    res = await plugin.resource_pre_fetch(ResourcePreFetchPayload(uri=url), None)
    assert res.continue_processing


@pytest.mark.asyncio
async def test_mixed_case_domain_allowed():
    """Whitelist with mixed-case entry should bypass blocked_domains for that domain."""
    config = PluginConfig(
        name="urlrep",
        kind="cpex_url_reputation.url_reputation.URLReputationPlugin",
        hooks=[ResourceHookType.RESOURCE_PRE_FETCH],
        config={
            "whitelist_domains": ["Example.COM"],
            "allowed_patterns": [],
            "blocked_domains": ["example.com"],
            "blocked_patterns": [],
            "use_heuristic_check": False,
            "entropy_threshold": 3.5,
            "block_non_secure_http": False,
        },
    )
    plugin = URLReputationPlugin(config)

    res = await plugin.resource_pre_fetch(ResourcePreFetchPayload(uri="https://example.com/path"), None)
    assert res.continue_processing


@pytest.mark.asyncio
async def test_url_with_port_allowed():
    """URLs with valid ports should be allowed if everything else is OK."""
    config = PluginConfig(
        name="urlrep",
        kind="cpex_url_reputation.url_reputation.URLReputationPlugin",
        hooks=[ResourceHookType.RESOURCE_PRE_FETCH],
        config={
            "whitelist_domains": [],
            "allowed_patterns": [],
            "blocked_domains": [],
            "blocked_patterns": [],
            "use_heuristic_check": True,
            "entropy_threshold": 3.5,
            "block_non_secure_http": True,
        },
    )
    plugin = URLReputationPlugin(config)

    url = "https://example.com:8080/path"
    res = await plugin.resource_pre_fetch(ResourcePreFetchPayload(uri=url), None)
    assert res.continue_processing


@pytest.mark.asyncio
async def test_config_normalize_domains_empty():
    """URLReputationConfig normalizes empty domain sets correctly."""
    cfg = URLReputationConfig(
        whitelist_domains=set(),
        blocked_domains=set(),
    )
    assert cfg.whitelist_domains == set()
    assert cfg.blocked_domains == set()


@pytest.mark.asyncio
async def test_config_normalize_domains_none():
    """URLReputationConfig normalizes None domain sets to empty sets."""
    cfg = URLReputationConfig(
        whitelist_domains=None,
        blocked_domains=None,
    )
    assert cfg.whitelist_domains == set()
    assert cfg.blocked_domains == set()


@pytest.mark.asyncio
async def test_config_normalize_domains_mixed_case():
    """URLReputationConfig normalizes domain sets to lowercase."""
    cfg = URLReputationConfig(
        whitelist_domains={"EXAMPLE.COM", "Test.ORG"},
        blocked_domains={"BAD.com"},
    )
    assert cfg.whitelist_domains == {"example.com", "test.org"}
    assert cfg.blocked_domains == {"bad.com"}


# ---------------------------------------------------------------------------
# Group — Metrics Emission (issue #129 rollout): trace_id-gated, namespaced
# result.metadata["url_reputation"]. This plugin previously wrote no
# result.metadata at all, so this is a pure additive contract, not a
# migration -- there are no legacy keys to remove or reconcile.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestMetricsEmission:
    """Exercise the namespaced `result.metadata["url_reputation"]` metrics
    contract. `resource_pre_fetch` checks exactly one URL per call with no
    running counter, so -- mirroring `rate_limiter`'s per-call `allowed`/
    `throttled` semantics -- metrics are gated on `trace_id` alone (every
    call has a meaningful checked/blocked outcome to report; unlike
    `encoded_exfil_detection`'s per-scan gate, there's no "nothing happened"
    case here).
    """

    async def test_allowed_url_trace_in_metrics_out(self):
        plugin = _plugin(_DEFAULT_CONFIG)

        result = await plugin.resource_pre_fetch(ResourcePreFetchPayload(uri="https://example.com/data"), None, _trace())

        assert result.continue_processing
        assert result.metadata == {
            "url_reputation": {"total_checked": 1, "total_blocked": 0, "reputation_categories": []}
        }

    async def test_blocked_url_trace_in_metrics_out(self):
        plugin = _plugin({**_DEFAULT_CONFIG, "blocked_domains": ["malicious.example"]})

        result = await plugin.resource_pre_fetch(ResourcePreFetchPayload(uri="https://malicious.example/path"), None, _trace())

        assert not result.continue_processing
        metrics = result.metadata["url_reputation"]
        assert metrics["total_checked"] == 1
        assert metrics["total_blocked"] == 1
        assert metrics["reputation_categories"] == ["blocked_domain"]

    async def test_non_secure_http_trace_in_metrics_out(self):
        plugin = _plugin(_DEFAULT_CONFIG)

        result = await plugin.resource_pre_fetch(ResourcePreFetchPayload(uri="http://safe.com"), None, _trace())

        assert not result.continue_processing
        metrics = result.metadata["url_reputation"]
        assert metrics["reputation_categories"] == ["insecure_scheme"]

    async def test_without_extensions_is_backward_compatible(self):
        """Legacy 2-arg calls (no `extensions`) must not error, and must emit
        no metadata at all -- allowed or blocked."""
        plugin = _plugin(_DEFAULT_CONFIG)
        allowed_result = await plugin.resource_pre_fetch(ResourcePreFetchPayload(uri="https://example.com"), None)
        assert allowed_result.metadata == {}

        blocked_plugin = _plugin({**_DEFAULT_CONFIG, "blocked_domains": ["malicious.example"]})
        blocked_result = await blocked_plugin.resource_pre_fetch(
            ResourcePreFetchPayload(uri="https://malicious.example/path"), None
        )
        assert not blocked_result.continue_processing
        assert blocked_result.metadata == {}

    async def test_no_trace_id_emits_no_metadata_even_when_blocked(self):
        """trace_id absence is the only gate -- no metrics regardless of
        outcome, matching the pre-metrics behavior byte-for-byte."""
        plugin = _plugin({**_DEFAULT_CONFIG, "blocked_domains": ["malicious.example"]})

        result = await plugin.resource_pre_fetch(
            ResourcePreFetchPayload(uri="https://malicious.example/path"), None, extensions=None
        )

        assert not result.continue_processing
        assert result.metadata == {}

    async def test_metrics_never_contain_raw_url_or_domain(self):
        """S1: result.metadata must contain ONLY total_checked (int),
        total_blocked (int), and reputation_categories (list[str]) -- no
        raw URL or domain content, regardless of outcome."""
        distinctive_domain = "distinctive-blocked-domain-xyz.example"
        plugin = _plugin({**_DEFAULT_CONFIG, "blocked_domains": [distinctive_domain]})
        url = f"https://{distinctive_domain}/secret/path?token=abc123"

        result = await plugin.resource_pre_fetch(ResourcePreFetchPayload(uri=url), None, _trace())

        assert not result.continue_processing
        metrics = result.metadata["url_reputation"]
        assert set(metrics.keys()) == {"total_checked", "total_blocked", "reputation_categories"}
        assert all(isinstance(c, str) for c in metrics["reputation_categories"])

        dumped = str(result.metadata)
        assert distinctive_domain not in dumped
        assert "distinctive-blocked-domain-xyz" not in dumped
        assert url not in dumped
        assert "token=abc123" not in dumped

    async def test_internal_error_path_trace_in_metrics_out(self, monkeypatch):
        """The generic exception-handling branch (Rust engine raising) should
        also gate on trace_id and report the internal_error category."""
        plugin = _plugin(_DEFAULT_CONFIG)

        def _boom(_url):
            raise RuntimeError("engine exploded")

        # The Rust-backed `_core` object doesn't support attribute patching
        # of individual methods, so swap the whole `_core` for a stub.
        monkeypatch.setattr(plugin, "_core", SimpleNamespace(validate_url=_boom))

        result = await plugin.resource_pre_fetch(ResourcePreFetchPayload(uri="https://example.com"), None, _trace())

        assert not result.continue_processing
        assert result.metadata == {
            "url_reputation": {"total_checked": 1, "total_blocked": 1, "reputation_categories": ["internal_error"]}
        }

    async def test_internal_error_path_without_trace_id_emits_no_metadata(self, monkeypatch):
        plugin = _plugin(_DEFAULT_CONFIG)

        def _boom(_url):
            raise RuntimeError("engine exploded")

        # The Rust-backed `_core` object doesn't support attribute patching
        # of individual methods, so swap the whole `_core` for a stub.
        monkeypatch.setattr(plugin, "_core", SimpleNamespace(validate_url=_boom))

        result = await plugin.resource_pre_fetch(ResourcePreFetchPayload(uri="https://example.com"), None)

        assert not result.continue_processing
        assert result.metadata == {}
