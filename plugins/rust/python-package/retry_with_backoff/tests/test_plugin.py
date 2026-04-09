"""Tests for the retry_with_backoff plugin package."""

from __future__ import annotations

import logging
import time
import uuid
from unittest.mock import MagicMock, patch

import pytest

from cpex_retry_with_backoff.retry_with_backoff import (
    RetryConfig,
    RetryWithBackoffPlugin,
    _cfg_for,
    _compute_delay_ms,
    _del_state,
    _get_state,
    _is_failure,
    _STATE,
    _STATE_TTL_SECONDS,
)
from mcpgateway.common.models import ResourceContent
from mcpgateway.plugins.framework import (
    GlobalContext,
    PluginConfig,
    PluginContext,
    ResourcePostFetchPayload,
    ToolPostInvokePayload,
)


def make_plugin(config_overrides: dict | None = None) -> RetryWithBackoffPlugin:
    cfg = {
        "max_retries": 3,
        "backoff_base_ms": 200,
        "max_backoff_ms": 5000,
        "jitter": False,
        "retry_on_status": [429, 500, 502, 503, 504],
        "tool_overrides": {},
    }
    if config_overrides:
        cfg.update(config_overrides)
    plugin_config = PluginConfig(
        id="test-retry",
        kind="cpex_retry_with_backoff.retry_with_backoff.RetryWithBackoffPlugin",
        name="Test Retry Plugin",
        enabled=True,
        order=0,
        config=cfg,
    )
    return RetryWithBackoffPlugin(plugin_config)


def make_context() -> PluginContext:
    return PluginContext(
        plugin_id="test-retry",
        global_context=GlobalContext(request_id=str(uuid.uuid4())),
    )


def make_payload(tool: str, result: dict) -> ToolPostInvokePayload:
    return ToolPostInvokePayload(name=tool, result=result)


class TestComputeDelayMs:
    def test_no_jitter_returns_exact_ceiling(self):
        cfg = RetryConfig(backoff_base_ms=200, max_backoff_ms=5000, jitter=False)
        assert _compute_delay_ms(0, cfg) == 200
        assert _compute_delay_ms(1, cfg) == 400
        assert _compute_delay_ms(2, cfg) == 800

    def test_no_jitter_caps_at_max_backoff(self):
        cfg = RetryConfig(backoff_base_ms=200, max_backoff_ms=500, jitter=False)
        assert _compute_delay_ms(0, cfg) == 200
        assert _compute_delay_ms(1, cfg) == 400
        assert _compute_delay_ms(2, cfg) == 500
        assert _compute_delay_ms(10, cfg) == 500

    def test_jitter_returns_value_within_cap(self):
        cfg = RetryConfig(backoff_base_ms=200, max_backoff_ms=300, jitter=True)
        delay = _compute_delay_ms(5, cfg)
        assert 0 <= delay <= 300

    def test_exponential_growth_without_jitter(self):
        cfg = RetryConfig(backoff_base_ms=100, max_backoff_ms=100_000, jitter=False)
        assert [_compute_delay_ms(i, cfg) for i in range(5)] == [100, 200, 400, 800, 1600]


class TestIsFailure:
    def setup_method(self):
        self.cfg = RetryConfig()

    def test_is_error_true_triggers_failure(self):
        assert _is_failure({"isError": True}, self.cfg) is True

    def test_is_error_false_is_not_failure(self):
        assert _is_failure({"isError": False}, self.cfg) is False

    def test_status_code_500_in_structured_content_is_failure(self):
        assert _is_failure({"isError": False, "structuredContent": {"status_code": 500}}, self.cfg) is True

    def test_status_400_in_structured_content_is_not_retriable(self):
        assert _is_failure({"isError": False, "structuredContent": {"status_code": 400}}, self.cfg) is False

    def test_check_text_content_enabled_retryable_status(self):
        cfg = RetryConfig(check_text_content=True)
        result = {
            "isError": False,
            "structuredContent": None,
            "content": [{"type": "text", "text": '{"status_code": 503}'}],
        }
        assert _is_failure(result, cfg) is True

    def test_structured_content_is_error_true_triggers_failure(self):
        assert _is_failure({"isError": False, "structuredContent": {"isError": True}}, self.cfg) is True

    def test_is_error_with_non_retryable_status_skips_retry(self):
        result = {"isError": True, "structuredContent": {"status_code": 400}}
        assert _is_failure(result, self.cfg) is False

    def test_non_dict_result_is_not_failure(self):
        assert _is_failure("error string", self.cfg) is False


class TestCfgFor:
    def test_no_override_returns_same_object(self):
        cfg = RetryConfig()
        assert _cfg_for(cfg, "unknown_tool") is cfg

    def test_override_merges_max_retries(self):
        cfg = RetryConfig(max_retries=3, tool_overrides={"my_tool": {"max_retries": 1}})
        merged = _cfg_for(cfg, "my_tool")
        assert merged.max_retries == 1
        assert merged.backoff_base_ms == cfg.backoff_base_ms

    def test_override_does_not_include_tool_overrides(self):
        cfg = RetryConfig(tool_overrides={"my_tool": {"max_retries": 1}})
        merged = _cfg_for(cfg, "my_tool")
        assert merged.tool_overrides == {}


class TestPluginInit:
    def test_max_retries_clamped_to_gateway_ceiling(self):
        with patch("cpex_retry_with_backoff.retry_with_backoff.get_settings") as mock_settings:
            mock_settings.return_value.max_tool_retries = 2
            plugin = make_plugin({"max_retries": 5})
            assert plugin._cfg.max_retries == 2

    def test_tool_override_max_retries_clamped(self):
        with patch("cpex_retry_with_backoff.retry_with_backoff.get_settings") as mock_settings:
            mock_settings.return_value.max_tool_retries = 2
            plugin = make_plugin(
                {
                    "max_retries": 2,
                    "tool_overrides": {"slow_api": {"max_retries": 10}},
                }
            )
            assert plugin._cfg.tool_overrides["slow_api"]["max_retries"] == 2

    def test_clamping_emits_warning(self, caplog):
        with patch("cpex_retry_with_backoff.retry_with_backoff.get_settings") as mock_settings:
            mock_settings.return_value.max_tool_retries = 1
            with caplog.at_level(logging.WARNING):
                make_plugin({"max_retries": 5})
            assert any("max_retries=5 exceeds gateway ceiling=1" in record.getMessage() for record in caplog.records)


class TestToolPostInvoke:
    @pytest.mark.asyncio
    async def test_first_failure_requests_retry(self):
        plugin = make_plugin()
        ctx = make_context()
        result = await plugin.tool_post_invoke(make_payload("tool_a", {"isError": True}), ctx)
        assert result.retry_delay_ms > 0

    @pytest.mark.asyncio
    async def test_exhausted_retries_returns_zero_delay(self):
        plugin = make_plugin({"max_retries": 2})
        ctx = make_context()
        payload = make_payload("tool_a", {"isError": True})
        await plugin.tool_post_invoke(payload, ctx)
        await plugin.tool_post_invoke(payload, ctx)
        result = await plugin.tool_post_invoke(payload, ctx)
        assert result.retry_delay_ms == 0

    @pytest.mark.asyncio
    async def test_success_resets_failure_counter(self):
        plugin = make_plugin({"max_retries": 1, "jitter": False})
        ctx = make_context()
        r1 = await plugin.tool_post_invoke(make_payload("t", {"isError": True}), ctx)
        assert r1.retry_delay_ms > 0
        await plugin.tool_post_invoke(make_payload("t", {"result": "ok"}), ctx)
        r3 = await plugin.tool_post_invoke(make_payload("t", {"isError": True}), ctx)
        assert r3.retry_delay_ms > 0

    @pytest.mark.asyncio
    async def test_per_tool_override_is_applied(self):
        plugin = make_plugin(
            {
                "max_retries": 3,
                "tool_overrides": {"fragile_tool": {"max_retries": 1}},
            }
        )
        ctx = make_context()
        r1 = await plugin.tool_post_invoke(make_payload("fragile_tool", {"isError": True}), ctx)
        assert r1.retry_delay_ms > 0
        r2 = await plugin.tool_post_invoke(make_payload("fragile_tool", {"isError": True}), ctx)
        assert r2.retry_delay_ms == 0

    @pytest.mark.asyncio
    async def test_max_retries_zero_gives_up_immediately(self):
        plugin = make_plugin({"max_retries": 0})
        ctx = make_context()
        result = await plugin.tool_post_invoke(make_payload("t", {"isError": True}), ctx)
        assert result.retry_delay_ms == 0


class TestGetState:
    def test_creates_fresh_state_for_new_tool(self):
        st = _get_state("brand_new_tool", "req-fresh")
        assert st.consecutive_failures == 0
        assert st.last_failure_at == 0.0

    def test_returns_same_object_on_second_call(self):
        s1 = _get_state("tool_x", "req-same")
        s1.consecutive_failures = 7
        s2 = _get_state("tool_x", "req-same")
        assert s2.consecutive_failures == 7
        assert s1 is s2

    def test_ttl_eviction_removes_stale_entries(self):
        from cpex_retry_with_backoff.retry_with_backoff import _ToolRetryState

        key = "evict_tool:evict_req"
        baseline = _STATE.copy()
        try:
            with patch("cpex_retry_with_backoff.retry_with_backoff.time.monotonic", return_value=_STATE_TTL_SECONDS + 10):
                _STATE[key] = _ToolRetryState(
                    consecutive_failures=3,
                    last_failure_at=9.0,
                )
                _get_state("other_tool", "other_req")
                assert key not in _STATE
                _del_state("other_tool", "other_req")
        finally:
            _STATE.clear()
            _STATE.update(baseline)


class TestRustFallback:
    @pytest.mark.asyncio
    async def test_python_fallback_when_rust_unavailable(self):
        plugin = make_plugin()
        ctx = make_context()

        with patch.object(plugin, "_rust", None):
            r1 = await plugin.tool_post_invoke(make_payload("t", {"isError": True}), ctx)
            assert r1.retry_delay_ms > 0
            r2 = await plugin.tool_post_invoke(make_payload("t", {"result": "ok"}), ctx)
            assert r2.retry_delay_ms == 0

    @pytest.mark.asyncio
    async def test_rust_path_taken_when_available(self):
        plugin = make_plugin()
        ctx = make_context()
        mock_rust = MagicMock()
        mock_rust.check_and_update.return_value = (True, 300)

        with patch.object(plugin, "_rust", mock_rust):
            result = await plugin.tool_post_invoke(make_payload("t", {"isError": True}), ctx)

        mock_rust.check_and_update.assert_called_once()
        assert result.retry_delay_ms == 300

    @pytest.mark.asyncio
    async def test_rust_path_bypassed_for_check_text_content(self):
        plugin = make_plugin({"check_text_content": True})
        ctx = make_context()
        mock_rust = MagicMock()
        mock_rust.check_and_update.return_value = (True, 300)

        with patch.object(plugin, "_rust", mock_rust):
            await plugin.tool_post_invoke(make_payload("t", {"isError": True}), ctx)

        mock_rust.check_and_update.assert_not_called()


class TestRetryPolicyMetadata:
    @pytest.mark.asyncio
    async def test_failure_retry_path_includes_policy_metadata(self):
        plugin = make_plugin({"max_retries": 3, "backoff_base_ms": 200, "max_backoff_ms": 5000, "retry_on_status": [500]})
        ctx = make_context()
        result = await plugin.tool_post_invoke(make_payload("t", {"isError": True}), ctx)
        assert result.retry_delay_ms > 0
        assert result.metadata["retry_policy"] == {
            "max_retries": 3,
            "backoff_base_ms": 200,
            "max_backoff_ms": 5000,
            "retry_on_status": [500],
        }

    @pytest.mark.asyncio
    async def test_resource_post_fetch_returns_policy_metadata(self):
        plugin = make_plugin({"max_retries": 2, "backoff_base_ms": 150, "max_backoff_ms": 3000, "retry_on_status": [503]})
        ctx = make_context()
        content = ResourceContent(type="resource", id="r1", uri="file:///data.txt", text="hello")
        payload = ResourcePostFetchPayload(uri="file:///data.txt", content=content)
        result = await plugin.resource_post_fetch(payload, ctx)
        assert result.metadata["retry_policy"] == {
            "max_retries": 2,
            "backoff_base_ms": 150,
            "max_backoff_ms": 3000,
            "retry_on_status": [503],
        }
