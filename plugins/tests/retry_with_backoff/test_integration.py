"""Tests for the retry_with_backoff plugin package."""

from __future__ import annotations

import uuid

import pytest

from cpex_retry_with_backoff.retry_with_backoff import RetryWithBackoffPlugin
from cpex_retry_with_backoff.retry_with_backoff_rust import RetryStateManager
from cpex.framework import (
    GlobalContext,
    PluginConfig,
    PluginContext,
    ResourceContent,
    ResourcePostFetchPayload,
    ToolPostInvokePayload,
)
from cpex.framework.extensions import Extensions, RequestExtension


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
        mgr = RetryStateManager(2, 200, 5000, False, [])
        assert mgr.compute_delay(0) == 200
        assert mgr.compute_delay(1) == 400
        assert mgr.compute_delay(2) == 800

    def test_no_jitter_caps_at_max_backoff(self):
        mgr = RetryStateManager(2, 200, 500, False, [])
        assert mgr.compute_delay(0) == 200
        assert mgr.compute_delay(1) == 400
        assert mgr.compute_delay(2) == 500
        assert mgr.compute_delay(10) == 500

    def test_jitter_returns_value_within_cap(self):
        mgr = RetryStateManager(2, 200, 300, True, [])
        delay = mgr.compute_delay(5)
        assert 0 <= delay <= 300

    def test_exponential_growth_without_jitter(self):
        mgr = RetryStateManager(2, 100, 100_000, False, [])
        assert [mgr.compute_delay(i) for i in range(5)] == [100, 200, 400, 800, 1600]


class TestIsFailure:
    def test_is_error_true_triggers_failure(self):
        mgr = RetryStateManager(2, 200, 5000, False, [429, 500, 502, 503, 504])
        assert mgr.check_failure(True, None) is True

    def test_is_error_false_is_not_failure(self):
        mgr = RetryStateManager(2, 200, 5000, False, [429, 500, 502, 503, 504])
        assert mgr.check_failure(False, None) is False

    def test_status_code_500_triggers_failure(self):
        mgr = RetryStateManager(2, 200, 5000, False, [429, 500, 502, 503, 504])
        assert mgr.check_failure(False, 500) is True

    def test_status_400_is_not_retriable(self):
        mgr = RetryStateManager(2, 200, 5000, False, [429, 500, 502, 503, 504])
        assert mgr.check_failure(False, 400) is False

    def test_is_error_with_non_retryable_status_skips_retry(self):
        mgr = RetryStateManager(2, 200, 5000, False, [429, 500, 502, 503, 504])
        assert mgr.check_failure(True, 400) is False

    def test_status_200_is_not_failure(self):
        mgr = RetryStateManager(2, 200, 5000, False, [429, 500, 502, 503, 504])
        assert mgr.check_failure(False, 200) is False


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

    @pytest.mark.asyncio
    async def test_exhaustion_resets_counter_for_next_call(self):
        """After exhaustion the counter resets so the next independent call gets a fresh retry budget."""
        plugin = make_plugin({"max_retries": 2, "jitter": False})
        ctx = make_context()
        payload = make_payload("tool_x", {"isError": True})
        # Exhaust: 3 failures (original + 2 retries)
        await plugin.tool_post_invoke(payload, ctx)
        await plugin.tool_post_invoke(payload, ctx)
        await plugin.tool_post_invoke(payload, ctx)  # exhausted, returns 0
        # Counter must be reset — next independent call should retry again
        r = await plugin.tool_post_invoke(payload, ctx)
        assert r.retry_delay_ms > 0, "next independent call must get a fresh retry, not be blocked by previous exhaustion"

    @pytest.mark.asyncio
    async def test_different_tools_have_independent_state(self):
        """Different tools maintain separate retry state."""
        plugin = make_plugin({"max_retries": 1, "jitter": False})
        ctx = make_context()
        # tool_a exhausts retries
        await plugin.tool_post_invoke(make_payload("tool_a", {"isError": True}), ctx)
        await plugin.tool_post_invoke(make_payload("tool_a", {"isError": True}), ctx)
        # tool_b is unaffected
        r = await plugin.tool_post_invoke(make_payload("tool_b", {"isError": True}), ctx)
        assert r.retry_delay_ms > 0


class TestRetryPolicyMetadata:
    """`resource_post_fetch` is out of scope for issue #129 and keeps its
    pre-existing, un-namespaced `retry_policy` config echo untouched. The
    `tool_post_invoke` hook, in contrast, drops that echo entirely in favor
    of the namespaced, trace_id-gated `retry_with_backoff` metrics dict
    (see `TestMetricsEmission` below) — regression-tested here.
    """

    @pytest.mark.asyncio
    async def test_tool_post_invoke_no_longer_emits_retry_policy_key(self):
        plugin = make_plugin({"max_retries": 3, "backoff_base_ms": 200, "max_backoff_ms": 5000, "retry_on_status": [500]})
        ctx = make_context()

        # Without trace_id.
        result = await plugin.tool_post_invoke(make_payload("t", {"isError": True}), ctx)
        assert result.retry_delay_ms > 0
        assert "retry_policy" not in result.metadata

        # With trace_id.
        result = await plugin.tool_post_invoke(make_payload("t", {"isError": True}), ctx, _trace())
        assert "retry_policy" not in result.metadata

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


# ---------------------------------------------------------------------------
# Metrics emission (issue #129): trace_id-gated result.metadata["retry_with_backoff"]
# ---------------------------------------------------------------------------


def _trace(trace_id: str = "t1") -> Extensions:
    return Extensions(request=RequestExtension(trace_id=trace_id))


class TestMetricsEmission:
    """Exercise the namespaced `result.metadata["retry_with_backoff"]` metrics
    across all three `tool_post_invoke` result-building branches: success,
    within-budget retry, and exhausted-budget. Mirrors the
    pii_filter/secrets_detection/rate_limiter contract: metrics are gated on
    `trace_id` and emit exactly `retry_count` + `retry_delay_ms` — no
    cumulative backoff total is tracked or emitted.
    """

    @pytest.mark.asyncio
    async def test_success_branch_gates_on_trace_id(self):
        plugin = make_plugin({"max_retries": 2, "jitter": False})
        ctx = make_context()

        # Without trace_id: no metadata write at all.
        result = await plugin.tool_post_invoke(make_payload("t", {"result": "ok"}), ctx)
        assert result.retry_delay_ms == 0
        assert result.metadata == {}

        # With trace_id: namespaced metrics present, both counters zero.
        result = await plugin.tool_post_invoke(make_payload("t", {"result": "ok"}), ctx, _trace())
        assert result.retry_delay_ms == 0
        metrics = result.metadata["retry_with_backoff"]
        assert metrics["retry_count"] == 0
        assert metrics["retry_delay_ms"] == 0

    @pytest.mark.asyncio
    async def test_within_budget_branch_emits_count_and_positive_delay(self):
        plugin = make_plugin({"max_retries": 3, "backoff_base_ms": 200, "jitter": False})
        ctx = make_context()
        payload = make_payload("t", {"isError": True})

        # Without trace_id: retry still happens, but no metadata write.
        result = await plugin.tool_post_invoke(payload, ctx)
        assert result.retry_delay_ms > 0
        assert result.metadata == {}

        # With trace_id: retry_count/retry_delay_ms reflect this attempt.
        result = await plugin.tool_post_invoke(payload, ctx, _trace())
        assert result.retry_delay_ms == 400  # second consecutive failure -> attempt 1
        metrics = result.metadata["retry_with_backoff"]
        assert metrics["retry_count"] == 2
        assert metrics["retry_delay_ms"] == 400

    @pytest.mark.asyncio
    async def test_exhausted_branch_emits_final_count_and_zero_delay(self):
        plugin = make_plugin({"max_retries": 1, "jitter": False})
        ctx = make_context()
        payload = make_payload("t", {"isError": True})

        await plugin.tool_post_invoke(payload, ctx, _trace())  # failure 1 (within budget)
        result = await plugin.tool_post_invoke(payload, ctx, _trace())  # failure 2 -> exhausted

        assert result.retry_delay_ms == 0
        metrics = result.metadata["retry_with_backoff"]
        assert metrics["retry_count"] == 2
        assert metrics["retry_delay_ms"] == 0

    @pytest.mark.asyncio
    async def test_without_extensions_arg_is_backward_compatible(self):
        # Legacy 2-arg call (no `extensions`) must not error.
        plugin = make_plugin({"max_retries": 2, "jitter": False})
        ctx = make_context()
        result = await plugin.tool_post_invoke(make_payload("t", {"isError": True}), ctx)
        assert result.retry_delay_ms > 0
        assert result.metadata == {}

    @pytest.mark.asyncio
    async def test_resource_post_fetch_is_unaffected_by_metrics_rollout(self):
        # Out of scope for issue #129: no `extensions` param, still emits the
        # legacy un-namespaced `retry_policy` echo, exactly as before.
        plugin = make_plugin({"max_retries": 2, "backoff_base_ms": 150, "max_backoff_ms": 3000, "retry_on_status": [503]})
        ctx = make_context()
        content = ResourceContent(type="resource", id="r1", uri="file:///data.txt", text="hello")
        payload = ResourcePostFetchPayload(uri="file:///data.txt", content=content)
        result = await plugin.resource_post_fetch(payload, ctx)
        assert "retry_with_backoff" not in result.metadata
        assert result.metadata["retry_policy"] == {
            "max_retries": 2,
            "backoff_base_ms": 150,
            "max_backoff_ms": 3000,
            "retry_on_status": [503],
        }
