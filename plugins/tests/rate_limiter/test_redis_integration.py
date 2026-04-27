# -*- coding: utf-8 -*-
"""Integration tests for rate limiter plugin.

Tests verify PLUGIN behaviour:
1. Rate limit enforcement via plugin hooks
2. HTTP 429 status code on limit exceeded
3. Retry-After and X-RateLimit-* headers
4. Multi-dimensional rate limiting (user, tenant, tool)
5. Window reset behavior
6. Plugin configuration from config file
7. Redis backend correctness (optional — auto-skips without Docker/Redis)

Out of scope here: executor-side dispatch (PERMISSIVE / ENFORCE / DISABLED
mode handling).  Those live in mc-c-f's tests/unit/mcpgateway/plugins/
framework/test_manager_*.py, where they are exercised against the real
PluginExecutor with inline trivial plugins.

Note: these tests drive the PLUGIN directly — no MCP gateway is required.
The plugin's `from mcpgateway.plugins.framework import ...` resolves
through the plugin hook contracts (see conftest.py).
"""

# Standard
import asyncio
import os
import socket
import subprocess
import time

# Third-Party
import pytest

# First-Party (mcpgateway framework surface, satisfied by plugin hook contracts)
from mcpgateway.plugins.framework import (
    GlobalContext,
    PluginConfig,
    PluginContext,
    PromptPrehookPayload,
    ToolPreInvokePayload,
)

from cpex_rate_limiter.rate_limiter import RateLimiterPlugin


@pytest.fixture
def rate_limit_plugin_2_per_second():
    """Rate limiter plugin configured for 2 requests per second."""
    config = PluginConfig(
        name="RateLimiter",
        kind="cpex_rate_limiter.rate_limiter.RateLimiterPlugin",
        hooks=["prompt_pre_fetch", "tool_pre_invoke"],
        priority=100,
        config={"by_user": "2/s", "by_tenant": None, "by_tool": {}},
    )
    return RateLimiterPlugin(config)


@pytest.fixture
def rate_limit_plugin_multi_dimensional():
    """Rate limiter plugin with multi-dimensional limits."""
    config = PluginConfig(
        name="RateLimiter",
        kind="cpex_rate_limiter.rate_limiter.RateLimiterPlugin",
        hooks=["prompt_pre_fetch", "tool_pre_invoke"],
        priority=100,
        config={"by_user": "10/s", "by_tenant": "5/s", "by_tool": {"restricted_tool": "1/s"}},
    )
    return RateLimiterPlugin(config)


class TestRateLimitBasics:
    """Basic rate limit enforcement tests via plugin."""

    @pytest.mark.asyncio
    async def test_under_limit_allows_requests(self, rate_limit_plugin_2_per_second):
        """Verify requests under limit are allowed."""
        plugin = rate_limit_plugin_2_per_second
        ctx = PluginContext(global_context=GlobalContext(request_id="r1", user="alice"))
        payload = PromptPrehookPayload(prompt_id="test", args={})

        # First request - should succeed
        result1 = await plugin.prompt_pre_fetch(payload, ctx)
        assert result1.violation is None
        assert result1.http_headers is not None
        assert result1.http_headers["X-RateLimit-Remaining"] == "1"

        # Second request - should succeed
        result2 = await plugin.prompt_pre_fetch(payload, ctx)
        assert result2.violation is None
        assert result2.http_headers["X-RateLimit-Remaining"] == "0"

    @pytest.mark.asyncio
    async def test_exceeding_limit_returns_violation(self, rate_limit_plugin_2_per_second):
        """Verify exceeding limit returns violation with HTTP 429."""
        plugin = rate_limit_plugin_2_per_second
        ctx = PluginContext(global_context=GlobalContext(request_id="r1", user="alice"))
        payload = PromptPrehookPayload(prompt_id="test", args={})

        # Exhaust rate limit
        await plugin.prompt_pre_fetch(payload, ctx)
        await plugin.prompt_pre_fetch(payload, ctx)

        # Third request should be rate limited
        result = await plugin.prompt_pre_fetch(payload, ctx)
        assert result.violation is not None
        assert result.violation.http_status_code == 429
        assert result.violation.code == "RATE_LIMIT"
        assert "rate limit exceeded" in result.violation.description.lower()

    @pytest.mark.asyncio
    async def test_rate_limit_headers_present(self, rate_limit_plugin_2_per_second):
        """Verify all rate limit headers are present."""
        plugin = rate_limit_plugin_2_per_second
        ctx = PluginContext(global_context=GlobalContext(request_id="r1", user="alice"))
        payload = PromptPrehookPayload(prompt_id="test", args={})

        result = await plugin.prompt_pre_fetch(payload, ctx)

        assert result.http_headers is not None
        assert "X-RateLimit-Limit" in result.http_headers
        assert "X-RateLimit-Remaining" in result.http_headers
        assert "X-RateLimit-Reset" in result.http_headers

        limit = int(result.http_headers["X-RateLimit-Limit"])
        remaining = int(result.http_headers["X-RateLimit-Remaining"])
        reset = int(result.http_headers["X-RateLimit-Reset"])

        assert limit == 2
        assert remaining == 1
        assert reset > int(time.time())

    @pytest.mark.asyncio
    async def test_retry_after_header_on_violation(self, rate_limit_plugin_2_per_second):
        """Verify Retry-After header is present on violations."""
        plugin = rate_limit_plugin_2_per_second
        ctx = PluginContext(global_context=GlobalContext(request_id="r1", user="alice"))
        payload = PromptPrehookPayload(prompt_id="test", args={})

        # Exhaust rate limit
        await plugin.prompt_pre_fetch(payload, ctx)
        await plugin.prompt_pre_fetch(payload, ctx)

        # Get violation
        result = await plugin.prompt_pre_fetch(payload, ctx)
        assert result.violation is not None
        assert result.violation.http_headers is not None
        assert "Retry-After" in result.violation.http_headers

        retry_after = int(result.violation.http_headers["Retry-After"])
        assert 0 < retry_after <= 1  # 1 second window

    @pytest.mark.asyncio
    async def test_success_response_no_retry_after(self, rate_limit_plugin_2_per_second):
        """Verify successful responses don't include Retry-After header."""
        plugin = rate_limit_plugin_2_per_second
        ctx = PluginContext(global_context=GlobalContext(request_id="r1", user="alice"))
        payload = PromptPrehookPayload(prompt_id="test", args={})

        result = await plugin.prompt_pre_fetch(payload, ctx)

        assert result.violation is None
        assert result.http_headers is not None
        assert "Retry-After" not in result.http_headers


class TestRateLimitAlgorithm:
    """Window-based rate limiting algorithm tests."""

    @pytest.mark.asyncio
    async def test_remaining_count_decrements(self, rate_limit_plugin_2_per_second):
        """Verify remaining count decrements correctly."""
        plugin = rate_limit_plugin_2_per_second
        ctx = PluginContext(global_context=GlobalContext(request_id="r1", user="alice"))
        payload = PromptPrehookPayload(prompt_id="test", args={})

        # First request
        result1 = await plugin.prompt_pre_fetch(payload, ctx)
        assert result1.http_headers["X-RateLimit-Remaining"] == "1"

        # Second request
        result2 = await plugin.prompt_pre_fetch(payload, ctx)
        assert result2.http_headers["X-RateLimit-Remaining"] == "0"

    @pytest.mark.asyncio
    async def test_rate_limit_resets_after_window(self, rate_limit_plugin_2_per_second):
        """Verify rate limit resets after the window expires."""
        plugin = rate_limit_plugin_2_per_second
        ctx = PluginContext(global_context=GlobalContext(request_id="r1", user="alice"))
        payload = PromptPrehookPayload(prompt_id="test", args={})

        # Exhaust rate limit
        await plugin.prompt_pre_fetch(payload, ctx)
        await plugin.prompt_pre_fetch(payload, ctx)

        # Verify rate limited
        result = await plugin.prompt_pre_fetch(payload, ctx)
        assert result.violation is not None

        # Wait for window to reset (1 second + buffer)
        await asyncio.sleep(1.1)

        # Verify rate limit reset
        result = await plugin.prompt_pre_fetch(payload, ctx)
        assert result.violation is None
        assert result.http_headers["X-RateLimit-Remaining"] == "1"

    @pytest.mark.asyncio
    async def test_reset_timestamp_accuracy(self, rate_limit_plugin_2_per_second):
        """Verify X-RateLimit-Reset timestamp is accurate."""
        plugin = rate_limit_plugin_2_per_second
        ctx = PluginContext(global_context=GlobalContext(request_id="r1", user="alice"))
        payload = PromptPrehookPayload(prompt_id="test", args={})

        result = await plugin.prompt_pre_fetch(payload, ctx)
        reset_time = int(result.http_headers["X-RateLimit-Reset"])
        current_time = int(time.time())

        # Reset should be current time + 1 second (with small tolerance)
        expected_reset = current_time + 1
        assert abs(reset_time - expected_reset) <= 2


class TestMultiDimensionalRateLimiting:
    """Multi-dimensional rate limiting tests (user, tenant, tool)."""

    @pytest.mark.asyncio
    async def test_user_rate_limit_enforced(self):
        """Verify user rate limits are enforced independently per user."""
        # Configure with ONLY user limits (no tenant limit)
        config = PluginConfig(
            name="RateLimiter",
            kind="cpex_rate_limiter.rate_limiter.RateLimiterPlugin",
            hooks=["prompt_pre_fetch"],
            priority=100,
            config={"by_user": "10/s", "by_tenant": None, "by_tool": {}},  # No tenant limit
        )
        plugin = RateLimiterPlugin(config)

        ctx_alice = PluginContext(global_context=GlobalContext(request_id="r1", user="alice", tenant_id="team1"))
        ctx_bob = PluginContext(global_context=GlobalContext(request_id="r2", user="bob", tenant_id="team1"))
        payload = PromptPrehookPayload(prompt_id="test", args={})

        # Alice makes 10 requests (her limit)
        for _ in range(10):
            result = await plugin.prompt_pre_fetch(payload, ctx_alice)
            assert result.violation is None

        # Alice's 11th request should be rate limited
        result = await plugin.prompt_pre_fetch(payload, ctx_alice)
        assert result.violation is not None

        # Bob should still have his own limit (not affected by Alice)
        result = await plugin.prompt_pre_fetch(payload, ctx_bob)
        assert result.violation is None

    @pytest.mark.asyncio
    async def test_tenant_rate_limit_enforced(self, rate_limit_plugin_multi_dimensional):
        """Verify tenant rate limits are enforced across users."""
        plugin = rate_limit_plugin_multi_dimensional
        ctx_alice = PluginContext(global_context=GlobalContext(request_id="r1", user="alice", tenant_id="team1"))
        ctx_bob = PluginContext(global_context=GlobalContext(request_id="r2", user="bob", tenant_id="team1"))
        payload = PromptPrehookPayload(prompt_id="test", args={})

        # Alice makes 3 requests
        for _ in range(3):
            result = await plugin.prompt_pre_fetch(payload, ctx_alice)
            assert result.violation is None

        # Bob makes 2 requests (total 5 for team1)
        for _ in range(2):
            result = await plugin.prompt_pre_fetch(payload, ctx_bob)
            assert result.violation is None

        # Next request from either user should be rate limited (tenant limit reached)
        result = await plugin.prompt_pre_fetch(payload, ctx_alice)
        assert result.violation is not None
        assert result.violation.http_status_code == 429

    @pytest.mark.asyncio
    async def test_per_tool_rate_limiting(self, rate_limit_plugin_multi_dimensional):
        """Verify per-tool rate limits are enforced."""
        plugin = rate_limit_plugin_multi_dimensional
        ctx = PluginContext(global_context=GlobalContext(request_id="r1", user="alice"))

        restricted_payload = ToolPreInvokePayload(name="restricted_tool", arguments={})
        unrestricted_payload = ToolPreInvokePayload(name="other_tool", arguments={})

        # First call to restricted tool succeeds
        result = await plugin.tool_pre_invoke(restricted_payload, ctx)
        assert result.violation is None

        # Second call to restricted tool should be rate limited
        result = await plugin.tool_pre_invoke(restricted_payload, ctx)
        assert result.violation is not None
        assert result.violation.http_status_code == 429

        # Other tool should still work
        result = await plugin.tool_pre_invoke(unrestricted_payload, ctx)
        assert result.violation is None

    @pytest.mark.asyncio
    async def test_most_restrictive_dimension_selected(self):
        """Verify most restrictive dimension is selected."""
        # Configure with different limits
        config = PluginConfig(
            name="RateLimiter",
            kind="cpex_rate_limiter.rate_limiter.RateLimiterPlugin",
            hooks=["prompt_pre_fetch"],
            priority=100,
            config={
                "by_user": "10/s",  # More permissive
                "by_tenant": "2/s",  # More restrictive
            },
        )
        plugin = RateLimiterPlugin(config)

        ctx = PluginContext(global_context=GlobalContext(request_id="r1", user="alice", tenant_id="team1"))
        payload = PromptPrehookPayload(prompt_id="test", args={})

        # Make 2 requests (tenant limit)
        await plugin.prompt_pre_fetch(payload, ctx)
        await plugin.prompt_pre_fetch(payload, ctx)

        # Third request should be rate limited by tenant limit
        result = await plugin.prompt_pre_fetch(payload, ctx)
        assert result.violation is not None
        # Headers should show tenant limit (2), not user limit (10)
        assert result.violation.http_headers["X-RateLimit-Limit"] == "2"


class TestToolPreInvoke:
    """Tests for tool_pre_invoke hook."""

    @pytest.mark.asyncio
    async def test_tool_invoke_rate_limiting(self, rate_limit_plugin_2_per_second):
        """Verify tool invocations are rate limited."""
        plugin = rate_limit_plugin_2_per_second
        ctx = PluginContext(global_context=GlobalContext(request_id="r1", user="alice"))
        payload = ToolPreInvokePayload(name="test_tool", arguments={})

        # First two requests succeed
        result1 = await plugin.tool_pre_invoke(payload, ctx)
        assert result1.violation is None

        result2 = await plugin.tool_pre_invoke(payload, ctx)
        assert result2.violation is None

        # Third request should be rate limited
        result3 = await plugin.tool_pre_invoke(payload, ctx)
        assert result3.violation is not None
        assert result3.violation.http_status_code == 429

    @pytest.mark.asyncio
    async def test_tool_invoke_headers_present(self, rate_limit_plugin_2_per_second):
        """Verify headers are present on tool invocations."""
        plugin = rate_limit_plugin_2_per_second
        ctx = PluginContext(global_context=GlobalContext(request_id="r1", user="alice"))
        payload = ToolPreInvokePayload(name="test_tool", arguments={})

        result = await plugin.tool_pre_invoke(payload, ctx)

        assert result.http_headers is not None
        assert "X-RateLimit-Limit" in result.http_headers
        assert "X-RateLimit-Remaining" in result.http_headers
        assert "X-RateLimit-Reset" in result.http_headers
        assert "Retry-After" not in result.http_headers  # Not on success


class TestSlidingWindowIntegration:
    """End-to-end integration tests for the sliding_window algorithm."""

    @pytest.fixture
    def plugin(self):
        config = PluginConfig(
            name="RateLimiter",
            kind="cpex_rate_limiter.rate_limiter.RateLimiterPlugin",
            hooks=["prompt_pre_fetch", "tool_pre_invoke"],
            priority=100,
            config={"by_user": "3/s", "algorithm": "sliding_window"},
        )
        return RateLimiterPlugin(config)

    @pytest.mark.asyncio
    async def test_sliding_window_enforces_limit(self, plugin):
        """Sliding window allows exactly N requests then blocks."""
        ctx = PluginContext(global_context=GlobalContext(request_id="r1", user="alice"))
        payload = ToolPreInvokePayload(name="tool", arguments={})

        for _ in range(3):
            result = await plugin.tool_pre_invoke(payload, ctx)
            assert result.violation is None

        result = await plugin.tool_pre_invoke(payload, ctx)
        assert result.violation is not None
        assert result.violation.http_status_code == 429

    @pytest.mark.asyncio
    async def test_sliding_window_returns_ratelimit_headers(self, plugin):
        """Sliding window includes X-RateLimit-* headers on allowed requests."""
        ctx = PluginContext(global_context=GlobalContext(request_id="r1", user="alice"))
        payload = ToolPreInvokePayload(name="tool", arguments={})

        result = await plugin.tool_pre_invoke(payload, ctx)
        assert result.violation is None
        assert result.http_headers is not None
        assert "X-RateLimit-Limit" in result.http_headers
        assert "X-RateLimit-Remaining" in result.http_headers
        assert "X-RateLimit-Reset" in result.http_headers
        assert "Retry-After" not in result.http_headers

    @pytest.mark.asyncio
    async def test_sliding_window_retry_after_on_violation(self, plugin):
        """Sliding window includes Retry-After on violations."""
        ctx = PluginContext(global_context=GlobalContext(request_id="r1", user="alice"))
        payload = ToolPreInvokePayload(name="tool", arguments={})

        for _ in range(3):
            await plugin.tool_pre_invoke(payload, ctx)

        result = await plugin.tool_pre_invoke(payload, ctx)
        assert result.violation is not None
        assert "Retry-After" in result.violation.http_headers

    @pytest.mark.asyncio
    async def test_sliding_window_resets_after_window(self, plugin):
        """Sliding window allows requests again after the window elapses."""
        ctx = PluginContext(global_context=GlobalContext(request_id="r1", user="alice"))
        payload = ToolPreInvokePayload(name="tool", arguments={})

        for _ in range(3):
            await plugin.tool_pre_invoke(payload, ctx)

        result = await plugin.tool_pre_invoke(payload, ctx)
        assert result.violation is not None

        await asyncio.sleep(1.1)

        result = await plugin.tool_pre_invoke(payload, ctx)
        assert result.violation is None

    @pytest.mark.asyncio
    async def test_sliding_window_independent_users(self, plugin):
        """Sliding window tracks separate counters per user."""
        ctx_alice = PluginContext(global_context=GlobalContext(request_id="r1", user="alice"))
        ctx_bob = PluginContext(global_context=GlobalContext(request_id="r2", user="bob"))
        payload = ToolPreInvokePayload(name="tool", arguments={})

        for _ in range(3):
            await plugin.tool_pre_invoke(payload, ctx_alice)

        alice_blocked = await plugin.tool_pre_invoke(payload, ctx_alice)
        assert alice_blocked.violation is not None

        bob_allowed = await plugin.tool_pre_invoke(payload, ctx_bob)
        assert bob_allowed.violation is None


class TestTokenBucketIntegration:
    """End-to-end integration tests for the token_bucket algorithm."""

    @pytest.fixture
    def plugin(self):
        config = PluginConfig(
            name="RateLimiter",
            kind="cpex_rate_limiter.rate_limiter.RateLimiterPlugin",
            hooks=["prompt_pre_fetch", "tool_pre_invoke"],
            priority=100,
            config={"by_user": "3/s", "algorithm": "token_bucket"},
        )
        return RateLimiterPlugin(config)

    @pytest.mark.asyncio
    async def test_token_bucket_enforces_limit(self, plugin):
        """Token bucket allows up to capacity requests then blocks."""
        ctx = PluginContext(global_context=GlobalContext(request_id="r1", user="alice"))
        payload = ToolPreInvokePayload(name="tool", arguments={})

        for _ in range(3):
            result = await plugin.tool_pre_invoke(payload, ctx)
            assert result.violation is None

        result = await plugin.tool_pre_invoke(payload, ctx)
        assert result.violation is not None
        assert result.violation.http_status_code == 429

    @pytest.mark.asyncio
    async def test_token_bucket_returns_ratelimit_headers(self, plugin):
        """Token bucket includes X-RateLimit-* headers on allowed requests."""
        ctx = PluginContext(global_context=GlobalContext(request_id="r1", user="alice"))
        payload = ToolPreInvokePayload(name="tool", arguments={})

        result = await plugin.tool_pre_invoke(payload, ctx)
        assert result.violation is None
        assert result.http_headers is not None
        assert "X-RateLimit-Limit" in result.http_headers
        assert "X-RateLimit-Remaining" in result.http_headers
        assert "X-RateLimit-Reset" in result.http_headers

    @pytest.mark.asyncio
    async def test_token_bucket_remaining_decrements(self, plugin):
        """Token bucket X-RateLimit-Remaining decrements with each request."""
        ctx = PluginContext(global_context=GlobalContext(request_id="r1", user="alice"))
        payload = ToolPreInvokePayload(name="tool", arguments={})

        r1 = await plugin.tool_pre_invoke(payload, ctx)
        r2 = await plugin.tool_pre_invoke(payload, ctx)

        remaining1 = int(r1.http_headers["X-RateLimit-Remaining"])
        remaining2 = int(r2.http_headers["X-RateLimit-Remaining"])
        assert remaining2 < remaining1

    @pytest.mark.asyncio
    async def test_token_bucket_refills_over_time(self, plugin):
        """Token bucket allows requests again after tokens refill."""
        ctx = PluginContext(global_context=GlobalContext(request_id="r1", user="alice"))
        payload = ToolPreInvokePayload(name="tool", arguments={})

        for _ in range(3):
            await plugin.tool_pre_invoke(payload, ctx)

        result = await plugin.tool_pre_invoke(payload, ctx)
        assert result.violation is not None

        await asyncio.sleep(1.1)

        result = await plugin.tool_pre_invoke(payload, ctx)
        assert result.violation is None

    @pytest.mark.asyncio
    async def test_token_bucket_independent_users(self, plugin):
        """Token bucket tracks separate buckets per user."""
        ctx_alice = PluginContext(global_context=GlobalContext(request_id="r1", user="alice"))
        ctx_bob = PluginContext(global_context=GlobalContext(request_id="r2", user="bob"))
        payload = ToolPreInvokePayload(name="tool", arguments={})

        for _ in range(3):
            await plugin.tool_pre_invoke(payload, ctx_alice)

        alice_blocked = await plugin.tool_pre_invoke(payload, ctx_alice)
        assert alice_blocked.violation is not None

        bob_allowed = await plugin.tool_pre_invoke(payload, ctx_bob)
        assert bob_allowed.violation is None


class TestCrossHookSharing:
    """Verify that prompt_pre_fetch and tool_pre_invoke share the same rate limit counters.

    Both hooks key by_user as 'user:{username}' and by_tenant as 'tenant:{tenant_id}'.
    A user consuming quota via one hook must be counted against the same bucket
    when using the other hook — the limit is per-identity, not per-hook.
    """

    @pytest.fixture
    def plugin(self):
        config = PluginConfig(
            name="RateLimiter",
            kind="cpex_rate_limiter.rate_limiter.RateLimiterPlugin",
            hooks=["prompt_pre_fetch", "tool_pre_invoke"],
            priority=100,
            config={"by_user": "5/s"},
        )
        return RateLimiterPlugin(config)

    @pytest.mark.asyncio
    async def test_prompt_and_tool_share_user_counter(self, plugin):
        """Requests via prompt_pre_fetch and tool_pre_invoke decrement the same user bucket."""
        ctx = PluginContext(global_context=GlobalContext(request_id="r1", user="alice"))
        prompt_payload = PromptPrehookPayload(prompt_id="p", args={})
        tool_payload = ToolPreInvokePayload(name="tool", arguments={})

        # 3 prompt requests
        for _ in range(3):
            result = await plugin.prompt_pre_fetch(prompt_payload, ctx)
            assert result.violation is None

        # 2 tool requests — total 5, still within limit
        for _ in range(2):
            result = await plugin.tool_pre_invoke(tool_payload, ctx)
            assert result.violation is None

        # 6th request (either hook) must be blocked
        result = await plugin.tool_pre_invoke(tool_payload, ctx)
        assert result.violation is not None, "6th request should be blocked — prompt and tool hooks must share the same user counter"

    @pytest.mark.asyncio
    async def test_remaining_count_decrements_across_hooks(self, plugin):
        """X-RateLimit-Remaining reflects consumption from both hooks."""
        ctx = PluginContext(global_context=GlobalContext(request_id="r1", user="alice"))
        prompt_payload = PromptPrehookPayload(prompt_id="p", args={})
        tool_payload = ToolPreInvokePayload(name="tool", arguments={})

        r1 = await plugin.prompt_pre_fetch(prompt_payload, ctx)
        remaining_after_prompt = int(r1.http_headers["X-RateLimit-Remaining"])

        r2 = await plugin.tool_pre_invoke(tool_payload, ctx)
        remaining_after_tool = int(r2.http_headers["X-RateLimit-Remaining"])

        assert remaining_after_tool < remaining_after_prompt, "Remaining count must decrease after a tool request following a prompt request — same shared counter"

    @pytest.mark.asyncio
    async def test_tenant_counter_shared_across_hooks_and_users(self, plugin):
        """Tenant bucket is shared across all users in the same tenant, regardless of hook."""
        config = PluginConfig(
            name="RateLimiter",
            kind="cpex_rate_limiter.rate_limiter.RateLimiterPlugin",
            hooks=["prompt_pre_fetch", "tool_pre_invoke"],
            priority=100,
            config={"by_user": "10/s", "by_tenant": "4/s"},
        )
        plugin = RateLimiterPlugin(config)

        ctx_alice = PluginContext(global_context=GlobalContext(request_id="r1", user="alice", tenant_id="team1"))
        ctx_bob = PluginContext(global_context=GlobalContext(request_id="r2", user="bob", tenant_id="team1"))

        # Alice: 2 prompt requests
        for _ in range(2):
            await plugin.prompt_pre_fetch(PromptPrehookPayload(prompt_id="p", args={}), ctx_alice)

        # Bob: 2 tool requests — total 4 for team1, tenant limit reached
        for _ in range(2):
            await plugin.tool_pre_invoke(ToolPreInvokePayload(name="tool", arguments={}), ctx_bob)

        # 5th request from either user must be blocked by tenant limit
        result = await plugin.prompt_pre_fetch(PromptPrehookPayload(prompt_id="p", args={}), ctx_alice)
        assert result.violation is not None, "Tenant limit must be enforced across both users and both hooks"


class TestTenantIsolation:
    """Tenant isolation tests across the GlobalContext shapes the plugin may
    receive from a gateway.

    Two input shapes are covered:
      - ``global_context.user`` as a ``dict`` (``{"email": ..., "is_admin":
        ..., "full_name": ...}``) vs as a plain ``str`` username.
      - ``global_context.tenant_id`` explicitly set vs ``None``.

    These tests document the plugin's behaviour under each combination so
    regressions are caught if bucket keying changes.  They do not attempt to
    pin down which combination the gateway produces today — that is the
    gateway's concern and is covered by gateway-side tests in mc-c-f.
    """

    @pytest.fixture
    def plugin(self):
        config = PluginConfig(
            name="RateLimiter",
            kind="cpex_rate_limiter.rate_limiter.RateLimiterPlugin",
            hooks=["tool_pre_invoke"],
            priority=100,
            config={"by_user": "3/s", "by_tenant": "5/s"},
        )
        return RateLimiterPlugin(config)

    @pytest.mark.asyncio
    async def test_user_dict_identity_is_rate_limited_independently(self, plugin):
        """When user is a dict, each distinct dict is a separate bucket.

        A gateway may pass ``global_context.user`` as a dict such as
        ``{"email": "alice@...", "is_admin": False, ...}``.  The rate limiter
        keys on ``str(user)``, so two distinct dicts must yield independent
        per-user counters.
        """
        alice_dict = {"email": "alice@example.com", "is_admin": False, "full_name": "Alice"}
        bob_dict = {"email": "bob@example.com", "is_admin": False, "full_name": "Bob"}

        ctx_alice = PluginContext(global_context=GlobalContext(request_id="r1", user=alice_dict))
        ctx_bob = PluginContext(global_context=GlobalContext(request_id="r2", user=bob_dict))
        payload = ToolPreInvokePayload(name="tool", arguments={})

        for _ in range(3):
            await plugin.tool_pre_invoke(payload, ctx_alice)

        alice_blocked = await plugin.tool_pre_invoke(payload, ctx_alice)
        assert alice_blocked.violation is not None, "Alice must be blocked after exhausting her limit"

        bob_allowed = await plugin.tool_pre_invoke(payload, ctx_bob)
        assert bob_allowed.violation is None, "Bob must have an independent counter — Alice's limit must not affect him"

    @pytest.mark.asyncio
    async def test_explicit_tenant_id_isolates_teams(self, plugin):
        """When tenant_id is explicitly set, different teams have independent tenant buckets.

        This is the behaviour a custom auth plugin would produce if it populates
        global_context.tenant_id from the JWT teams claim.
        """
        ctx_team1 = PluginContext(global_context=GlobalContext(request_id="r1", user="alice", tenant_id="team1"))
        ctx_team2 = PluginContext(global_context=GlobalContext(request_id="r2", user="bob", tenant_id="team2"))
        payload = ToolPreInvokePayload(name="tool", arguments={})

        # Exhaust team1's tenant limit (5/s)
        for _ in range(5):
            await plugin.tool_pre_invoke(payload, ctx_team1)

        team1_blocked = await plugin.tool_pre_invoke(payload, ctx_team1)
        assert team1_blocked.violation is not None, "team1 must be blocked after 5 requests"

        # team2 must be unaffected — its own counter starts at 0
        team2_allowed = await plugin.tool_pre_invoke(payload, ctx_team2)
        assert team2_allowed.violation is None, "team2 must have its own independent tenant bucket"

    @pytest.mark.asyncio
    async def test_anonymous_user_has_separate_bucket_from_authenticated(self, plugin):
        """Unauthenticated requests (user=None → 'anonymous') must not consume authenticated user quota."""
        ctx_anon = PluginContext(global_context=GlobalContext(request_id="r1", user=None))
        ctx_alice = PluginContext(global_context=GlobalContext(request_id="r2", user="alice"))
        payload = ToolPreInvokePayload(name="tool", arguments={})

        # Exhaust anonymous bucket
        for _ in range(3):
            await plugin.tool_pre_invoke(payload, ctx_anon)

        anon_blocked = await plugin.tool_pre_invoke(payload, ctx_anon)
        assert anon_blocked.violation is not None, "Anonymous bucket must be exhausted"

        # Alice must be unaffected
        alice_allowed = await plugin.tool_pre_invoke(payload, ctx_alice)
        assert alice_allowed.violation is None, "Authenticated user must have a separate bucket from anonymous"

    # ------------------------------------------------------------------
    # by_tenant behaviour when tenant_id is absent
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_none_tenant_id_skips_by_tenant_entirely(self):
        """When tenant_id is None, by_tenant must be skipped — not enforced against a shared 'default' bucket.

        Rationale: bucketing every tenant-less request into a single
        'tenant:default' bucket would cross-throttle unrelated users — worse
        than having no tenant limiting at all.  The plugin must treat
        tenant_id=None as "no tenant dimension configured for this request".
        Uses a high by_user limit so only by_tenant could trigger a block.
        """
        config = PluginConfig(
            name="RateLimiter",
            kind="cpex_rate_limiter.rate_limiter.RateLimiterPlugin",
            hooks=["tool_pre_invoke"],
            priority=100,
            config={"by_user": "100/s", "by_tenant": "5/s"},
        )
        plugin = RateLimiterPlugin(config)
        ctx = PluginContext(global_context=GlobalContext(request_id="r1", user="alice", tenant_id=None))
        payload = ToolPreInvokePayload(name="tool", arguments={})

        # by_tenant limit is 5/s; without a real tenant, no request should be
        # blocked by the tenant dimension regardless of how many we send.
        for i in range(7):
            result = await plugin.tool_pre_invoke(payload, ctx)
            assert result.violation is None, f"Request {i + 1}: by_tenant must be skipped when tenant_id is None — " "no request should be blocked by a phantom 'default' tenant bucket"

    @pytest.mark.asyncio
    async def test_multi_team_users_do_not_share_tenant_bucket(self, plugin):
        """Two users with tenant_id=None must not throttle each other via a shared 'default' bucket.

        This is the multi-tenant deployment correctness test: if alice and bob are
        from different organisations but both have tenant_id=None (e.g. multi-team
        API tokens), a fake 'default' bucket would cross-throttle them.  The plugin
        must skip by_tenant for both instead.
        """
        ctx_alice = PluginContext(global_context=GlobalContext(request_id="r1", user="alice", tenant_id=None))
        ctx_bob = PluginContext(global_context=GlobalContext(request_id="r2", user="bob", tenant_id=None))
        payload = ToolPreInvokePayload(name="tool", arguments={})

        # Alice sends 5 requests — tenant limit is 5/s
        for _ in range(5):
            await plugin.tool_pre_invoke(payload, ctx_alice)

        # Bob's first request must not be blocked — he should not share Alice's bucket
        bob_result = await plugin.tool_pre_invoke(payload, ctx_bob)
        assert bob_result.violation is None, "Bob must not be blocked by Alice's activity — " "users with tenant_id=None must not share a 'default' tenant bucket"

    @pytest.mark.asyncio
    async def test_explicit_tenant_scopes_correctly_after_fix(self):
        """P1: when tenant_id IS provided, by_tenant still enforces correctly.

        This is a regression guard: the fix must not break the case where tenant_id
        is explicitly set (e.g. by a custom auth plugin or future auth-layer fix).
        Uses a high by_user limit so only by_tenant can trigger a block.
        """
        config = PluginConfig(
            name="RateLimiter",
            kind="cpex_rate_limiter.rate_limiter.RateLimiterPlugin",
            hooks=["tool_pre_invoke"],
            priority=100,
            config={"by_user": "100/s", "by_tenant": "5/s"},
        )
        plugin = RateLimiterPlugin(config)
        ctx = PluginContext(global_context=GlobalContext(request_id="r1", user="alice", tenant_id="org-acme"))
        payload = ToolPreInvokePayload(name="tool", arguments={})

        for _ in range(5):
            result = await plugin.tool_pre_invoke(payload, ctx)
            assert result.violation is None

        blocked = await plugin.tool_pre_invoke(payload, ctx)
        assert blocked.violation is not None, "by_tenant must still enforce when tenant_id is explicitly set"


class TestNoLimitsAndMissingContext:
    """Behaviour when no limits are configured or GlobalContext fields are absent.

    These tests document the plugin's safe defaults so regressions are caught
    if the fallback logic in prompt_pre_fetch / tool_pre_invoke changes.
    """

    @pytest.mark.asyncio
    async def test_no_limits_configured_allows_all_requests(self):
        """Plugin with all dimensions None must allow every request without tracking."""
        config = PluginConfig(
            name="RateLimiter",
            kind="cpex_rate_limiter.rate_limiter.RateLimiterPlugin",
            hooks=["tool_pre_invoke"],
            config={},  # no by_user, no by_tenant, no by_tool
        )
        plugin = RateLimiterPlugin(config)
        ctx = PluginContext(global_context=GlobalContext(request_id="r1", user="alice"))
        payload = ToolPreInvokePayload(name="tool", arguments={})

        for _ in range(20):
            result = await plugin.tool_pre_invoke(payload, ctx)
            assert result.violation is None, "Unconfigured plugin must never block"

    @pytest.mark.asyncio
    async def test_no_limits_configured_returns_no_headers(self):
        """Plugin with no configured limits must not set X-RateLimit-* headers."""
        config = PluginConfig(
            name="RateLimiter",
            kind="cpex_rate_limiter.rate_limiter.RateLimiterPlugin",
            hooks=["tool_pre_invoke"],
            config={},
        )
        plugin = RateLimiterPlugin(config)
        ctx = PluginContext(global_context=GlobalContext(request_id="r1", user="alice"))
        payload = ToolPreInvokePayload(name="tool", arguments={})

        result = await plugin.tool_pre_invoke(payload, ctx)
        assert not result.http_headers, "No limits configured — X-RateLimit-* headers must not be present"

    @pytest.mark.asyncio
    async def test_both_user_and_tenant_none_still_enforces(self):
        """With both user=None and tenant_id=None the plugin must still enforce limits."""
        config = PluginConfig(
            name="RateLimiter",
            kind="cpex_rate_limiter.rate_limiter.RateLimiterPlugin",
            hooks=["tool_pre_invoke"],
            config={"by_user": "2/s", "by_tenant": "10/s"},
        )
        plugin = RateLimiterPlugin(config)
        ctx = PluginContext(global_context=GlobalContext(request_id="r1", user=None, tenant_id=None))
        payload = ToolPreInvokePayload(name="tool", arguments={})

        await plugin.tool_pre_invoke(payload, ctx)
        await plugin.tool_pre_invoke(payload, ctx)

        result = await plugin.tool_pre_invoke(payload, ctx)
        assert result.violation is not None, "With user=None and tenant_id=None the plugin must still enforce via anonymous/default buckets"

    @pytest.mark.asyncio
    async def test_separate_plugin_instances_have_independent_stores(self):
        """Two RateLimiterPlugin instances must never share backend state."""

        def make_plugin():
            return RateLimiterPlugin(
                PluginConfig(
                    name="RateLimiter",
                    kind="cpex_rate_limiter.rate_limiter.RateLimiterPlugin",
                    hooks=["tool_pre_invoke"],
                    config={"by_user": "2/s"},
                )
            )

        plugin_a = make_plugin()
        plugin_b = make_plugin()

        ctx = PluginContext(global_context=GlobalContext(request_id="r1", user="alice"))
        payload = ToolPreInvokePayload(name="tool", arguments={})

        # Exhaust plugin_a
        await plugin_a.tool_pre_invoke(payload, ctx)
        await plugin_a.tool_pre_invoke(payload, ctx)
        a_blocked = await plugin_a.tool_pre_invoke(payload, ctx)
        assert a_blocked.violation is not None

        # plugin_b must be completely unaffected
        b_allowed = await plugin_b.tool_pre_invoke(payload, ctx)
        assert b_allowed.violation is None, "Two plugin instances must have independent stores — exhausting one must not affect the other"


# =============================================================================
# Redis Backend Integration Tests
# =============================================================================
#
# These tests require a real Redis instance.  They are skipped automatically
# when Redis is not reachable and Docker cannot start one.  Each test flushes
# DB 15 before use to avoid cross-test contamination.
#
# Run with: uv run pytest tests/integration/test_rate_limiter.py -k Redis -v
# =============================================================================


def _redis_port_open(host: str = "127.0.0.1", port: int = 6379, timeout: float = 0.2) -> bool:
    """Return True if a TCP connection to host:port succeeds."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def _redis_responds_to_ping(host: str = "127.0.0.1", port: int = 6379, timeout: float = 0.5) -> bool:
    """Return True if Redis responds PONG to a PING.

    The Docker Redis container opens its TCP port before the server is
    ready to serve commands; waiting only on the port can race the first
    test.  Driving an end-to-end PING confirms readiness.
    """
    try:
        # Third-Party
        import redis as _redis_sync  # noqa: PLC0415 — same wheel as redis.asyncio
    except Exception:
        return False
    try:
        client = _redis_sync.Redis(
            host=host,
            port=port,
            socket_connect_timeout=timeout,
            socket_timeout=timeout,
        )
        try:
            return bool(client.ping())
        finally:
            try:
                client.close()
            except Exception:
                pass
    except Exception:
        return False


# Port constants.  The test container is bound to a non-standard host port so
# it never collides with — or silently reuses — a developer's local Redis on
# the default 6379.  Reusing localhost:6379 requires explicit opt-in via the
# ALLOW_LOCAL_REDIS=1 environment variable AND a successful PING.
_TEST_REDIS_HOST = "127.0.0.1"
_TEST_REDIS_CONTAINER_PORT = 16379
_LOCAL_REDIS_PORT = 6379


@pytest.fixture(scope="module")
def redis_url_for_integration():
    """Yield a Redis URL pointing at a real, hermetically verified Redis.

    Default behaviour: start a dedicated Docker container bound to host port
    16379 so the test suite never touches any Redis already running on the
    standard 6379 port.  A successful PING is required before the URL is
    yielded — the TCP port alone is not enough, since Redis accepts
    connections before it can serve commands.

    Opt-in reuse: if ``ALLOW_LOCAL_REDIS=1`` is set in the environment, the
    fixture will prefer an existing Redis on 127.0.0.1:6379, but only after
    a successful PING.  This avoids mistakenly FLUSHDB-ing a non-Redis
    listener, an auth-protected Redis, or a developer's real data.
    Flushing still targets DB 15 only.

    Skips the test module if neither path can produce a responsive Redis.
    """
    try:
        # Third-Party
        import redis.asyncio  # noqa: F401
    except Exception:
        pytest.skip("redis.asyncio package not installed")

    # Opt-in: reuse whatever Redis the developer has on the standard port,
    # but only if it answers PING.  Keeps CI and unsuspecting developers
    # safe by default; hands control to developers who want the speed of
    # skipping the docker spawn.
    if os.environ.get("ALLOW_LOCAL_REDIS") == "1":
        if _redis_port_open(_TEST_REDIS_HOST, _LOCAL_REDIS_PORT) and _redis_responds_to_ping(_TEST_REDIS_HOST, _LOCAL_REDIS_PORT):
            yield f"redis://{_TEST_REDIS_HOST}:{_LOCAL_REDIS_PORT}/15"  # DB 15 — isolated
            return

    # Default path: spawn a test-owned container on a dedicated host port.
    host, port = _TEST_REDIS_HOST, _TEST_REDIS_CONTAINER_PORT
    container_id = None
    try:
        res = subprocess.run(
            ["docker", "run", "-d", "--rm", "-p", f"{port}:6379", "--name", "pytest-rl-redis-integ", "redis:7"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        container_id = res.stdout.strip()
    except Exception as exc:
        pytest.skip(f"Docker unavailable for Redis container: {exc}")

    # Wait for both TCP and a successful PING.  Redis can accept TCP
    # connections before it is ready to serve commands; without the PING
    # check the first Redis-backed test races the server warmup on slower
    # runners and fails with ConnectionError.
    for _ in range(50):
        if _redis_port_open(host, port) and _redis_responds_to_ping(host, port):
            break
        time.sleep(0.1)
    else:
        if container_id:
            subprocess.run(["docker", "stop", container_id], check=False)
        pytest.skip("Redis did not become ready in time")

    yield f"redis://{host}:{port}/15"  # DB 15 — isolated from other data

    if container_id:
        subprocess.run(["docker", "stop", container_id], check=False)


def _make_redis_plugin(redis_url: str, algorithm: str = "fixed_window", limit: str = "3/s") -> RateLimiterPlugin:
    """Create a RateLimiterPlugin backed by real Redis."""
    return RateLimiterPlugin(
        PluginConfig(
            name="RateLimiter",
            kind="cpex_rate_limiter.rate_limiter.RateLimiterPlugin",
            hooks=["tool_pre_invoke"],
            priority=100,
            config={
                "by_user": limit,
                "backend": "redis",
                "redis_url": redis_url,
                "algorithm": algorithm,
            },
        )
    )


async def _flush_redis(redis_url: str) -> None:
    """Flush DB 15 before each test to ensure a clean slate."""
    # Third-Party
    import redis.asyncio as aioredis  # noqa: PLC0415

    client = aioredis.from_url(redis_url)
    await client.flushdb()
    await client.aclose()


async def _keys_in_redis(redis_url: str, pattern: str) -> list[str]:
    """Return all Redis keys matching the pattern. Used by isolation tests."""
    # Third-Party
    import redis.asyncio as aioredis  # noqa: PLC0415

    client = aioredis.from_url(redis_url, decode_responses=True)
    try:
        return sorted(await client.keys(pattern))
    finally:
        await client.aclose()


async def _count_redis_clients(redis_url: str) -> int:
    """Return the number of connected clients reported by Redis CLIENT LIST.

    Includes the monitoring client we open here, so callers use this as a
    relative measure (delta before/after an action), not an absolute count.
    """
    # Third-Party
    import redis.asyncio as aioredis  # noqa: PLC0415

    client = aioredis.from_url(redis_url, decode_responses=True)
    try:
        listing = await client.execute_command("CLIENT", "LIST")
        return len([line for line in listing.splitlines() if line.strip()])
    finally:
        await client.aclose()


class TestRedisBackendIntegration:
    """End-to-end integration tests for the Redis backend.

    Validates plugin wiring, shared-counter semantics, TTL/window reset
    behavior, and fallback behavior against a real Redis-backed gateway flow.
    """

    @pytest.mark.asyncio
    async def test_redis_plugin_enforces_limit(self, redis_url_for_integration):
        """Plugin wired to real Redis blocks on N+1 requests within the window."""
        await _flush_redis(redis_url_for_integration)

        plugin = _make_redis_plugin(redis_url_for_integration, algorithm="fixed_window", limit="3/s")
        ctx = PluginContext(global_context=GlobalContext(request_id="r1", user="alice"))
        payload = ToolPreInvokePayload(name="tool", arguments={})

        for _ in range(3):
            result = await plugin.tool_pre_invoke(payload, ctx)
            assert result.violation is None

        result = await plugin.tool_pre_invoke(payload, ctx)
        assert result.violation is not None
        assert result.violation.http_status_code == 429

    @pytest.mark.asyncio
    async def test_redis_shared_counter_across_plugin_instances(self, redis_url_for_integration):
        """Two plugin instances pointing at the same Redis share rate limit counters.

        This is the core multi-instance correctness test: after instance A exhausts
        the limit, instance B must be blocked because they share the same Redis key.
        """
        await _flush_redis(redis_url_for_integration)

        plugin_a = _make_redis_plugin(redis_url_for_integration, limit="3/s")
        plugin_b = _make_redis_plugin(redis_url_for_integration, limit="3/s")
        ctx = PluginContext(global_context=GlobalContext(request_id="r1", user="alice"))
        payload = ToolPreInvokePayload(name="tool", arguments={})

        for _ in range(3):
            result = await plugin_a.tool_pre_invoke(payload, ctx)
            assert result.violation is None

        result = await plugin_b.tool_pre_invoke(payload, ctx)
        assert result.violation is not None, "Redis backend must share counters across plugin instances — " "instance B must be blocked after instance A exhausts the limit"

    @pytest.mark.asyncio
    async def test_redis_window_resets_after_ttl(self, redis_url_for_integration):
        """After the rate window expires, Redis TTL resets counters and requests are allowed again."""
        await _flush_redis(redis_url_for_integration)

        plugin = _make_redis_plugin(redis_url_for_integration, algorithm="fixed_window", limit="2/s")
        ctx = PluginContext(global_context=GlobalContext(request_id="r1", user="alice"))
        payload = ToolPreInvokePayload(name="tool", arguments={})

        await plugin.tool_pre_invoke(payload, ctx)
        await plugin.tool_pre_invoke(payload, ctx)
        blocked = await plugin.tool_pre_invoke(payload, ctx)
        assert blocked.violation is not None

        # Wait for the 1-second window to expire via real Redis TTL
        await asyncio.sleep(1.1)

        result = await plugin.tool_pre_invoke(payload, ctx)
        assert result.violation is None, "After the rate window expires, Redis TTL must reset counters and allow fresh requests"

    @pytest.mark.asyncio
    async def test_unreachable_redis_fails_open(self):
        """Plugin fails open when Redis is unreachable — requests are allowed
        through without rate-limiting.  This is the plugin's documented
        design (README: "an infrastructure failure must never block
        legitimate traffic"), not a memory-backend fallback.

        We drive the number of calls past the configured limit so a
        regression that switched the plugin to fail-closed (blocking on
        backend errors) would surface as a violation on calls 4+.

        Limitation worth naming: the plugin's hook wrapper catches all
        exceptions and returns a blank success result, so this test can't
        distinguish "engine correctly fails open" from "engine crashed and
        the wrapper swallowed it".  The useful signal the assertions carry
        is the absence of a violation under sustained traffic — enough to
        catch a fail-closed regression, not enough to verify the error path.
        """
        plugin = _make_redis_plugin("redis://127.0.0.1:19999/0", limit="3/s")
        ctx = PluginContext(global_context=GlobalContext(request_id="r1", user="alice"))
        payload = ToolPreInvokePayload(name="tool", arguments={})

        # Five calls — two above the configured 3/s limit.  Fail-open means
        # none of them are blocked; none of them raise.
        for i in range(5):
            result = await plugin.tool_pre_invoke(payload, ctx)
            assert result.violation is None, f"Request {i + 1}: plugin must fail open when Redis is unavailable"
            assert result.continue_processing is not False

    # ------------------------------------------------------------------
    # sliding_window on real Redis
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_redis_sliding_window_enforces_limit(self, redis_url_for_integration):
        """sliding_window on real Redis blocks on N+1 requests within the window."""
        await _flush_redis(redis_url_for_integration)

        plugin = _make_redis_plugin(redis_url_for_integration, algorithm="sliding_window", limit="3/s")
        ctx = PluginContext(global_context=GlobalContext(request_id="r1", user="alice"))
        payload = ToolPreInvokePayload(name="tool", arguments={})

        for _ in range(3):
            result = await plugin.tool_pre_invoke(payload, ctx)
            assert result.violation is None

        result = await plugin.tool_pre_invoke(payload, ctx)
        assert result.violation is not None
        assert result.violation.http_status_code == 429

    @pytest.mark.asyncio
    async def test_redis_sliding_window_shared_counter_across_instances(self, redis_url_for_integration):
        """Two sliding_window plugin instances share counters via Redis.

        After instance A exhausts the limit, instance B must be blocked because
        they share the same Redis sorted-set key.
        """
        await _flush_redis(redis_url_for_integration)

        plugin_a = _make_redis_plugin(redis_url_for_integration, algorithm="sliding_window", limit="3/s")
        plugin_b = _make_redis_plugin(redis_url_for_integration, algorithm="sliding_window", limit="3/s")
        ctx = PluginContext(global_context=GlobalContext(request_id="r1", user="alice"))
        payload = ToolPreInvokePayload(name="tool", arguments={})

        for _ in range(3):
            result = await plugin_a.tool_pre_invoke(payload, ctx)
            assert result.violation is None

        result = await plugin_b.tool_pre_invoke(payload, ctx)
        assert result.violation is not None, "sliding_window Redis backend must share counters across instances — " "instance B must be blocked after instance A exhausts the limit"

    @pytest.mark.asyncio
    async def test_redis_sliding_window_resets_after_window(self, redis_url_for_integration):
        """After the sliding window elapses, Redis TTL resets the sorted set and requests are allowed again."""
        await _flush_redis(redis_url_for_integration)

        plugin = _make_redis_plugin(redis_url_for_integration, algorithm="sliding_window", limit="2/s")
        ctx = PluginContext(global_context=GlobalContext(request_id="r1", user="alice"))
        payload = ToolPreInvokePayload(name="tool", arguments={})

        await plugin.tool_pre_invoke(payload, ctx)
        await plugin.tool_pre_invoke(payload, ctx)
        blocked = await plugin.tool_pre_invoke(payload, ctx)
        assert blocked.violation is not None

        await asyncio.sleep(1.1)

        result = await plugin.tool_pre_invoke(payload, ctx)
        assert result.violation is None, "After the sliding window elapses, Redis TTL must reset the sorted set and allow fresh requests"

    # ------------------------------------------------------------------
    # token_bucket on real Redis
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_redis_token_bucket_enforces_limit(self, redis_url_for_integration):
        """token_bucket on real Redis blocks when bucket is empty."""
        await _flush_redis(redis_url_for_integration)

        plugin = _make_redis_plugin(redis_url_for_integration, algorithm="token_bucket", limit="3/s")
        ctx = PluginContext(global_context=GlobalContext(request_id="r1", user="alice"))
        payload = ToolPreInvokePayload(name="tool", arguments={})

        for _ in range(3):
            result = await plugin.tool_pre_invoke(payload, ctx)
            assert result.violation is None

        result = await plugin.tool_pre_invoke(payload, ctx)
        assert result.violation is not None
        assert result.violation.http_status_code == 429

    @pytest.mark.asyncio
    async def test_redis_token_bucket_shared_counter_across_instances(self, redis_url_for_integration):
        """Two token_bucket plugin instances share bucket state via Redis.

        After instance A drains the bucket, instance B must be blocked because
        they share the same Redis hash key.
        """
        await _flush_redis(redis_url_for_integration)

        plugin_a = _make_redis_plugin(redis_url_for_integration, algorithm="token_bucket", limit="3/s")
        plugin_b = _make_redis_plugin(redis_url_for_integration, algorithm="token_bucket", limit="3/s")
        ctx = PluginContext(global_context=GlobalContext(request_id="r1", user="alice"))
        payload = ToolPreInvokePayload(name="tool", arguments={})

        for _ in range(3):
            result = await plugin_a.tool_pre_invoke(payload, ctx)
            assert result.violation is None

        result = await plugin_b.tool_pre_invoke(payload, ctx)
        assert result.violation is not None, "token_bucket Redis backend must share bucket state across instances — " "instance B must be blocked after instance A drains the bucket"

    @pytest.mark.asyncio
    async def test_redis_token_bucket_refills_over_time(self, redis_url_for_integration):
        """After the bucket drains, tokens refill over time and requests are allowed again."""
        await _flush_redis(redis_url_for_integration)

        plugin = _make_redis_plugin(redis_url_for_integration, algorithm="token_bucket", limit="2/s")
        ctx = PluginContext(global_context=GlobalContext(request_id="r1", user="alice"))
        payload = ToolPreInvokePayload(name="tool", arguments={})

        await plugin.tool_pre_invoke(payload, ctx)
        await plugin.tool_pre_invoke(payload, ctx)
        blocked = await plugin.tool_pre_invoke(payload, ctx)
        assert blocked.violation is not None

        await asyncio.sleep(1.1)

        result = await plugin.tool_pre_invoke(payload, ctx)
        assert result.violation is None, "After tokens refill over time, token_bucket Redis backend must allow requests again"


class TestRedisTenantIsolation:
    """Tenant-scoped Redis key isolation (G2).

    Without tenant-scoped keys, the same user hitting two different teams
    through the same Redis would share a single ``rl:user:alice:*`` counter —
    Team A's strict limit would poison Team B. The fix prefixes dimension
    keys with the tenant id so counters are isolated per tenant.
    """

    @pytest.mark.asyncio
    async def test_same_user_different_tenants_isolated_in_redis(self, redis_url_for_integration):
        """Same user, two tenant ids, one Redis → independent per-user counters."""
        await _flush_redis(redis_url_for_integration)

        plugin = _make_redis_plugin(redis_url_for_integration, limit="3/s")
        payload = ToolPreInvokePayload(name="tool", arguments={})
        ctx_team_a = PluginContext(global_context=GlobalContext(request_id="r1", user="alice", tenant_id="team_a"))
        ctx_team_b = PluginContext(global_context=GlobalContext(request_id="r2", user="alice", tenant_id="team_b"))

        # Exhaust alice's limit under team_a.
        for _ in range(3):
            result = await plugin.tool_pre_invoke(payload, ctx_team_a)
            assert result.violation is None, "team_a: requests within limit must be allowed"
        blocked = await plugin.tool_pre_invoke(payload, ctx_team_a)
        assert blocked.violation is not None, "team_a: 4th request must be blocked"

        # Same user under team_b must not be affected.
        result = await plugin.tool_pre_invoke(payload, ctx_team_b)
        assert result.violation is None, "team_b: alice must have an independent counter — team_a's limit must not bleed across tenants"

        # Key-shape proof: the two tenants occupy disjoint key namespaces in Redis.
        keys_team_a = await _keys_in_redis(redis_url_for_integration, "rl:team_a:user:alice:*")
        keys_team_b = await _keys_in_redis(redis_url_for_integration, "rl:team_b:user:alice:*")
        assert keys_team_a, f"expected team_a-prefixed key, got none. keys_team_a={keys_team_a}"
        assert keys_team_b, f"expected team_b-prefixed key, got none. keys_team_b={keys_team_b}"
        assert set(keys_team_a).isdisjoint(set(keys_team_b)), "team_a and team_b key sets must not overlap"


class TestRedisLifecycle:
    """Plugin-manager lifecycle compliance (G3, G10).

    When the plugin framework disables a plugin it calls ``await plugin.shutdown()``;
    when it re-enables, a fresh instance is constructed. A compliant Redis-backed
    plugin must release its cached connection on shutdown so the old instance
    doesn't leak sockets while the new one opens its own.
    """

    @pytest.mark.asyncio
    async def test_initialize_logs_backend(self, redis_url_for_integration, caplog):
        """plugin.initialize() emits a log record identifying the active backend."""
        import logging  # noqa: PLC0415

        plugin = _make_redis_plugin(redis_url_for_integration, limit="5/s")

        with caplog.at_level(logging.INFO, logger="cpex_rate_limiter.rate_limiter"):
            await plugin.initialize()

        matches = [r for r in caplog.records if "initialized" in r.getMessage() and "redis" in r.getMessage()]
        assert matches, (
            "plugin.initialize() must log a record mentioning the backend so operators can confirm the plugin is live — "
            f"captured records: {[r.getMessage() for r in caplog.records]}"
        )

    @pytest.mark.asyncio
    async def test_shutdown_releases_redis_connection(self, redis_url_for_integration):
        """After plugin.shutdown(), the Redis connection cached by the Rust core is dropped."""
        await _flush_redis(redis_url_for_integration)

        plugin = _make_redis_plugin(redis_url_for_integration, limit="5/s")
        ctx = PluginContext(global_context=GlobalContext(request_id="r1", user="alice"))
        payload = ToolPreInvokePayload(name="tool", arguments={})

        # Warm the connection — the Rust core opens Redis lazily on first request.
        await plugin.tool_pre_invoke(payload, ctx)

        clients_before = await _count_redis_clients(redis_url_for_integration)

        await plugin.shutdown()

        # Allow the TCP close to propagate to the server's client list.
        await asyncio.sleep(0.2)
        clients_after = await _count_redis_clients(redis_url_for_integration)

        assert clients_after < clients_before, (
            "plugin.shutdown() must release the Rust core's cached Redis connection — "
            f"expected fewer clients after shutdown, got before={clients_before} after={clients_after}"
        )


def _make_redis_plugin_with_config(redis_url: str, extra_config: dict) -> RateLimiterPlugin:
    """Redis-backed plugin with caller-supplied extra config keys (e.g. fail_mode)."""
    base = {
        "by_user": "3/s",
        "backend": "redis",
        "redis_url": redis_url,
        "algorithm": "fixed_window",
    }
    base.update(extra_config)
    return RateLimiterPlugin(
        PluginConfig(
            name="RateLimiter",
            kind="cpex_rate_limiter.rate_limiter.RateLimiterPlugin",
            hooks=["tool_pre_invoke"],
            priority=100,
            config=base,
        )
    )


# A Redis URL that parses fine but points at a port where nothing listens.
# Used by fail-mode tests to trigger a backend error deterministically
# without depending on Docker being slow or flaky.
_DEAD_REDIS_URL = "redis://127.0.0.1:1/15"


class TestRedisFailModeAndViolationContext:
    """Fail-mode policy and violation context (G4, G7, G8, G14).

    When the Redis backend is unreachable, the plugin must either fail open
    (default) or fail closed (opt-in via fail_mode="closed") — and in both
    cases an operator-visible log record must describe what happened. When
    the plugin blocks a request the violation must carry enough context
    (tenant_id, user_id) for downstream debugging.
    """

    @pytest.mark.asyncio
    async def test_redis_unreachable_default_fail_open_logs_warning(self, caplog):
        """Unreachable backend + default fail_mode: request is allowed AND a WARNING is logged."""
        import logging  # noqa: PLC0415

        plugin = RateLimiterPlugin(
            PluginConfig(
                name="RateLimiter",
                kind="cpex_rate_limiter.rate_limiter.RateLimiterPlugin",
                hooks=["tool_pre_invoke"],
                priority=100,
                config={"by_user": "3/s", "backend": "redis", "redis_url": _DEAD_REDIS_URL},
            )
        )
        ctx = PluginContext(global_context=GlobalContext(request_id="r1", user="alice"))
        payload = ToolPreInvokePayload(name="tool", arguments={})

        with caplog.at_level(logging.WARNING, logger="cpex_rate_limiter.rate_limiter"):
            result = await plugin.tool_pre_invoke(payload, ctx)

        assert result.violation is None, "default fail_mode=open: unreachable backend must not block"
        warnings = [r for r in caplog.records if r.levelno >= logging.WARNING]
        assert warnings, (
            "backend failures must be logged at WARNING or higher so operators notice silent fail-open — "
            f"captured records: {[(r.levelname, r.getMessage()) for r in caplog.records]}"
        )

    @pytest.mark.asyncio
    async def test_redis_unreachable_fail_mode_closed_blocks(self):
        """fail_mode=closed: unreachable backend blocks the request with BACKEND_UNAVAILABLE."""
        plugin = _make_redis_plugin_with_config(_DEAD_REDIS_URL, {"fail_mode": "closed"})
        ctx = PluginContext(global_context=GlobalContext(request_id="r1", user="alice"))
        payload = ToolPreInvokePayload(name="tool", arguments={})

        result = await plugin.tool_pre_invoke(payload, ctx)

        assert result.violation is not None, "fail_mode=closed must block when the backend is unreachable"
        assert result.violation.code == "BACKEND_UNAVAILABLE", (
            f"expected code=BACKEND_UNAVAILABLE, got {result.violation.code!r}"
        )

    @pytest.mark.asyncio
    async def test_violation_details_includes_tenant_and_user(self, redis_url_for_integration):
        """Blocked requests carry tenant_id + user_id in violation.details for downstream debugging."""
        await _flush_redis(redis_url_for_integration)

        plugin = _make_redis_plugin(redis_url_for_integration, limit="2/s")
        ctx = PluginContext(
            global_context=GlobalContext(request_id="r1", user="alice@example.com", tenant_id="team_a")
        )
        payload = ToolPreInvokePayload(name="tool", arguments={})

        await plugin.tool_pre_invoke(payload, ctx)
        await plugin.tool_pre_invoke(payload, ctx)
        blocked = await plugin.tool_pre_invoke(payload, ctx)

        assert blocked.violation is not None, "3rd request must be blocked"
        details = blocked.violation.details or {}
        assert details.get("tenant_id") == "team_a", (
            f"violation.details must carry tenant_id; got details={details!r}"
        )
        assert details.get("user_id") == "alice@example.com", (
            f"violation.details must carry user_id; got details={details!r}"
        )

    @pytest.mark.asyncio
    async def test_invalid_fail_mode_logs_warning_and_defaults_open(self, redis_url_for_integration, caplog):
        """Typos like 'clsoed' must WARN and default to fail-open, not silently disable.

        Before the strict parser, anything that didn't case-insensitively
        equal 'closed' silently became fail-open — including obvious
        typos — which undermined the point of having a fail-closed knob.
        Operators get no signal that their configured policy isn't the
        one being applied. After the fix, unknown values are rejected
        with a WARN log so the typo surfaces at init time.
        """
        import logging  # noqa: PLC0415

        with caplog.at_level(logging.WARNING):
            plugin = _make_redis_plugin_with_config(redis_url_for_integration, {"fail_mode": "clsoed"})

        warnings = [
            r for r in caplog.records
            if r.levelno >= logging.WARNING
            and "fail_mode" in r.getMessage()
            and "clsoed" in r.getMessage()
        ]
        assert warnings, (
            "invalid fail_mode must emit a WARN naming both the field and the bad value; "
            f"captured records: {[(r.levelname, r.getMessage()) for r in caplog.records]}"
        )

        # Behaviour: fall back to fail-open (not fail-closed, not crash).
        ctx = PluginContext(global_context=GlobalContext(request_id="r1", user="alice"))
        payload = ToolPreInvokePayload(name="tool", arguments={})
        # Deliberately hit the happy path — limit is 3/s, one request stays well under.
        result = await plugin.tool_pre_invoke(payload, ctx)
        assert result.violation is None, "invalid fail_mode must default to fail-open, not block"

    @pytest.mark.asyncio
    async def test_allowed_request_metadata_does_not_carry_identity(self, redis_url_for_integration):
        """Allowed responses must NOT carry user_id / tenant_id in metadata.

        Identity fields belong on the block path (violation.details) so
        operators can see who triggered a 429. Exposing them on every
        allowed response widens identity leak surface to downstream
        consumers that inspect plugin metadata and bloats the hot path
        with data no caller needs.
        """
        await _flush_redis(redis_url_for_integration)

        plugin = _make_redis_plugin(redis_url_for_integration, limit="5/s")
        ctx = PluginContext(
            global_context=GlobalContext(request_id="r1", user="alice@example.com", tenant_id="team_a")
        )
        payload = ToolPreInvokePayload(name="tool", arguments={})

        result = await plugin.tool_pre_invoke(payload, ctx)

        assert result.violation is None, "request under limit must be allowed"
        metadata = result.metadata or {}
        assert "user_id" not in metadata, (
            f"allowed response must not carry user_id in metadata; got metadata={metadata!r}"
        )
        assert "tenant_id" not in metadata, (
            f"allowed response must not carry tenant_id in metadata; got metadata={metadata!r}"
        )


class TestConfigHardening:
    """Config hardening (G13, G15).

    The plugin must reject obviously-misconfigured rate strings and warn
    when the operator passes a key the engine doesn't understand (typos
    surface visibly instead of silently being ignored).
    """

    @pytest.mark.asyncio
    async def test_unknown_config_key_emits_warning(self, redis_url_for_integration, caplog):
        """Misspelled config keys (e.g. 'redis_ur') log a WARNING so the operator notices."""
        import logging  # noqa: PLC0415

        with caplog.at_level(logging.WARNING):
            RateLimiterPlugin(
                PluginConfig(
                    name="RateLimiter",
                    kind="cpex_rate_limiter.rate_limiter.RateLimiterPlugin",
                    hooks=["tool_pre_invoke"],
                    priority=100,
                    config={
                        "by_user": "3/s",
                        "backend": "redis",
                        "redis_url": redis_url_for_integration,
                        "redis_ur": "typo-key",  # misspelled
                    },
                )
            )

        warnings = [
            r for r in caplog.records
            if r.levelno >= logging.WARNING and "redis_ur" in r.getMessage()
        ]
        assert warnings, (
            "engine must warn on unknown config keys so misspellings are visible — "
            f"captured records: {[(r.levelname, r.getMessage()) for r in caplog.records]}"
        )
