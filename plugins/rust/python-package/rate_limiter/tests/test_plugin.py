"""End-to-end tests for RateLimiterPlugin using the real Rust engine."""

import pytest

from mcpgateway_mock.plugins.framework import (
    GlobalContext,
    PluginConfig,
    PluginContext,
    PromptPrehookPayload,
    ToolPreInvokePayload,
)

from cpex_rate_limiter.rate_limiter import RateLimiterPlugin


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_config(**overrides) -> PluginConfig:
    """Build a PluginConfig with sensible defaults for testing."""
    config = {
        "by_user": "5/s",
        "algorithm": "fixed_window",
        "backend": "memory",
    }
    config.update(overrides)
    return PluginConfig(name="rate_limiter", config=config)


def _make_context(user="testuser", tenant_id="tenant-1") -> PluginContext:
    return PluginContext(
        global_context=GlobalContext(user=user, tenant_id=tenant_id),
    )


# ---------------------------------------------------------------------------
# Plugin construction
# ---------------------------------------------------------------------------


class TestPluginInit:
    """Validate plugin construction and config validation."""

    def test_basic_construction(self):
        plugin = RateLimiterPlugin(_make_config())
        assert plugin is not None

    def test_all_algorithms(self):
        for algo in ("fixed_window", "sliding_window", "token_bucket"):
            plugin = RateLimiterPlugin(_make_config(algorithm=algo))
            assert plugin is not None

    def test_invalid_algorithm_raises(self):
        with pytest.raises(ValueError, match="algorithm"):
            RateLimiterPlugin(_make_config(algorithm="bogus"))

    def test_invalid_backend_raises(self):
        with pytest.raises(ValueError, match="backend"):
            RateLimiterPlugin(_make_config(backend="memcached"))

    def test_invalid_rate_string_raises(self):
        with pytest.raises(ValueError, match="by_user"):
            RateLimiterPlugin(_make_config(by_user="not-a-rate"))

    def test_invalid_by_tool_rate_raises(self):
        with pytest.raises(ValueError, match="by_tool"):
            RateLimiterPlugin(_make_config(by_tool={"search": "bad"}))

    def test_no_limits_configured(self):
        cfg = PluginConfig(name="rate_limiter", config={
            "algorithm": "fixed_window",
            "backend": "memory",
        })
        plugin = RateLimiterPlugin(cfg)
        assert plugin is not None


# ---------------------------------------------------------------------------
# tool_pre_invoke hook
# ---------------------------------------------------------------------------


class TestToolPreInvoke:
    """Exercise the tool_pre_invoke hook end-to-end."""

    @pytest.fixture
    def plugin(self):
        return RateLimiterPlugin(_make_config(by_user="5/s"))

    async def test_allowed_under_limit(self, plugin):
        payload = ToolPreInvokePayload(name="search")
        context = _make_context()
        result = await plugin.tool_pre_invoke(payload, context)
        assert result.continue_processing is True
        assert result.violation is None

    async def test_blocked_over_limit(self, plugin):
        payload = ToolPreInvokePayload(name="search")
        context = _make_context()
        # Exhaust the 5/s limit
        for _ in range(5):
            result = await plugin.tool_pre_invoke(payload, context)
            assert result.continue_processing is True
        # 6th request should be blocked
        result = await plugin.tool_pre_invoke(payload, context)
        assert result.continue_processing is False
        assert result.violation is not None
        assert result.violation.http_status_code == 429
        assert result.violation.code == "RATE_LIMIT"

    async def test_different_users_independent(self, plugin):
        payload = ToolPreInvokePayload(name="search")
        # Exhaust limit for user A
        for _ in range(5):
            await plugin.tool_pre_invoke(payload, _make_context(user="userA"))
        # User B should still be allowed
        result = await plugin.tool_pre_invoke(payload, _make_context(user="userB"))
        assert result.continue_processing is True

    async def test_dict_user_identity_uses_email_before_other_fields(self, plugin):
        payload = ToolPreInvokePayload(name="search")
        for _ in range(5):
            await plugin.tool_pre_invoke(
                payload,
                _make_context(user={"email": "same@example.com", "id": "ignored"}),
            )
        result = await plugin.tool_pre_invoke(
            payload,
            _make_context(user={"email": "same@example.com", "id": "different"}),
        )
        assert result.continue_processing is False

    async def test_non_string_user_identity_is_stringified(self):
        plugin = RateLimiterPlugin(_make_config(by_user="1/s"))
        payload = ToolPreInvokePayload(name="search")

        first = await plugin.tool_pre_invoke(payload, _make_context(user=42))
        second = await plugin.tool_pre_invoke(payload, _make_context(user=42))

        assert first.continue_processing is True
        assert second.continue_processing is False

    async def test_dict_user_identity_falls_back_to_numeric_id(self):
        plugin = RateLimiterPlugin(_make_config(by_user="1/s"))
        payload = ToolPreInvokePayload(name="search")

        first = await plugin.tool_pre_invoke(
            payload,
            _make_context(user={"id": 42}),
        )
        second = await plugin.tool_pre_invoke(
            payload,
            _make_context(user={"id": 42}),
        )

        assert first.continue_processing is True
        assert second.continue_processing is False

    async def test_dict_user_identity_falls_back_to_sub(self):
        plugin = RateLimiterPlugin(_make_config(by_user="1/s"))
        payload = ToolPreInvokePayload(name="search")

        first = await plugin.tool_pre_invoke(
            payload,
            _make_context(user={"email": "   ", "id": None, "sub": "subject-42"}),
        )
        second = await plugin.tool_pre_invoke(
            payload,
            _make_context(user={"sub": "subject-42"}),
        )

        assert first.continue_processing is True
        assert second.continue_processing is False

    async def test_blank_user_identity_defaults_to_anonymous(self):
        plugin = RateLimiterPlugin(_make_config(by_user="1/s"))
        payload = ToolPreInvokePayload(name="search")

        first = await plugin.tool_pre_invoke(payload, _make_context(user="   "))
        second = await plugin.tool_pre_invoke(payload, _make_context(user=""))

        assert first.continue_processing is True
        assert second.continue_processing is False

    async def test_none_user_identity_defaults_to_anonymous(self):
        plugin = RateLimiterPlugin(_make_config(by_user="1/s"))
        payload = ToolPreInvokePayload(name="search")

        first = await plugin.tool_pre_invoke(payload, _make_context(user=None))
        second = await plugin.tool_pre_invoke(payload, _make_context(user=None))

        assert first.continue_processing is True
        assert second.continue_processing is False

    async def test_headers_present_when_allowed(self, plugin):
        payload = ToolPreInvokePayload(name="search")
        context = _make_context()
        result = await plugin.tool_pre_invoke(payload, context)
        assert result.http_headers is not None

    async def test_retry_after_stripped_when_allowed(self, plugin):
        payload = ToolPreInvokePayload(name="search")
        context = _make_context()
        result = await plugin.tool_pre_invoke(payload, context)
        if result.http_headers:
            assert "Retry-After" not in result.http_headers

    async def test_retry_after_present_when_blocked(self, plugin):
        payload = ToolPreInvokePayload(name="search")
        context = _make_context()
        for _ in range(5):
            await plugin.tool_pre_invoke(payload, context)
        result = await plugin.tool_pre_invoke(payload, context)
        assert result.violation is not None
        assert result.violation.http_headers.get("Retry-After")


# ---------------------------------------------------------------------------
# prompt_pre_fetch hook
# ---------------------------------------------------------------------------


class TestPromptPreFetch:
    """Exercise the prompt_pre_fetch hook end-to-end."""

    @pytest.fixture
    def plugin(self):
        return RateLimiterPlugin(_make_config(by_user="3/s"))

    async def test_allowed_under_limit(self, plugin):
        payload = PromptPrehookPayload(prompt_id="my-prompt")
        context = _make_context()
        result = await plugin.prompt_pre_fetch(payload, context)
        assert result.continue_processing is True
        assert result.violation is None

    async def test_blocked_over_limit(self, plugin):
        payload = PromptPrehookPayload(prompt_id="my-prompt")
        context = _make_context()
        for _ in range(3):
            await plugin.prompt_pre_fetch(payload, context)
        result = await plugin.prompt_pre_fetch(payload, context)
        assert result.continue_processing is False
        assert result.violation is not None
        assert result.violation.http_status_code == 429


# ---------------------------------------------------------------------------
# by_tenant limiting
# ---------------------------------------------------------------------------


class TestByTenant:
    """Verify tenant-scoped rate limiting."""

    @pytest.fixture
    def plugin(self):
        return RateLimiterPlugin(_make_config(by_user=None, by_tenant="3/s"))

    async def test_tenant_limit_enforced(self, plugin):
        payload = ToolPreInvokePayload(name="search")
        # Different users, same tenant — share the tenant bucket
        for i in range(3):
            result = await plugin.tool_pre_invoke(
                payload, _make_context(user=f"user{i}", tenant_id="shared-tenant"),
            )
            assert result.continue_processing is True
        result = await plugin.tool_pre_invoke(
            payload, _make_context(user="user99", tenant_id="shared-tenant"),
        )
        assert result.continue_processing is False

    async def test_different_tenants_independent(self, plugin):
        payload = ToolPreInvokePayload(name="search")
        for _ in range(3):
            await plugin.tool_pre_invoke(
                payload, _make_context(user="u", tenant_id="tenantA"),
            )
        # tenantB should still be allowed
        result = await plugin.tool_pre_invoke(
            payload, _make_context(user="u", tenant_id="tenantB"),
        )
        assert result.continue_processing is True


# ---------------------------------------------------------------------------
# by_tool limiting
# ---------------------------------------------------------------------------


class TestByTool:
    """Verify per-tool rate limiting."""

    @pytest.fixture
    def plugin(self):
        return RateLimiterPlugin(_make_config(
            by_user=None,
            by_tool={"expensive": "2/s"},
        ))

    async def test_tool_limit_enforced(self, plugin):
        payload = ToolPreInvokePayload(name="expensive")
        context = _make_context()
        for _ in range(2):
            result = await plugin.tool_pre_invoke(payload, context)
            assert result.continue_processing is True
        result = await plugin.tool_pre_invoke(payload, context)
        assert result.continue_processing is False

    async def test_unlisted_tool_not_limited(self, plugin):
        payload = ToolPreInvokePayload(name="cheap")
        context = _make_context()
        for _ in range(20):
            result = await plugin.tool_pre_invoke(payload, context)
        assert result.metadata.get("limited") is False


# ---------------------------------------------------------------------------
# Fail-open behaviour
# ---------------------------------------------------------------------------


class TestFailOpen:
    """Verify the plugin allows requests when the engine errors."""

    async def test_tool_pre_invoke_fail_open(self, monkeypatch):
        plugin = RateLimiterPlugin(_make_config(by_user="5/s"))
        class ExplodingCore:
            async def tool_pre_invoke(self, payload, context):
                raise RuntimeError("boom")

        plugin._core = ExplodingCore()
        payload = ToolPreInvokePayload(name="search")
        context = _make_context()
        result = await plugin.tool_pre_invoke(payload, context)
        assert result.continue_processing is True

    async def test_prompt_pre_fetch_fail_open(self, monkeypatch):
        plugin = RateLimiterPlugin(_make_config(by_user="5/s"))
        class ExplodingCore:
            async def prompt_pre_fetch(self, payload, context):
                raise RuntimeError("boom")

        plugin._core = ExplodingCore()
        payload = PromptPrehookPayload(prompt_id="my-prompt")
        context = _make_context()
        result = await plugin.prompt_pre_fetch(payload, context)
        assert result.continue_processing is True

    async def test_redis_backend_async_fail_open(self):
        plugin = RateLimiterPlugin(_make_config(
            by_user="1/s",
            backend="redis",
            redis_url="redis://127.0.0.1:1/0",
        ))
        payload = ToolPreInvokePayload(name="search")
        context = _make_context()
        result = await plugin.tool_pre_invoke(payload, context)
        assert result.continue_processing is True


# ---------------------------------------------------------------------------
# Algorithms (smoke tests — detailed algorithm testing belongs in Rust)
# ---------------------------------------------------------------------------


class TestAlgorithms:
    """Smoke-test each algorithm through the Python plugin layer."""

    @pytest.mark.parametrize("algorithm", ["fixed_window", "sliding_window", "token_bucket"])
    async def test_algorithm_allows_then_blocks(self, algorithm):
        plugin = RateLimiterPlugin(_make_config(by_user="3/s", algorithm=algorithm))
        payload = ToolPreInvokePayload(name="search")
        context = _make_context()
        for _ in range(3):
            result = await plugin.tool_pre_invoke(payload, context)
            assert result.continue_processing is True
        result = await plugin.tool_pre_invoke(payload, context)
        assert result.continue_processing is False
