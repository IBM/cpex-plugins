"""Behavioral normalization tests for Rust-owned rate parsing."""

from cpex.framework import (
    GlobalContext,
    PluginConfig,
    PluginContext,
    ToolPreInvokePayload,
)

from cpex_rate_limiter.rate_limiter import RateLimiterPlugin, _parse_rate


def _context(user="testuser", tenant_id="tenant-1") -> PluginContext:
    return PluginContext(global_context=GlobalContext(user=user, tenant_id=tenant_id))


class TestRateParsingBehavior:
    """Verify rate strings are parsed and normalized through the public plugin."""

    def test_module_level_parse_rate_compatibility(self):
        assert _parse_rate("60/sec") == (60, 1)
        assert _parse_rate("10/ MIN") == (10, 60)

    async def test_unit_whitespace_and_case_are_accepted(self):
        plugin = RateLimiterPlugin(PluginConfig(
            name="rate_limiter",
            config={
                "by_user": "2/ MIN",
                "algorithm": "fixed_window",
                "backend": "memory",
            },
        ))
        payload = ToolPreInvokePayload(name="search")
        context = _context()

        first = await plugin.tool_pre_invoke(payload, context)
        second = await plugin.tool_pre_invoke(payload, context)
        third = await plugin.tool_pre_invoke(payload, context)

        assert first.continue_processing is True
        assert second.continue_processing is True
        assert third.continue_processing is False

    async def test_by_tool_keys_are_trimmed_and_casefolded(self):
        plugin = RateLimiterPlugin(PluginConfig(
            name="rate_limiter",
            config={
                "by_tool": {"  Expensive  ": "2/s"},
                "algorithm": "fixed_window",
                "backend": "memory",
            },
        ))
        context = _context()

        first = await plugin.tool_pre_invoke(ToolPreInvokePayload(name="expensive"), context)
        second = await plugin.tool_pre_invoke(ToolPreInvokePayload(name="EXPENSIVE"), context)
        third = await plugin.tool_pre_invoke(ToolPreInvokePayload(name=" expensive "), context)

        assert first.continue_processing is True
        assert second.continue_processing is True
        assert third.continue_processing is False
