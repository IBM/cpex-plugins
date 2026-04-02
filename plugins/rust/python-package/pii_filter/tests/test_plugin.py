import logging

import pytest

from mcpgateway_mock.plugins.framework import (
    GlobalContext,
    Message,
    PluginConfig,
    PluginContext,
    PromptPosthookPayload,
    PromptPrehookPayload,
    PromptResult,
    TextContent,
    ToolPostInvokePayload,
    ToolPreInvokePayload,
)

from cpex_pii_filter.pii_filter import PIIFilterPlugin


class _Profile:
    def __init__(self, email: str) -> None:
        self.email = email


def _make_config(**overrides) -> PluginConfig:
    config = {
        "detect_ssn": True,
        "detect_email": True,
        "block_on_detection": False,
    }
    config.update(overrides)
    return PluginConfig(name="pii_filter", config=config)


def _make_context() -> PluginContext:
    return PluginContext(global_context=GlobalContext(user="user-1"))


class TestPluginInit:
    def test_basic_construction(self):
        plugin = PIIFilterPlugin(_make_config())
        assert plugin is not None

    async def test_detection_observability_is_opt_in_by_default(self, caplog):
        plugin = PIIFilterPlugin(_make_config())
        caplog.set_level(logging.INFO, logger="cpex_pii_filter.pii_filter")
        payload = PromptPrehookPayload(
            prompt_id="prompt-1",
            args={"email": "alice@example.com"},
        )
        context = _make_context()

        await plugin.prompt_pre_fetch(payload, context)

        assert "PII detected during prompt_pre_fetch" not in caplog.text
        assert "pii_detections" not in context.metadata


class TestPromptPreFetch:
    @pytest.fixture
    def plugin(self):
        return PIIFilterPlugin(_make_config())

    async def test_masks_prompt_arguments(self, plugin):
        payload = PromptPrehookPayload(
            prompt_id="prompt-1",
            args={"email": "alice@example.com"},
        )
        result = await plugin.prompt_pre_fetch(payload, _make_context())
        assert result.modified_payload is not None
        assert result.modified_payload.args["email"] != "alice@example.com"
        assert result.modified_payload.args["email"] == "[REDACTED]"

    async def test_blocks_when_configured(self):
        plugin = PIIFilterPlugin(_make_config(block_on_detection=True))
        payload = PromptPrehookPayload(
            prompt_id="prompt-1",
            args={"ssn": "123-45-6789"},
        )
        result = await plugin.prompt_pre_fetch(payload, _make_context())
        assert result.continue_processing is False
        assert result.violation is not None
        assert result.violation.code == "PII_DETECTED"

    async def test_aggregates_detection_metadata_across_prompt_args(self, plugin):
        plugin = PIIFilterPlugin(_make_config(include_detection_details=True))
        payload = PromptPrehookPayload(
            prompt_id="prompt-1",
            args={
                "primary_email": "alice@example.com",
                "secondary_email": "bob@example.com",
            },
        )
        context = _make_context()
        await plugin.prompt_pre_fetch(payload, context)
        assert context.metadata["pii_detections"]["prompt_pre_fetch"]["total_count"] == 2

    async def test_logs_detected_prompt_arguments(self, plugin, caplog):
        plugin = PIIFilterPlugin(_make_config(log_detections=True))
        caplog.set_level(logging.INFO, logger="cpex_pii_filter.pii_filter")
        payload = PromptPrehookPayload(
            prompt_id="prompt-1",
            args={"email": "alice@example.com"},
        )

        await plugin.prompt_pre_fetch(payload, _make_context())

        assert "PII detected during prompt_pre_fetch" in caplog.text
        assert "action=masked" in caplog.text

    async def test_suppresses_detection_logs_when_disabled(self, caplog):
        plugin = PIIFilterPlugin(_make_config(log_detections=False))
        caplog.set_level(logging.INFO, logger="cpex_pii_filter.pii_filter")
        payload = PromptPrehookPayload(
            prompt_id="prompt-1",
            args={"email": "alice@example.com"},
        )

        await plugin.prompt_pre_fetch(payload, _make_context())

        assert "PII detected during prompt_pre_fetch" not in caplog.text

    async def test_masks_nested_prompt_arguments(self, plugin):
        payload = PromptPrehookPayload(
            prompt_id="prompt-1",
            args={"contact": {"email": "alice@example.com"}},
        )
        result = await plugin.prompt_pre_fetch(payload, _make_context())
        assert result.modified_payload is not None
        assert result.modified_payload.args["contact"]["email"] != "alice@example.com"

    async def test_masks_tuple_prompt_arguments(self, plugin):
        payload = PromptPrehookPayload(
            prompt_id="prompt-1",
            args={"contacts": ("alice@example.com", "safe")},
        )
        result = await plugin.prompt_pre_fetch(payload, _make_context())
        assert result.modified_payload is not None
        assert result.modified_payload.args["contacts"][0] == "[REDACTED]"

    async def test_masks_set_prompt_arguments(self, plugin):
        payload = PromptPrehookPayload(
            prompt_id="prompt-1",
            args={"contacts": {"alice@example.com", "safe"}},
        )
        result = await plugin.prompt_pre_fetch(payload, _make_context())
        assert result.modified_payload is not None
        assert "[REDACTED]" in result.modified_payload.args["contacts"]

    async def test_masks_object_prompt_arguments(self, plugin):
        payload = PromptPrehookPayload(
            prompt_id="prompt-1",
            args={"profile": _Profile("alice@example.com")},
        )
        result = await plugin.prompt_pre_fetch(payload, _make_context())
        assert result.modified_payload is not None
        assert result.modified_payload.args["profile"].email == "[REDACTED]"

    async def test_disabled_detector_skips_masking(self):
        plugin = PIIFilterPlugin(_make_config(detect_email=False))
        payload = PromptPrehookPayload(
            prompt_id="prompt-1",
            args={"email": "alice@example.com"},
        )
        result = await plugin.prompt_pre_fetch(payload, _make_context())
        assert result.modified_payload is None

    async def test_omits_detection_metadata_when_disabled(self):
        plugin = PIIFilterPlugin(_make_config(include_detection_details=False))
        payload = PromptPrehookPayload(
            prompt_id="prompt-1",
            args={"email": "alice@example.com"},
        )
        context = _make_context()
        await plugin.prompt_pre_fetch(payload, context)
        assert "pii_detections" not in context.metadata

    async def test_whitelist_patterns_skip_detection(self):
        plugin = PIIFilterPlugin(
            _make_config(whitelist_patterns=[r"alice@example\.com"])
        )
        payload = PromptPrehookPayload(
            prompt_id="prompt-1",
            args={"email": "alice@example.com"},
        )
        result = await plugin.prompt_pre_fetch(payload, _make_context())
        assert result.modified_payload is None

    def test_invalid_whitelist_pattern_raises(self):
        with pytest.raises(ValueError, match="Pattern compilation failed"):
            PIIFilterPlugin(_make_config(whitelist_patterns=["("]))


class TestToolHooks:
    @pytest.fixture
    def plugin(self):
        return PIIFilterPlugin(_make_config())

    async def test_masks_nested_tool_arguments(self, plugin):
        payload = ToolPreInvokePayload(
            name="search",
            args={"user": {"email": "alice@example.com"}},
        )
        result = await plugin.tool_pre_invoke(payload, _make_context())
        assert result.modified_payload is not None
        assert result.modified_payload.args["user"]["email"] != "alice@example.com"

    async def test_masks_tool_results(self, plugin):
        payload = ToolPostInvokePayload(
            name="search",
            result={"contact": "alice@example.com"},
        )
        context = _make_context()
        result = await plugin.tool_post_invoke(payload, context)
        assert result.modified_payload is not None
        assert result.modified_payload.result["contact"] != "alice@example.com"
        assert context.metadata["pii_filter_stats"] == {
            "total_detections": 1,
            "total_masked": 1,
        }

    async def test_masks_prompt_messages(self, plugin):
        payload = PromptPosthookPayload(
            result=PromptResult(
                messages=[
                    Message(
                        role="assistant",
                        content=TextContent(text="Contact alice@example.com"),
                    ),
                ]
            )
        )
        result = await plugin.prompt_post_fetch(payload, _make_context())
        assert result.modified_payload is not None
        assert "alice@example.com" not in result.modified_payload.result.messages[0].content.text

    async def test_blocks_prompt_messages_when_configured(self):
        plugin = PIIFilterPlugin(_make_config(block_on_detection=True))
        payload = PromptPosthookPayload(
            result=PromptResult(
                messages=[
                    Message(
                        role="assistant",
                        content=TextContent(text="Contact alice@example.com"),
                    ),
                ]
            )
        )
        result = await plugin.prompt_post_fetch(payload, _make_context())
        assert result.continue_processing is False
        assert result.violation is not None
        assert result.violation.code == "PII_DETECTED_IN_PROMPT_RESULT"

    async def test_hash_mask_strategy_changes_output_shape(self):
        plugin = PIIFilterPlugin(
            _make_config(
                detect_email=False,
                custom_patterns=[
                    {
                        "pattern": r"Customer [A-Z]{3}\d{3}",
                        "description": "Customer code",
                        "mask_strategy": "hash",
                    }
                ],
            )
        )
        payload = ToolPostInvokePayload(
            name="search",
            result={"contact": "Customer ABC123"},
        )
        result = await plugin.tool_post_invoke(payload, _make_context())
        assert result.modified_payload is not None
        assert result.modified_payload.result["contact"].startswith("[HASH:")

    async def test_hash_masking_is_salted_per_plugin_instance(self):
        config = _make_config(
            detect_email=False,
            custom_patterns=[
                {
                    "pattern": r"Customer [A-Z]{3}\d{3}",
                    "description": "Customer code",
                    "mask_strategy": "hash",
                }
            ],
        )
        first_plugin = PIIFilterPlugin(config)
        second_plugin = PIIFilterPlugin(config)
        first_payload = ToolPostInvokePayload(
            name="search",
            result={"contact": "Customer ABC123"},
        )
        second_payload = ToolPostInvokePayload(
            name="search",
            result={"contact": "Customer ABC123"},
        )

        first = await first_plugin.tool_post_invoke(first_payload, _make_context())
        second = await second_plugin.tool_post_invoke(second_payload, _make_context())

        assert first.modified_payload is not None
        assert second.modified_payload is not None
        assert (
            first.modified_payload.result["contact"]
            != second.modified_payload.result["contact"]
        )

    async def test_credit_card_detection_masks_amex(self):
        plugin = PIIFilterPlugin(_make_config())
        payload = ToolPostInvokePayload(
            name="payment_lookup",
            result={"card": "3782 822463 10005"},
        )
        result = await plugin.tool_post_invoke(payload, _make_context())
        assert result.modified_payload is not None
        assert result.modified_payload.result["card"] != "3782 822463 10005"

    async def test_nested_limits_raise_validation_error(self):
        plugin = PIIFilterPlugin(_make_config(max_nested_depth=1))
        payload = ToolPreInvokePayload(
            name="search",
            args={"level1": {"level2": {"email": "alice@example.com"}}},
        )
        with pytest.raises(ValueError, match="maximum depth"):
            await plugin.tool_pre_invoke(payload, _make_context())

    async def test_blocks_tool_arguments_when_configured(self):
        plugin = PIIFilterPlugin(_make_config(block_on_detection=True))
        payload = ToolPreInvokePayload(
            name="search",
            args={"email": "alice@example.com"},
        )
        result = await plugin.tool_pre_invoke(payload, _make_context())
        assert result.continue_processing is False
        assert result.violation is not None
        assert result.violation.code == "PII_DETECTED_IN_TOOL_ARGS"

    async def test_blocks_tool_results_when_configured(self):
        plugin = PIIFilterPlugin(_make_config(block_on_detection=True))
        payload = ToolPostInvokePayload(
            name="search",
            result={"contact": "alice@example.com"},
        )
        context = _make_context()
        result = await plugin.tool_post_invoke(payload, context)
        assert result.continue_processing is False
        assert result.violation is not None
        assert result.violation.code == "PII_DETECTED_IN_TOOL_RESULT"
        assert context.metadata.get("pii_filter_stats") is None

    async def test_stats_reset_per_request_on_reused_plugin_instance(self, plugin):
        first = ToolPostInvokePayload(
            name="search",
            result={"contact": "alice@example.com"},
        )
        first_context = _make_context()
        await plugin.tool_post_invoke(first, first_context)
        assert first_context.metadata["pii_filter_stats"] == {
            "total_detections": 1,
            "total_masked": 1,
        }

        second = ToolPostInvokePayload(
            name="search",
            result={"ssn": "123-45-6789"},
        )
        second_context = _make_context()
        await plugin.tool_post_invoke(second, second_context)
        assert second_context.metadata["pii_filter_stats"] == {
            "total_detections": 1,
            "total_masked": 1,
        }
