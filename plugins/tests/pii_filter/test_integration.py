from dataclasses import dataclass
import logging
from pathlib import Path

import pytest

from real_cpex_imports import assert_real_cpex_imports
from cpex.framework import (
    PluginConfig,
    PluginContext,
    PromptPosthookPayload,
    PromptPrehookPayload,
    ToolPostInvokePayload,
    ToolPreInvokePayload,
)
from cpex.framework.models import GlobalContext

from cpex_pii_filter.pii_filter import PIIDetectorRust, PIIFilterPlugin


def test_imports_with_real_cpex_package() -> None:
    plugin_root = (
        Path(__file__).resolve().parents[3]
        / "plugins"
        / "rust"
        / "python-package"
        / "pii_filter"
    )
    assert_real_cpex_imports(
        plugin_root,
        [
            "from cpex_pii_filter.pii_filter import PIIFilterPlugin",
        ],
    )


@dataclass
class TextContent:
    text: str


@dataclass
class Message:
    role: str
    content: TextContent


@dataclass
class PromptResult:
    messages: list[Message]


def _make_config(**overrides) -> PluginConfig:
    config = {
        "detect_ssn": True,
        "detect_email": True,
        "block_on_detection": False,
    }
    config.update(overrides)
    return PluginConfig(
        name="pii_filter",
        kind="cpex_pii_filter.pii_filter.PIIFilterPlugin",
        config=config,
    )


def _make_context() -> PluginContext:
    return PluginContext(
        global_context=GlobalContext(request_id="req-pii", server_id="srv-pii")
    )


def test_python_module_exports_rust_types():
    assert PIIDetectorRust is not None
    assert PIIFilterPlugin(_make_config()) is not None


def test_invalid_whitelist_pattern_raises():
    with pytest.raises(ValueError, match="Pattern compilation failed"):
        PIIFilterPlugin(_make_config(whitelist_patterns=["("]))


@pytest.mark.asyncio
async def test_prompt_pre_fetch_masks_through_python_shim():
    plugin = PIIFilterPlugin(_make_config())
    payload = PromptPrehookPayload(
        prompt_id="prompt-1",
        args={"email": "alice@example.com"},
    )

    result = await plugin.prompt_pre_fetch(payload, _make_context())

    assert result.modified_payload is not None
    assert result.modified_payload.args["email"] == "[REDACTED]"


@pytest.mark.asyncio
async def test_prompt_pre_fetch_leaves_logs_and_metadata_disabled_by_default(caplog):
    plugin = PIIFilterPlugin(_make_config())
    payload = PromptPrehookPayload(
        prompt_id="prompt-1",
        args={"email": "alice@example.com"},
    )
    context = _make_context()

    await plugin.prompt_pre_fetch(payload, context)

    assert "PII detected during" not in caplog.text
    assert "pii_detections" not in context.metadata


@pytest.mark.asyncio
async def test_prompt_pre_fetch_records_metadata_and_logs_when_enabled(caplog):
    plugin = PIIFilterPlugin(
        _make_config(include_detection_details=True, log_detections=True)
    )
    caplog.set_level(logging.INFO, logger="cpex_pii_filter.pii_filter")
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
    assert "PII detected during prompt_pre_fetch" in caplog.text
    assert "action=masked" in caplog.text


@pytest.mark.asyncio
async def test_prompt_pre_fetch_blocks_when_configured():
    plugin = PIIFilterPlugin(_make_config(block_on_detection=True))
    payload = PromptPrehookPayload(
        prompt_id="prompt-1",
        args={"ssn": "123-45-6789"},
    )

    result = await plugin.prompt_pre_fetch(payload, _make_context())

    assert result.continue_processing is False
    assert result.violation is not None
    assert result.violation.code == "PII_DETECTED"


@pytest.mark.asyncio
async def test_prompt_pre_fetch_skips_masking_when_detector_disabled():
    plugin = PIIFilterPlugin(_make_config(detect_email=False))
    payload = PromptPrehookPayload(
        prompt_id="prompt-1",
        args={"email": "alice@example.com"},
    )

    result = await plugin.prompt_pre_fetch(payload, _make_context())

    assert result.modified_payload is None


@pytest.mark.asyncio
async def test_prompt_post_fetch_masks_message_content_through_python_shim():
    plugin = PIIFilterPlugin(_make_config())
    payload = PromptPosthookPayload(
        prompt_id="prompt-1",
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


@pytest.mark.asyncio
async def test_prompt_post_fetch_does_not_mutate_original_payload():
    plugin = PIIFilterPlugin(_make_config())
    original_first = Message(
        role="assistant",
        content=TextContent(text="Contact alice@example.com"),
    )
    original_second = Message(
        role="assistant",
        content=TextContent(text="Status nominal"),
    )
    payload = PromptPosthookPayload(
        prompt_id="prompt-1",
        result=PromptResult(
            messages=[original_first, original_second]
        ),
    )

    result = await plugin.prompt_post_fetch(payload, _make_context())

    assert result.modified_payload is not None
    assert payload.result.messages[0].content.text == "Contact alice@example.com"
    assert payload.result.messages[1].content.text == "Status nominal"
    assert (
        "alice@example.com"
        not in result.modified_payload.result.messages[0].content.text
    )
    assert result.modified_payload.result.messages[1].content.text == "Status nominal"
    assert result.modified_payload.result.messages is not payload.result.messages
    assert result.modified_payload.result.messages[0] is not original_first
    assert result.modified_payload.result.messages[0].content is not original_first.content
    assert result.modified_payload.result.messages[1] is not original_second
    assert result.modified_payload.result.messages[1].content is not original_second.content


@pytest.mark.asyncio
async def test_prompt_post_fetch_blocks_when_configured():
    plugin = PIIFilterPlugin(_make_config(block_on_detection=True))
    payload = PromptPosthookPayload(
        prompt_id="prompt-1",
        result=PromptResult(
            messages=[
                Message(
                    role="assistant",
                    content=TextContent(text="Contact alice@example.com"),
                ),
            ]
        ),
    )

    result = await plugin.prompt_post_fetch(payload, _make_context())

    assert result.continue_processing is False
    assert result.violation is not None
    assert result.violation.code == "PII_DETECTED_IN_PROMPT_RESULT"


@pytest.mark.asyncio
async def test_tool_pre_invoke_masks_nested_args_through_python_shim():
    plugin = PIIFilterPlugin(_make_config())
    payload = ToolPreInvokePayload(
        name="search",
        args={"user": {"email": "alice@example.com"}},
    )

    result = await plugin.tool_pre_invoke(payload, _make_context())

    assert result.modified_payload is not None
    assert result.modified_payload.args["user"]["email"] == "[REDACTED]"


@pytest.mark.asyncio
async def test_tool_pre_invoke_returns_copied_payload_for_frozen_models():
    plugin = PIIFilterPlugin(_make_config())
    payload = ToolPreInvokePayload(
        name="search",
        args={"user": {"email": "alice@example.com"}},
    )

    result = await plugin.tool_pre_invoke(payload, _make_context())

    assert result.modified_payload is not None
    assert result.modified_payload is not payload
    assert payload.args["user"]["email"] == "alice@example.com"
    assert result.modified_payload.args["user"]["email"] == "[REDACTED]"


@pytest.mark.asyncio
async def test_tool_pre_invoke_propagates_nested_depth_errors():
    plugin = PIIFilterPlugin(_make_config(max_nested_depth=1))
    payload = ToolPreInvokePayload(
        name="search",
        args={"level1": {"level2": {"email": "alice@example.com"}}},
    )

    with pytest.raises(ValueError, match="maximum depth"):
        await plugin.tool_pre_invoke(payload, _make_context())


@pytest.mark.asyncio
async def test_tool_post_invoke_masks_result_and_updates_context_through_python_shim():
    plugin = PIIFilterPlugin(_make_config())
    payload = ToolPostInvokePayload(
        name="search",
        result={"contact": "alice@example.com"},
    )
    context = _make_context()

    result = await plugin.tool_post_invoke(payload, context)

    assert result.modified_payload is not None
    assert result.modified_payload.result["contact"] == "[REDACTED]"
    assert context.metadata["pii_filter_stats"] == {
        "total_detections": 1,
        "total_masked": 1,
    }


@pytest.mark.asyncio
async def test_tool_post_invoke_returns_copied_payload_for_frozen_models():
    plugin = PIIFilterPlugin(_make_config())
    payload = ToolPostInvokePayload(
        name="search",
        result={"contact": "alice@example.com"},
    )

    result = await plugin.tool_post_invoke(payload, _make_context())

    assert result.modified_payload is not None
    assert result.modified_payload is not payload
    assert payload.result["contact"] == "alice@example.com"
    assert result.modified_payload.result["contact"] == "[REDACTED]"


@pytest.mark.asyncio
async def test_tool_post_invoke_blocks_when_configured():
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


@pytest.mark.asyncio
async def test_tool_post_invoke_hash_masking_is_salted_per_plugin_instance():
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
    first = PIIFilterPlugin(config)
    second = PIIFilterPlugin(config)
    payload = ToolPostInvokePayload(
        name="search",
        result={"contact": "Customer ABC123"},
    )

    first_result = await first.tool_post_invoke(payload, _make_context())
    second_result = await second.tool_post_invoke(payload, _make_context())

    assert first_result.modified_payload is not None
    assert second_result.modified_payload is not None
    first_value = first_result.modified_payload.result["contact"]
    second_value = second_result.modified_payload.result["contact"]
    assert first_value.startswith("[HASH:")
    assert second_value.startswith("[HASH:")
    assert first_value != second_value


@pytest.mark.asyncio
async def test_tool_post_invoke_custom_pattern_without_mask_strategy_uses_default():
    plugin = PIIFilterPlugin(
        _make_config(
            detect_email=False,
            default_mask_strategy="partial",
            custom_patterns=[
                {
                    "pattern": r"Customer [A-Z]{3}\d{3}",
                    "description": "Customer code",
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
    assert result.modified_payload.result["contact"] == "C*************3"


@pytest.mark.asyncio
async def test_tool_post_invoke_custom_pattern_none_mask_strategy_uses_default():
    plugin = PIIFilterPlugin(
        _make_config(
            detect_email=False,
            default_mask_strategy="partial",
            custom_patterns=[
                {
                    "pattern": r"Customer [A-Z]{3}\d{3}",
                    "description": "Customer code",
                    "mask_strategy": None,
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
    assert result.modified_payload.result["contact"] == "C*************3"


@pytest.mark.asyncio
async def test_tool_post_invoke_stats_reset_per_request():
    plugin = PIIFilterPlugin(_make_config())

    first_payload = ToolPostInvokePayload(
        name="search",
        result={"contact": "alice@example.com"},
    )
    first_context = _make_context()
    await plugin.tool_post_invoke(first_payload, first_context)

    second_payload = ToolPostInvokePayload(
        name="search",
        result={"ssn": "123-45-6789"},
    )
    second_context = _make_context()
    await plugin.tool_post_invoke(second_payload, second_context)

    assert first_context.metadata["pii_filter_stats"] == {
        "total_detections": 1,
        "total_masked": 1,
    }
    assert second_context.metadata["pii_filter_stats"] == {
        "total_detections": 1,
        "total_masked": 1,
    }
