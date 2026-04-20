from dataclasses import dataclass

import pytest

from mcpgateway.plugins.framework import (
    PluginConfig,
    PluginContext,
    PromptPosthookPayload,
    PromptPrehookPayload,
    ToolPostInvokePayload,
    ToolPreInvokePayload,
)
from mcpgateway.plugins.framework.models import GlobalContext

from cpex_pii_filter.pii_filter import PIIDetectorRust, PIIFilterPlugin


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
