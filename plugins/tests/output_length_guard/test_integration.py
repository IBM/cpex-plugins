"""Plugin-framework integration tests for output_length_guard.

Tests the full plugin stack: PyO3 bindings → Python shim → cpex framework.
Run via: make test-integration from the plugin directory.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from real_cpex_imports import assert_real_cpex_imports
from cpex.framework import (
    PluginConfig,
    PluginContext,
    ToolPostInvokePayload,
)
from cpex.framework.extensions import Extensions, RequestExtension
from cpex.framework.models import GlobalContext

from cpex_output_length_guard.output_length_guard import OutputLengthGuardPlugin


def test_imports_with_real_cpex_package() -> None:
    plugin_root = (
        Path(__file__).resolve().parents[3]
        / "plugins"
        / "rust"
        / "python-package"
        / "output_length_guard"
    )
    assert_real_cpex_imports(
        plugin_root,
        [
            "from cpex_output_length_guard.output_length_guard import OutputLengthGuardPlugin",
        ],
    )


def _make_config(**overrides) -> PluginConfig:
    config: dict = {
        "max_chars": 100,
        "strategy": "truncate",
        "limit_mode": "character",
    }
    config.update(overrides)
    return PluginConfig(
        name="output_length_guard",
        kind="cpex_output_length_guard.output_length_guard.OutputLengthGuardPlugin",
        config=config,
    )


def _make_context() -> PluginContext:
    return PluginContext(
        global_context=GlobalContext(
            request_id="req-olg", server_id="srv-olg"
        )
    )


def test_plugin_instantiates() -> None:
    plugin = OutputLengthGuardPlugin(_make_config())
    assert plugin is not None


def test_invalid_strategy_raises() -> None:
    with pytest.raises((ValueError, Exception)):
        OutputLengthGuardPlugin(_make_config(strategy="skip"))


def test_invalid_limit_mode_raises() -> None:
    with pytest.raises((ValueError, Exception)):
        OutputLengthGuardPlugin(_make_config(limit_mode="bytes"))


@pytest.mark.asyncio
async def test_truncates_long_plain_string() -> None:
    plugin = OutputLengthGuardPlugin(_make_config(max_chars=10))
    payload = ToolPostInvokePayload(name="tool1", result="A" * 100)
    result = await plugin.tool_post_invoke(payload, _make_context())
    assert result.modified_payload is not None
    assert len(result.modified_payload.result) <= 10


@pytest.mark.asyncio
async def test_short_string_passes_through_unchanged() -> None:
    plugin = OutputLengthGuardPlugin(_make_config(max_chars=1000))
    payload = ToolPostInvokePayload(name="tool1", result="hello")
    result = await plugin.tool_post_invoke(payload, _make_context())
    assert result.modified_payload is None


@pytest.mark.asyncio
async def test_blocks_long_string_in_block_mode() -> None:
    plugin = OutputLengthGuardPlugin(_make_config(max_chars=10, strategy="block"))
    payload = ToolPostInvokePayload(name="tool1", result="A" * 100)
    result = await plugin.tool_post_invoke(payload, _make_context())
    assert result.continue_processing is False
    assert result.violation is not None
    assert result.violation.code == "OUTPUT_LENGTH_VIOLATION"


@pytest.mark.asyncio
async def test_numeric_string_passes_through_unchanged_even_in_block_mode() -> None:
    plugin = OutputLengthGuardPlugin(_make_config(max_chars=2, strategy="block"))
    payload = ToolPostInvokePayload(name="tool1", result="42")
    result = await plugin.tool_post_invoke(payload, _make_context())
    assert result.continue_processing is True


@pytest.mark.asyncio
async def test_dict_with_text_field_is_truncated() -> None:
    plugin = OutputLengthGuardPlugin(_make_config(max_chars=10))
    payload = ToolPostInvokePayload(
        name="tool1", result={"text": "A very long string that exceeds the limit"}
    )
    result = await plugin.tool_post_invoke(payload, _make_context())
    assert result.modified_payload is not None
    assert len(result.modified_payload.result["text"]) <= 10


@pytest.mark.asyncio
async def test_dict_without_text_field_passes_through() -> None:
    plugin = OutputLengthGuardPlugin(_make_config(max_chars=5))
    payload = ToolPostInvokePayload(name="t", result={"other": "value"})
    result = await plugin.tool_post_invoke(payload, _make_context())
    assert result.modified_payload is None


@pytest.mark.asyncio
async def test_mcp_content_array_text_item_is_truncated() -> None:
    plugin = OutputLengthGuardPlugin(_make_config(max_chars=10))
    payload = ToolPostInvokePayload(
        name="t",
        result=[{"type": "text", "text": "A" * 100}],
    )
    result = await plugin.tool_post_invoke(payload, _make_context())
    assert result.modified_payload is not None
    assert len(result.modified_payload.result[0]["text"]) <= 10


@pytest.mark.asyncio
async def test_mcp_content_dict_with_content_array_is_truncated() -> None:
    plugin = OutputLengthGuardPlugin(_make_config(max_chars=10))
    payload = ToolPostInvokePayload(
        name="t",
        result={
            "content": [{"type": "text", "text": "A" * 100}],
            "isError": False,
        },
    )
    result = await plugin.tool_post_invoke(payload, _make_context())
    assert result.modified_payload is not None
    content = result.modified_payload.result["content"]
    assert len(content[0]["text"]) <= 10


@pytest.mark.asyncio
async def test_string_list_is_truncated() -> None:
    plugin = OutputLengthGuardPlugin(_make_config(max_chars=5))
    payload = ToolPostInvokePayload(name="t", result=["hello world", "hi"])
    result = await plugin.tool_post_invoke(payload, _make_context())
    assert result.modified_payload is not None
    assert len(result.modified_payload.result[0]) <= 5
    assert result.modified_payload.result[1] == "hi"


@pytest.mark.asyncio
async def test_word_boundary_truncation() -> None:
    plugin = OutputLengthGuardPlugin(
        _make_config(max_chars=20, word_boundary=True, ellipsis="…")
    )
    payload = ToolPostInvokePayload(
        name="t", result="The quick brown fox jumps over the lazy dog"
    )
    result = await plugin.tool_post_invoke(payload, _make_context())
    assert result.modified_payload is not None
    new_text = result.modified_payload.result
    # Result should respect character limit
    assert len(new_text) <= 20


@pytest.mark.asyncio
async def test_token_mode_truncates_by_token_budget() -> None:
    plugin = OutputLengthGuardPlugin(
        _make_config(
            max_chars=None,
            max_tokens=2,
            limit_mode="token",
            chars_per_token=4,
        )
    )
    payload = ToolPostInvokePayload(
        name="t", result="abcdefghijklmnop"  # 16 chars = 4 estimated tokens
    )
    result = await plugin.tool_post_invoke(payload, _make_context())
    assert result.modified_payload is not None


@pytest.mark.asyncio
async def test_metrics_emitted_when_trace_id_present() -> None:
    plugin = OutputLengthGuardPlugin(_make_config(max_chars=10))
    ext = Extensions(request=RequestExtension(trace_id="t1"))
    payload = ToolPostInvokePayload(name="t", result="A" * 100)
    result = await plugin.tool_post_invoke(payload, _make_context(), ext)
    assert result.modified_payload is not None
    assert result.metadata is not None
    metrics = result.metadata.get("output_length_guard")
    assert metrics is not None
    assert "chars_seen" in metrics
    assert "truncated_count" in metrics
    assert "blocked" in metrics
    assert "limit_mode" in metrics
    assert "strategy" in metrics
    assert "stage" in metrics


@pytest.mark.asyncio
async def test_metrics_not_emitted_without_trace_id() -> None:
    plugin = OutputLengthGuardPlugin(_make_config(max_chars=10))
    payload = ToolPostInvokePayload(name="t", result="A" * 100)
    result = await plugin.tool_post_invoke(payload, _make_context())
    if result.metadata:
        assert "output_length_guard" not in result.metadata


@pytest.mark.asyncio
async def test_no_raw_content_in_metrics() -> None:
    """Verify metrics carry no raw text content."""
    plugin = OutputLengthGuardPlugin(_make_config(max_chars=10))
    ext = Extensions(request=RequestExtension(trace_id="t1"))
    oversized_text = "SENSITIVE_DATA_" * 10
    payload = ToolPostInvokePayload(name="t", result=oversized_text)
    result = await plugin.tool_post_invoke(payload, _make_context(), ext)
    if result.metadata:
        flat = str(result.metadata)
        assert "SENSITIVE_DATA_" not in flat


@pytest.mark.asyncio
async def test_hook_backward_compatible_without_extensions() -> None:
    plugin = OutputLengthGuardPlugin(_make_config(max_chars=1000))
    payload = ToolPostInvokePayload(name="t", result="hello")
    result = await plugin.tool_post_invoke(payload, _make_context())  # 2-arg call
    assert result is not None


@pytest.mark.asyncio
async def test_security_limit_max_structure_size_block() -> None:
    plugin = OutputLengthGuardPlugin(
        _make_config(max_chars=10000, strategy="block", max_structure_size=2)
    )
    payload = ToolPostInvokePayload(
        name="t",
        result={"content": [{"type": "text", "text": "a"}, {"type": "text", "text": "b"}, {"type": "text", "text": "c"}]},
    )
    result = await plugin.tool_post_invoke(payload, _make_context())
    # Should block due to oversized content list
    assert result.continue_processing is False
    assert result.violation is not None
    assert result.violation.code == "STRUCTURE_SIZE_VIOLATION"


@pytest.mark.asyncio
async def test_security_limit_max_recursion_depth_block() -> None:
    plugin = OutputLengthGuardPlugin(
        _make_config(max_chars=10000, strategy="block", max_recursion_depth=10)
    )
    # Build deeply nested dict
    nested: dict = {"value": "leaf"}
    for _ in range(15):
        nested = {"child": nested}
    payload = ToolPostInvokePayload(
        name="t",
        result={
            "content": [{"type": "text", "text": str(nested)}],
            "structuredContent": nested,
        },
    )
    result = await plugin.tool_post_invoke(payload, _make_context())
    assert result.continue_processing is False
    assert result.violation is not None
    assert result.violation.code == "STRUCTURE_DEPTH_VIOLATION"
