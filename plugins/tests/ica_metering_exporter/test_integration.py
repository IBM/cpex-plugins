# SPDX-License-Identifier: Apache-2.0
"""Plugin-framework integration tests for the ICA metering exporter.

These tests pass ``Extensions`` directly to the hooks and therefore
intentionally bypass the gateway's ``read_headers`` capability filter; the
gateway registration must still grant that capability for attribution to
function in production.
"""

from __future__ import annotations

import copy
import sys
from collections.abc import AsyncIterator, Callable
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import pytest
from cpex.framework import (
    PluginConfig,
    PluginContext,
    ToolPostInvokePayload,
    ToolPreInvokePayload,
)
from cpex.framework.constants import GATEWAY_METADATA
from cpex.framework.extensions import Extensions, HttpExtension, RequestExtension
from cpex.framework.models import GlobalContext
from cpex_ica_metering_exporter.plugin import IcaMeteringExporterPlugin
from real_cpex_imports import assert_real_cpex_imports

PLUGIN_KIND = "cpex_ica_metering_exporter.plugin.IcaMeteringExporterPlugin"
HOOKS = ["tool_pre_invoke", "tool_post_invoke"]
METERING_URL = "https://metering.example.invalid/events"


def _make_config(**overrides: Any) -> PluginConfig:
    config: dict[str, Any] = {"enabled": False}
    config.update(overrides)
    return PluginConfig(
        name="ica_metering_exporter_test",
        kind=PLUGIN_KIND,
        hooks=HOOKS,
        config=config,
    )


def _make_context(**global_kwargs: Any) -> PluginContext:
    global_kwargs.setdefault("request_id", "req-ica-1")
    global_kwargs.setdefault("server_id", "srv-ica-1")
    return PluginContext(global_context=GlobalContext(**global_kwargs))


def _make_extensions(
    headers: dict[str, str], trace_id: str | None = None
) -> Extensions:
    request = RequestExtension(trace_id=trace_id) if trace_id is not None else None
    return Extensions(http=HttpExtension(headers=headers), request=request)


def _sent_payload(send: AsyncMock) -> dict[str, Any]:
    send.assert_awaited_once()
    await_args = send.await_args
    assert await_args is not None
    payload = await_args.args[0]
    assert isinstance(payload, dict)
    return payload


@pytest.fixture
async def make_plugin() -> AsyncIterator[Callable[..., IcaMeteringExporterPlugin]]:
    """Construct plugins and close any HTTP clients after the test."""
    created: list[IcaMeteringExporterPlugin] = []

    def _factory(**config: Any) -> IcaMeteringExporterPlugin:
        plugin = IcaMeteringExporterPlugin(_make_config(**config))
        created.append(plugin)
        return plugin

    yield _factory

    for plugin in created:
        await plugin.shutdown()


def test_imports_with_real_cpex_package() -> None:
    # Given the installed plugin package location.
    plugin_root = (
        Path(__file__).resolve().parents[3]
        / "plugins"
        / "python"
        / "ica_metering_exporter"
    )

    # When imports are resolved against the real cpex package in a subprocess.
    # Then the plugin imports without the conftest shim, exercising the
    # expanded real-cpex module tuple (constants and extensions included).
    assert_real_cpex_imports(
        plugin_root,
        ["from cpex_ica_metering_exporter.plugin import IcaMeteringExporterPlugin"],
    )


def test_plugin_module_imports_through_constants_shim() -> None:
    # Given the active conftest shim (gated by CPEX_TEST_PLUGIN_HOOKS=1).
    # When the plugin package is imported through the shimmed cpex.framework.constants.
    import cpex.framework.constants as constants_module
    import cpex_ica_metering_exporter

    # Then the shim served GATEWAY_METADATA and exposed the plugin entry point.
    assert GATEWAY_METADATA == "gateway"
    assert sys.modules["cpex.framework.constants"] is constants_module
    assert (
        cpex_ica_metering_exporter.IcaMeteringExporterPlugin
        is IcaMeteringExporterPlugin
    )


@pytest.mark.asyncio
async def test_disabled_by_default_hooks_continue_without_send(
    make_plugin: Callable[..., IcaMeteringExporterPlugin],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given a plugin with default configuration (disabled).
    plugin = make_plugin()
    monkeypatch.setattr(plugin, "_send_to_ica", AsyncMock(return_value="sent"))
    send = plugin.__dict__["_send_to_ica"]
    assert isinstance(send, AsyncMock)
    context = _make_context()
    extensions = _make_extensions({"X-App-Id": "app-1"}, trace_id="t-1")

    # When both hooks run.
    pre_result = await plugin.tool_pre_invoke(
        ToolPreInvokePayload(name="tool", args={}), context, extensions
    )
    post_result = await plugin.tool_post_invoke(
        ToolPostInvokePayload(name="tool", result={"isError": False}),
        context,
        extensions,
    )

    # Then both allow processing and no export or HTTP client was attempted.
    assert pre_result.continue_processing is True
    assert post_result.continue_processing is True
    send.assert_not_called()
    assert plugin.http_client is None
    assert context.state == {}


@pytest.mark.asyncio
async def test_enabled_pre_post_invoke_exports_caller_attribution(
    make_plugin: Callable[..., IcaMeteringExporterPlugin],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given an enabled plugin and the full caller-attribution header set.
    plugin = make_plugin(enabled=True, metering_url=METERING_URL)
    monkeypatch.setattr(plugin, "_send_to_ica", AsyncMock(return_value="sent"))
    send = plugin.__dict__["_send_to_ica"]
    assert isinstance(send, AsyncMock)
    context = _make_context()
    extensions = _make_extensions(
        {
            "X-App-Id": "app-1",
            "X-OpenWebUI-Model-Id": "gpt-4o",
            "llm_call_type": "assistant",
            "assistant_name": "Helper",
        },
        trace_id="t-1",
    )

    # When the tool invocation flows through both hooks.
    await plugin.tool_pre_invoke(
        ToolPreInvokePayload(name="tool", args={}), context, extensions
    )
    result = await plugin.tool_post_invoke(
        ToolPostInvokePayload(name="tool", result={"isError": False}),
        context,
        extensions,
    )

    # Then the exported payload carries the header-derived attribution.
    exported = _sent_payload(send)
    assert exported["appId"] == "app-1"
    assert exported["toolDetails"]["modelName"] == "gpt-4o"
    assert exported["assistantName"] == "Helper"
    assert result.metadata["ica_metering_exporter"]["export_status"] == "sent"


@pytest.mark.asyncio
async def test_headers_are_case_insensitive_via_extensions(
    make_plugin: Callable[..., IcaMeteringExporterPlugin],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given a lower-case app id header on the extensions.
    plugin = make_plugin(enabled=True, metering_url=METERING_URL)
    monkeypatch.setattr(plugin, "_send_to_ica", AsyncMock(return_value="sent"))
    context = _make_context()
    extensions = _make_extensions({"x-app-id": "lower-app-1"}, trace_id="t-1")

    # When pre-invoke reads the headers.
    await plugin.tool_pre_invoke(
        ToolPreInvokePayload(name="tool", args={}), context, extensions
    )

    # Then the lower-case header was honored.
    assert context.state["ica_app_id"] == "lower-app-1"


@pytest.mark.asyncio
async def test_hooks_do_not_mutate_payloads(
    make_plugin: Callable[..., IcaMeteringExporterPlugin],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given an enabled plugin and remembered payload contents.
    plugin = make_plugin(enabled=True, metering_url=METERING_URL)
    monkeypatch.setattr(plugin, "_send_to_ica", AsyncMock(return_value="sent"))
    context = _make_context()
    extensions = _make_extensions({"X-App-Id": "app-1"}, trace_id="t-1")
    pre_payload = ToolPreInvokePayload(name="tool", args={"query": "weather"})
    post_payload = ToolPostInvokePayload(
        name="tool", result={"output": "sunny", "meta": {"tokens": {"input": 3}}}
    )
    pre_snapshot = copy.deepcopy(pre_payload.args)
    post_snapshot = copy.deepcopy(post_payload.result)

    # When both hooks run.
    pre_result = await plugin.tool_pre_invoke(pre_payload, context, extensions)
    post_result = await plugin.tool_post_invoke(post_payload, context, extensions)

    # Then neither hook replaced or mutated the payloads.
    assert pre_result.modified_payload is None
    assert post_result.modified_payload is None
    assert pre_payload.args == pre_snapshot
    assert post_payload.result == post_snapshot


@pytest.mark.asyncio
async def test_hooks_callable_without_extensions(
    make_plugin: Callable[..., IcaMeteringExporterPlugin],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given an enabled plugin.
    plugin = make_plugin(enabled=True, metering_url=METERING_URL)
    monkeypatch.setattr(plugin, "_send_to_ica", AsyncMock(return_value="sent"))
    context = _make_context()

    # When both hooks are called with only (payload, context).
    pre_result = await plugin.tool_pre_invoke(
        ToolPreInvokePayload(name="tool", args={}), context
    )
    post_result = await plugin.tool_post_invoke(
        ToolPostInvokePayload(name="tool", result={}), context
    )

    # Then both succeed and no metadata is emitted without a trace.
    assert pre_result.continue_processing is True
    assert post_result.continue_processing is True
    assert "ica_metering_exporter" not in (post_result.metadata or {})
