# SPDX-License-Identifier: Apache-2.0
"""Observability and security contract tests for the ICA metering exporter.

Covers the OpenTelemetry metadata gating, the non-sensitivity of emitted
metadata and logs, falsy-input handling, and the non-mutating pluginConfig
overlay. ``Extensions`` are passed directly to the hooks, intentionally
bypassing the gateway's ``read_headers`` capability filter.
"""

from __future__ import annotations

import copy
import logging
from collections.abc import AsyncIterator, Callable
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

PLUGIN_KIND = "cpex_ica_metering_exporter.plugin.IcaMeteringExporterPlugin"
HOOKS = ["tool_pre_invoke", "tool_post_invoke"]
METERING_URL = "https://metering.example.invalid/events"
OPERATIONAL_METADATA_KEYS = {"export_status", "latency_ms", "model_source", "stage"}
SENTINELS = {
    "app_id": "sentinel-app-9",
    "user_agent": "sentinel-ua/9",
    "persona": "sentinel-persona",
    "payload": "sentinel-payload",
    "token": "sentinel-token",
    "jwt_secret": "sentinel-secret",
    "trace_id": "sentinel-trace-9",
}


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


def _flatten_strings(value: Any) -> list[str]:
    """Recursively collect every string in a nested metadata structure."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        collected: list[str] = []
        for key, item in value.items():
            collected.extend(_flatten_strings(key))
            collected.extend(_flatten_strings(item))
        return collected
    if isinstance(value, (list, tuple, set, frozenset)):
        items: list[str] = []
        for item in value:
            items.extend(_flatten_strings(item))
        return items
    return []


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


@pytest.mark.asyncio
async def test_otel_gating_omits_metadata_without_trace_id(
    make_plugin: Callable[..., IcaMeteringExporterPlugin],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given an enabled plugin and extensions carrying no request trace.
    plugin = make_plugin(enabled=True, metering_url=METERING_URL)
    monkeypatch.setattr(plugin, "_send_to_ica", AsyncMock(return_value="sent"))
    send = plugin.__dict__["_send_to_ica"]
    assert isinstance(send, AsyncMock)
    context = _make_context()
    extensions = _make_extensions({"X-App-Id": "app-1"})

    # When post-invoke runs.
    result = await plugin.tool_post_invoke(
        ToolPostInvokePayload(name="tool", result={}), context, extensions
    )

    # Then the export happened but no exporter metadata was emitted.
    send.assert_awaited_once()
    assert "ica_metering_exporter" not in (result.metadata or {})


@pytest.mark.asyncio
async def test_otel_gating_emits_metadata_with_trace_id(
    make_plugin: Callable[..., IcaMeteringExporterPlugin],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given an enabled plugin and a request trace on the extensions.
    plugin = make_plugin(enabled=True, metering_url=METERING_URL)
    monkeypatch.setattr(plugin, "_send_to_ica", AsyncMock(return_value="sent"))
    context = _make_context()
    extensions = _make_extensions(
        {"X-OpenWebUI-Model-Id": "gpt-4o"}, trace_id="trace-integration-9"
    )

    # When the invocation flows through both hooks.
    await plugin.tool_pre_invoke(
        ToolPreInvokePayload(name="tool", args={}), context, extensions
    )
    result = await plugin.tool_post_invoke(
        ToolPostInvokePayload(name="tool", result={}), context, extensions
    )

    # Then metadata holds exactly the four operational keys and never the trace id.
    metadata = result.metadata["ica_metering_exporter"]
    assert set(metadata) == OPERATIONAL_METADATA_KEYS
    assert metadata["export_status"] == "sent"
    assert metadata["model_source"] == "transport_header"
    assert metadata["stage"] == "tool_post_invoke"
    assert isinstance(metadata["latency_ms"], int)
    assert "trace-integration-9" not in _flatten_strings(result.metadata)


@pytest.mark.asyncio
async def test_metadata_and_logs_exclude_sensitive_sentinels(
    make_plugin: Callable[..., IcaMeteringExporterPlugin],
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    # Given an enabled plugin wired with unique sentinel credentials and caller data.
    plugin = make_plugin(
        enabled=True,
        metering_url=METERING_URL,
        metering_token=SENTINELS["token"],
        jwt_secret=SENTINELS["jwt_secret"],
    )
    monkeypatch.setattr(plugin, "_send_to_ica", AsyncMock(return_value="sent"))
    send = plugin.__dict__["_send_to_ica"]
    assert isinstance(send, AsyncMock)
    context = _make_context()
    extensions = _make_extensions(
        {
            "X-App-Id": SENTINELS["app_id"],
            "User-Agent": SENTINELS["user_agent"],
            "assistant_name": SENTINELS["persona"],
        },
        trace_id=SENTINELS["trace_id"],
    )
    caplog.set_level(logging.DEBUG)

    # When an invocation carrying a sentinel-laden payload flows through both hooks.
    await plugin.tool_pre_invoke(
        ToolPreInvokePayload(
            name="sentinel-tool", args={"input": SENTINELS["payload"]}
        ),
        context,
        extensions,
    )
    result = await plugin.tool_post_invoke(
        ToolPostInvokePayload(
            name="sentinel-tool", result={"output": SENTINELS["payload"]}
        ),
        context,
        extensions,
    )

    # Then the exported payload proves the sentinels were processed.
    exported = _sent_payload(send)
    assert exported["appId"] == SENTINELS["app_id"]
    assert exported["userAgent"] == SENTINELS["user_agent"]
    assert exported["assistantName"] == SENTINELS["persona"]

    # And result metadata and logs contain none of the raw sentinel values.
    assert set(result.metadata["ica_metering_exporter"]) == OPERATIONAL_METADATA_KEYS
    flattened = _flatten_strings(result.metadata)
    for label, sentinel in SENTINELS.items():
        assert sentinel not in flattened, (
            f"{label} sentinel leaked into result metadata"
        )
        assert sentinel not in caplog.text, f"{label} sentinel leaked into logs"


@pytest.mark.asyncio
async def test_falsy_header_values_do_not_fabricate_attribution(
    make_plugin: Callable[..., IcaMeteringExporterPlugin],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given attribution headers that are present but carry empty values.
    plugin = make_plugin(enabled=True, metering_url=METERING_URL)
    monkeypatch.setattr(plugin, "_send_to_ica", AsyncMock(return_value="sent"))
    send = plugin.__dict__["_send_to_ica"]
    assert isinstance(send, AsyncMock)
    context = _make_context()
    extensions = _make_extensions(
        {
            "X-App-Id": "",
            "X-MCP-Client-Name": "",
            "User-Agent": "",
            "assistant_name": "",
        },
        trace_id="t-1",
    )

    # When the invocation flows through both hooks.
    await plugin.tool_pre_invoke(
        ToolPreInvokePayload(name="tool", args={}), context, extensions
    )
    await plugin.tool_post_invoke(
        ToolPostInvokePayload(name="tool", result={}), context, extensions
    )

    # Then no attribution was fabricated from the empty values.
    exported = _sent_payload(send)
    assert exported["appId"] is None
    assert exported["userAgent"] is None
    assert exported["assistantName"] is None
    assert "ica_app_id" not in context.state


@pytest.mark.asyncio
async def test_plugin_config_overlay_does_not_mutate_caller_config(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given a caller-owned configuration mapping with nested gateway entries.
    config: dict[str, Any] = {
        "enabled": True,
        "metering_url": METERING_URL,
        "gateways": [{"id": "gw-1", "default_model": "gpt-4o-mini"}],
        "global_default_model": "gpt-4o",
    }
    snapshot = copy.deepcopy(config)
    plugin = IcaMeteringExporterPlugin(
        PluginConfig(
            name="ica_metering_exporter_test",
            kind=PLUGIN_KIND,
            hooks=HOOKS,
            config=config,
        )
    )
    monkeypatch.setattr(plugin, "_send_to_ica", AsyncMock(return_value="sent"))
    send = plugin.__dict__["_send_to_ica"]
    assert isinstance(send, AsyncMock)

    try:
        # When the plugin operates on the configuration, reading the gateway fallback.
        context = _make_context(
            metadata={GATEWAY_METADATA: {"id": "gw-1", "transport": "sse"}}
        )
        extensions = _make_extensions({}, trace_id="t-1")
        await plugin.tool_pre_invoke(
            ToolPreInvokePayload(name="tool", args={}), context, extensions
        )
        result = await plugin.tool_post_invoke(
            ToolPostInvokePayload(name="tool", result={}), context, extensions
        )

        # Then the gateway default was honored through the overlay copy.
        assert _sent_payload(send)["toolDetails"]["modelName"] == "gpt-4o-mini"
        assert (
            result.metadata["ica_metering_exporter"]["model_source"]
            == "gateway_default"
        )
        assert plugin.telemetry_config is not config
        assert config == snapshot
    finally:
        await plugin.shutdown()
