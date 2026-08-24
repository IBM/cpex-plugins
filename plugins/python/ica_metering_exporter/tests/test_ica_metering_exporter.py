# SPDX-License-Identifier: Apache-2.0
"""Unit tests ported from IBM/mcp-context-forge PR #5696."""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock

import httpx
import jwt
import pytest
from cpex.framework import (
    GlobalContext,
    PluginConfig,
    PluginContext,
    ToolPostInvokePayload,
    ToolPreInvokePayload,
)
from cpex.framework.constants import GATEWAY_METADATA
from cpex.framework.extensions import Extensions, RequestExtension
from cpex.framework.extensions.http import HttpExtension
from pydantic import BaseModel

from cpex_ica_metering_exporter import IcaMeteringExporterPlugin

Config = dict[str, Any]
Payload = dict[str, Any]
JWT_FIXTURE = "fixture-jwt-secret-at-least-thirty-two-bytes"


def _plugin(
    monkeypatch: pytest.MonkeyPatch,
    config: Config | None = None,
    *,
    mock_send: bool = True,
) -> IcaMeteringExporterPlugin:
    resolved = (
        config
        if config is not None
        else {
            "enabled": True,
            "metering_url": "https://metering.example.invalid/event",
            "metering_token": "fixture-static-token",
        }
    )
    plugin = IcaMeteringExporterPlugin(
        PluginConfig(
            name="ica_metering_test",
            kind="cpex_ica_metering_exporter.plugin.IcaMeteringExporterPlugin",
            hooks=["tool_pre_invoke", "tool_post_invoke"],
            config=resolved,
        )
    )
    if mock_send:
        monkeypatch.setattr(plugin, "_send_to_ica", AsyncMock(return_value="sent"), raising=False)
    return plugin


def _context(metadata: Config | None = None, *, user: str | Config = "user@example.test") -> PluginContext:
    return PluginContext(
        global_context=GlobalContext(
            request_id="request-123",
            user=user,
            tenant_id="team-1",
            server_id="server-1",
            metadata=metadata or {},
        )
    )


def _extensions(headers: dict[str, str] | None = None, trace_id: str | None = "trace-123") -> Extensions:
    return Extensions(
        http=HttpExtension(headers=headers or {}),
        request=RequestExtension(trace_id=trace_id),
    )


def _pre(name: str = "tool") -> ToolPreInvokePayload:
    return ToolPreInvokePayload(name=name, args={})


def _post(name: str = "tool", result: Any = None) -> ToolPostInvokePayload:
    return ToolPostInvokePayload(name=name, result=result if result is not None else {"isError": False})


def _sent(plugin: IcaMeteringExporterPlugin) -> Payload:
    sender = plugin._send_to_ica
    assert isinstance(sender, AsyncMock)
    await_args = sender.await_args
    assert await_args is not None
    value = await_args.args[0]
    assert isinstance(value, dict)
    return value


@pytest.mark.asyncio
async def test_pre_invoke_records_timestamp(monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = _plugin(monkeypatch)
    context = _context()
    await plugin.tool_pre_invoke(_pre(), context)
    assert isinstance(context.state["ica_metering_start_time"], float)


@pytest.mark.asyncio
async def test_pre_invoke_is_noop_when_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = _plugin(monkeypatch, {"enabled": False})
    context = _context()
    result = await plugin.tool_pre_invoke(_pre(), context)
    assert result.continue_processing is True and context.state == {}


@pytest.mark.asyncio
async def test_pre_invoke_accepts_extensions_none(monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = _plugin(monkeypatch)
    result = await plugin.tool_pre_invoke(_pre(), _context(), None)
    assert result.continue_processing is True


@pytest.mark.asyncio
async def test_pre_invoke_extracts_app_id(monkeypatch: pytest.MonkeyPatch) -> None:
    context = _context()
    await _plugin(monkeypatch).tool_pre_invoke(_pre(), context, _extensions({"x-app-id": "app-1"}))
    assert context.state["ica_app_id"] == "app-1"


@pytest.mark.asyncio
async def test_pre_invoke_extracts_model_case_insensitively(monkeypatch: pytest.MonkeyPatch) -> None:
    context = _context()
    await _plugin(monkeypatch).tool_pre_invoke(_pre(), context, _extensions({"x-OPENwebui-MODEL-id": "model-1"}))
    assert context.state["ica_metering_model_name"] == "model-1"


@pytest.mark.asyncio
async def test_pre_invoke_extracts_mcp_client(monkeypatch: pytest.MonkeyPatch) -> None:
    context = _context()
    headers = {"X-MCP-Client-Name": "opencode", "x-mcp-client-version": "1.5.0"}
    await _plugin(monkeypatch).tool_pre_invoke(_pre(), context, _extensions(headers))
    assert context.state["ica_mcp_client_name"] == "opencode"
    assert context.state["ica_mcp_client_version"] == "1.5.0"


@pytest.mark.asyncio
async def test_pre_invoke_uses_forwarded_user_agent(monkeypatch: pytest.MonkeyPatch) -> None:
    context = _context()
    headers = {"User-Agent": "fallback/1", "X-Forwarded-User-Agent": "forwarded/2"}
    await _plugin(monkeypatch).tool_pre_invoke(_pre(), context, _extensions(headers))
    assert context.state["ica_user_agent"] == "forwarded/2"


@pytest.mark.asyncio
async def test_pre_invoke_uses_client_user_agent_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    context = _context()
    headers = {"X-MCP-Client-Name": "opencode", "X-MCP-Client-Version": "2.0"}
    await _plugin(monkeypatch).tool_pre_invoke(_pre(), context, _extensions(headers))
    assert context.state["ica_user_agent"] == "opencode/2.0"


@pytest.mark.asyncio
async def test_pre_invoke_uses_bare_client_name(monkeypatch: pytest.MonkeyPatch) -> None:
    context = _context()
    await _plugin(monkeypatch).tool_pre_invoke(_pre(), context, _extensions({"X-MCP-Client-Name": "client"}))
    assert context.state["ica_user_agent"] == "client"


@pytest.mark.asyncio
async def test_pre_invoke_uses_user_agent_last(monkeypatch: pytest.MonkeyPatch) -> None:
    context = _context()
    await _plugin(monkeypatch).tool_pre_invoke(_pre(), context, _extensions({"User-Agent": "sdk/3"}))
    assert context.state["ica_user_agent"] == "sdk/3"


@pytest.mark.asyncio
async def test_pre_invoke_derives_app_from_client(monkeypatch: pytest.MonkeyPatch) -> None:
    context = _context()
    await _plugin(monkeypatch).tool_pre_invoke(_pre(), context, _extensions({"X-MCP-Client-Name": "client"}))
    assert context.state["ica_app_id"] == "api:client"


@pytest.mark.asyncio
async def test_pre_invoke_derives_app_from_user_agent(monkeypatch: pytest.MonkeyPatch) -> None:
    context = _context()
    await _plugin(monkeypatch).tool_pre_invoke(_pre(), context, _extensions({"User-Agent": "sdk/3.0"}))
    assert context.state["ica_app_id"] == "api:sdk"


@pytest.mark.asyncio
async def test_pre_invoke_does_not_derive_browser_app(monkeypatch: pytest.MonkeyPatch) -> None:
    context = _context()
    await _plugin(monkeypatch).tool_pre_invoke(_pre(), context, _extensions({"User-Agent": "Mozilla/5.0"}))
    assert "ica_app_id" not in context.state


@pytest.mark.asyncio
async def test_pre_invoke_preserves_explicit_app(monkeypatch: pytest.MonkeyPatch) -> None:
    context = _context()
    headers = {"X-App-Id": "explicit", "X-MCP-Client-Name": "client"}
    await _plugin(monkeypatch).tool_pre_invoke(_pre(), context, _extensions(headers))
    assert context.state["ica_app_id"] == "explicit"


@pytest.mark.asyncio
async def test_pre_invoke_extracts_all_persona_headers(monkeypatch: pytest.MonkeyPatch) -> None:
    context = _context()
    headers = {
        "LlM_CaLl_TyPe": "assistant",
        "ASSISTANT_NAME": "Helper",
        "assistant_uuid": "a-1",
        "agent_name": "Agent",
        "agent_uuid": "g-1",
        "agent_tool_ids": "t-1",
        "digital-ibmer_name": "Digital",
        "digital-ibmer_uuid": "d-1",
        "digital-ibmer_tool_ids": "t-2",
    }
    await _plugin(monkeypatch).tool_pre_invoke(_pre(), context, _extensions(headers))
    assert {key for key in context.state if key.startswith("ica_") and key != "ica_metering_start_time"} >= {
        "ica_llm_call_type",
        "ica_assistant_name",
        "ica_assistant_uuid",
        "ica_agent_name",
        "ica_agent_uuid",
        "ica_agent_tool_ids",
        "ica_digital_ibmer_name",
        "ica_digital_ibmer_uuid",
        "ica_digital_ibmer_tool_ids",
    }


@pytest.mark.asyncio
async def test_pre_invoke_absent_headers_do_not_fabricate_attribution(monkeypatch: pytest.MonkeyPatch) -> None:
    context = _context()
    await _plugin(monkeypatch).tool_pre_invoke(_pre(), context, _extensions())
    assert set(context.state) == {"ica_metering_start_time"}


@pytest.mark.asyncio
async def test_model_priority_transport_header(monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = _plugin(monkeypatch, {"enabled": True, "global_default_model": "global"})
    plugin.env_model_name = "environment"
    plugin._gateway_configs = {"gateway": {"default_model": "gateway-default"}}
    context = _context({"model_name": "session", "meta_data": {"model": "tool"}, GATEWAY_METADATA: {"id": "gateway"}})
    await plugin.tool_pre_invoke(_pre(), context, _extensions({"X-OpenWebUI-Model-Id": "transport"}))
    await plugin.tool_post_invoke(_post(), context)
    assert _sent(plugin)["toolDetails"]["modelName"] == "transport"


@pytest.mark.asyncio
async def test_model_priority_session(monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = _plugin(monkeypatch, {"enabled": True, "global_default_model": "global"})
    plugin.env_model_name = "environment"
    context = _context({"model_name": "session", "meta_data": {"model": "tool"}})
    await plugin.tool_post_invoke(_post(), context)
    assert _sent(plugin)["toolDetails"]["modelName"] == "session"


@pytest.mark.asyncio
async def test_model_priority_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = _plugin(monkeypatch, {"enabled": True, "global_default_model": "global"})
    plugin.env_model_name = "environment"
    context = _context({"meta_data": {"model": "tool"}})
    await plugin.tool_post_invoke(_post(), context)
    assert _sent(plugin)["toolDetails"]["modelName"] == "environment"


@pytest.mark.asyncio
async def test_model_priority_tool_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = _plugin(monkeypatch, {"enabled": True, "global_default_model": "global"})
    context = _context({"meta_data": {"model": "tool"}})
    await plugin.tool_post_invoke(_post(), context)
    assert _sent(plugin)["toolDetails"]["modelName"] == "tool"


@pytest.mark.asyncio
async def test_model_priority_gateway_default(monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = _plugin(
        monkeypatch, {"enabled": True, "gateways": [{"id": "gateway", "default_model": "gateway-default"}]}
    )
    context = _context({GATEWAY_METADATA: {"id": "gateway"}})
    await plugin.tool_post_invoke(_post(), context)
    assert _sent(plugin)["toolDetails"]["modelName"] == "gateway-default"


class _GatewayMetadata(BaseModel):
    id: str
    name: str = "Gateway"
    transport: str = "sse"


@pytest.mark.asyncio
async def test_model_gateway_default_accepts_model_dump(monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = _plugin(monkeypatch, {"enabled": True, "gateways": [{"id": "gateway", "default_model": "gateway-model"}]})
    context = _context({GATEWAY_METADATA: _GatewayMetadata(id="gateway")})
    await plugin.tool_post_invoke(_post(), context)
    assert _sent(plugin)["toolDetails"]["modelName"] == "gateway-model"


@pytest.mark.asyncio
async def test_model_priority_global_default(monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = _plugin(monkeypatch, {"enabled": True, "global_default_model": "global"})
    await plugin.tool_post_invoke(_post(), _context())
    assert _sent(plugin)["toolDetails"]["modelName"] == "global"


@pytest.mark.asyncio
async def test_model_priority_unknown(monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = _plugin(monkeypatch)
    await plugin.tool_post_invoke(_post(), _context())
    assert _sent(plugin)["toolDetails"]["modelName"] is None


@pytest.mark.asyncio
async def test_model_source_is_included_when_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = _plugin(monkeypatch, {"enabled": True, "include_model_source": True})
    await plugin.tool_post_invoke(_post(), _context({"model_name": "session"}))
    assert _sent(plugin)["_metadata"]["modelSource"] == "session_init"


@pytest.mark.asyncio
async def test_model_source_is_omitted_when_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = _plugin(monkeypatch)
    await plugin.tool_post_invoke(_post(), _context({"model_name": "session"}))
    assert "_metadata" not in _sent(plugin)


@pytest.mark.asyncio
async def test_post_invoke_calculates_latency(monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = _plugin(monkeypatch)
    context = _context()
    await plugin.tool_pre_invoke(_pre(), context)
    await plugin.tool_post_invoke(_post(), context)
    assert _sent(plugin)["toolDetails"]["latencyMs"] >= 0


@pytest.mark.asyncio
async def test_post_invoke_latency_is_none_without_pre(monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = _plugin(monkeypatch)
    await plugin.tool_post_invoke(_post(), _context())
    assert _sent(plugin)["toolDetails"]["latencyMs"] is None


@pytest.mark.asyncio
async def test_post_invoke_skips_empty_name(monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = _plugin(monkeypatch)
    result = await plugin.tool_post_invoke(_post(""), _context())
    sender = plugin._send_to_ica
    assert result.continue_processing is True and isinstance(sender, AsyncMock) and sender.await_count == 0


@pytest.mark.asyncio
async def test_post_invoke_is_noop_when_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = _plugin(monkeypatch, {"enabled": False})
    result = await plugin.tool_post_invoke(_post(), _context(), _extensions())
    assert result.continue_processing is True and result.metadata in ({}, None)


@pytest.mark.asyncio
async def test_post_invoke_structured_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = _plugin(monkeypatch)
    context = _context({GATEWAY_METADATA: {"id": "gw-1", "name": "Gateway", "transport": "streamablehttp"}})
    await plugin.tool_post_invoke(_post("weather", {"meta": {"tokens": {"input": 10, "output": 20}}}), context)
    sent = _sent(plugin)
    assert sent["userEmail"] == "user@example.test"
    assert sent["teamName"] == "team-1"
    assert sent["toolDetails"] == {
        "toolName": "weather",
        "serverId": "server-1",
        "serverName": "Gateway",
        "gatewayId": "gw-1",
        "integrationType": "MCP",
        "requestType": "STREAMABLE_HTTP",
        "latencyMs": None,
        "hasError": False,
        "errorMessage": None,
        "cached": False,
        "retryAttempt": 0,
        "modelName": None,
        "traceId": "request-123",
        "tokenInput": 10,
        "tokenOutput": 20,
        "source": "ContextForge",
    }


@pytest.mark.asyncio
async def test_post_invoke_includes_attribution(monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = _plugin(monkeypatch)
    context = _context()
    headers = {"X-App-Id": "app", "User-Agent": "client/1", "assistant_name": "Helper"}
    await plugin.tool_pre_invoke(_pre(), context, _extensions(headers))
    await plugin.tool_post_invoke(_post(), context)
    sent = _sent(plugin)
    assert (sent["appId"], sent["userAgent"], sent["assistantName"]) == ("app", "client/1", "Helper")


@pytest.mark.asyncio
async def test_post_invoke_does_not_fabricate_attribution(monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = _plugin(monkeypatch)
    await plugin.tool_post_invoke(_post(), _context())
    sent = _sent(plugin)
    assert sent["appId"] is None and sent["userAgent"] is None and sent["assistantName"] is None


@pytest.mark.asyncio
async def test_post_invoke_user_email_from_string(monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = _plugin(monkeypatch)
    await plugin.tool_post_invoke(_post(), _context(user="person@example.test"))
    assert _sent(plugin)["userEmail"] == "person@example.test"


@pytest.mark.asyncio
async def test_post_invoke_user_email_from_dict_property(monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = _plugin(monkeypatch)
    await plugin.tool_post_invoke(_post(), _context(user={"email": "dict@example.test"}))
    assert _sent(plugin)["userEmail"] == "dict@example.test"


@pytest.mark.asyncio
async def test_request_type_streamablehttp(monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = _plugin(monkeypatch)
    await plugin.tool_post_invoke(_post(), _context({GATEWAY_METADATA: {"transport": "streamablehttp"}}))
    assert _sent(plugin)["toolDetails"]["requestType"] == "STREAMABLE_HTTP"


@pytest.mark.asyncio
async def test_request_type_streamable_http(monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = _plugin(monkeypatch)
    await plugin.tool_post_invoke(_post(), _context({GATEWAY_METADATA: {"transport": "streamable_http"}}))
    assert _sent(plugin)["toolDetails"]["requestType"] == "STREAMABLE_HTTP"


@pytest.mark.asyncio
async def test_request_type_sse(monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = _plugin(monkeypatch)
    await plugin.tool_post_invoke(_post(), _context({GATEWAY_METADATA: {"transport": "sse"}}))
    assert _sent(plugin)["toolDetails"]["requestType"] == "SSE"


@pytest.mark.asyncio
async def test_request_type_unknown(monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = _plugin(monkeypatch)
    await plugin.tool_post_invoke(_post(), _context())
    assert _sent(plugin)["toolDetails"]["requestType"] == "UNKNOWN"


@pytest.mark.asyncio
async def test_error_detection_true(monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = _plugin(monkeypatch)
    await plugin.tool_post_invoke(_post(result={"isError": True, "errorMessage": "failed"}), _context())
    details = _sent(plugin)["toolDetails"]
    assert details["hasError"] is True and details["errorMessage"] == "failed"


@pytest.mark.asyncio
async def test_error_detection_false(monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = _plugin(monkeypatch)
    await plugin.tool_post_invoke(_post(result={"isError": False}), _context())
    assert _sent(plugin)["toolDetails"]["hasError"] is False


@pytest.mark.asyncio
async def test_error_detection_non_dict(monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = _plugin(monkeypatch)
    await plugin.tool_post_invoke(_post(result="plain"), _context())
    assert _sent(plugin)["toolDetails"]["hasError"] is False


@pytest.mark.asyncio
async def test_token_extraction_integer(monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = _plugin(monkeypatch)
    await plugin.tool_post_invoke(_post(result={"meta": {"tokens": {"input": 10, "output": 20}}}), _context())
    details = _sent(plugin)["toolDetails"]
    assert (details["tokenInput"], details["tokenOutput"]) == (10, 20)


@pytest.mark.asyncio
async def test_token_extraction_coerces_values(monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = _plugin(monkeypatch)
    await plugin.tool_post_invoke(_post(result={"meta": {"tokens": {"input": 10.9, "output": "20"}}}), _context())
    details = _sent(plugin)["toolDetails"]
    assert (details["tokenInput"], details["tokenOutput"]) == (10, 20)


@pytest.mark.asyncio
async def test_token_extraction_malformed_meta(monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = _plugin(monkeypatch)
    await plugin.tool_post_invoke(_post(result={"meta": "invalid"}), _context())
    details = _sent(plugin)["toolDetails"]
    assert details["tokenInput"] is None and details["tokenOutput"] is None


@pytest.mark.asyncio
async def test_cache_and_retry_state(monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = _plugin(monkeypatch)
    context = _context()
    context.state.update({"cache_hit": True, "retry_count": 3})
    await plugin.tool_post_invoke(_post(), context)
    details = _sent(plugin)["toolDetails"]
    assert details["cached"] is True and details["retryAttempt"] == 3


@pytest.mark.asyncio
async def test_http_send_static_token_with_mock_transport(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(202)

    plugin = _plugin(monkeypatch, mock_send=False)
    assert plugin.http_client is not None
    await plugin.http_client.aclose()
    plugin.http_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    status = await plugin._send_to_ica({"key": "value"})
    await plugin.shutdown()
    assert status == "sent" and captured[0].headers["x-mcp-metering-token"] == "fixture-static-token"


@pytest.mark.asyncio
async def test_http_send_jwt_with_mock_transport(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(202)

    plugin = _plugin(
        monkeypatch,
        {"enabled": True, "metering_url": "https://example.invalid", "jwt_secret": JWT_FIXTURE},
        mock_send=False,
    )
    assert plugin.http_client is not None
    await plugin.http_client.aclose()
    plugin.http_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    status = await plugin._send_to_ica({"key": "value"})
    await plugin.shutdown()
    assert status == "sent" and captured[0].headers["authorization"].startswith("Bearer ")


@pytest.mark.asyncio
async def test_http_send_is_awaited_sequentially(monkeypatch: pytest.MonkeyPatch) -> None:
    completed = False

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal completed
        completed = True
        return httpx.Response(202)

    plugin = _plugin(monkeypatch, mock_send=False)
    assert plugin.http_client is not None
    await plugin.http_client.aclose()
    plugin.http_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    await plugin.tool_post_invoke(_post(), _context())
    await plugin.shutdown()
    assert completed is True


@pytest.mark.asyncio
async def test_http_non_202_returns_failed(monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = _plugin(monkeypatch, mock_send=False)
    assert plugin.http_client is not None
    await plugin.http_client.aclose()
    plugin.http_client = httpx.AsyncClient(transport=httpx.MockTransport(lambda _request: httpx.Response(500)))
    status = await plugin._send_to_ica({})
    await plugin.shutdown()
    assert status == "failed"


@pytest.mark.asyncio
async def test_http_network_error_is_best_effort(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        message = "offline"
        raise httpx.ConnectError(message, request=request)

    plugin = _plugin(monkeypatch, mock_send=False)
    assert plugin.http_client is not None
    await plugin.http_client.aclose()
    plugin.http_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    status = await plugin._send_to_ica({})
    await plugin.shutdown()
    assert status == "failed"


@pytest.mark.asyncio
async def test_http_skips_without_client(monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = _plugin(monkeypatch, {"enabled": False}, mock_send=False)
    assert await plugin._send_to_ica({}) == "failed"


@pytest.mark.asyncio
async def test_http_skips_without_url(monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = _plugin(monkeypatch, {"enabled": True, "metering_token": "token"}, mock_send=False)
    status = await plugin._send_to_ica({})
    await plugin.shutdown()
    assert status == "skipped_no_url"


@pytest.mark.asyncio
async def test_http_skips_without_auth(monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = _plugin(monkeypatch, {"enabled": True, "metering_url": "https://example.invalid"}, mock_send=False)
    status = await plugin._send_to_ica({})
    await plugin.shutdown()
    assert status == "skipped_no_auth"


def test_jwt_is_hs256(monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = _plugin(monkeypatch)
    token = plugin._get_service_jwt(JWT_FIXTURE)
    assert jwt.get_unverified_header(token)["alg"] == "HS256"


def test_jwt_subject_claim(monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = _plugin(monkeypatch)
    claims = jwt.decode(plugin._get_service_jwt(JWT_FIXTURE), JWT_FIXTURE, algorithms=["HS256"])
    assert claims["sub"] == "contextforge-metering"


def test_jwt_service_claims(monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = _plugin(monkeypatch)
    claims = jwt.decode(plugin._get_service_jwt(JWT_FIXTURE), JWT_FIXTURE, algorithms=["HS256"])
    assert claims["service"] == "mcp-context-forge" and claims["scope"] == "metering:write"


def test_jwt_expiry(monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = _plugin(monkeypatch)
    claims = jwt.decode(plugin._get_service_jwt(JWT_FIXTURE), JWT_FIXTURE, algorithms=["HS256"])
    assert 86_300 <= claims["exp"] - claims["iat"] <= 86_500


@pytest.mark.asyncio
async def test_post_metadata_requires_trace(monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = _plugin(monkeypatch)
    result = await plugin.tool_post_invoke(_post(), _context(), _extensions(trace_id=None))
    assert result.metadata == {}


@pytest.mark.asyncio
async def test_post_metadata_with_trace_has_exact_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = _plugin(monkeypatch)
    result = await plugin.tool_post_invoke(_post(), _context({"model_name": "session"}), _extensions())
    assert result.metadata is not None
    metadata = result.metadata["ica_metering_exporter"]
    assert set(metadata) == {"export_status", "latency_ms", "model_source", "stage"}


@pytest.mark.asyncio
async def test_post_metadata_never_contains_trace_id(monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = _plugin(monkeypatch)
    result = await plugin.tool_post_invoke(_post(), _context(), _extensions(trace_id="unique-trace-sentinel"))
    assert "unique-trace-sentinel" not in json.dumps(result.metadata)


@pytest.mark.asyncio
async def test_post_metadata_is_non_sensitive(monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = _plugin(
        monkeypatch,
        {"enabled": True, "metering_token": "unique-token-sentinel", "jwt_secret": "unique-secret-sentinel"},
    )
    context = _context()
    extensions = _extensions(
        {
            "X-App-Id": "unique-app-sentinel",
            "User-Agent": "unique-agent-sentinel",
            "assistant_name": "unique-persona-sentinel",
        }
    )
    await plugin.tool_pre_invoke(
        ToolPreInvokePayload(name="tool", args={"value": "unique-argument-sentinel"}), context, extensions
    )
    result = await plugin.tool_post_invoke(_post(result={"content": "unique-output-sentinel"}), context, extensions)
    serialized = json.dumps(result.metadata)
    for sentinel in (
        "unique-token",
        "unique-secret",
        "unique-app",
        "unique-agent",
        "unique-persona",
        "unique-argument",
        "unique-output",
    ):
        assert sentinel not in serialized


@pytest.mark.asyncio
async def test_post_accepts_extensions_none(monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = _plugin(monkeypatch)
    result = await plugin.tool_post_invoke(_post(), _context(), None)
    assert result.continue_processing is True and result.metadata == {}


def test_config_none_is_normalized(monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = IcaMeteringExporterPlugin(
        PluginConfig(
            name="test", kind="cpex_ica_metering_exporter.plugin.IcaMeteringExporterPlugin", hooks=[], config=None
        )
    )
    assert plugin.telemetry_config == {} and plugin.http_client is None


def test_disabled_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = _plugin(monkeypatch, {})
    assert plugin.http_client is None


def test_enabled_creates_http_client(monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = _plugin(monkeypatch)
    assert isinstance(plugin.http_client, httpx.AsyncClient)


@pytest.mark.asyncio
async def test_shutdown_closes_client(monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = _plugin(monkeypatch)
    client = plugin.http_client
    assert client is not None
    await plugin.shutdown()
    assert client.is_closed and plugin.http_client is None


@pytest.mark.asyncio
async def test_shutdown_without_client(monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = _plugin(monkeypatch, {"enabled": False})
    await plugin.shutdown()
    assert plugin.http_client is None


def test_get_header_is_case_insensitive(monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = _plugin(monkeypatch)
    assert plugin._get_header({"X-App-ID": "value"}, "x-app-id") == "value"


def test_get_header_handles_malformed_values(monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = _plugin(monkeypatch)
    assert plugin._get_header({"X-App-ID": 123}, "x-app-id") == "123"


def test_coerce_int_valid(monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = _plugin(monkeypatch)
    assert plugin._coerce_int("42") == 42


def test_coerce_int_invalid(monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = _plugin(monkeypatch)
    assert plugin._coerce_int([]) is None


def test_extract_tokens_valid(monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = _plugin(monkeypatch)
    assert plugin._extract_tokens({"meta": {"tokens": {"input": 1}}}) == {"input": 1}


def test_extract_tokens_invalid(monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = _plugin(monkeypatch)
    assert plugin._extract_tokens({"meta": []}) == {}


def test_is_error_various(monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = _plugin(monkeypatch)
    assert plugin._is_error({"isError": True}) is True and plugin._is_error(None) is False


def test_extract_error_message(monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = _plugin(monkeypatch)
    assert plugin._extract_error_message({"isError": True, "errorMessage": "failed"}) == "failed"
