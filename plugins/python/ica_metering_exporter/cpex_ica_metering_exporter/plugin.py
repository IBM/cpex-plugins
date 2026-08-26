# SPDX-License-Identifier: Apache-2.0
"""ICA metering exporter plugin."""

from __future__ import annotations

import logging
import os
import time
from typing import Any, ClassVar, Optional

import httpx
from cpex.framework import (
    Plugin,
    PluginConfig,
    PluginContext,
    ToolPostInvokePayload,
    ToolPostInvokeResult,
    ToolPreInvokePayload,
    ToolPreInvokeResult,
)
from cpex.framework.constants import GATEWAY_METADATA

from cpex_ica_metering_exporter.metering import (
    coerce_int,
    extract_error_message,
    extract_tokens,
    get_header,
    is_error,
)
from cpex_ica_metering_exporter.transport import ExportRequest, get_service_jwt, send_to_ica

logger = logging.getLogger(__name__)


class IcaMeteringExporterPlugin(Plugin):
    """Export MCP tool invocation metrics to ICA metering service."""

    CALL_CONTEXT_HEADERS: ClassVar[dict[str, str]] = {
        "ica_llm_call_type": "llm_call_type",
        "ica_assistant_name": "assistant_name",
        "ica_assistant_uuid": "assistant_uuid",
        "ica_agent_name": "agent_name",
        "ica_agent_uuid": "agent_uuid",
        "ica_agent_tool_ids": "agent_tool_ids",
        "ica_digital_ibmer_name": "digital-ibmer_name",
        "ica_digital_ibmer_uuid": "digital-ibmer_uuid",
        "ica_digital_ibmer_tool_ids": "digital-ibmer_tool_ids",
    }

    _get_header = staticmethod(get_header)
    _coerce_int = staticmethod(coerce_int)
    _get_service_jwt = staticmethod(get_service_jwt)
    _is_error = staticmethod(is_error)
    _extract_error_message = staticmethod(extract_error_message)
    _extract_tokens = staticmethod(extract_tokens)

    def __init__(self, config: PluginConfig) -> None:
        """Initialize normalized configuration and the optional HTTP client."""
        super().__init__(config)
        self.telemetry_config: dict[str, Any] = dict(config.config or {})
        self.http_client: Optional[httpx.AsyncClient] = None
        self.env_model_name: Optional[str] = None
        raw_secret = self.telemetry_config.get("jwt_secret")
        self._jwt_secret: Optional[str] = raw_secret if isinstance(raw_secret, str) and raw_secret else None
        self._gateway_configs: dict[str, dict[str, Any]] = {}
        raw_gateways = self.telemetry_config.get("gateways", [])
        if isinstance(raw_gateways, list):
            for gateway in raw_gateways:
                if not isinstance(gateway, dict):
                    continue
                gateway_id = gateway.get("id")
                if isinstance(gateway_id, str) and gateway_id:
                    self._gateway_configs[gateway_id] = gateway
        if bool(self.telemetry_config.get("enabled", False)):
            self.http_client = httpx.AsyncClient(
                timeout=httpx.Timeout(5.0, connect=2.0),
                limits=httpx.Limits(max_keepalive_connections=5),
            )
            self.env_model_name = os.getenv("MCP_DEFAULT_MODEL")

    async def shutdown(self) -> None:
        """Close the HTTP client held by the plugin."""
        if self.http_client is not None:
            await self.http_client.aclose()
            self.http_client = None

    async def tool_pre_invoke(
        self,
        payload: ToolPreInvokePayload,
        context: PluginContext,
        extensions: Any = None,
    ) -> ToolPreInvokeResult:
        """Record start time and caller attribution from HTTP extensions."""
        if not bool(self.telemetry_config.get("enabled", False)):
            return ToolPreInvokeResult(continue_processing=True)
        context.state["ica_metering_start_time"] = time.monotonic()
        raw_headers: dict[str, Any] = {}
        if extensions is not None:
            http_extension = getattr(extensions, "http", None)
            if http_extension is not None:
                extension_headers = getattr(http_extension, "headers", None)
                if isinstance(extension_headers, dict):
                    raw_headers = extension_headers
        model_name = self._get_header(raw_headers, "X-OpenWebUI-Model-Id")
        if model_name:
            context.state["ica_metering_model_name"] = model_name
        app_id = self._get_header(raw_headers, "X-App-Id")
        if app_id:
            context.state["ica_app_id"] = app_id
        client_name = self._get_header(raw_headers, "X-MCP-Client-Name")
        client_version = self._get_header(raw_headers, "X-MCP-Client-Version")
        if client_name:
            context.state["ica_mcp_client_name"] = client_name
            context.state["ica_mcp_client_version"] = client_version
        user_agent = self._get_header(raw_headers, "X-Forwarded-User-Agent")
        if not user_agent and client_name:
            user_agent = f"{client_name}/{client_version}" if client_version else client_name
        if not user_agent:
            user_agent = self._get_header(raw_headers, "User-Agent")
        if user_agent:
            context.state["ica_user_agent"] = user_agent
        if not app_id and client_name:
            context.state["ica_app_id"] = f"api:{client_name}"
        elif not app_id and user_agent:
            user_agent_name = user_agent.split("/", maxsplit=1)[0].strip()
            if "/" not in user_agent:
                user_agent_name = user_agent.split(maxsplit=1)[0].strip()
            if user_agent_name and not user_agent_name.startswith("Mozilla"):
                context.state["ica_app_id"] = f"api:{user_agent_name}"
        for state_key, header_name in self.CALL_CONTEXT_HEADERS.items():
            value = self._get_header(raw_headers, header_name)
            if value:
                context.state[state_key] = value
        logger.debug("ICA metering: Pre-invoke for tool %s", payload.name)
        return ToolPreInvokeResult(continue_processing=True)

    async def tool_post_invoke(
        self,
        payload: ToolPostInvokePayload,
        context: PluginContext,
        extensions: Any = None,
    ) -> ToolPostInvokeResult:
        """Build and export one tool invocation metering record."""
        if not bool(self.telemetry_config.get("enabled", False)):
            return ToolPostInvokeResult(continue_processing=True)
        started_at = context.state.get("ica_metering_start_time")
        latency_ms: Optional[int] = None
        if isinstance(started_at, (int, float)):
            latency_ms = max(0, int((time.monotonic() - started_at) * 1000))
        if not payload.name:
            logger.warning("ICA metering: Tool name is empty, skipping")
            return ToolPostInvokeResult(continue_processing=True)
        gateway_raw = context.global_context.metadata.get(GATEWAY_METADATA, {})
        if hasattr(gateway_raw, "model_dump"):
            dumped_gateway = gateway_raw.model_dump()
            gateway_meta = dumped_gateway if isinstance(dumped_gateway, dict) else {}
        elif isinstance(gateway_raw, dict):
            gateway_meta = gateway_raw
        else:
            gateway_meta = {}
        context_raw = context.global_context.metadata.get("meta_data", {})
        context_meta = context_raw if isinstance(context_raw, dict) else {}
        model_name, model_source = self._resolve_model_name(context, context_meta, gateway_meta)
        raw_transport = gateway_meta.get("transport", "")
        transport = raw_transport.lower() if isinstance(raw_transport, str) else ""
        if transport in ("streamablehttp", "streamable_http"):
            request_type = "STREAMABLE_HTTP"
        elif transport == "sse":
            request_type = "SSE"
        else:
            request_type = transport.upper() if transport else "UNKNOWN"
        tokens = self._extract_tokens(payload.result)
        tool_details: dict[str, Any] = {
            "toolName": payload.name,
            "serverId": context.global_context.server_id or "unknown",
            "serverName": gateway_meta.get("name"),
            "gatewayId": gateway_meta.get("id"),
            "integrationType": "MCP",
            "requestType": request_type,
            "latencyMs": latency_ms,
            "hasError": self._is_error(payload.result),
            "errorMessage": self._extract_error_message(payload.result),
            "cached": context.state.get("cache_hit", False),
            "retryAttempt": context.state.get("retry_count", 0),
            "modelName": model_name,
            "traceId": context.global_context.request_id,
            "tokenInput": self._coerce_int(tokens.get("input")),
            "tokenOutput": self._coerce_int(tokens.get("output")),
            "source": "ContextForge",
        }
        global_user = context.global_context.user
        user_email = context.user_email or (global_user if isinstance(global_user, str) else None) or "unknown"
        metering_payload: dict[str, Any] = {
            "userEmail": user_email,
            "teamName": context.global_context.tenant_id or "unknown",
            "appId": context.state.get("ica_app_id"),
            "userAgent": context.state.get("ica_user_agent"),
            "llmCallType": context.state.get("ica_llm_call_type"),
            "assistantName": context.state.get("ica_assistant_name"),
            "assistantUuid": context.state.get("ica_assistant_uuid"),
            "agentName": context.state.get("ica_agent_name"),
            "agentUuid": context.state.get("ica_agent_uuid"),
            "agentToolIds": context.state.get("ica_agent_tool_ids"),
            "digitalIbmerName": context.state.get("ica_digital_ibmer_name"),
            "digitalIbmerUuid": context.state.get("ica_digital_ibmer_uuid"),
            "digitalIbmerToolIds": context.state.get("ica_digital_ibmer_tool_ids"),
            "toolDetails": tool_details,
        }
        if bool(self.telemetry_config.get("include_model_source", False)):
            metering_payload["_metadata"] = {"modelSource": model_source}
        export_status = await self._send_to_ica(metering_payload)
        trace_id = getattr(getattr(extensions, "request", None), "trace_id", None) if extensions is not None else None
        metadata = (
            {
                "ica_metering_exporter": {
                    "export_status": export_status,
                    "latency_ms": latency_ms,
                    "model_source": model_source,
                    "stage": "tool_post_invoke",
                }
            }
            if trace_id
            else {}
        )
        return ToolPostInvokeResult(continue_processing=True, metadata=metadata)

    def _resolve_model_name(
        self,
        context: PluginContext,
        context_meta: dict[str, Any],
        gateway_meta: dict[str, Any],
    ) -> tuple[Optional[str], Optional[str]]:
        """Resolve the model name through the seven-level precedence cascade."""
        model = context.state.get("ica_metering_model_name")
        if model:
            return str(model), "transport_header"
        model = context.global_context.metadata.get("model_name")
        if model:
            return str(model), "session_init"
        if self.env_model_name:
            return self.env_model_name, "environment"
        model = context_meta.get("model")
        if model:
            return str(model), "tool_metadata"
        gateway_id = gateway_meta.get("id")
        if isinstance(gateway_id, str) and gateway_id in self._gateway_configs:
            model = self._gateway_configs[gateway_id].get("default_model")
            if model:
                return str(model), "gateway_default"
        model = self.telemetry_config.get("global_default_model")
        if model:
            return str(model), "global_default"
        return None, "unknown"

    async def _send_to_ica(self, payload: dict[str, Any]) -> str:
        """Delegate an awaited best-effort export to the transport boundary."""
        return await send_to_ica(
            ExportRequest(
                client=self.http_client,
                config=self.telemetry_config,
                jwt_secret=self._jwt_secret,
                payload=payload,
            )
        )
