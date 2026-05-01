from dataclasses import dataclass

from pydantic import BaseModel, RootModel, model_serializer

from cpex.framework import (
    GlobalContext,
    PluginConfig,
    PluginContext,
    PluginManager,
    PluginMode,
    PromptHookType,
    PromptPrehookPayload,
    ResourceHookType,
    ResourcePostFetchPayload,
    ToolHookType,
    ToolPostInvokePayload,
)

from cpex_secrets_detection.secrets_detection import SecretsDetectionPlugin
from cpex_secrets_detection.secrets_detection_rust import py_scan_container

__all__ = [
    "BaseModel",
    "GlobalContext",
    "PluginManager",
    "PluginMode",
    "PromptHookType",
    "PromptPrehookPayload",
    "ResourceContent",
    "ResourceHookType",
    "ResourcePostFetchPayload",
    "RootModel",
    "SecretsDetectionPlugin",
    "ToolHookType",
    "ToolPostInvokePayload",
    "make_config",
    "make_context",
    "model_serializer",
    "py_scan_container",
]


@dataclass
class ResourceContent:
    type: str
    id: str
    uri: str
    text: str


def make_context() -> PluginContext:
    return PluginContext(
        global_context=GlobalContext(request_id="req-secrets", server_id="srv-secrets")
    )


def make_config(**overrides) -> PluginConfig:
    config = {
        "block_on_detection": False,
        "redact": True,
        "redaction_text": "[REDACTED]",
    }
    config.update(overrides)
    return PluginConfig(
        name="secrets_detection",
        kind="cpex_secrets_detection.secrets_detection.SecretsDetectionPlugin",
        config=config,
    )
