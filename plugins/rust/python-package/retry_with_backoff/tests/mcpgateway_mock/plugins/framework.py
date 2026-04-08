"""Minimal mock of mcpgateway.plugins.framework for testing."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


class Plugin:
    def __init__(self, config: "PluginConfig") -> None:
        self.config = config


@dataclass
class PluginConfig:
    id: str = ""
    kind: str = ""
    name: str = ""
    enabled: bool = True
    order: int = 0
    config: dict[str, Any] | None = None


@dataclass
class GlobalContext:
    request_id: str = ""


@dataclass
class PluginContext:
    plugin_id: str = ""
    global_context: GlobalContext = field(default_factory=GlobalContext)


@dataclass
class ToolPostInvokePayload:
    name: str
    result: Any


@dataclass
class ToolPostInvokeResult:
    retry_delay_ms: int = 0
    metadata: dict[str, Any] | None = None


@dataclass
class ResourcePostFetchPayload:
    uri: str
    content: Any


@dataclass
class ResourcePostFetchResult:
    metadata: dict[str, Any] | None = None
