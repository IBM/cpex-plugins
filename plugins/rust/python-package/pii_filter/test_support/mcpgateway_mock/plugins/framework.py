from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


class Plugin:
    def __init__(self, config: PluginConfig) -> None:
        self._config = config


@dataclass
class PluginConfig:
    name: str = ""
    config: dict[str, Any] | None = None


@dataclass
class GlobalContext:
    user: Any = None
    tenant_id: str | None = None


@dataclass
class PluginContext:
    global_context: GlobalContext = field(default_factory=GlobalContext)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class PluginViolation:
    reason: str = ""
    description: str = ""
    code: str = ""
    details: dict[str, Any] | None = None
    http_status_code: int = 400
    http_headers: dict[str, str] | None = None


@dataclass
class PromptPrehookPayload:
    prompt_id: str = ""
    args: dict[str, Any] | None = None


@dataclass
class PromptPrehookResult:
    continue_processing: bool = True
    violation: PluginViolation | None = None
    modified_payload: PromptPrehookPayload | None = None


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


@dataclass
class PromptPosthookPayload:
    result: PromptResult


@dataclass
class PromptPosthookResult:
    continue_processing: bool = True
    violation: PluginViolation | None = None
    modified_payload: PromptPosthookPayload | None = None


@dataclass
class ToolPreInvokePayload:
    name: str = ""
    args: dict[str, Any] | None = None


@dataclass
class ToolPreInvokeResult:
    continue_processing: bool = True
    violation: PluginViolation | None = None
    modified_payload: ToolPreInvokePayload | None = None


@dataclass
class ToolPostInvokePayload:
    name: str = ""
    result: Any = None


@dataclass
class ToolPostInvokeResult:
    continue_processing: bool = True
    violation: PluginViolation | None = None
    modified_payload: ToolPostInvokePayload | None = None
