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


@dataclass
class PromptPrehookPayload:
    prompt_id: str = ""
    args: dict[str, Any] | None = None


@dataclass
class PromptPrehookResult:
    continue_processing: bool = True
    violation: PluginViolation | None = None
    modified_payload: PromptPrehookPayload | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ToolPostInvokePayload:
    name: str = ""
    result: Any = None


@dataclass
class ToolPostInvokeResult:
    continue_processing: bool = True
    violation: PluginViolation | None = None
    modified_payload: ToolPostInvokePayload | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ResourceContent:
    text: str

    def model_dump(self) -> dict[str, Any]:
        return {"text": self.text}


@dataclass
class ResourcePostFetchPayload:
    uri: str = ""
    content: ResourceContent | Any = None


@dataclass
class ResourcePostFetchResult:
    continue_processing: bool = True
    violation: PluginViolation | None = None
    modified_payload: ResourcePostFetchPayload | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
