from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Plugin:
    def __init__(self, config: "PluginConfig") -> None:
        self._config = config


class PromptHookType(str, Enum):
    PROMPT_PRE_FETCH = "prompt_pre_fetch"


class ToolHookType(str, Enum):
    TOOL_POST_INVOKE = "tool_post_invoke"


class ResourceHookType(str, Enum):
    RESOURCE_POST_FETCH = "resource_post_fetch"


@dataclass
class PluginConfig:
    name: str = ""
    kind: str = ""
    hooks: list[Any] = field(default_factory=list)
    config: dict[str, Any] | None = None


@dataclass
class GlobalContext:
    request_id: str = ""


@dataclass
class PluginContext:
    global_context: GlobalContext | None = None


@dataclass
class PluginViolation:
    reason: str = ""
    description: str = ""
    code: str = ""
    details: dict[str, Any] | None = None


@dataclass
class PromptPrehookPayload:
    prompt_id: str
    args: dict[str, Any] | None = None


@dataclass
class PromptPrehookResult:
    continue_processing: bool = True
    violation: PluginViolation | None = None
    modified_payload: PromptPrehookPayload | None = None
    metadata: dict[str, Any] | None = None


@dataclass
class ToolPostInvokePayload:
    name: str
    result: Any


@dataclass
class ToolPostInvokeResult:
    continue_processing: bool = True
    violation: PluginViolation | None = None
    modified_payload: ToolPostInvokePayload | None = None
    metadata: dict[str, Any] | None = None


@dataclass
class ResourcePostFetchPayload:
    uri: str
    content: Any


@dataclass
class ResourcePostFetchResult:
    continue_processing: bool = True
    violation: PluginViolation | None = None
    modified_payload: ResourcePostFetchPayload | None = None
    metadata: dict[str, Any] | None = None
