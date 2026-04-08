from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Plugin:
    def __init__(self, config: PluginConfig) -> None:
        self.config = config


class ResourceHookType(str, Enum):
    RESOURCE_PRE_FETCH = "resource_pre_fetch"


@dataclass
class PluginConfig:
    name: str = ""
    kind: str = ""
    version: str = ""
    hooks: list[str] | list[ResourceHookType] = field(default_factory=list)
    config: dict[str, Any] | None = None


@dataclass
class PluginContext:
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
class ResourcePreFetchPayload:
    uri: str = ""


@dataclass
class ResourcePreFetchResult:
    continue_processing: bool = True
    violation: PluginViolation | None = None
    metadata: dict[str, Any] | None = None
    http_headers: dict[str, str] | None = None
