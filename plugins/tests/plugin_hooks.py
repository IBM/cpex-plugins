"""Minimal plugin hook contracts for integration tests."""

from __future__ import annotations

import importlib
from dataclasses import dataclass, field, fields, is_dataclass
from enum import Enum
from typing import Any


@dataclass(frozen=True)
class HookPayloadPolicy:
    writable_fields: frozenset[str]


class CopyOnWriteDict(dict):
    def __init__(self, original: dict[str, Any]) -> None:
        super().__init__()
        self._original = original

    def __getitem__(self, key: Any) -> Any:
        return super().__getitem__(key) if key in self else self._original[key]

    def __iter__(self):
        return iter(self._original)

    def __len__(self) -> int:
        return len(self._original)

    def items(self):
        return ((key, self[key]) for key in self)

    def copy(self) -> dict:
        return dict(self.items())


def wrap_payload_for_isolation(payload: Any) -> Any:
    if not is_dataclass(payload):
        return payload
    updates = {}
    for item in fields(payload):
        value = getattr(payload, item.name)
        updates[item.name] = CopyOnWriteDict(value) if isinstance(value, dict) else value
    return type(payload)(**updates)


def apply_policy(
    original: Any,
    modified: Any,
    policy: HookPayloadPolicy,
    *,
    apply_to: Any | None = None,
) -> Any | None:
    target = apply_to if apply_to is not None else original
    updates = {}
    for item in fields(modified):
        old_value = getattr(original, item.name)
        new_value = getattr(modified, item.name)
        if new_value == old_value:
            continue
        if item.name in policy.writable_fields:
            updates[item.name] = new_value
    if not updates:
        return None
    values = {item.name: getattr(target, item.name) for item in fields(target)}
    values.update(updates)
    return type(target)(**values)


class PromptHookType(str, Enum):
    PROMPT_PRE_FETCH = "prompt_pre_fetch"
    PROMPT_POST_FETCH = "prompt_post_fetch"


class ToolHookType(str, Enum):
    TOOL_PRE_INVOKE = "tool_pre_invoke"
    TOOL_POST_INVOKE = "tool_post_invoke"


class ResourceHookType(str, Enum):
    RESOURCE_PRE_FETCH = "resource_pre_fetch"
    RESOURCE_POST_FETCH = "resource_post_fetch"


class PluginMode(str, Enum):
    DISABLED = "disabled"
    ENFORCE = "enforce"
    ENFORCE_IGNORE_ERROR = "enforce_ignore_error"
    PERMISSIVE = "permissive"


@dataclass
class PluginConfig:
    name: str = ""
    kind: str = ""
    version: str = ""
    hooks: list[Any] = field(default_factory=list)
    priority: int = 0
    mode: str = PluginMode.ENFORCE.value
    id: str = ""
    enabled: bool = True
    order: int = 0
    config: dict[str, Any] | None = None


class Plugin:
    def __init__(self, config: PluginConfig) -> None:
        self._config = config
        self.config = config

    @property
    def name(self) -> str:
        return self._config.name

    @property
    def priority(self) -> int:
        return self._config.priority

    @property
    def mode(self) -> str:
        return self._config.mode

    async def initialize(self) -> None:
        pass

    async def shutdown(self) -> None:
        pass


@dataclass
class GlobalContext:
    request_id: str = ""
    server_id: str = ""
    user: Any = None
    tenant_id: str | None = None


@dataclass
class PluginContext:
    plugin_id: str = ""
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
    plugin_name: str = ""


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
    http_headers: dict[str, str] | None = None


@dataclass
class PromptPosthookPayload:
    prompt_id: str = ""
    result: Any = None


@dataclass
class PromptPosthookResult:
    continue_processing: bool = True
    violation: PluginViolation | None = None
    modified_payload: PromptPosthookPayload | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    http_headers: dict[str, str] | None = None


@dataclass
class ToolPreInvokePayload:
    name: str = ""
    args: dict[str, Any] | None = None
    arguments: dict[str, Any] | None = None


@dataclass
class ToolPreInvokeResult:
    continue_processing: bool = True
    violation: PluginViolation | None = None
    modified_payload: ToolPreInvokePayload | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    http_headers: dict[str, str] | None = None


@dataclass
class ToolPostInvokePayload:
    name: str
    result: Any


@dataclass
class ToolPostInvokeResult:
    continue_processing: bool = True
    violation: PluginViolation | None = None
    modified_payload: ToolPostInvokePayload | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    retry_delay_ms: int = 0


@dataclass
class ResourcePreFetchPayload:
    uri: str = ""


@dataclass
class ResourcePreFetchResult:
    continue_processing: bool = True
    violation: PluginViolation | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    http_headers: dict[str, str] | None = None


@dataclass
class ResourcePostFetchPayload:
    uri: str
    content: Any


@dataclass
class ResourcePostFetchResult:
    continue_processing: bool = True
    violation: PluginViolation | None = None
    modified_payload: ResourcePostFetchPayload | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ResourceContent:
    type: str
    id: str
    uri: str
    text: str


class _Settings:
    max_tool_retries = 5


def get_settings() -> _Settings:
    return _Settings()


class PluginManager:
    _instances: list[Plugin] = []

    def __init__(self, config_file: str) -> None:
        self.config_file = config_file
        self.plugins: list[Plugin] = []
        self._initialized = False

    @classmethod
    def reset(cls) -> None:
        cls._instances = []

    async def initialize(self) -> None:
        import yaml

        with open(self.config_file, encoding="utf-8") as handle:
            config = yaml.safe_load(handle) or {}
        for item in config.get("plugins", []):
            if item.get("enabled", True) is False:
                continue
            if item.get("mode") == PluginMode.DISABLED.value:
                continue
            module_name, class_name = item["kind"].rsplit(".", 1)
            plugin_type = getattr(importlib.import_module(module_name), class_name)
            plugin_config = PluginConfig(
                name=item.get("name", ""),
                kind=item.get("kind", ""),
                hooks=item.get("hooks", []),
                priority=item.get("priority", 0),
                mode=item.get("mode", PluginMode.ENFORCE.value),
                config=item.get("config") or {},
            )
            plugin = plugin_type(plugin_config)
            await plugin.initialize()
            self.plugins.append(plugin)
        self.plugins.sort(key=lambda plugin: plugin.priority)
        type(self)._instances = self.plugins
        self._initialized = True

    async def shutdown(self) -> None:
        for plugin in self.plugins:
            await plugin.shutdown()
        self.plugins = []
        self._initialized = False

    async def invoke_hook(
        self,
        hook_type: PromptHookType | ToolHookType | ResourceHookType,
        payload: Any,
        global_context: GlobalContext,
        local_contexts: dict[str, Any] | None = None,
        violations_as_exceptions: bool = True,
    ) -> tuple[Any, None]:
        del local_contexts, violations_as_exceptions
        hook_name = hook_type.value if isinstance(hook_type, Enum) else str(hook_type)
        context = PluginContext(global_context=global_context)
        result = None
        for plugin in self.plugins:
            configured_hooks = {
                hook.value if isinstance(hook, Enum) else str(hook)
                for hook in plugin.config.hooks
            }
            if hook_name not in configured_hooks:
                continue
            method = getattr(plugin, hook_name, None)
            if method is None:
                continue
            try:
                result = await method(payload, context)
            except Exception:
                if plugin.mode == PluginMode.ENFORCE_IGNORE_ERROR.value:
                    continue
                raise
            if result is not None and getattr(result, "modified_payload", None) is not None:
                payload = result.modified_payload
            if (
                plugin.mode != PluginMode.PERMISSIVE.value
                and result is not None
                and getattr(result, "continue_processing", True) is False
            ):
                break
        return result, None
