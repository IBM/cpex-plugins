"""Minimal mock of mcpgateway.plugins.framework for testing.

Provides just enough surface area to let cpex_rate_limiter.rate_limiter
import and function without the real mcpgateway package installed.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple


class PluginMode(str, Enum):
    ENFORCE = "enforce"
    ENFORCE_IGNORE_ERROR = "enforce_ignore_error"
    PERMISSIVE = "permissive"
    DISABLED = "disabled"


class PromptHookType(str, Enum):
    PROMPT_PRE_FETCH = "prompt_pre_fetch"
    PROMPT_POST_FETCH = "prompt_post_fetch"


class ToolHookType(str, Enum):
    TOOL_PRE_INVOKE = "tool_pre_invoke"
    TOOL_POST_INVOKE = "tool_post_invoke"


@dataclass
class PluginConfig:
    """Plugin configuration envelope."""

    name: str = ""
    kind: str = ""
    hooks: List[Any] = field(default_factory=list)
    priority: int = 0
    mode: PluginMode = PluginMode.ENFORCE
    config: Optional[Dict[str, Any]] = None


@dataclass
class GlobalContext:
    request_id: str = ""
    user: Any = None
    tenant_id: Optional[str] = None


@dataclass
class PluginContext:
    global_context: GlobalContext = field(default_factory=GlobalContext)


@dataclass
class PluginViolation:
    reason: str = ""
    description: str = ""
    code: str = ""
    details: Optional[Dict[str, Any]] = None
    http_status_code: int = 400
    http_headers: Optional[Dict[str, str]] = None
    plugin_name: str = ""


@dataclass
class PromptPrehookPayload:
    prompt_id: str = ""
    args: Optional[Dict[str, Any]] = None


@dataclass
class PromptPrehookResult:
    continue_processing: bool = True
    violation: Optional[PluginViolation] = None
    modified_payload: Optional[PromptPrehookPayload] = None
    metadata: Optional[Dict[str, Any]] = None
    http_headers: Optional[Dict[str, str]] = None


@dataclass
class ToolPreInvokePayload:
    name: str = ""
    arguments: Optional[Dict[str, Any]] = None


@dataclass
class ToolPreInvokeResult:
    continue_processing: bool = True
    violation: Optional[PluginViolation] = None
    modified_payload: Optional[ToolPreInvokePayload] = None
    metadata: Optional[Dict[str, Any]] = None
    http_headers: Optional[Dict[str, str]] = None


@dataclass
class PluginResult:
    """Generic result wrapper returned by PluginExecutor."""

    continue_processing: bool = True
    violation: Optional[PluginViolation] = None
    modified_payload: Any = None
    metadata: Optional[Dict[str, Any]] = None


class Plugin:
    """Base class stub for gateway plugins."""

    def __init__(self, config: PluginConfig) -> None:
        self._config = config

    @property
    def config(self) -> PluginConfig:
        return self._config

    @property
    def name(self) -> str:
        return self._config.name

    @property
    def priority(self) -> int:
        return self._config.priority

    @property
    def mode(self) -> PluginMode:
        return self._config.mode


class PluginError(Exception):
    """Generic plugin execution error."""


class PluginViolationError(Exception):
    """Raised by PluginExecutor in enforce mode when a plugin returns a violation."""

    def __init__(self, message: str, violation: Optional[PluginViolation] = None) -> None:
        super().__init__(message)
        self.violation = violation


class PluginRef:
    """Lightweight reference to a plugin, exposing the attributes the executor reads."""

    def __init__(self, plugin: Plugin) -> None:
        self._plugin = plugin

    @property
    def plugin(self) -> Plugin:
        return self._plugin

    @property
    def name(self) -> str:
        return self._plugin.name

    @property
    def mode(self) -> PluginMode:
        return self._plugin.mode

    @property
    def priority(self) -> int:
        return self._plugin.priority

    @property
    def conditions(self) -> Any:
        return None


class HookRef:
    """A (hook name, plugin) pair, resolving to the plugin's async hook method."""

    def __init__(self, hook: str, plugin_ref: PluginRef) -> None:
        self._hook = hook
        self._plugin_ref = plugin_ref
        func = getattr(plugin_ref.plugin, hook, None)
        if func is None or not asyncio.iscoroutinefunction(func):
            raise PluginError(f"Plugin '{plugin_ref.name}' has no async hook '{hook}'")
        self._func: Callable[[Any, PluginContext], Awaitable[Any]] = func

    @property
    def name(self) -> str:
        return self._hook

    @property
    def plugin_ref(self) -> PluginRef:
        return self._plugin_ref

    @property
    def hook(self) -> Callable[[Any, PluginContext], Awaitable[Any]]:
        return self._func


class PluginExecutor:
    """Minimal executor mirroring mcpgateway.plugins.framework.manager.PluginExecutor.

    Supports the subset exercised by the integration tests:
    - execute(hook_refs, payload, global_context, hook_type, violations_as_exceptions)
      skips DISABLED plugins and short-circuits when a plugin returns
      continue_processing=False under ENFORCE mode.
    - execute_plugin(hook_ref, payload, local_context, violations_as_exceptions)
      runs a single plugin, honours PERMISSIVE (never raises) vs ENFORCE
      (raises PluginViolationError when violations_as_exceptions=True).
    """

    def __init__(self, timeout: int = 30) -> None:
        self.timeout = timeout

    async def execute_plugin(
        self,
        hook_ref: HookRef,
        payload: Any,
        local_context: PluginContext,
        violations_as_exceptions: bool = False,
        global_context: Optional[GlobalContext] = None,
        combined_metadata: Optional[Dict[str, Any]] = None,
    ) -> PluginResult:
        result = await hook_ref.hook(payload, local_context)

        violation = getattr(result, "violation", None)
        if violation is not None:
            violation.plugin_name = hook_ref.plugin_ref.name

        if not getattr(result, "continue_processing", True):
            mode = hook_ref.plugin_ref.mode
            if mode == PluginMode.ENFORCE and violations_as_exceptions:
                raise PluginViolationError(
                    f"{hook_ref.name} blocked by plugin {hook_ref.plugin_ref.name}",
                    violation=violation,
                )

        return PluginResult(
            continue_processing=getattr(result, "continue_processing", True),
            violation=violation,
            modified_payload=getattr(result, "modified_payload", None),
            metadata=getattr(result, "metadata", None),
        )

    async def execute(
        self,
        hook_refs: List[HookRef],
        payload: Any,
        global_context: GlobalContext,
        hook_type: str,
        local_contexts: Optional[Dict[str, PluginContext]] = None,
        violations_as_exceptions: bool = False,
    ) -> Tuple[PluginResult, Optional[Dict[str, PluginContext]]]:
        res_contexts: Dict[str, PluginContext] = {}
        combined_metadata: Dict[str, Any] = {}

        for hook_ref in hook_refs:
            if hook_ref.plugin_ref.mode == PluginMode.DISABLED:
                continue

            local_context = PluginContext(global_context=global_context)
            key = f"{global_context.request_id}:{hook_ref.plugin_ref.name}"
            res_contexts[key] = local_context

            result = await self.execute_plugin(
                hook_ref,
                payload,
                local_context,
                violations_as_exceptions=violations_as_exceptions,
                global_context=global_context,
                combined_metadata=combined_metadata,
            )

            if result.metadata:
                combined_metadata.update(result.metadata)

            if not result.continue_processing and hook_ref.plugin_ref.mode in (
                PluginMode.ENFORCE,
                PluginMode.ENFORCE_IGNORE_ERROR,
            ):
                return (
                    PluginResult(
                        continue_processing=False,
                        violation=result.violation,
                        modified_payload=result.modified_payload,
                        metadata=combined_metadata,
                    ),
                    res_contexts,
                )

        return (
            PluginResult(continue_processing=True, metadata=combined_metadata),
            res_contexts,
        )
