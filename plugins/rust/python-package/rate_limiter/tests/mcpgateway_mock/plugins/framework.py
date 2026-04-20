"""Minimal mock of mcpgateway.plugins.framework for testing.

Provides just enough surface area to let cpex_rate_limiter.rate_limiter
import and function without the real mcpgateway package installed.

Deliberately narrow: the plugin tests in this repo only drive the plugin
directly via its async hook methods.  Executor-mode dispatch (ENFORCE /
PERMISSIVE / DISABLED handling) is covered in mcp-context-forge against
the real PluginExecutor — see
tests/unit/mcpgateway/plugins/framework/test_manager_*.py there — so no
executor, HookRef, PluginRef, or PluginMode enum is modelled here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class PluginConfig:
    """Plugin configuration envelope."""

    name: str = ""
    kind: str = ""
    hooks: List[Any] = field(default_factory=list)
    priority: int = 0
    mode: str = "enforce"
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
    def mode(self) -> str:
        return self._config.mode

    async def initialize(self) -> None:
        """Lifecycle hook. Mirrors mcpgateway.plugins.framework.base.Plugin."""

    async def shutdown(self) -> None:
        """Lifecycle hook. Mirrors mcpgateway.plugins.framework.base.Plugin."""
