"""Minimal mock of mcpgateway.plugins.framework for testing.

Provides just enough surface area to let cpex_rate_limiter.rate_limiter
import and function without the real mcpgateway package installed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional


class Plugin:
    """Base class stub for gateway plugins."""

    def __init__(self, config: PluginConfig) -> None:
        self.config = config


@dataclass
class PluginConfig:
    """Plugin configuration envelope."""

    name: str = ""
    config: Optional[Dict[str, Any]] = None


@dataclass
class GlobalContext:
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


@dataclass
class PromptPrehookPayload:
    prompt_id: str = ""


@dataclass
class PromptPrehookResult:
    continue_processing: bool = True
    violation: Optional[PluginViolation] = None
    metadata: Optional[Dict[str, Any]] = None
    http_headers: Optional[Dict[str, str]] = None


@dataclass
class ToolPreInvokePayload:
    name: str = ""


@dataclass
class ToolPreInvokeResult:
    continue_processing: bool = True
    violation: Optional[PluginViolation] = None
    metadata: Optional[Dict[str, Any]] = None
    http_headers: Optional[Dict[str, str]] = None
