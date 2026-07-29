# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
# Copyright 2024 ContextForge Contributors
"""Output Length Guard plugin implementation."""

from __future__ import annotations

import logging
from typing import Any

from pydantic import BaseModel, Field

try:
    from cpex.framework import Plugin, PluginViolation
    from cpex.framework import ToolPreInvokeResult, ToolPostInvokeResult
except ModuleNotFoundError:
    # Fallback stubs for standalone testing
    class Plugin:  # type: ignore[no-redef]
        def __init__(self, config) -> None:
            self.config = config

    class PluginViolation:  # type: ignore[no-redef]
        def __init__(
            self,
            reason: str = "",
            description: str = "",
            code: str = "",
            details: dict[str, Any] | None = None,
            http_status_code: int = 400,
            http_headers: dict[str, str] | None = None,
        ) -> None:
            self.reason = reason
            self.description = description
            self.code = code
            self.details = details
            self.http_status_code = http_status_code
            self.http_headers = http_headers

    class ToolPreInvokeResult:  # type: ignore[no-redef]
        def __init__(
            self,
            continue_processing: bool = True,
            violation: PluginViolation | None = None,
            modified_payload: Any = None,
            metadata: dict[str, Any] | None = None,
        ) -> None:
            self.continue_processing = continue_processing
            self.violation = violation
            self.modified_payload = modified_payload
            self.metadata = metadata

    class ToolPostInvokeResult:  # type: ignore[no-redef]
        def __init__(
            self,
            continue_processing: bool = True,
            violation: PluginViolation | None = None,
            modified_result: Any = None,
            metadata: dict[str, Any] | None = None,
        ) -> None:
            self.continue_processing = continue_processing
            self.violation = violation
            self.modified_result = modified_result
            self.metadata = metadata


try:
    from cpex_output_length_guard.output_length_guard_rust import OutputLengthGuardEngine
    _RUST_AVAILABLE = True
except ImportError:
    OutputLengthGuardEngine = None  # type: ignore[misc,assignment]
    _RUST_AVAILABLE = False

logger = logging.getLogger(__name__)


class OutputLengthGuardConfig(BaseModel):
    """Configuration for Output Length Guard."""

    # TODO: Add configuration fields
    example_option: str = Field(default="default_value", description="Example configuration option")


class OutputLengthGuardPlugin(Plugin):
    """Gateway-facing Plugin subclass that delegates behavior to the Rust engine."""

    def __init__(self, config) -> None:
        super().__init__(config)
        if not _RUST_AVAILABLE or OutputLengthGuardEngine is None:
            raise RuntimeError(
                "Rust output_length_guard_rust module is required but not available. "
                "Please ensure the plugin is properly installed with: make install"
            )
        self._cfg = OutputLengthGuardConfig(**(config.config or {}))
        self._core = OutputLengthGuardEngine(self._cfg.model_dump())

    async def tool_post_invoke(self, result, context):
        """Hook called after tool is invoked."""
        try:
            hook_result = self._core.tool_post_invoke(result, context)
            if hasattr(hook_result, "__await__"):
                return await hook_result
            return hook_result
        except Exception as exc:
            logger.warning("Output Length Guard tool_post_invoke failed: %s", exc)
            return ToolPostInvokeResult(
                continue_processing=True,
                metadata={"error": str(exc)},
            )


__all__ = [
    "OutputLengthGuardConfig",
    "OutputLengthGuardPlugin",
]
