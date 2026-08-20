# -*- coding: utf-8 -*-
# Copyright 2025
# SPDX-License-Identifier: Apache-2.0
"""Thin compatibility shim for the Rust-owned output length guard plugin."""

from __future__ import annotations

from cpex.framework import Plugin
from cpex_output_length_guard.output_length_guard_rust import OutputLengthGuardPluginCore


class OutputLengthGuardPlugin(Plugin):
    """Gateway-facing Plugin subclass that delegates behavior to Rust."""

    def __init__(self, config) -> None:
        super().__init__(config)
        self._core = OutputLengthGuardPluginCore(config.config or {})

    async def tool_post_invoke(self, payload, context, extensions=None):
        return self._core.tool_post_invoke(payload, context, extensions)


__all__ = ["OutputLengthGuardPlugin"]
