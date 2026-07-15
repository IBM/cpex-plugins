# -*- coding: utf-8 -*-
# Copyright 2026
# SPDX-License-Identifier: Apache-2.0
"""Thin compatibility shim for the Rust-owned SQL sanitizer plugin."""

from __future__ import annotations

from cpex.framework import Plugin
from cpex_sql_sanitizer.sql_sanitizer_rust import SqlSanitizerPluginCore


class SQLSanitizerPlugin(Plugin):
    """Gateway-facing Plugin subclass that delegates all behaviour to Rust.

    Configuration keys (all optional, defaults match the original Python plugin):

    - ``fields``                    – list[str] | null — field names to scan (null = all strings)
    - ``blocked_statements``        – list[str]  — replaces the default blocked-statement
      patterns (DROP / TRUNCATE / ALTER / GRANT / REVOKE); an empty list disables
      this category entirely
    - ``block_delete_without_where``– bool (default true)
    - ``block_update_without_where``– bool (default true)
    - ``strip_comments``            – bool (default true)
    - ``require_parameterization``  – bool (default false)
    - ``block_on_violation``        – bool (default true)
    """

    def __init__(self, config) -> None:
        super().__init__(config)
        self._core = SqlSanitizerPluginCore(config.config or {})

    async def prompt_pre_fetch(self, payload, context, extensions=None):
        return self._core.prompt_pre_fetch(payload, context, extensions)

    async def tool_pre_invoke(self, payload, context, extensions=None):
        return self._core.tool_pre_invoke(payload, context, extensions)


__all__ = ["SQLSanitizerPlugin", "SqlSanitizerPluginCore"]
