# -*- coding: utf-8 -*-
"""SQL sanitizer plugin package."""

from __future__ import annotations


def __getattr__(name: str):
    if name == "SqlSanitizerPluginCore":
        from cpex_sql_sanitizer.sql_sanitizer_rust import SqlSanitizerPluginCore

        return SqlSanitizerPluginCore
    if name == "SQLSanitizerPlugin":
        from cpex_sql_sanitizer.sql_sanitizer import SQLSanitizerPlugin

        return SQLSanitizerPlugin
    raise AttributeError(f"module 'cpex_sql_sanitizer' has no attribute {name!r}")

__all__ = ["SqlSanitizerPluginCore", "SQLSanitizerPlugin"]
