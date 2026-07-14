# -*- coding: utf-8 -*-
# Copyright 2026
# SPDX-License-Identifier: Apache-2.0
"""Integration tests for the SQL sanitizer plugin (Rust + Python shim)."""

from __future__ import annotations

from pathlib import Path

import pytest

from real_cpex_imports import assert_real_cpex_imports
from cpex.framework import (
    PluginConfig,
    PluginContext,
    PromptPrehookPayload,
    ToolPreInvokePayload,
)
from cpex.framework.models import GlobalContext

from cpex_sql_sanitizer.sql_sanitizer import SQLSanitizerPlugin


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _cfg(**overrides) -> PluginConfig:
    defaults: dict = {}
    defaults.update(overrides)
    return PluginConfig(
        name="sql_sanitizer",
        kind="cpex_sql_sanitizer.sql_sanitizer.SQLSanitizerPlugin",
        config=defaults,
    )


def _ctx() -> PluginContext:
    return PluginContext(
        global_context=GlobalContext(request_id="req-sql", server_id="srv-sql")
    )


# ---------------------------------------------------------------------------
# Import / packaging smoke test
# ---------------------------------------------------------------------------


def test_imports_with_real_cpex_package() -> None:
    plugin_root = (
        Path(__file__).resolve().parents[3]
        / "plugins"
        / "rust"
        / "python-package"
        / "sql_sanitizer"
    )
    assert_real_cpex_imports(
        plugin_root,
        [
            "from cpex_sql_sanitizer.sql_sanitizer import SQLSanitizerPlugin",
        ],
    )


def test_plugin_instantiates() -> None:
    plugin = SQLSanitizerPlugin(_cfg())
    assert plugin is not None


# ---------------------------------------------------------------------------
# prompt_pre_fetch — block path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_blocks_delete_without_where_in_prompt():
    plugin = SQLSanitizerPlugin(_cfg())
    payload = PromptPrehookPayload(
        prompt_id="p1",
        args={"sql": "DELETE FROM employees"},
    )
    result = await plugin.prompt_pre_fetch(payload, _ctx())

    assert result.continue_processing is False
    assert result.violation is not None
    assert result.violation.code == "SQL_SANITIZER"
    assert result.violation.details["issues"] == ["DELETE without WHERE clause"]


@pytest.mark.asyncio
async def test_blocks_update_without_where_in_prompt():
    plugin = SQLSanitizerPlugin(_cfg())
    payload = PromptPrehookPayload(
        prompt_id="p1",
        args={"sql": "UPDATE salary SET amount = 0"},
    )
    result = await plugin.prompt_pre_fetch(payload, _ctx())

    assert result.continue_processing is False
    assert result.violation is not None
    assert result.violation.code == "SQL_SANITIZER"
    assert result.violation.details["issues"] == ["UPDATE without WHERE clause"]


@pytest.mark.asyncio
async def test_blocks_drop_in_prompt():
    plugin = SQLSanitizerPlugin(_cfg())
    payload = PromptPrehookPayload(
        prompt_id="p1",
        args={"query": "DROP TABLE users"},
    )
    result = await plugin.prompt_pre_fetch(payload, _ctx())

    assert result.continue_processing is False
    assert result.violation is not None
    assert result.violation.code == "SQL_SANITIZER"
    assert result.violation.details["issues"] == ["Blocked statement matched: \\bDROP\\b"]


# ---------------------------------------------------------------------------
# prompt_pre_fetch — allow path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_allows_safe_select_in_prompt():
    plugin = SQLSanitizerPlugin(_cfg())
    payload = PromptPrehookPayload(
        prompt_id="p1",
        args={"sql": "SELECT id, name FROM users WHERE active = true"},
    )
    result = await plugin.prompt_pre_fetch(payload, _ctx())

    assert result.continue_processing is True
    assert result.violation is None


@pytest.mark.asyncio
async def test_allows_delete_with_where_in_prompt():
    plugin = SQLSanitizerPlugin(_cfg())
    payload = PromptPrehookPayload(
        prompt_id="p1",
        args={"sql": "DELETE FROM sessions WHERE expired_at < NOW()"},
    )
    result = await plugin.prompt_pre_fetch(payload, _ctx())

    assert result.continue_processing is True
    assert result.violation is None


@pytest.mark.asyncio
async def test_allows_update_with_where_in_prompt():
    plugin = SQLSanitizerPlugin(_cfg())
    payload = PromptPrehookPayload(
        prompt_id="p1",
        args={"sql": "UPDATE users SET last_login = NOW() WHERE id = 42"},
    )
    result = await plugin.prompt_pre_fetch(payload, _ctx())

    assert result.continue_processing is True
    assert result.violation is None


# ---------------------------------------------------------------------------
# tool_pre_invoke — block path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_blocks_delete_without_where_in_tool():
    plugin = SQLSanitizerPlugin(_cfg())
    payload = ToolPreInvokePayload(
        name="run_sql",
        args={"statement": "DELETE FROM orders"},
    )
    result = await plugin.tool_pre_invoke(payload, _ctx())

    assert result.continue_processing is False
    assert result.violation is not None
    assert result.violation.code == "SQL_SANITIZER"
    assert result.violation.details["issues"] == ["DELETE without WHERE clause"]


@pytest.mark.asyncio
async def test_blocks_truncate_in_tool():
    plugin = SQLSanitizerPlugin(_cfg())
    payload = ToolPreInvokePayload(
        name="execute",
        args={"query": "TRUNCATE TABLE audit_log"},
    )
    result = await plugin.tool_pre_invoke(payload, _ctx())

    assert result.continue_processing is False
    assert result.violation is not None
    assert result.violation.code == "SQL_SANITIZER"
    assert result.violation.details["issues"] == ["Blocked statement matched: \\bTRUNCATE\\b"]


# ---------------------------------------------------------------------------
# Per-statement splitting
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_per_statement_fix_all_four_updates_blocked():
    """A WHERE in one statement must not suppress violations in other statements."""
    plugin = SQLSanitizerPlugin(_cfg())
    sql = (
        "UPDATE a SET x=1;"
        "UPDATE b SET x=2;"
        "UPDATE c SET x=3;"
        "UPDATE d SET x=4;"
        "SELECT * FROM e WHERE id=1"
    )
    payload = ToolPreInvokePayload(name="exec", args={"sql": sql})
    result = await plugin.tool_pre_invoke(payload, _ctx())

    assert result.continue_processing is False
    assert result.violation is not None
    assert result.violation.details["issues"] == [
        "UPDATE without WHERE clause",
        "UPDATE without WHERE clause",
        "UPDATE without WHERE clause",
        "UPDATE without WHERE clause",
    ]


@pytest.mark.asyncio
async def test_multi_statement_all_safe_is_allowed():
    plugin = SQLSanitizerPlugin(_cfg())
    sql = (
        "SELECT 1;"
        "SELECT id FROM users WHERE id = 1;"
        "UPDATE users SET seen = NOW() WHERE id = 1"
    )
    payload = ToolPreInvokePayload(name="exec", args={"sql": sql})
    result = await plugin.tool_pre_invoke(payload, _ctx())

    assert result.continue_processing is True
    assert result.violation is None


# ---------------------------------------------------------------------------
# Field filtering
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_fields_filter_ignores_non_sql_fields():
    """When fields=['sql'], non-sql fields like 'message' must not trigger issues."""
    plugin = SQLSanitizerPlugin(_cfg(fields=["sql"]))
    payload = ToolPreInvokePayload(
        name="commit",
        args={
            "message": "Add DELETE FROM employees entry in docs",
            "sql": "SELECT 1",
        },
    )
    result = await plugin.tool_pre_invoke(payload, _ctx())

    # 'message' field should not be scanned — DELETE FROM in a commit message must pass
    assert result.continue_processing is True
    assert result.violation is None


@pytest.mark.asyncio
async def test_fields_filter_scans_specified_field():
    """When fields=['sql'], the 'sql' field must still be checked."""
    plugin = SQLSanitizerPlugin(_cfg(fields=["sql"]))
    payload = ToolPreInvokePayload(
        name="exec",
        args={"sql": "DELETE FROM users", "message": "routine cleanup"},
    )
    result = await plugin.tool_pre_invoke(payload, _ctx())

    assert result.continue_processing is False
    assert result.violation is not None


# ---------------------------------------------------------------------------
# Monitoring mode (block_on_violation=False)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_monitoring_mode_passes_through_with_metadata():
    plugin = SQLSanitizerPlugin(_cfg(block_on_violation=False))
    payload = ToolPreInvokePayload(
        name="exec",
        args={"sql": "DELETE FROM sessions"},
    )
    result = await plugin.tool_pre_invoke(payload, _ctx())

    assert result.continue_processing is True
    assert result.violation is None
    assert result.metadata is not None
    assert result.metadata.get("sql_issues") == ["DELETE without WHERE clause"]


# ---------------------------------------------------------------------------
# Comment stripping
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_drop_inside_comment_is_not_flagged():
    """Comments are stripped before analysis; DROP inside a comment must not block."""
    plugin = SQLSanitizerPlugin(_cfg())
    payload = ToolPreInvokePayload(
        name="exec",
        args={"sql": "SELECT 1 /* DROP TABLE secret */ FROM t"},
    )
    result = await plugin.tool_pre_invoke(payload, _ctx())

    assert result.continue_processing is True
    assert result.violation is None


@pytest.mark.asyncio
async def test_comment_stripping_returns_modified_payload():
    """When strip_comments=True and comments exist, modified_payload must be returned."""
    plugin = SQLSanitizerPlugin(_cfg())
    payload = ToolPreInvokePayload(
        name="exec",
        args={"sql": "SELECT id -- filter col\nFROM users WHERE id = 1"},
    )
    result = await plugin.tool_pre_invoke(payload, _ctx())

    assert result.continue_processing is True
    assert result.modified_payload is not None
    clean_sql = result.modified_payload.args["sql"]
    assert "--" not in clean_sql
