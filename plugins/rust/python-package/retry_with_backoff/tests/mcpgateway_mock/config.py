"""Minimal mock of mcpgateway.config."""

from __future__ import annotations


class _Settings:
    max_tool_retries = 5


def get_settings() -> _Settings:
    return _Settings()
