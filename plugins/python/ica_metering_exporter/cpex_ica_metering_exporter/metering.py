# SPDX-License-Identifier: Apache-2.0
"""Metering value extraction helpers."""

from __future__ import annotations

from typing import Any


def get_header(headers: dict[str, Any], name: str) -> str | None:
    """Return a header value using case-insensitive lookup."""
    lowered_name = name.lower()
    for key, value in headers.items():
        if isinstance(key, str) and key.lower() == lowered_name and value is not None:
            return str(value)
    return None


def coerce_int(value: Any) -> int | None:
    """Coerce a value to an integer when possible."""
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def is_error(result: Any) -> bool:
    """Return whether a tool result declares an error."""
    return isinstance(result, dict) and bool(result.get("isError", False))


def extract_error_message(result: Any) -> str | None:
    """Extract a declared tool error message."""
    if not isinstance(result, dict) or not result.get("isError"):
        return None
    content = result.get("content")
    if isinstance(content, list):
        for block in content:
            if isinstance(block, dict):
                text = block.get("text")
                if isinstance(text, str):
                    return text
    value = result.get("errorMessage")
    return str(value) if value is not None else None


def extract_tokens(result: Any) -> dict[str, Any]:
    """Extract token metadata from a tool result."""
    if not isinstance(result, dict):
        return {}
    for metadata_key in ("_meta", "meta"):
        metadata = result.get(metadata_key)
        if isinstance(metadata, dict):
            tokens = metadata.get("tokens")
            if isinstance(tokens, dict):
                return tokens
    return {}
