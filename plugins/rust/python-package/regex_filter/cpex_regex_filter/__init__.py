# -*- coding: utf-8 -*-
"""Regex filter plugin package."""

from __future__ import annotations


def __getattr__(name: str):
    if name == "SearchReplacePlugin":
        from cpex_regex_filter.regex_filter import SearchReplacePlugin

        return SearchReplacePlugin
    if name == "SearchReplacePluginRust":
        from cpex_regex_filter.regex_filter_rust import SearchReplacePluginRust

        return SearchReplacePluginRust
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = ["SearchReplacePlugin", "SearchReplacePluginRust"]
