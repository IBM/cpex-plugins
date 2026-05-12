# -*- coding: utf-8 -*-
"""Retry With Backoff plugin package."""

from __future__ import annotations


def __getattr__(name: str):
    if name == "RetryWithBackoffPlugin":
        from cpex_retry_with_backoff.retry_with_backoff import RetryWithBackoffPlugin

        return RetryWithBackoffPlugin
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = ["RetryWithBackoffPlugin"]