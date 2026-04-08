# -*- coding: utf-8 -*-
"""Retry With Backoff plugin package."""

from __future__ import annotations


def __getattr__(name: str):
    if name in {"RetryConfig", "RetryWithBackoffPlugin"}:
        from cpex_retry_with_backoff.retry_with_backoff import RetryConfig, RetryWithBackoffPlugin

        exports = {
            "RetryConfig": RetryConfig,
            "RetryWithBackoffPlugin": RetryWithBackoffPlugin,
        }
        return exports[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = ["RetryConfig", "RetryWithBackoffPlugin"]
