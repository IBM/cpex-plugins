# -*- coding: utf-8 -*-
"""PII filter plugin package."""

from __future__ import annotations

def __getattr__(name: str):
    if name == "PIIDetectorRust":
        from cpex_pii_filter.pii_filter_rust import PIIDetectorRust

        return PIIDetectorRust
    if name == "PIIFilterPlugin":
        from cpex_pii_filter.pii_filter import PIIFilterPlugin

        return PIIFilterPlugin
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

__all__ = ["PIIDetectorRust", "PIIFilterPlugin"]
