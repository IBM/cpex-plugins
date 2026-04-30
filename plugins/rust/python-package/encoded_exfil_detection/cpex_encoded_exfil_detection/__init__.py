# -*- coding: utf-8 -*-
"""Encoded exfiltration detection plugin package."""

from __future__ import annotations


def __getattr__(name: str):
    if name in {"EncodedExfilDetectorConfig", "EncodedExfilDetectorPlugin"}:
        from cpex_encoded_exfil_detection.encoded_exfil_detection import (
            EncodedExfilDetectorConfig,
            EncodedExfilDetectorPlugin,
        )

        exports = {
            "EncodedExfilDetectorConfig": EncodedExfilDetectorConfig,
            "EncodedExfilDetectorPlugin": EncodedExfilDetectorPlugin,
        }
        return exports[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

__all__ = ["EncodedExfilDetectorConfig", "EncodedExfilDetectorPlugin"]
