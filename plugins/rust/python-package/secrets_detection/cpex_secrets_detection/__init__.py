# -*- coding: utf-8 -*-
"""Secrets detection plugin package."""

from __future__ import annotations


def __getattr__(name: str):
    if name == "SecretsDetectionPlugin":
        from cpex_secrets_detection.secrets_detection import SecretsDetectionPlugin

        return SecretsDetectionPlugin
    if name == "py_scan_container":
        from cpex_secrets_detection.secrets_detection_rust import py_scan_container

        return py_scan_container
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = ["SecretsDetectionPlugin", "py_scan_container"]
