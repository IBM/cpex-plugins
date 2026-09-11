# -*- coding: utf-8 -*-
"""Output length guard plugin package."""

from __future__ import annotations


def __getattr__(name: str):
    if name == "OutputLengthGuardPlugin":
        from cpex_output_length_guard.output_length_guard import OutputLengthGuardPlugin

        return OutputLengthGuardPlugin
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = ["OutputLengthGuardPlugin"]
