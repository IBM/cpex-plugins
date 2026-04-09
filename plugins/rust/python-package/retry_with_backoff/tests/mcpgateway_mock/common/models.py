"""Minimal mock models used by retry_with_backoff tests."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ResourceContent:
    type: str
    id: str
    uri: str
    text: str
