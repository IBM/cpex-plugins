# -*- coding: utf-8 -*-
"""Location: ./plugins/encoded_exfil_detection/encoded_exfil_detector.py
Copyright 2026
SPDX-License-Identifier: Apache-2.0

Encoded Exfiltration Detector Plugin.

Detects suspicious encoded payloads (base64, base64url, hex, percent-encoding,
hex escapes) in prompt args and tool outputs, then blocks or redacts.

Hooks: prompt_pre_fetch, tool_post_invoke, resource_post_fetch
"""

# Future
from __future__ import annotations

# Standard
import logging
from typing import Any, Dict, Iterable

# Third-Party
from pydantic import BaseModel, Field, field_validator

# First-Party
from cpex.framework import (
    Plugin,
    PluginConfig,
    PluginContext,
    PluginViolation,
    PromptPrehookPayload,
    PromptPrehookResult,
    ResourcePostFetchPayload,
    ResourcePostFetchResult,
    ToolPostInvokePayload,
    ToolPostInvokeResult,
)
from cpex_encoded_exfil_detection.encoded_exfil_detection_rust import (
    ExfilDetectorEngine,
    py_scan_container as _py_scan_container,
)

logger = logging.getLogger(__name__)

_ENCODING_NAMES = ("base64", "base64url", "hex", "percent_encoding", "escaped_hex")


class EncodedExfilDetectorConfig(BaseModel):
    """Configuration for encoded exfiltration detection.

    Attributes:
        enabled: Per-detector enable flags.
        min_encoded_length: Minimum encoded segment length to inspect.
        min_decoded_length: Minimum decoded byte length to treat as meaningful.
        min_entropy: Minimum Shannon entropy for suspicious payload scoring.
        min_printable_ratio: Minimum decoded printable ASCII ratio for scoring.
        min_suspicion_score: Score threshold to flag a candidate as suspicious.
        max_scan_string_length: Skip scanning strings above this size for latency safety.
        max_findings_per_value: Per-string finding limit.
        redact: Whether to redact detected segments.
        redaction_text: Replacement text when redaction is enabled.
        block_on_detection: Whether to block request on findings.
        min_findings_to_block: Number of findings required before blocking.
        include_detection_details: Include detailed findings in metadata.
        allowlist_patterns: Regex patterns to skip known-good encoded strings.
        extra_sensitive_keywords: Additional sensitive keywords merged with built-in defaults.
        extra_egress_hints: Additional egress hints merged with built-in defaults.
        max_decode_depth: Maximum nested encoding layers to peel during detection.
        max_recursion_depth: Maximum container nesting depth for recursive scanning.
        log_detections: Whether to log detection events.
    """

    enabled: Dict[str, bool] = Field(default_factory=lambda: {name: True for name in _ENCODING_NAMES})

    min_encoded_length: int = Field(default=24, ge=8, le=8192)
    min_decoded_length: int = Field(default=12, ge=4, le=32768)
    min_entropy: float = Field(default=3.3, ge=0.0, le=8.0)
    min_printable_ratio: float = Field(default=0.70, ge=0.0, le=1.0)
    min_suspicion_score: int = Field(default=3, ge=1, le=10)
    max_scan_string_length: int = Field(default=200_000, ge=1_000, le=5_000_000)
    max_findings_per_value: int = Field(default=50, ge=1, le=500)

    redact: bool = Field(default=False)
    redaction_text: str = Field(default="***ENCODED_REDACTED***")
    block_on_detection: bool = Field(default=True)
    min_findings_to_block: int = Field(default=1, ge=1, le=1000)
    include_detection_details: bool = Field(default=True)

    allowlist_patterns: list[str] = Field(default_factory=list)
    extra_sensitive_keywords: list[str] = Field(default_factory=list)
    extra_egress_hints: list[str] = Field(default_factory=list)
    max_decode_depth: int = Field(default=2, ge=1, le=5)
    max_recursion_depth: int = Field(default=32, ge=1, le=1000)
    log_detections: bool = Field(default=True)
    per_encoding_score: Dict[str, int] = Field(default_factory=dict)
    parse_json_strings: bool = Field(default=True)

    @field_validator("allowlist_patterns")
    @classmethod
    def _validate_allowlist_patterns(cls, v: list[str]) -> list[str]:
        """Validate allowlist patterns are non-empty strings; Rust validates regex syntax at engine init."""
        for idx, pattern in enumerate(v):
            if not isinstance(pattern, str) or not pattern:
                raise ValueError(f"allowlist_patterns[{idx}] must be a non-empty string")
        return v


def _prefix_finding_paths(findings: Iterable[dict[str, Any]], root_path: str) -> list[dict[str, Any]]:
    """Prefix Rust finding paths with the caller's root container path."""
    if not root_path:
        return [dict(finding) for finding in findings]

    prefixed: list[dict[str, Any]] = []
    for finding in findings:
        updated = dict(finding)
        finding_path = str(updated.get("path") or "$")
        if finding_path == "$":
            updated["path"] = root_path
        elif finding_path.startswith("["):
            updated["path"] = f"{root_path}{finding_path}"
        else:
            updated["path"] = f"{root_path}.{finding_path}"
        prefixed.append(updated)
    return prefixed


def _scan_container(
    container: Any,
    cfg: EncodedExfilDetectorConfig,
    path: str = "",
) -> tuple[int, Any, list[dict[str, Any]]]:
    """Scan a container for encoded exfiltration patterns via the Rust engine."""
    count, redacted, findings = _py_scan_container(container, cfg)
    normalized = _prefix_finding_paths(
        [f for f in findings if isinstance(f, dict)],
        path,
    )
    return int(count), redacted, normalized


def _scan_text(
    text: str,
    cfg: EncodedExfilDetectorConfig,
    path: str = "",
) -> tuple[str, list[dict[str, Any]]]:
    """Scan a single text value via the Rust engine."""
    _count, redacted, findings = _scan_container(text, cfg, path=path)
    return redacted, findings


class EncodedExfilDetectorPlugin(Plugin):
    """Detect and mitigate suspicious encoded exfiltration payloads."""

    def __init__(self, config: PluginConfig) -> None:
        """Initialize encoded exfiltration detector plugin.

        Args:
            config: Plugin configuration.
        """
        super().__init__(config)
        self._cfg = EncodedExfilDetectorConfig(**(config.config or {}))
        try:
            self._rust_engine = ExfilDetectorEngine(self._cfg)
        except ValueError as exc:
            raise ValueError(
                f"Failed to initialize Rust engine — check allowlist_patterns for Rust regex compatibility "
                f"(lookaround and backreferences are not supported): {exc}"
            ) from exc
        self.implementation = "Rust"

    def _findings_for_metadata(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Return sanitized findings details for metadata emission."""
        if self._cfg.include_detection_details:
            return findings[:10]
        return [{"encoding": f.get("encoding"), "path": f.get("path"), "score": f.get("score")} for f in findings[:10]]

    def _scan(self, container: Any, path: str = "") -> tuple[int, Any, list[dict[str, Any]]]:
        """Run the Rust scanner with plugin-level configuration."""
        count, redacted, findings = self._rust_engine.scan(container)
        normalized = _prefix_finding_paths(
            [f for f in findings if isinstance(f, dict)],
            path,
        )
        return int(count), redacted, normalized

    def _log_detection(self, hook: str, count: int, findings: list[dict[str, Any]], context: PluginContext) -> None:
        """Log detection events without exposing sensitive content."""
        if not self._cfg.log_detections or count == 0:
            return
        encoding_types = sorted({f.get("encoding", "unknown") for f in findings})
        request_id = context.global_context.request_id if context and context.global_context else "unknown"
        logger.warning("Encoded exfiltration detected [hook=%s, count=%d, encodings=%s, request_id=%s]", hook, count, encoding_types, request_id)

    async def prompt_pre_fetch(self, payload: PromptPrehookPayload, context: PluginContext) -> PromptPrehookResult:
        """Scan prompt arguments for encoded exfiltration attempts."""
        count, new_args, findings = self._scan(payload.args or {}, path="args")
        self._log_detection("prompt_pre_fetch", count, findings, context)

        if count >= self._cfg.min_findings_to_block and self._cfg.block_on_detection:
            return PromptPrehookResult(
                continue_processing=False,
                violation=PluginViolation(
                    reason="Encoded exfiltration pattern detected",
                    description="Suspicious encoded payload detected in prompt arguments",
                    code="ENCODED_EXFIL_DETECTED",
                    details={
                        "count": count,
                        "examples": self._findings_for_metadata(findings),
                        "implementation": self.implementation,
                        "request_id": context.global_context.request_id if context and context.global_context else None,
                    },
                ),
            )

        metadata = {"encoded_exfil_count": count, "encoded_exfil_findings": self._findings_for_metadata(findings), "implementation": self.implementation} if count else {}

        if self._cfg.redact and new_args != (payload.args or {}):
            modified_payload = PromptPrehookPayload(prompt_id=payload.prompt_id, args=new_args)
            metadata = {**metadata, "encoded_exfil_redacted": True}
            return PromptPrehookResult(modified_payload=modified_payload, metadata=metadata)

        return PromptPrehookResult(metadata=metadata)

    async def tool_post_invoke(self, payload: ToolPostInvokePayload, context: PluginContext) -> ToolPostInvokeResult:
        """Scan tool outputs for suspicious encoded exfiltration payloads."""
        count, new_result, findings = self._scan(payload.result, path="result")
        self._log_detection("tool_post_invoke", count, findings, context)

        if count >= self._cfg.min_findings_to_block and self._cfg.block_on_detection:
            return ToolPostInvokeResult(
                continue_processing=False,
                violation=PluginViolation(
                    reason="Encoded exfiltration pattern detected",
                    description=f"Suspicious encoded payload detected in tool output '{payload.name}'",
                    code="ENCODED_EXFIL_DETECTED",
                    details={
                        "tool": payload.name,
                        "count": count,
                        "examples": self._findings_for_metadata(findings),
                        "implementation": self.implementation,
                        "request_id": context.global_context.request_id if context and context.global_context else None,
                    },
                ),
            )

        metadata = {"encoded_exfil_count": count, "encoded_exfil_findings": self._findings_for_metadata(findings), "implementation": self.implementation} if count else {}

        if self._cfg.redact and new_result != payload.result:
            modified_payload = ToolPostInvokePayload(name=payload.name, result=new_result)
            metadata = {**metadata, "encoded_exfil_redacted": True}
            return ToolPostInvokeResult(modified_payload=modified_payload, metadata=metadata)

        return ToolPostInvokeResult(metadata=metadata)

    async def resource_post_fetch(self, payload: ResourcePostFetchPayload, context: PluginContext) -> ResourcePostFetchResult:
        """Scan fetched resource content for suspicious encoded exfiltration payloads."""
        count, new_content, findings = self._scan(payload.content, path="content")
        self._log_detection("resource_post_fetch", count, findings, context)

        if count >= self._cfg.min_findings_to_block and self._cfg.block_on_detection:
            return ResourcePostFetchResult(
                continue_processing=False,
                violation=PluginViolation(
                    reason="Encoded exfiltration pattern detected",
                    description="Suspicious encoded payload detected in resource content",
                    code="ENCODED_EXFIL_DETECTED",
                    details={
                        "uri": payload.uri,
                        "count": count,
                        "examples": self._findings_for_metadata(findings),
                        "implementation": self.implementation,
                        "request_id": context.global_context.request_id if context and context.global_context else None,
                    },
                ),
            )

        metadata = {"encoded_exfil_count": count, "encoded_exfil_findings": self._findings_for_metadata(findings), "implementation": self.implementation} if count else {}

        if self._cfg.redact and new_content != payload.content:
            modified_payload = ResourcePostFetchPayload(uri=payload.uri, content=new_content)
            metadata = {**metadata, "encoded_exfil_redacted": True}
            return ResourcePostFetchResult(modified_payload=modified_payload, metadata=metadata)

        return ResourcePostFetchResult(metadata=metadata)


__all__ = [
    "EncodedExfilDetectorConfig",
    "EncodedExfilDetectorPlugin",
    "_scan_container",
    "_scan_text",
]
