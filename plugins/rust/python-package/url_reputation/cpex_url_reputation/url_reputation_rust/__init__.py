# -*- coding: utf-8 -*-
"""Python compatibility layer for the in-progress URL reputation Rust port."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

try:
    from mcpgateway.plugins.framework import PluginViolation, ResourcePreFetchResult
except ModuleNotFoundError:
    class PluginViolation:  # type: ignore[no-redef]
        def __init__(
            self,
            reason: str = "",
            description: str = "",
            code: str = "",
            details: dict[str, Any] | None = None,
            http_status_code: int = 400,
            http_headers: dict[str, str] | None = None,
        ) -> None:
            self.reason = reason
            self.description = description
            self.code = code
            self.details = details
            self.http_status_code = http_status_code
            self.http_headers = http_headers

    class ResourcePreFetchResult:  # type: ignore[no-redef]
        def __init__(
            self,
            continue_processing: bool = True,
            violation: PluginViolation | None = None,
            metadata: dict[str, Any] | None = None,
            http_headers: dict[str, str] | None = None,
        ) -> None:
            self.continue_processing = continue_processing
            self.violation = violation
            self.metadata = metadata
            self.http_headers = http_headers

_SAFE_TLDS = {"com", "org", "net", "edu", "gov", "io", "dev", "co"}


def _normalize_domains(values: Any) -> set[str]:
    if not values:
        return set()
    return {str(value).lower() for value in values}


def _matches_domain(host: str, domains: set[str]) -> bool:
    return any(host == domain or host.endswith(f".{domain}") for domain in domains)


def _compile_patterns(values: Any) -> list[re.Pattern[str]]:
    compiled: list[re.Pattern[str]] = []
    for value in values or []:
        try:
            compiled.append(re.compile(str(value)))
        except re.error as exc:
            raise ValueError(f"Pattern compilation failed for {value!r}") from exc
    return compiled


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {char: value.count(char) for char in set(value)}
    total = len(value)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def _is_unicode_secure(host: str) -> bool:
    if host.isascii():
        return True
    scripts = set()
    for char in host:
        if char in ".-":
            continue
        if "LATIN" in (name := __import__("unicodedata").name(char, "")):
            scripts.add("latin")
        elif "CYRILLIC" in name:
            scripts.add("cyrillic")
        elif "GREEK" in name:
            scripts.add("greek")
        else:
            scripts.add("other")
    return len(scripts) <= 1


def _has_legal_tld(host: str) -> bool:
    tld = host.rsplit(".", 1)[-1].lower()
    return bool(tld) and (tld in _SAFE_TLDS or (tld.isalpha() and len(tld) >= 2))


@dataclass
class _Config:
    whitelist_domains: set[str]
    allowed_patterns: list[re.Pattern[str]]
    blocked_domains: set[str]
    blocked_patterns: list[re.Pattern[str]]
    use_heuristic_check: bool
    entropy_threshold: float
    block_non_secure_http: bool


class URLReputationResult:
    def __init__(self, continue_processing: bool, violation: PluginViolation | None = None) -> None:
        self.continue_processing = continue_processing
        self.violation = violation


class URLReputationEngine:
    """Pure-Python fallback matching the intended Rust API surface."""

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        raw = config or {}
        self._config = _Config(
            whitelist_domains=_normalize_domains(raw.get("whitelist_domains")),
            allowed_patterns=_compile_patterns(raw.get("allowed_patterns")),
            blocked_domains=_normalize_domains(raw.get("blocked_domains")),
            blocked_patterns=_compile_patterns(raw.get("blocked_patterns")),
            use_heuristic_check=bool(raw.get("use_heuristic_check", False)),
            entropy_threshold=float(raw.get("entropy_threshold", 3.65)),
            block_non_secure_http=bool(raw.get("block_non_secure_http", True)),
        )

    def validate_url(self, url: str) -> URLReputationResult:
        parsed = urlparse(url.strip())
        if not parsed.scheme or not parsed.hostname:
            return URLReputationResult(
                False,
                PluginViolation(
                    reason="Could not parse url",
                    description=f"URL {url} is blocked",
                    code="URL_REPUTATION_BLOCK",
                    details={"url": url},
                ),
            )

        host = parsed.hostname.lower()
        if _matches_domain(host, self._config.whitelist_domains):
            return URLReputationResult(True)

        if any(pattern.search(url) for pattern in self._config.allowed_patterns):
            return URLReputationResult(True)

        if self._config.block_non_secure_http and parsed.scheme != "https":
            return URLReputationResult(
                False,
                PluginViolation(
                    reason="Blocked non secure http url",
                    description=f"URL {url} is blocked",
                    code="URL_REPUTATION_BLOCK",
                    details={"url": url},
                ),
            )

        if _matches_domain(host, self._config.blocked_domains):
            return URLReputationResult(
                False,
                PluginViolation(
                    reason="Blocked domain",
                    description=f"Domain {host} is blocked",
                    code="URL_REPUTATION_BLOCK",
                    details={"domain": host},
                ),
            )

        if any(pattern.search(url) for pattern in self._config.blocked_patterns):
            return URLReputationResult(
                False,
                PluginViolation(
                    reason="Blocked pattern",
                    description="URL matches blocked pattern",
                    code="URL_REPUTATION_BLOCK",
                    details={"url": url},
                ),
            )

        if self._config.use_heuristic_check and not _is_ip_literal(host):
            if len(host) >= 8 and _entropy(host) > self._config.entropy_threshold:
                return URLReputationResult(
                    False,
                    PluginViolation(
                        reason="High entropy domain",
                        description=f"Domain exceeds entropy threshold: {host}",
                        code="URL_REPUTATION_BLOCK",
                        details={"domain": host},
                    ),
                )
            if not _has_legal_tld(host):
                return URLReputationResult(
                    False,
                    PluginViolation(
                        reason="Illegal TLD",
                        description=f"Domain TLD not legal: {host}",
                        code="URL_REPUTATION_BLOCK",
                        details={"domain": host},
                    ),
                )
            if not _is_unicode_secure(host):
                return URLReputationResult(
                    False,
                    PluginViolation(
                        reason="Domain unicode is not secure",
                        description=f"Domain unicode is not secure for domain: {host}",
                        code="URL_REPUTATION_BLOCK",
                        details={"domain": host},
                    ),
                )

        return URLReputationResult(True)


def _is_ip_literal(host: str) -> bool:
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
        return True
    if ":" in host:
        return True
    return False


class URLReputationPluginCore:
    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self.engine = URLReputationEngine(config)

    def resource_pre_fetch(self, payload, _context):
        result = self.engine.validate_url(payload.uri)
        if result.continue_processing:
            return ResourcePreFetchResult(continue_processing=True)
        return ResourcePreFetchResult(
            continue_processing=False,
            violation=result.violation,
        )


__all__ = [
    "PluginViolation",
    "URLReputationEngine",
    "URLReputationPluginCore",
    "URLReputationResult",
]
