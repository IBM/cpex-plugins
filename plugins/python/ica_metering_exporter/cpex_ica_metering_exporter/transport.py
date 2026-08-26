# SPDX-License-Identifier: Apache-2.0
"""ICA metering transport and authentication."""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass
from typing import Any

import httpx
import jwt

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class ExportRequest:
    """Inputs for one ICA metering export."""

    client: httpx.AsyncClient | None
    config: dict[str, Any]
    jwt_secret: str | None
    payload: dict[str, Any]


def get_service_jwt(secret: str) -> str:
    """Create an HS256 service token for ICA metering."""
    now = int(time.time())
    claims = {
        "sub": "contextforge-metering",
        "service": "mcp-context-forge",
        "instance": os.getenv("HOSTNAME", "unknown"),
        "scope": "metering:write",
        "iat": now,
        "exp": now + 86_400,
    }
    return jwt.encode(claims, secret, algorithm="HS256")


async def send_to_ica(request: ExportRequest) -> str:
    """Await one best-effort ICA export and return its operational status."""
    if request.client is None:
        return "failed"
    metering_url = request.config.get("metering_url")
    if not isinstance(metering_url, str) or not metering_url:
        logger.warning("ICA metering URL not configured")
        return "skipped_no_url"
    metering_token = request.config.get("metering_token")
    if request.jwt_secret:
        headers = {"Authorization": f"Bearer {get_service_jwt(request.jwt_secret)}"}
    elif isinstance(metering_token, str) and metering_token:
        headers = {"X-MCP-Metering-Token": metering_token}
    else:
        logger.warning("ICA metering: neither jwt_secret nor metering_token configured")
        return "skipped_no_auth"
    try:
        response = await request.client.post(metering_url, json=request.payload, headers=headers)
        if response.status_code != httpx.codes.ACCEPTED:
            logger.warning("ICA metering endpoint returned %s", response.status_code)
            return "failed"
    except httpx.TimeoutException:
        logger.warning("ICA metering: Timeout sending metrics")
    except httpx.NetworkError:
        logger.warning("ICA metering: Network error")
    except httpx.HTTPStatusError as error:
        logger.exception("ICA metering: HTTP %s", error.response.status_code)
    except Exception:
        logger.exception("ICA metering: Failed to send metrics")
    else:
        logger.debug("ICA metering: Successfully sent metrics")
        return "sent"
    return "failed"
