"""Redact secrets from logs, evidence, prompts, and exports."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence

from app.domain.http import HttpExchange, HttpHeader

_REDACTED = "[REDACTED]"
_SECRET_HEADERS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-access-token",
    "x-csrf-token",
    "x-session-token",
    "api-key",
    "apikey",
}
_PATTERNS = (
    re.compile(r"(?i)bearer\s+[a-z0-9._\-+=/]+"),
    re.compile(r"(?i)basic\s+[a-z0-9=+/]+"),
    re.compile(r"(?i)(api[_-]?key|secret|token|password|passwd|authorization)\s*[:=]\s*\S+"),
    re.compile(r"(?i)(access_token|refresh_token|id_token)=([^&\s]+)"),
)


def redact_text(value: str | None) -> str:
    if not value:
        return ""
    redacted = value
    for pattern in _PATTERNS:
        redacted = pattern.sub(_REDACTED, redacted)
    return redacted


def redact_headers(headers: Sequence[HttpHeader]) -> tuple[HttpHeader, ...]:
    cleaned: list[HttpHeader] = []
    for header in headers:
        if header.name.lower() in _SECRET_HEADERS:
            cleaned.append(HttpHeader(name=header.name, value=_REDACTED))
        else:
            cleaned.append(HttpHeader(name=header.name, value=redact_text(header.value)))
    return tuple(cleaned)


def redact_mapping(values: Mapping[str, str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for key, value in values.items():
        if key.lower() in _SECRET_HEADERS or "token" in key.lower() or "secret" in key.lower():
            out[key] = _REDACTED
        else:
            out[key] = redact_text(value)
    return out


def redact_exchange(exchange: HttpExchange) -> HttpExchange:
    return HttpExchange(
        method=exchange.method,
        url=exchange.url,
        request_id=exchange.request_id,
        timestamp=exchange.timestamp,
        scheme=exchange.scheme,
        host=exchange.host,
        port=exchange.port,
        path=exchange.path,
        request_headers=redact_headers(exchange.request_headers),
        request_body=redact_text(exchange.request_body) or None,
        request_body_meta=exchange.request_body_meta,
        query=exchange.query,
        cookies=tuple(_REDACTED for _ in exchange.cookies) if exchange.cookies else (),
        response_status=exchange.response_status,
        response_headers=redact_headers(exchange.response_headers),
        response_body=redact_text(exchange.response_body) or None,
        response_body_meta=exchange.response_body_meta,
        elapsed_ms=exchange.elapsed_ms,
        source_tool=exchange.source_tool,
        scope_decision=exchange.scope_decision,
        metadata=exchange.metadata,
    )


def environment_credential(name: str, *, required: bool = False) -> str:
    """Read a secret from the environment. Never log the value."""
    import os

    value = os.environ.get(name, "")
    if required and not value:
        raise RuntimeError(f"Missing required credential environment variable {name}")
    return value
