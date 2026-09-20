"""Isolated research identities. Credentials are never shared automatically."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from uuid import uuid4

from app.security_testing.errors import RestrictedActivityError


@dataclass
class ResearchIdentity:
    label: str
    cookies: dict[str, str] = field(default_factory=dict)
    storage: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    id: str = field(default_factory=lambda: uuid4().hex)

    def snapshot(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "label": self.label,
            "cookies": dict(self.cookies),
            "storage": dict(self.storage),
            "header_names": sorted(self.headers),
        }


@dataclass
class IdentityPair:
    context_a: ResearchIdentity = field(default_factory=lambda: ResearchIdentity(label="A"))
    context_b: ResearchIdentity = field(default_factory=lambda: ResearchIdentity(label="B"))

    def isolated(self) -> bool:
        return (
            self.context_a.cookies != self.context_b.cookies
            or self.context_a.headers != self.context_b.headers
            or self.context_a.storage != self.context_b.storage
        )


async def compare_identities(
    engine: Any,
    pair: IdentityPair,
    *,
    method: str,
    url: str,
    expectation: str,
) -> Any:
    """Send the same request as A and B. Never share credentials. Never mutate."""
    from app.security_agent.authorization_diff import compare_authorization

    if method.upper() in {"DELETE", "PUT", "PATCH"} and not engine.session.scope.lab_mode:
        raise RestrictedActivityError("destructive_identity_compare")
    exchange_a = await engine.http("identity_a").request(
        method,
        url,
        headers={**pair.context_a.headers, **_cookie_header(pair.context_a.cookies)},
        active=True,
        destructive=False,
    )
    exchange_b = await engine.http("identity_b").request(
        method,
        url,
        headers={**pair.context_b.headers, **_cookie_header(pair.context_b.cookies)},
        active=True,
        destructive=False,
    )
    return compare_authorization(
        _as_exchange(exchange_a),
        _as_exchange(exchange_b),
        expectation=expectation,
    )


def _cookie_header(cookies: dict[str, str]) -> dict[str, str]:
    if not cookies:
        return {}
    return {"Cookie": "; ".join(f"{key}={value}" for key, value in cookies.items())}


def _as_exchange(result: Any) -> dict[str, Any]:
    if hasattr(result, "response_status"):
        return {
            "url": result.url,
            "status": result.response_status,
            "response": {"status": result.response_status, "body": result.response_body},
        }
    return {"status": getattr(result, "state", None), "response": {"body": str(result)}}
