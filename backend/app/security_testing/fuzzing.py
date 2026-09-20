"""Controlled fuzzing. Never unrestricted. Always ScopeGuard + SafetyController."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, replace
from enum import StrEnum
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from app.domain.evidence import Evidence, EvidenceKind
from app.domain.http import HttpExchange
from app.security_testing.approvals import ApprovalKind
from app.security_testing.engine import SecurityTestEngine
from app.security_testing.errors import ApprovalRequiredError, AuthorizationDeniedError
from app.security_testing.failures import ToolExecutionResult, ToolExecutionState


class MutationKind(StrEnum):
    QUERY = "query"
    PATH = "path"
    JSON = "json"
    FORM = "form"
    HEADER = "header"
    API = "api"


@dataclass(frozen=True)
class SeedRequest:
    method: str
    url: str
    headers: tuple[tuple[str, str], ...] = ()
    body: str | None = None


@dataclass(frozen=True)
class FuzzLimits:
    request_limit: int = 10
    requests_per_second: float = 1.0
    concurrency: int = 1
    timeout_seconds: float = 5.0
    payload_count: int = 8
    max_body_size: int = 2048


_DEFAULT_PAYLOADS = (
    "'",
    '"',
    "<x>",
    "../",
    "%00",
    "1 OR 1=1",
    "{}",
    "A" * 64,
)


class ResponseDifferenceAnalyzer:
    def diff(self, baseline: HttpExchange, candidate: HttpExchange) -> str | None:
        if baseline.response_status != candidate.response_status:
            return f"status {baseline.response_status} -> {candidate.response_status}"
        base_len = len(baseline.response_body or "")
        cand_len = len(candidate.response_body or "")
        if abs(base_len - cand_len) > max(32, int(base_len * 0.3)):
            return f"body length {base_len} -> {cand_len}"
        return None


class FuzzingEngine:
    def __init__(self, engine: SecurityTestEngine, *, limits: FuzzLimits | None = None) -> None:
        self.engine = engine
        self.limits = limits or FuzzLimits()
        self.analyzer = ResponseDifferenceAnalyzer()

    async def fuzz(
        self,
        seed: SeedRequest,
        *,
        kinds: Sequence[MutationKind] = (MutationKind.QUERY,),
        operator: str | None = None,
    ) -> list[Evidence] | ToolExecutionResult:
        if not self.engine.session.fuzzing_enabled and not self.engine.approvals.is_granted(
            ApprovalKind.ENABLE_FUZZING
        ):
            if operator:
                self.engine.grant(ApprovalKind.ENABLE_FUZZING, operator=operator)
            else:
                raise ApprovalRequiredError(ApprovalKind.ENABLE_FUZZING.value)
        decision = self.engine.authorize(seed.url, method=seed.method, tool="fuzzer", active=True)
        if not decision.allowed:
            raise AuthorizationDeniedError(decision.reason, target=seed.url, tool="fuzzer")

        client = self.engine.http("fuzzer")
        baseline = await client.request(
            seed.method, seed.url, headers=dict(seed.headers), content=seed.body
        )
        if isinstance(baseline, ToolExecutionResult):
            return baseline
        evidence: list[Evidence] = [
            Evidence(
                kind=EvidenceKind.FUZZING,
                source="fuzzer",
                summary=f"Baseline {baseline.response_status} for {seed.method} {seed.url}",
            )
        ]
        sent = 0
        payloads = _DEFAULT_PAYLOADS[: self.limits.payload_count]
        for kind in kinds:
            for payload in payloads:
                if sent >= self.limits.request_limit:
                    evidence.append(
                        Evidence(
                            kind=EvidenceKind.FUZZING,
                            source="fuzzer",
                            summary=f"Stopped at request_limit={self.limits.request_limit}",
                        )
                    )
                    return evidence
                if len(payload.encode()) > self.limits.max_body_size:
                    continue
                mutated = _mutate(seed, kind, payload)
                result = await client.request(
                    mutated.method,
                    mutated.url,
                    headers=dict(mutated.headers),
                    content=mutated.body,
                )
                sent += 1
                if isinstance(result, ToolExecutionResult):
                    if result.state is ToolExecutionState.DRY_RUN:
                        evidence.append(
                            Evidence(
                                kind=EvidenceKind.FUZZING,
                                source="fuzzer",
                                summary=result.detail or "dry-run",
                            )
                        )
                        return evidence
                    continue
                delta = self.analyzer.diff(baseline, result)
                if delta:
                    evidence.append(
                        Evidence(
                            kind=EvidenceKind.FUZZING,
                            source="fuzzer",
                            summary=f"{kind.value} payload {payload!r}: {delta}",
                            details=f"status={result.response_status}",
                        )
                    )
        self.engine.add_evidence(evidence)
        return evidence


def _mutate(seed: SeedRequest, kind: MutationKind, payload: str) -> SeedRequest:
    if kind is MutationKind.QUERY:
        parsed = urlparse(seed.url)
        query = dict(parse_qsl(parsed.query, keep_blank_values=True))
        if not query:
            query = {"q": payload}
        else:
            first = next(iter(query))
            query[first] = payload
        url = urlunparse(parsed._replace(query=urlencode(query)))
        return replace(seed, url=url)
    if kind is MutationKind.PATH:
        parsed = urlparse(seed.url)
        path = parsed.path.rstrip("/") + "/" + payload
        return replace(seed, url=urlunparse(parsed._replace(path=path)))
    if kind is MutationKind.JSON:
        body = seed.body or "{}"
        injected = body[:-1] + f', "fuzz": {payload!r}}}' if body.endswith("}") else payload
        return replace(seed, body=injected[:2048])
    if kind is MutationKind.FORM:
        return replace(seed, body=f"fuzz={payload}")
    if kind is MutationKind.HEADER:
        return replace(seed, headers=seed.headers + (("X-BugForge-Fuzz", payload),))
    return replace(seed, body=payload)
