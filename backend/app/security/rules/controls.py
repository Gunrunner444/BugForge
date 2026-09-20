"""Conservative authentication, authorization, and control-missing indicators."""

from __future__ import annotations

import re
from collections.abc import Sequence

from app.analyzers.framework_detector import FrameworkInfo
from app.domain.security import VulnerabilityClass
from app.parsing.model import SyntaxGraph
from app.security.rules.base import RuleDocumentation, SecurityObservation, SecurityRule

JWT_DOC = RuleDocumentation(
    detects="JWT or token decoding with signature verification disabled.",
    evidence="Matching source line.",
    limitations="Does not prove the token is attacker-controlled.",
    false_positives="Local test helpers that decode unsigned fixtures.",
)
AUTH_CMP_DOC = RuleDocumentation(
    detects="Direct equality comparison against a password or secret.",
    evidence="Matching comparison line.",
    limitations="Does not prove the comparison is on a login path.",
    false_positives="Comparisons against empty-string guards or dummy values.",
)
CSRF_DOC = RuleDocumentation(
    detects="CSRF protection explicitly disabled on a handler.",
    evidence="Decorator or assignment line.",
    limitations="Framework defaults are not modeled.",
    false_positives="Internal APIs that use another anti-CSRF control.",
)
AUTHZ_DOC = RuleDocumentation(
    detects="Object lookup by request id without an adjacent ownership check.",
    evidence="Lookup call site.",
    limitations="Intra-procedural only; authorization may live in middleware.",
    false_positives="Admin tools and already-scoped querysets.",
)

_JWT = re.compile(
    r"jwt\.decode\s*\([^)]*(?:verify\s*=\s*False|verify_signature['\"]\s*:\s*False)",
    re.IGNORECASE,
)
_PASSWORD_EQ = re.compile(
    r"(?:password|passwd|secret_key|api_secret)\s*==\s*[^=]",
    re.IGNORECASE,
)
_CSRF = re.compile(r"csrf_exempt|csrf\s*=\s*False|csrf_protection\s*=\s*False", re.IGNORECASE)
_IDOR = re.compile(
    r"(get_object_or_404|find_by_id|findById|objects\.get)\s*\([^)]*(?:id|pk)\s*=",
    re.IGNORECASE,
)
_OWNER = re.compile(r"request\.user|current_user|owner|user_id", re.IGNORECASE)


class JwtUnverifiedRule(SecurityRule):
    rule_id = "sec.auth.jwt_unverified"
    vulnerability_class = VulnerabilityClass.AUTHENTICATION
    documentation = JWT_DOC

    def check(
        self,
        graph: SyntaxGraph,
        *,
        frameworks: Sequence[FrameworkInfo] = (),
    ) -> list[SecurityObservation]:
        del frameworks
        return _line_hits(self, graph, _JWT, "JWT decoded without signature verification")


class PasswordCompareRule(SecurityRule):
    rule_id = "sec.auth.password_compare"
    vulnerability_class = VulnerabilityClass.AUTHENTICATION
    documentation = AUTH_CMP_DOC

    def check(
        self,
        graph: SyntaxGraph,
        *,
        frameworks: Sequence[FrameworkInfo] = (),
    ) -> list[SecurityObservation]:
        del frameworks
        return _line_hits(
            self, graph, _PASSWORD_EQ, "Password compared with == instead of a digest"
        )


class CsrfDisabledRule(SecurityRule):
    rule_id = "sec.authz.csrf_disabled"
    vulnerability_class = VulnerabilityClass.MISSING_SECURITY_CONTROL
    documentation = CSRF_DOC

    def check(
        self,
        graph: SyntaxGraph,
        *,
        frameworks: Sequence[FrameworkInfo] = (),
    ) -> list[SecurityObservation]:
        del frameworks
        return _line_hits(self, graph, _CSRF, "CSRF protection disabled")


class UnscopedLookupRule(SecurityRule):
    rule_id = "sec.authz.unscoped_lookup"
    vulnerability_class = VulnerabilityClass.IDOR
    documentation = AUTHZ_DOC

    def check(
        self,
        graph: SyntaxGraph,
        *,
        frameworks: Sequence[FrameworkInfo] = (),
    ) -> list[SecurityObservation]:
        del frameworks
        observations: list[SecurityObservation] = []
        for i, line in enumerate(graph.lines, start=1):
            if _IDOR.search(line) is None:
                continue
            window = "\n".join(graph.lines[max(0, i - 3) : min(len(graph.lines), i + 3)])
            if _OWNER.search(window):
                continue
            observations.append(
                SecurityObservation(
                    rule_id=self.rule_id,
                    vulnerability_class=self.vulnerability_class,
                    title="Potential insecure direct object reference",
                    summary="Object fetched by id without an adjacent ownership check",
                    file_path=graph.file_path,
                    line=i,
                    evidence_text=line.strip()[:400],
                    confidence="low",
                    language=graph.language,
                    documentation=self.documentation,
                )
            )
        return observations


def _line_hits(
    rule: SecurityRule,
    graph: SyntaxGraph,
    pattern: re.Pattern[str],
    summary: str,
) -> list[SecurityObservation]:
    observations: list[SecurityObservation] = []
    for i, line in enumerate(graph.lines, start=1):
        if pattern.search(line) is None:
            continue
        observations.append(
            SecurityObservation(
                rule_id=rule.rule_id,
                vulnerability_class=rule.vulnerability_class,
                title=f"Potential {rule.vulnerability_class.value.replace('_', ' ')}",
                summary=summary,
                file_path=graph.file_path,
                line=i,
                evidence_text=line.strip()[:400],
                confidence="medium",
                language=graph.language,
                documentation=rule.documentation,
            )
        )
    return observations
