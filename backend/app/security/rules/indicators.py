"""Conservative secret, crypto, and configuration indicators."""

from __future__ import annotations

import re
from collections.abc import Sequence

from app.analyzers.framework_detector import FrameworkInfo
from app.domain.security import VulnerabilityClass
from app.parsing.model import SyntaxGraph
from app.parsing.profiles import profile_for
from app.security.rules.base import RuleDocumentation, SecurityObservation, SecurityRule
from app.security.taint import compile_patterns, matches_any

_SECRET_ASSIGN = re.compile(
    r"(?i)(api[_-]?key|secret|password|passwd|token|private[_-]?key)\s*[=:]\s*['\"]([^'\"]{8,})['\"]"
)
_PLACEHOLDER = re.compile(
    r"(?i)(change_me|placeholder|example|todo|xxx|your[_-]?secret|changeme|dummy)"
)
_AWS_KEY = re.compile(r"AKIA[0-9A-Z]{16}")
_PEM = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")

SECRET_DOC = RuleDocumentation(
    detects="Hard-coded credentials, cloud keys, or PEM private keys in source.",
    evidence="Assignment snippet with the secret value redacted.",
    limitations="Cannot distinguish test fixtures from production secrets.",
    false_positives="Example configs and unit-test doubles.",
)
CRYPTO_DOC = RuleDocumentation(
    detects="Use of MD5/SHA1/DES/RC4/ECB which is often inappropriate for secrets.",
    evidence="Matching source line.",
    limitations="Hashing for non-security checksums is common and not a vuln.",
    false_positives="Checksums, ETags, cache keys.",
)
DEBUG_DOC = RuleDocumentation(
    detects="Debug or insecure TLS/app settings left enabled.",
    evidence="Matching configuration line.",
    limitations="Local development settings are expected.",
    false_positives="Tests that intentionally enable debug.",
)

_DEBUG_PATTERNS = (
    r"DEBUG\s*=\s*True",
    r"ssl_verify\s*=\s*False",
    r"verify\s*=\s*False",
    r"InsecureRequestWarning",
    r"NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]0['\"]",
    r"SECRET_KEY\s*=\s*['\"][^'\"]{0,8}['\"]",
)


class HardcodedSecretRule(SecurityRule):
    rule_id = "sec.secrets.hardcoded"
    vulnerability_class = VulnerabilityClass.HARDCODED_SECRET
    documentation = SECRET_DOC

    def check(
        self,
        graph: SyntaxGraph,
        *,
        frameworks: Sequence[FrameworkInfo] = (),
    ) -> list[SecurityObservation]:
        del frameworks
        observations: list[SecurityObservation] = []
        for i, line in enumerate(graph.lines, start=1):
            if _PEM.search(line):
                observations.append(self._obs(graph, i, "PEM private key in source", line))
                continue
            aws = _AWS_KEY.search(line)
            if aws:
                observations.append(self._obs(graph, i, "AWS-style access key id", line))
                continue
            assigned = _SECRET_ASSIGN.search(line)
            if assigned and not _PLACEHOLDER.search(assigned.group(2)):
                observations.append(self._obs(graph, i, f"Hard-coded {assigned.group(1)}", line))
        return observations

    def _obs(self, graph: SyntaxGraph, line: int, summary: str, raw: str) -> SecurityObservation:
        redacted = _SECRET_ASSIGN.sub(r"\1 = '***'", raw)
        return SecurityObservation(
            rule_id=self.rule_id,
            vulnerability_class=self.vulnerability_class,
            title="Potential hard-coded secret",
            summary=summary,
            file_path=graph.file_path,
            line=line,
            evidence_text=redacted.strip()[:400],
            confidence="medium",
            language=graph.language,
            documentation=self.documentation,
        )


class WeakCryptoRule(SecurityRule):
    rule_id = "sec.crypto.weak"
    vulnerability_class = VulnerabilityClass.WEAK_CRYPTOGRAPHY
    documentation = CRYPTO_DOC

    def check(
        self,
        graph: SyntaxGraph,
        *,
        frameworks: Sequence[FrameworkInfo] = (),
    ) -> list[SecurityObservation]:
        del frameworks
        profile = profile_for(graph.language)
        if profile is None:
            return []
        patterns = compile_patterns(profile.crypto_patterns)
        observations: list[SecurityObservation] = []
        for i, line in enumerate(graph.lines, start=1):
            if matches_any(line, patterns) is None:
                continue
            if not any(
                hint in line.lower()
                for hint in ("password", "passwd", "secret", "token", "auth", "hash")
            ):
                # Require a security-relevant hint to cut checksum noise.
                if (
                    "md5" not in line.lower()
                    and "sha1" not in line.lower()
                    and "des" not in line.lower()
                ):
                    continue
                if "password" not in graph.source.lower() and "secret" not in line.lower():
                    continue
            observations.append(
                SecurityObservation(
                    rule_id=self.rule_id,
                    vulnerability_class=self.vulnerability_class,
                    title="Potential weak cryptography",
                    summary="Weak hash or cipher used in a security-sensitive context",
                    file_path=graph.file_path,
                    line=i,
                    evidence_text=line.strip()[:400],
                    confidence="low",
                    language=graph.language,
                    documentation=self.documentation,
                )
            )
        return observations


class InsecureConfigRule(SecurityRule):
    rule_id = "sec.config.insecure"
    vulnerability_class = VulnerabilityClass.INSECURE_CONFIGURATION
    documentation = DEBUG_DOC

    def check(
        self,
        graph: SyntaxGraph,
        *,
        frameworks: Sequence[FrameworkInfo] = (),
    ) -> list[SecurityObservation]:
        del frameworks
        patterns = compile_patterns(_DEBUG_PATTERNS)
        observations: list[SecurityObservation] = []
        for i, line in enumerate(graph.lines, start=1):
            if matches_any(line, patterns) is None:
                continue
            observations.append(
                SecurityObservation(
                    rule_id=self.rule_id,
                    vulnerability_class=self.vulnerability_class,
                    title="Potential insecure configuration",
                    summary="Debug or TLS verification disabled in source",
                    file_path=graph.file_path,
                    line=i,
                    evidence_text=line.strip()[:400],
                    confidence="low",
                    language=graph.language,
                    documentation=self.documentation,
                )
            )
        return observations
