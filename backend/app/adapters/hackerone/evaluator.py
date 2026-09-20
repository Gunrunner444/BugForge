"""Deterministic HackerOne scope evaluator. AI never decides scope."""

from __future__ import annotations

from dataclasses import dataclass

from app.adapters.hackerone.models import (
    HackerOneProgram,
    ScopeExclusionRecord,
    ScopeMode,
    StructuredScopeRecord,
)
from app.security_testing.target import (
    NETWORK_ASSET_TYPES,
    AssetType,
    NormalizedTarget,
    TargetNormalizer,
    hostname_matches,
    path_matches,
)


@dataclass(frozen=True)
class HackerOneScopeDecision:
    allowed: bool
    reason: str
    structured_scope_id: str | None = None
    asset_type: str | None = None
    asset_identifier: str | None = None
    eligible_for_submission: bool = False
    eligible_for_bounty: bool = False
    in_scope: bool = False
    matched_instructions: str = ""
    exclusions_considered: tuple[str, ...] = ()


class HackerOneScopeEvaluator:
    def __init__(self, normalizer: TargetNormalizer | None = None) -> None:
        self.normalizer = normalizer or TargetNormalizer()

    def evaluate(self, program: HackerOneProgram, target: str) -> HackerOneScopeDecision:
        exclusions = tuple(self._exclusion_hits(program.exclusions, target))
        if exclusions:
            return HackerOneScopeDecision(
                allowed=False,
                reason="Target matches a HackerOne scope exclusion",
                exclusions_considered=exclusions,
            )
        match = self._match_structured(program.structured_scopes, target)
        if match is None:
            if program.scope_mode is ScopeMode.OPEN:
                return HackerOneScopeDecision(
                    allowed=False,
                    reason=(
                        "Open-scope program: unknown assets are not automatically authorized. "
                        "An operator must approve an explicit active-testing policy before "
                        "BugForge may test assets that are not listed in structured scope."
                    ),
                    exclusions_considered=exclusions,
                )
            return HackerOneScopeDecision(
                allowed=False,
                reason="Closed-scope program: unknown asset is denied",
                exclusions_considered=exclusions,
            )
        in_scope = True
        # Eligible-for-bounty is independent of in-scope.
        allowed = in_scope and match.eligible_for_submission
        reason = "In structured scope"
        if not match.eligible_for_submission:
            reason = "Asset is in structured scope but not eligible for submission"
            allowed = False
        return HackerOneScopeDecision(
            allowed=allowed,
            reason=reason,
            structured_scope_id=match.id,
            asset_type=match.asset_type.value,
            asset_identifier=match.asset_identifier,
            eligible_for_submission=match.eligible_for_submission,
            eligible_for_bounty=match.eligible_for_bounty,
            in_scope=in_scope,
            matched_instructions=match.instruction,
            exclusions_considered=exclusions,
        )

    def _match_structured(
        self, scopes: tuple[StructuredScopeRecord, ...], target: str
    ) -> StructuredScopeRecord | None:
        network_target = self._try_network_target(target)
        for record in scopes:
            if record.asset_type not in NETWORK_ASSET_TYPES:
                if target.strip() == record.asset_identifier.strip():
                    return record
                continue
            if network_target is None:
                continue
            if self._network_match(record, network_target):
                return record
        return None

    def _network_match(self, record: StructuredScopeRecord, target: NormalizedTarget) -> bool:
        ident = record.asset_identifier.strip()
        if record.asset_type is AssetType.CIDR:
            return hostname_matches(target.hostname or target.ip or "", (ident,))
        if record.asset_type is AssetType.IP:
            return hostname_matches(target.hostname or target.ip or "", (ident,))
        if (
            record.asset_type is AssetType.URL
            or ident.startswith("http://")
            or ident.startswith("https://")
        ):
            try:
                wanted = self.normalizer.normalize(ident)
            except ValueError:
                return False
            if target.hostname != wanted.hostname:
                return False
            if wanted.scheme and target.scheme and wanted.scheme != target.scheme:
                return False
            if wanted.port and target.port and wanted.port != target.port:
                return False
            if wanted.path not in {"", "/"} and not path_matches(target.path, wanted.path):
                return False
            return True
        return hostname_matches(target.hostname, (ident,))

    def _try_network_target(self, target: str) -> NormalizedTarget | None:
        try:
            return self.normalizer.normalize(target)
        except ValueError:
            return None

    def _exclusion_hits(
        self, exclusions: tuple[ScopeExclusionRecord, ...], target: str
    ) -> list[str]:
        hits: list[str] = []
        lowered = target.strip().lower()
        hostname = ""
        path = ""
        parsed = self._try_network_target(target)
        if parsed is not None:
            hostname = parsed.hostname
            path = parsed.path
        for item in exclusions:
            details = (item.details or "").strip()
            if not details:
                continue
            token = details.lower()
            if hostname and hostname_matches(hostname, (details,)):
                hits.append(item.id or details)
                continue
            if details.startswith("/") and path and path_matches(path, details):
                hits.append(item.id or details)
                continue
            try:
                wanted = self.normalizer.normalize(details)
            except ValueError:
                if token in lowered:
                    # Avoid naive substring on hostnames; only exact identifier equality.
                    if details.strip().lower() == lowered:
                        hits.append(item.id or details)
                continue
            if parsed is None:
                continue
            if wanted.hostname and hostname_matches(hostname, (wanted.hostname,)):
                if wanted.path in {"", "/"} or path_matches(path, wanted.path):
                    hits.append(item.id or details)
        return hits
