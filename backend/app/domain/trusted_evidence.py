"""Server-issued observations.

``Evidence(...)`` is never trusted. ``issue_server_observation`` generates
the observation id and HMAC with the server secret. A caller cannot opt in
by setting ``attribution=server`` or any other metadata flag.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from uuid import uuid4

from app.core.config import settings
from app.domain.evidence import Evidence
from app.domain.target_identity import semantic_target_identity

_DROPPED = frozenset(
    {
        "attribution",
        "execution_id",
        "finding_id",
        "finding_key",
        "observation_signature",
        "observed_target",
        "server_observation_id",
    }
)


def issue_server_observation(
    item: Evidence,
    *,
    execution_id: str,
    observed_target: str,
    finding_id: str = "",
    finding_key: str = "",
) -> ServerObservation:
    """Issue one observation. Identity fields come from the arguments, not the item."""
    if not execution_id.strip():
        raise ValueError("A server observation requires a server-generated execution id")
    if not observed_target.strip():
        raise ValueError("A server observation must be bound to a semantic target")
    metadata = {
        key: value for key, value in item.metadata.items() if key not in _DROPPED
    }
    metadata["attribution"] = "server"
    metadata["execution_id"] = execution_id
    metadata["observed_target"] = observed_target
    if finding_id:
        metadata["finding_id"] = finding_id
    if finding_key:
        metadata["finding_key"] = finding_key
    observation_id = uuid4().hex
    metadata["server_observation_id"] = observation_id
    drafted = ServerObservation(
        kind=item.kind,
        source=item.source,
        summary=item.summary,
        details=item.details,
        artifact_path=item.artifact_path,
        metadata=metadata,
        collected_at=item.collected_at,
        server_observation_id=observation_id,
        observation_signature=_sign(item.kind.value, item.source, item.summary, item.details, item.artifact_path, metadata, observation_id),
    )
    return drafted


def issue_for_finding(
    finding: object,
    item: Evidence,
    execution_id: str,
) -> ServerObservation:
    """Issue an observation bound to ``finding``'s current semantic target."""
    return issue_server_observation(
        item,
        execution_id=execution_id,
        observed_target=semantic_target_identity(finding),
        finding_id=str(getattr(finding, "id", "") or ""),
        finding_key=str(getattr(finding, "finding_key", "") or ""),
    )


def is_trusted_observation(item: Evidence) -> bool:
    """True only for a signature that matches this process's server secret."""
    if not isinstance(item, ServerObservation):
        return False
    if not item.server_observation_id:
        return False
    actual = str(item.metadata.get("observation_signature") or "")
    expected = item.observation_signature
    if not actual or not expected or len(actual) != len(expected):
        return False
    if not hmac.compare_digest(actual, expected):
        return False
    return hmac.compare_digest(actual, _sign(
        item.kind.value,
        item.source,
        item.summary,
        item.details,
        item.artifact_path,
        item.metadata,
        item.server_observation_id,
    ))


def restore_server_observation(item: Evidence) -> Evidence:
    """Rebuild a trusted observation from storage, or leave the record untrusted."""
    observation_id = str(item.metadata.get("server_observation_id") or "")
    signature = str(item.metadata.get("observation_signature") or "")
    if not observation_id or not signature:
        return _without_trust_markers(item)
    try:
        restored = ServerObservation(
            kind=item.kind,
            source=item.source,
            summary=item.summary,
            details=item.details,
            artifact_path=item.artifact_path,
            metadata=dict(item.metadata),
            collected_at=item.collected_at,
            server_observation_id=observation_id,
            observation_signature=signature,
        )
    except ValueError:
        return _without_trust_markers(item)
    if not is_trusted_observation(restored):
        return _without_trust_markers(item)
    return restored


@dataclass(frozen=True)
class ServerObservation(Evidence):
    """Observation issued by BugForge. Construction checks the server signature."""

    server_observation_id: str = ""
    observation_signature: str = ""

    def __post_init__(self) -> None:
        super().__post_init__()
        if not self.server_observation_id:
            raise ValueError("server observation id is required")
        expected = _sign(
            self.kind.value,
            self.source,
            self.summary,
            self.details,
            self.artifact_path,
            self.metadata,
            self.server_observation_id,
        )
        actual = self.observation_signature or str(self.metadata.get("observation_signature") or "")
        if len(actual) != len(expected) or not hmac.compare_digest(actual, expected):
            raise ValueError("observation signature was not issued by BugForge")
        object.__setattr__(self, "observation_signature", expected)
        metadata = dict(self.metadata)
        metadata["observation_signature"] = expected
        metadata["server_observation_id"] = self.server_observation_id
        object.__setattr__(self, "metadata", metadata)


def _sign(
    kind: str,
    source: str,
    summary: str,
    details: str,
    artifact: str | None,
    metadata: dict[str, object],
    observation_id: str,
) -> str:
    body = {
        "artifact": artifact or "",
        "details": hashlib.sha256(details.encode("utf-8")).hexdigest(),
        "execution_id": str(metadata.get("execution_id") or ""),
        "finding_id": str(metadata.get("finding_id") or ""),
        "finding_key": str(metadata.get("finding_key") or ""),
        "id": observation_id,
        "kind": kind,
        "observed_target": str(metadata.get("observed_target") or ""),
        "outcome": str(metadata.get("outcome") or ""),
        "source": source,
        "summary": " ".join(summary.split()),
    }
    payload = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hmac.new(settings.secret_key.encode("utf-8"), payload, hashlib.sha256).hexdigest()


def _without_trust_markers(item: Evidence) -> Evidence:
    """Drop a forged stamp. Keep execution metadata so dedup stays stable."""
    from dataclasses import replace

    dropped = {
        "attribution",
        "observation_signature",
        "observed_target",
        "server_observation_id",
    }
    metadata = {key: value for key, value in item.metadata.items() if key not in dropped}
    return replace(item, metadata=metadata)
