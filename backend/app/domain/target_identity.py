"""Semantic target identity for lifecycle verification.

Line number and formatting whitespace are not part of the identity. A
material change of file, scope, sink, argument, field, or source does not
keep an old observation as proof of the new target.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from app.domain.evidence import EvidenceKind


def semantic_target_identity(finding: Any) -> str:
    """Stable identity of the code a verification observation was bound to."""
    location = getattr(finding, "source_location", None)
    path = ""
    if location is not None and getattr(location, "file_path", None):
        path = str(location.file_path).replace("\\", "/").lstrip("./")
    scope = ""
    argument = ""
    evidence = getattr(finding, "evidence", None)
    items = getattr(evidence, "items", ()) if evidence is not None else ()
    for item in items:
        if getattr(item, "kind", None) is not EvidenceKind.STATIC_ANALYSIS:
            continue
        meta = getattr(item, "metadata", {}) or {}
        scope = scope or _norm(meta.get("scope_id"))
        argument = argument or _norm(meta.get("argument_index"))
    parts = (
        path,
        _norm(getattr(finding, "vulnerability_class", "")),
        _norm(getattr(finding, "flow_sink", "")),
        _norm(getattr(finding, "flow_source", "")),
        _norm(getattr(finding, "field_path", "")),
        scope,
        argument,
    )
    payload = json.dumps(parts, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:32]


def _norm(value: object) -> str:
    return " ".join(str(value or "").split())
