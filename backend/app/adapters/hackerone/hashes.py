"""Canonical hashes for versioned report approval."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any


def canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def sha256_hex(value: object) -> str:
    if isinstance(value, str):
        payload = value.encode("utf-8")
    else:
        payload = canonical_json(value).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def report_content_hash(
    *,
    title: str,
    vulnerability_information: str,
    impact: str,
    severity: str | None,
    weakness_id: int | None,
    structured_scope_id: int | None,
    target: str | None,
    program_handle: str,
) -> str:
    return sha256_hex(
        {
            "title": title,
            "vulnerability_information": vulnerability_information,
            "impact": impact,
            "severity": severity,
            "weakness_id": weakness_id,
            "structured_scope_id": structured_scope_id,
            "target": target,
            "program_handle": program_handle,
        }
    )


def evidence_hash(references: tuple[str, ...], extra: Mapping[str, Any] | None = None) -> str:
    payload: dict[str, Any] = {"references": list(references)}
    if extra:
        payload["extra"] = dict(extra)
    return sha256_hex(payload)


def scope_snapshot_hash(snapshot: Mapping[str, Any]) -> str:
    return sha256_hex(dict(snapshot))


def payload_hash(payload: Mapping[str, Any]) -> str:
    return sha256_hex(dict(payload))
