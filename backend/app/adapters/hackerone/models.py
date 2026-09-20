"""HackerOne-normalized records. These are adapter types, not core domain imports."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any

from app.security_testing.target import AssetType


class ProgramSyncStatus(StrEnum):
    NEVER = "never"
    OK = "ok"
    ERROR = "error"


class ScopeMode(StrEnum):
    CLOSED = "closed"
    OPEN = "open"


HACKERONE_ASSET_MAP: dict[str, AssetType] = {
    "domain": AssetType.DOMAIN,
    "url": AssetType.URL,
    "wildcard": AssetType.WILDCARD,
    "ip_address": AssetType.IP,
    "ip": AssetType.IP,
    "cidr": AssetType.CIDR,
    "source_code": AssetType.SOURCE_CODE,
    "executable": AssetType.EXECUTABLE,
    "android_app": AssetType.ANDROID_APP,
    "ios_app": AssetType.IOS_APP,
    "hardware": AssetType.HARDWARE,
    "other": AssetType.OTHER_ASSET,
    "ai_model": AssetType.AI_MODEL,
    "other_asset": AssetType.OTHER_ASSET,
}


def asset_type_from_hackerone(raw: str) -> AssetType:
    key = (raw or "").strip().lower().replace(" ", "_").replace("-", "_")
    aliases = {
        "hardware_iot": AssetType.HARDWARE,
        "hardware/iot": AssetType.HARDWARE,
        "wildcard": AssetType.WILDCARD,
        "ai_model": AssetType.AI_MODEL,
        "ai-model": AssetType.AI_MODEL,
    }
    if key in aliases:
        return aliases[key]
    return HACKERONE_ASSET_MAP.get(key, AssetType.OTHER)


@dataclass(frozen=True)
class StructuredScopeRecord:
    id: str
    asset_type_raw: str
    asset_type: AssetType
    asset_identifier: str
    instruction: str = ""
    eligible_for_bounty: bool = False
    eligible_for_submission: bool = True
    reference: str | None = None
    original: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ScopeExclusionRecord:
    id: str
    category: str
    details: str
    created_at: str | None = None
    updated_at: str | None = None
    original: dict[str, Any] = field(default_factory=dict)


@dataclass
class HackerOneProgram:
    handle: str
    name: str = ""
    program_id: str | None = None
    program_url: str | None = None
    fetched_at: datetime | None = None
    sync_status: ProgramSyncStatus = ProgramSyncStatus.NEVER
    error: str | None = None
    scope_mode: ScopeMode = ScopeMode.CLOSED
    offers_bounties: bool | None = None
    requires_severity: bool = True
    instructions: str = ""
    structured_scopes: tuple[StructuredScopeRecord, ...] = ()
    exclusions: tuple[ScopeExclusionRecord, ...] = ()
    open_scope_policy: str = ""
    open_scope_acknowledged: bool = False
    active_testing_approved: bool = False

    def snapshot(self) -> dict[str, Any]:
        return {
            "handle": self.handle,
            "id": self.program_id,
            "name": self.name,
            "program_url": self.program_url,
            "fetched_at": self.fetched_at.isoformat() if self.fetched_at else None,
            "sync_status": self.sync_status.value,
            "error": self.error,
            "scope_mode": self.scope_mode.value,
            "offers_bounties": self.offers_bounties,
            "requires_severity": self.requires_severity,
            "scope_count": len(self.structured_scopes),
            "exclusion_count": len(self.exclusions),
            "active_testing_approved": self.active_testing_approved,
            "open_scope_acknowledged": self.open_scope_acknowledged,
        }


def attributes(node: object) -> dict[str, Any]:
    if isinstance(node, dict):
        attrs = node.get("attributes")
        if isinstance(attrs, dict):
            return attrs
    return {}


def node_id(node: object) -> str:
    if isinstance(node, dict):
        return str(node.get("id") or "")
    return ""
