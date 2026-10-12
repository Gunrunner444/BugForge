"""Truncation-aware source selection (Phase 51, owner Phase 4).

When a repository holds more Solidity than can be analysed under the file budget,
the files that are kept must be the ones that matter: in-scope and deployed assets
first, then proxy/implementation code, then files imported by those, then
security-sensitive code, then the rest. Truncation is always reported explicitly
with ``truncated=true``; a file that was dropped is *not* implied to be clean, safe,
or out of scope. It was simply not read under the budget.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path
from typing import Any

from app.discovery.bounty.campaign import BountyManifest

MAX_CANDIDATE_FILES = 2000
DEFAULT_LIMIT = 64
MAX_FILE_BYTES = 400_000
MAX_DEPENDENCY_DEPTH = 4
MAX_DEPENDENCY_FILES = 32
# Bounded follow-up for high-priority files that did not fit the primary budget.
MAX_FOLLOWUP_BATCHES = 2
FOLLOWUP_PRIORITY = 4  # Priority.SECURITY_SENSITIVE and better
_SKIP_DIRS = frozenset(
    {".git", "node_modules", "lib", "out", "cache", "artifacts", "broadcast", "test", "tests"}
)
_IMPORT = re.compile(r"""import\s+(?:[^\"';]*\s+from\s+)?["']([^"']+)["']""")
_CONTRACT_DECL = re.compile(r"\b(?:contract|library|interface)\s+([A-Za-z_]\w*)")
_BASES = re.compile(r"\b(?:abstract\s+)?contract\s+[A-Za-z_]\w*(?:\s+is\s+([^{;]+))?\s*\{")
_SENSITIVE = (
    re.compile(r"\.delegatecall\s*\("),
    re.compile(r"\bselfdestruct\s*\(|\bsuicide\s*\("),
    re.compile(r"\bassembly\b"),
    re.compile(r"\.call\s*\{\s*value"),
    re.compile(r"\becrecover\s*\("),
    re.compile(r"\btransferFrom\s*\(|\bsafeTransferFrom\s*\("),
    re.compile(r"\b_mint\b|\b_burn\b"),
    re.compile(r"\bonlyOwner\b|\bAccessControl\b|\bhasRole\b"),
    re.compile(r"\b_authorizeUpgrade\b|\bupgradeTo\b"),
)


class Priority(IntEnum):
    SCOPE = 0
    DEPLOYED = 1
    PROXY = 2
    IMPORTED_BY_SCOPE = 3
    SECURITY_SENSITIVE = 4
    OTHER = 5


@dataclass(frozen=True)
class RankedFile:
    path: str
    priority: Priority
    reason: str


@dataclass(frozen=True)
class SourceSelection:
    selected: tuple[str, ...]
    ranked: tuple[RankedFile, ...]
    considered: int
    limit: int
    truncated: bool
    dropped: tuple[str, ...]
    # contract name -> every file that declares it, when more than one does. Such a
    # name is never silently bound to the first file in alphabetical order.
    ambiguous_contracts: tuple[tuple[str, tuple[str, ...]], ...] = ()
    mode: str = "ranked"  # ranked | explicit
    # Imports and bases that could not be tied to one file inside the repository.
    unresolved_imports: tuple[tuple[str, str], ...] = ()
    ambiguous_imports: tuple[tuple[str, tuple[str, ...]], ...] = ()
    escaped_imports: tuple[tuple[str, str], ...] = ()
    dependency_notes: tuple[str, ...] = ()

    @staticmethod
    def explicit(files: tuple[str, ...]) -> SourceSelection:
        """The operator named the files; nothing was ranked or dropped."""
        ranked = tuple(RankedFile(path, Priority.SCOPE, "named by the operator") for path in files)
        return SourceSelection(
            selected=tuple(files),
            ranked=ranked,
            considered=len(files),
            limit=len(files),
            truncated=False,
            dropped=(),
            mode="explicit",
        )

    @property
    def dropped_high_priority(self) -> tuple[str, ...]:
        """Dropped files that matter: scope, deployed, proxy, imported, sensitive."""
        priority = {item.path: item.priority for item in self.ranked}
        return tuple(
            path
            for path in self.dropped
            if priority.get(path, Priority.OTHER).value <= FOLLOWUP_PRIORITY
        )

    def followup_batches(
        self, max_batches: int = MAX_FOLLOWUP_BATCHES
    ) -> tuple[tuple[str, ...], ...]:
        """Bounded follow-up batches over the dropped high-priority files, best first."""
        pending = list(self.dropped_high_priority)
        size = max(1, self.limit)
        batches: list[tuple[str, ...]] = []
        while pending and len(batches) < max(0, max_batches):
            batches.append(tuple(pending[:size]))
            pending = pending[size:]
        return tuple(batches)

    def request_extra(self) -> dict[str, str]:
        """Selection facts that travel with the analysis request and its evidence."""
        extra = {
            "source_selection_mode": self.mode,
            "source_selection_truncated": str(self.truncated).lower(),
            "source_selection_considered": str(self.considered),
            "source_selection_selected": str(len(self.selected)),
        }
        if self.truncated:
            extra["source_selection_dropped"] = str(len(self.dropped))
            extra["source_selection_dropped_high_priority"] = str(len(self.dropped_high_priority))
        if self.ambiguous_contracts:
            extra["source_selection_ambiguous"] = ",".join(
                name for name, _ in self.ambiguous_contracts
            )[:300]
        if self.unresolved_imports or self.ambiguous_imports or self.escaped_imports:
            extra["source_dependency_status"] = "partial"
        elif self.dependency_notes:
            extra["source_dependency_status"] = "bounded"
        else:
            extra["source_dependency_status"] = "traced"
        return extra

    def as_dict(self) -> dict[str, Any]:
        batches = self.followup_batches()
        followed = {path for batch in batches for path in batch}
        return {
            "mode": self.mode,
            "selected": list(self.selected),
            "considered": self.considered,
            "limit": self.limit,
            "truncated": self.truncated,
            "dropped_count": len(self.dropped),
            "dropped": list(self.dropped[:200]),
            "dropped_high_priority": list(self.dropped_high_priority[:200]),
            "followup_batches": [list(batch) for batch in batches],
            "never_read": [p for p in self.dropped_high_priority if p not in followed][:200],
            "ambiguous_contracts": {name: list(files) for name, files in self.ambiguous_contracts},
            "unresolved_imports": [
                {"file": src, "import": target} for src, target in self.unresolved_imports
            ],
            "ambiguous_imports": [
                {"import": target, "files": list(files)} for target, files in self.ambiguous_imports
            ],
            "escaped_imports": [
                {"file": src, "import": target} for src, target in self.escaped_imports
            ],
            "dependency_notes": list(self.dependency_notes),
            "dependency_status": (
                "partial"
                if self.unresolved_imports or self.ambiguous_imports or self.escaped_imports
                else "bounded"
                if self.dependency_notes or self.truncated
                else "traced"
            ),
            "note": (
                "truncated=true means files were not read under the budget; a dropped file "
                "is not implied to be clean, safe, or out of scope"
            )
            if self.truncated
            else "all candidate files fit within the budget",
            "ranking": [
                {"path": item.path, "priority": item.priority.name.lower(), "reason": item.reason}
                for item in self.ranked
            ],
        }


def _gather(repo_root: Path) -> list[Path]:
    files: list[Path] = []
    for path in sorted(repo_root.rglob("*.sol")):
        rel = path.relative_to(repo_root)
        if set(rel.parts) & _SKIP_DIRS:
            continue
        if path.is_file():
            files.append(path)
        if len(files) >= MAX_CANDIDATE_FILES:
            break
    return files


def _read(path: Path) -> str:
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return ""
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError, ValueError):
        return ""


def select_sources(
    repo_root: Path,
    *,
    manifest: BountyManifest | None = None,
    focus_contract: str = "",
    focus_file: str = "",
    limit: int = DEFAULT_LIMIT,
) -> SourceSelection:
    """Rank and select source files, keeping the most relevant within ``limit``."""

    root = repo_root.resolve()
    if not root.is_dir():
        return SourceSelection((), (), 0, limit, False, ())
    paths = _gather(root)
    rel_paths = [p.relative_to(root).as_posix() for p in paths]
    texts = {rel: _read(path) for rel, path in zip(rel_paths, paths, strict=True)}

    scope_contracts, scope_paths = _scope_targets(manifest, focus_contract, focus_file)
    deployed_contracts = (
        {d.contract_name for d in manifest.deployments if d.contract_name} if manifest else set()
    )
    contract_to_files = _contract_index(texts)
    scope_files = _files_for(scope_contracts, scope_paths, contract_to_files, focus_file)
    dependencies, unresolved, ambiguous_imports, escaped, dependency_notes = _trace_dependencies(
        scope_files, texts, root, contract_to_files
    )
    ambiguous = tuple(
        (name, tuple(files))
        for name, files in sorted(contract_to_files.items())
        if len(files) > 1 and (name in scope_contracts or name in deployed_contracts)
    )
    ambiguous_files = {path: name for name, files in ambiguous for path in files}

    ranked: list[RankedFile] = []
    for rel in rel_paths:
        text = texts[rel]
        priority, reason = _rank_one(rel, text, scope_files, deployed_contracts, dependencies)
        if rel in ambiguous_files and priority.value <= Priority.DEPLOYED.value:
            reason = f"{reason}; contract name {ambiguous_files[rel]} is declared in several files"
        ranked.append(RankedFile(rel, priority, reason))

    ranked.sort(key=lambda item: (item.priority.value, item.path))
    selected = tuple(item.path for item in ranked[:limit])
    dropped = tuple(item.path for item in ranked[limit:])
    return SourceSelection(
        selected=selected,
        ranked=tuple(ranked),
        considered=len(ranked),
        limit=limit,
        truncated=len(ranked) > limit,
        dropped=dropped,
        ambiguous_contracts=ambiguous,
        unresolved_imports=tuple(unresolved),
        ambiguous_imports=tuple(ambiguous_imports),
        escaped_imports=tuple(escaped),
        dependency_notes=tuple(dependency_notes),
    )


def _scope_targets(
    manifest: BountyManifest | None, focus_contract: str, focus_file: str
) -> tuple[set[str], set[str]]:
    contracts: set[str] = set()
    paths: set[str] = set()
    if focus_contract:
        contracts.add(focus_contract)
    if focus_file:
        paths.add(focus_file)
    if manifest is not None:
        for asset in manifest.in_scope:
            if asset.kind == "contract":
                contracts.add(asset.identifier)
            elif asset.kind == "path":
                paths.add(asset.identifier)
        contracts.update(name for name in manifest.contract_names if name)
    return contracts, paths


def _contract_index(texts: dict[str, str]) -> dict[str, list[str]]:
    """Every file that declares each contract name (not only the first one)."""
    index: dict[str, list[str]] = {}
    for rel, text in texts.items():
        for name in _CONTRACT_DECL.findall(text):
            files = index.setdefault(name, [])
            if rel not in files:
                files.append(rel)
    return index


def _files_for(
    contracts: set[str],
    paths: set[str],
    contract_to_files: dict[str, list[str]],
    focus_file: str = "",
) -> set[str]:
    """Files for the scoped contracts. A name declared in several files keeps all of
    them unless the operator's focus file disambiguates it."""
    files: set[str] = set()
    for name in contracts:
        declaring = contract_to_files.get(name, [])
        if focus_file and focus_file in declaring:
            files.add(focus_file)
        else:
            files.update(declaring)
    files.update(paths)
    return files


def _base_names(text: str) -> list[str]:
    names: list[str] = []
    for match in _BASES.finditer(text):
        clause = match.group(1) or ""
        for part in clause.split(","):
            found = re.match(r"\s*([A-Za-z_][\w.]*)", part)
            if found:
                names.append(found.group(1).split(".")[-1])
    return names


def _resolve_import(
    target: str, rel: str, texts: dict[str, str], root: Path
) -> tuple[str, str | tuple[str, ...]]:
    """Resolve one import to a single repository path, or report why it cannot.

    A non-relative import matches the full suffix first. A bare basename is used
    only when exactly one file has that name. Several matches stay ambiguous.
    """
    if target.startswith("."):
        resolved = ((root / rel).parent / target).resolve()
        try:
            posix = resolved.relative_to(root).as_posix()
        except ValueError:
            return "escaped", target
        if posix in texts:
            return "resolved", posix
        return "unresolved", target
    suffix = target.lstrip("/")
    matches = [path for path in texts if path == suffix or path.endswith("/" + suffix)]
    if len(matches) == 1:
        return "resolved", matches[0]
    if len(matches) > 1:
        return "ambiguous", tuple(sorted(matches))
    base = suffix.split("/")[-1]
    if base and base != suffix:
        base_matches = [path for path in texts if path == base or path.endswith("/" + base)]
        if len(base_matches) == 1:
            return "resolved", base_matches[0]
        if len(base_matches) > 1:
            return "ambiguous", tuple(sorted(base_matches))
    base_matches = [path for path in texts if path == base or path.endswith("/" + base)]
    if len(base_matches) == 1:
        return "resolved", base_matches[0]
    if len(base_matches) > 1:
        return "ambiguous", tuple(sorted(base_matches))
    return "unresolved", target


def _trace_dependencies(
    scope_files: set[str],
    texts: dict[str, str],
    root: Path,
    contract_to_files: dict[str, list[str]],
) -> tuple[
    set[str],
    list[tuple[str, str]],
    list[tuple[str, tuple[str, ...]]],
    list[tuple[str, str]],
    list[str],
]:
    """Bounded imports and unique bases of the in-scope files. Uncertainty stays visible."""
    resolved: set[str] = set()
    unresolved: list[tuple[str, str]] = []
    ambiguous: list[tuple[str, tuple[str, ...]]] = []
    escaped: list[tuple[str, str]] = []
    notes: list[str] = []
    seen_imports: set[tuple[str, str]] = set()
    queue = [(path, 0) for path in sorted(scope_files) if path in texts]
    visited: set[str] = set()
    while queue:
        rel, depth = queue.pop(0)
        if rel in visited:
            continue
        visited.add(rel)
        if depth > 0 and len(resolved) >= MAX_DEPENDENCY_FILES:
            notes.append(
                f"dependency trace stopped after {MAX_DEPENDENCY_FILES} files; "
                "further imports were not followed"
            )
            break
        if depth >= MAX_DEPENDENCY_DEPTH:
            notes.append(f"dependency depth limit {MAX_DEPENDENCY_DEPTH} reached at {rel}")
            continue
        text = texts.get(rel, "")
        for target in _IMPORT.findall(text):
            key = (rel, target)
            if key in seen_imports:
                continue
            seen_imports.add(key)
            status, payload = _resolve_import(target, rel, texts, root)
            if status == "resolved" and isinstance(payload, str):
                if payload not in scope_files:
                    resolved.add(payload)
                if payload not in visited:
                    queue.append((payload, depth + 1))
            elif status == "ambiguous" and isinstance(payload, tuple):
                ambiguous.append((target, payload))
            elif status == "escaped":
                escaped.append((rel, target))
            else:
                unresolved.append((rel, target))
        for base in _base_names(text):
            declaring = contract_to_files.get(base, [])
            if len(declaring) == 1:
                path = declaring[0]
                if path not in scope_files:
                    resolved.add(path)
                if path not in visited:
                    queue.append((path, depth + 1))
            elif len(declaring) > 1:
                ambiguous.append((base, tuple(declaring)))
            else:
                unresolved.append((rel, base))
    return resolved, unresolved, ambiguous, escaped, notes


def _rank_one(
    rel: str,
    text: str,
    scope_files: set[str],
    deployed_contracts: set[str],
    imported: set[str],
) -> tuple[Priority, str]:
    if rel in scope_files or any(rel.endswith("/" + f) for f in scope_files):
        return Priority.SCOPE, "in-scope asset"
    declared = set(_CONTRACT_DECL.findall(text))
    if declared & deployed_contracts:
        return Priority.DEPLOYED, "declares a deployed contract"
    if _is_proxy_like(text):
        return Priority.PROXY, "proxy / implementation code (delegatecall + slot/base)"
    if rel in imported:
        return Priority.IMPORTED_BY_SCOPE, "import or base required by an in-scope contract"
    if any(pattern.search(text) for pattern in _SENSITIVE):
        return Priority.SECURITY_SENSITIVE, "security-sensitive construct present"
    return Priority.OTHER, "not prioritized"


def _is_proxy_like(text: str) -> bool:
    has_delegate = "delegatecall(" in text
    erc1967 = "360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc" in text.lower()
    bases = any(
        token in text
        for token in ("UUPSUpgradeable", "TransparentUpgradeableProxy", "BeaconProxy", "diamondCut")
    )
    return bool(bases or (has_delegate and ("fallback" in text or erc1967)))
