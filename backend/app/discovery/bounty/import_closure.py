"""Bounded import closure for an explicit Solidity target.

The walk starts at the named files and follows only their imports. It does not
inventory the repository, and a file that merely shares a directory is not a
dependency. Remappings come from the project's ``remappings.txt`` using the
same prefix rules as the compiler project. A limit, a missing file, or an
excluded root is reported on the edge that stopped the walk.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from app.parsing.solidity_project import _read_remappings, _solc_remapping
from app.parsing.solidity_research import strip_comments

DEFAULT_CLOSURE_LIMIT = 512
_IMPORT = re.compile(r"""import\s+(?:[^\"';]*\s+from\s+)?["']([^"']+)["']""")
_SRC = re.compile(r"""(?m)^\s*src\s*=\s*['"]([^'"]+)['"]""")


@dataclass(frozen=True)
class ImportEdge:
    origin: str
    spec: str
    status: str  # resolved | unresolved | cycle | omitted
    resolved: str = ""
    reason: str = ""

    def as_tuple(self) -> tuple[str, str, str, str]:
        return (self.origin, self.spec, self.status, self.resolved or self.reason)


@dataclass(frozen=True)
class ImportClosure:
    targets: tuple[str, ...]
    dependencies: tuple[str, ...]
    edges: tuple[ImportEdge, ...]
    file_limit: int
    closure_complete: bool
    notes: tuple[str, ...]

    @property
    def unresolved(self) -> tuple[ImportEdge, ...]:
        return tuple(edge for edge in self.edges if edge.status == "unresolved")

    @property
    def omitted(self) -> tuple[ImportEdge, ...]:
        return tuple(edge for edge in self.edges if edge.status == "omitted")

    def as_dict(self) -> dict[str, object]:
        return {
            "targets": list(self.targets),
            "dependencies": list(self.dependencies),
            "resolved_count": sum(1 for edge in self.edges if edge.status == "resolved"),
            "unresolved_count": len(self.unresolved),
            "omitted_count": len(self.omitted),
            "cycle_count": sum(1 for edge in self.edges if edge.status == "cycle"),
            "file_limit": self.file_limit,
            "closure_complete": self.closure_complete,
            "notes": list(self.notes),
            "edges": [
                {
                    "origin": edge.origin,
                    "import": edge.spec,
                    "status": edge.status,
                    "resolved": edge.resolved,
                    "reason": edge.reason,
                }
                for edge in self.edges
            ],
        }


def resolve_import_closure(
    repo_root: Path,
    targets: tuple[str, ...],
    *,
    file_limit: int = DEFAULT_CLOSURE_LIMIT,
    excluded_roots: tuple[str, ...] = (),
) -> ImportClosure:
    """Resolve the import graph of ``targets``. Order is deterministic."""
    root = repo_root.resolve()
    limit = max(1, file_limit)
    notes: list[str] = []
    remappings, remap_notes = _remapping_pairs(root)
    notes.extend(remap_notes)
    source_roots = _source_roots(root)
    excluded = tuple(_normalize_prefix(item) for item in excluded_roots if _normalize_prefix(item))
    edges: list[ImportEdge] = []
    dependencies: list[str] = []
    seen_edges: set[tuple[str, str]] = set()
    complete = not any("truncated" in note or "not used" in note for note in notes)
    stack: list[str] = []
    visiting: set[str] = set()
    finished: set[str] = set()

    def remember(edge: ImportEdge) -> None:
        key = (edge.origin, edge.spec)
        if key in seen_edges:
            return
        seen_edges.add(key)
        edges.append(edge)

    def walk(rel: str) -> None:
        nonlocal complete
        if rel in finished or rel in visiting:
            return
        included = {item for item in (*targets, *dependencies)}
        if rel not in included and len(included) >= limit:
            return
        path = root / rel
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            notes.append(f"{rel} could not be read ({type(exc).__name__})")
            complete = False
            finished.add(rel)
            return
        visiting.add(rel)
        stack.append(rel)
        for spec in _import_specs(text):
            status, resolved, reason = _resolve_one(root, path, spec, remappings, source_roots)
            if status == "escaped":
                remember(ImportEdge(rel, spec, "unresolved", reason=reason or "outside_repository"))
                complete = False
                continue
            if status != "resolved" or not resolved:
                remember(ImportEdge(rel, spec, "unresolved", reason=reason or "not_found"))
                complete = False
                continue
            if _excluded(resolved, excluded):
                remember(
                    ImportEdge(rel, spec, "unresolved", resolved=resolved, reason="excluded_root")
                )
                complete = False
                continue
            if resolved in visiting:
                remember(ImportEdge(rel, spec, "cycle", resolved=resolved, reason="import_cycle"))
                continue
            if not (root / resolved).is_file():
                remember(ImportEdge(rel, spec, "unresolved", resolved=resolved, reason="not_found"))
                complete = False
                continue
            if resolved in finished or resolved in targets or resolved in dependencies:
                remember(ImportEdge(rel, spec, "resolved", resolved=resolved, reason="resolved"))
                continue
            included = {item for item in (*targets, *dependencies)}
            if len(included) >= limit:
                remember(ImportEdge(rel, spec, "omitted", resolved=resolved, reason="file_limit"))
                notes.append(
                    f"dependency closure stopped at {limit} files; {resolved} was not included"
                )
                complete = False
                continue
            remember(ImportEdge(rel, spec, "resolved", resolved=resolved, reason="resolved"))
            dependencies.append(resolved)
            walk(resolved)
        stack.pop()
        visiting.remove(rel)
        finished.add(rel)

    for target in targets:
        if (root / target).is_file():
            walk(target)
    return ImportClosure(
        targets=tuple(targets),
        dependencies=tuple(dependencies),
        edges=tuple(edges),
        file_limit=limit,
        closure_complete=complete
        and not any(edge.status in {"unresolved", "omitted"} for edge in edges),
        notes=tuple(notes),
    )


def _import_specs(text: str) -> tuple[str, ...]:
    return tuple(dict.fromkeys(_IMPORT.findall(strip_comments(text))))


def _remapping_pairs(root: Path) -> tuple[list[tuple[str, str, str]], list[str]]:
    raw, notes = _read_remappings(root)
    pairs: list[tuple[str, str, str]] = []
    for line in raw:
        normalized = _solc_remapping(line)
        context = ""
        body = normalized
        if ":" in normalized.split("=", 1)[0]:
            context, body = normalized.split(":", 1)
        if "=" not in body:
            continue
        prefix, target = body.split("=", 1)
        pairs.append((context.strip("/"), prefix, target))
    pairs.sort(key=lambda item: len(item[1]), reverse=True)
    return pairs, notes


def _source_roots(root: Path) -> tuple[str, ...]:
    path = root / "foundry.toml"
    if not path.is_file() or path.is_symlink():
        return ()
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ()
    found: list[str] = []
    for match in _SRC.finditer(text):
        prefix = _normalize_prefix(match.group(1))
        if prefix and prefix not in found and ".." not in prefix.split("/"):
            found.append(prefix)
    return tuple(found)


def _normalize_prefix(value: str) -> str:
    text = value.replace("\\", "/").strip().strip("/")
    if not text or text.startswith("/") or ".." in text.split("/"):
        return ""
    return text


def _excluded(rel: str, prefixes: tuple[str, ...]) -> bool:
    return any(rel == prefix or rel.startswith(prefix + "/") for prefix in prefixes)


def _resolve_one(
    root: Path,
    origin: Path,
    spec: str,
    remappings: list[tuple[str, str, str]],
    source_roots: tuple[str, ...],
) -> tuple[str, str, str]:
    """``(resolved|unresolved|escaped, relative path, reason)``."""
    if not spec or "\x00" in spec:
        return "unresolved", "", "malformed_import"
    origin_rel = ""
    try:
        origin_rel = origin.resolve().relative_to(root).as_posix()
    except ValueError:
        origin_rel = ""
    for context, prefix, target in remappings:
        if context and not (origin_rel == context or origin_rel.startswith(context + "/")):
            continue
        if spec.startswith(prefix):
            candidate = root / target / spec[len(prefix) :]
            return _inside(root, candidate, "remapping")
    if spec.startswith("."):
        return _inside(root, origin.parent / spec, "relative")
    rooted = _inside(root, root / spec, "project_root")
    if rooted[0] == "resolved":
        return rooted
    for src in source_roots:
        via_src = _inside(root, root / src / spec, "source_root")
        if via_src[0] == "resolved":
            return via_src
    return "unresolved", "", "not_found"


def _inside(root: Path, candidate: Path, reason: str) -> tuple[str, str, str]:
    try:
        if candidate.is_symlink():
            target = candidate.resolve()
            if root != target and root not in target.parents:
                return "escaped", "", "outside_repository"
        resolved = candidate.resolve()
    except OSError:
        return "unresolved", "", "not_found"
    try:
        relative = resolved.relative_to(root).as_posix()
    except ValueError:
        return "escaped", "", "outside_repository"
    if ".." in relative.split("/"):
        return "escaped", "", "outside_repository"
    if resolved.is_file():
        return "resolved", relative, reason
    return "unresolved", relative, "not_found"
