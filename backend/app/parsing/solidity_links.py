"""Unambiguous Solidity relationships across files.

Duplicate contract names are left unresolved. BugForge does not invent an edge
when more than one definition matches.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.parsing.model import SyntaxGraph


@dataclass(frozen=True)
class SolidityLink:
    kind: str
    source_file: str
    source_name: str
    target_file: str
    target_name: str


def relate_solidity_files(graphs: dict[str, SyntaxGraph]) -> list[SolidityLink]:
    contracts: dict[str, list[tuple[str, str]]] = {}
    for path, graph in graphs.items():
        if graph.language != "solidity" or graph.parser_tier.value == "profile_fallback":
            continue
        for entity in graph.entities:
            if entity.entity_type in {"contract", "interface", "library"}:
                contracts.setdefault(entity.name, []).append((path, entity.entity_type))
    links: list[SolidityLink] = []
    for path, graph in graphs.items():
        for event in graph.events:
            if event.kind != "sol_contract":
                continue
            fields = _fields(event.extra)
            for base in fields.get("bases", "").split(","):
                base_name = base.strip().split("(")[0].strip()
                if not base_name:
                    continue
                matches = contracts.get(base_name, [])
                if len(matches) != 1:
                    continue
                target_file, _kind = matches[0]
                if target_file == path:
                    continue
                links.append(
                    SolidityLink(
                        "inherits",
                        path,
                        fields.get("kind", "contract") + ":" + event.text[:80],
                        target_file,
                        base_name,
                    )
                )
        for imported in graph.imports:
            module = imported.module.rsplit("/", 1)[-1]
            for other, other_graph in graphs.items():
                if other == path:
                    continue
                other_name = other.rsplit("/", 1)[-1]
                if module and module == other_name:
                    links.append(SolidityLink("imports", path, module, other, other_name))
    return links


def _fields(extra: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for part in extra.split("|"):
        if "=" in part:
            key, value = part.split("=", 1)
            fields[key] = value
    return fields
