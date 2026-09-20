"""Evidence graph: finding → hypothesis → evidence → tool → request/source/reproduction."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from uuid import uuid4


@dataclass
class EvidenceNode:
    id: str
    kind: str
    provenance: str
    summary: str
    source: str = ""
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class EvidenceGraph:
    nodes: dict[str, EvidenceNode] = field(default_factory=dict)
    edges: list[tuple[str, str, str]] = field(default_factory=list)

    def add(
        self,
        *,
        kind: str,
        provenance: str,
        summary: str,
        source: str = "",
        extra: dict[str, Any] | None = None,
        parent_id: str | None = None,
        relation: str = "supports",
    ) -> EvidenceNode:
        node = EvidenceNode(
            id=uuid4().hex,
            kind=kind,
            provenance=provenance,
            summary=summary,
            source=source,
            extra=extra or {},
        )
        self.nodes[node.id] = node
        if parent_id:
            self.edges.append((parent_id, node.id, relation))
        return node

    def why(self, node_id: str) -> list[dict[str, Any]]:
        """Explain why BugForge believes a node, following inbound edges."""
        chain: list[dict[str, Any]] = []
        seen: set[str] = set()
        current = [node_id]
        while current:
            nxt: list[str] = []
            for ident in current:
                if ident in seen:
                    continue
                seen.add(ident)
                node = self.nodes.get(ident)
                if node is None:
                    continue
                chain.append(
                    {
                        "id": node.id,
                        "kind": node.kind,
                        "provenance": node.provenance,
                        "summary": node.summary,
                        "source": node.source,
                    }
                )
                for src, dst, _rel in self.edges:
                    if dst == ident:
                        nxt.append(src)
            current = nxt
        return chain

    def snapshot(self) -> dict[str, Any]:
        return {
            "nodes": [
                {
                    "id": node.id,
                    "kind": node.kind,
                    "provenance": node.provenance,
                    "summary": node.summary,
                    "source": node.source,
                }
                for node in self.nodes.values()
            ],
            "edges": [{"from": src, "to": dst, "relation": rel} for src, dst, rel in self.edges],
        }
