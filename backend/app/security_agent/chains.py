"""Structured attack-chain planning.

The model may propose a chain and a next experiment. BugForge does not treat
that proposal as verified. Every step needs authoritative evidence first.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from uuid import uuid4


@dataclass
class ChainStep:
    summary: str
    hypothesis_id: str = ""
    observation_id: str = ""
    evidence_id: str = ""
    evidence_tier: str = ""

    def snapshot(self) -> dict[str, str]:
        return {
            "summary": self.summary,
            "hypothesis_id": self.hypothesis_id,
            "observation_id": self.observation_id,
            "evidence_id": self.evidence_id,
            "evidence_tier": self.evidence_tier,
        }


@dataclass
class ExploitChain:
    chain_id: str
    steps: tuple[ChainStep, ...]
    status: str
    parent_id: str = ""
    next_experiment: str = ""
    evidence_requirements: tuple[str, ...] = ()
    termination_reason: str = ""

    @property
    def verified(self) -> bool:
        return self.status == "verified"

    def snapshot(self) -> dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "status": self.status,
            "parent_id": self.parent_id,
            "next_experiment": self.next_experiment,
            "evidence_requirements": list(self.evidence_requirements),
            "termination_reason": self.termination_reason,
            "steps": [step.snapshot() for step in self.steps],
            "verified": self.verified,
        }


def propose_chain(
    chain_id: str,
    steps: tuple[ChainStep, ...],
    *,
    parent_id: str = "",
) -> ExploitChain:
    if len(steps) < 2:
        raise ValueError("a chain needs at least two steps")
    chain = ExploitChain(chain_id, steps, "proposed", parent_id=parent_id)
    return assess_chain(chain)


def follow_on(chain: ExploitChain, summary: str) -> str:
    """Ask what becomes possible if the current chain's first observation holds.

    The answer is a proposed experiment, not a verified step.
    """
    if chain.verified:
        return ""
    head = chain.steps[0].summary if chain.steps else "the observation"
    return (
        f"What new attack becomes possible because `{head}` is true? "
        f"Next experiment: {summary}. This proposal is not evidence."
    )


def reject_chain(chain: ExploitChain, reason: str) -> ExploitChain:
    if not reason.strip():
        raise ValueError("a rejected chain requires a termination reason")
    chain.status = "rejected"
    chain.termination_reason = reason.strip()
    chain.next_experiment = ""
    return chain


def assess_chain(chain: ExploitChain) -> ExploitChain:
    if chain.status == "rejected":
        return chain
    missing = [step.summary for step in chain.steps if not step.evidence_id]
    chain.evidence_requirements = tuple(missing)
    if missing:
        chain.status = "proposed"
        chain.next_experiment = f"Collect evidence for: {missing[0]}"
        return chain
    tiers = {step.evidence_tier for step in chain.steps}
    if tiers == {"verified"}:
        chain.status = "verified"
        chain.next_experiment = ""
        return chain
    if tiers == {"reproduced"}:
        chain.status = "reproduced"
        chain.next_experiment = "Promote only with authoritative verified evidence"
        return chain
    chain.status = "evidenced"
    chain.next_experiment = "Repeat the missing authoritative evidence"
    return chain


def chain_from_snapshot(payload: dict[str, Any]) -> ExploitChain:
    steps = tuple(
        ChainStep(
            summary=str(item.get("summary") or ""),
            hypothesis_id=str(item.get("hypothesis_id") or ""),
            observation_id=str(item.get("observation_id") or ""),
            evidence_id=str(item.get("evidence_id") or ""),
            evidence_tier=str(item.get("evidence_tier") or ""),
        )
        for item in payload.get("steps") or []
        if isinstance(item, dict)
    )
    chain = ExploitChain(
        chain_id=str(payload.get("chain_id") or uuid4().hex),
        steps=steps,
        status=str(payload.get("status") or "proposed"),
        parent_id=str(payload.get("parent_id") or ""),
        next_experiment=str(payload.get("next_experiment") or ""),
        evidence_requirements=tuple(payload.get("evidence_requirements") or ()),
        termination_reason=str(payload.get("termination_reason") or ""),
    )
    if chain.status == "rejected":
        return chain
    return assess_chain(chain)


def remember_chain(memory: Any, chain: ExploitChain) -> None:
    extra = chain.snapshot()
    for entry in list(memory.entries):
        if entry.kind == "exploit_chain" and entry.extra.get("chain_id") == chain.chain_id:
            entry.summary = chain.next_experiment or chain.status
            entry.extra = extra
            return
    memory.remember("exploit_chain", chain.next_experiment or chain.status, extra)


def chains_from_memory(memory: Any) -> list[ExploitChain]:
    found: list[ExploitChain] = []
    for entry in memory.entries:
        if entry.kind != "exploit_chain":
            continue
        found.append(chain_from_snapshot(dict(entry.extra)))
    return found
