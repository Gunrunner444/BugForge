"""Structured attack-chain planning.

The model may propose a chain. BugForge does not treat that proposal as
verified. Every step needs authoritative evidence before verification is allowed.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ChainStep:
    summary: str
    hypothesis_id: str = ""
    observation_id: str = ""
    evidence_id: str = ""
    evidence_tier: str = ""


@dataclass(frozen=True)
class ExploitChain:
    chain_id: str
    steps: tuple[ChainStep, ...]
    status: str

    @property
    def verified(self) -> bool:
        return self.status == "verified"


def propose_chain(chain_id: str, steps: tuple[ChainStep, ...]) -> ExploitChain:
    if len(steps) < 2:
        raise ValueError("a chain needs at least two steps")
    return ExploitChain(chain_id, steps, "proposed")


def assess_chain(chain: ExploitChain) -> ExploitChain:
    if any(not step.evidence_id for step in chain.steps):
        return ExploitChain(chain.chain_id, chain.steps, "proposed")
    if any(step.evidence_tier != "verified" for step in chain.steps):
        return ExploitChain(chain.chain_id, chain.steps, "evidenced")
    return ExploitChain(chain.chain_id, chain.steps, "verified")
