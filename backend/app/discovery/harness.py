"""Candidate Solidity harnesses. They are not written into the analyzed repository."""

from __future__ import annotations

from pathlib import Path

from app.discovery.engine import AnalysisRequest
from app.parsing.solidity_graph import parse_solidity_source


def candidate_foundry_test(request: AnalysisRequest) -> str:
    function = request.function or "target"
    contract = request.contract or "Target"
    return (
        "// UNTRUSTED CANDIDATE. Not a verified proof.\n"
        "pragma solidity ^0.8.20;\n"
        'import {Test} from "forge-std/Test.sol";\n'
        f"interface ITarget {{ function {function}() external; }}\n"
        f"contract {contract}Candidate is Test {{\n"
        f"    function test_{function}() public {{\n"
        "        // Candidate sequence generated from a static target.\n"
        "    }\n"
        "}\n"
    )


def validate_harness(source: str, path: Path) -> bool:
    graph = parse_solidity_source(path, source)
    return graph.parser_tier.value == "full_ast" and not graph.diagnostics.has_errors


def write_candidate(source: str, destination: Path, *, repo_root: Path) -> Path:
    resolved = destination.resolve()
    root = repo_root.resolve()
    if resolved == root or root in resolved.parents:
        raise ValueError("candidate harnesses are not written into the analyzed repository")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(source, encoding="utf-8")
    return destination
