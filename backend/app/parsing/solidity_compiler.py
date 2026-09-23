"""Optional Solidity compiler overlay.

solc and forge are not required to start BugForge or to build a syntax graph.
When a compiler is absent, this module reports UNAVAILABLE and does not invent
storage layout, types, or diagnostics. A successful compiler response may add
layout facts; a failed or unparsable response stays failed.
"""

from __future__ import annotations

import json
import shutil
from collections.abc import Callable
from dataclasses import dataclass, field


@dataclass(frozen=True)
class SolidityCompilerStatus:
    status: str
    tool: str
    detail: str


@dataclass
class CompilerSemantics:
    status: str
    tool: str
    detail: str
    storage: list[dict[str, str]] = field(default_factory=list)
    compiler_version: str = ""


def solidity_compiler_status() -> SolidityCompilerStatus:
    """Report whether a local compiler exists. Does not execute it."""
    for name in ("solc", "forge"):
        if shutil.which(name):
            return SolidityCompilerStatus(
                "AVAILABLE",
                name,
                f"{name} is installed. Tree-sitter remains the syntax graph. "
                "Compiler output is an optional overlay and is not a proof.",
            )
    return SolidityCompilerStatus(
        "UNAVAILABLE",
        "",
        "solc and forge are not installed. Type resolution, storage layout, "
        "and inheritance stay on the Tree-sitter parser. No compiler facts are fabricated.",
    )


def compiler_semantics(
    source: str, *, runner: Callable[[str], str] | None = None
) -> CompilerSemantics:
    """Return compiler facts when a real result is available.

    ``runner`` receives the source and returns a standard-JSON string. It is
    invoked only after a compiler binary is reported available. A missing
    compiler never produces a layout.
    """
    status = solidity_compiler_status()
    if status.status != "AVAILABLE":
        return CompilerSemantics("UNAVAILABLE", "", status.detail)
    if runner is None:
        return CompilerSemantics(
            "AVAILABLE",
            status.tool,
            "Compiler binary is present. BugForge does not replace the parser "
            "graph with compiler output unless a standard-JSON result is supplied.",
        )
    try:
        raw = runner(source)
    except (OSError, TimeoutError, ValueError) as exc:
        return CompilerSemantics("FAILED", status.tool, f"compiler invocation failed: {exc}")
    return _parse_standard_json(raw, status.tool)


def _parse_standard_json(raw: str, tool: str) -> CompilerSemantics:
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return CompilerSemantics("FAILED", tool, "compiler output was not JSON")
    if not isinstance(payload, dict):
        return CompilerSemantics("FAILED", tool, "compiler output was not an object")
    errors = payload.get("errors")
    if isinstance(errors, list) and any(
        isinstance(item, dict) and item.get("severity") == "error" for item in errors
    ):
        return CompilerSemantics("FAILED", tool, "compiler reported an error")
    storage: list[dict[str, str]] = []
    contracts = payload.get("contracts")
    if isinstance(contracts, dict):
        for file_contracts in contracts.values():
            if not isinstance(file_contracts, dict):
                continue
            for contract in file_contracts.values():
                if not isinstance(contract, dict):
                    continue
                layout = contract.get("storageLayout")
                if not isinstance(layout, dict):
                    continue
                slots = layout.get("storage")
                if not isinstance(slots, list):
                    continue
                for slot in slots:
                    if not isinstance(slot, dict):
                        continue
                    label = str(slot.get("label") or "")
                    index = str(slot.get("slot") or "")
                    if label and index:
                        storage.append({"label": label, "slot": index})
    version = ""
    if isinstance(payload.get("version"), str):
        version = str(payload["version"])
    if not storage and not version:
        return CompilerSemantics(
            "FAILED", tool, "compiler JSON did not include storage layout or a version"
        )
    return CompilerSemantics(
        "AVAILABLE",
        tool,
        "Compiler overlay parsed. These facts do not mark any finding verified.",
        storage=storage,
        compiler_version=version,
    )
