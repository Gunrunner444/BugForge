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
    layouts: list[dict[str, str]] = field(default_factory=list)
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


def compiler_semantics_for_scan(source: str) -> CompilerSemantics:
    """Overlay helper used by a Solidity scan.

    A missing compiler stays UNAVAILABLE. ``solc`` may be invoked with
    standard JSON and a minimal environment. ``forge`` without a safe
    standard-JSON runner does not invent a layout. Tests should monkeypatch
    availability rather than depend on a host compiler.
    """
    status = solidity_compiler_status()
    if status.status != "AVAILABLE":
        return CompilerSemantics("UNAVAILABLE", "", status.detail)
    if status.tool != "solc":
        return CompilerSemantics(
            "AVAILABLE",
            status.tool,
            "Compiler is present but BugForge has no safe standard-JSON runner "
            "for it. No storage layout was invented.",
        )
    return compiler_semantics(source, runner=_run_solc_standard_json)


def _run_solc_standard_json(source: str) -> str:
    import os
    import subprocess

    payload = json.dumps(
        {
            "language": "Solidity",
            "sources": {"BugForge.sol": {"content": source}},
            "settings": {"outputSelection": {"*": {"*": ["storageLayout"]}}},
        }
    )
    completed = subprocess.run(
        ["solc", "--standard-json"],
        input=payload,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
        env={"PATH": os.environ.get("PATH", "")},
    )
    if not completed.stdout:
        raise ValueError((completed.stderr or "solc produced no JSON")[:400])
    return completed.stdout


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
    layouts: list[dict[str, str]] = []
    contracts = payload.get("contracts")
    if isinstance(contracts, dict):
        for file_name, file_contracts in contracts.items():
            if not isinstance(file_contracts, dict):
                continue
            for contract_name, contract in file_contracts.items():
                if not isinstance(contract, dict):
                    continue
                layout = contract.get("storageLayout")
                if not isinstance(layout, dict):
                    continue
                slots = layout.get("storage")
                if not isinstance(slots, list):
                    continue
                raw_types = layout.get("types")
                types: dict[str, object] = raw_types if isinstance(raw_types, dict) else {}
                for slot in slots:
                    if not isinstance(slot, dict):
                        continue
                    label = str(slot.get("label") or "")
                    index = str(slot.get("slot") or "")
                    if not label or not index:
                        continue
                    storage.append({"label": label, "slot": index})
                    rich = {
                        "contract": str(contract_name),
                        "label": label,
                        "slot": index,
                        "source": str(file_name),
                    }
                    if slot.get("offset") is not None:
                        rich["offset"] = str(slot.get("offset"))
                    type_name = slot.get("type")
                    if isinstance(type_name, str) and type_name:
                        described = types.get(type_name)
                        if isinstance(described, dict) and described.get("label"):
                            rich["type"] = str(described["label"])
                        else:
                            rich["type"] = type_name
                    layouts.append(rich)
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
        layouts=layouts,
        compiler_version=version,
    )
