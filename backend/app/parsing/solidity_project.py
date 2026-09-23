"""Project-level Solidity compiler input.

The bundle is the repository snapshot already being analyzed. Paths stay
inside that root. BugForge does not execute Hardhat, Foundry scripts, or
package-manager commands. A missing compiler does not invent facts.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from contextvars import ContextVar, Token
from dataclasses import dataclass, field
from pathlib import Path

from app.core.paths import safe_join
from app.parsing.model import SyntaxGraph
from app.parsing.solidity_compiler import (
    CompilerSemantics,
    compiler_cache_key,
    interpret_standard_json,
)
from app.parsing.solidity_version import solidity_language_facts

_MAX_FILES = 40
_MAX_BYTES = 200_000
_SKIP_DIRS = {
    ".git",
    "node_modules",
    "out",
    "cache",
    "lib",
    "broadcast",
    "bugforge-output",
    "bugforge-explore",
}
_PROJECT: ContextVar[CompilerProjectModel | None] = ContextVar(
    "bugforge_compiler_project", default=None
)
_PROJECT_CACHE: ContextVar[dict[str, CompilerProjectModel] | None] = ContextVar(
    "bugforge_compiler_project_cache", default=None
)


@dataclass(frozen=True)
class CompilerProjectModel:
    """One scan's compiler picture. Unknown stays unknown."""

    status: str
    tool: str = ""
    compiler_version: str = ""
    source_identity: str = ""
    configuration_identity: str = ""
    diagnostics: tuple[str, ...] = ()
    contracts: tuple[str, ...] = ()
    sources: tuple[str, ...] = ()
    storage: tuple[dict[str, str], ...] = ()
    layouts: tuple[dict[str, str], ...] = ()
    selectors: tuple[dict[str, str], ...] = ()
    ast_available: bool = False
    ir_available: bool = False
    ir: str = ""
    ir_truncated: bool = False
    language: dict[str, str] = field(default_factory=dict)
    complete: bool = False
    unsupported: tuple[str, ...] = ()
    detail: str = ""


def set_compiler_project(
    model: CompilerProjectModel | None,
) -> Token[CompilerProjectModel | None]:
    return _PROJECT.set(model)


def reset_compiler_project(token: Token[CompilerProjectModel | None]) -> None:
    _PROJECT.reset(token)


def current_compiler_project() -> CompilerProjectModel | None:
    return _PROJECT.get()


def set_compiler_project_cache() -> Token[dict[str, CompilerProjectModel] | None]:
    return _PROJECT_CACHE.set({})


def reset_compiler_project_cache(token: Token[dict[str, CompilerProjectModel] | None]) -> None:
    _PROJECT_CACHE.reset(token)


def resolve_analysis_source(
    repo_root: Path, public_path: str, embedded: str
) -> tuple[str, str, str]:
    """Return ``(status, relative_path, text)``.

    ``status`` is ``ok``, ``missing``, or ``rejected``. An escaping path is
    rejected and is not read. Embedded parser bytes are used only after the
    public path resolves inside the repository.
    """
    if not public_path or "\x00" in public_path:
        return "rejected", "", ""
    root = repo_root.resolve()
    candidate = Path(public_path)
    if candidate.is_absolute():
        try:
            relative = candidate.resolve().relative_to(root).as_posix()
        except ValueError:
            return "rejected", "", ""
        if _contains_symlink(root, relative):
            return "rejected", "", ""
    else:
        if ".." in Path(public_path).parts or public_path.startswith(("/", "\\")):
            return "rejected", "", ""
        try:
            safe_join(root, public_path)
        except ValueError:
            return "rejected", "", ""
        relative = Path(public_path).as_posix()
        if _contains_symlink(root, relative):
            return "rejected", "", ""
    full = root / relative
    if embedded:
        return "ok", relative, embedded
    if not full.is_file():
        return "missing", relative, ""
    try:
        return "ok", relative, full.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return "missing", relative, ""


def project_standard_json(sources: dict[str, str], remappings: list[str]) -> dict[str, object]:
    """Standard JSON for the bounded source bundle. No model-supplied flags."""
    return {
        "language": "Solidity",
        "sources": {path: {"content": text} for path, text in sorted(sources.items())},
        "settings": {
            "remappings": list(remappings),
            "outputSelection": {
                "*": {
                    "*": ["storageLayout", "ir", "evm.methodIdentifiers"],
                    "": ["ast"],
                }
            },
        },
    }


def build_compiler_project(
    repo_root: Path,
    graphs: dict[str, SyntaxGraph],
    *,
    runner: Callable[[str], str] | None = None,
) -> CompilerProjectModel:
    """Build a project compiler model from graphs already parsed for this scan."""
    sources, diagnostics, complete, unsupported, remappings = _bundle(repo_root, graphs)
    identity = _source_identity(sources)
    config_identity = hashlib.sha256(
        json.dumps({"remappings": remappings, "unsupported": unsupported}, sort_keys=True).encode()
    ).hexdigest()
    language = solidity_language_facts("\n".join(sources.values()))
    language_dict = {
        "arithmetic": language.arithmetic,
        "selfdestruct": language.selfdestruct,
        "source": language.source,
    }
    tool, host_enabled = _compiler_tool()
    key = compiler_cache_key(
        snapshot=identity,
        compiler=tool,
        version="host" if host_enabled else "disabled",
        config=config_identity,
        sources=identity,
    )
    cache = _PROJECT_CACHE.get()
    if cache is not None and key in cache and runner is None:
        return cache[key]
    base = CompilerProjectModel(
        status="UNAVAILABLE",
        tool=tool,
        source_identity=identity,
        configuration_identity=config_identity,
        diagnostics=tuple(diagnostics),
        sources=tuple(sorted(sources)),
        language=language_dict,
        complete=False,
        unsupported=tuple(unsupported),
    )
    if not sources:
        model = _replace(base, detail="no readable Solidity sources were available for compilation")
        return _store(cache, key, model)
    if not complete:
        model = _replace(
            base,
            status="INCOMPLETE",
            detail="project source bundle is incomplete; compiler facts are not treated as proof",
        )
        return _store(cache, key, model)
    if runner is None and not host_enabled:
        model = _replace(
            base,
            detail=(
                "Host compiler execution is disabled. No compiler facts were fabricated. "
                "Parser results remain available."
            ),
        )
        return _store(cache, key, model)
    compile_runner = runner or _host_runner
    try:
        raw = compile_runner(json.dumps(project_standard_json(sources, remappings)))
    except (OSError, TimeoutError, ValueError) as exc:
        model = _replace(
            base,
            status="FAILED",
            detail=f"compiler invocation failed: {exc}"[:400],
        )
        return _store(cache, key, model)
    parsed = interpret_standard_json(raw, tool=tool or "solc")
    if parsed.status != "AVAILABLE":
        model = _replace(
            base, status="FAILED", detail=parsed.detail[:400], tool=parsed.tool or tool
        )
        return _store(cache, key, model)
    contracts = tuple(
        sorted(
            {
                item.get("contract", "")
                for item in [*parsed.layouts, *parsed.selectors]
                if item.get("contract")
            }
        )
    )
    compiled_language = solidity_language_facts(
        "\n".join(sources.values()), parsed.compiler_version
    )
    model = CompilerProjectModel(
        status="AVAILABLE",
        tool=parsed.tool or tool,
        compiler_version=parsed.compiler_version,
        source_identity=identity,
        configuration_identity=config_identity,
        diagnostics=tuple(diagnostics),
        contracts=contracts,
        sources=tuple(sorted(sources)),
        storage=tuple(parsed.storage),
        layouts=tuple(parsed.layouts),
        selectors=tuple(parsed.selectors),
        ast_available=parsed.ast_available,
        ir_available=parsed.ir_available,
        ir=parsed.ir,
        ir_truncated=parsed.ir_truncated,
        language={
            "arithmetic": compiled_language.arithmetic,
            "selfdestruct": compiled_language.selfdestruct,
            "source": compiled_language.source,
        },
        complete=True,
        unsupported=tuple(unsupported),
        detail=parsed.detail,
    )
    return _store(cache, key, model)


def project_semantics(model: CompilerProjectModel) -> CompilerSemantics:
    """Compiler semantics for rules. Incomplete and unavailable invent no layout."""
    if model.status != "AVAILABLE" or not model.complete:
        return CompilerSemantics(model.status or "UNAVAILABLE", model.tool, model.detail)
    return CompilerSemantics(
        "AVAILABLE",
        model.tool,
        model.detail,
        storage=[dict(item) for item in model.storage],
        layouts=[dict(item) for item in model.layouts],
        compiler_version=model.compiler_version,
        ir=model.ir,
        ir_available=model.ir_available,
        ir_truncated=model.ir_truncated,
        ast_available=model.ast_available,
        selectors=[dict(item) for item in model.selectors],
        language=dict(model.language),
    )


def slice_semantics(semantics: CompilerSemantics, relative_path: str) -> CompilerSemantics:
    """Keep compiler facts whose source path is this file. Do not merge names."""
    if semantics.status != "AVAILABLE":
        return semantics
    wanted = _normalize(relative_path)
    layouts = [
        item for item in semantics.layouts if _normalize(str(item.get("source", ""))) == wanted
    ]
    selectors = [
        item for item in semantics.selectors if _normalize(str(item.get("source", ""))) == wanted
    ]
    storage = [
        {"label": item["label"], "slot": item["slot"]}
        for item in layouts
        if item.get("label") and item.get("slot")
    ]
    return CompilerSemantics(
        semantics.status,
        semantics.tool,
        semantics.detail,
        storage=storage,
        layouts=layouts,
        compiler_version=semantics.compiler_version,
        pragma_version=semantics.pragma_version,
        ir=semantics.ir,
        ir_available=semantics.ir_available,
        ir_truncated=semantics.ir_truncated,
        ast_available=semantics.ast_available,
        selectors=selectors,
        language=dict(semantics.language),
    )


def _bundle(
    repo_root: Path, graphs: dict[str, SyntaxGraph]
) -> tuple[dict[str, str], list[str], bool, list[str], list[str]]:
    sources: dict[str, str] = {}
    diagnostics: list[str] = []
    complete = True
    unsupported = _static_limits(repo_root)
    remappings, remap_notes = _read_remappings(repo_root)
    unsupported.extend(remap_notes)
    for public, graph in graphs.items():
        if graph.language != "solidity":
            continue
        status, relative, text = resolve_analysis_source(repo_root, public, graph.source)
        if status != "ok":
            complete = False
            diagnostics.append(f"{status} source: {public}")
            continue
        if text == "":
            complete = False
            diagnostics.append(f"empty source: {relative or public}")
            continue
        sources[relative] = text
    total = sum(len(item.encode("utf-8")) for item in sources.values())
    root = repo_root.resolve()
    if root.is_dir():
        for path in sorted(root.rglob("*.sol")):
            if len(sources) >= _MAX_FILES or total >= _MAX_BYTES:
                complete = False
                diagnostics.append("source bundle limit reached")
                break
            if any(part in _SKIP_DIRS for part in path.parts):
                continue
            if path.is_symlink():
                diagnostics.append(f"skipped symlink: {path.name}")
                continue
            try:
                relative = path.resolve().relative_to(root).as_posix()
            except ValueError:
                diagnostics.append(f"rejected source: {path.name}")
                complete = False
                continue
            if relative in sources or _contains_symlink(root, relative):
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                diagnostics.append(f"missing source: {relative}")
                complete = False
                continue
            size = len(text.encode("utf-8"))
            if total + size > _MAX_BYTES:
                complete = False
                diagnostics.append("source bundle limit reached")
                break
            sources[relative] = text
            total += size
    return sources, diagnostics, complete, unsupported, remappings


def _static_limits(repo_root: Path) -> list[str]:
    notes: list[str] = []
    root = repo_root.resolve()
    if not root.is_dir():
        return notes
    for name in ("hardhat.config.js", "hardhat.config.ts", "foundry.toml"):
        path = root / name
        if path.is_file() and not path.is_symlink():
            notes.append(f"{name} was not executed")
    lib = root / "lib"
    if lib.is_dir() and not lib.is_symlink():
        notes.append("package directory lib was not executed or compiled")
    return notes


def _read_remappings(repo_root: Path) -> tuple[list[str], list[str]]:
    path = repo_root.resolve() / "remappings.txt"
    if not path.is_file() or path.is_symlink():
        return [], []
    found: list[str] = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return [], ["remappings.txt could not be read"]
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue
        if any(char in line for char in "$`;&|<>"):
            return [], ["remappings.txt contains unsupported syntax and was not used"]
        if line.count("=") != 1:
            return [], ["remappings.txt is not a static prefix map and was not used"]
        found.append(line)
        if len(found) > 64:
            return found[:64], ["remappings.txt was truncated at 64 entries"]
    return found, []


def _compiler_tool() -> tuple[str, bool]:
    import shutil

    from app.core.config import get_settings

    enabled = bool(get_settings().solidity_host_compiler)
    if shutil.which("solc"):
        return "solc", enabled
    if shutil.which("forge"):
        return "forge", False
    return "", False


def _host_runner(payload: str) -> str:
    from app.parsing.solidity_compiler import run_solc_standard_json

    return run_solc_standard_json(payload)


def _source_identity(sources: dict[str, str]) -> str:
    digest = hashlib.sha256()
    for path in sorted(sources):
        digest.update(path.encode("utf-8"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(sources[path].encode("utf-8")).digest())
    return digest.hexdigest()


def _store(
    cache: dict[str, CompilerProjectModel] | None, key: str, model: CompilerProjectModel
) -> CompilerProjectModel:
    if cache is not None:
        cache[key] = model
    return model


def _replace(model: CompilerProjectModel, **changes: object) -> CompilerProjectModel:
    data = {
        "status": model.status,
        "tool": model.tool,
        "compiler_version": model.compiler_version,
        "source_identity": model.source_identity,
        "configuration_identity": model.configuration_identity,
        "diagnostics": model.diagnostics,
        "contracts": model.contracts,
        "sources": model.sources,
        "storage": model.storage,
        "layouts": model.layouts,
        "selectors": model.selectors,
        "ast_available": model.ast_available,
        "ir_available": model.ir_available,
        "ir": model.ir,
        "ir_truncated": model.ir_truncated,
        "language": model.language,
        "complete": model.complete,
        "unsupported": model.unsupported,
        "detail": model.detail,
    }
    data.update(changes)
    return CompilerProjectModel(**data)  # type: ignore[arg-type]


def _contains_symlink(root: Path, relative: str) -> bool:
    current = root
    for part in Path(relative).parts:
        current = current / part
        if current.is_symlink():
            return True
    return False


def _normalize(path: str) -> str:
    text = path.replace("\\", "/").strip()
    while text.startswith("./"):
        text = text[2:]
    return text
