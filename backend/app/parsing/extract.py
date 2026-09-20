"""Profile-driven extraction of imports, entities, calls, and bindings."""

from __future__ import annotations

import re
from pathlib import Path

from app.domain.source import ParsedEntity, ParsedImport
from app.parsing.comments import strip_comments
from app.parsing.model import Binding, CallSite, LanguageProfile, SyntaxGraph

_IDENT = re.compile(r"[A-Za-z_$/\\][\w$\\]*")
_DYNAMIC_MARKERS = ("+", "${", 'f"', "f'", "%s", "%d", "{}", ".format(", "`", "#{")


def parse_with_profile(profile: LanguageProfile, file_path: Path, source: str) -> SyntaxGraph:
    cleaned = strip_comments(
        source,
        line_comment=profile.line_comment,
        block_comment=profile.block_comment,
    )
    lines = tuple(cleaned.splitlines() or [""])
    imports = _imports(profile, lines)
    entities = _entities(profile, lines)
    bindings = _bindings(profile, lines)
    calls = _calls(cleaned)
    return SyntaxGraph(
        language=profile.language_id,
        file_path=str(file_path),
        source=source,
        lines=lines,
        imports=tuple(imports),
        entities=tuple(entities),
        calls=tuple(calls),
        bindings=tuple(bindings),
    )


def _imports(profile: LanguageProfile, lines: tuple[str, ...]) -> list[ParsedImport]:
    found: list[ParsedImport] = []
    compiled = [re.compile(p) for p in profile.import_patterns]
    for i, line in enumerate(lines, start=1):
        for rx in compiled:
            match = rx.search(line)
            if not match:
                continue
            module = match.group(1)
            found.append(
                ParsedImport(
                    module=module,
                    line_number=i,
                    is_from_import="from" in line or "import " in line and "{" in line,
                    import_type="unknown",
                )
            )
            break
    return found


def _entities(profile: LanguageProfile, lines: tuple[str, ...]) -> list[ParsedEntity]:
    found: list[ParsedEntity] = []
    func_rx = [re.compile(p) for p in profile.function_patterns]
    class_rx = [re.compile(p) for p in profile.class_patterns]
    for i, line in enumerate(lines, start=1):
        for rx in class_rx:
            match = rx.search(line)
            if match:
                name = match.group(1)
                found.append(
                    ParsedEntity(
                        entity_type="class",
                        name=name,
                        qualified_name=name,
                        start_line=i,
                        end_line=i,
                    )
                )
                break
        else:
            for rx in func_rx:
                match = rx.search(line)
                if match:
                    name = match.group(1)
                    found.append(
                        ParsedEntity(
                            entity_type="function",
                            name=name,
                            qualified_name=name,
                            start_line=i,
                            end_line=i,
                        )
                    )
                    break
    return found


def _bindings(profile: LanguageProfile, lines: tuple[str, ...]) -> list[Binding]:
    found: list[Binding] = []
    compiled = [re.compile(p) for p in profile.assignment_patterns]
    for i, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith(("if ", "for ", "while ", "return ", "elif ")):
            continue
        for rx in compiled:
            match = rx.search(stripped)
            if match and match.lastindex and match.lastindex >= 2:
                name, rhs = match.group(1), match.group(2).strip()
                if name and rhs:
                    found.append(Binding(name=name.lstrip("$"), line=i, rhs=rhs))
                break
    return found


def _calls(source: str) -> list[CallSite]:
    found: list[CallSite] = []
    i = 0
    n = len(source)
    line = 1
    while i < n:
        if source[i] == "\n":
            line += 1
            i += 1
            continue
        match = _IDENT.match(source, i)
        if not match:
            i += 1
            continue
        ident = match.group(0)
        j = match.end()
        qualified = ident
        while j < n and source[j] in " \t":
            j += 1
        while j < n and source.startswith((".", "::"), j):
            sep_len = 2 if source.startswith("::", j) else 1
            j += sep_len
            while j < n and source[j] in " \t":
                j += 1
            nxt = _IDENT.match(source, j)
            if not nxt:
                break
            qualified = f"{qualified}.{nxt.group(0)}"
            ident = nxt.group(0)
            j = nxt.end()
            while j < n and source[j] in " \t":
                j += 1
        if j < n and source[j] == "(":
            args, end = _balanced_parens(source, j)
            found.append(
                CallSite(
                    name=ident,
                    qualified=qualified,
                    line=line,
                    argument_text=args,
                    dynamic=_is_dynamic(args),
                )
            )
            line += source[j:end].count("\n")
            i = end
            continue
        i = match.end()
    return found


def _balanced_parens(source: str, start: int) -> tuple[str, int]:
    depth = 0
    i = start
    n = len(source)
    in_str: str | None = None
    escape = False
    while i < n:
        ch = source[i]
        if in_str:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == in_str:
                in_str = None
            i += 1
            continue
        if ch in {'"', "'", "`"}:
            in_str = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return source[start + 1 : i], i + 1
        i += 1
    return source[start + 1 :], n


def _is_dynamic(argument_text: str) -> bool:
    return any(marker in argument_text for marker in _DYNAMIC_MARKERS)
