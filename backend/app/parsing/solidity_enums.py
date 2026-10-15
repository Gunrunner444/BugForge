"""Enum declarations read from Solidity source.

Members stay in source order. Solidity enums have no explicit values, so the
ABI integer of a member is its index and the underlying type is ``uint8``.
This reader does not infer members from comments or from function names.
"""

from __future__ import annotations

import re
from collections.abc import Mapping

_ENUM = re.compile(r"\benum\s+([A-Za-z_]\w*)\s*\{([^{}]*)\}")
_MEMBER = re.compile(r"[A-Za-z_]\w*")


def enums_in_text(text: str) -> dict[str, tuple[str, ...]]:
    """``name -> members`` for every enum in ``text``. Later duplicates in one file win only when equal."""
    from app.parsing.solidity_research import strip_comments

    found: dict[str, tuple[str, ...]] = {}
    for match in _ENUM.finditer(strip_comments(text)):
        members = tuple(_MEMBER.findall(match.group(2)))
        name = match.group(1)
        previous = found.get(name)
        if previous is not None and previous != members:
            found[name] = ()
            continue
        found[name] = members
    return {name: members for name, members in found.items() if members}


def lookup_enum(texts: Mapping[str, str], name: str) -> tuple[str, tuple[str, ...]] | None:
    """``(path, members)`` when every declaration of ``name`` agrees. Empty members mean a conflict."""
    short = name.split(".")[-1]
    if not short:
        return None
    found: list[tuple[str, tuple[str, ...]]] = []
    for path in sorted(texts):
        members = enums_in_text(texts[path]).get(short)
        if members is not None:
            found.append((path, members))
    if not found:
        return None
    first = found[0][1]
    if any(members != first for _path, members in found):
        return ("", ())
    return found[0]
