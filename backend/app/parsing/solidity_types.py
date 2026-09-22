"""Canonical Solidity ABI types.

Selectors use the canonical type string. Data locations are not part of a
selector. A type BugForge cannot canonicalize does not get a guessed selector.
"""

from __future__ import annotations

import re

_ELEMENTARY = {
    "address": "address",
    "bool": "bool",
    "string": "string",
    "bytes": "bytes",
    "uint": "uint256",
    "int": "int256",
}
_DYNAMIC = frozenset({"bytes", "string"})


def canonical_solidity_type(annotation: str) -> str:
    """Return the canonical ABI type, or '' when it cannot be established."""
    text = _strip_locations(annotation)
    if not text:
        return ""
    return _piece(text)


def type_kind(annotation: str) -> str:
    """elementary, array, fixed_array, mapping, tuple, dynamic, or unresolved."""
    text = _strip_locations(annotation)
    if not text:
        return "unresolved"
    if text.startswith("mapping(") or text.startswith("mapping "):
        return "mapping"
    if text.startswith("("):
        return "tuple"
    if text.endswith("]"):
        match = re.fullmatch(r".+\[(\d*)\]", text.replace(" ", ""))
        if match is None:
            return "unresolved"
        return "fixed_array" if match.group(1) else "array"
    canon = _piece(text.replace(" ", ""))
    if not canon:
        return "unresolved"
    if canon in _DYNAMIC or canon.endswith("]"):
        return "dynamic" if canon in _DYNAMIC else type_kind(canon)
    return "elementary"


def is_dynamic_type(annotation: str) -> bool:
    kind = type_kind(annotation)
    if kind in {"dynamic", "array", "tuple"}:
        return True
    if kind == "fixed_array":
        return is_dynamic_type(re.sub(r"\[\d+\]$", "", _strip_locations(annotation)))
    return False


def _strip_locations(annotation: str) -> str:
    text = annotation.strip()
    text = re.sub(r"\b(memory|calldata|storage|indexed)\b", "", text)
    text = re.sub(r"\bpayable\b", "", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def _piece(text: str) -> str:
    compact = text.replace(" ", "")
    if not compact:
        return ""
    array = re.fullmatch(r"(.+)\[(\d*)\]", compact)
    if array and array.group(1):
        base = _piece(array.group(1))
        if not base:
            return ""
        return f"{base}[{array.group(2)}]"
    if compact.startswith("("):
        if not compact.endswith(")"):
            return ""
        inner = compact[1:-1]
        parts = _split_top(inner)
        if not parts or any(part == "" for part in parts):
            return "" if inner else "()"
        canon = [_piece(part) for part in parts]
        if not all(canon):
            return ""
        return "(" + ",".join(canon) + ")"
    if compact.startswith("mapping("):
        return ""
    if compact in _ELEMENTARY:
        return _ELEMENTARY[compact]
    if re.fullmatch(r"u?int\d+", compact) or re.fullmatch(r"bytes\d+", compact):
        return compact
    return ""


def _split_top(text: str) -> list[str]:
    parts: list[str] = []
    depth = 0
    start = 0
    for index, char in enumerate(text):
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif char == "," and depth == 0:
            parts.append(text[start:index])
            start = index + 1
    parts.append(text[start:])
    return [part for part in parts if part != ""]
