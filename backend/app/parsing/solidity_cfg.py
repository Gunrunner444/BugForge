"""Conservative intra-procedural control-flow for one Solidity function.

This is not a compiler CFG. Brace structure that cannot be split stays unknown.
A guard dominates a later operation only when every path that reaches the
operation has already passed the guard.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field

_CONTROL = ("if", "for", "while", "do", "unchecked", "try")


@dataclass
class CfgNode:
    node_id: int
    kind: str
    text: str


@dataclass
class FunctionCfg:
    nodes: list[CfgNode] = field(default_factory=list)
    edges: list[tuple[int, int, str]] = field(default_factory=list)
    entry: int = 0
    known: bool = True

    def successors(self, node_id: int) -> list[int]:
        return [dst for src, dst, _label in self.edges if src == node_id]

    def reachable_from(self, start: int) -> set[int]:
        seen: set[int] = set()
        stack = [start]
        while stack:
            current = stack.pop()
            if current in seen:
                continue
            seen.add(current)
            stack.extend(self.successors(current))
        return seen

    def dominates(self, guard: int, target: int) -> bool:
        """Every entry-to-target path passes through ``guard``."""
        if not self.known:
            return False
        if guard == target:
            return True
        if target not in self.reachable_from(self.entry):
            return False
        seen: set[int] = set()
        stack = [self.entry]
        while stack:
            current = stack.pop()
            if current == guard or current in seen:
                continue
            if current == target:
                return False
            seen.add(current)
            for nxt in self.successors(current):
                if nxt != guard:
                    stack.append(nxt)
        return True


def extract_body(function_text: str) -> str:
    start = function_text.find("{")
    if start < 0:
        return ""
    depth = 0
    for index in range(start, len(function_text)):
        char = function_text[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return function_text[start + 1 : index]
    return ""


def build_function_cfg(function_text: str) -> FunctionCfg:
    body = extract_body(function_text)
    if not body.strip():
        cfg = FunctionCfg()
        entry = _add(cfg, "entry", "")
        cfg.entry = entry
        return cfg
    cfg = FunctionCfg()
    try:
        statements = split_top_statements(body)
        entry = _add(cfg, "entry", "")
        cfg.entry = entry
        exit_id = _add(cfg, "exit", "")
        terminals = _link_sequence(cfg, statements, entry, exit_id)
        for terminal in terminals:
            if terminal != exit_id:
                cfg.edges.append((terminal, exit_id, "next"))
    except ValueError:
        failed = FunctionCfg(known=False)
        failed.entry = _add(failed, "unknown", body[:180])
        return failed
    return cfg


def auth_dominates_sensitive(function_text: str) -> bool:
    """True when an authorization check protects every sensitive operation.

    ``owner = msg.sender`` and a ternary that mentions ``msg.sender`` are not
    checks. A check that appears only after the operation does not protect it.
    """
    cfg = build_function_cfg(function_text)
    if not cfg.known:
        return False
    guards = _tight_nodes(cfg, _is_auth_guard)
    sensitive = _tight_nodes(cfg, _is_sensitive)
    if not guards or not sensitive:
        return False
    return all(any(cfg.dominates(guard, op) for guard in guards) for op in sensitive)


def write_reachable_after(function_text: str, earlier: str, later: str) -> bool | None:
    """Whether ``later`` can run after ``earlier`` on one path.

    None means the function body could not be split confidently.
    """
    cfg = build_function_cfg(function_text)
    if not cfg.known or not earlier or not later:
        return None
    starts = _tight_ids(cfg, lambda text: earlier in text)
    ends = _tight_ids(cfg, lambda text: later in text)
    if not starts or not ends:
        return None
    reachable: set[int] = set()
    for start in starts:
        reachable |= cfg.reachable_from(start)
    for end in ends:
        if end in reachable and end not in starts:
            return True
    return False


def _tight_nodes(cfg: FunctionCfg, predicate: Callable[[str], bool]) -> list[int]:
    matched = [
        node
        for node in cfg.nodes
        if node.kind not in {"entry", "exit", "join"} and predicate(node.text)
    ]
    return _drop_wrappers(matched)


def _tight_ids(cfg: FunctionCfg, predicate: Callable[[str], bool]) -> list[int]:
    matched = [
        node
        for node in cfg.nodes
        if node.kind not in {"entry", "exit", "join"} and predicate(node.text)
    ]
    return _drop_wrappers(matched)


def _drop_wrappers(nodes: list[CfgNode]) -> list[int]:
    kept: list[int] = []
    for node in nodes:
        wrapped = any(
            other is not node
            and other.text
            and other.text in node.text
            and len(other.text) < len(node.text)
            for other in nodes
        )
        if not wrapped:
            kept.append(node.node_id)
    return kept


def split_top_statements(body: str) -> list[str]:
    parts: list[str] = []
    index = 0
    length = len(body)
    while index < length:
        while index < length and body[index].isspace():
            index += 1
        if index >= length:
            break
        start = index
        if _keyword_at(body, index):
            index = _consume_control(body, index)
        else:
            index = _consume_simple(body, index)
        piece = body[start:index].strip()
        if piece:
            parts.append(piece)
    return parts


def _link_sequence(cfg: FunctionCfg, statements: list[str], entry: int, exit_id: int) -> list[int]:
    previous = [entry]
    for statement in statements:
        kind = _statement_kind(statement)
        node = _add(cfg, kind, statement.strip())
        for src in previous:
            cfg.edges.append((src, node, "next"))
        if kind in {"return", "revert"}:
            cfg.edges.append((node, exit_id, "exit"))
            previous = []
            continue
        if kind == "require":
            cfg.edges.append((node, exit_id, "fail"))
            previous = [node]
            continue
        if kind == "if":
            previous = _link_if(cfg, statement, node, exit_id)
            continue
        if kind == "loop":
            cfg.edges.append((node, node, "back"))
            previous = [node]
            continue
        previous = [node]
    return previous


def _link_if(cfg: FunctionCfg, statement: str, node: int, exit_id: int) -> list[int]:
    then_body, else_body = _if_branches(statement)
    join = _add(cfg, "join", "")
    then_end = _link_sequence(cfg, split_top_statements(then_body), node, exit_id)
    for src in then_end:
        cfg.edges.append((src, join, "then"))
    if else_body is None:
        cfg.edges.append((node, join, "else"))
    else:
        else_end = _link_sequence(cfg, split_top_statements(else_body), node, exit_id)
        for src in else_end:
            cfg.edges.append((src, join, "else"))
    return [join]


def _if_branches(statement: str) -> tuple[str, str | None]:
    then_at = statement.find("{")
    if then_at < 0:
        return "", None
    then_body, then_end = _matching_brace(statement, then_at)
    rest = statement[then_end:].strip()
    if rest.startswith("else"):
        else_at = rest.find("{")
        if else_at < 0:
            return then_body, rest[len("else") :].strip()
        else_body, _end = _matching_brace(rest, else_at)
        return then_body, else_body
    return then_body, None


def _matching_brace(text: str, open_at: int) -> tuple[str, int]:
    depth = 0
    for index in range(open_at, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return text[open_at + 1 : index], index + 1
    raise ValueError("unbalanced brace")


def _add(cfg: FunctionCfg, kind: str, text: str) -> int:
    node_id = len(cfg.nodes)
    cfg.nodes.append(CfgNode(node_id, kind, text[:500]))
    return node_id


def _keyword_at(text: str, index: int) -> bool:
    for word in _CONTROL:
        if text.startswith(word, index) and _boundary(text, index + len(word)):
            return True
    return False


def _boundary(text: str, index: int) -> bool:
    return index >= len(text) or not (text[index].isalnum() or text[index] == "_")


def _consume_simple(text: str, index: int) -> int:
    depth = 0
    while index < len(text):
        char = text[index]
        if char in "({[":
            depth += 1
        elif char in ")}]":
            depth = max(0, depth - 1)
        elif char == ";" and depth == 0:
            return index + 1
        index += 1
    return index


def _consume_control(text: str, index: int) -> int:
    keyword = _word(text, index)
    cursor = index + len(keyword)
    if keyword in {"if", "for", "while"}:
        cursor = _consume_parens(text, cursor)
    if keyword == "do":
        cursor = _consume_block_or_stmt(text, cursor)
        while cursor < len(text) and text[cursor].isspace():
            cursor += 1
        if text.startswith("while", cursor):
            cursor = _consume_parens(text, cursor + len("while"))
            if cursor < len(text) and text[cursor] == ";":
                cursor += 1
        return cursor
    cursor = _consume_block_or_stmt(text, cursor)
    if keyword == "if":
        probe = cursor
        while probe < len(text) and text[probe].isspace():
            probe += 1
        if text.startswith("else", probe) and _boundary(text, probe + 4):
            cursor = probe + 4
            cursor = _consume_block_or_stmt(text, cursor)
    return cursor


def _consume_parens(text: str, index: int) -> int:
    while index < len(text) and text[index].isspace():
        index += 1
    if index >= len(text) or text[index] != "(":
        return index
    depth = 0
    while index < len(text):
        if text[index] == "(":
            depth += 1
        elif text[index] == ")":
            depth -= 1
            if depth == 0:
                return index + 1
        index += 1
    raise ValueError("unbalanced paren")


def _consume_block_or_stmt(text: str, index: int) -> int:
    while index < len(text) and text[index].isspace():
        index += 1
    if index < len(text) and text[index] == "{":
        _body, end = _matching_brace(text, index)
        return end
    if index < len(text) and _keyword_at(text, index):
        return _consume_control(text, index)
    return _consume_simple(text, index)


def _word(text: str, index: int) -> str:
    end = index
    while end < len(text) and (text[end].isalnum() or text[end] == "_"):
        end += 1
    return text[index:end]


def _statement_kind(statement: str) -> str:
    stripped = statement.lstrip()
    if stripped.startswith("if ") or stripped.startswith("if("):
        return "if"
    if stripped.startswith(("for ", "for(", "while ", "while(", "do ", "do{")):
        return "loop"
    if stripped.startswith("unchecked"):
        return "unchecked"
    if stripped.startswith("try ") or stripped.startswith("try{"):
        return "try"
    if re.match(r"return\b", stripped):
        return "return"
    if re.match(r"revert\b", stripped):
        return "revert"
    if re.match(r"require\s*\(", stripped) or re.match(r"assert\s*\(", stripped):
        return "require"
    return "stmt"


def _is_auth_guard(text: str) -> bool:
    if not text:
        return False
    if not re.search(r"\b(require|assert|if)\s*\(", text):
        return False
    return bool(re.search(r"msg\.sender\s*==|==\s*msg\.sender|\bhasRole\s*\(|\bonlyOwner\b", text))


def _is_sensitive(text: str) -> bool:
    if not text or _is_auth_guard(text):
        return False
    if re.search(r"\.(call|delegatecall|staticcall|send|transfer|safeTransferFrom)\s*[\(\{]", text):
        return True
    if re.match(
        r"(uint\d*|int\d*|address|bool|string|bytes\d*|mapping)\b",
        text.lstrip(),
    ):
        return False
    return bool(re.search(r"\b[A-Za-z_]\w*\b\s*(\[[^\]]+\])?\s*=[^=]", text))
