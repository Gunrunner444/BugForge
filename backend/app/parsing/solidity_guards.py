"""Semantic checks for initializer and reentrancy modifiers.

A modifier name is not evidence. The body has to show the check, the state
write, and, for a reentrancy lock, the clear after the placeholder.
"""

from __future__ import annotations

import re

from app.parsing.solidity_cfg import FunctionCfg, _skip_string_or_comment, build_function_cfg

_INIT_FLAG = r"(?:_?initialized|version)"
_LOCK_NAME = (
    r"(?:locked|_locked|_status|status|_entered|entered|"
    r"_reentrancyStatus|_reentrancyGuardEntered)"
)


def initializer_is_protected(body: str, helpers: dict[str, str] | None = None) -> bool:
    """True when prior init state is checked and then written before ``_;``.

    ``initialized = true; _;`` and ``version = 1; _;`` are not protection.
    A versioned guard counts only when a comparison establishes monotonicity.
    """
    if _direct_initializer(body):
        return True
    if not helpers or not re.search(r"_\s*;", body):
        return False
    before = body.split("_;", 1)[0]
    for name, helper in helpers.items():
        if not re.search(rf"\b{re.escape(name)}\s*\(", before):
            continue
        if _direct_initializer(_helper_as_modifier(helper)):
            return True
    return False


def reentrancy_guard_holds(body: str) -> bool:
    """True for check → entered → body → clear.

    ``locked = true; _;``, an owner check, and ``locked = computeLock(); _;``
    do not establish that sequence. Unknown assignments are not treated as safe.
    """
    if not re.search(r"_\s*;", body):
        return False
    cfg_text = _as_function(_replace_placeholder(body, "BODY_PLACEHOLDER = 1;"))
    cfg = build_function_cfg(cfg_text)
    if not cfg.known:
        return False
    placeholders = [node for node in cfg.nodes if "BODY_PLACEHOLDER" in node.text]
    if len(placeholders) != 1:
        return False
    placeholder = placeholders[0].node_id
    for variable in _lock_variables(body):
        if not _lock_check_dominates(cfg, variable, placeholder):
            continue
        if not _lock_set_dominates(cfg, variable, placeholder):
            continue
        if _lock_cleared_after(cfg, variable, placeholder):
            return True
    return False


def _direct_initializer(body: str) -> bool:
    if not re.search(r"_\s*;", body):
        return False
    cfg = build_function_cfg(_as_function(_replace_placeholder(body, "INIT_PLACEHOLDER = 1;")))
    if not cfg.known:
        return False
    placeholders = [node.node_id for node in cfg.nodes if "INIT_PLACEHOLDER" in node.text]
    checks = [node.node_id for node in cfg.nodes if _is_prior_init_check(node.text)]
    writes = [node.node_id for node in cfg.nodes if _is_init_write(node.text)]
    if not placeholders or not checks or not writes:
        return False
    for placeholder in placeholders:
        guarding = [check for check in checks if cfg.dominates(check, placeholder)]
        writing = [write for write in writes if cfg.dominates(write, placeholder)]
        if not guarding or not writing:
            return False
        if not any(cfg.dominates(check, write) for check in guarding for write in writing):
            return False
    return True


def _helper_as_modifier(helper: str) -> str:
    if re.search(r"_\s*;", helper):
        return helper
    start = helper.find("{")
    end = helper.rfind("}")
    if start < 0 or end <= start:
        return helper + "\n_;"
    return "{\n" + helper[start + 1 : end] + "\n_;\n}"


def _as_function(body: str) -> str:
    inner = body.strip()
    if inner.startswith("{") and inner.endswith("}"):
        inner = inner[1:-1]
    return "function _mod() {\n" + inner + "\n}"


def _replace_placeholder(body: str, replacement: str) -> str:
    return re.sub(r"_\s*;", replacement, body, count=1)


def _strip(text: str) -> str:
    chars: list[str] = []
    index = 0
    while index < len(text):
        skipped = _skip_string_or_comment(text, index)
        if skipped is not None:
            chars.append(" " * (skipped - index))
            index = skipped
            continue
        chars.append(text[index])
        index += 1
    return "".join(chars)


def _is_prior_init_check(text: str) -> bool:
    compact = re.sub(r"\s+", " ", _strip(text))
    if re.search(rf"require\s*\(\s*!\s*{_INIT_FLAG}\b", compact):
        return True
    if re.search(rf"require\s*\([^;]*\b{_INIT_FLAG}\b", compact) and re.search(
        r"==\s*false|==\s*0\b|<\s*", compact
    ):
        return True
    if re.search(rf"if\s*\(\s*{_INIT_FLAG}\s*\)", compact) and re.search(r"\brevert\b", compact):
        return True
    return bool(
        re.search(rf"if\s*\([^)]*\b{_INIT_FLAG}\b[^)]*(>=|>|!=\s*0)", compact)
        and re.search(r"\brevert\b|\brequire\b", compact)
    )


def _is_init_write(text: str) -> bool:
    if "INIT_PLACEHOLDER" in text or "BODY_PLACEHOLDER" in text:
        return False
    return bool(re.search(rf"\b{_INIT_FLAG}\b\s*=(?!=)", _strip(text)))


def _lock_variables(body: str) -> list[str]:
    found: list[str] = []
    for match in re.finditer(rf"\b({_LOCK_NAME})\b", body):
        name = match.group(1)
        if name not in found:
            found.append(name)
    return found


def _lock_check_dominates(cfg: FunctionCfg, variable: str, placeholder: int) -> bool:
    for node in cfg.nodes:
        if not _is_lock_check(node.text, variable):
            continue
        if cfg.dominates(node.node_id, placeholder):
            return True
    return False


def _lock_set_dominates(cfg: FunctionCfg, variable: str, placeholder: int) -> bool:
    for node in cfg.nodes:
        if not _is_entered_assignment(node.text, variable):
            continue
        if not cfg.dominates(node.node_id, placeholder):
            continue
        if any(
            _is_lock_check(check.text, variable) and cfg.dominates(check.node_id, node.node_id)
            for check in cfg.nodes
        ):
            return True
    return False


def _lock_cleared_after(cfg: FunctionCfg, variable: str, placeholder: int) -> bool:
    after = cfg.reachable_from(placeholder)
    for node in cfg.nodes:
        if node.node_id == placeholder or node.node_id not in after:
            continue
        if _is_clear_assignment(node.text, variable):
            return True
    return False


def _is_lock_check(text: str, variable: str) -> bool:
    name = re.escape(variable)
    compact = re.sub(r"\s+", " ", _strip(text))
    if re.search(rf"require\s*\(\s*!+\s*{name}\b", compact):
        return True
    if re.search(rf"require\s*\([^;]*\b{name}\b", compact) and re.search(
        r"==\s*false|!=\s*_?ENTERED|==\s*_?NOT_ENTERED|==\s*1\b|!=\s*2\b",
        compact,
    ):
        return True
    if re.search(rf"if\s*\(\s*{name}\s*\)", compact) and "revert" in compact:
        return True
    return bool(
        re.search(rf"if\s*\([^)]*\b{name}\b[^)]*(==\s*_?ENTERED|!=\s*_?NOT_ENTERED)", compact)
        and "revert" in compact
    )


def _is_entered_assignment(text: str, variable: str) -> bool:
    match = re.search(rf"\b{re.escape(variable)}\b\s*=\s*([^;]+)", _strip(text))
    if match is None:
        return False
    rhs = match.group(1).strip()
    if "(" in rhs:
        return False
    return bool(re.fullmatch(r"true|2|_ENTERED|ENTERED|_entered", rhs))


def _is_clear_assignment(text: str, variable: str) -> bool:
    match = re.search(rf"\b{re.escape(variable)}\b\s*=\s*([^;]+)", _strip(text))
    if match is None:
        return False
    rhs = match.group(1).strip()
    if "(" in rhs:
        return False
    return bool(re.fullmatch(r"false|0|1|_NOT_ENTERED|NOT_ENTERED|_notEntered", rhs))
