"""Syntactic HTTP route facts.

Only a member call or decorator with a string-literal path is a route, and
only when the receiver is bound to a known framework constructor. The
decorator is not executed and the framework is not imported.
"""

from __future__ import annotations

import re
from collections.abc import Sequence

from app.parsing.model import Binding

_ROUTE_METHODS = frozenset(
    {"get", "post", "put", "delete", "patch", "head", "options", "all", "route", "api_route"}
)
_PATH_PARAM = re.compile(r"<(?:[A-Za-z_]\w*:)?([A-Za-z_]\w*)>|\{([A-Za-z_]\w*)\}|:([A-Za-z_]\w*)")
_JS_LANGS = frozenset({"javascript", "typescript"})


def is_route_method(name: str) -> bool:
    return name.lower() in _ROUTE_METHODS


def route_constructors_for_language(language: str) -> frozenset[str]:
    """Constructor names that create a route object for this language."""
    from app.analyzers.framework_registry import get_framework_registry

    names: set[str] = set()
    for spec in get_framework_registry().all_specs():
        if not _language_matches(spec.language, language):
            continue
        names.update(spec.constructors)
    return frozenset(names)


def constructed_route_receiver(
    bindings: Sequence[Binding],
    *,
    language: str,
    name: str,
    at_byte: int,
    scope_id: str,
) -> bool:
    """True when ``name`` is bound to a framework constructor at this use.

    ``app = Flask(__name__)`` and ``const app = express()`` count.
    An unrelated object named ``app`` does not.
    """
    constructors = route_constructors_for_language(language)
    if not constructors or not name or "." in name:
        return False
    current: str | None = scope_id or "module"
    seen: set[str] = set()
    while current and current not in seen:
        seen.add(current)
        hits = [
            binding
            for binding in bindings
            if binding.scope_id == current
            and binding.name == name
            and _binding_byte(binding) <= at_byte
        ]
        if hits:
            chosen = max(
                hits, key=lambda binding: (_binding_byte(binding), binding.definition_index)
            )
            return _callee_is_constructor(chosen, constructors)
        if "/" not in current:
            break
        current = current.rsplit("/", 1)[0]
    if "module" not in seen:
        return constructed_route_receiver(
            bindings, language=language, name=name, at_byte=at_byte, scope_id="module"
        )
    return False


def looks_like_route_path(path: str) -> bool:
    """A literal path, not an arbitrary string such as a cache key."""
    return path.startswith("/")


def path_parameters(path: str) -> tuple[str, ...]:
    found: list[str] = []
    for match in _PATH_PARAM.finditer(path):
        name = next(group for group in match.groups() if group)
        if name in {"self", "cls"} or name in found:
            continue
        found.append(name)
    return tuple(found)


def _language_matches(spec_language: str, graph_language: str) -> bool:
    spec = spec_language.strip().lower()
    lang = graph_language.strip().lower()
    if not spec or not lang:
        return False
    parts = {part for part in spec.replace(",", "/").split("/") if part}
    if lang in parts:
        return True
    if lang in _JS_LANGS and parts & _JS_LANGS:
        return True
    return spec == lang


def _binding_byte(binding: Binding) -> int:
    start = getattr(binding.span, "start_byte", None)
    if isinstance(start, int):
        return start
    return max(0, binding.line) * 10_000


def _callee_is_constructor(binding: Binding, constructors: frozenset[str]) -> bool:
    for callee in binding.rhs_callees:
        simple = callee.rsplit(".", 1)[-1]
        if simple in constructors or callee in constructors:
            return True
    return False
