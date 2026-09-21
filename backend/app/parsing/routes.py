"""Syntactic HTTP route facts.

Only a member call or decorator with a string-literal path is a route.
The decorator is not executed and the framework is not imported.
"""

from __future__ import annotations

import re

_ROUTE_METHODS = frozenset(
    {"get", "post", "put", "delete", "patch", "head", "options", "all", "route", "api_route"}
)
_PATH_PARAM = re.compile(r"<(?:[A-Za-z_]\w*:)?([A-Za-z_]\w*)>|\{([A-Za-z_]\w*)\}|:([A-Za-z_]\w*)")


def is_route_method(name: str) -> bool:
    return name.lower() in _ROUTE_METHODS


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
