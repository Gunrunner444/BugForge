"""BugForge class → HackerOne weakness candidates. Never pick silently when ambiguous."""

from __future__ import annotations

from dataclasses import dataclass

# Candidate HackerOne weakness IDs are CWE-oriented identifiers. Programs may
# require a numeric HackerOne weakness record id; the researcher must confirm.
_MAP: dict[str, tuple[str, ...]] = {
    "xss": ("cwe-79",),
    "cross_site_scripting": ("cwe-79",),
    "sql_injection": ("cwe-89",),
    "sqli": ("cwe-89",),
    "ssrf": ("cwe-918",),
    "csrf": ("cwe-352",),
    "open_redirect": ("cwe-601",),
    "path_traversal": ("cwe-22",),
    "command_injection": ("cwe-77", "cwe-78"),
    "insecure_direct_object_reference": ("cwe-639", "cwe-284"),
    "idor": ("cwe-639", "cwe-284"),
    "broken_access_control": ("cwe-284", "cwe-285", "cwe-639"),
    "authentication": ("cwe-287",),
    "sensitive_data_exposure": ("cwe-200",),
    "insecure_deserialization": ("cwe-502",),
    "xxe": ("cwe-611",),
    "misconfiguration": ("cwe-16",),
}


@dataclass(frozen=True)
class WeaknessMapping:
    bugforge_class: str
    candidates: tuple[str, ...]
    requires_human_selection: bool

    @property
    def selected(self) -> str | None:
        if self.requires_human_selection or len(self.candidates) != 1:
            return None
        return self.candidates[0]


def map_weakness(vulnerability_class: str | None) -> WeaknessMapping:
    key = (vulnerability_class or "").strip().lower().replace(" ", "_").replace("-", "_")
    candidates = _MAP.get(key, ())
    if not candidates:
        return WeaknessMapping(key, (), requires_human_selection=True)
    if len(candidates) > 1:
        return WeaknessMapping(key, candidates, requires_human_selection=True)
    return WeaknessMapping(key, candidates, requires_human_selection=False)
