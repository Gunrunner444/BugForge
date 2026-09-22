"""Graph-backed Solidity detectors.

Rules read syntax events produced by the Solidity parser. They do not treat a
keyword as proof, and they do not mark findings verified.
"""

from __future__ import annotations

import re
from collections.abc import Sequence

from app.analyzers.framework_detector import FrameworkInfo
from app.domain.security import VulnerabilityClass
from app.parsing.model import SyntaxEvent, SyntaxGraph
from app.security.rules.base import RuleDocumentation, SecurityObservation, SecurityRule

_DOC = RuleDocumentation(
    detects="A Solidity-specific pattern on the syntax graph.",
    evidence="The function or statement span that triggered the rule.",
    limitations=(
        "Static structure only. Cross-contract callbacks, assembly control flow, "
        "and compiler type checking are not fully modeled."
    ),
    false_positives=(
        "A custom modifier or a check expressed in assembly can be missed, "
        "which keeps the finding at potential rather than suppressing it."
    ),
)


def solidity_security_rules() -> list[SecurityRule]:
    return [
        ReentrancyRule(),
        TxOriginRule(),
        UncheckedCallRule(),
        ArbitraryDelegatecallRule(),
        MissingAuthorizationRule(),
        DowncastRule(),
        UncheckedArithmeticRule(),
        Pre08ArithmeticRule(),
        RoundingRule(),
        SignatureReplayRule(),
        InitializerRule(),
        StorageCollisionRule(),
        UnboundedLoopRule(),
        Erc20ReturnRule(),
        CallbackReentrancyRule(),
        UpgradeAuthRule(),
    ]


class _SolidityRule(SecurityRule):
    rule_id: str
    vulnerability_class: VulnerabilityClass
    documentation = _DOC
    event_kind = ""

    def check(
        self,
        graph: SyntaxGraph,
        *,
        frameworks: Sequence[FrameworkInfo] = (),
    ) -> list[SecurityObservation]:
        del frameworks
        if graph.language != "solidity" or graph.parser_tier.value == "profile_fallback":
            return []
        return self._check(graph)

    def _check(self, graph: SyntaxGraph) -> list[SecurityObservation]:
        return []

    def _obs(
        self, graph: SyntaxGraph, event: SyntaxEvent, title: str, summary: str
    ) -> SecurityObservation:
        fields = _fields(event.extra)
        return SecurityObservation(
            rule_id=self.rule_id,
            vulnerability_class=self.vulnerability_class,
            title=title,
            summary=summary,
            file_path=graph.file_path,
            line=event.line,
            evidence_text=event.text[:300],
            confidence="medium",
            language="solidity",
            documentation=self.documentation,
            parser_backend=graph.parser_backend,
            parser_tier=str(graph.parser_tier),
            node_id=fields.get("function", ""),
            metadata={
                "contract": fields.get("contract", ""),
                "function": fields.get("function", ""),
                "status": "potential",
            },
        )


class ReentrancyRule(_SolidityRule):
    rule_id = "sol.reentrancy"
    vulnerability_class = VulnerabilityClass.REENTRANCY

    def _check(self, graph: SyntaxGraph) -> list[SecurityObservation]:
        return _reentrancy(self, graph, hooks_only=False)


class CallbackReentrancyRule(_SolidityRule):
    rule_id = "sol.callback_reentrancy"
    vulnerability_class = VulnerabilityClass.REENTRANCY

    def _check(self, graph: SyntaxGraph) -> list[SecurityObservation]:
        return _reentrancy(self, graph, hooks_only=True)


class TxOriginRule(_SolidityRule):
    rule_id = "sol.tx_origin"
    vulnerability_class = VulnerabilityClass.AUTHORIZATION

    def _check(self, graph: SyntaxGraph) -> list[SecurityObservation]:
        return [
            self._obs(graph, event, "tx.origin authorization", "Authorization uses tx.origin.")
            for event in graph.events
            if event.kind == "sol_tx_origin"
        ]


class UncheckedCallRule(_SolidityRule):
    rule_id = "sol.unchecked_call"
    vulnerability_class = VulnerabilityClass.UNSAFE_EXTERNAL_CALL

    def _check(self, graph: SyntaxGraph) -> list[SecurityObservation]:
        found: list[SecurityObservation] = []
        for event in graph.events:
            fields = _fields(event.extra)
            if event.kind == "sol_external_call" and fields.get("kind") in {
                "call",
                "delegatecall",
                "staticcall",
            }:
                if fields.get("checked") != "true":
                    found.append(
                        self._obs(
                            graph,
                            event,
                            "Unchecked low-level call",
                            "Low-level call result is ignored.",
                        )
                    )
        return found


class ArbitraryDelegatecallRule(_SolidityRule):
    rule_id = "sol.arbitrary_delegatecall"
    vulnerability_class = VulnerabilityClass.UNSAFE_EXTERNAL_CALL

    def _check(self, graph: SyntaxGraph) -> list[SecurityObservation]:
        immutable = {
            _fields(event.extra).get("name", "")
            for event in graph.events
            if event.kind == "sol_state"
            and _fields(event.extra).get("mutability") in {"immutable", "constant"}
        }
        found: list[SecurityObservation] = []
        for event in graph.events:
            if event.kind != "sol_delegatecall":
                continue
            target = _fields(event.extra).get("target", "")
            base = target.split(".", 1)[0].strip()
            if "address(this)" in target or base in immutable:
                continue
            found.append(
                self._obs(
                    graph,
                    event,
                    "Arbitrary delegatecall",
                    "delegatecall target is not a fixed implementation.",
                )
            )
        return found


class MissingAuthorizationRule(_SolidityRule):
    rule_id = "sol.missing_authorization"
    vulnerability_class = VulnerabilityClass.AUTHORIZATION

    def _check(self, graph: SyntaxGraph) -> list[SecurityObservation]:
        found: list[SecurityObservation] = []
        privileged = {
            "withdraw",
            "setowner",
            "upgradeto",
            "upgradetoandcall",
            "pause",
            "unpause",
            "mint",
            "grantrole",
            "transferownership",
        }
        for event in _functions(graph):
            fields = _fields(event.extra)
            name = _function_name(event).lower()
            if name not in privileged:
                continue
            if fields.get("visibility") not in {"public", "external"}:
                continue
            if fields.get("mutability") in {"view", "pure"}:
                continue
            if _has_auth(fields.get("modifiers", "")) or "msg.sender" in event.text:
                continue
            found.append(
                self._obs(
                    graph,
                    event,
                    "Missing authorization",
                    f"{name} is externally reachable without an auth check.",
                )
            )
        return found


class DowncastRule(_SolidityRule):
    rule_id = "sol.downcast"
    vulnerability_class = VulnerabilityClass.UNSAFE_ARITHMETIC

    def _check(self, graph: SyntaxGraph) -> list[SecurityObservation]:
        found: list[SecurityObservation] = []
        for event in graph.events:
            if event.kind != "sol_downcast":
                continue
            function = _enclosing_function(graph, event)
            if function and "type(" in function.text and ".max" in function.text:
                continue
            found.append(
                self._obs(
                    graph, event, "Unsafe downcast", "Narrowing cast has no visible range check."
                )
            )
        return found


class UncheckedArithmeticRule(_SolidityRule):
    rule_id = "sol.unchecked_arithmetic"
    vulnerability_class = VulnerabilityClass.UNSAFE_ARITHMETIC

    def _check(self, graph: SyntaxGraph) -> list[SecurityObservation]:
        return [
            self._obs(
                graph,
                event,
                "Unchecked arithmetic",
                "Arithmetic sits in an explicit unchecked block.",
            )
            for event in graph.events
            if event.kind == "sol_unchecked"
        ]


class Pre08ArithmeticRule(_SolidityRule):
    rule_id = "sol.pre_0_8_arithmetic"
    vulnerability_class = VulnerabilityClass.UNSAFE_ARITHMETIC

    def _check(self, graph: SyntaxGraph) -> list[SecurityObservation]:
        if _checked(graph) is not False:
            return []
        return [
            self._obs(
                graph,
                event,
                "Pre-0.8 arithmetic",
                "State update uses arithmetic before Solidity 0.8 checks.",
            )
            for event in graph.events
            if event.kind == "sol_state_write" and re.search(r"[+\-*/]", event.text)
        ]


class RoundingRule(_SolidityRule):
    rule_id = "sol.rounding"
    vulnerability_class = VulnerabilityClass.UNSAFE_ARITHMETIC

    def _check(self, graph: SyntaxGraph) -> list[SecurityObservation]:
        return [
            self._obs(
                graph,
                event,
                "Division before multiplication",
                "This expression divides before it multiplies.",
            )
            for event in graph.events
            if event.kind == "sol_div_mul"
        ]


class SignatureReplayRule(_SolidityRule):
    rule_id = "sol.signature_replay"
    vulnerability_class = VulnerabilityClass.SIGNATURE_FLAW

    def _check(self, graph: SyntaxGraph) -> list[SecurityObservation]:
        found: list[SecurityObservation] = []
        for event in graph.events:
            if event.kind != "sol_ecrecover":
                continue
            function = _enclosing_function(graph, event)
            if function and re.search(r"\bnonce", function.text, re.IGNORECASE):
                continue
            found.append(
                self._obs(
                    graph,
                    event,
                    "Signature replay risk",
                    "ecrecover is used without a nonce binding.",
                )
            )
        return found


class InitializerRule(_SolidityRule):
    rule_id = "sol.initializer"
    vulnerability_class = VulnerabilityClass.UNSAFE_PROXY

    def _check(self, graph: SyntaxGraph) -> list[SecurityObservation]:
        found: list[SecurityObservation] = []
        for event in _functions(graph):
            name = _function_name(event)
            fields = _fields(event.extra)
            if name not in {"initialize", "reinitialize"}:
                continue
            if fields.get("visibility") not in {"public", "external"}:
                continue
            modifiers = fields.get("modifiers", "").lower()
            if "initializer" in modifiers:
                continue
            found.append(
                self._obs(
                    graph,
                    event,
                    "Initializer without guard",
                    "initialize is externally callable without an initializer modifier.",
                )
            )
        return found


class StorageCollisionRule(_SolidityRule):
    rule_id = "sol.storage_collision"
    vulnerability_class = VulnerabilityClass.UNSAFE_PROXY

    def _check(self, graph: SyntaxGraph) -> list[SecurityObservation]:
        mutable_impl = [
            event
            for event in graph.events
            if event.kind == "sol_state"
            and _fields(event.extra).get("name") in {"implementation", "impl"}
            and _fields(event.extra).get("mutability") == "storage"
        ]
        if not mutable_impl:
            return []
        calls = [event for event in graph.events if event.kind == "sol_delegatecall"]
        if not calls:
            return []
        return [
            self._obs(
                graph,
                calls[0],
                "Proxy storage collision indicator",
                "delegatecall uses a mutable implementation variable stored in normal layout.",
            )
        ]


class UnboundedLoopRule(_SolidityRule):
    rule_id = "sol.unbounded_loop"
    vulnerability_class = VulnerabilityClass.DENIAL_OF_SERVICE

    def _check(self, graph: SyntaxGraph) -> list[SecurityObservation]:
        found: list[SecurityObservation] = []
        for event in graph.events:
            if event.kind != "sol_loop":
                continue
            if ".length" not in event.text:
                continue
            if re.search(r"<\s*\d+", event.text):
                continue
            if not re.search(r"\.(call|transfer|send|delegatecall)\s*\(", event.text):
                continue
            found.append(
                self._obs(
                    graph,
                    event,
                    "Unbounded external loop",
                    "Loop bound follows an array length and performs an external call.",
                )
            )
        return found


class Erc20ReturnRule(_SolidityRule):
    rule_id = "sol.erc20_unchecked_return"
    vulnerability_class = VulnerabilityClass.UNSAFE_EXTERNAL_CALL

    def _check(self, graph: SyntaxGraph) -> list[SecurityObservation]:
        found: list[SecurityObservation] = []
        for event in graph.events:
            if event.kind != "sol_erc20":
                continue
            if _fields(event.extra).get("checked") == "true" or "require(" in event.text:
                continue
            found.append(
                self._obs(
                    graph,
                    event,
                    "Ignored ERC-20 return",
                    "ERC-20 transfer return value is ignored.",
                )
            )
        return found


class UpgradeAuthRule(_SolidityRule):
    rule_id = "sol.upgrade_auth"
    vulnerability_class = VulnerabilityClass.UNSAFE_PROXY

    def _check(self, graph: SyntaxGraph) -> list[SecurityObservation]:
        found: list[SecurityObservation] = []
        for event in _functions(graph):
            name = _function_name(event).lower()
            fields = _fields(event.extra)
            if not name.startswith("upgrade"):
                continue
            if fields.get("visibility") not in {"public", "external"}:
                continue
            if _has_auth(fields.get("modifiers", "")) or "msg.sender" in event.text:
                continue
            found.append(
                self._obs(
                    graph,
                    event,
                    "Upgradeable function without auth",
                    f"{name} can be called without an authorization modifier.",
                )
            )
        return found


def _reentrancy(
    rule: _SolidityRule, graph: SyntaxGraph, *, hooks_only: bool
) -> list[SecurityObservation]:
    hooks = {"onerc721received", "tokensreceived", "onerc1155received"}
    found: list[SecurityObservation] = []
    for function in _functions(graph):
        name = _function_name(function).lower()
        if hooks_only and name not in hooks:
            continue
        if not hooks_only and name in hooks:
            continue
        modifiers = _fields(function.extra).get("modifiers", "").lower()
        if "nonreentrant" in modifiers:
            continue
        body_events = _inside(graph, function)
        calls = [event.line for event in body_events if event.kind == "sol_external_call"]
        writes = [event.line for event in body_events if event.kind == "sol_state_write"]
        if calls and writes and max(writes) > min(calls):
            title = "Callback reentrancy" if hooks_only else "State update after external call"
            found.append(
                rule._obs(
                    graph, function, title, "An external call happens before a later state write."
                )
            )
    return found


def _functions(graph: SyntaxGraph) -> list[SyntaxEvent]:
    return [event for event in graph.events if event.kind == "sol_function"]


def _function_name(event: SyntaxEvent) -> str:
    match = re.search(r"function\s+([A-Za-z_][\w]*)", event.text)
    if match:
        return match.group(1)
    stripped = event.text.lstrip()
    if stripped.startswith("constructor"):
        return "constructor"
    if stripped.startswith("receive"):
        return "receive"
    if stripped.startswith("fallback"):
        return "fallback"
    return ""


def _inside(graph: SyntaxGraph, function: SyntaxEvent) -> list[SyntaxEvent]:
    span = function.span
    if span is None:
        return []
    return [
        event
        for event in graph.events
        if event.span is not None
        and span.start_byte <= event.span.start_byte < span.end_byte
        and event is not function
    ]


def _enclosing_function(graph: SyntaxGraph, event: SyntaxEvent) -> SyntaxEvent | None:
    if event.span is None:
        return None
    chosen: SyntaxEvent | None = None
    for function in _functions(graph):
        span = function.span
        if span is None:
            continue
        if span.start_byte <= event.span.start_byte < span.end_byte and (
            chosen is None
            or (
                chosen.span
                and span.end_byte - span.start_byte < chosen.span.end_byte - chosen.span.start_byte
            )
        ):
            chosen = function
    return chosen


def _fields(extra: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for part in extra.split("|"):
        if "=" in part:
            key, value = part.split("=", 1)
            fields[key] = value
    return fields


def _has_auth(modifiers: str) -> bool:
    names = {item.strip().lower() for item in modifiers.split(",") if item.strip()}
    return bool(
        names & {"onlyowner", "onlyrole", "onlyadmin", "authorized", "requiresauth", "auth"}
    )


def _checked(graph: SyntaxGraph) -> bool | None:
    for item in graph.semantic_context:
        if item == "checked_arithmetic=true":
            return True
        if item == "checked_arithmetic=false":
            return False
    return None
