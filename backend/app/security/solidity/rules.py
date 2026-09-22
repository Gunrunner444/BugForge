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
        CrossFunctionReentrancyRule(),
        UpgradeAuthRule(),
        EncodePackedRule(),
        RandomnessRule(),
        SignatureDomainRule(),
        SelfdestructRule(),
        SignedCastRule(),
        StaleOracleRule(),
        DonationInflationRule(),
        FeeOnTransferRule(),
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
                "send",
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
            if _has_auth(fields.get("modifiers", "")) or _function_has_guard(graph, event):
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
            external = re.search(r"\.(call|transfer|send|delegatecall|safeTransferFrom)\s*[\(\{]", event.text)
            stored = re.search(r"\b\w+\s*\[[^\]]+\]\s*(\+=|-=|=)", event.text)
            if not external and not stored:
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


class CrossFunctionReentrancyRule(_SolidityRule):
    rule_id = "sol.cross_function_reentrancy"
    vulnerability_class = VulnerabilityClass.REENTRANCY

    def _check(self, graph: SyntaxGraph) -> list[SecurityObservation]:
        writers = {
            _fields(event.extra).get("function", "")
            for event in graph.events
            if event.kind == "sol_state_write"
        }
        found: list[SecurityObservation] = []
        for function in _functions(graph):
            if "nonreentrant" in _fields(function.extra).get("modifiers", "").lower():
                continue
            body = _inside(graph, function)
            external = [
                event
                for event in body
                if event.kind == "sol_external_call"
                and _fields(event.extra).get("kind") in {"call", "delegatecall", "send", "transfer"}
            ]
            if not external or function.span is None:
                continue
            for call in body:
                if call.kind != "sol_direct_call" or call.span is None:
                    continue
                callee = _fields(call.extra).get("name", "")
                if callee not in writers or callee == _function_name(function):
                    continue
                external_span = external[0].span
                if external_span is None or call.span.start_byte <= external_span.start_byte:
                    continue
                found.append(
                    self._obs(
                        graph,
                        function,
                        "Cross-function reentrancy",
                        f"External call happens before {callee}, which writes state.",
                    )
                )
                break
        return found


class EncodePackedRule(_SolidityRule):
    rule_id = "sol.encode_packed"
    vulnerability_class = VulnerabilityClass.SIGNATURE_FLAW

    def _check(self, graph: SyntaxGraph) -> list[SecurityObservation]:
        found: list[SecurityObservation] = []
        for event in graph.events:
            if event.kind != "sol_encode_packed":
                continue
            fields = _fields(event.extra)
            dynamic = int(fields.get("dynamic") or "0")
            unknown = int(fields.get("unknown") or "0")
            if dynamic >= 2 or (dynamic >= 1 and unknown >= 1):
                found.append(
                    self._obs(
                        graph,
                        event,
                        "Ambiguous abi.encodePacked",
                        "Packed encoding concatenates more than one dynamic value.",
                    )
                )
        return found


class RandomnessRule(_SolidityRule):
    rule_id = "sol.insecure_randomness"
    vulnerability_class = VulnerabilityClass.WEAK_CRYPTOGRAPHY

    def _check(self, graph: SyntaxGraph) -> list[SecurityObservation]:
        return [
            self._obs(
                graph,
                event,
                "Predictable randomness",
                "Block data is used as a randomness source. A deadline comparison is not this pattern.",
            )
            for event in graph.events
            if event.kind == "sol_randomness"
        ]


class SignatureDomainRule(_SolidityRule):
    rule_id = "sol.signature_domain"
    vulnerability_class = VulnerabilityClass.SIGNATURE_FLAW

    def _check(self, graph: SyntaxGraph) -> list[SecurityObservation]:
        found: list[SecurityObservation] = []
        for event in graph.events:
            if event.kind != "sol_ecrecover":
                continue
            function = _enclosing_function(graph, event)
            if function is None:
                continue
            if not re.search(r"\bnonce", function.text, re.IGNORECASE):
                continue
            if re.search(
                r"DOMAIN_SEPARATOR|domainSeparator|chainid|chainId|address\(this\)|typehash|typeHash",
                function.text,
            ):
                continue
            found.append(
                self._obs(
                    graph,
                    event,
                    "Signature missing domain separation",
                    "ecrecover is nonce-bound but not bound to a domain, chain, or this contract.",
                )
            )
        return found


class SelfdestructRule(_SolidityRule):
    rule_id = "sol.selfdestruct"
    vulnerability_class = VulnerabilityClass.DENIAL_OF_SERVICE

    def _check(self, graph: SyntaxGraph) -> list[SecurityObservation]:
        floor = next(
            (item for item in graph.semantic_context if item.startswith("compiler_floor=")),
            "compiler_floor=unknown",
        )
        return [
            self._obs(
                graph,
                event,
                "selfdestruct is version-sensitive",
                f"{floor}. selfdestruct does not have the same effect on every EVM version.",
            )
            for event in graph.events
            if event.kind == "sol_selfdestruct"
        ]


class SignedCastRule(_SolidityRule):
    rule_id = "sol.signed_cast"
    vulnerability_class = VulnerabilityClass.UNSAFE_ARITHMETIC

    def _check(self, graph: SyntaxGraph) -> list[SecurityObservation]:
        found: list[SecurityObservation] = []
        for event in graph.events:
            if event.kind != "sol_sign_cast":
                continue
            function = _enclosing_function(graph, event)
            if function and "type(" in function.text and ".max" in function.text:
                continue
            found.append(
                self._obs(
                    graph,
                    event,
                    "Signed to unsigned conversion",
                    "A signed value is cast to an unsigned type without a visible bound.",
                )
            )
        return found


class StaleOracleRule(_SolidityRule):
    rule_id = "sol.stale_oracle"
    vulnerability_class = VulnerabilityClass.UNSAFE_EXTERNAL_CALL

    def _check(self, graph: SyntaxGraph) -> list[SecurityObservation]:
        found: list[SecurityObservation] = []
        for function in _functions(graph):
            if not re.search(r"latestRoundData|latestAnswer", function.text):
                continue
            if re.search(r"updatedAt|answeredInRound", function.text):
                continue
            found.append(
                self._obs(
                    graph,
                    function,
                    "Unchecked oracle freshness",
                    "An oracle answer is used without an updatedAt or round check.",
                )
            )
        return found


class DonationInflationRule(_SolidityRule):
    rule_id = "sol.donation_inflation"
    vulnerability_class = VulnerabilityClass.UNSAFE_ARITHMETIC

    def _check(self, graph: SyntaxGraph) -> list[SecurityObservation]:
        found: list[SecurityObservation] = []
        for function in _functions(graph):
            if "balanceOf(address(this))" not in function.text.replace(" ", ""):
                continue
            if "totalSupply" not in function.text or "/" not in function.text:
                continue
            found.append(
                self._obs(
                    graph,
                    function,
                    "Donation or inflation indicator",
                    "Shares are derived from this contract's token balance and total supply.",
                )
            )
        return found


class FeeOnTransferRule(_SolidityRule):
    rule_id = "sol.fee_on_transfer"
    vulnerability_class = VulnerabilityClass.UNSAFE_EXTERNAL_CALL

    def _check(self, graph: SyntaxGraph) -> list[SecurityObservation]:
        found: list[SecurityObservation] = []
        for function in _functions(graph):
            if "balanceOf" not in function.text or ".transfer" not in function.text:
                continue
            if function.text.count("balanceOf") >= 2 or "balanceAfter" in function.text:
                continue
            found.append(
                self._obs(
                    graph,
                    function,
                    "Fee-on-transfer indicator",
                    "A transfer is paired with one balanceOf read and no measured balance delta.",
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
            if _has_auth(fields.get("modifiers", "")) or _function_has_guard(graph, event):
                continue
            found.append(
                self._obs(
                    graph,
                    event,
                    "Upgradeable function without auth",
                    f"{name} can be called without an authorization check.",
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
        calls = [
            event
            for event in body_events
            if event.kind == "sol_external_call"
            and _fields(event.extra).get("kind")
            in {"call", "delegatecall", "transfer", "send", "safeTransferFrom"}
            and event.span is not None
        ]
        writes = [
            event
            for event in body_events
            if event.kind == "sol_state_write" and event.span is not None
        ]
        reads = [
            event
            for event in body_events
            if event.kind == "sol_state_read" and event.span is not None
        ]
        for call in calls:
            for write in writes:
                assert call.span is not None and write.span is not None
                if write.span.start_byte <= call.span.start_byte:
                    continue
                variable = _fields(write.extra).get("name", "")
                read_before = any(
                    _fields(read.extra).get("name") == variable
                    and read.span is not None
                    and read.span.start_byte < call.span.start_byte
                    for read in reads
                )
                written_before = any(
                    _fields(prior.extra).get("name") == variable
                    and prior.span is not None
                    and prior.span.start_byte < call.span.start_byte
                    for prior in writes
                )
                used_in_call = bool(variable and variable in call.text)
                if written_before and not read_before and not used_in_call:
                    continue
                if not read_before and not used_in_call and written_before:
                    continue
                title = "Callback reentrancy" if hooks_only else "State update after external call"
                found.append(
                    rule._obs(
                        graph,
                        function,
                        title,
                        f"{variable or 'state'} is written after an external call.",
                    )
                )
                break
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
    names = set()
    for item in modifiers.split(","):
        token = re.split(r"[\(\s]", item.strip(), maxsplit=1)[0].lower()
        if token:
            names.add(token)
    return bool(
        names
        & {
            "onlyowner",
            "onlyrole",
            "onlyadmin",
            "authorized",
            "requiresauth",
            "requiresrole",
            "auth",
        }
    )


def _function_has_guard(graph: SyntaxGraph, function: SyntaxEvent) -> bool:
    return any(event.kind == "sol_auth_guard" for event in _inside(graph, function))


def _checked(graph: SyntaxGraph) -> bool | None:
    for item in graph.semantic_context:
        if item == "checked_arithmetic=true":
            return True
        if item == "checked_arithmetic=false":
            return False
    return None
