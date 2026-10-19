"""Property / oracle layer for executable VFCS (Phase 52 hardening, Part 2).

A sequence that *runs* is not a vulnerability. Every executable VFCS therefore
declares exactly one of:

* ``property_under_test``   -- a property with an executable oracle;
* ``no_property_available`` -- nothing meaningful can be judged from execution;
* ``property_unsupported``  -- a property exists but the bounded local harness
  cannot express its oracle (it needs a signer, a market, an EntryPoint, ...).

After execution a security property is ``property_violated``, ``property_held``
or an ``execution_only_observation``. A behavioral probe can instead record
``mechanism_observed`` or ``failure_propagated``; neither is a security verdict.
A sequence that executed without an oracle is ``SEQUENCE_EXECUTED_NO_ORACLE``
and is never a strong vulnerability candidate.

Every property is built from the static candidate *and* code evidence (the
function body, the state variable it writes, its public getter) and carries
provenance: file, line range, contract, functions, variables, the candidate it
came from, why it was chosen, its assumptions, and the oracle expression. A
property is a hypothesis until executed evidence exists; nothing here verifies.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from enum import StrEnum
from typing import Any

from app.discovery.bounty.shares import share_accounting
from app.discovery.bounty.vfcs import ATTACKER, Vfcs
from app.discovery.orchestration.codec import digest
from app.parsing.keccak import function_selector
from app.parsing.solidity_conservation import custody_pair
from app.parsing.solidity_research import ResearchModel, RFunction, SemanticCandidate


class PropertyFamily(StrEnum):
    AUTHORIZATION = "authorization"
    INITIALIZATION = "initialization"
    ACCOUNTING = "accounting"
    SOLVENCY = "solvency"
    TOKEN_MOVEMENT = "token_movement"
    ORACLE_SAFETY = "oracle_safety"
    NONCE_REPLAY = "nonce_replay"
    UPGRADE_SAFETY = "upgrade_safety"
    GOVERNANCE = "governance"
    BRIDGE_MESSAGE_BINDING = "bridge_message_binding"
    ACCESS_CONTROL_HIERARCHY = "access_control_hierarchy"
    MECHANISM = "mechanism"
    EIP7702 = "eip7702"
    ERC4337 = "erc4337"
    TRANSIENT_STORAGE = "transient_storage"


class PropertyDeclaration(StrEnum):
    PROPERTY_UNDER_TEST = "property_under_test"
    NO_PROPERTY_AVAILABLE = "no_property_available"
    PROPERTY_UNSUPPORTED = "property_unsupported"
    # An executable behavioral probe. Not a security invariant.
    MECHANISM_OBSERVATION = "mechanism_observation"


class PropertyVerdict(StrEnum):
    PROPERTY_VIOLATED = "property_violated"
    PROPERTY_HELD = "property_held"
    # Behavioral probe results. They are not security-property verdicts.
    MECHANISM_OBSERVED = "mechanism_observed"
    FAILURE_PROPAGATED = "failure_propagated"
    EXECUTION_ONLY_OBSERVATION = "execution_only_observation"
    NOT_EVALUATED = "not_evaluated"


class OracleKind(StrEnum):
    """How the harness judges the property. NONE means execution-only."""

    NONE = "none"
    # the probe call (by an actor who must not be able to make it) must revert
    CALL_MUST_FAIL = "call_must_fail"
    # a second initialization / replay of an authorization must revert
    SECOND_CALL_MUST_FAIL = "second_call_must_fail"
    # a privileged public getter must not change across the probe
    STATE_UNCHANGED = "state_unchanged"
    # the attacker's fixture-token balance after the last call must not exceed its
    # balance before the first call (read for the attacker, not the target)
    BALANCE_NOT_INCREASED = "balance_not_increased"
    # credited balance (public getter for the actor) must not exceed tokens received
    CREDIT_LE_RECEIVED = "credit_le_received"
    # solvency formulation: the actor's credit must not exceed what the contract holds
    CREDIT_LE_HOLDINGS = "credit_le_holdings"
    # Behavioral probe: did a reverting callee's failure reach the outer call?
    # Outer success is evidence of a mechanism, not a security-property violation.
    MECHANISM_PROBE = "mechanism_probe"
    # A configured value is still present in the return data of a read.
    CONFIGURED_VALUE = "configured_value"
    # The probe succeeds and a public getter ends at the expected word.
    STATE_EQUALS = "state_equals"


EXECUTABLE_ORACLES = frozenset(OracleKind) - {OracleKind.NONE}


@dataclass(frozen=True)
class OracleSpec:
    kind: OracleKind = OracleKind.NONE
    # The probe and precondition calls are bound by (role, function), not index,
    # so mutation/minimization cannot silently move the oracle onto another call.
    probe_role: str = ""
    probe_function: str = ""
    precondition_roles: tuple[str, ...] = ()
    getter: str = ""  # e.g. "owner()" or "balances(address)"
    getter_actor: str = ""  # actor passed to a mapping getter
    token_fixture: str = ""  # standard | fee_on_transfer | false_return
    snapshot: str = "before_probe"  # before_probe | before_sequence
    expression: str = ""
    formulation: str = "primary"  # primary | alternate
    # 0x plus 8 hex digits. Empty means a revert of any kind still satisfies
    # CALL_MUST_FAIL. A selector is required only for an authorization oracle
    # that names one custom error from the source.
    revert_selector: str = ""
    # Local positive-control sender, ``address(0x...)`` only. Empty means none.
    control_sender: str = ""
    # Word of a static return tuple. -1 means the oracle does not read one.
    word_index: int = -1
    observed_fixture: str = ""
    # Decimal words for STATE_EQUALS. Empty expected_before means the start is not checked.
    expected_before: str = ""
    expected_after: str = ""
    # "" or "payout_matches_credit": the caller's token gain equals the owner's credit loss
    # and the contract's token loss. An authorized payout of that amount is not theft.
    balance_relation: str = ""

    @property
    def executable(self) -> bool:
        return self.kind in EXECUTABLE_ORACLES

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "probe_role": self.probe_role,
            "probe_function": self.probe_function,
            "precondition_roles": list(self.precondition_roles),
            "getter": self.getter,
            "getter_actor": self.getter_actor,
            "token_fixture": self.token_fixture,
            "snapshot": self.snapshot,
            "expression": self.expression,
            "formulation": self.formulation,
            "revert_selector": self.revert_selector,
            "control_sender": self.control_sender,
            "word_index": self.word_index,
            "observed_fixture": self.observed_fixture,
            "expected_before": self.expected_before,
            "expected_after": self.expected_after,
            "balance_relation": self.balance_relation,
            "executable": self.executable,
        }


@dataclass(frozen=True)
class PropertyProvenance:
    file: str
    line_start: int
    line_end: int
    contract: str
    functions: tuple[str, ...]
    variables: tuple[str, ...]
    candidate: str
    reason: str
    assumptions: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "contract": self.contract,
            "functions": list(self.functions),
            "variables": list(self.variables),
            "candidate": self.candidate,
            "reason": self.reason,
            "assumptions": list(self.assumptions),
        }


@dataclass(frozen=True)
class PropertySpec:
    property_id: str
    family: PropertyFamily
    statement: str
    declaration: PropertyDeclaration
    oracle: OracleSpec
    provenance: PropertyProvenance
    unsupported_reason: str = ""
    alternates: tuple[OracleSpec, ...] = ()
    status: str = "hypothesis"  # a hypothesis until executed evidence exists
    verified: bool = False

    @property
    def executable(self) -> bool:
        return (
            self.declaration
            in {
                PropertyDeclaration.PROPERTY_UNDER_TEST,
                PropertyDeclaration.MECHANISM_OBSERVATION,
            }
            and self.oracle.executable
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "property_id": self.property_id,
            "family": self.family.value,
            "statement": self.statement,
            "declaration": self.declaration.value,
            "oracle": self.oracle.as_dict(),
            "alternates": [item.as_dict() for item in self.alternates],
            "provenance": self.provenance.as_dict(),
            "unsupported_reason": self.unsupported_reason,
            "status": self.status,
            "executable": self.executable,
            "verified": False,
        }


# ---- detector -> family ---------------------------------------------------------------------

_FAMILY_BY_PREFIX: tuple[tuple[str, PropertyFamily], ...] = (
    ("aa.unprotected_account_initializer", PropertyFamily.INITIALIZATION),
    ("aa.", PropertyFamily.ERC4337),
    ("caller_context.swallowed_call_failure", PropertyFamily.MECHANISM),
    ("caller_context.unrestricted_dispatch_with_approval_authority", PropertyFamily.TOKEN_MOVEMENT),
    ("caller_context.trusted_intermediary_actor_parameter", PropertyFamily.AUTHORIZATION),
    ("caller_context.", PropertyFamily.ACCESS_CONTROL_HIERARCHY),
    ("accounting.donation_share_price", PropertyFamily.SOLVENCY),
    ("accounting.fee_on_transfer_mismatch", PropertyFamily.TOKEN_MOVEMENT),
    ("accounting.unchecked_token_return", PropertyFamily.TOKEN_MOVEMENT),
    ("accounting.", PropertyFamily.ACCOUNTING),
    ("message.replay_no_consumption", PropertyFamily.NONCE_REPLAY),
    ("message.nonce_not_in_digest", PropertyFamily.NONCE_REPLAY),
    ("message.missing_expiry", PropertyFamily.NONCE_REPLAY),
    ("message.", PropertyFamily.BRIDGE_MESSAGE_BINDING),
    ("oracle.", PropertyFamily.ORACLE_SAFETY),
    ("arithmetic.", PropertyFamily.ACCOUNTING),
    ("eip7702.", PropertyFamily.EIP7702),
    ("transient_storage.", PropertyFamily.TRANSIENT_STORAGE),
    ("read_only_reentrancy.", PropertyFamily.ACCOUNTING),
    ("proxy.", PropertyFamily.UPGRADE_SAFETY),
    ("upgrade.", PropertyFamily.UPGRADE_SAFETY),
    ("governance.", PropertyFamily.GOVERNANCE),
    ("bridge.", PropertyFamily.BRIDGE_MESSAGE_BINDING),
    ("v4_hooks.", PropertyFamily.ACCESS_CONTROL_HIERARCHY),
    ("profile.configured_asset", PropertyFamily.ACCOUNTING),
    ("conservation.", PropertyFamily.SOLVENCY),
)


def family_for(detector: str) -> PropertyFamily:
    for prefix, family in _FAMILY_BY_PREFIX:
        if detector.startswith(prefix):
            return family
    return PropertyFamily.AUTHORIZATION


_OWNER_WRITE = re.compile(r"\b(owner\w*|admin\w*|_owner\w*)\s*=(?!=)")
_STATE_WRITE = r"\b{name}\b\s*(?:\[[^\]]*\]\s*)*(?:=(?!=)|\+=|-=)"
_CREDIT_NAMES = ("balances", "balanceOf", "deposits", "shares", "credit", "credited")


def _resolve(model: ResearchModel, contract: str, signature: str) -> RFunction | None:
    for function in model.functions_of(contract):
        if function.signature == signature and function.has_body:
            return function
    return None


def public_getter(model: ResearchModel, contract: str, variable: str) -> str:
    """The getter signature of a public state variable, or "" when it has none."""
    for owner in model.lineage(contract):
        item = model.contracts.get(owner)
        if item is None:
            continue
        kind = dict(item.state_vars).get(variable)
        if kind is None:
            continue
        if not re.search(rf"\bpublic\b[^;{{}}]*\b{re.escape(variable)}\s*[;=]", item.body):
            return ""
        mapping = re.fullmatch(r"mapping\s*\(\s*(\w+)\s*=>\s*(\w+)\s*\)", kind.replace(" ", " "))
        if kind.startswith("mapping"):
            if mapping is None or mapping.group(1) != "address":
                return ""
            if not re.fullmatch(r"u?int\d*|bool|address", mapping.group(2)):
                return ""
            return f"{variable}(address)"
        if re.fullmatch(r"u?int\d*|bool|address|bytes\d+", kind) or model.contract_for_type(kind):
            return f"{variable}()"
        return ""
    return ""


def _written_public_state(
    model: ResearchModel, contract: str, function: RFunction
) -> tuple[str, str]:
    """A public, scalar state variable this function writes, with its getter."""
    for variable in sorted(model.state_vars(contract)):
        if re.search(_STATE_WRITE.format(name=re.escape(variable)), function.body):
            getter = public_getter(model, contract, variable)
            if getter.endswith("()"):
                return variable, getter
    return "", ""


def _credit_getter(model: ResearchModel, contract: str, function: RFunction) -> tuple[str, str]:
    """A reader of the amount this function credits, in the same unit as assets pulled.

    A public per-account mapping is the original reader. A view is accepted only
    when source structure shows it returns that credited slot. A converted share
    balance is not a credit reader: share units are not asset units.
    """
    for variable in sorted(model.state_vars(contract)):
        if not re.search(rf"\b{re.escape(variable)}\s*\[\s*msg\.sender\s*\]\s*\+=", function.body):
            continue
        getter = public_getter(model, contract, variable)
        if getter == f"{variable}(address)":
            return variable, getter
    for name in _CREDIT_NAMES:
        getter = public_getter(model, contract, name)
        if getter == f"{name}(address)":
            return name, getter
    info = share_accounting(model, function)
    reader = info.credit_reader
    if reader is None:
        return "", ""
    if info.share_unit == "converted_shares" and reader.kind == "share":
        return "", ""
    return reader.variable, reader.getter


def _exit_sizing(sequence: Vfcs) -> str:
    for call in sequence.calls:
        if call.role != "withdraw":
            continue
        for _name, value in call.arguments:
            if value == "share_balance":
                return "the attacker's share balance"
            if value.startswith("asset_exit:"):
                return f"{value.split(':', 1)[1]} in asset units"
            if value in {"all_shares", "actor_credit"}:
                return f"the share balance reported for the attacker ({value})"
    return "the sequence's withdrawal amount"


def _position_getter(model: ResearchModel, function: RFunction) -> tuple[str, str]:
    """The user's share balance, including a converted-share reader used only to size an exit."""
    variable, getter = _credit_getter(model, function.contract, function)
    if getter.endswith("(address)"):
        return variable, getter
    info = share_accounting(model, function)
    reader = info.share_reader
    if reader is None:
        return "", ""
    return reader.variable, reader.getter


def _span(function: RFunction) -> tuple[int, int]:
    return function.line, function.line + max(0, function.body.count("\n"))


def _property_id(sequence_key: str, family: PropertyFamily, oracle: OracleSpec) -> str:
    return "pr_" + digest(
        (sequence_key, family.value, oracle.kind.value, oracle.getter, oracle.probe_role)
    )


def _role_function(sequence: Vfcs, role: str) -> str:
    for call in sequence.calls:
        if call.role == role and not call.primitive:
            return call.function
    return ""


def build_property(
    sequence: Vfcs,
    model: ResearchModel,
    candidate: SemanticCandidate | None = None,
) -> PropertySpec:
    """The property a sequence tests, built from the candidate plus code evidence."""
    detector, _, target = sequence.derived_from.partition("@")
    contract, _, signature = target.partition(".")
    family = family_for(detector)
    function = _resolve(model, contract, signature)
    file = function.file if function else (candidate.file if candidate else "")
    start, end = _span(function) if function else ((candidate.line if candidate else 0),) * 2
    called = [call.function for call in sequence.calls if not call.primitive]
    if function is not None and function.signature not in called:
        called.insert(0, function.signature)
    functions = tuple(dict.fromkeys(called))
    builder = _ORACLE_BUILDERS.get(sequence.template)
    oracle: OracleSpec
    alternates: tuple[OracleSpec, ...]
    variables: tuple[str, ...]
    reason: str
    assumptions: tuple[str, ...]
    unsupported: str
    if function is None:
        oracle, alternates, variables, reason, assumptions, unsupported = (
            OracleSpec(),
            (),
            (),
            "the candidate function is not in the model",
            (),
            "candidate function unresolved",
        )
    elif builder is None:
        oracle, alternates, variables, reason, assumptions, unsupported = (
            OracleSpec(),
            (),
            (),
            f"no oracle is defined for template {sequence.template!r}",
            (),
            "",
        )
    else:
        oracle, alternates, variables, reason, assumptions, unsupported = builder(
            sequence, model, function, detector
        )
        oracle = _retarget_probe(sequence, function.signature, oracle)
        alternates = tuple(
            _retarget_probe(sequence, function.signature, item) for item in alternates
        )
    path_assumptions = tuple(sequence.call_path[:8]) + tuple(sequence.path_notes[:8])
    if path_assumptions:
        assumptions = (*assumptions, *path_assumptions)
    if oracle.kind is OracleKind.MECHANISM_PROBE and oracle.executable:
        declaration = PropertyDeclaration.MECHANISM_OBSERVATION
    elif oracle.executable:
        declaration = PropertyDeclaration.PROPERTY_UNDER_TEST
    elif unsupported:
        declaration = PropertyDeclaration.PROPERTY_UNSUPPORTED
    else:
        declaration = PropertyDeclaration.NO_PROPERTY_AVAILABLE
    provenance = PropertyProvenance(
        file=file,
        line_start=start,
        line_end=end,
        contract=contract,
        functions=functions,
        variables=tuple(variables),
        candidate=sequence.derived_from,
        reason=reason,
        assumptions=tuple(assumptions),
    )
    return PropertySpec(
        property_id=_property_id(sequence.derived_from, family, oracle),
        family=family,
        statement=sequence.property_under_test,
        declaration=declaration,
        oracle=oracle,
        provenance=provenance,
        unsupported_reason=unsupported,
        alternates=tuple(alternates),
    )


OracleBuilt = tuple[OracleSpec, tuple[OracleSpec, ...], tuple[str, ...], str, tuple[str, ...], str]


def _initializer(sequence: Vfcs, model: ResearchModel, fn: RFunction, det: str) -> OracleBuilt:
    primary = OracleSpec(
        kind=OracleKind.SECOND_CALL_MUST_FAIL,
        probe_role="reinitialize",
        probe_function=fn.signature,
        precondition_roles=("initialize",),
        expression=f"after a successful {fn.name}(), a second {fn.name}() must revert",
    )
    variables: tuple[str, ...] = ()
    alternates: list[OracleSpec] = []
    match = _OWNER_WRITE.search(fn.body)
    if match:
        variable = match.group(1)
        getter = public_getter(model, fn.contract, variable)
        if getter.endswith("()"):
            variables = (variable,)
            alternates.append(
                OracleSpec(
                    kind=OracleKind.STATE_UNCHANGED,
                    probe_role="reinitialize",
                    probe_function=fn.signature,
                    precondition_roles=("initialize",),
                    getter=getter,
                    expression=f"{getter} set by the first {fn.name}() must not change",
                    formulation="alternate",
                )
            )
    return (
        primary,
        tuple(alternates),
        variables,
        f"{fn.name} assigns the owner without a one-time guard (code evidence: owner write)",
        ("the first initialization is the legitimate one",),
        "",
    )


def _unauthenticated(sequence: Vfcs, model: ResearchModel, fn: RFunction, det: str) -> OracleBuilt:
    if det not in {
        "aa.unauthenticated_account_execution",
        "v4_hooks.callback_without_pool_manager_check",
        "bridge.receiver_without_endpoint_check",
    }:
        return (
            OracleSpec(),
            (),
            (),
            "validateUserOp takes a PackedUserOperation and needs an EntryPoint/userOp fixture",
            (),
            "ERC-4337 validation needs an EntryPoint and a signed user operation fixture",
        )
    return (
        OracleSpec(
            kind=OracleKind.CALL_MUST_FAIL,
            probe_role="execute",
            probe_function=fn.signature,
            expression=f"{fn.name}() called by an arbitrary attacker must revert",
        ),
        (),
        (),
        f"{fn.name} acts on caller-supplied input and has no caller authentication",
        (
            "the attacker is not the trusted caller (account owner/EntryPoint, PoolManager, "
            "or bridge endpoint)",
            "a revert for these fixture inputs holds the property only for these inputs",
        ),
        "",
    )


def _nested_dispatch(sequence: Vfcs, model: ResearchModel, fn: RFunction, det: str) -> OracleBuilt:
    nested = ""
    for call in sequence.calls:
        for _name, value in call.arguments:
            if value.startswith("nested_call:"):
                nested = value.split(":", 1)[1]
    callee_contract, _, callee_sig = nested.partition(".")
    callee = _resolve(model, callee_contract, callee_sig) if nested else None
    if callee is None:
        return (OracleSpec(), (), (), "the nested callee is not resolvable", (), "")
    variable, getter = _written_public_state(model, callee_contract, callee)
    if not getter:
        return (
            OracleSpec(),
            (),
            (),
            f"{callee.name} writes no public scalar state an oracle could observe",
            (),
            "no observable privileged state",
        )
    primary = OracleSpec(
        kind=OracleKind.STATE_UNCHANGED,
        probe_role="dispatch",
        probe_function=fn.signature,
        getter=getter,
        snapshot="before_probe",
        expression=(
            f"an attacker dispatching through {fn.name}() must not change {getter} "
            f"(written only by {callee.name})"
        ),
    )
    return (
        primary,
        (),
        (variable,),
        f"{fn.name} re-enters {callee.name}, which writes {variable} behind a caller check",
        ("the nested call is encoded by the attacker",),
        "",
    )


def _unsupported(reason: str, needs: str) -> Any:
    def build(sequence: Vfcs, model: ResearchModel, fn: RFunction, det: str) -> OracleBuilt:
        return (OracleSpec(), (), (), reason.format(name=fn.name), (), needs)

    return build


def _no_property(reason: str) -> Any:
    def build(sequence: Vfcs, model: ResearchModel, fn: RFunction, det: str) -> OracleBuilt:
        return (OracleSpec(), (), (), reason.format(name=fn.name), (), "")

    return build


def _share_inflation(sequence: Vfcs, model: ResearchModel, fn: RFunction, _det: str) -> OracleBuilt:
    """A donation must not let one depositor redeem another depositor's assets.

    The first deposit is one unit, the donation and the second deposit are one
    fixture unit each (1e18), and the redemption is the attacker's share balance.
    Ending above the starting token balance is an unauthorized gain. Receiving
    one's own donation back, or an ordinary share-price move that does not pay
    the attacker more than they put in, is not.
    """
    variable, getter = _position_getter(model, fn)
    withdraw = _role_function(sequence, "withdraw")
    if not getter:
        return (
            OracleSpec(),
            (),
            (),
            f"{fn.name} exposes no public per-account share or credit balance",
            (),
            "no readable share balance to size the redemption",
        )
    if not withdraw:
        return (OracleSpec(), (), (), "the sequence has no redemption", (), "")
    order = [call.role for call in sequence.calls]
    probe_at = order.index("withdraw")
    preconditions = tuple(dict.fromkeys(role for role in order[:probe_at]))
    sizing = _exit_sizing(sequence)
    classic = any(
        call.role == "deposit" and any(value == "unit_amount" for _name, value in call.arguments)
        for call in sequence.calls
    )
    expression: str
    assumptions: tuple[str, ...]
    statement: str
    if classic:
        expression = (
            "after a 1-unit deposit, a 1000000000000000000-unit donation by the attacker, "
            "a second depositor's 1000000000000000000-unit deposit, and redemption of the "
            f"share balance {getter} reports for the attacker, the sum of the attacker's "
            "fixture-token balance and the designated recipient balance must not exceed "
            "that sum before the first deposit. The donation and both deposits are part "
            "of the measured sequence"
        )
        assumptions = (
            "attacker deposit: 1",
            "donation: 1000000000000000000 fixture units transferred to the contract",
            "second depositor: 1000000000000000000 fixture units",
            f"redemption: {getter} of the attacker, read after both deposits and the donation",
            "a balance that cannot be read is not a held property",
        )
        statement = (
            f"{fn.name} prices new shares from the contract's token balance and {withdraw} redeems"
        )
    else:
        expression = (
            "after the attacker deposits, donates one fixture unit, and a second depositor "
            f"deposits, the exit is sized by {sizing}. Share position is read with {getter}. "
            "The sum of the attacker's fixture-token balance and the designated recipient "
            "balance must not exceed that sum before the first deposit. Share units are not "
            "compared with asset units. A zero position, a failed read, or a reverted setup "
            "is not a held property"
        )
        assumptions = (
            "attacker deposit through an exposed entry that pulls the fixture asset",
            "donation: 1000000000000000000 fixture units transferred to the contract",
            "second depositor: the same exposed deposit",
            f"exit amount: {sizing}",
            f"share reader: {getter}",
            "a balance that cannot be read is not a held property",
            "an empty position is not a held property",
        )
        statement = f"{fn.name} changes a share position and {withdraw} pays the underlying asset"
    oracle = OracleSpec(
        kind=OracleKind.BALANCE_NOT_INCREASED,
        probe_role="withdraw",
        probe_function=withdraw,
        precondition_roles=preconditions,
        getter=getter,
        getter_actor=ATTACKER,
        token_fixture="standard",
        snapshot="before_sequence",
        expression=expression,
    )
    return oracle, (), (variable,), statement, assumptions, ""


def _credit_oracle(sequence: Vfcs, model: ResearchModel, fn: RFunction, det: str) -> OracleBuilt:
    """Credited balance must not exceed what the contract actually received.

    Executable only when the contract exposes a public per-account credit mapping
    and the credit function takes the token as a parameter or the harness can
    attach a fixture token; otherwise the property is unsupported (Slice B adds
    the token fixture primitive that makes it executable).
    """
    variable, getter = _credit_getter(model, fn.contract, fn)
    info = share_accounting(model, fn)
    if not getter and info.share_unit == "converted_shares":
        return (
            OracleSpec(),
            (),
            (info.slot.field,) if info.slot is not None else (),
            f"{fn.name} mints converted shares; those units are not compared with tokens received",
            (
                "share units and underlying-asset units are kept separate",
                info.share_reader.basis if info.share_reader is not None else "no share reader",
            ),
            "converted share balance is not an asset-unit credit",
        )
    if not getter:
        return (
            OracleSpec(),
            (),
            (),
            f"{fn.name} credits no public per-account mapping an oracle could read",
            (),
            "no observable credited balance",
        )
    fixture = "fee_on_transfer" if det == "accounting.fee_on_transfer_mismatch" else "standard"
    if det == "accounting.unchecked_token_return":
        fixture = "false_return"
    primary = OracleSpec(
        kind=OracleKind.CREDIT_LE_RECEIVED,
        probe_role=_role_of(sequence, fn.signature),
        probe_function=fn.signature,
        getter=getter,
        getter_actor=ATTACKER,
        token_fixture=fixture,
        snapshot="before_probe",
        expression=(
            f"{getter} credited to the attacker must not exceed the tokens {fn.contract} "
            f"received ({fixture} fixture token)"
        ),
    )
    alternate = OracleSpec(
        kind=OracleKind.CREDIT_LE_HOLDINGS,
        probe_role=primary.probe_role,
        probe_function=fn.signature,
        getter=getter,
        getter_actor=ATTACKER,
        token_fixture=fixture,
        snapshot="before_probe",
        expression=(
            f"after the probe, {getter} for the attacker must not exceed the fixture tokens "
            f"{fn.contract} holds (solvency formulation)"
        ),
        formulation="alternate",
    )
    return (
        primary,
        (alternate,),
        (variable,),
        f"{fn.name} credits {variable} from the pulled asset amount",
        (
            "the fixture token is the asset the contract accounts for",
            "the credited expression is in asset units, not a converted share price",
            info.credit_reader.basis if info.credit_reader is not None else f"reader {getter}",
        ),
        "",
    )


def _round_trip(sequence: Vfcs, model: ResearchModel, fn: RFunction, det: str) -> OracleBuilt:
    """The attacker must not end a deposit/withdraw round trip with more tokens.

    The pair is re-derived from the model by the custody trace, so the credit slot,
    the token binding and the getter are the traced ones, never a name match. The
    withdrawal amount is the attacker's credit as the traced getter reports it when
    one exists, otherwise the deposited amount, and that choice is recorded.
    """
    probe_role = "withdraw_again" if _role_function(sequence, "withdraw_again") else "withdraw"
    payout = _role_function(sequence, probe_role)
    if not payout:
        return (OracleSpec(), (), (), "the sequence has no withdrawal", (), "")
    pair = custody_pair(model, fn.contract, fn.signature, payout)
    if pair is None:
        return (
            OracleSpec(),
            (),
            (),
            f"no traced custody pair links {fn.signature} and {payout}",
            (),
            "custody trace did not reproduce",
        )
    getter = pair.getter
    variable = pair.mapping
    roles = ("initialize", "deposit", "victim_deposit", "withdraw", "withdraw_again")
    order = [call.role for call in sequence.calls]
    probe_at = order.index(probe_role)
    preconditions = tuple(r for r in roles if r in order[:probe_at])
    credit = f"{variable}[{pair.keys}]" + (f".{pair.credit_field}" if pair.credit_field else "")
    amount = (
        f"the attacker withdraws the value {getter} reports for it ({pair.getter_basis})"
        if getter
        else "the attacker withdraws the amount it deposited (no traced getter reads the credit)"
    )
    payout_name = payout.split("(")[0]
    oracle = OracleSpec(
        kind=OracleKind.BALANCE_NOT_INCREASED,
        probe_role=probe_role,
        probe_function=payout,
        precondition_roles=preconditions,
        getter=getter,
        getter_actor=ATTACKER,
        token_fixture="standard",
        snapshot="before_sequence",
        expression=(
            f"after the sequence {' > '.join(order)}, the sum of the attacker's balance of "
            f"{pair.token_label} and the designated attacker-controlled recipient balance "
            f"must not exceed that sum before the first call to {fn.name}"
        ),
    )
    assumptions = [
        "one ordering: " + " > ".join(order),
        f"asset: {pair.token_label} bound by {pair.token_binding} ({pair.token_source or 'n/a'})",
        "account: the attacker wallet plus the designated recipient wallet; "
        f"credit {credit} is in the contract's own units, not assumed to be token units",
        amount,
        "no call advances block.timestamp or accrues interest, rewards or index growth, "
        "so a gain is not yield",
    ]
    if pair.initializer:
        assumptions.append(f"{pair.initializer} runs first: {pair.initializer_basis}")
    if pair.incomplete:
        assumptions.append("trace incomplete: " + "; ".join(pair.incomplete)[:300])
    return (
        oracle,
        (),
        (variable,),
        f"{fn.name} credits {credit} and {payout_name} pays {pair.token_label} back",
        tuple(assumptions),
        "",
    )


def _swallowed(sequence: Vfcs, model: ResearchModel, fn: RFunction, det: str) -> OracleBuilt:
    """Observe whether a reverting callee's failure is swallowed. Not a security invariant."""
    bound = any(call.primitive and call.function == "deploy_reverting()" for call in sequence.calls)
    probe = next((call for call in sequence.calls if call.role == "probe"), None)
    if not bound or probe is None:
        return (
            OracleSpec(),
            (),
            (),
            "no failing callee is bound to a caller-supplied address parameter",
            ("upstream reliance and impact are unknown",),
            "the call receiver is not a parameter the harness can replace",
        )
    return (
        OracleSpec(
            kind=OracleKind.MECHANISM_PROBE,
            probe_role="probe",
            probe_function=probe.function,
            precondition_roles=("failing_callee",),
            expression=(
                f"behavioral probe of {fn.name}(): whether a reverting callee's failure "
                "is swallowed. Outer success is not a security-property violation"
            ),
        ),
        (),
        (),
        f"{fn.name} stores a low-level call success flag and a failure path returns normally",
        (
            "the local callee reverts on every call",
            "outer success is a mechanism observation, not a bounty-eligible finding",
            "application-level impact and intentional design remain unproven",
        ),
        "",
    )


def _role_of(sequence: Vfcs, signature: str) -> str:
    """The role of the first call to ``signature``, wherever reordering moved it.

    A call whose ``entrypoint_for`` is the candidate stands in for that candidate.
    The role stays the one the template assigned to the helper.
    """
    for call in sequence.calls:
        if call.primitive:
            continue
        if call.function == signature or call.entrypoint_for == signature:
            return call.role
    return ""


def _retarget_probe(sequence: Vfcs, helper: str, oracle: OracleSpec) -> OracleSpec:
    """Point the oracle at the executed entry when the helper is not itself called.

    The helper stays the provenance of the property. An ambiguous stand-in is left
    unchanged so evaluation reports that the probe is not in the sequence.
    """
    if not helper or oracle.probe_function != helper:
        return oracle
    if any(
        not call.primitive and call.function == helper and call.role == oracle.probe_role
        for call in sequence.calls
    ):
        return oracle
    standins = [
        call
        for call in sequence.calls
        if not call.primitive
        and call.entrypoint_for == helper
        and (not oracle.probe_role or call.role == oracle.probe_role)
    ]
    if len(standins) != 1:
        return oracle
    return replace(oracle, probe_function=standins[0].function, probe_role=standins[0].role)


def _body_compact(body: str) -> str:
    text = re.sub(r"/\*.*?\*/", " ", body, flags=re.S)
    text = re.sub(r"//.*?$", " ", text, flags=re.M)
    return re.sub(r"\s+", "", text)


def _authorization_error(model: ResearchModel, fn: RFunction) -> tuple[str, str] | None:
    """``(Name, selector)`` for ``revert Name()`` when that error is declared.

    A string revert returns None. The caller then keeps the selector-less oracle.
    A custom-error revert whose declaration is missing also returns None; the
    property builder treats that as unsupported rather than as any revert.
    """
    compact = _body_compact(fn.body)
    match = re.search(r"revert([A-Z][A-Za-z0-9_]*)\(\)", compact)
    if match is None:
        return None
    name = match.group(1)
    declared = re.compile(rf"\berror\s+{re.escape(name)}\s*\(\s*\)\s*;")
    for contract in model.contracts.values():
        if declared.search(contract.body) or declared.search(contract.head):
            return name, function_selector(f"{name}()")
    return None


def _unauthorized_pause(
    sequence: Vfcs, model: ResearchModel, fn: RFunction, det: str
) -> OracleBuilt:
    """Unauthorized pause must revert for the source's reason and leave state unchanged.

    The check is read from the function body. A renamed template cannot claim
    this property when the source does not contain the authorization condition.
    When the body reverts a declared custom error, the oracle requires that
    selector and a successful authorized call that changes the same getter.
    """
    del sequence, det
    compact = _body_compact(fn.body)
    authorized = (
        "msg.sender!=governor&&msg.sender!=pauseGuardian" in compact
        or "msg.sender==governor||msg.sender==pauseGuardian" in compact
    )
    getter = next(
        (
            item
            for item in model.functions_of(fn.contract)
            if item.signature == "isSupplyPaused()" and item.has_body
        ),
        None,
    )
    if not authorized or getter is None:
        return (
            OracleSpec(),
            (),
            (),
            f"{fn.name} does not check governor and pauseGuardian against isSupplyPaused()",
            (),
            "the authorization check or isSupplyPaused() is not in this source",
        )
    named = _authorization_error(model, fn)
    if re.search(r"revert[A-Z]", compact) and named is None:
        return (
            OracleSpec(),
            (),
            (),
            f"{fn.name} reverts a custom error that is not declared in this source",
            (),
            "the authorization error is not declared in the modeled source",
        )
    selector = ""
    assumptions = [
        "the attacker is neither the configured governor nor the pause guardian",
        "a revert with an unchanged pause flag holds only for this local configuration",
    ]
    if named is not None:
        error_name, selector = named
        assumptions.append(
            f"the unauthorized caller reverts {error_name}() ({selector}), "
            "which is declared in this source"
        )
        assumptions.append(
            "the configured governor can call the same function and changes isSupplyPaused()"
        )
    return (
        OracleSpec(
            kind=OracleKind.CALL_MUST_FAIL,
            probe_role="execute",
            probe_function=fn.signature,
            getter="isSupplyPaused()",
            expression=(
                "an account that is neither governor nor pauseGuardian must not "
                "change the supply pause flag"
            ),
            revert_selector=selector,
            control_sender="address(0xC0FE)" if selector else "",
        ),
        (),
        ("pauseFlags",),
        f"{fn.name} reverts unless msg.sender is governor or pauseGuardian",
        tuple(assumptions),
        "",
    )


def _struct_layout(model: ResearchModel, struct_name: str) -> tuple[tuple[str, str], ...] | None:
    """Fields of one struct name. Differing declarations in the model are rejected."""
    from app.discovery.bounty.constructor_profile import parse_struct_fields

    found: list[tuple[tuple[str, str], ...]] = []
    for contract in model.contracts.values():
        for text in (contract.body, contract.head):
            fields = parse_struct_fields(text, struct_name)
            if fields:
                found.append(fields)
    if not found or any(item != found[0] for item in found):
        return None
    return found[0]


def _configured_asset(sequence: Vfcs, model: ResearchModel, fn: RFunction, det: str) -> OracleBuilt:
    """The asset address stored at construction is the address getAssetInfo returns."""
    del det
    fixture = ""
    for call in sequence.calls:
        if call.established_by.startswith("fixture:"):
            fixture = call.established_by.split(":", 1)[1]
    if not fixture or not fn.returns:
        return (
            OracleSpec(),
            (),
            (),
            f"{fn.name} has no configured asset fixture to compare",
            (),
            "the configured-asset oracle needs one return struct and one fixture",
        )
    short = fn.returns[0].type_name.split(".")[-1]
    fields = _struct_layout(model, short)
    if fields is None:
        return (
            OracleSpec(),
            (),
            (),
            f"{short} is not a single struct declaration in this source",
            (),
            "the return struct layout is missing or ambiguous",
        )
    index = next((i for i, (type_name, name) in enumerate(fields) if name == "asset"), None)
    if index is None or fields[index][0] != "address":
        return (
            OracleSpec(),
            (),
            (),
            f"{short} does not expose an address field named asset",
            (),
            "the asset field is not an address in the declared struct",
        )
    return (
        OracleSpec(
            kind=OracleKind.CONFIGURED_VALUE,
            probe_role=sequence.calls[0].role if sequence.calls else "read",
            probe_function=fn.signature,
            word_index=index,
            observed_fixture=fixture,
            expression=(
                f"{fn.signature} word {index} is the address of fixture {fixture} "
                "configured at construction"
            ),
        ),
        (),
        ("asset",),
        f"{fn.name} returns the collateral asset stored from the constructor configuration",
        (
            "the fixture token and price feed are local and report the decimals the constructor requires",
            "the comparison is the returned asset address, not a price or a liquidation",
            "a matching word holds only for this local configuration",
        ),
        "",
    )


_ORACLE_BUILDERS: dict[str, Any] = {
    "initialize→reinitialize": _initializer,
    "unauthenticated-execution": _unauthenticated,
    "AA validation→execution": _unauthenticated,
    "nested-dispatch": _nested_dispatch,
    "forwarded-actor": _unsupported(
        "{name} acts for a caller-named account; judging it needs that account funded",
        "needs a funded victim position in the callee (funding fixture)",
    ),
    "approve→transferFrom": _unsupported(
        "{name} forwards caller-chosen calldata; an unsupported allowance property is not "
        "evidence that the call is safe",
        "needs a fixture token, a victim approval, and nested transferFrom calldata "
        "before this template can be judged",
    ),
    "deposit→donate→withdraw": _share_inflation,
    "donate→credit": _credit_oracle,
    "deposit": _credit_oracle,
    "deposit→withdraw": _credit_oracle,
    "authorize→execute": _unsupported(
        "{name} consumes a signed authorization; leaving it unexecuted is not a held property",
        "needs a signer fixture that produces a valid authorization for this digest "
        "before replay, expiry, or field binding can be judged",
    ),
    "oracle update→valuation→borrow": _unsupported(
        "{name} reads an external price; judging it needs a controlled price source",
        "needs a controlled oracle/market fixture wired as the price source",
    ),
    "unauthorized-call": _unauthorized_pause,
    "configured-asset": _configured_asset,
    "boundary-batch": _no_property(
        "{name}'s totals are internal; no public observable distinguishes a wrap"
    ),
    "failing-callee→swallowed-call": _swallowed,
    "deposit→deposit→withdraw→withdraw": _round_trip,
    "initialize→deposit→deposit→withdraw": _round_trip,
}


# ---- evaluation -------------------------------------------------------------------------------


@dataclass(frozen=True)
class OracleObservation:
    """The structured observation a harness reported for one oracle (no text parsing)."""

    call_ok: tuple[int, ...]  # per call: 1 ok, 0 reverted, -1 not reached
    before: str = ""  # getter value before (hex word) or ""
    after: str = ""
    readable: bool = True
    received: int | None = None  # tokens the target received across the probe
    credited: int | None = None  # credit the getter added for the actor across the probe
    holdings_after: int | None = None  # tokens the target holds after the probe
    credit_after: int | None = None  # the actor's credit after the probe
    actor_before: int | None = None  # attacker fixture balance before the first call
    actor_after: int | None = None  # attacker fixture balance after the last call
    # A second attacker-controlled wallet. Missing means the economic sum was not read.
    recipient_before: int | None = None
    recipient_after: int | None = None
    revert_selector: str = ""  # 0x plus 8 hex digits, or ""
    revert_data_ok: bool = True
    control_ok: int = -1  # -1 not run, 0 reverted, 1 succeeded
    control_before: str = ""
    control_after: str = ""
    observed_word: str = ""
    fixture_word: str = ""
    # Supplementary readings by name (see EVIDENCE_SLOTS). They describe the run;
    # the verdict is still decided by the oracle's own measurement.
    evidence: tuple[tuple[str, int], ...] = ()


# K_EVIDENCE slot -> name. Credits are in the contract's own units.
EVIDENCE_SLOTS = (
    "holdings_before",
    "holdings_after",
    "victim_balance_before",
    "victim_balance_after",
    "attacker_credit_before",
    "attacker_credit_after",
    "victim_credit_before",
    "victim_credit_after",
    "attacker_withdrawal_amount",
    "attacker_repeat_withdrawal_amount",
)


@dataclass(frozen=True)
class PropertyEvaluation:
    verdict: PropertyVerdict
    reason: str
    probe_index: int = -1
    precondition_ok: bool = True
    evaluated: bool = False
    # "" | changed | failed | unchanged | not_run. Not a finding by itself.
    positive_control: str = ""
    evidence: tuple[tuple[str, int], ...] = ()

    def as_dict(self) -> dict[str, Any]:
        body: dict[str, Any] = {
            "verdict": self.verdict.value,
            "reason": self.reason,
            "probe_index": self.probe_index,
            "precondition_ok": self.precondition_ok,
            "evaluated": self.evaluated,
            "positive_control": self.positive_control,
            "verified": False,
        }
        if self.evidence:
            body["evidence"] = {name: str(value) for name, value in self.evidence}
        return body


def probe_index(sequence: Vfcs, oracle: OracleSpec) -> int:
    """The index of the probe call, bound by (role, function), or -1 when lost."""
    for index, call in enumerate(sequence.calls):
        if call.role == oracle.probe_role and call.function == oracle.probe_function:
            if not call.primitive:
                return index
    return -1


def precondition_indices(sequence: Vfcs, oracle: OracleSpec, probe: int) -> tuple[int, ...]:
    return tuple(
        index
        for index, call in enumerate(sequence.calls)
        if call.role in oracle.precondition_roles and index < probe
    )


def prior_payout_indices(sequence: Vfcs, oracle: OracleSpec, probe: int) -> tuple[int, ...]:
    """Earlier calls that pay the probe's function for the probe's actor.

    The ordinary payout is one of these calls. The probe is an additional
    payout only when one of them succeeded. A role named ``withdraw`` is not
    that evidence: the binding is the probe's ``(role, function)`` plus a
    prior call of the same function by the same actor.
    """
    if probe < 0 or probe >= len(sequence.calls):
        return ()
    probe_call = sequence.calls[probe]
    function = oracle.probe_function
    if probe_call.primitive or not function or probe_call.function != function:
        return ()
    return tuple(
        index
        for index, call in enumerate(sequence.calls)
        if index < probe
        and not call.primitive
        and call.function == function
        and call.actor == probe_call.actor
        and call.role != probe_call.role
    )


def evaluate(
    sequence: Vfcs, oracle: OracleSpec, observation: OracleObservation
) -> PropertyEvaluation:
    """Judge one oracle from a structured observation. Deterministic; nothing verified."""
    if not oracle.executable:
        return PropertyEvaluation(
            PropertyVerdict.EXECUTION_ONLY_OBSERVATION, "no executable oracle for this sequence"
        )
    probe = probe_index(sequence, oracle)
    if probe < 0 or probe >= len(observation.call_ok):
        return PropertyEvaluation(
            PropertyVerdict.NOT_EVALUATED, "the oracle's probe call is not in this sequence"
        )
    required = precondition_indices(sequence, oracle, probe)
    if any(
        role not in {sequence.calls[i].role for i in required} for role in oracle.precondition_roles
    ):
        return PropertyEvaluation(
            PropertyVerdict.NOT_EVALUATED,
            "a precondition call the oracle needs does not precede the probe",
            probe,
            False,
        )
    if any(observation.call_ok[i] != 1 for i in required):
        if oracle.kind is OracleKind.BALANCE_NOT_INCREASED and _ordinary_payout_failed(
            sequence, oracle, observation, probe
        ):
            return _payout_not_completed(probe)
        return PropertyEvaluation(
            PropertyVerdict.NOT_EVALUATED,
            "a precondition call reverted, so the property could not be judged",
            probe,
            False,
        )
    probe_ok = observation.call_ok[probe]
    if probe_ok not in {0, 1}:
        return PropertyEvaluation(
            PropertyVerdict.NOT_EVALUATED, "the probe call was not reached", probe
        )
    kind = oracle.kind
    if kind is OracleKind.MECHANISM_PROBE:
        if probe_ok == 1:
            return PropertyEvaluation(
                PropertyVerdict.MECHANISM_OBSERVED,
                (
                    f"the callee reverted and {oracle.probe_function} returned normally. "
                    "Application-level impact and intentional design remain unproven. "
                    "This is a mechanism observation, not a validated security-property violation."
                ),
                probe,
                True,
                True,
            )
        return PropertyEvaluation(
            PropertyVerdict.FAILURE_PROPAGATED,
            (
                "the outer call also reverted, so the swallowed-call mechanism was not "
                "reproduced. This is not a security-property result."
            ),
            probe,
            True,
            True,
        )
    if kind in {OracleKind.CALL_MUST_FAIL, OracleKind.SECOND_CALL_MUST_FAIL}:
        if oracle.getter:
            if not observation.readable or not observation.before or not observation.after:
                return PropertyEvaluation(
                    PropertyVerdict.NOT_EVALUATED,
                    f"{oracle.getter} could not be read, so the probe result is not a verdict",
                    probe,
                )
            if observation.before != observation.after:
                return PropertyEvaluation(
                    PropertyVerdict.PROPERTY_VIOLATED,
                    f"{oracle.getter} changed across the probe ({observation.before} -> "
                    f"{observation.after})",
                    probe,
                    True,
                    True,
                )
        if oracle.revert_selector or oracle.control_sender:
            return _authorization_verdict(oracle, observation, probe, probe_ok)
        if probe_ok == 1:
            return PropertyEvaluation(
                PropertyVerdict.PROPERTY_VIOLATED,
                f"the probe call {oracle.probe_function} succeeded: {oracle.expression}",
                probe,
                True,
                True,
            )
        return PropertyEvaluation(
            PropertyVerdict.PROPERTY_HELD, "the probe call reverted as required", probe, True, True
        )
    if kind is OracleKind.STATE_EQUALS:
        return _state_equals_verdict(oracle, observation, probe, probe_ok)
    if kind is OracleKind.CONFIGURED_VALUE:
        return _configured_verdict(oracle, observation, probe, probe_ok)
    if kind is OracleKind.STATE_UNCHANGED:
        if not observation.readable or not observation.before or not observation.after:
            return PropertyEvaluation(
                PropertyVerdict.NOT_EVALUATED, f"{oracle.getter} could not be read", probe
            )
        if observation.before != observation.after:
            return PropertyEvaluation(
                PropertyVerdict.PROPERTY_VIOLATED,
                f"{oracle.getter} changed across the probe ({observation.before} -> "
                f"{observation.after})",
                probe,
                True,
                True,
            )
        return PropertyEvaluation(
            PropertyVerdict.PROPERTY_HELD, f"{oracle.getter} did not change", probe, True, True
        )
    if kind is OracleKind.BALANCE_NOT_INCREASED:
        return _conservation_verdict(sequence, oracle, observation, probe, probe_ok)
    if kind is OracleKind.CREDIT_LE_RECEIVED:
        if not observation.readable or observation.credited is None or observation.received is None:
            return PropertyEvaluation(
                PropertyVerdict.NOT_EVALUATED, "credit or receipt could not be read", probe
            )
        if probe_ok != 1:
            return PropertyEvaluation(
                PropertyVerdict.NOT_EVALUATED, "the credit call reverted; nothing credited", probe
            )
        if observation.credited > observation.received:
            return PropertyEvaluation(
                PropertyVerdict.PROPERTY_VIOLATED,
                f"credited {observation.credited} exceeds received {observation.received}",
                probe,
                True,
                True,
            )
        return PropertyEvaluation(
            PropertyVerdict.PROPERTY_HELD,
            f"credited {observation.credited} <= received {observation.received}",
            probe,
            True,
            True,
        )
    if kind is OracleKind.CREDIT_LE_HOLDINGS:
        if (
            not observation.readable
            or observation.credit_after is None
            or observation.holdings_after is None
        ):
            return PropertyEvaluation(
                PropertyVerdict.NOT_EVALUATED, "credit or holdings could not be read", probe
            )
        if probe_ok != 1:
            return PropertyEvaluation(
                PropertyVerdict.NOT_EVALUATED, "the credit call reverted; nothing credited", probe
            )
        if observation.credit_after > observation.holdings_after:
            return PropertyEvaluation(
                PropertyVerdict.PROPERTY_VIOLATED,
                f"credit {observation.credit_after} exceeds holdings {observation.holdings_after}",
                probe,
                True,
                True,
            )
        return PropertyEvaluation(
            PropertyVerdict.PROPERTY_HELD,
            f"credit {observation.credit_after} <= holdings {observation.holdings_after}",
            probe,
            True,
            True,
        )
    return PropertyEvaluation(PropertyVerdict.NOT_EVALUATED, f"unknown oracle {kind.value}")


def _unfunded_exit(sequence: Vfcs, observation: OracleObservation) -> bool:
    """True when a sized exit observed an empty position. That is not a held property."""
    sized = any(
        value == "share_balance" or value.startswith("asset_exit:")
        for call in sequence.calls
        for _name, value in call.arguments
    )
    if not sized:
        return False
    evidence = dict(observation.evidence)
    amount = evidence.get("attacker_withdrawal_amount")
    return amount is None or amount == 0


def _ordinary_payout_failed(
    sequence: Vfcs, oracle: OracleSpec, observation: OracleObservation, probe: int
) -> bool:
    """True when an earlier payout of the probe's function did not succeed.

    A failed deposit is not this case. Only a payout that the sequence placed
    before the probe, and that itself did not succeed, is the ordinary payout
    the round trip needed.
    """
    payouts = prior_payout_indices(sequence, oracle, probe)
    if not payouts or any(
        observation.call_ok[i] != 1
        for i in precondition_indices(sequence, oracle, probe)
        if i not in payouts and i < min(payouts)
    ):
        return False
    return any(observation.call_ok[i] != 1 for i in payouts)


def _payout_not_completed(probe: int) -> PropertyEvaluation:
    return PropertyEvaluation(
        PropertyVerdict.NOT_EVALUATED,
        "the intended withdrawal did not succeed, so the round trip did not complete. "
        "This test does not establish normal withdrawal behavior",
        probe,
        False,
    )


def _conservation_verdict(
    sequence: Vfcs,
    oracle: OracleSpec,
    observation: OracleObservation,
    probe: int,
    probe_ok: int,
) -> PropertyEvaluation:
    """Attacker-controlled fixture balances over the whole sequence.

    A reverted probe is a refused additional payout only when an earlier call of
    the same function, by the same actor, succeeded. Otherwise the probe is the
    ordinary payout, and its revert means the round trip was not exercised.
    """
    if _unfunded_exit(sequence, observation):
        return PropertyEvaluation(
            PropertyVerdict.NOT_EVALUATED,
            "the exit amount read from the source-backed position was zero, so the "
            "payout was not exercised",
            probe,
            False,
        )
    wallet_before, wallet_after = observation.actor_before, observation.actor_after
    recipient_before, recipient_after = observation.recipient_before, observation.recipient_after
    evidence = observation.evidence
    payouts = prior_payout_indices(sequence, oracle, probe)
    ordinary_done = bool(payouts) and all(observation.call_ok[i] == 1 for i in payouts)
    if not ordinary_done and probe_ok != 1:
        return _payout_not_completed(probe)
    missing = []
    if not observation.readable or wallet_before is None or wallet_after is None:
        missing.append("the attacker's fixture balance")
    if recipient_before is None or recipient_after is None:
        missing.append("the designated recipient balance")
    if missing or wallet_before is None or wallet_after is None:
        return PropertyEvaluation(
            PropertyVerdict.NOT_EVALUATED,
            f"{' and '.join(missing) or 'a required balance'} could not be read, "
            "so nothing was judged",
            probe,
            evidence=evidence,
        )
    if recipient_before is None or recipient_after is None:
        return PropertyEvaluation(
            PropertyVerdict.NOT_EVALUATED,
            "the designated recipient balance could not be read, so nothing was judged",
            probe,
            evidence=evidence,
        )
    before = wallet_before + recipient_before
    after = wallet_after + recipient_after
    evidence = evidence + (
        ("attacker_balance_before", wallet_before),
        ("attacker_balance_after", wallet_after),
        ("recipient_balance_before", recipient_before),
        ("recipient_balance_after", recipient_after),
    )
    wallets = (
        f"attacker wallet {wallet_before} -> {wallet_after}, designated recipient "
        f"{recipient_before} -> {recipient_after}"
    )
    if ordinary_done and probe_ok != 1:
        outcome = (
            f"; an earlier {oracle.probe_function} by the same actor succeeded, and the "
            "additional payout reverted"
        )
    elif ordinary_done:
        outcome = f"; the additional {oracle.probe_function} succeeded"
    else:
        outcome = ""
    readings = _evidence_text(evidence)
    if after > before:
        return PropertyEvaluation(
            PropertyVerdict.PROPERTY_VIOLATED,
            (
                f"attacker-controlled fixture balances rose from {before} to {after} "
                f"(+{after - before}; {wallets}) across the sequence while another "
                f"depositor's funds were in custody{outcome}. {readings}"
                f"{_payout_source(evidence, after - before)}"
            ),
            probe,
            True,
            True,
            evidence=evidence,
        )
    return PropertyEvaluation(
        PropertyVerdict.PROPERTY_HELD,
        (
            f"attacker-controlled fixture balances went from {before} to {after} "
            f"(-{before - after}; {wallets}){outcome}. {readings}This holds for this one "
            "ordering, amount, and fixture token only"
        ),
        probe,
        True,
        True,
        evidence=evidence,
    )


def _evidence_text(evidence: tuple[tuple[str, int], ...]) -> str:
    seen = dict(evidence)
    parts = []
    for label, stem in (
        ("contract holdings", "holdings"),
        ("victim token balance", "victim_balance"),
        ("attacker credit (contract units)", "attacker_credit"),
        ("victim credit (contract units)", "victim_credit"),
    ):
        first, last = seen.get(f"{stem}_before"), seen.get(f"{stem}_after")
        if first is not None and last is not None:
            parts.append(f"{label} {first} -> {last}")
    for label, name in (
        ("attacker withdrawal amount", "attacker_withdrawal_amount"),
        ("repeat withdrawal amount", "attacker_repeat_withdrawal_amount"),
    ):
        if name in seen:
            parts.append(f"{label} {seen[name]}")
    return ("Readings: " + "; ".join(parts) + ". ") if parts else ""


def _payout_source(evidence: tuple[tuple[str, int], ...], gain: int) -> str:
    """Where the excess came from, only as far as the readings show. Never a loss claim."""
    seen = dict(evidence)
    first, last = seen.get("holdings_before"), seen.get("holdings_after")
    if first is None or last is None:
        return "The payout source was not read. Victim loss is not established by this test."
    return (
        f"The excess {gain} was paid from the contract's holdings, which hold {last} after the "
        f"sequence against {first} before. Victim loss is not established by this test: the "
        "victim did not attempt a withdrawal"
    )


def _selector_word(value: str) -> bool:
    return bool(re.fullmatch(r"0x[0-9a-fA-F]{8}", value))


def _authorization_verdict(
    oracle: OracleSpec, observation: OracleObservation, probe: int, probe_ok: int
) -> PropertyEvaluation:
    """Authorization holds only for the expected error after a real control change.

    A selector-less CALL_MUST_FAIL does not use this path, so an arbitrary revert
    elsewhere in BugForge is not turned into an authorization verdict.
    """
    control = "not_run"
    if oracle.control_sender:
        if observation.control_ok != 1:
            return PropertyEvaluation(
                PropertyVerdict.NOT_EVALUATED,
                "the authorized positive control did not succeed",
                probe,
                True,
                False,
                "failed",
            )
        if not observation.control_before or not observation.control_after:
            return PropertyEvaluation(
                PropertyVerdict.NOT_EVALUATED,
                "the authorized positive control could not read state",
                probe,
                True,
                False,
                "failed",
            )
        if observation.control_before == observation.control_after:
            return PropertyEvaluation(
                PropertyVerdict.NOT_EVALUATED,
                "the authorized call did not change the observed state",
                probe,
                True,
                False,
                "unchanged",
            )
        control = "changed"
    if not oracle.getter:
        return PropertyEvaluation(
            PropertyVerdict.NOT_EVALUATED,
            "the authorization oracle has no state getter",
            probe,
            True,
            False,
            control,
        )
    if probe_ok == 1:
        return PropertyEvaluation(
            PropertyVerdict.PROPERTY_VIOLATED,
            f"the probe call {oracle.probe_function} succeeded: {oracle.expression}",
            probe,
            True,
            True,
            control,
        )
    if (
        not observation.revert_data_ok
        or not _selector_word(observation.revert_selector)
        or not _selector_word(oracle.revert_selector)
        or observation.revert_selector.lower() != oracle.revert_selector.lower()
    ):
        return PropertyEvaluation(
            PropertyVerdict.NOT_EVALUATED,
            "the revert data was missing, truncated, or not the expected authorization error",
            probe,
            True,
            False,
            control,
        )
    if control == "changed":
        control_text = "after the authorized positive control changed it"
    else:
        control_text = "no positive control was part of this test"
    return PropertyEvaluation(
        PropertyVerdict.PROPERTY_HELD,
        "the probe call reverted with the expected authorization error "
        f"{oracle.revert_selector} and the observed state stayed unchanged; {control_text}",
        probe,
        True,
        True,
        control,
    )


def _decimal(text: str) -> int | None:
    if not re.fullmatch(r"[0-9]{1,78}", text or ""):
        return None
    return int(text)


def _word(text: str) -> int | None:
    if not re.fullmatch(r"0x[0-9a-fA-F]{1,64}", text or ""):
        return None
    return int(text, 16)


def _payout_relation(observation: OracleObservation) -> PropertyEvaluation | None:
    """None when the caller's gain matches the owner's credit and the contract's tokens.

    A missing reading is not evaluated. A mismatch is a counterexample. A call that
    moves nothing did not establish the payout.
    """
    seen = dict(observation.evidence)
    needed = (
        "holdings_before",
        "holdings_after",
        "victim_balance_before",
        "victim_balance_after",
        "victim_credit_before",
        "victim_credit_after",
    )
    if (
        observation.actor_before is None
        or observation.actor_after is None
        or any(name not in seen for name in needed)
    ):
        return PropertyEvaluation(
            PropertyVerdict.NOT_EVALUATED,
            "the payout balances were not read, so the transfer was not judged",
        )
    gained = observation.actor_after - observation.actor_before
    holdings = seen["holdings_before"] - seen["holdings_after"]
    credit = seen["victim_credit_before"] - seen["victim_credit_after"]
    wallet = seen["victim_balance_after"] - seen["victim_balance_before"]
    if gained == 0 and holdings == 0 and credit == 0 and wallet == 0:
        return PropertyEvaluation(
            PropertyVerdict.NOT_EVALUATED,
            "the payout did not move value, so the authorized transfer was not established",
        )
    if gained != credit or holdings != credit or wallet != 0 or gained <= 0:
        return PropertyEvaluation(
            PropertyVerdict.PROPERTY_VIOLATED,
            f"the caller gained {gained}, the owner credit changed by {credit}, "
            f"holdings changed by {holdings}, and the owner wallet changed by {wallet}",
            evaluated=True,
            evidence=observation.evidence,
        )
    return None


def _state_equals_verdict(
    oracle: OracleSpec, observation: OracleObservation, probe: int, probe_ok: int
) -> PropertyEvaluation:
    """A successful call established the expected getter value, or it did not."""
    if probe_ok != 1:
        return PropertyEvaluation(
            PropertyVerdict.NOT_EVALUATED,
            "the call that should establish the state reverted, so the property was not established",
            probe,
        )
    if (
        not oracle.getter
        or not observation.readable
        or not observation.before
        or not observation.after
    ):
        return PropertyEvaluation(
            PropertyVerdict.NOT_EVALUATED,
            "the state getter could not be read",
            probe,
        )
    expected_after = _decimal(oracle.expected_after)
    before = _word(observation.before)
    after = _word(observation.after)
    if expected_after is None or before is None or after is None:
        return PropertyEvaluation(
            PropertyVerdict.NOT_EVALUATED,
            "the state oracle has no readable expected value",
            probe,
        )
    if oracle.expected_before:
        expected_before = _decimal(oracle.expected_before)
        if expected_before is None:
            return PropertyEvaluation(
                PropertyVerdict.NOT_EVALUATED,
                "the expected starting state is not an integer",
                probe,
            )
        if before != expected_before:
            return PropertyEvaluation(
                PropertyVerdict.NOT_EVALUATED,
                f"{oracle.getter} started at {before}, not {expected_before}, so the "
                "transition was not established",
                probe,
            )
    if oracle.balance_relation == "payout_matches_credit":
        payout = _payout_relation(observation)
        if payout is not None:
            return PropertyEvaluation(
                payout.verdict,
                payout.reason,
                probe,
                payout.precondition_ok,
                payout.evaluated,
                evidence=observation.evidence,
            )
    elif oracle.balance_relation:
        return PropertyEvaluation(
            PropertyVerdict.NOT_EVALUATED,
            "the balance relation is not supported",
            probe,
        )
    evidence = observation.evidence
    if after != expected_after:
        return PropertyEvaluation(
            PropertyVerdict.PROPERTY_VIOLATED,
            f"{oracle.getter} ended at {after}, not {expected_after}",
            probe,
            True,
            True,
            evidence=evidence,
        )
    return PropertyEvaluation(
        PropertyVerdict.PROPERTY_HELD,
        f"{oracle.getter} is {expected_after} after the call",
        probe,
        True,
        True,
        evidence=evidence,
    )


def _configured_verdict(
    oracle: OracleSpec, observation: OracleObservation, probe: int, probe_ok: int
) -> PropertyEvaluation:
    if probe_ok != 1 or oracle.word_index < 0:
        return PropertyEvaluation(
            PropertyVerdict.NOT_EVALUATED,
            "the configured-value read did not return data",
            probe,
        )
    if not observation.observed_word or not observation.fixture_word:
        return PropertyEvaluation(
            PropertyVerdict.NOT_EVALUATED,
            "the returned word or the fixture address was not observed",
            probe,
        )
    if observation.observed_word.lower() != observation.fixture_word.lower():
        return PropertyEvaluation(
            PropertyVerdict.PROPERTY_VIOLATED,
            f"word {oracle.word_index} was {observation.observed_word}, not the configured "
            f"fixture {observation.fixture_word}",
            probe,
            True,
            True,
        )
    return PropertyEvaluation(
        PropertyVerdict.PROPERTY_HELD,
        f"word {oracle.word_index} is the configured fixture address {observation.fixture_word}",
        probe,
        True,
        True,
    )


def property_index(specs: list[PropertySpec]) -> dict[str, Any]:
    """Counts by declaration and family (for coverage reporting)."""
    by_declaration: dict[str, int] = {}
    by_family: dict[str, int] = {}
    for spec in specs:
        by_declaration[spec.declaration.value] = by_declaration.get(spec.declaration.value, 0) + 1
        by_family[spec.family.value] = by_family.get(spec.family.value, 0) + 1
    return {"by_declaration": by_declaration, "by_family": by_family, "total": len(specs)}


__all__ = [
    "EXECUTABLE_ORACLES",
    "OracleKind",
    "OracleObservation",
    "OracleSpec",
    "PropertyDeclaration",
    "PropertyEvaluation",
    "PropertyFamily",
    "PropertyProvenance",
    "PropertySpec",
    "PropertyVerdict",
    "build_property",
    "evaluate",
    "family_for",
    "probe_index",
    "property_index",
    "public_getter",
]
