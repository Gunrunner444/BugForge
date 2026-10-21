"""Vulnerable Function Call Sequences, feedback-directed mutation, and minimization.

A VFCS is a short plan that is derived from a static candidate and built only from
functions that exist in the analyzed sources. Where an environment primitive is
unavoidable (a donation, an approval, a clock change) it is marked as a primitive
together with what established that it applies. Nothing here runs a transaction,
so a VFCS is never a finding, a counterexample, or a reproduction, and mutation and
minimization never produce verification.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass, field, replace

from app.discovery.bounty.entrypoints import (
    entrypoints_for,
    forwarded_entry_params,
    path_lines,
)
from app.discovery.bounty.shares import ShareAccounting, position_entry, share_accounting
from app.discovery.orchestration.codec import digest
from app.discovery.sequences import MAX_MUTATIONS as _EXISTING_MUTATIONS
from app.discovery.sequences import MAX_SEQUENCE_LENGTH as _EXISTING_LENGTH
from app.parsing.solidity_accounting import reported_site
from app.parsing.solidity_research import (
    ResearchModel,
    RFunction,
    SemanticCandidate,
    model_source_problems,
)

MAX_VFCS_LENGTH = _EXISTING_LENGTH
MAX_VFCS_CANDIDATES = 16
MAX_MUTATIONS = _EXISTING_MUTATIONS
MAX_MINIMIZATION_ATTEMPTS = 24
MAX_FEEDBACK_SIGNALS = 16

ATTACKER = "attacker"
VICTIM = "victim"
ATTACKER_CONTROLLED = "attacker_controlled"
UNCONSTRAINED = "unconstrained"
_BOUNDARY_VALUES = ("zero", "one", "max_uint", "contract_balance", "total_supply")
# A value property that held at the fixture amount is retried where rounding
# remainders are largest relative to the amount.
_SMALL_AMOUNTS = ("one", "two", "three")


@dataclass(frozen=True)
class SequenceIdentity:
    """What the sequence is bound to. A sequence cannot be replayed against anything else."""

    campaign_id: str = ""
    source_snapshot: str = ""
    compiler_configuration: str = ""
    fork_reference: str = ""
    program_context: str = ""
    # chain:address of the deployment the sequence targets ("" = source only).
    deployment: str = ""
    # path -> sha256 of the source set the calls were built from. Empty means the
    # sequence has no content identity; execution must refuse it. Not part of the
    # sequence id, so existing ids stay stable.
    source_hashes: tuple[tuple[str, str], ...] = ()
    implementation: str = ""


@dataclass(frozen=True)
class VfcsCall:
    contract: str
    function: str
    role: str
    actor: str
    arguments: tuple[tuple[str, str], ...] = ()
    primitive: bool = False
    established_by: str = ""
    # Signature of the semantic candidate this call stands in for. Empty when the
    # call is the candidate itself or an unrelated step.
    entrypoint_for: str = ""

    @property
    def identity(self) -> str:
        return f"{self.contract}.{self.function}"


@dataclass(frozen=True)
class Vfcs:
    sequence_id: str
    template: str
    origin: str
    calls: tuple[VfcsCall, ...]
    property_under_test: str
    derived_from: str
    identity: SequenceIdentity
    status: str = "candidate"
    verified: bool = False
    # Exposed call path that reaches the candidate. Empty when the candidate is
    # itself the call, or when no path was established.
    call_path: tuple[str, ...] = ()
    path_notes: tuple[str, ...] = ()
    # Contract the harness deploys when it is not the candidate's contract.
    # Empty keeps the candidate contract, so existing sequences are unchanged.
    execution_contract: str = ""


@dataclass(frozen=True)
class VfcsResult:
    sequences: tuple[Vfcs, ...]
    skipped: tuple[tuple[str, str], ...]
    truncated: bool


@dataclass(frozen=True)
class FeedbackSignal:
    """What a run learned. Only these kinds steer mutation."""

    kind: str  # coverage_gain | symbolic_counterexample | near_miss | contradiction |
    # caller_context_mismatch | oracle_mismatch
    sequence_id: str
    call_index: int = -1
    values: tuple[tuple[str, str], ...] = ()
    engine: str = ""  # the fuzzer that produced the signal (foundry/echidna/medusa/ityfuzz)
    call_instance: str = ""  # stable call-instance id, resolved to call_index when given


def source_hashes_of(sources: Mapping[str, str]) -> tuple[tuple[str, str], ...]:
    """sha256 of each source file. This is content identity, not a snapshot label."""
    return tuple(
        sorted(
            (path, hashlib.sha256(text.encode("utf-8")).hexdigest())
            for path, text in sources.items()
        )
    )


def stamp_source_identity(sequence: Vfcs, sources: Mapping[str, str]) -> Vfcs:
    """Bind a sequence to source text. The caller supplies the text it claims, not the executor."""
    return replace(
        sequence, identity=replace(sequence.identity, source_hashes=source_hashes_of(sources))
    )


def sequence_id_of(
    calls: Iterable[VfcsCall],
    template: str,
    identity: SequenceIdentity,
    *,
    derived_from: str = "",
) -> str:
    """Identity of one hypothesis, not of an in-memory object.

    ``derived_from`` is the candidate key. ``entrypoint_for`` is the helper a
    promoted call stands in for. Two helpers that reach the same exposed call
    therefore stay distinct. ``call_path`` and ``path_notes`` are omitted, so
    equivalent executions of one candidate still deduplicate. Content hashes and
    the implementation address stay out of the id. A deployment still is.
    """
    bound: dict[str, str] = {
        "campaign_id": identity.campaign_id,
        "source_snapshot": identity.source_snapshot,
        "compiler_configuration": identity.compiler_configuration,
        "fork_reference": identity.fork_reference,
        "program_context": identity.program_context,
    }
    if identity.deployment:
        bound["deployment"] = identity.deployment
    rows = [
        (c.contract, c.function, c.role, c.actor, c.arguments, c.primitive, c.entrypoint_for)
        for c in calls
    ]
    return "vf_" + digest((rows, template, bound, derived_from))


# ---- generation -----------------------------------------------------------------------------


def _candidate_key(
    candidate: SemanticCandidate, lines: Mapping[tuple[str, str, str], set[int]]
) -> str:
    """``detector@contract.function``, plus ``#line`` when that triple has two locations.

    ``cap()`` already keeps both source locations. Collapsing them onto one key made
    ``candidate_for`` and ``execution_summary`` attach one location's result to the other.
    The same candidate supplied twice is still one location, so its key does not change.
    """
    base = f"{candidate.detector}@{candidate.contract}.{candidate.function}"
    ident = (candidate.detector, candidate.contract, candidate.function)
    if len(lines.get(ident, ())) > 1:
        return f"{base}#{candidate.line}"
    return base


def generate(
    model: ResearchModel,
    candidates: Iterable[SemanticCandidate],
    identity: SequenceIdentity = SequenceIdentity(),
    *,
    limit: int = MAX_VFCS_CANDIDATES,
    sources: Mapping[str, str] | None = None,
) -> VfcsResult:
    """Build sequences. ``sources`` records the content identity those sequences may execute against.

    When ``sources`` is supplied it must be the text the model was parsed from.
    A mismatch does not restamp the model or the plan against the new text.
    """
    limit = max(0, min(limit, MAX_VFCS_CANDIDATES))
    found: dict[str, Vfcs] = {}
    skipped: list[tuple[str, str]] = []
    truncated = False
    material = list(candidates)
    lines: dict[tuple[str, str, str], set[int]] = {}
    for candidate in material:
        ident = (candidate.detector, candidate.contract, candidate.function)
        lines.setdefault(ident, set()).add(candidate.line)
    if sources is not None:
        problems = model_source_problems(model, sources)
        if problems:
            reason = "model source attestation does not match the supplied sources: " + problems[0]
            for candidate in material:
                skipped.append((_candidate_key(candidate, lines), reason))
            return VfcsResult((), tuple(skipped), False)
        identity = replace(identity, source_hashes=source_hashes_of(sources))
    for candidate in material:
        key = _candidate_key(candidate, lines)
        if len(found) >= limit:
            truncated = True
            skipped.append((key, "the sequence limit was reached"))
            continue
        builder = _BUILDERS.get(candidate.detector)
        if builder is None:
            skipped.append((key, "no sequence template applies to this detector"))
            continue
        built = builder(model, candidate)
        plans: list[tuple[str, list[VfcsCall], str]]
        if isinstance(built, str):
            skipped.append((key, built))
            continue
        if isinstance(built, list):
            if not built:
                skipped.append((key, "the candidate produced no sequence"))
                continue
            plans = built
        else:
            plans = [built]
        for template, calls, prop in plans:
            if len(found) >= limit:
                truncated = True
                skipped.append((key, "the sequence limit was reached"))
                continue
            if not calls or len(calls) > MAX_VFCS_LENGTH:
                skipped.append((key, "the sequence would exceed the length limit"))
                continue
            for promoted in _promote(model, candidate, calls):
                if len(found) >= limit:
                    truncated = True
                    skipped.append((key, "the sequence limit was reached"))
                    break
                promoted_calls, call_path, path_notes, execution_contract = promoted
                if not promoted_calls or len(promoted_calls) > MAX_VFCS_LENGTH:
                    skipped.append((key, "the sequence would exceed the length limit"))
                    continue
                if any(
                    value == "asset_exit:unsupported"
                    for call in promoted_calls
                    for _n, value in call.arguments
                ):
                    skipped.append(
                        (
                            key,
                            "the exit amount is in asset units and no source-backed "
                            "conversion or limit was resolved",
                        )
                    )
                    continue
                sequence = Vfcs(
                    sequence_id=sequence_id_of(
                        promoted_calls, template, identity, derived_from=key
                    ),
                    template=template,
                    origin=f"template:{template}",
                    calls=tuple(promoted_calls),
                    property_under_test=prop,
                    derived_from=key,
                    identity=identity,
                    call_path=call_path,
                    path_notes=path_notes,
                    execution_contract=execution_contract,
                )
                if sequence.sequence_id in found:
                    skipped.append(
                        (key, "deduplicated: an equivalent sequence was already generated")
                    )
                    continue
                found[sequence.sequence_id] = sequence
    return VfcsResult(tuple(found.values()), tuple(skipped), truncated)


Plan = tuple[str, list[VfcsCall], str]
Built = Plan | list[Plan] | str
Builder = Callable[[ResearchModel, SemanticCandidate], Built]
_VariantIter = Iterator[tuple[str, list[VfcsCall]]]


def _resolve(model: ResearchModel, contract: str, signature: str) -> RFunction | None:
    for function in model.functions_of(contract):
        if function.signature == signature and function.has_body:
            return function
    return None


def _promote(
    model: ResearchModel, candidate: SemanticCandidate, calls: list[VfcsCall]
) -> tuple[tuple[tuple[VfcsCall, ...], tuple[str, ...], tuple[str, ...], str], ...]:
    """Rewrite candidate calls onto each exposed entry that source structure reaches.

    The candidate identity stays on the sequence. A helper with no established
    entry is left as the original call and the gap is recorded on the sequence.
    An already ABI-callable exposed function is not rewritten.
    """
    function = _resolve(model, candidate.contract, candidate.function)
    aimed = [
        call
        for call in calls
        if not call.primitive
        and call.contract == candidate.contract
        and call.function == candidate.function
    ]
    if function is None or not aimed:
        return ((tuple(calls), (), (), ""),)
    found = entrypoints_for(model, function)
    if found.directly_executable:
        return ((tuple(calls), (), found.incomplete, ""),)
    if not found.paths:
        notes = found.incomplete or (f"no exposed entrypoint reaches {function.identity}",)
        gap = ("no exposed entrypoint was established; the helper was not wrapped",)
        return ((tuple(calls), (), notes + gap, ""),)
    promoted: list[tuple[tuple[VfcsCall, ...], tuple[str, ...], tuple[str, ...], str]] = []
    for path in found.paths:
        entry = _resolve(model, path.entry_contract, path.entry_signature)
        if entry is None:
            continue
        binding = forwarded_entry_params(path, function)
        rewritten: list[VfcsCall] = []
        for call in calls:
            if (
                call.primitive
                or call.contract != candidate.contract
                or call.function != candidate.function
            ):
                rewritten.append(call)
                continue
            rewritten.append(_entry_call(call, entry, function, binding))
        contract = "" if path.entry_contract == candidate.contract else path.entry_contract
        notes = path.notes + found.incomplete
        unbound = tuple(
            param.name for param in entry.params if param.name and param.name not in binding
        )
        if unbound:
            shown = ", ".join(unbound[:6])
            notes = (*notes, f"entry parameters without a forwarded candidate value: {shown}")
        promoted.append((tuple(rewritten), path_lines(path), notes, contract))
    if not promoted:
        return (
            (
                tuple(calls),
                (),
                found.incomplete + ("an exposed path did not resolve to a function",),
                "",
            ),
        )
    return tuple(promoted)


def _entry_call(
    call: VfcsCall,
    entry: RFunction,
    helper: RFunction,
    binding: dict[str, str],
) -> VfcsCall:
    values = dict(call.arguments)
    arguments = []
    for index, param in enumerate(entry.params):
        key = param.name or f"arg{index}"
        if param.name and param.name in binding:
            arguments.append((key, values.get(binding[param.name], UNCONSTRAINED)))
        else:
            arguments.append((key, UNCONSTRAINED))
    why = call.established_by or f"entrypoint:{entry.contract}.{entry.signature}"
    return VfcsCall(
        entry.contract,
        entry.signature,
        call.role,
        call.actor,
        tuple(arguments),
        False,
        why[:240],
        helper.signature,
    )


def _split_callee(text: str) -> tuple[str, str]:
    contract, _, signature = text.partition(".")
    return contract, signature


def _call(
    function: RFunction,
    role: str,
    actor: str,
    overrides: Mapping[str, str] | None = None,
    default: str = UNCONSTRAINED,
) -> VfcsCall:
    overrides = overrides or {}
    arguments = tuple(
        (item.name or f"arg{i}", overrides.get(item.name, default))
        for i, item in enumerate(function.params)
    )
    return VfcsCall(function.contract, function.signature, role, actor, arguments)


def _primitive(contract: str, function: str, role: str, actor: str, why: str) -> VfcsCall:
    return VfcsCall(contract, function, role, actor, (), True, why)


def _own(model: ResearchModel, candidate: SemanticCandidate) -> RFunction | str:
    function = _resolve(model, candidate.contract, candidate.function)
    return function if function is not None else "the candidate function is not in the model"


def _withdraw_like(model: ResearchModel, contract: str, exclude: str) -> RFunction | None:
    for function in model.functions_of(contract):
        if (
            function.exposed
            and function.kind == "function"
            and function.signature != exclude
            and function.has_body
            and function.params
            and any(
                token in function.body for token in (".transfer(", ".safeTransfer(", ".call{value")
            )
        ):
            return function
    return None


def _dispatch(model: ResearchModel, candidate: SemanticCandidate) -> Built:
    function = _own(model, candidate)
    if isinstance(function, str):
        return function
    callee_text = candidate.fact("eventual_callee")
    callee_contract, callee_signature = _split_callee(callee_text)
    if "(" not in callee_signature or _resolve(model, callee_contract, callee_signature) is None:
        return "the nested callee is not a function in the model"
    nested = f"nested_call:{callee_contract}.{callee_signature}"
    overrides = {item.name: nested for item in function.params if "bytes" in item.type_name}
    calls = [_call(function, "dispatch", ATTACKER, overrides, ATTACKER_CONTROLLED)]
    return "nested-dispatch", calls, "the nested callee must authorize the original actor"


def _approval_dispatch(model: ResearchModel, candidate: SemanticCandidate) -> Built:
    function = _own(model, candidate)
    if isinstance(function, str):
        return function
    approve = _primitive(
        "token",
        "approve(address,uint256)",
        "approve",
        VICTIM,
        f"{function.contract} pulls tokens from users, so users may approve it",
    )
    call = _call(function, "execute", ATTACKER, default=ATTACKER_CONTROLLED)
    return (
        "approve→transferFrom",
        [approve, call],
        "an allowance granted to the contract must not be spendable by another actor",
    )


def _actor_parameter(model: ResearchModel, candidate: SemanticCandidate) -> Built:
    function = _own(model, candidate)
    if isinstance(function, str):
        return function
    callee_contract, callee_signature = _split_callee(candidate.fact("eventual_callee"))
    if _resolve(model, callee_contract, callee_signature) is None:
        return "the callee is not a function in the model"
    acted_for = candidate.fact("acted_for_parameter").strip("` ")
    overrides = {acted_for: VICTIM} if acted_for else {}
    calls = [_call(function, "relay", ATTACKER, overrides, ATTACKER_CONTROLLED)]
    return "forwarded-actor", calls, "the callee must bind the acted-for account to the caller"


def _payout_lifecycle(model: ResearchModel, function: RFunction, donate: VfcsCall) -> Built | None:
    """Deposit, then exit, when source links the two. None when this is not a payout.

    A string means the payout cannot be sized, so no withdrawal-without-a-position
    sequence is emitted in its place.
    """
    info = share_accounting(model, function)
    if not info.decreases_shares and not info.pay_param:
        return None
    if info.share_reader is None or info.slot is None:
        return "no source-backed reader reports the share position this payout uses"
    setup = position_entry(model, function.contract, info.slot)
    if setup is None:
        return "no exposed deposit establishes the share position this payout redeems"
    deposit = VfcsCall(
        setup.contract,
        setup.function,
        "deposit",
        ATTACKER,
        setup.arguments,
        False,
        setup.basis[:240],
    )
    victim = replace(
        deposit,
        role="victim_deposit",
        actor=VICTIM,
        arguments=tuple(
            (name, VICTIM if value == ATTACKER else value) for name, value in setup.arguments
        ),
    )
    exit_call = _call(function, "withdraw", ATTACKER, _exit_overrides(function, info))
    return (
        "deposit→donate→withdraw",
        [deposit, donate, victim, exit_call],
        "a sized exit must not increase the attacker's assets or the designated recipient; "
        "share units and asset units are not interchangeable",
    )


def _exit_overrides(function: RFunction, info: ShareAccounting) -> dict[str, str]:
    overrides: dict[str, str] = {}
    for index, param in enumerate(function.params):
        name = param.name or f"arg{index}"
        if _is_address(param.type_name):
            # A distinct payout receiver is the designated alternate wallet.
            # The owner of the burned shares stays the caller.
            overrides[name] = "recipient" if name == info.pay_to else ATTACKER
        elif _is_uint(param.type_name):
            overrides[name] = _amount_role(name, info) or "zero"
    return overrides


def _amount_role(name: str, info: ShareAccounting) -> str:
    pay, burn = info.pay_param, info.burn_param
    if name and name == pay and name == burn:
        if info.pay_bare and info.burn_bare:
            return "share_balance"
        if info.burn_bare and not info.pay_bare:
            return "share_balance"
        return _asset_override(info)
    if name and name == burn and name != pay:
        return "share_balance"
    if name and name == pay and name != burn:
        return _asset_override(info)
    return ""


def _asset_override(info: ShareAccounting) -> str:
    if info.asset_sizer:
        return f"asset_exit:{info.asset_sizer}"
    return "asset_exit:unsupported"


def _is_address(type_name: str) -> bool:
    return type_name.replace(" ", "") in {"address", "addresspayable"}


def _is_uint(type_name: str) -> bool:
    text = type_name.replace(" ", "")
    return text == "uint" or bool(re.fullmatch(r"u?int\d*", text))


def _donation(model: ResearchModel, candidate: SemanticCandidate) -> Built:
    function = _own(model, candidate)
    if isinstance(function, str):
        return function
    donate = _primitive(
        "token",
        "transfer(address,uint256)",
        "donate",
        ATTACKER,
        "balanceOf(address(this)) is read by the candidate function",
    )
    if candidate.detector == "accounting.balance_as_deposit":
        linked = _payout_lifecycle(model, function, donate)
        if linked is not None:
            return linked
        calls = [donate, _call(function, "credit", ATTACKER, default=ATTACKER_CONTROLLED)]
        return "donate→credit", calls, "a donation must not be credited as a deposit"
    withdraw = _withdraw_like(model, function.contract, function.signature)
    if withdraw is None:
        return "no function that pays out was found in the contract"
    calls = [
        _call(function, "deposit", ATTACKER, default="unit_amount"),
        donate,
        _call(function, "deposit", VICTIM, default="victim_amount"),
        _call(withdraw, "withdraw", ATTACKER, default="all_shares"),
    ]
    return "deposit→donate→withdraw", calls, "no actor may withdraw more than it deposited"


def _token_behavior(model: ResearchModel, candidate: SemanticCandidate) -> Built:
    function = _own(model, candidate)
    if isinstance(function, str):
        return function
    origin = candidate.fact("token_origin", "unknown")
    token_value = "fee_on_transfer_token" if "caller-chosen" in origin else UNCONSTRAINED
    overrides = {item.name: token_value for item in function.params if "IERC20" in item.type_name}
    calls = [_call(function, "deposit", ATTACKER, overrides, "amount_one")]
    withdraw = _withdraw_like(model, function.contract, function.signature)
    if withdraw is not None:
        calls.append(_call(withdraw, "withdraw", ATTACKER, default="credited_balance"))
    template = "deposit→withdraw" if withdraw is not None else "deposit"
    return template, calls, "credited balance must equal the amount received"


def _round_trip(model: ResearchModel, candidate: SemanticCandidate) -> Built:
    """Attacker deposits, another depositor deposits, the attacker withdraws its credit.

    The second depositor puts funds in custody that an over-paying withdrawal could
    take. Without an initializer the attacker withdraws twice; the repeat asks for
    whatever credit it still has. A contract that needs a one-time initializer
    spends the first call on it and withdraws once, so the sequence stays within
    the length cap. A token argument the path pins to the custodied token is bound
    to that token; any other parameter keeps the role's default.
    """
    deposit = _own(model, candidate)
    if isinstance(deposit, str):
        return deposit
    payout = _resolve(model, candidate.contract, candidate.fact("payout_function"))
    if payout is None:
        return "the payout function is not in the model"
    differs = candidate.fact("token_must_differ_from")
    if differs:
        return (
            f"the custody path needs a token argument other than {differs}; the local "
            "harness provides one fixture token"
        )

    # An argument-bound token is custodied because it is passed. A state-bound one
    # only matches the passed token when construction bound the same token.
    passed = "bound_token" if candidate.fact("token_binding") == "argument" else "custodied_token"

    def call(
        function: RFunction, role: str, actor: str, default: str, token: str, amount: str
    ) -> VfcsCall:
        overrides = {name: passed for name in (token,) if name}
        if amount:
            overrides[amount] = default
        built = _call(function, role, actor, overrides, default=default)
        return replace(built, contract=candidate.contract)

    put_token = candidate.fact("deposit_token_argument")
    put_amount = candidate.fact("deposit_amount_argument")
    take_token = candidate.fact("payout_token_argument")
    take_amount = candidate.fact("payout_amount_argument")
    calls = [
        call(deposit, "deposit", ATTACKER, "minimum_amount", put_token, put_amount),
        call(deposit, "victim_deposit", VICTIM, "victim_amount", put_token, put_amount),
        call(payout, "withdraw", ATTACKER, "actor_credit", take_token, take_amount),
    ]
    initializer = candidate.fact("initializer")
    template = "deposit→deposit→withdraw→withdraw"
    if initializer:
        setup = _resolve(model, candidate.contract, initializer)
        if setup is None or setup.params:
            return f"the initializer {initializer} is not a parameterless function in the model"
        first = replace(_call(setup, "initialize", ATTACKER), contract=candidate.contract)
        calls.insert(0, first)
        template = "initialize→deposit→deposit→withdraw"
    else:
        calls.append(
            call(payout, "withdraw_again", ATTACKER, "actor_credit", take_token, take_amount)
        )
    return template, calls, "a caller must not withdraw more value than it deposited"


def _message(model: ResearchModel, candidate: SemanticCandidate) -> Built:
    function = _own(model, candidate)
    if isinstance(function, str):
        return function
    detector = candidate.detector
    if detector in {"message.replay_no_consumption", "message.nonce_not_in_digest"}:
        first = _call(function, "execute", ATTACKER, default="valid_message")
        again = replace(
            first,
            role="replay",
            arguments=tuple((n, "replay_of_call:0") for n, _ in first.arguments),
        )
        return "authorize→execute", [first, again], "an authorization must be consumable once"
    omitted = {
        name for name in candidate.fact("omitted_fields").split(",") if name and name != "none"
    }
    if detector == "message.missing_expiry":
        calls = [_call(function, "execute", ATTACKER, default="expired_message")]
        return "authorize→execute", calls, "an expired authorization must be refused"
    overrides = {name: "attacker_substituted" for name in omitted}
    calls = [_call(function, "execute", ATTACKER, overrides, "valid_message")]
    return "authorize→execute", calls, "an authorization must bind every effectful field"


def _oracle(model: ResearchModel, candidate: SemanticCandidate) -> Built:
    function = _own(model, candidate)
    if isinstance(function, str):
        return function
    if candidate.detector == "oracle.stale_source_accepted":
        shift = _primitive(
            "vm", "warp(uint256)", "age_price", ATTACKER, "the feed timestamp is not checked"
        )
    elif candidate.detector == "oracle.spot_price_sensitive_use":
        shift = _primitive(
            "market",
            "swap(uint256)",
            "move_spot_price",
            ATTACKER,
            "the price is read from pool reserves",
        )
    else:
        shift = _primitive(
            "oracle", "report(uint256)", "update_price", ATTACKER, "the source set is weak"
        )
    calls = [shift, _call(function, "valuation", ATTACKER, default=UNCONSTRAINED)]
    spender = _withdraw_like(model, function.contract, function.signature)
    if spender is not None:
        calls.append(_call(spender, "borrow_or_withdraw", ATTACKER, default="maximum"))
    return "oracle update→valuation→borrow", calls, "value must not depend on a weak price"


def _initializer(model: ResearchModel, candidate: SemanticCandidate) -> Built:
    function = _own(model, candidate)
    if isinstance(function, str):
        return function
    first = _call(function, "initialize", ATTACKER, default=ATTACKER)
    second = _call(function, "reinitialize", VICTIM, default="second_owner")
    return "initialize→reinitialize", [first, second], "an account initializes exactly once"


UNAUTHENTICATED_EXECUTION = frozenset(
    {
        "aa.unauthenticated_account_execution",
        "v4_hooks.callback_without_pool_manager_check",
        "bridge.receiver_without_endpoint_check",
    }
)


def _account_validation(model: ResearchModel, candidate: SemanticCandidate) -> Built:
    function = _own(model, candidate)
    if isinstance(function, str):
        return function
    if candidate.detector in UNAUTHENTICATED_EXECUTION:
        calls = [_call(function, "execute", ATTACKER, default=ATTACKER_CONTROLLED)]
        return "unauthenticated-execution", calls, "execution requires a valid operation"
    calls = [_call(function, "validate", ATTACKER, default="forged_operation")]
    for other in model.functions_of(function.contract):
        if other.exposed and other.signature != function.signature and "call{" in other.body:
            calls.append(_call(other, "execute", ATTACKER, default=ATTACKER_CONTROLLED))
            break
    return "AA validation→execution", calls, "execution requires a valid operation"


def _swallowed_call(model: ResearchModel, candidate: SemanticCandidate) -> Built:
    """Bind a swallowed low-level call to a local failing callee when the source allows it.

    Possible false positives and ambiguous propagation are not turned into exploit
    sequences. A receiver that is not a caller-supplied address stays unknown.
    """
    function = _own(model, candidate)
    if isinstance(function, str):
        return function
    evidence = candidate.fact("evidence_class", "unknown")
    pattern = candidate.fact("pattern", "unknown")
    if evidence == "possible_false_positive":
        return f"possible false positive ({pattern}); not synthesized as an exploit sequence"
    if evidence == "ambiguous":
        return "failure propagation is ambiguous; a sequence is not synthesized"
    if evidence != "detector_emission":
        return "evidence class is unknown; a sequence is not synthesized"
    target = candidate.fact("target_parameter", "unknown")
    if target in {"", "unknown"}:
        return (
            "the call receiver is not a caller-supplied address parameter; "
            "a failing callee is not invented"
        )
    why = (
        f"failure {candidate.fact('failure_propagation', 'unknown')}; "
        f"gas guard {candidate.fact('gas_guard', 'unknown')}; "
        f"call kind {candidate.fact('call_kind', 'unknown')}; "
        f"receiver parameter {target}"
    )[:240]
    deploy = _primitive("callee", "deploy_reverting()", "failing_callee", ATTACKER, why)
    overrides = {target: "reverting_callee"}
    data_param = candidate.fact("calldata_parameter", "unknown")
    if data_param not in {"", "unknown", "empty"}:
        overrides[data_param] = "reverting_calldata"
    probe = _call(function, "probe", ATTACKER, overrides, UNCONSTRAINED)
    return (
        "failing-callee→swallowed-call",
        [deploy, probe],
        "behavioral probe of a reverting callee: outer success shows the failure was "
        "swallowed and is not by itself a security-property violation",
    )


def _reported(model: ResearchModel, candidate: SemanticCandidate) -> Built:
    """Profit, no-change, unauthorized, loss, and unlock sequences for one report.

    Each sequence is a separate hypothesis. An unauthorized revert is not a
    profit-accounting result, and a duration warp is not an unlock-formula proof.
    """
    function = _own(model, candidate)
    if isinstance(function, str):
        return function
    site = reported_site(model, function)
    if site is None:
        return "the function does not store a called value into accounting state"
    actor = "deployer" if site.role_getter else ATTACKER
    why = (
        f"role_getter:{site.role_getter}"
        if site.role_getter
        else "no source role getter; the report caller is the ordinary attacker"
    )
    report = replace(_call(function, "report", actor), established_by=why[:240])
    if not site.judgeable:
        return [
            (
                "report",
                [report],
                "the reported value is not idle holdings or idle holdings plus one public "
                "getter, so the reconciliation is not judged",
            )
        ]
    donate = _primitive(
        "token",
        "transfer(address,uint256)",
        "donation",
        ATTACKER,
        "increase the token balance without writing the stored total",
    )
    if site.reported_form == "idle_balance":
        statement = (
            "after the report, the stored total is at most the idle token balance; "
            "assets held outside this contract are not part of this check"
        )
    else:
        statement = (
            "after the report, the stored total is at most the idle token balance plus "
            f"{site.external_getter}"
        )
    plans: list[Plan] = [
        ("donate→report", [donate, report], statement),
        (
            "report",
            [report],
            "a report that observes no new profit or loss keeps the stored total "
            "within the token balance",
        ),
    ]
    if site.role_getter:
        plans.append(
            (
                "unauthorized-report",
                [_call(function, "unauthorized_report", ATTACKER)],
                "a caller other than the source-declared role must revert; "
                "that revert is only the caller check and is not a profit-accounting result",
            )
        )
    if site.outflow:
        outflow = _resolve(model, function.contract, site.outflow)
        if outflow is not None:
            second = replace(report, role="report_after")
            plans.append(
                (
                    "donate→report→outflow→report",
                    [donate, report, _call(outflow, "outflow", ATTACKER), second],
                    "after the reportable balance falls, a later report still stores at most "
                    "the source-backed total",
                )
            )
    if site.gain:
        owner = site.host or function.contract
        gain = _resolve(model, owner, site.gain)
        if gain is not None:
            plans.append(
                (
                    "gain→report",
                    [_call(gain, "gain", ATTACKER), report],
                    "after the public component increases, the stored total is at most "
                    "idle holdings plus that component; this does not prove a fee formula",
                )
            )
    if site.unlock_seconds and site.role_getter:
        warp = VfcsCall(
            "vm",
            "warp(uint256)",
            "time",
            "harness",
            (("seconds", site.unlock_seconds),),
            True,
            f"the only duration literal in this contract is {site.unlock_seconds} seconds",
        )
        second = replace(report, role="report_after")
        plans.append(
            (
                "donate→report→warp→report",
                [donate, report, warp, second],
                "after the source duration, a second report still stores at most the "
                "source-backed total; this does not prove the unlock formula",
            )
        )
    return plans


def _boundary(model: ResearchModel, candidate: SemanticCandidate) -> Built:
    function = _own(model, candidate)
    if isinstance(function, str):
        return function
    calls = [_call(function, "batch", ATTACKER, default="boundary_value")]
    return "boundary-batch", calls, "totals must not wrap or truncate"


_BUILDERS: dict[str, Builder] = {
    "v4_hooks.callback_without_pool_manager_check": _account_validation,
    "bridge.receiver_without_endpoint_check": _account_validation,
    "caller_context.swallowed_call_failure": _swallowed_call,
    "caller_context.self_call_elevation": _dispatch,
    "caller_context.forwarded_sender_delegatecall": _dispatch,
    "caller_context.unrestricted_dispatch_with_approval_authority": _approval_dispatch,
    "caller_context.trusted_intermediary_actor_parameter": _actor_parameter,
    "accounting.donation_share_price": _donation,
    "accounting.balance_as_deposit": _donation,
    "accounting.fee_on_transfer_mismatch": _token_behavior,
    "accounting.unchecked_token_return": _token_behavior,
    "accounting.reported_balance": _reported,
    "message.field_not_bound": _message,
    "message.missing_domain_separation": _message,
    "message.missing_expiry": _message,
    "message.replay_no_consumption": _message,
    "message.nonce_not_in_digest": _message,
    "oracle.insufficient_quorum": _oracle,
    "oracle.price_not_validated": _oracle,
    "oracle.stale_source_accepted": _oracle,
    "oracle.fallback_weaker": _oracle,
    "oracle.spot_price_sensitive_use": _oracle,
    "aa.unprotected_account_initializer": _initializer,
    "aa.signature_not_bound_to_userophash": _account_validation,
    "aa.signature_result_ignored": _account_validation,
    "aa.validate_without_entrypoint_binding": _account_validation,
    "aa.unauthenticated_account_execution": _account_validation,
    "arithmetic.batch_accumulation_overflow": _boundary,
    "arithmetic.unsafe_downcast_after_arithmetic": _boundary,
    "conservation.round_trip_value": _round_trip,
}


# ---- feedback-directed mutation -------------------------------------------------------------


def mutate(
    parents: Iterable[Vfcs],
    signals: Iterable[FeedbackSignal],
    *,
    limit: int = MAX_MUTATIONS,
) -> tuple[Vfcs, ...]:
    """Deterministic, bounded variants of known sequences. Every operator keeps real functions."""
    limit = max(0, min(limit, MAX_MUTATIONS))
    by_id = {item.sequence_id: item for item in parents}
    known = set(by_id)
    out: dict[str, Vfcs] = {}
    # Variants are taken round-robin across signals so one parent cannot spend the
    # whole budget; children already known are skipped and do not count.
    pending: list[tuple[FeedbackSignal, Vfcs, _VariantIter]] = []
    for signal in sorted(
        list(signals)[:MAX_FEEDBACK_SIGNALS], key=lambda s: (s.kind, s.sequence_id, s.call_index)
    ):
        parent = by_id.get(signal.sequence_id)
        if parent is not None:
            pending.append((signal, parent, iter(_variants(parent, signal))))
    while pending and len(out) < limit:
        still: list[tuple[FeedbackSignal, Vfcs, _VariantIter]] = []
        for signal, parent, variants in pending:
            if len(out) >= limit:
                break
            for operator, calls in variants:
                if not calls or len(calls) > MAX_VFCS_LENGTH:
                    continue
                child_id = sequence_id_of(
                    calls, parent.template, parent.identity, derived_from=parent.derived_from
                )
                if child_id in known or child_id in out:
                    continue
                out[child_id] = replace(
                    parent,
                    sequence_id=child_id,
                    origin=f"mutation:{signal.kind}:{operator}:{parent.sequence_id}",
                    calls=tuple(calls),
                )
                still.append((signal, parent, variants))
                break
        pending = still
    return tuple(out.values())


def _variants(parent: Vfcs, signal: FeedbackSignal) -> Iterable[tuple[str, list[VfcsCall]]]:
    calls = list(parent.calls)
    index = signal.call_index if 0 <= signal.call_index < len(calls) else len(calls) - 1
    kind = signal.kind
    if kind == "symbolic_counterexample" and signal.values:
        seeded = dict(signal.values)
        target = calls[index]
        arguments = tuple((n, seeded.get(n, v)) for n, v in target.arguments)
        yield (
            "seed_arguments",
            [*calls[:index], replace(target, arguments=arguments), *calls[index + 1 :]],
        )
    if kind in {"near_miss", "oracle_mismatch", "coverage_gain"}:
        target = calls[index]
        for value in _BOUNDARY_VALUES:
            arguments = tuple(
                (n, value if v in {UNCONSTRAINED, ATTACKER_CONTROLLED} else v)
                for n, v in target.arguments
            )
            if arguments != target.arguments:
                yield (
                    f"boundary_{value}",
                    [*calls[:index], replace(target, arguments=arguments), *calls[index + 1 :]],
                )
    if kind in {"near_miss", "coverage_gain"} and index + 1 < len(calls):
        swapped = list(calls)
        swapped[index], swapped[index + 1] = swapped[index + 1], swapped[index]
        yield "reorder", swapped
    if kind == "near_miss":
        for position, call in enumerate(calls):
            if call.role != "deposit" or call.primitive:
                continue
            for value in _SMALL_AMOUNTS:
                arguments = tuple(
                    (n, value if v == "minimum_amount" else v) for n, v in call.arguments
                )
                if arguments != call.arguments:
                    yield (
                        f"small_amount_{value}",
                        [
                            *calls[:position],
                            replace(call, arguments=arguments),
                            *calls[position + 1 :],
                        ],
                    )
    if kind == "coverage_gain" and len(calls) < MAX_VFCS_LENGTH and not calls[index].primitive:
        yield "repeat_call", [*calls[: index + 1], calls[index], *calls[index + 1 :]]
    if kind in {"caller_context_mismatch", "contradiction"}:
        target = calls[index]
        if not target.primitive:
            other = VICTIM if target.actor == ATTACKER else ATTACKER
            yield "swap_actor", [*calls[:index], replace(target, actor=other), *calls[index + 1 :]]


# ---- minimization ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MinimizationResult:
    """A reduction. It preserves one named property and it is not verification."""

    original: tuple[VfcsCall, ...]
    minimized: tuple[VfcsCall, ...]
    completed: bool
    reason: str
    attempts: int
    preserved_property: str
    evaluator: str
    inconclusive_attempts: int = 0
    verified: bool = False
    removed: tuple[str, ...] = field(default=())

    @property
    def reduced(self) -> bool:
        return len(self.minimized) < len(self.original)


Evaluator = Callable[[tuple[VfcsCall, ...]], bool | None]


def minimize(
    sequence: Vfcs,
    evaluator: Evaluator,
    *,
    evaluator_name: str,
    max_attempts: int = MAX_MINIMIZATION_ATTEMPTS,
) -> MinimizationResult:
    """Delta debugging over the calls. ``None`` from the evaluator means it could not tell."""
    budget = max(0, min(max_attempts, MAX_MINIMIZATION_ATTEMPTS))
    attempts = 0
    inconclusive = 0
    original = sequence.calls

    def test(candidate: tuple[VfcsCall, ...]) -> bool | None:
        nonlocal attempts, inconclusive
        attempts += 1
        try:
            outcome = evaluator(candidate)
        except Exception:
            outcome = None
        if outcome is None:
            inconclusive += 1
        return outcome

    def result(current: tuple[VfcsCall, ...], completed: bool, reason: str) -> MinimizationResult:
        kept = {c.identity for c in current}
        return MinimizationResult(
            original=original,
            minimized=current,
            completed=completed,
            reason=reason,
            attempts=attempts,
            preserved_property=sequence.property_under_test,
            evaluator=evaluator_name,
            inconclusive_attempts=inconclusive,
            removed=tuple(sorted({c.identity for c in original} - kept)),
        )

    if budget == 0:
        return result(original, False, "attempt_budget_exhausted")
    if test(original) is not True:
        return result(original, True, "original_not_reproduced")
    current = original
    granularity = 2
    while len(current) >= 2:
        size = max(1, len(current) // granularity)
        chunks = [current[i : i + size] for i in range(0, len(current), size)]
        reduced = False
        for index in range(len(chunks)):
            if attempts >= budget:
                return result(current, False, "attempt_budget_exhausted")
            complement = tuple(c for j, chunk in enumerate(chunks) if j != index for c in chunk)
            if complement and test(complement) is True:
                current = complement
                granularity = max(granularity - 1, 2)
                reduced = True
                break
        if reduced:
            continue
        if granularity >= len(current):
            return result(current, True, "one_minimal")
        granularity = min(len(current), granularity * 2)
    return result(current, True, "one_minimal")


# ---- stable call-instance identity and bounded feedback loop (Phase 51, owner Phase 5) -------
#
# A sequence may call the same (contract, function) more than once; a per-instance identity is
# needed so a fuzzer's feedback maps back to the exact call it refers to. The identity is derived
# from the deterministic sequence id plus the call's position and role, so it is stable across
# regeneration of the same sequence. Feedback is accepted only from the existing bounded fuzzers
# (Foundry, Echidna, Medusa, ItyFuzz); BugForge adds no fuzzer of its own.

ALLOWED_FEEDBACK_ENGINES = frozenset({"foundry", "echidna", "medusa", "ityfuzz"})


def call_instance_id(sequence: Vfcs, index: int) -> str:
    """A stable identity for one call position within a sequence."""
    call = sequence.calls[index]
    return "ci_" + digest(
        (sequence.sequence_id, index, call.contract, call.function, call.role, call.actor)
    )


def instance_identities(sequence: Vfcs) -> tuple[str, ...]:
    """Stable per-call-instance identities, one per call position."""
    return tuple(call_instance_id(sequence, index) for index in range(len(sequence.calls)))


def index_for_instance(sequence: Vfcs, instance_id: str) -> int:
    """Resolve a stable call-instance id to its position, or -1 when it does not belong."""
    for index in range(len(sequence.calls)):
        if call_instance_id(sequence, index) == instance_id:
            return index
    return -1


@dataclass(frozen=True)
class FeedbackOutcome:
    """The result of folding fuzzer feedback back into the research loop. Nothing verified."""

    children: tuple[Vfcs, ...]
    accepted: tuple[str, ...]
    refused: tuple[tuple[str, str], ...]  # (signal reference, reason)
    unavailable_engines: tuple[str, ...]
    verified: bool = False

    def as_dict(self) -> dict[str, object]:
        return {
            "verified": False,
            "children": [
                {
                    "sequence_id": child.sequence_id,
                    "origin": child.origin,
                    "template": child.template,
                    "calls": [call.identity for call in child.calls],
                    "instances": list(instance_identities(child)),
                }
                for child in self.children
            ],
            "accepted": list(self.accepted),
            "refused": [{"signal": ref, "reason": reason} for ref, reason in self.refused],
            "unavailable_engines": list(self.unavailable_engines),
        }


def incorporate_feedback(
    parents: Iterable[Vfcs],
    signals: Iterable[FeedbackSignal],
    *,
    available_engines: frozenset[str] | None = None,
    limit: int = MAX_MUTATIONS,
) -> FeedbackOutcome:
    """Fold bounded fuzzer feedback into new candidate sequences.

    Only signals from the allowed fuzzers are considered. A signal whose engine is allowed
    but not currently available is reported as unavailable and ignored (never fabricated).
    A signal that names a stable call-instance has it resolved to the concrete call index.
    The actual expansion reuses the existing bounded ``mutate`` and stays within ``limit``.
    """

    parent_list = list(parents)
    by_id = {item.sequence_id: item for item in parent_list}
    usable: list[FeedbackSignal] = []
    refused: list[tuple[str, str]] = []
    unavailable: set[str] = set()
    for signal in signals:
        ref = f"{signal.engine or '?'}:{signal.kind}:{signal.sequence_id}"
        engine = (signal.engine or "").strip().lower()
        if engine not in ALLOWED_FEEDBACK_ENGINES:
            refused.append((ref, "feedback is accepted only from foundry/echidna/medusa/ityfuzz"))
            continue
        if available_engines is not None and engine not in available_engines:
            unavailable.add(engine)
            refused.append((ref, f"{engine} is unavailable; its feedback is not fabricated"))
            continue
        parent = by_id.get(signal.sequence_id)
        if parent is None:
            refused.append((ref, "signal does not match a known sequence"))
            continue
        resolved = signal
        if signal.call_instance:
            index = index_for_instance(parent, signal.call_instance)
            if index < 0:
                refused.append((ref, "call-instance id does not belong to this sequence"))
                continue
            resolved = replace(signal, call_index=index)
        usable.append(resolved)

    children = mutate(parent_list, usable, limit=limit)
    accepted = tuple(f"{s.engine}:{s.kind}:{s.sequence_id}:{s.call_index}" for s in usable)
    return FeedbackOutcome(
        children=children,
        accepted=accepted,
        refused=tuple(refused),
        unavailable_engines=tuple(sorted(unavailable)),
    )
