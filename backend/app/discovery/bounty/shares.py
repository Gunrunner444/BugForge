"""Source-backed share and asset readers.

A function named ``balanceOf`` is not evidence. A reader is recorded only when an
exposed view returns a slot this function writes for one user, or returns the
scalar an inflow credits with the pulled amount. Share units and asset units stay
separate: a converted share balance is not treated as tokens received.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from app.discovery.bounty.entrypoints import entrypoints_for, forwarded_entry_params
from app.parsing.solidity_research import (
    ResearchModel,
    RFunction,
    member_calls,
    plain_calls,
)

_MAX_DEPTH = 4
_MAX_VISITS = 32
_NOISE = frozenset(
    {
        "uint",
        "uint256",
        "int",
        "int256",
        "address",
        "bool",
        "true",
        "false",
        "type",
        "msg",
        "sender",
    }
)
_IDENT = re.compile(r"[A-Za-z_]\w*")
_MAP_WRITE = re.compile(
    r"(?<![\w.])([A-Za-z_]\w*)(?:\.([A-Za-z_]\w*))?\s*\[\s*([^\]\n]+?)\s*\]\s*"
    r"(\+=|-=|=(?!=))\s*([^;]+);"
)
_SCALAR_WRITE = re.compile(r"(?<![\w.])([A-Za-z_]\w*)(?:\.([A-Za-z_]\w*))?\s*(\+=)\s*([^;]+);")
_UINT = re.compile(r"u?int\d*")
_ADDRESS = re.compile(r"address(?:payable)?")
_MAP_UINT = re.compile(r"mapping\(address=>u?int\d*\)")


@dataclass(frozen=True)
class Slot:
    """A user-keyed share mapping or a scalar the inflow credits."""

    kind: str  # struct | state | scalar
    owner: str
    field: str

    @property
    def label(self) -> str:
        if self.kind == "state":
            return self.field
        return f"{self.owner}.{self.field}"


@dataclass(frozen=True)
class Reader:
    getter: str
    variable: str
    basis: str
    kind: str  # share | asset_accounted


@dataclass(frozen=True)
class SizedEntry:
    """An exposed call that can establish or continue a position. Not a finding."""

    contract: str
    function: str
    arguments: tuple[tuple[str, str], ...]
    basis: str


@dataclass(frozen=True)
class ShareAccounting:
    slot: Slot | None = None
    share_reader: Reader | None = None
    credit_reader: Reader | None = None
    share_unit: str = ""  # accounted_amount | converted_shares | ""
    pull_param: str = ""
    pay_param: str = ""
    mint_param: str = ""
    burn_param: str = ""
    mint_bare: bool = False
    burn_bare: bool = False
    pay_bare: bool = False
    increases_shares: bool = False
    decreases_shares: bool = False
    asset_sizer: str = ""
    asset_basis: str = ""
    pay_to: str = ""
    notes: tuple[str, ...] = ()


@dataclass
class _Bag:
    pulls: list[tuple[str, bool]] = field(default_factory=list)
    pays: list[tuple[str, bool]] = field(default_factory=list)
    increases: list[tuple[Slot, str, bool, bool]] = field(default_factory=list)
    decreases: list[tuple[Slot, str, bool, bool]] = field(default_factory=list)
    scalars: list[tuple[Slot, str]] = field(default_factory=list)
    sizers: list[tuple[str, str, int]] = field(default_factory=list)
    pay_tos: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    visits: int = 0


def share_accounting(model: ResearchModel, function: RFunction) -> ShareAccounting:
    """What ``function`` does to a user share slot and to the pulled asset amount."""
    bag = _Bag()
    binding = {param.name: (param.name, True) for param in function.params if param.name}
    _walk(model, function, binding, 0, frozenset(), bag)
    return _summarize(model, function, bag)


def position_entry(model: ResearchModel, contract: str, slot: Slot) -> SizedEntry | None:
    """One exposed deposit that pulls assets and mints ``slot``. None when that is ambiguous."""
    found: list[SizedEntry] = []
    for function in model.functions_of(contract):
        if not function.has_body or function.mutability in {"view", "pure"}:
            continue
        info = share_accounting(model, function)
        if info.slot != slot or not info.increases_shares or not info.pull_param:
            continue
        found.extend(_entries_for(model, function, info.pull_param))
        if len(found) > 4:
            break
    unique = {(item.contract, item.function, item.arguments): item for item in found}
    if len(unique) != 1:
        return None
    return next(iter(unique.values()))


def _entries_for(model: ResearchModel, function: RFunction, pull: str) -> list[SizedEntry]:
    result = entrypoints_for(model, function)
    chosen: list[SizedEntry] = []
    if result.directly_executable:
        filled = _fill(function, pull)
        if filled is not None:
            chosen.append(
                SizedEntry(
                    function.contract,
                    function.signature,
                    filled,
                    f"{function.signature} pulls {pull} into the share slot",
                )
            )
        return chosen
    for path in result.paths:
        binding = forwarded_entry_params(path, function)
        amount = next((entry for entry, helper in binding.items() if helper == pull), "")
        if not amount:
            continue
        entry = _resolve(model, path.entry_contract, path.entry_signature)
        if entry is None:
            continue
        filled = _fill(entry, amount)
        if filled is None:
            continue
        chosen.append(
            SizedEntry(
                entry.contract,
                entry.signature,
                filled,
                f"{entry.signature} forwards {amount} to the pulled amount {pull}",
            )
        )
    return chosen


def _fill(function: RFunction, amount: str) -> tuple[tuple[str, str], ...] | None:
    arguments: list[tuple[str, str]] = []
    for index, param in enumerate(function.params):
        name = param.name or f"arg{index}"
        if name == amount:
            arguments.append((name, "amount_one"))
        elif _is_address(param.type_name):
            arguments.append((name, "attacker"))
        elif _is_uint(param.type_name):
            arguments.append((name, "zero"))
        else:
            return None
    return tuple(arguments)


def _one_name(names: list[str]) -> str:
    unique = set(names)
    if len(unique) != 1:
        return ""
    return next(iter(unique))


def _summarize(model: ResearchModel, function: RFunction, bag: _Bag) -> ShareAccounting:
    pulls = _unique_flags(bag.pulls)
    pays = _unique_flags(bag.pays)
    pull_param, _pull_bare = pulls[0] if len(pulls) == 1 else ("", False)
    pay_param, pay_bare = pays[0] if len(pays) == 1 else ("", False)
    slot, increases, decreases = _share_slot(bag)
    mint_param, mint_bare, mint_reduction = _one_effect(bag.increases, slot)
    burn_param, burn_bare, _burn_reduction = _one_effect(bag.decreases, slot)
    share_unit = _share_unit(pull_param, mint_param, bool(bag.increases), mint_bare, mint_reduction)
    share_reader = _mapping_reader(model, function.contract, slot) if slot is not None else None
    credit_reader = _credit_reader(model, function.contract, bag, pull_param, slot, share_unit)
    if pay_param and not bag.sizers:
        _bounds_from_callers(model, function, pay_param, bag)
    sizer, sizer_basis = _asset_sizer(model, function.contract, bag)
    notes = tuple(bag.notes[:8])
    if slot is not None and share_reader is None:
        notes = (*notes, f"no exposed view returns {slot.label} for one user")
    return ShareAccounting(
        slot=slot,
        share_reader=share_reader,
        credit_reader=credit_reader,
        share_unit=share_unit,
        pull_param=pull_param,
        pay_param=pay_param,
        pay_to=_one_name(bag.pay_tos),
        mint_param=mint_param,
        burn_param=burn_param,
        mint_bare=mint_bare,
        burn_bare=burn_bare,
        pay_bare=pay_bare,
        increases_shares=increases,
        decreases_shares=decreases,
        asset_sizer=sizer,
        asset_basis=sizer_basis,
        notes=notes,
    )


def _unique_flags(items: list[tuple[str, bool]]) -> list[tuple[str, bool]]:
    found: dict[str, bool] = {}
    for name, bare in items:
        if not name:
            continue
        found[name] = found.get(name, True) and bare
    return [(name, bare) for name, bare in sorted(found.items())]


def _share_slot(bag: _Bag) -> tuple[Slot | None, bool, bool]:
    slots = {item[0] for item in (*bag.increases, *bag.decreases)}
    if len(slots) != 1:
        if len(slots) > 1:
            bag.notes.append("more than one user share slot is written; none is selected")
        return None, False, False
    slot = next(iter(slots))
    return (
        slot,
        any(item[0] == slot for item in bag.increases),
        any(item[0] == slot for item in bag.decreases),
    )


def _one_effect(
    effects: list[tuple[Slot, str, bool, bool]], slot: Slot | None
) -> tuple[str, bool, bool]:
    if slot is None:
        return "", False, False
    roots = {
        (root, bare, reduction) for item, root, bare, reduction in effects if item == slot and root
    }
    if len(roots) != 1:
        return "", False, False
    return next(iter(roots))


def _share_unit(pull: str, mint: str, increased: bool, bare: bool, reduction: bool) -> str:
    """A bare or reduced pull amount is an asset unit. A scaled write is shares."""
    if not increased or not mint or not pull:
        return ""
    if mint == pull and (bare or reduction):
        return "accounted_amount"
    return "converted_shares"


def _credit_reader(
    model: ResearchModel,
    contract: str,
    bag: _Bag,
    pull: str,
    slot: Slot | None,
    share_unit: str,
) -> Reader | None:
    """A reader of the slot credited with the pulled amount, never a converted share price."""
    if share_unit == "accounted_amount" and slot is not None:
        reader = _mapping_reader(model, contract, slot)
        if reader is not None:
            return Reader(reader.getter, reader.variable, reader.basis, "asset_accounted")
    scalars = [item for item in bag.scalars if item[1] == pull and pull]
    owners = {item[0] for item in scalars}
    if len(owners) != 1:
        return None
    scalar = next(iter(owners))
    reader = _scalar_reader(model, contract, scalar)
    if reader is None:
        return None
    return Reader(reader.getter, reader.variable, reader.basis, "asset_accounted")


def _mapping_reader(model: ResearchModel, contract: str, slot: Slot) -> Reader | None:
    if slot.kind == "scalar":
        return None
    found = [
        item
        for item in model.functions_of(contract)
        if _view_shape(item) and _returns_slot(model, item, slot, _address_param(item))
    ]
    public = _public_mapping(model, contract, slot)
    readers = {(_signature(item), item) for item in found}
    if public and not readers:
        return Reader(public, slot.field, f"the public getter of {slot.label}", "share")
    if len(readers) != 1:
        return None
    signature, function = next(iter(readers))
    if not signature:
        return None
    return Reader(
        signature,
        slot.field,
        f"{signature} returns {slot.label} for its address parameter "
        f"({function.file}:{function.line})",
        "share",
    )


def _scalar_reader(model: ResearchModel, contract: str, slot: Slot) -> Reader | None:
    found = [
        item
        for item in model.functions_of(contract)
        if _view_shape(item) and not item.params and _returns_slot(model, item, slot, "")
    ]
    if len(found) != 1:
        return None
    function = found[0]
    signature = _signature(function)
    if not signature:
        return None
    return Reader(
        signature,
        slot.field,
        f"{signature} returns {slot.label} ({function.file}:{function.line})",
        "asset_accounted",
    )


def _bounds_from_callers(model: ResearchModel, function: RFunction, pay: str, bag: _Bag) -> None:
    """A caller may bound the paid amount before forwarding it. The helper itself may not."""
    index = next((i for i, param in enumerate(function.params) if param.name == pay), -1)
    if index < 0:
        return
    for caller in model.functions_of(function.contract):
        if not caller.has_body or caller.identity == function.identity:
            continue
        caller_params = {param.name for param in caller.params}
        for name, arguments, _offset in plain_calls(caller.body):
            if name != function.name or len(arguments) != len(function.params):
                continue
            argument = " ".join(arguments[index].split())
            if argument not in caller_params:
                continue
            _record_sizers(caller.body, argument, bag)


def _asset_sizer(model: ResearchModel, contract: str, bag: _Bag) -> tuple[str, str]:
    if not bag.sizers:
        return "", ""
    # A bound on the paid amount outranks an assignment of a conversion.
    ranked = sorted(bag.sizers, key=lambda item: (0 if item[0] == "bound" else 1, item[1]))
    kind = ranked[0][0]
    group = [item for item in ranked if item[0] == kind]
    wrappers: list[tuple[str, str]] = []
    for _kind, name, arity in group:
        for function in _wrappers(model, contract, name, arity):
            signature = _signature(function)
            if signature:
                wrappers.append((signature, f"{signature} returns {name}"))
    unique = dict(wrappers)
    if len(unique) != 1:
        return "", ""
    signature, basis = next(iter(unique.items()))
    return signature, basis


def _wrappers(model: ResearchModel, contract: str, name: str, arity: int) -> list[RFunction]:
    found: list[RFunction] = []
    helper = _unique(model, contract, name, arity)
    if helper is not None and helper.exposed and _view_shape(helper):
        found.append(helper)
    for function in model.functions_of(contract):
        if not _view_shape(function):
            continue
        expressions = _return_exprs(function.body)
        if len(expressions) != 1:
            continue
        calls = [item for item in plain_calls(expressions[0]) if item[2] == 0]
        if (
            len(calls) == 1
            and calls[0][0] == name
            and len(calls[0][1]) == arity
            and _call_is_whole_expression(expressions[0], name)
        ):
            found.append(function)
    fewest = min((len(item.params) for item in found), default=-1)
    return [item for item in found if len(item.params) == fewest]


def _walk(
    model: ResearchModel,
    function: RFunction,
    binding: dict[str, tuple[str, bool]],
    depth: int,
    seen: frozenset[str],
    bag: _Bag,
) -> None:
    bag.visits += 1
    if bag.visits > _MAX_VISITS or depth > _MAX_DEPTH or function.identity in seen:
        if bag.visits > _MAX_VISITS:
            bag.notes.append(f"share walk stopped at {_MAX_VISITS} visits")
        return
    seen = seen | {function.identity}
    _collect(model, function, binding, bag)
    if function.mutability in {"view", "pure"}:
        return
    for name, arguments, _offset in plain_calls(function.body):
        callee = _unique(model, function.contract, name, len(arguments))
        if callee is None or not callee.has_body or callee.mutability in {"view", "pure"}:
            continue
        _walk(model, callee, _bind(callee, arguments, binding), depth + 1, seen, bag)


def _bind(
    callee: RFunction,
    arguments: tuple[str, ...],
    binding: dict[str, tuple[str, bool]],
) -> dict[str, tuple[str, bool]]:
    child: dict[str, tuple[str, bool]] = {}
    for index, param in enumerate(callee.params):
        if not param.name or index >= len(arguments):
            continue
        traced = _trace(arguments[index], binding)
        child[param.name] = traced if traced is not None else ("", False)
    return child


def _collect(
    model: ResearchModel,
    function: RFunction,
    binding: dict[str, tuple[str, bool]],
    bag: _Bag,
) -> None:
    body = function.body
    for match in _MAP_WRITE.finditer(body):
        slot = _slot(model, function, match.group(1), match.group(2) or "")
        if slot is None or slot.kind == "scalar" or not _user_key(function, match.group(3)):
            continue
        rhs = match.group(5)
        traced = _effect(rhs, binding)
        if traced is None:
            continue
        bucket = bag.decreases if match.group(4) == "-=" else bag.increases
        bucket.append((slot, traced[0], traced[1], "-" in rhs))
    for match in _SCALAR_WRITE.finditer(body):
        # A mapping write has an index between the name and +=, so it is not a scalar.
        slot = _scalar_slot(model, function, match.group(1), match.group(2) or "")
        traced = _effect(match.group(4), binding)
        if slot is None or traced is None or not traced[0]:
            continue
        bag.scalars.append((slot, traced[0]))
    before = len(bag.pays)
    for call in member_calls(body):
        _flow(call.name, call.arguments, binding, bag)
    local_pays = {item[0] for item in bag.pays[before:] if item[0]}
    if len(local_pays) != 1:
        return
    pay = next(iter(local_pays))
    _record_sizers(body, pay, bag)


def _record_sizers(body: str, pay: str, bag: _Bag) -> None:
    for name, arguments, offset in plain_calls(body):
        statement = _statement(body, offset)
        if not re.search(rf"(?<![\w.]){re.escape(pay)}\b", statement):
            continue
        if re.search(r"<=|>=", statement):
            bag.sizers.append(("bound", name, len(arguments)))
        elif re.search(rf"(?<![\w.]){re.escape(pay)}\s*=(?!=)", statement):
            bag.sizers.append(("assign", name, len(arguments)))


def _flow(
    name: str,
    arguments: tuple[str, ...],
    binding: dict[str, tuple[str, bool]],
    bag: _Bag,
) -> None:
    if name in {"transferFrom", "safeTransferFrom"} and len(arguments) >= 3:
        if arguments[1].strip() in {"address(this)", "this"}:
            traced = _trace(arguments[2], binding)
            if traced is not None and traced[0]:
                bag.pulls.append(traced)
    if name in {"transfer", "safeTransfer"} and len(arguments) >= 2:
        if arguments[0].strip() not in {"address(this)", "this"}:
            traced = _trace(arguments[1], binding)
            if traced is not None and traced[0]:
                bag.pays.append(traced)
            destination = _trace(arguments[0], binding)
            # msg.sender is not a parameter, so a payout to the caller is not redirected.
            if destination is not None and destination[0]:
                bag.pay_tos.append(destination[0])


def _effect(expression: str, binding: dict[str, tuple[str, bool]]) -> tuple[str, bool] | None:
    text = " ".join(expression.split())
    idents = [item for item in _IDENT.findall(text) if item not in _NOISE]
    if len(idents) == 1 and text == idents[0] and idents[0] in binding:
        root, bare = binding[idents[0]]
        return (root, bare) if root else None
    return _trace(expression, binding)


def _trace(expression: str, binding: dict[str, tuple[str, bool]]) -> tuple[str, bool] | None:
    text = " ".join(expression.split())
    idents = [item for item in _IDENT.findall(text) if item not in _NOISE]
    if not idents:
        return None
    roots: list[str] = []
    for ident in idents:
        if ident not in binding:
            return None
        root, _bare = binding[ident]
        if not root:
            return None
        roots.append(root)
    if len(set(roots)) != 1:
        return None
    bare = len(idents) == 1 and text == idents[0] and binding[idents[0]][1]
    return roots[0], bare


def _slot(model: ResearchModel, function: RFunction, receiver: str, field: str) -> Slot | None:
    if field:
        param = next((item for item in function.params if item.name == receiver), None)
        if param is None:
            return None
        owner = param.type_name.split(".")[-1]
        fields = model.struct_fields(owner)
        if fields is None:
            return None
        kind = next((item.type_name for item in fields if item.name == field), "")
        if not _MAP_UINT.fullmatch(kind.replace(" ", "")):
            return None
        return Slot("struct", owner, field)
    kind = model.state_vars(function.contract).get(receiver, "")
    if not _MAP_UINT.fullmatch(kind.replace(" ", "")):
        return None
    return Slot("state", function.contract, receiver)


def _scalar_slot(
    model: ResearchModel, function: RFunction, receiver: str, field: str
) -> Slot | None:
    if field:
        param = next((item for item in function.params if item.name == receiver), None)
        if param is None:
            return None
        owner = param.type_name.split(".")[-1]
        fields = model.struct_fields(owner)
        if fields is None:
            return None
        kind = next((item.type_name for item in fields if item.name == field), "")
        if not _UINT.fullmatch(kind.replace(" ", "")):
            return None
        return Slot("scalar", owner, field)
    kind = model.state_vars(function.contract).get(receiver, "")
    if not _UINT.fullmatch(kind.replace(" ", "")):
        return None
    return Slot("scalar", function.contract, receiver)


def _user_key(function: RFunction, expression: str) -> str:
    text = " ".join(expression.split())
    if text == "msg.sender":
        return text
    if not re.fullmatch(r"[A-Za-z_]\w*", text):
        return ""
    param = next((item for item in function.params if item.name == text), None)
    if param is not None and _is_address(param.type_name):
        return text
    return ""


def _returns_slot(model: ResearchModel, function: RFunction, slot: Slot, key: str) -> bool:
    expressions = _return_exprs(function.body)
    if not expressions or len(expressions) > 4:
        return False
    for expression in expressions:
        if ".balanceOf(" in expression.replace(" ", ""):
            return False
        if _expression_returns(model, function, expression, slot, key, 0):
            continue
        return False
    return True


def _expression_returns(
    model: ResearchModel,
    function: RFunction,
    expression: str,
    slot: Slot,
    key: str,
    depth: int,
) -> bool:
    text = " ".join(expression.split())
    if _slot_access(text, slot, key):
        return True
    if depth >= 2:
        return False
    calls = [item for item in plain_calls(text) if item[2] == 0]
    if len(calls) != 1:
        return False
    name, arguments, _offset = calls[0]
    if not _call_is_whole_expression(text, name):
        return False
    callee = _unique(model, function.contract, name, len(arguments))
    if callee is None or not callee.has_body:
        return False
    forwarded = _forwarded_key(function, callee, arguments, key)
    if key and not forwarded:
        return False
    return _returns_slot(model, callee, slot, forwarded)


def _call_is_whole_expression(expression: str, name: str) -> bool:
    """True when ``expression`` is one call, not that call plus more arithmetic."""
    from app.parsing.solidity_research import match_close, skeleton

    skel = skeleton(expression)
    if not skel.startswith(name):
        return False
    open_at = skel.find("(")
    if open_at < 0:
        return False
    close = match_close(skel, open_at)
    return close == len(skel) - 1


def _forwarded_key(
    function: RFunction, callee: RFunction, arguments: tuple[str, ...], key: str
) -> str:
    if not key:
        return ""
    for index, param in enumerate(callee.params):
        if index >= len(arguments) or not param.name:
            continue
        argument = " ".join(arguments[index].split())
        if argument == key and _is_address(param.type_name):
            return param.name
        if key == "msg.sender" and argument == "msg.sender" and _is_address(param.type_name):
            return param.name
    del function
    return ""


def _slot_access(expression: str, slot: Slot, key: str) -> bool:
    text = expression.replace(" ", "")
    if slot.kind == "scalar":
        return bool(re.search(rf"(?:^|[^.\w])(?:\w+\.)?{re.escape(slot.field)}$", text))
    if not key:
        return False
    key_text = "msg.sender" if key == "msg.sender" else key
    pattern = rf"(?:\w+\.)?{re.escape(slot.field)}\[{re.escape(key_text)}\](?:[+\-].*)?$"
    return re.search(pattern, text) is not None


def _public_mapping(model: ResearchModel, contract: str, slot: Slot) -> str:
    if slot.kind != "state":
        return ""
    for owner in model.lineage(contract):
        item = model.contracts.get(owner)
        if item is None:
            continue
        if dict(item.state_vars).get(slot.field) is None:
            continue
        if re.search(rf"\bpublic\b[^;{{}}]*\b{re.escape(slot.field)}\s*[;=]", item.body):
            return f"{slot.field}(address)"
    return ""


def _view_shape(function: RFunction) -> bool:
    if (
        not function.exposed
        or function.kind != "function"
        or function.mutability not in {"view", "pure"}
        or not function.has_body
        or len(function.returns) != 1
    ):
        return False
    return _UINT.fullmatch(function.returns[0].type_name.replace(" ", "")) is not None


def _address_param(function: RFunction) -> str:
    names = [param.name for param in function.params if param.name and _is_address(param.type_name)]
    if len(names) != 1:
        return ""
    return names[0]


def _return_exprs(body: str) -> list[str]:
    return [item.strip() for item in re.findall(r"\breturn\b([^;]*);", body)]


def _statement(body: str, offset: int) -> str:
    start = body.rfind(";", 0, offset) + 1
    end = body.find(";", offset)
    return body[start:] if end < 0 else body[start:end]


def _signature(function: RFunction) -> str:
    types: list[str] = []
    for param in function.params:
        kind = _abi(param.type_name)
        if not kind:
            return ""
        types.append(kind)
    return f"{function.name}({','.join(types)})"


def _abi(type_name: str) -> str:
    text = type_name.replace(" ", "").replace("payable", "")
    if text == "uint":
        return "uint256"
    if text == "int":
        return "int256"
    if _UINT.fullmatch(text) or text in {"address", "bool"}:
        return "uint256" if text == "uint" else text
    return ""


def _unique(model: ResearchModel, contract: str, name: str, arity: int) -> RFunction | None:
    found = [
        item
        for item in model.functions_of(contract)
        if item.kind == "function"
        and item.name == name
        and len(item.params) == arity
        and item.has_body
    ]
    if len(found) == 1:
        return found[0]
    return None


def _resolve(model: ResearchModel, contract: str, signature: str) -> RFunction | None:
    for function in model.functions_of(contract):
        if function.signature == signature and function.has_body:
            return function
    return None


def _is_address(type_name: str) -> bool:
    return _ADDRESS.fullmatch(type_name.replace(" ", "")) is not None


def _is_uint(type_name: str) -> bool:
    text = type_name.replace(" ", "")
    return text == "uint" or _UINT.fullmatch(text) is not None
