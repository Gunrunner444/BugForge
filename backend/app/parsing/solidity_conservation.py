"""Conservation hypotheses derived from a contract's own token custody.

These are not defect patterns. A contract whose external entry pulls a token from
its caller and credits an account slot keyed by that caller, and whose other entry
reads that slot and pays the same token back to the caller, has a value
conservation property that execution can judge: after depositing and withdrawing
its credit, the caller must not hold more of the token than it started with, even
when another depositor's funds are in custody.

The custody walk is interprocedural and bounded. From each external entry it
follows internal and library calls that resolve to exactly one function, binding
callee parameters to what the caller passed. ``msg.sender`` is tracked through
those parameters by value flow, never by parameter name. A token is identified by
the expression that reaches the transfer receiver: a state variable (with its
constructor source when one assigns it), or an entry argument, optionally pinned
to a state variable by an equality guard on the path. Similar names are not
evidence. Storage is field-sensitive: ``m[k]``, ``m[k].f``, storage references,
memory copies written back whole, and storage-reference helpers are each
attributed to a mapping, its key values, and a field.

Limits are explicit (depth, visits per entry, entries per contract, pairs per
contract). A limit that was hit, an overload that does not resolve uniquely, or a
struct write whose fields are unknown leaves the trace incomplete. Incomplete is
reported; it is never read as safe.

The candidate is emitted on safe and unsafe contracts alike. Only an executed
round trip distinguishes them, so emission alone carries no defect signal and the
confidence stays ``low``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, replace
from typing import Any

from app.parsing.solidity_research import (
    ResearchModel,
    RFunction,
    SemanticCandidate,
    cap,
    match_close,
    member_calls,
    plain_calls,
    skeleton,
    split_top,
)

FAMILY = "conservation"
DETECTOR = "conservation.round_trip_value"
MAX_PAIRS_PER_CONTRACT = 4
MAX_TRACE_DEPTH = 6  # helper call edges below the entry
MAX_TRACE_VISITS = 48  # function visits per entry
MAX_ENTRIES_PER_CONTRACT = 64
_PULL = frozenset({"transferFrom", "safeTransferFrom"})
_PAY = frozenset({"transfer", "safeTransfer"})
_ASSIGN = r"(?:\+=|-=|\*=|/=|\|=|&=|<<=|>>=|=(?!=)|\+\+|--)"
_NOT_TYPES = frozenset({"return", "emit", "delete", "else", "revert", "require", "new"})


@dataclass(frozen=True)
class Sym:
    """What an expression denotes for the custody walk."""

    kind: str  # caller | this | arg | state | slot | unknown
    name: str = ""
    keys: tuple[Sym, ...] = ()
    storage: bool = False  # a slot that is a storage reference, not a memory copy
    # Fields the caller assigned on a memory copy before passing it to a helper.
    written: tuple[str, ...] = ()

    def label(self) -> str:
        if self.kind == "caller":
            return "msg.sender"
        if self.kind == "this":
            return "address(this)"
        if self.kind == "arg":
            return f"argument {self.name}"
        if self.kind == "state":
            return self.name
        if self.kind == "slot":
            return f"{self.name}[{']['.join(key.label() for key in self.keys)}]"
        return "unknown"


CALLER = Sym("caller")
THIS = Sym("this")
UNKNOWN = Sym("unknown")


@dataclass(frozen=True)
class Guard:
    """An equality between an entry argument and a state variable on the path."""

    argument: str
    state: str
    equal: bool
    site: str


@dataclass(frozen=True)
class Transfer:
    direction: str  # pull | pay
    token: Sym
    amount: Sym
    site: str
    path: tuple[str, ...]
    guards: tuple[Guard, ...]


@dataclass(frozen=True)
class Access:
    write: bool
    mapping: str
    keys: tuple[Sym, ...]
    field: str  # "" for an elementary value, "*" when the written fields are unknown
    verified: bool  # the field is declared on the mapping's value struct
    site: str
    path: tuple[str, ...]
    guards: tuple[Guard, ...] = ()


@dataclass(frozen=True)
class AmountSource:
    """``target = getter(account)`` on a payout path: the getter sizes the payout."""

    getter: str
    account: Sym
    target: Sym
    site: str


@dataclass
class EntryTrace:
    entry: RFunction
    transfers: list[Transfer] = field(default_factory=list)
    accesses: list[Access] = field(default_factory=list)
    amount_sources: list[AmountSource] = field(default_factory=list)
    visited: list[str] = field(default_factory=list)
    state_reads: set[str] = field(default_factory=set)
    incomplete: list[str] = field(default_factory=list)
    truncated: bool = False


@dataclass(frozen=True)
class CustodyPair:
    contract: str
    deposit: RFunction
    payout: RFunction
    pull: Transfer
    pay: Transfer
    mapping: str
    keys: str
    fields: tuple[str, ...]
    credit_field: str
    write_site: str
    read_site: str
    token_label: str
    token_binding: str
    token_source: str
    deposit_token_argument: str
    payout_token_argument: str
    token_must_differ_from: str
    deposit_amount_argument: str
    payout_amount_argument: str
    getter: str
    getter_basis: str
    initializer: str
    initializer_basis: str
    caller_flow: str
    incomplete: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "contract": self.contract,
            "deposit": self.deposit.signature,
            "payout": self.payout.signature,
            "pull_site": self.pull.site,
            "pull_path": list(self.pull.path),
            "pay_site": self.pay.site,
            "pay_path": list(self.pay.path),
            "credit": f"{self.mapping}[{self.keys}]",
            "fields": list(self.fields),
            "credit_field": self.credit_field,
            "write_site": self.write_site,
            "read_site": self.read_site,
            "token": self.token_label,
            "token_binding": self.token_binding,
            "token_source": self.token_source,
            "deposit_token_argument": self.deposit_token_argument,
            "payout_token_argument": self.payout_token_argument,
            "token_must_differ_from": self.token_must_differ_from,
            "deposit_amount_argument": self.deposit_amount_argument,
            "payout_amount_argument": self.payout_amount_argument,
            "getter": self.getter,
            "getter_basis": self.getter_basis,
            "initializer": self.initializer,
            "initializer_basis": self.initializer_basis,
            "caller_flow": self.caller_flow,
            "incomplete": list(self.incomplete),
        }


def _compound(op: re.Match[str] | None) -> bool:
    """A read-modify-write: ``+=``, ``-=``, ``++`` and the like, not a plain ``=``."""
    return op is None or op.group(1) != "="


def _site(function: RFunction, offset: int) -> str:
    line = function.line + function.body[:offset].count("\n")
    return f"{function.file}:{line} {function.contract}.{function.name}"


def _mutating(function: RFunction) -> bool:
    return (
        function.has_body
        and function.exposed
        and function.kind == "function"
        and function.mutability not in {"view", "pure"}
    )


def _mapping_value(type_name: str, depth: int) -> str:
    """The value type after ``depth`` lookups into a mapping type, or ""."""
    text = type_name.replace(" ", "")
    for _ in range(depth):
        match = re.fullmatch(r"mapping\((?:[^=]+?)=>(.+)\)", text)
        if match is None:
            return ""
        text = match.group(1)
    return text


def _statement_end(skel: str, index: int) -> int:
    """End offset of the statement starting at ``index`` (if/else chains included)."""
    while index < len(skel) and skel[index].isspace():
        index += 1
    if index >= len(skel):
        return len(skel)
    if skel[index] == "{":
        close = match_close(skel, index)
        return len(skel) if close == -1 else close
    head = re.match(r"if\s*\(", skel[index:])
    if head:
        open_at = index + head.end() - 1
        close = match_close(skel, open_at)
        if close == -1:
            return len(skel)
        end = _statement_end(skel, close + 1)
        rest = re.match(r"\s*else\b", skel[end + 1 :])
        if rest:
            return _statement_end(skel, end + 1 + rest.end())
        return end
    stop = skel.find(";", index)
    return len(skel) if stop == -1 else stop


def _comparisons(condition: str) -> list[tuple[str, str, bool]]:
    found: list[tuple[str, str, bool]] = []
    for part in split_top(condition, "&"):
        part = part.strip("& ")
        match = re.fullmatch(r"(.+?)\s*(?<![<>=!])(==|!=)\s*(.+)", part, re.S)
        if match:
            found.append((match.group(1).strip(), match.group(3).strip(), match.group(2) == "=="))
    return found


def _regions(skel: str, body: str) -> list[tuple[int, int, str, bool]]:
    """(start, end, condition, holds) spans over which a condition is known."""
    regions: list[tuple[int, int, str, bool]] = []
    for match in re.finditer(r"\bif\s*\(", skel):
        open_at = match.end() - 1
        close = match_close(skel, open_at)
        if close == -1:
            continue
        condition = body[open_at + 1 : close]
        start = close + 1
        end = _statement_end(skel, start)
        regions.append((start, end, condition, True))
        if re.match(r"\s*\{?\s*revert\b", skel[start:end]):
            regions.append((end, len(skel), condition, False))
        rest = re.match(r"\s*else\b", skel[end + 1 :])
        if rest:
            other = end + 1 + rest.end()
            regions.append((other, _statement_end(skel, other), condition, False))
    for match in re.finditer(r"\brequire\s*\(", skel):
        open_at = match.end() - 1
        close = match_close(skel, open_at)
        if close == -1:
            continue
        arguments = split_top(body[open_at + 1 : close])
        if arguments:
            regions.append((close, len(skel), arguments[0], True))
    return regions


class _Walker:
    def __init__(self, model: ResearchModel, contract: str) -> None:
        self.model = model
        self.contract = contract
        self.state = model.state_vars(contract)
        self.libraries = {name for name, item in model.contracts.items() if item.kind == "library"}
        self._by_name: dict[str, dict[str, list[RFunction]]] = {}
        self._context: tuple[list[tuple[int, int, str, bool]], dict[str, Sym], tuple[Guard, ...]]
        self._context = ([], {}, ())

    # -- resolution ----------------------------------------------------------------------
    def _named(self, owner: str, name: str, arity: int) -> list[RFunction]:
        table = self._by_name.get(owner)
        if table is None:
            table = {}
            for function in self.model.functions_of(owner):
                if function.kind == "function" and function.has_body:
                    table.setdefault(function.name, []).append(function)
            self._by_name[owner] = table
        return [item for item in table.get(name, []) if len(item.params) == arity]

    def _is_type(self, name: str) -> bool:
        if name in {"address", "payable"} or name in self.model.contracts:
            return True
        return bool(re.fullmatch(r"I[A-Z]\w*|(?:Safe)?ERC20\w*", name))

    def value(self, expr: str, local: dict[str, Sym]) -> Sym:
        text = expr.strip()
        while text.startswith("(") and match_close(text, 0) == len(text) - 1:
            text = text[1:-1].strip()
        if text == "msg.sender":
            return CALLER
        if text in {"address(this)", "this", "payable(address(this))"}:
            return THIS
        call = re.fullmatch(r"([A-Za-z_]\w*)\s*\((.*)\)", text, re.S)
        if call and match_close(text, text.index("(")) == len(text) - 1:
            if self._is_type(call.group(1)) and not self._named(self.contract, call.group(1), 1):
                return self.value(call.group(2), local)
            return UNKNOWN
        if re.fullmatch(r"[A-Za-z_]\w*", text):
            if text in local:
                return local[text]
            if text in self.state:
                return Sym("state", text)
            return UNKNOWN
        slot = self._slot(text, local)
        return slot if slot is not None else UNKNOWN

    def _mapping_of(self, name: str, local: dict[str, Sym]) -> str:
        bound = local.get(name)
        if bound is not None:
            name = bound.name if bound.kind == "state" else ""
        elif name not in self.state:
            return ""
        return name if self.state.get(name, "").startswith("mapping") else ""

    def _slot(self, text: str, local: dict[str, Sym], storage: bool = False) -> Sym | None:
        skel = skeleton(text)
        head = re.match(r"\s*([A-Za-z_]\w*)\s*\[", skel)
        if head is None:
            return None
        mapping = self._mapping_of(head.group(1), local)
        if not mapping:
            return None
        keys, end = self._keys(skel, text, head.end() - 1)
        if skel[end:].strip():
            return None
        return Sym("slot", mapping, tuple(self.value(key, local) for key in keys), storage)

    @staticmethod
    def _keys(skel: str, body: str, index: int) -> tuple[list[str], int]:
        keys: list[str] = []
        while index < len(skel) and skel[index] == "[":
            close = match_close(skel, index)
            if close == -1:
                break
            keys.append(body[index + 1 : close])
            index = close + 1
            while index < len(skel) and skel[index].isspace():
                index += 1
        return keys, index

    def _storage_helper(self, text: str, local: dict[str, Sym]) -> Sym | None:
        """``helper(args)`` that returns a storage reference ``m[k]`` of its arguments."""
        call = re.fullmatch(r"\s*([A-Za-z_]\w*)\s*\((.*)\)\s*", text, re.S)
        if call is None:
            return None
        arguments = [item for item in split_top(call.group(2)) if item]
        callees = self._named(self.contract, call.group(1), len(arguments))
        if len(callees) != 1:
            return None
        callee = callees[0]
        env = {p.name: self.value(a, local) for p, a in zip(callee.params, arguments, strict=False)}
        returned = re.search(r"\breturn\s+([^;]+);", callee.body)
        if returned is None:
            return None
        return self._slot(returned.group(1), env, storage=True)

    # -- walk -----------------------------------------------------------------------------
    def trace(self, entry: RFunction) -> EntryTrace:
        trace = EntryTrace(entry)
        env = {p.name: Sym("arg", p.name) for p in entry.params if p.name}
        self._visit(trace, entry, env, 0, (entry.identity,), (), set())
        return trace

    def _guards(
        self,
        regions: list[tuple[int, int, str, bool]],
        offset: int,
        local: dict[str, Sym],
        site: str,
    ) -> tuple[Guard, ...]:
        found: list[Guard] = []
        for start, end, condition, holds in regions:
            if not start <= offset <= end:
                continue
            parts = _comparisons(condition)
            if not holds and len(parts) != 1:
                continue
            for left, right, equal in parts:
                a, b = self.value(left, local), self.value(right, local)
                if a.kind == "state" and b.kind == "arg":
                    a, b = b, a
                if a.kind == "arg" and b.kind == "state":
                    found.append(Guard(a.name, b.name, equal if holds else not equal, site))
        return tuple(found)

    def _visit(
        self,
        trace: EntryTrace,
        function: RFunction,
        env: dict[str, Sym],
        depth: int,
        path: tuple[str, ...],
        guards: tuple[Guard, ...],
        seen: set[tuple[Any, ...]],
    ) -> None:
        key = (function.identity, tuple(sorted(env.items(), key=lambda kv: kv[0])), guards)
        if key in seen:
            return
        if len(trace.visited) >= MAX_TRACE_VISITS:
            trace.truncated = True
            trace.incomplete.append(
                f"visit limit {MAX_TRACE_VISITS} reached before {function.identity}"
            )
            return
        seen.add(key)
        trace.visited.append(function.identity)
        owner = function.contract
        library = owner in self.libraries
        body = function.body
        skel = skeleton(body)
        local = dict(env)
        names = set(local)
        regions = _regions(skel, body)
        self._declarations(skel, body, local, names)
        for word in set(re.findall(r"(?<![\w.])([A-Za-z_]\w*)\b", skel)):
            if word in self.state and word not in names:
                trace.state_reads.add(word)
        self._context = (regions, local, guards)
        assigned = self._struct_fields(trace, function, skel, local, path)
        self._indexed(trace, function, skel, body, local, assigned, path)
        self._amount_sources(trace, function, skel, body, local)
        for call in member_calls(body):
            offset = max(call.start, 0)
            here = (*guards, *self._guards(regions, offset, local, _site(function, offset)))
            if call.name in _PULL or call.name in _PAY:
                self._transfer(trace, function, call, offset, local, path, here)
                continue
            self._library_call(trace, function, call, offset, local, depth, path, here, seen)
        for name, arguments, offset in plain_calls(body):
            prefix = skel[:offset].rstrip()
            if prefix.endswith(("emit", "revert")):
                continue
            resolve_in = owner if library else self.contract
            callees = self._named(resolve_in, name, len(arguments))
            if not callees:
                continue
            if len(callees) > 1:
                trace.incomplete.append(
                    f"{name} has {len(callees)} overloads with {len(arguments)} arguments "
                    f"at {_site(function, offset)}; not followed"
                )
                continue
            callee = callees[0]
            if callee.mutability == "pure":
                continue  # no storage access and no token transfer is possible
            if depth + 1 > MAX_TRACE_DEPTH:
                trace.truncated = True
                trace.incomplete.append(
                    f"depth limit {MAX_TRACE_DEPTH} reached at {callee.identity} "
                    f"from {_site(function, offset)}"
                )
                continue
            callee_env = {
                p.name: self._argument(a, local, assigned)
                for p, a in zip(callee.params, arguments, strict=False)
                if p.name
            }
            here = (*guards, *self._guards(regions, offset, local, _site(function, offset)))
            line = function.line + body[:offset].count("\n")
            self._visit(
                trace,
                callee,
                callee_env,
                depth + 1,
                (*path, f"{callee.identity}@{line}"),
                here,
                seen,
            )

    def _argument(self, text: str, local: dict[str, Sym], assigned: dict[str, set[str]]) -> Sym:
        """An argument's value; a memory copy keeps the fields assigned on it here."""
        sym = self.value(text, local)
        name = text.strip()
        if sym.kind == "slot" and not sym.storage and name in assigned:
            return replace(sym, written=tuple(sorted({*sym.written, *assigned[name]})))
        return sym

    def _declarations(self, skel: str, body: str, local: dict[str, Sym], names: set[str]) -> None:
        pattern = re.compile(
            r"(?:^|(?<=[;{}(]))\s*([A-Za-z_][\w.]*(?:\s*\[\s*\])?)\s+"
            r"(?:(memory|storage|calldata)\s+)?([A-Za-z_]\w*)\s*(=|;)"
        )
        for match in pattern.finditer(skel):
            type_word, location, name, op = match.groups()
            if type_word in _NOT_TYPES:
                continue
            names.add(name)
            if op == ";":
                local[name] = UNKNOWN
                continue
            stop = skel.find(";", match.end())
            rhs = body[match.end() : stop if stop != -1 else len(body)]
            sym: Sym | None = None
            if location in {"storage", "memory"}:
                sym = self._slot(rhs, local, storage=location == "storage")
                if sym is None and location == "storage":
                    sym = self._storage_helper(rhs, local)
            local[name] = sym if sym is not None else self.value(rhs, local)

    def _struct_fields(
        self,
        trace: EntryTrace,
        function: RFunction,
        skel: str,
        local: dict[str, Sym],
        path: tuple[str, ...],
    ) -> dict[str, set[str]]:
        """Field writes on memory copies (returned) and field accesses on slot locals."""
        assigned: dict[str, set[str]] = {}
        for match in re.finditer(r"(?<![\w.])([A-Za-z_]\w*)\s*\.\s*([A-Za-z_]\w*)\b", skel):
            sym = local.get(match.group(1))
            if sym is None or sym.kind != "slot":
                continue
            tail = skel[match.end() :]
            if re.match(r"\s*\(", tail):
                continue
            op = re.match(rf"\s*({_ASSIGN})", tail)
            write = bool(op) or bool(re.search(r"(?:\+\+|--|\bdelete)\s*$", skel[: match.start()]))
            if write and not sym.storage:
                assigned.setdefault(match.group(1), set()).add(match.group(2))
                continue
            if write and _compound(op):
                self._record(trace, function, match.start(), False, sym, match.group(2), path)
            self._record(trace, function, match.start(), write, sym, match.group(2), path)
        return assigned

    def _record(
        self,
        trace: EntryTrace,
        function: RFunction,
        offset: int,
        write: bool,
        slot: Sym,
        name: str,
        path: tuple[str, ...],
    ) -> None:
        regions, local, inherited = self._context
        site = _site(function, offset)
        guards = (*inherited, *self._guards(regions, offset, local, site))
        value_type = _mapping_value(self.state.get(slot.name, ""), len(slot.keys))
        fields = self.model.struct_fields(value_type) if value_type else None
        if name in {"", "*"}:
            verified = fields is None and bool(value_type) and name == ""
        else:
            verified = fields is not None and any(item.name == name for item in fields)
        trace.accesses.append(
            Access(write, slot.name, slot.keys, name, verified, site, path, guards)
        )

    def _indexed(
        self,
        trace: EntryTrace,
        function: RFunction,
        skel: str,
        body: str,
        local: dict[str, Sym],
        assigned: dict[str, set[str]],
        path: tuple[str, ...],
    ) -> None:
        for match in re.finditer(r"(?<![\w.])([A-Za-z_]\w*)\s*\[", skel):
            mapping = self._mapping_of(match.group(1), local)
            if not mapping:
                continue
            keys_text, index = self._keys(skel, body, match.end() - 1)
            slot = Sym("slot", mapping, tuple(self.value(key, local) for key in keys_text))
            fields: list[str] = []
            while True:
                found = re.match(r"\s*\.\s*([A-Za-z_]\w*)\b(?!\s*\()", skel[index:])
                if found is None:
                    break
                fields.append(found.group(1))
                index += found.end()
            op = re.match(rf"\s*({_ASSIGN})", skel[index:])
            write = bool(op) or bool(re.search(r"(?:\+\+|--|\bdelete)\s*$", skel[: match.start()]))
            if write and _compound(op):
                self._record(
                    trace, function, match.start(), False, slot, fields[0] if fields else "", path
                )
            if fields:
                self._record(trace, function, match.start(), write, slot, fields[0], path)
                continue
            value_type = _mapping_value(self.state.get(mapping, ""), len(slot.keys))
            struct = self.model.struct_fields(value_type) if value_type else None
            if write and op and op.group(1) == "=" and struct is not None:
                stop = skel.find(";", index)
                rhs = body[index + op.end() : stop if stop != -1 else len(body)].strip()
                copied = local.get(rhs)
                written = assigned.get(rhs) or (
                    set(copied.written) if copied is not None and copied.kind == "slot" else set()
                )
                if not written:
                    trace.incomplete.append(
                        f"{mapping}[...] is written whole at {_site(function, match.start())} "
                        "with fields the walk cannot attribute"
                    )
                    self._record(trace, function, match.start(), True, slot, "*", path)
                    continue
                for name in sorted(written):
                    self._record(trace, function, match.start(), True, slot, name, path)
                continue
            if struct is not None and not write:
                continue  # a whole-struct read is attributed through the local it is copied to
            self._record(trace, function, match.start(), write, slot, "", path)

    def _amount_sources(
        self, trace: EntryTrace, function: RFunction, skel: str, body: str, local: dict[str, Sym]
    ) -> None:
        for match in re.finditer(
            r"(?<![\w.])([A-Za-z_]\w*)\s*=(?!=)\s*([A-Za-z_]\w*)\s*\(([^;()]*)\)\s*;", skel
        ):
            arguments = [item for item in split_top(body[match.start(3) : match.end(3)]) if item]
            if len(arguments) != 1:
                continue
            callees = self._named(self.contract, match.group(2), 1)
            if len(callees) != 1:
                continue
            getter = callees[0]
            if not getter.exposed or getter.mutability not in {"view", "pure"}:
                continue
            if getter.params[0].type_name != "address":
                continue
            trace.amount_sources.append(
                AmountSource(
                    getter.signature,
                    self.value(arguments[0], local),
                    self.value(match.group(1), local),
                    _site(function, match.start()),
                )
            )

    def _transfer(
        self,
        trace: EntryTrace,
        function: RFunction,
        call: Any,
        offset: int,
        local: dict[str, Sym],
        path: tuple[str, ...],
        guards: tuple[Guard, ...],
    ) -> None:
        arguments = list(call.arguments)
        receiver = call.receiver
        via_library = receiver.split(".")[-1] in self.libraries or receiver in self.libraries
        if via_library and arguments:
            token, arguments = self.value(arguments[0], local), arguments[1:]
        else:
            token = self.value(receiver, local)
        site = _site(function, offset)
        if call.name in _PULL and len(arguments) == 3:
            source, destination, amount = (self.value(item, local) for item in arguments)
            if source == CALLER and destination == THIS:
                trace.transfers.append(Transfer("pull", token, amount, site, path, guards))
        elif call.name in _PAY and len(arguments) == 2:
            destination, amount = (self.value(item, local) for item in arguments)
            if destination == CALLER:
                trace.transfers.append(Transfer("pay", token, amount, site, path, guards))

    def _library_call(
        self,
        trace: EntryTrace,
        function: RFunction,
        call: Any,
        offset: int,
        local: dict[str, Sym],
        depth: int,
        path: tuple[str, ...],
        guards: tuple[Guard, ...],
        seen: set[tuple[Any, ...]],
    ) -> None:
        receiver = call.receiver.strip()
        arguments = [item for item in call.arguments if item]
        callees: list[RFunction] = []
        bound: list[Sym] = []
        if receiver in self.libraries:
            callees = self._named(receiver, call.name, len(arguments))
            bound = [self.value(item, local) for item in arguments]
        else:
            attached = [
                item
                for library in sorted(self.libraries)
                for item in self._named(library, call.name, len(arguments) + 1)
            ]
            if not attached:
                return
            if re.fullmatch(r"[A-Za-z_]\w*", receiver):
                target: Sym | None = self.value(receiver, local)
            else:
                target = self._slot(receiver, local, storage=True) or self._storage_helper(
                    receiver, local
                )
            if target is None:
                trace.incomplete.append(
                    f"library call {call.name} on {receiver[:60]} at {_site(function, offset)}: "
                    "the receiver is not a resolvable storage reference; not followed"
                )
                return
            callees = attached
            bound = [target, *(self.value(a, local) for a in arguments)]
        if not callees:
            return
        if len(callees) > 1:
            trace.incomplete.append(
                f"{call.name} resolves to {len(callees)} library functions at "
                f"{_site(function, offset)}; not followed"
            )
            return
        callee = callees[0]
        if callee.mutability == "pure":
            return
        if depth + 1 > MAX_TRACE_DEPTH:
            trace.truncated = True
            trace.incomplete.append(f"depth limit {MAX_TRACE_DEPTH} reached at {callee.identity}")
            return
        env = {p.name: value for p, value in zip(callee.params, bound, strict=False) if p.name}
        line = function.line + function.body[:offset].count("\n")
        self._visit(
            trace, callee, env, depth + 1, (*path, f"{callee.identity}@{line}"), guards, seen
        )


# ---- pairing ----------------------------------------------------------------------------------


def _feasible(guards: tuple[Guard, ...]) -> bool:
    facts: dict[tuple[str, str], bool] = {}
    for guard in guards:
        key = (guard.argument, guard.state)
        if facts.setdefault(key, guard.equal) != guard.equal:
            return False
    return True


def _token_binding(transfer: Transfer) -> tuple[str, str, str]:
    """(identity, token argument, must differ from) for a transfer's token."""
    token = transfer.token
    if token.kind == "state":
        argument = next(
            (g.argument for g in transfer.guards if g.state == token.name and g.equal), ""
        )
        return f"state:{token.name}", argument, ""
    if token.kind == "arg":
        bound = next((g.state for g in transfer.guards if g.argument == token.name and g.equal), "")
        if bound:
            return f"state:{bound}", token.name, ""
        differs = ",".join(
            sorted({g.state for g in transfer.guards if g.argument == token.name and not g.equal})
        )
        return "argument", token.name, differs
    return "", "", ""


def _token_source(model: ResearchModel, contract: str, name: str) -> str:
    """How the constructor assigns a state token, from source only."""
    ctor = next(
        (f for f in model.functions_of(contract) if f.kind == "constructor" and f.has_body), None
    )
    if ctor is None:
        return "not assigned by a constructor"
    match = re.search(rf"(?<![\w.]){re.escape(name)}\s*=(?!=)\s*([^;]+);", ctor.body)
    if match is None:
        return "not assigned by the constructor"
    rhs = match.group(1).strip()
    params = {p.name: p for p in ctor.params}
    direct = re.fullmatch(r"(?:\w+\s*\()?\s*([A-Za-z_]\w*)\s*\)?", rhs)
    if direct and direct.group(1) in params:
        return f"constructor parameter {direct.group(1)}"
    member = re.fullmatch(r"(?:\w+\s*\()?\s*([A-Za-z_]\w*)\.([A-Za-z_]\w*)\s*\)?", rhs)
    if member and member.group(1) in params:
        fields = model.struct_fields(params[member.group(1)].type_name)
        if fields is not None and any(item.name == member.group(2) for item in fields):
            return f"constructor struct field {member.group(1)}.{member.group(2)}"
        return f"constructor expression {rhs[:80]} (field not verified)"
    return f"constructor expression {rhs[:80]}"


def _getter(
    model: ResearchModel,
    contract: str,
    walker: _Walker,
    payout: EntryTrace,
    pay: Transfer,
    mapping: str,
    fields: tuple[str, ...],
) -> tuple[str, str, str]:
    """(getter, basis, field) that reports the payout amount for the caller, or empty."""
    for source in payout.amount_sources:
        if source.account != CALLER or source.target != pay.amount or pay.amount.kind != "arg":
            continue
        function = next(
            (f for f in model.functions_of(contract) if f.signature == source.getter), None
        )
        if function is None:
            continue
        traced = walker.trace(function)
        param = Sym("arg", function.params[0].name)
        read = next(
            (
                item
                for item in traced.accesses
                if not item.write
                and item.mapping == mapping
                and item.keys[:1] == (param,)
                and item.field in fields
            ),
            None,
        )
        if read is not None:
            return (
                source.getter,
                f"the payout sizes its amount from {source.getter} at {source.site}, which "
                f"reads {mapping}[account].{read.field or '(value)'} at {read.site}",
                read.field,
            )
    from_field = fields[0] if len(fields) == 1 else ""
    value_type = _mapping_value(walker.state.get(mapping, ""), 1)
    public = re.search(
        rf"\bpublic\b[^;{{}}]*\b{re.escape(mapping)}\s*;",
        "".join(
            item.body for item in model.contracts.values() if item.name in model.lineage(contract)
        ),
    )
    if (
        public
        and from_field == ""
        and re.fullmatch(r"mapping\(address=>u?int\d*\)", walker.state.get(mapping, ""))
        and re.fullmatch(r"u?int\d*", value_type)
    ):
        return f"{mapping}(address)", f"the public getter of {mapping}", ""
    return "", "", from_field


def _initializer(
    model: ResearchModel, contract: str, reads: set[str]
) -> tuple[str, str, tuple[str, ...]]:
    """A permissionless one-time function that sets state the round trip reads."""
    state = model.state_vars(contract)
    ctor = next(
        (f for f in model.functions_of(contract) if f.kind == "constructor" and f.has_body), None
    )
    ctor_writes = {
        name
        for name in state
        if ctor is not None and re.search(rf"(?<![\w.]){re.escape(name)}\s*=(?!=)", ctor.body)
    }
    found: list[tuple[RFunction, str, tuple[str, ...]]] = []
    for function in model.functions_of(contract):
        if not _mutating(function) or function.params:
            continue
        skel = skeleton(function.body)
        once = re.search(r"if\s*\(\s*([A-Za-z_]\w*)\s*!=\s*0\s*\)\s*revert\b", skel) or re.search(
            r"require\s*\(\s*([A-Za-z_]\w*)\s*==\s*0\b", skel
        )
        if once is None or once.group(1) not in state:
            continue
        if re.search(r"msg\.sender|onlyOwner|onlyRole|_checkOwner", skel) or function.modifiers:
            continue
        writes = tuple(
            sorted(
                name for name in state if re.search(rf"(?<![\w.]){re.escape(name)}\s*=(?!=)", skel)
            )
        )
        if once.group(1) not in writes:
            continue
        relevant = tuple(name for name in writes if name in reads and name not in ctor_writes)
        if relevant:
            found.append((function, once.group(1), relevant))
    if len(found) != 1:
        return "", "", ()
    function, flag, relevant = found[0]
    return (
        function.signature,
        f"{function.signature} is permissionless, runs once (guarded by {flag}), and sets "
        f"{', '.join(relevant)}, which the round trip reads and the constructor does not set",
        relevant,
    )


def _caller_flow(path: tuple[str, ...]) -> str:
    return " > ".join(item.split(".", 1)[-1] for item in path)


def custody_pairs(model: ResearchModel, contract: str) -> tuple[list[CustodyPair], list[str]]:
    """Deposit/payout pairs that share a caller-keyed credit slot and a token."""
    notes: list[str] = []
    walker = _Walker(model, contract)
    entries = [item for item in model.functions_of(contract) if _mutating(item)]
    if len(entries) > MAX_ENTRIES_PER_CONTRACT:
        notes.append(
            f"{contract}: only {MAX_ENTRIES_PER_CONTRACT} of {len(entries)} entries were traced"
        )
        entries = entries[:MAX_ENTRIES_PER_CONTRACT]
    traces = [walker.trace(entry) for entry in entries]
    for trace in traces:
        notes.extend(f"{trace.entry.identity}: {item}" for item in trace.incomplete[:8])
    best: dict[tuple[str, str], CustodyPair] = {}
    alternatives: dict[tuple[str, str], int] = {}
    for deposit in traces:
        pulls = [t for t in deposit.transfers if t.direction == "pull" and _feasible(t.guards)]
        writes = [a for a in deposit.accesses if a.write and a.keys[:1] == (CALLER,)]
        if not pulls or not writes:
            continue
        for payout in traces:
            if payout.entry.signature == deposit.entry.signature:
                continue
            pays = [t for t in payout.transfers if t.direction == "pay" and _feasible(t.guards)]
            reads = [a for a in payout.accesses if not a.write and a.keys[:1] == (CALLER,)]
            for pull in pulls:
                identity, deposit_arg, differs = _token_binding(pull)
                if not identity:
                    continue
                for pay in pays:
                    pay_identity, payout_arg, pay_differs = _token_binding(pay)
                    if pay_identity != identity:
                        continue
                    pair = _pair(
                        model, contract, walker, deposit, payout, pull, pay, writes, reads,
                        identity, deposit_arg, payout_arg, differs or pay_differs,
                    )  # fmt: skip
                    if pair is None:
                        continue
                    key = (deposit.entry.signature, payout.entry.signature)
                    alternatives[key] = alternatives.get(key, 0) + 1
                    current = best.get(key)
                    if current is None or _rank(pair) < _rank(current):
                        best[key] = pair
    pairs = sorted(best.values(), key=lambda p: (p.deposit.line, p.payout.line))
    for key, count in alternatives.items():
        if count > 1:
            notes.append(
                f"{contract}.{key[0]} / {key[1]}: {count} custody paths; the one with a "
                "state-bound token is kept"
            )
    if len(pairs) > MAX_PAIRS_PER_CONTRACT:
        notes.append(
            f"{contract}: {len(pairs)} custody pairs, only {MAX_PAIRS_PER_CONTRACT} are emitted"
        )
    return pairs[:MAX_PAIRS_PER_CONTRACT], notes


def _rank(pair: CustodyPair) -> tuple[int, int, str]:
    return (
        0 if pair.token_binding.startswith("state:") else 1,
        len(pair.incomplete),
        pair.mapping,
    )


def _pair(
    model: ResearchModel,
    contract: str,
    walker: _Walker,
    deposit: EntryTrace,
    payout: EntryTrace,
    pull: Transfer,
    pay: Transfer,
    writes: list[Access],
    reads: list[Access],
    identity: str,
    deposit_arg: str,
    payout_arg: str,
    differs: str,
) -> CustodyPair | None:
    def compatible(write: Access, read: Access) -> bool:
        if write.mapping != read.mapping or len(write.keys) != len(read.keys):
            return False
        for left, right in zip(write.keys[1:], read.keys[1:], strict=True):
            if left == right:
                continue
            if left.kind == right.kind == "arg" and left == pull.token and right == pay.token:
                continue
            return False
        return True

    matched = [
        (w, r)
        for w in writes
        for r in reads
        if compatible(w, r)
        and w.field == r.field
        and w.field != "*"
        and _feasible((*pull.guards, *w.guards))
        and _feasible((*pay.guards, *r.guards))
    ]
    if not matched:
        return None
    mapping = matched[0][0].mapping
    fields = tuple(sorted({w.field for w, _r in matched if w.mapping == mapping}))
    getter, basis, getter_field = _getter(model, contract, walker, payout, pay, mapping, fields)
    credit_field = (
        getter_field if getter_field in fields else (fields[0] if len(fields) == 1 else "")
    )
    write, read = next(
        ((w, r) for w, r in matched if w.mapping == mapping and w.field == credit_field),
        next((w, r) for w, r in matched if w.mapping == mapping),
    )
    reads_all = deposit.state_reads | payout.state_reads
    initializer, initializer_basis, _set = _initializer(model, contract, reads_all)
    token = pull.token
    if identity.startswith("state:"):
        name = identity.split(":", 1)[1]
        label = name
        source = _token_source(model, contract, name)
    else:
        label = f"argument {token.name}"
        source = "caller-chosen argument"
    incomplete = tuple(
        dict.fromkeys(
            [
                *deposit.incomplete[:4],
                *payout.incomplete[:4],
                *(
                    ["credit field is ambiguous: " + ",".join(fields)]
                    if not credit_field and fields != ("",)
                    else []
                ),
            ]
        )
    )
    keys = "][".join("caller" if key == CALLER else key.label() for key in write.keys)
    return CustodyPair(
        contract=contract,
        deposit=deposit.entry,
        payout=payout.entry,
        pull=pull,
        pay=pay,
        mapping=mapping,
        keys=keys,
        fields=fields,
        credit_field=credit_field,
        write_site=write.site,
        read_site=read.site,
        token_label=label,
        token_binding=identity,
        token_source=source,
        deposit_token_argument=deposit_arg,
        payout_token_argument=payout_arg,
        token_must_differ_from=differs,
        deposit_amount_argument=pull.amount.name if pull.amount.kind == "arg" else "",
        payout_amount_argument=pay.amount.name if pay.amount.kind == "arg" else "",
        getter=getter,
        getter_basis=basis,
        initializer=initializer,
        initializer_basis=initializer_basis,
        caller_flow=_caller_flow(pull.path),
        incomplete=incomplete,
    )


def custody_pair(
    model: ResearchModel, contract: str, deposit: str, payout: str
) -> CustodyPair | None:
    """The traced pair for two signatures, re-derived from the model alone."""
    pairs, _notes = custody_pairs(model, contract)
    return next(
        (p for p in pairs if p.deposit.signature == deposit and p.payout.signature == payout), None
    )


def custody_report(model: ResearchModel) -> dict[str, Any]:
    """Every traced pair and every reason a trace stayed incomplete."""
    contracts: dict[str, Any] = {}
    for name in sorted(model.contracts):
        if model.contracts[name].kind != "contract":
            continue
        pairs, notes = custody_pairs(model, name)
        if pairs or notes:
            contracts[name] = {"pairs": [p.as_dict() for p in pairs], "incomplete": notes[:32]}
    return {
        "limits": {
            "depth": MAX_TRACE_DEPTH,
            "visits_per_entry": MAX_TRACE_VISITS,
            "entries_per_contract": MAX_ENTRIES_PER_CONTRACT,
            "pairs_per_contract": MAX_PAIRS_PER_CONTRACT,
        },
        "contracts": contracts,
        "incomplete_is_not_safe": True,
    }


def analyze_conservation(model: ResearchModel) -> list[SemanticCandidate]:
    found: list[SemanticCandidate] = []
    for name in sorted(model.contracts):
        if model.contracts[name].kind != "contract":
            continue
        pairs, _notes = custody_pairs(model, name)
        for pair in pairs:
            found.append(_candidate(pair))
    return cap(found)


def _candidate(pair: CustodyPair) -> SemanticCandidate:
    deposit, payout = pair.deposit, pair.payout
    credit = f"{pair.mapping}[{pair.keys}]" + (f".{pair.credit_field}" if pair.credit_field else "")
    helper = len(pair.pull.path) > 1 or len(pair.pay.path) > 1
    facts: list[tuple[str, str]] = [
        ("hypothesis_basis", "token_custody"),
        ("credit_mapping", pair.mapping),
        ("credit_field", pair.credit_field),
        ("credit_fields", ",".join(pair.fields)),
        ("payout_function", payout.signature),
        ("token", pair.token_label),
        ("token_binding", pair.token_binding),
        ("token_source", pair.token_source),
        ("deposit_token_argument", pair.deposit_token_argument),
        ("payout_token_argument", pair.payout_token_argument),
        ("token_must_differ_from", pair.token_must_differ_from),
        ("deposit_amount_argument", pair.deposit_amount_argument),
        ("payout_amount_argument", pair.payout_amount_argument),
        ("credit_getter", pair.getter),
        ("credit_getter_basis", pair.getter_basis[:300]),
        ("initializer", pair.initializer),
        ("initializer_basis", pair.initializer_basis[:300]),
        ("pull_site", pair.pull.site),
        ("pay_site", pair.pay.site),
        ("credit_write_site", pair.write_site),
        ("credit_read_site", pair.read_site),
        ("deposit_path", " > ".join(pair.pull.path)[:400]),
        ("payout_path", " > ".join(pair.pay.path)[:400]),
        ("helper_mediated", "true" if helper else "false"),
        ("trace_incomplete", "; ".join(pair.incomplete)[:400]),
    ]
    return SemanticCandidate(
        detector=DETECTOR,
        family=FAMILY,
        title="A deposit and full withdrawal must conserve the caller's value",
        summary=(
            f"{pair.contract}.{deposit.name} pulls `{pair.token_label}` from msg.sender "
            f"(at {pair.pull.site}) and credits `{credit}` (at {pair.write_site}); "
            f"{payout.name} reads that credit (at {pair.read_site}) and pays "
            f"`{pair.token_label}` to msg.sender (at {pair.pay.site}). Hypothesis: a caller "
            "that deposits and withdraws its credit ends with no more tokens than it started "
            "with while another depositor's funds are in custody. This is a property to "
            "test, not a suspected defect."
        ),
        file=deposit.file,
        line=deposit.line,
        contract=pair.contract,
        function=deposit.signature,
        path=(deposit.identity, payout.identity),
        facts=tuple(facts),
        observed=(
            f"{deposit.name} pulls {pair.token_label} from msg.sender via "
            f"{_caller_flow(pair.pull.path)}",
            f"{deposit.name} writes {credit}",
            f"{payout.name} reads {credit} and pays {pair.token_label} to msg.sender via "
            f"{_caller_flow(pair.pay.path)}",
        ),
        missing=(
            "an executed round trip with another depositor's funds in custody",
            *(
                ("a complete trace: " + "; ".join(pair.incomplete)[:200],)
                if pair.incomplete
                else ()
            ),
        ),
        confidence="low",
        impact_tags=("value_transfer", "custody", "vault_accounting"),
    )
