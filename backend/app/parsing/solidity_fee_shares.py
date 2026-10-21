"""Source-backed fee-share recognition.

The formula is the one the source structure establishes: profit is the increase in
the stored asset total, that profit converts to shares with the source's
down-rounding conversion (supply 0 yields the asset amount), performance-fee
shares are ``profitShares * feeBps / MAX_BPS``, and protocol-fee shares are that
amount times the protocol bps over the same denominator. The remainder is the
performance recipient's shares. Locked shares are not fee shares.

A mint expression is not the specification. The judge compares observed share
deltas with this formula. Names of a particular protocol are not required.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from app.parsing.solidity_accounting import (
    FAMILY,
    _called_names,
    _lookup,
    _return_expr,
    _strip_comments,
    reported_site,
)
from app.parsing.solidity_research import ResearchModel, RFunction, SemanticCandidate

_BPS_VALUE = re.compile(r"\bconstant\s+([A-Za-z_]\w*)\s*=\s*(?:10_000|10000)\b")
_PRODUCT = re.compile(r"([A-Za-z_]\w*)=\(([^()]+)\)/([A-Za-z_]\w*)")


@dataclass(frozen=True)
class FeeShareSite:
    max_bps: int
    asset_getter: str
    supply_getter: str
    share_getter: str
    rate_getter: str
    recipient_getter: str
    protocol_factory_getter: str
    protocol_config_getter: str
    role_getter: str
    report_scope: str
    reporting_host: str
    reporting_host_evidence: str
    complete: bool
    gap: str

    @property
    def protocol_external(self) -> bool:
        return bool(self.protocol_factory_getter and self.protocol_config_getter)


def fee_share_site(model: ResearchModel, function: RFunction) -> FeeShareSite | None:
    """The fee-share shape on ``function``, or None when the shape is absent."""
    report = reported_site(model, function)
    if report is None or not report.judgeable or report.store_relation != "equal":
        return None
    const = _bps_constant(model, function.contract)
    if const is None:
        return None
    const_name, max_bps = const
    compact = re.sub(r"\s+", "", _strip_comments(function.body))
    products: list[tuple[str, str, str]] = []
    for name, expr, divisor in _PRODUCT.findall(compact):
        if divisor != const_name or "*" not in expr:
            continue
        left, right = expr.rsplit("*", 1)
        if re.fullmatch(r"[A-Za-z_]\w*", right):
            products.append((name, left, right))
    if not products:
        return None
    assignees = {name for name, _left, _right in products}
    performance = [
        right for _name, left, right in products if left not in assignees and right not in assignees
    ]
    protocol_vars = [
        right for _name, left, right in products if left in assignees and right not in assignees
    ]
    if not performance:
        return _incomplete(report, max_bps, "the performance-fee product was not found")
    if not protocol_vars:
        return _incomplete(report, max_bps, "the protocol-fee product was not found")
    rate = _rate_getter(model, function, compact, performance[0])
    supply = _supply_getter(model, function.contract)
    share = _share_getter(model, function.contract)
    protocol_factory, protocol_config = _protocol_config(model, function, compact)
    recipient = _recipient_getter(model, function, compact, protocol_factory)
    conversion = _conversion_text(model, function)
    gaps: list[str] = []
    if not rate:
        gaps.append("the performance-fee rate has no public getter")
    if not supply:
        gaps.append("totalSupply() was not found")
    elif conversion and not _linked(supply[1], conversion):
        gaps.append("totalSupply() is not the supply used by the share conversion")
        supply = None
    if not share:
        gaps.append("balanceOf(address) was not found")
    if not recipient:
        gaps.append("the performance-fee recipient has no public getter")
    if not protocol_config:
        gaps.append("the protocol-fee configuration is not a readable (uint, address) call")
    if not conversion:
        gaps.append("share conversion rounding is not established from the source")
    complete = not gaps
    return FeeShareSite(
        max_bps=max_bps,
        asset_getter=report.getter,
        supply_getter=supply[0] if supply else "",
        share_getter=share,
        rate_getter=rate,
        recipient_getter=recipient,
        protocol_factory_getter=protocol_factory,
        protocol_config_getter=protocol_config,
        role_getter=report.role_getter,
        report_scope=report.report_scope,
        reporting_host=report.host,
        reporting_host_evidence=model.reporting_host_evidence if report.host else "",
        complete=complete,
        gap="; ".join(gaps),
    )


def fee_share_candidates(model: ResearchModel, function: RFunction) -> list[SemanticCandidate]:
    site = fee_share_site(model, function)
    if site is None:
        return []
    gaps = [
        "locked-share adjustments are not judged",
        "the unlock formula is not judged",
        "a stored-total equality check does not prove this fee split",
    ]
    if site.gap:
        gaps.insert(0, site.gap)
    return [
        SemanticCandidate(
            detector="accounting.fee_shares",
            family=FAMILY,
            title="A report mints fee shares from profit",
            summary=(
                f"{function.contract}.{function.name} charges a {site.max_bps}-denominator "
                "fee on the share value of profit and can split a protocol portion of that "
                "fee. The check compares observed share deltas with that formula. "
                "It does not treat a configured recipient's shares as theft, and it does "
                "not prove the reported asset total is the right economic value."
            ),
            file=function.file,
            line=function.line,
            contract=function.contract,
            function=function.signature,
            path=(
                f"{function.contract}.{function.signature} @{function.file}:{function.line}",
                f"performance fee: {site.rate_getter or 'unresolved'}",
                f"protocol config: {site.protocol_config_getter or 'unresolved'}",
            ),
            facts=(
                ("max_bps", str(site.max_bps)),
                ("stored_getter", site.asset_getter),
                ("supply_getter", site.supply_getter),
                ("share_getter", site.share_getter),
                ("fee_rate_getter", site.rate_getter),
                ("fee_recipient_getter", site.recipient_getter),
                ("protocol_factory_getter", site.protocol_factory_getter),
                ("protocol_config_getter", site.protocol_config_getter),
                ("role_getter", site.role_getter),
                ("report_scope", site.report_scope),
                ("reporting_host", site.reporting_host),
                ("reporting_host_evidence", site.reporting_host_evidence),
                (
                    "host_dependence",
                    "observed_inputs" if site.report_scope == "host" else "",
                ),
                ("token_behavior", "unknown"),
                ("fee_complete", "true" if site.complete else "false"),
            ),
            observed=("fee shares are minted from a basis-point fraction of profit shares",),
            missing=tuple(gaps),
            confidence="medium" if site.complete else "low",
            impact_tags=("custody", "vault_accounting"),
        )
    ]


def _incomplete(report: object, max_bps: int, gap: str) -> FeeShareSite:
    role = getattr(report, "role_getter", "")
    return FeeShareSite(
        max_bps=max_bps,
        asset_getter=getattr(report, "getter", ""),
        supply_getter="",
        share_getter="",
        rate_getter="",
        recipient_getter="",
        protocol_factory_getter="",
        protocol_config_getter="",
        role_getter=role,
        report_scope=getattr(report, "report_scope", ""),
        reporting_host=getattr(report, "host", ""),
        reporting_host_evidence="",
        complete=False,
        gap=gap,
    )


def _bps_constant(model: ResearchModel, contract: str) -> tuple[str, int] | None:
    found: list[tuple[str, int]] = []
    for owner in model.lineage(contract):
        item = model.contracts.get(owner)
        if item is None:
            continue
        for match in _BPS_VALUE.finditer(_strip_comments(item.body)):
            found.append((match.group(1), 10_000))
    unique = sorted(set(found))
    if len(unique) != 1:
        return None
    return unique[0]


def _rate_getter(model: ResearchModel, function: RFunction, compact: str, ident: str) -> str:
    from app.discovery.bounty.properties import public_getter

    direct = public_getter(model, function.contract, ident)
    if direct.endswith("()") and _returns_uint(model, function.contract, direct):
        return direct
    match = re.search(rf"{re.escape(ident)}=((?:[A-Za-z_]\w*\.)*)([A-Za-z_]\w*)", compact)
    if match is None:
        return ""
    field = match.group(2)
    named = [
        item.signature
        for item in model.functions_of(function.contract)
        if item.name == field
        and item.exposed
        and not item.params
        and item.returns
        and item.returns[0].type_name.startswith("uint")
    ]
    if len(named) == 1:
        return named[0]
    getter = public_getter(model, function.contract, field)
    if getter.endswith("()") and _returns_uint(model, function.contract, getter):
        return getter
    found: list[str] = []
    for item in model.functions_of(function.contract):
        if (
            item.exposed
            and not item.params
            and item.returns
            and item.returns[0].type_name.startswith("uint")
            and item.has_body
            and re.search(rf"\b{re.escape(field)}\b", item.body)
        ):
            found.append(item.signature)
    if len(found) == 1:
        return found[0]
    return ""


def _returns_uint(model: ResearchModel, contract: str, signature: str) -> bool:
    # A public state getter has no parsed body. The state type was already checked.
    for item in model.functions_of(contract):
        if item.signature == signature and item.returns:
            return item.returns[0].type_name.startswith("uint")
    return signature.endswith("()")


def _supply_getter(model: ResearchModel, contract: str) -> tuple[str, str] | None:
    for item in model.functions_of(contract):
        if (
            item.name == "totalSupply"
            and item.exposed
            and not item.params
            and item.has_body
            and item.returns
            and item.returns[0].type_name.startswith("uint")
        ):
            return item.signature, item.body
    return None


def _share_getter(model: ResearchModel, contract: str) -> str:
    from app.discovery.bounty.properties import public_getter

    for item in model.functions_of(contract):
        if (
            item.name == "balanceOf"
            and item.exposed
            and len(item.params) == 1
            and item.returns
            and item.returns[0].type_name.startswith("uint")
        ):
            return item.signature
    return public_getter(model, contract, "balanceOf")


def _protocol_config(model: ResearchModel, function: RFunction, compact: str) -> tuple[str, str]:
    from app.discovery.bounty.properties import public_getter

    member = re.search(r"([A-Za-z_]\w*)\)?\.protocol_fee_config\(\)", compact)
    if member:
        factory = public_getter(model, function.contract, member.group(1))
        if factory.endswith("()"):
            return factory, "protocol_fee_config()"
        return "", ""
    for name in _called_names(function.body):
        target = _lookup(model, model.lineage(function.contract), name)
        if target is None or target.params or not target.exposed:
            continue
        if len(target.returns) != 2:
            continue
        if not target.returns[0].type_name.startswith("uint"):
            continue
        if not target.returns[1].type_name.replace(" payable", "").startswith("address"):
            continue
        return "", target.signature
    return "", ""


def _recipient_getter(
    model: ResearchModel, function: RFunction, compact: str, factory_getter: str
) -> str:
    from app.discovery.bounty.properties import public_getter

    factory_name = factory_getter[:-2] if factory_getter.endswith("()") else ""
    found: list[str] = []
    seen: set[str] = set()
    for item in model.functions_of(function.contract):
        if (
            item.exposed
            and not item.params
            and item.returns
            and item.returns[0].type_name.replace(" payable", "").startswith("address")
            and item.name != factory_name
            and item.name in compact
            and item.signature not in seen
        ):
            seen.add(item.signature)
            found.append(item.signature)
    for name, kind in model.state_vars(function.contract).items():
        if name == factory_name or kind != "address":
            continue
        getter = public_getter(model, function.contract, name)
        if getter.endswith("()") and name in compact and getter not in seen:
            seen.add(getter)
            found.append(getter)
    if len(found) == 1:
        return found[0]
    return ""


def _conversion_text(model: ResearchModel, function: RFunction) -> str:
    body = _strip_comments(function.body)
    if re.search(r"==\s*0\s*\?", body) and "/" in body:
        return body
    if not re.search(r"\bDown\b", body):
        return ""
    names = set(_called_names(body))
    names.update(re.findall(r"(?<![\w.])([A-Za-z_]\w*)\s*\(", body))
    texts: list[str] = []
    for name in names:
        target = _lookup(model, model.lineage(function.contract), name)
        if target is None:
            continue
        inner = _strip_comments(target.body)
        converts = "mulDiv" in inner or "*" in inner
        if re.search(r"==\s*0\b", inner) and "return" in inner and converts:
            texts.append(inner)
    return "\n".join(texts)


def _linked(getter_body: str, conversion: str) -> bool:
    returned = _return_expr(getter_body)
    tokens = [item for item in re.findall(r"[A-Za-z_]\w*", returned) if len(item) > 2]
    return any(token in conversion for token in tokens)
