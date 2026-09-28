"""In-process economic observations.

The engine does not start a process, open a network connection, or call a
model. Missing observations stay unsupported. A result is evidence, not
authority, and it cannot mark a finding verified.
"""

from __future__ import annotations

from collections.abc import Callable

from app.discovery.capabilities import EngineAvailability, EngineCapability, ResultStatus
from app.discovery.engine import AnalysisRequest, DiscoveryEngine
from app.discovery.results import DynamicResult
from app.parsing.solidity_economics import (
    AssetDelta,
    Conversion,
    ConversionKind,
    EconomicResult,
    OracleStatus,
    Quantity,
    amm_invariant,
    donation_inflation,
    erc20_delta,
    fee_on_transfer,
    flash_position,
    lending_transition,
    native_eth_delta,
    net_change,
    oracle_dependency,
    preview_discrepancy,
    reserve_delta,
    share_delta,
)

_VERSION = "phase46"


class EconomicEngine(DiscoveryEngine):
    @property
    def engine_id(self) -> str:
        return "bugforge-economic"

    @property
    def display_name(self) -> str:
        return "BugForge economic analysis"

    @property
    def supported_languages(self) -> frozenset[str]:
        return frozenset({"solidity"})

    def capabilities(self) -> frozenset[EngineCapability]:
        return frozenset({EngineCapability.ECONOMIC_SIMULATION, EngineCapability.RESULTS_INGESTION})

    def availability(self) -> EngineAvailability:
        return EngineAvailability.AVAILABLE

    def version(self) -> str:
        return _VERSION

    def _start_campaign(self, request: AnalysisRequest) -> DynamicResult:
        return _observe(self, request)

    def _analyze_target(self, request: AnalysisRequest) -> DynamicResult:
        return _observe(self, request)


def _observe(engine: EconomicEngine, request: AnalysisRequest) -> DynamicResult:
    case = request.extra.get("case", "")
    if not case:
        return DynamicResult(
            engine=engine.engine_id,
            engine_version=engine.version(),
            language=request.language,
            target=request.target,
            status=ResultStatus.UNSUPPORTED,
            executed=False,
            provenance="economic",
            oracle_explanation="no economic observations were supplied",
            oracle_kind="economic",
            metadata=_meta("unsupported"),
        )
    result = _dispatch(request.extra)
    return DynamicResult(
        engine=engine.engine_id,
        engine_version=engine.version(),
        language=request.language,
        target=request.target,
        campaign_id=request.campaign_id,
        status=ResultStatus.EXECUTED,
        executed=True,
        provenance="economic",
        oracle_explanation=result.explanation,
        oracle_kind="economic",
        metadata=_meta(result.status),
    )


def _meta(status: str) -> dict[str, str]:
    return {
        "verified": "false",
        "economic_status": status,
        "evidence_class": "economic",
        "environment": "in-process",
    }


def _dispatch(extra: dict[str, str]) -> EconomicResult:
    case = extra.get("case", "")
    if case == "eth":
        return _pair(extra, native_eth_delta, "eth", "wei")
    if case == "erc20":
        return _pair(extra, erc20_delta, "erc20", extra.get("unit", "token"))
    if case == "share":
        return _pair(extra, share_delta, "share", "shares")
    if case == "reserve":
        return _pair(extra, reserve_delta, "reserve", extra.get("unit", "token"))
    if case == "net":
        return net_change(
            final=_optional(extra.get("final")),
            initial=_optional(extra.get("initial")),
            costs=_optional(extra.get("costs")),
            fees=_optional(extra.get("fees")),
            repayments=_optional(extra.get("repayments")),
            token=extra.get("token", ""),
        )
    if case == "flash":
        return flash_position(
            owned_initial=_optional(extra.get("owned_initial")),
            owned_final=_optional(extra.get("owned_final")),
            borrowed=_optional(extra.get("borrowed")),
            repayment=_optional(extra.get("repayment")),
            fee=_optional(extra.get("fee")),
            token=extra.get("token", ""),
        )
    if case == "donation":
        return donation_inflation(
            assets_before=int(extra.get("assets_before", "0")),
            shares_before=int(extra.get("shares_before", "0")),
            donated=int(extra.get("donated", "0")),
            deposit_assets=int(extra.get("deposit_assets", "0")),
            shares_minted=int(extra.get("shares_minted", "0")),
            established=frozenset(extra.get("established", "").split(",")) - {""},
            observed=extra.get("observed") == "true",
        )
    if case == "preview":
        return preview_discrepancy(
            preview=int(extra.get("preview", "0")),
            executed=int(extra.get("executed", "0")),
            established=frozenset({"erc4626-preview"}),
        )
    if case == "fee":
        return fee_on_transfer(
            requested=int(extra.get("requested", "0")),
            sender_delta=int(extra.get("sender_delta", "0")),
            receiver_delta=int(extra.get("receiver_delta", "0")),
            accounted=_optional(extra.get("accounted")),
            semantics=extra.get("semantics", "unknown"),
        )
    if case == "oracle":
        return oracle_dependency(
            state_changed=extra.get("state_changed") == "true",
            freshness=extra.get("freshness", "unknown"),
            design=extra.get("design", "unknown"),
            input_relation=extra.get("input_relation") == "true",
            valued=extra.get("valued") == "true",
            sensitive=extra.get("sensitive") == "true",
        )
    if case == "amm":
        return amm_invariant(
            reserve0=_optional(extra.get("reserve0")),
            reserve1=_optional(extra.get("reserve1")),
            model=extra.get("model", ""),
        )
    if case == "lending":
        return lending_transition(
            debt_before=_optional(extra.get("debt_before")),
            debt_after=_optional(extra.get("debt_after")),
            repayment=_optional(extra.get("repayment")),
            collateral_before=_optional(extra.get("collateral_before")),
            collateral_after=_optional(extra.get("collateral_after")),
            health=extra.get("health", "unknown"),
            liquidated=extra.get("liquidated") == "true",
        )
    if case == "convert":
        source = Conversion(
            kind=extra.get("conversion_kind", ConversionKind.UNSUPPORTED.value),
            from_token=extra.get("from_token", ""),
            to_token=extra.get("to_token", ""),
            numerator=_optional(extra.get("numerator")),
            denominator=_optional(extra.get("denominator")),
            provenance=extra.get("provenance", ""),
        )
        return net_change(
            final=_optional(extra.get("final")),
            initial=_optional(extra.get("initial")),
            costs=_optional(extra.get("costs")),
            fees=_optional(extra.get("fees")),
            repayments=_optional(extra.get("repayments")),
            token=extra.get("token", ""),
            other_token=extra.get("other_token", ""),
            other_amount=_optional(extra.get("other_amount")),
            conversion=source,
        )
    return _unsupported()


def _unsupported() -> EconomicResult:
    return EconomicResult(OracleStatus.UNSUPPORTED.value, "the economic case is unsupported")


def _pair(
    extra: dict[str, str],
    function: Callable[[Quantity, Quantity], AssetDelta],
    kind: str,
    unit: str,
) -> EconomicResult:
    before = _quantity(extra, "before", kind, unit)
    after = _quantity(extra, "after", kind, unit)
    if before is None or after is None:
        return EconomicResult(OracleStatus.UNKNOWN.value, "the balance observation is incomplete")
    delta = function(before, after)
    if delta.known == "unknown":
        return EconomicResult(OracleStatus.UNKNOWN.value, "the delta is unknown", deltas=(delta,))
    if delta.known == "positive":
        status = OracleStatus.POTENTIAL_POSITIVE_DELTA.value
    elif delta.known == "negative":
        status = OracleStatus.POTENTIAL_LOSS.value
    else:
        status = OracleStatus.BALANCED.value
    return EconomicResult(status, f"{kind} delta {delta.delta}", deltas=(delta,))


def _quantity(extra: dict[str, str], prefix: str, kind: str, unit: str) -> Quantity | None:
    raw = extra.get(prefix, "")
    if raw == "":
        return None
    amount = _optional(raw)
    return Quantity(
        token=extra.get("token", ""),
        unit=unit,
        actor=extra.get("actor", ""),
        amount=amount,
        source=extra.get("source", "observation"),
        transaction_index=int(extra.get("transaction_index", "0")),
        snapshot=prefix,
        provenance="runtime-observation",
        confidence="observed" if amount is not None else "unknown",
        kind=kind,
    )


def _optional(raw: str | None) -> int | None:
    if raw is None or raw == "" or raw == "unknown":
        return None
    return int(raw)
