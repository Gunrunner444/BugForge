"""Deterministic collateral sequences for the pinned Silo V3 share conversion.

This is a target-specific enumerator, not a protocol fuzzer. It replays deposit,
mint, withdraw, and redeem against the collateral formulas in SiloMathLib:
when share supply is zero the calculation resets its local asset total to zero,
then collateral adds 1,000 virtual shares and one virtual asset. Persistent
stored assets are not cleared by that reset.
"""

from __future__ import annotations

from dataclasses import dataclass

OFFSET = 1000
FUND = 2_000_000
SEQUENCE_LIMIT = 24
MAX_LENGTH = 6
PER_LENGTH = 6
BEAM_WIDTH = 24
ENUMERATION = "deterministic-beam-v1"

OP_KIND = {"deposit": 1, "mint": 2, "withdraw": 3, "redeem": 4}
INFLOWS = frozenset({"deposit", "mint"})
OUTFLOWS = frozenset({"withdraw", "redeem"})


@dataclass(frozen=True)
class MenuOp:
    name: str
    actor: int
    amount: int
    reason: str


@dataclass(frozen=True)
class Market:
    assets: int
    shares: int
    tokens: tuple[int, int]
    balances: tuple[int, int]
    nonzero: int
    inflows: int
    outflows: int
    op_names: frozenset[str]
    actors: frozenset[int]


@dataclass(frozen=True)
class Applied:
    market: Market
    expected: int
    remainder: int


@dataclass(frozen=True)
class Node:
    market: Market
    path: tuple[int, ...]
    steps: tuple[dict[str, object], ...]


def menu() -> tuple[MenuOp, ...]:
    """Amounts that the offset formula can divide with a nonzero remainder."""
    return (
        MenuOp("deposit", 0, 1_000_000, "seed actor A at the empty-market offset identity"),
        MenuOp("deposit", 1, 1_000_000, "actor B deposits a round amount into the current market"),
        MenuOp(
            "mint", 1, 2001, "mint 2001 shares; the product leaves a remainder against the offset"
        ),
        MenuOp("mint", 0, 2001, "actor A mints 2001 shares against the current virtual totals"),
        MenuOp(
            "mint",
            1,
            1,
            "mint 1 share so ceil asset pull is visible when the ratio is just under 1000",
        ),
        MenuOp("mint", 0, 1, "actor A mints 1 share"),
        MenuOp("deposit", 1, 1, "floor deposit of 1 asset after the ratio is no longer exact"),
        MenuOp("deposit", 0, 1, "actor A deposits 1 asset"),
        MenuOp("deposit", 1, 7, "deposit 7 assets so the remainder is not the 1-asset case"),
        MenuOp("deposit", 0, 7, "actor A deposits 7 assets"),
        MenuOp("deposit", 0, 2, "actor A deposits 2 assets"),
        MenuOp("withdraw", 1, 1, "ceil-burn the shares owed for 1 asset from actor B"),
        MenuOp("withdraw", 0, 1, "ceil-burn the shares owed for 1 asset from actor A"),
        MenuOp("withdraw", 1, 2, "ceil-burn the shares owed for 2 assets from actor B"),
        MenuOp("withdraw", 0, 2, "ceil-burn the shares owed for 2 assets from actor A"),
        MenuOp("withdraw", 1, 7, "ceil-burn the shares owed for 7 assets when B can cover them"),
        MenuOp("redeem", 1, 1, "floor-redeem 1 collateral share"),
        MenuOp("redeem", 0, 1, "actor A floor-redeems 1 share"),
        MenuOp("redeem", 1, 1000, "floor-redeem 1000 shares"),
        MenuOp("redeem", 0, 1000, "actor A floor-redeems 1000 shares"),
        MenuOp("redeem", 1, 2001, "redeem a 2001-share position when actor B still holds it"),
        MenuOp(
            "redeem",
            0,
            1_000_000_000,
            "redeem the offset-identity seed when actor A still holds those shares",
        ),
    )


def virtual_totals(assets: int, shares: int) -> tuple[int, int]:
    """Return (virtual shares, virtual assets). A zero share supply resets assets locally."""
    calculation_assets = 0 if shares == 0 else assets
    return shares + OFFSET, calculation_assets + 1


def convert_to_shares(amount: int, assets: int, shares: int, *, ceil: bool) -> tuple[int, int]:
    virtual_shares, virtual_assets = virtual_totals(assets, shares)
    return _mul_div(amount, virtual_shares, virtual_assets, ceil=ceil)


def convert_to_assets(amount: int, assets: int, shares: int, *, ceil: bool) -> tuple[int, int]:
    virtual_shares, virtual_assets = virtual_totals(assets, shares)
    return _mul_div(amount, virtual_assets, virtual_shares, ceil=ceil)


def initial_market() -> Market:
    return Market(0, 0, (FUND, FUND), (0, 0), 0, 0, 0, frozenset(), frozenset())


def apply_op(market: Market, op: MenuOp) -> Applied:
    """Apply one collateral operation. Raise ValueError with a precondition reason."""
    if op.amount <= 0:
        raise ValueError("zero_amount")
    if op.name in INFLOWS and market.tokens[op.actor] < _assets_required(market, op):
        raise ValueError("insufficient_tokens")
    if op.name == "deposit":
        expected, remainder = convert_to_shares(op.amount, market.assets, market.shares, ceil=False)
        if expected == 0:
            raise ValueError("zero_output")
        return Applied(
            _credit_shares(market, op, expected, remainder, op.amount), expected, remainder
        )
    if op.name == "mint":
        expected, remainder = convert_to_assets(op.amount, market.assets, market.shares, ceil=True)
        if expected == 0:
            raise ValueError("zero_output")
        if market.tokens[op.actor] < expected:
            raise ValueError("insufficient_tokens")
        return Applied(
            _credit_shares(market, op, op.amount, remainder, expected), expected, remainder
        )
    if market.shares == 0:
        raise ValueError("nothing_to_withdraw")
    if op.name == "withdraw":
        expected, remainder = convert_to_shares(op.amount, market.assets, market.shares, ceil=True)
        if expected == 0:
            raise ValueError("zero_output")
        if market.balances[op.actor] < expected:
            raise ValueError("insufficient_shares")
        if op.amount > market.assets:
            raise ValueError("not_enough_liquidity")
        return Applied(
            _debit_shares(market, op, expected, remainder, op.amount), expected, remainder
        )
    if op.name == "redeem":
        if market.balances[op.actor] < op.amount:
            raise ValueError("insufficient_shares")
        expected, remainder = convert_to_assets(op.amount, market.assets, market.shares, ceil=False)
        if expected == 0:
            raise ValueError("zero_output")
        if expected > market.assets:
            raise ValueError("not_enough_liquidity")
        return Applied(
            _debit_shares(market, op, op.amount, remainder, expected), expected, remainder
        )
    raise ValueError("unknown_operation")


def generate_collateral_sequences(
    *,
    limit: int = SEQUENCE_LIMIT,
    max_length: int = MAX_LENGTH,
    per_length: int = PER_LENGTH,
    beam_width: int = BEAM_WIDTH,
) -> dict[str, object]:
    """Beam-search a bounded set of valid sequences. Enumeration order is fixed."""
    if limit < 1 or max_length < 3 or per_length < 1 or beam_width < 1:
        raise ValueError("sequence limits must stay positive")
    ops = menu()
    beam = [Node(initial_market(), (), ())]
    examined = 0
    invalid: list[dict[str, object]] = []
    dropped: list[dict[str, object]] = []
    retained: list[dict[str, object]] = []
    selected: dict[int, list[Node]] = {length: [] for length in range(3, max_length + 1)}
    for depth in range(1, max_length + 1):
        candidates: list[Node] = []
        for node in beam:
            for index, op in enumerate(ops):
                examined += 1
                try:
                    applied = apply_op(node.market, op)
                except ValueError as exc:
                    invalid.append(_attempt(node, op, str(exc)))
                    continue
                candidates.append(_extend(node, index, op, applied))
        candidates.sort(key=_beam_key)
        kept: list[Node] = []
        for candidate in candidates:
            if len(kept) >= beam_width:
                dropped.append(_attempt_node(candidate, "beam_limit"))
                continue
            kept.append(candidate)
        if depth >= 3 and depth in selected:
            selected[depth] = _choose(kept, per_length, dropped)
        else:
            retained.extend(_node_summary(node) for node in kept)
        beam = kept
        if not beam:
            break
    executed = [node for length in range(3, max_length + 1) for node in selected.get(length, ())]
    executed = executed[:limit]
    return {
        "enumeration": ENUMERATION,
        "limit": limit,
        "max_length": max_length,
        "per_length": per_length,
        "beam_width": beam_width,
        "fund_per_actor": FUND,
        "offset": OFFSET,
        "actors": 2,
        "operations": ["deposit", "mint", "withdraw", "redeem"],
        "rule": (
            "Deterministic beam search over a fixed menu. A sequence is executed only when "
            "it is 3 to 6 operations, uses both actors, contains an inflow and an outflow, "
            "and at least one conversion remainder is nonzero. Invalid preconditions are "
            "excluded. The beam keeps the highest-ranked valid prefixes."
        ),
        "menu": [_op_dict(op) for op in ops],
        "examined": examined,
        "invalid_count": len(invalid),
        "invalid": invalid,
        "excluded_count": len(dropped),
        "excluded": dropped,
        "retained_prefix_count": len(retained),
        "retained_prefixes": retained,
        "generated_count": len(dropped) + len(retained) + len(executed),
        "executed_count": len(executed),
        "executed": [_node_trace(node) for node in executed],
        "length_counts": {str(length): len(nodes) for length, nodes in selected.items()},
        "invariants": [
            "deposit_floor_shares",
            "mint_ceil_assets",
            "withdraw_ceil_shares",
            "redeem_floor_assets",
            "preview_matches_formula",
            "owner_and_receiver_token_delta",
            "silo_token_delta",
            "stored_collateral_delta",
            "owner_share_delta",
            "share_supply_delta",
            "share_balances_sum_to_supply",
            "floor_entitlement_within_collateral",
            "zero_share_calculation_resets_local_assets",
        ],
        "receiver_is_owner": True,
        "packed": _pack(executed),
    }


def trace_round_trip() -> dict[str, object]:
    """Model the named round trip. The harness recomputes these from chain state."""
    market = initial_market()
    deposit = apply_op(market, MenuOp("deposit", 0, 1_000_000, "seed"))
    minted = apply_op(deposit.market, MenuOp("mint", 1, 2001, "mint"))
    withdrawn = apply_op(minted.market, MenuOp("withdraw", 1, 1, "withdraw"))
    redeposited = apply_op(withdrawn.market, MenuOp("deposit", 1, 1, "redeposit"))
    remaining = redeposited.market.balances[1]
    redeemed = apply_op(redeposited.market, MenuOp("redeem", 1, remaining, "redeem"))
    return {
        "mint_assets": minted.expected,
        "mint_remainder": minted.remainder,
        "withdraw_shares": withdrawn.expected,
        "withdraw_remainder": withdrawn.remainder,
        "redeposit_shares": redeposited.expected,
        "redeposit_remainder": redeposited.remainder,
        "redeem_shares": remaining,
        "redeem_assets": redeemed.expected,
        "redeem_remainder": redeemed.remainder,
        "final_assets": redeemed.market.assets,
        "final_shares": redeemed.market.shares,
        "final_b_shares": redeemed.market.balances[1],
        "final_a_shares": redeemed.market.balances[0],
        "final_b_tokens": redeemed.market.tokens[1],
    }


def trace_zero_supply() -> dict[str, object]:
    """Redeem both positions, then deposit 1 asset into whatever collateral remains."""
    market = initial_market()
    deposit = apply_op(market, MenuOp("deposit", 0, 1_000_000, "seed"))
    minted = apply_op(deposit.market, MenuOp("mint", 1, 2001, "mint"))
    b_shares = minted.market.balances[1]
    b_exit = apply_op(minted.market, MenuOp("redeem", 1, b_shares, "redeem B"))
    a_shares = b_exit.market.balances[0]
    a_exit = apply_op(b_exit.market, MenuOp("redeem", 0, a_shares, "redeem A"))
    residual = a_exit.market.assets
    fresh = apply_op(a_exit.market, MenuOp("deposit", 1, 1, "fresh deposit"))
    no_reset, _remainder = _mul_div(1, OFFSET, residual + 1, ceil=False)
    return {
        "supply_after_exit": a_exit.market.shares,
        "residual_assets": residual,
        "b_assets_out": b_exit.expected,
        "a_assets_out": a_exit.expected,
        "fresh_shares": fresh.expected,
        "fresh_stored_assets": fresh.market.assets,
        "no_reset_shares": no_reset,
        "reset_observable": residual != 0 and fresh.expected != no_reset,
    }


def _assets_required(market: Market, op: MenuOp) -> int:
    if op.name == "deposit":
        return op.amount
    if op.name != "mint":
        return 0
    assets, _remainder = convert_to_assets(op.amount, market.assets, market.shares, ceil=True)
    return assets


def _credit_shares(market: Market, op: MenuOp, shares: int, remainder: int, assets: int) -> Market:
    tokens = _replace(market.tokens, op.actor, market.tokens[op.actor] - assets)
    balances = _replace(market.balances, op.actor, market.balances[op.actor] + shares)
    return _next(
        market, op, market.assets + assets, market.shares + shares, tokens, balances, remainder
    )


def _debit_shares(market: Market, op: MenuOp, shares: int, remainder: int, assets: int) -> Market:
    tokens = _replace(market.tokens, op.actor, market.tokens[op.actor] + assets)
    balances = _replace(market.balances, op.actor, market.balances[op.actor] - shares)
    return _next(
        market, op, market.assets - assets, market.shares - shares, tokens, balances, remainder
    )


def _next(
    market: Market,
    op: MenuOp,
    assets: int,
    shares: int,
    tokens: tuple[int, int],
    balances: tuple[int, int],
    remainder: int,
) -> Market:
    return Market(
        assets,
        shares,
        tokens,
        balances,
        market.nonzero + (1 if remainder else 0),
        market.inflows + (1 if op.name in INFLOWS else 0),
        market.outflows + (1 if op.name in OUTFLOWS else 0),
        market.op_names | {op.name},
        market.actors | {op.actor},
    )


def _extend(node: Node, index: int, op: MenuOp, applied: Applied) -> Node:
    pre = node.market
    post = applied.market
    step = {
        "op": op.name,
        "actor": op.actor,
        "amount": op.amount,
        "reason": op.reason,
        "pre_assets": pre.assets,
        "pre_shares": pre.shares,
        "pre_tokens": list(pre.tokens),
        "pre_balances": list(pre.balances),
        "expected": applied.expected,
        "remainder": applied.remainder,
        "post_assets": post.assets,
        "post_shares": post.shares,
        "post_tokens": list(post.tokens),
        "post_balances": list(post.balances),
    }
    return Node(post, node.path + (index,), node.steps + (step,))


def _choose(kept: list[Node], per_length: int, dropped: list[dict[str, object]]) -> list[Node]:
    qualifying = [node for node in kept if _reject_reason(node) is None]
    qualifying.sort(key=_selection_key)
    chosen: list[Node] = []
    seen: set[tuple[str, ...]] = set()
    deferred: list[Node] = []
    for node in qualifying:
        signature = tuple(str(step["op"]) + str(step["actor"]) for step in node.steps)
        if signature in seen:
            deferred.append(node)
            continue
        seen.add(signature)
        chosen.append(node)
        if len(chosen) == per_length:
            break
    if len(chosen) < per_length:
        for node in deferred:
            chosen.append(node)
            if len(chosen) == per_length:
                break
    chosen_ids = {id(node) for node in chosen}
    for node in kept:
        if id(node) in chosen_ids:
            continue
        reason = _reject_reason(node) or "length_quota"
        dropped.append(_attempt_node(node, reason))
    return chosen


def _reject_reason(node: Node) -> str | None:
    market = node.market
    if market.inflows == 0 or market.outflows == 0:
        return "missing_inflow_or_outflow"
    if market.nonzero == 0:
        return "missing_rounding_remainder"
    if len(market.op_names) < 2:
        return "narrow_operations"
    if len(market.actors) < 2:
        return "single_actor"
    return None


def _beam_key(node: Node) -> tuple[object, ...]:
    market = node.market
    return (
        -(market.nonzero > 0),
        -(market.inflows > 0 and market.outflows > 0),
        -len(market.op_names),
        -len(market.actors),
        -(market.shares == 0),
        -market.nonzero,
        node.path,
    )


def _selection_key(node: Node) -> tuple[object, ...]:
    market = node.market
    return (
        -(market.shares == 0),
        -len(market.op_names),
        -market.nonzero,
        -len(market.actors),
        node.path,
    )


def _attempt(node: Node, op: MenuOp, reason: str) -> dict[str, object]:
    return {
        "path": [_step_label(step) for step in node.steps],
        "op": op.name,
        "actor": op.actor,
        "amount": op.amount,
        "reason": reason,
    }


def _attempt_node(node: Node, reason: str) -> dict[str, object]:
    return {"path": [_step_label(step) for step in node.steps], "reason": reason}


def _step_label(step: dict[str, object]) -> str:
    return f"{step['op']}:{step['actor']}:{step['amount']}"


def _node_summary(node: Node) -> dict[str, object]:
    return {
        "length": len(node.steps),
        "path": [_step_label(step) for step in node.steps],
        "nonzero_remainders": node.market.nonzero,
        "final_assets": node.market.assets,
        "final_shares": node.market.shares,
    }


def _node_trace(node: Node) -> dict[str, object]:
    summary = _node_summary(node)
    summary["steps"] = [dict(step) for step in node.steps]
    summary["selection_reason"] = (
        "both actors, inflow and outflow, nonzero conversion remainder, beam rank"
    )
    return summary


def _op_dict(op: MenuOp) -> dict[str, object]:
    return {"op": op.name, "actor": op.actor, "amount": op.amount, "reason": op.reason}


def _pack(executed: list[Node]) -> dict[str, object]:
    lengths = bytearray()
    payload = bytearray()
    for node in executed:
        lengths.append(len(node.steps))
        for step in node.steps:
            kind = OP_KIND[str(step["op"])]
            amount = _as_int(step["amount"])
            payload.append(_as_int(step["actor"]))
            payload.append(kind)
            payload.extend(amount.to_bytes(8, "big"))
    return {
        "count": len(executed),
        "lengths_hex": lengths.hex(),
        "ops_hex": payload.hex(),
    }


def _as_int(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("sequence field is not an integer")
    return value


def _replace(values: tuple[int, int], index: int, value: int) -> tuple[int, int]:
    pair = [values[0], values[1]]
    pair[index] = value
    return pair[0], pair[1]


def _mul_div(amount: int, numerator: int, denominator: int, *, ceil: bool) -> tuple[int, int]:
    product = amount * numerator
    quotient, remainder = divmod(product, denominator)
    if ceil and remainder:
        quotient += 1
    return quotient, remainder


def render_round_trip_body(
    *, contract: str, silo_iface: str, factory: str, config: str, clone_expr: str
) -> str:
    return _body("ROUND", contract, silo_iface, factory, config, clone_expr)


def render_zero_supply_body(
    *, contract: str, silo_iface: str, factory: str, config: str, clone_expr: str
) -> str:
    return _body("ZERO", contract, silo_iface, factory, config, clone_expr)


def render_sequence_body(
    *,
    contract: str,
    silo_iface: str,
    factory: str,
    config: str,
    clone_expr: str,
    generation: dict[str, object],
) -> str:
    packed = generation["packed"]
    if not isinstance(packed, dict):
        raise ValueError("sequence packing is missing")
    body = _body("SEQUENCE", contract, silo_iface, factory, config, clone_expr)
    return (
        body.replace("@@COUNT@@", str(int(packed["count"])))
        .replace("@@LENGTHS@@", str(packed["lengths_hex"]))
        .replace("@@OPS@@", str(packed["ops_hex"]))
    )


def _body(
    kind: str, contract: str, silo_iface: str, factory: str, config: str, clone_expr: str
) -> str:
    names = {"ROUND": "RoundFlow", "ZERO": "ZeroFlow", "SEQUENCE": "SequenceFlow"}
    if kind not in names:
        raise ValueError(kind)
    fragment = {"ROUND": _ROUND, "ZERO": _ZERO, "SEQUENCE": _SEQUENCE}[kind]
    text = _SHARED + fragment
    for token, value in (
        ("@@KIND@@", names[kind]),
        ("@@CONTRACT@@", contract),
        ("@@SILO@@", silo_iface),
        ("@@FACTORY@@", factory),
        ("@@CONFIG@@", config),
        ("@@CLONE@@", clone_expr),
    ):
        text = text.replace(token, value)
    return text


_SHARED = """
contract LocalActor {
    function approveAll(LocalAsset asset_, address silo_) external {
        asset_.approve(silo_, asset_.balanceOf(address(this)));
    }

    function depositTo(address silo_, uint256 amount) external returns (bool ok, bytes memory data) {
        (ok, data) = silo_.call(
            abi.encodeWithSelector(bytes4(keccak256("deposit(uint256,address)")), amount, address(this))
        );
    }

    function mintTo(address silo_, uint256 shares) external returns (bool ok, bytes memory data) {
        (ok, data) = silo_.call(
            abi.encodeWithSelector(bytes4(keccak256("mint(uint256,address)")), shares, address(this))
        );
    }

    function withdrawTo(address silo_, uint256 amount) external returns (bool ok, bytes memory data) {
        (ok, data) = silo_.call(
            abi.encodeWithSelector(
                bytes4(keccak256("withdraw(uint256,address,address)")),
                amount,
                address(this),
                address(this)
            )
        );
    }

    function redeemTo(address silo_, uint256 shares) external returns (bool ok, bytes memory data) {
        (ok, data) = silo_.call(
            abi.encodeWithSelector(
                bytes4(keccak256("redeem(uint256,address,address)")),
                shares,
                address(this),
                address(this)
            )
        );
    }
}

contract @@KIND@@Accounting {
    uint256 internal constant OFFSET = 1000;
    uint256 internal constant SEED = 1_000_000;
    uint256 internal constant MINT_SHARES = 2_001;
    uint256 internal constant FUND = 2_000_000;
    event BugForgeState(string label, uint256 value);

    struct Flow {
        uint256 assetsBefore;
        uint256 supplyBefore;
        uint256 viewBefore;
        uint256 virtualShares;
        uint256 virtualAssets;
        uint256 previewed;
        uint256 formula;
        uint256 remainder;
        uint256 actual;
        uint256 ownerTokens;
        uint256 siloBefore;
        uint256 ownerShares;
        uint256 sharesA;
        uint256 sharesB;
        uint256 assetsAfter;
        uint256 supplyAfter;
        uint256 viewAfter;
        uint256 ownerTokensAfter;
        uint256 siloAfter;
        uint256 ownerSharesAfter;
        uint256 sharesAAfter;
        uint256 sharesBAfter;
        uint256 mintAssets;
        uint256 mintRemainder;
        uint256 ratioRemainder;
        uint256 amount;
    }

    Flow internal flow;
    @@CONTRACT@@ internal activeSilo;
    LocalAsset internal activeAsset;
    LocalActor internal actorA;
    LocalActor internal actorB;
    LocalActor internal actorC;
    uint256 internal activeKind;
    uint256 internal activeAmount;

    function _virtual() internal {
        uint256 calculationAssets = flow.supplyBefore == 0 ? 0 : flow.assetsBefore;
        flow.virtualShares = flow.supplyBefore + OFFSET;
        flow.virtualAssets = calculationAssets + 1;
    }

    function _floorShares(uint256 amount) internal {
        uint256 product = amount * flow.virtualShares;
        flow.remainder = product % flow.virtualAssets;
        flow.formula = product / flow.virtualAssets;
    }

    function _ceilShares(uint256 amount) internal {
        uint256 product = amount * flow.virtualShares;
        flow.remainder = product % flow.virtualAssets;
        flow.formula = product / flow.virtualAssets;
        if (flow.remainder != 0) flow.formula += 1;
    }

    function _floorAssets(uint256 amount) internal {
        uint256 product = amount * flow.virtualAssets;
        flow.remainder = product % flow.virtualShares;
        flow.formula = product / flow.virtualShares;
    }

    function _ceilAssets(uint256 amount) internal {
        uint256 product = amount * flow.virtualAssets;
        flow.remainder = product % flow.virtualShares;
        flow.formula = product / flow.virtualShares;
        if (flow.remainder != 0) flow.formula += 1;
    }

    function _loadAssets() internal {
        flow.assetsBefore = activeSilo.getTotalAssetsStorage(@@SILO@@.AssetType.Collateral);
        flow.supplyBefore = activeSilo.totalSupply();
        flow.viewBefore = activeSilo.totalAssets();
    }

    function _loadOwner(LocalActor actor) internal {
        flow.ownerTokens = activeAsset.balanceOf(address(actor));
        flow.siloBefore = activeAsset.balanceOf(address(activeSilo));
        flow.ownerShares = activeSilo.balanceOf(address(actor));
    }

    function _loadPositions() internal {
        flow.sharesA = activeSilo.balanceOf(address(actorA));
        flow.sharesB = activeSilo.balanceOf(address(actorB));
    }

    function _captureAssets() internal {
        flow.assetsAfter = activeSilo.getTotalAssetsStorage(@@SILO@@.AssetType.Collateral);
        flow.supplyAfter = activeSilo.totalSupply();
        flow.viewAfter = activeSilo.totalAssets();
    }

    function _captureOwner(LocalActor actor) internal {
        flow.ownerTokensAfter = activeAsset.balanceOf(address(actor));
        flow.siloAfter = activeAsset.balanceOf(address(activeSilo));
        flow.ownerSharesAfter = activeSilo.balanceOf(address(actor));
    }

    function _capturePositions() internal {
        flow.sharesAAfter = activeSilo.balanceOf(address(actorA));
        flow.sharesBAfter = activeSilo.balanceOf(address(actorB));
    }

    function _preview(uint256 kind, uint256 amount) internal {
        bytes4 selector = bytes4(keccak256("previewDeposit(uint256)"));
        if (kind == 2) selector = bytes4(keccak256("previewMint(uint256)"));
        else if (kind == 3) selector = bytes4(keccak256("previewWithdraw(uint256)"));
        else if (kind == 4) selector = bytes4(keccak256("previewRedeem(uint256)"));
        (bool ok, bytes memory data) = address(activeSilo).staticcall(
            abi.encodeWithSelector(selector, amount)
        );
        if (!ok || data.length < 32) revert BugForgeFixture(data);
        flow.previewed = abi.decode(data, (uint256));
    }

    function _invoke(LocalActor actor, uint256 kind, uint256 amount)
        internal
        returns (bool ok, bytes memory data)
    {
        if (kind == 1) return actor.depositTo(address(activeSilo), amount);
        if (kind == 2) return actor.mintTo(address(activeSilo), amount);
        if (kind == 3) return actor.withdrawTo(address(activeSilo), amount);
        if (kind == 4) return actor.redeemTo(address(activeSilo), amount);
        revert BugForgeFixture(bytes("kind"));
    }

    function _take(LocalActor actor, uint256 kind, uint256 amount) internal {
        (bool ok, bytes memory data) = _invoke(actor, kind, amount);
        if (!ok || data.length < 32) revert BugForgeFixture(data);
        flow.actual = abi.decode(data, (uint256));
    }

    function _setup() internal {
        activeAsset = new LocalAsset();
        LocalInterestRateModel rate = new LocalInterestRateModel();
        LocalSiloConfig config_ = new LocalSiloConfig(address(activeAsset), address(rate));
        LocalFactory deployedFactory = new LocalFactory();
        @@CONTRACT@@ implementation = new @@CONTRACT@@(@@FACTORY@@(address(deployedFactory)));
        activeSilo = @@CONTRACT@@(@@CLONE@@);
        config_.bind(address(activeSilo));
        (bool ok, bytes memory data) = address(activeSilo).call(
            abi.encodeCall(@@CONTRACT@@.initialize, (@@CONFIG@@(address(config_))))
        );
        if (!ok) revert BugForgeFixture(data);
        actorA = new LocalActor();
        actorB = new LocalActor();
        if (address(actorA) == address(actorB)) revert BugForgeFixture(bytes("same_actor"));
    }

    function _emit(string memory prefix, string memory key, uint256 value) internal {
        emit BugForgeState(string.concat(prefix, key), value);
    }

    function _positions() internal view {
        if (flow.sharesAAfter + flow.sharesBAfter != flow.supplyAfter) revert BugForgeProperty("share_sum");
        if (flow.siloAfter != flow.assetsAfter) revert BugForgeProperty("silo_balance");
        if (flow.viewAfter != flow.assetsAfter) revert BugForgeProperty("view_storage");
        if (flow.supplyAfter == 0) {
            if (flow.sharesAAfter != 0 || flow.sharesBAfter != 0) revert BugForgeProperty("share_sum");
            return;
        }
        uint256 virtualShares = flow.supplyAfter + OFFSET;
        uint256 virtualAssets = flow.assetsAfter + 1;
        uint256 entitled = flow.sharesAAfter * virtualAssets / virtualShares;
        entitled += flow.sharesBAfter * virtualAssets / virtualShares;
        if (entitled > flow.assetsAfter) revert BugForgeProperty("position");
    }
}
"""

_ROUND = """
contract WithdrawRedepositRoundTripTest is @@KIND@@Accounting {
    function test_withdraw_redeposit_roundtrip() public {
        _setup();
        _seed();
        _mintNonExact();
        _stage(3, 1, actorB, "t0_");
        if (flow.ownerSharesAfter == 0) revert BugForgeProperty("owner_exited");
        _stage(1, 1, actorB, "t1_");
        uint256 remaining = activeSilo.balanceOf(address(actorB));
        _stage(4, remaining, actorB, "t2_");
        if (flow.ownerSharesAfter != 0) revert BugForgeProperty("redeem_remaining");
        _emitFinal();
    }

    function _seed() internal {
        activeAsset.credit(address(actorA), SEED);
        actorA.approveAll(activeAsset, address(activeSilo));
        _loadAssets();
        _virtual();
        _floorShares(SEED);
        _preview(1, SEED);
        _take(actorA, 1, SEED);
        _captureAssets();
        if (flow.actual != flow.formula || flow.previewed != flow.formula) revert BugForgeProperty("seed_accounting");
        if (flow.assetsAfter != SEED || flow.supplyAfter != flow.actual) revert BugForgeProperty("seed_accounting");
        if (flow.supplyAfter + OFFSET != OFFSET * (flow.assetsAfter + 1)) revert BugForgeProperty("offset_identity");
    }

    function _mintNonExact() internal {
        _loadAssets();
        _virtual();
        _ceilAssets(MINT_SHARES);
        if (flow.remainder == 0) revert BugForgeProperty("mint_exact");
        flow.mintAssets = flow.formula;
        flow.mintRemainder = flow.remainder;
        activeAsset.credit(address(actorB), flow.mintAssets);
        actorB.approveAll(activeAsset, address(activeSilo));
        _preview(2, MINT_SHARES);
        if (flow.previewed != flow.formula) revert BugForgeProperty("formula_mismatch");
        _take(actorB, 2, MINT_SHARES);
        _captureAssets();
        _captureOwner(actorB);
        if (flow.actual != flow.mintAssets) revert BugForgeProperty("mint_assets");
        if (flow.assetsAfter != flow.assetsBefore + flow.actual) revert BugForgeProperty("mint_collateral");
        if (flow.supplyAfter != flow.supplyBefore + MINT_SHARES) revert BugForgeProperty("mint_supply");
        if (flow.ownerSharesAfter != MINT_SHARES || flow.ownerTokensAfter != 0) revert BugForgeProperty("mint_receiver");
        flow.ratioRemainder = (flow.supplyAfter + OFFSET) % (flow.assetsAfter + 1);
        if (flow.ratioRemainder == 0) revert BugForgeProperty("ratio_exact");
        _emit("m_", "assets_before", flow.assetsAfter);
        _emit("m_", "supply_before", flow.supplyAfter);
        _emit("m_", "b_shares", flow.ownerSharesAfter);
        _emit("m_", "mint_assets", flow.mintAssets);
        _emit("m_", "mint_remainder", flow.mintRemainder);
        _emit("m_", "ratio_remainder", flow.ratioRemainder);
    }

    function _stage(uint256 kind, uint256 amount, LocalActor actor, string memory prefix) internal {
        if (amount == 0) revert BugForgeFixture(bytes("zero_amount"));
        flow.amount = amount;
        _loadAssets();
        _loadOwner(actor);
        _loadPositions();
        _virtual();
        if (kind == 1) _floorShares(amount);
        else if (kind == 3) _ceilShares(amount);
        else if (kind == 4) _floorAssets(amount);
        else revert BugForgeFixture(bytes("kind"));
        if (flow.formula == 0) revert BugForgeFixture(bytes("zero_output"));
        if (flow.remainder == 0) revert BugForgeProperty("expected_remainder");
        _preview(kind, amount);
        if (flow.previewed != flow.formula) revert BugForgeProperty("formula_mismatch");
        if (kind == 1 || kind == 4) {
            if (flow.previewed > flow.formula) revert BugForgeProperty("preview_direction");
        } else if (flow.previewed < flow.formula) {
            revert BugForgeProperty("preview_direction");
        }
        if (kind == 1) actor.approveAll(activeAsset, address(activeSilo));
        uint256 sharesBeforeA = flow.sharesA;
        _take(actor, kind, amount);
        _captureAssets();
        _captureOwner(actor);
        _capturePositions();
        _checkStage(kind, amount, sharesBeforeA);
        _emitStage(prefix);
    }

    function _checkStage(uint256 kind, uint256 amount, uint256 sharesBeforeA) internal view {
        if (flow.actual != flow.formula) revert BugForgeProperty("formula_mismatch");
        if (flow.sharesAAfter != sharesBeforeA) revert BugForgeProperty("first_depositor");
        if (kind == 3) _checkWithdraw(amount);
        else if (kind == 1) _checkDeposit(amount);
        else _checkRedeem(amount);
        if (flow.siloAfter != flow.assetsAfter || flow.viewAfter != flow.assetsAfter) {
            revert BugForgeProperty("view_storage");
        }
    }

    function _checkWithdraw(uint256 amount) internal view {
        if (flow.ownerTokensAfter != flow.ownerTokens + amount) revert BugForgeProperty("asset_delta");
        if (flow.siloAfter + amount != flow.siloBefore) revert BugForgeProperty("asset_delta");
        if (flow.assetsAfter + amount != flow.assetsBefore) revert BugForgeProperty("asset_delta");
        if (flow.ownerSharesAfter + flow.actual != flow.ownerShares) revert BugForgeProperty("share_delta");
        if (flow.supplyAfter + flow.actual != flow.supplyBefore) revert BugForgeProperty("share_delta");
    }

    function _checkDeposit(uint256 amount) internal view {
        if (flow.ownerTokensAfter + amount != flow.ownerTokens) revert BugForgeProperty("asset_delta");
        if (flow.siloAfter != flow.siloBefore + amount) revert BugForgeProperty("asset_delta");
        if (flow.assetsAfter != flow.assetsBefore + amount) revert BugForgeProperty("asset_delta");
        if (flow.ownerSharesAfter != flow.ownerShares + flow.actual) revert BugForgeProperty("share_delta");
        if (flow.supplyAfter != flow.supplyBefore + flow.actual) revert BugForgeProperty("share_delta");
    }

    function _checkRedeem(uint256 amount) internal view {
        if (flow.ownerTokensAfter != flow.ownerTokens + flow.actual) revert BugForgeProperty("asset_delta");
        if (flow.siloAfter + flow.actual != flow.siloBefore) revert BugForgeProperty("asset_delta");
        if (flow.assetsAfter + flow.actual != flow.assetsBefore) revert BugForgeProperty("asset_delta");
        if (flow.ownerSharesAfter + amount != flow.ownerShares) revert BugForgeProperty("share_delta");
        if (flow.supplyAfter + amount != flow.supplyBefore) revert BugForgeProperty("share_delta");
    }

    function _emitStage(string memory prefix) internal {
        _emit(prefix, "amount", flow.amount);
        _emit(prefix, "assets_before", flow.assetsBefore);
        _emit(prefix, "supply_before", flow.supplyBefore);
        _emit(prefix, "preview", flow.previewed);
        _emit(prefix, "actual", flow.actual);
        _emit(prefix, "formula", flow.formula);
        _emit(prefix, "remainder", flow.remainder);
        _emit(prefix, "b_shares", flow.ownerSharesAfter);
        _emit(prefix, "b_tokens", flow.ownerTokensAfter);
        _emit(prefix, "silo_tokens", flow.siloAfter);
        _emit(prefix, "a_shares", flow.sharesAAfter);
        _emit(prefix, "supply_after", flow.supplyAfter);
        _emit(prefix, "collateral_after", flow.assetsAfter);
    }

    function _emitFinal() internal {
        _emit("t3_", "b_shares", activeSilo.balanceOf(address(actorB)));
        _emit("t3_", "b_tokens", activeAsset.balanceOf(address(actorB)));
        _emit("t3_", "a_shares", activeSilo.balanceOf(address(actorA)));
        _emit("t3_", "supply_after", activeSilo.totalSupply());
        _emit("t3_", "silo_tokens", activeAsset.balanceOf(address(activeSilo)));
        _emit("t3_", "collateral_after", activeSilo.getTotalAssetsStorage(@@SILO@@.AssetType.Collateral));
    }
}
"""

_ZERO = """
contract ZeroShareSupplyRedepositTest is @@KIND@@Accounting {
    function test_zero_share_supply_redeposit() public {
        _setup();
        _seed();
        _mintNonExact();
        uint256 bShares = activeSilo.balanceOf(address(actorB));
        _exit(actorB, bShares, "z1_");
        uint256 aShares = activeSilo.balanceOf(address(actorA));
        _exit(actorA, aShares, "z2_");
        if (activeSilo.totalSupply() != 0) revert BugForgeProperty("supply_not_zero");
        if (flow.supplyAfter != 0) revert BugForgeProperty("supply_not_zero");
        _freshDeposit();
    }

    function _seed() internal {
        activeAsset.credit(address(actorA), SEED);
        actorA.approveAll(activeAsset, address(activeSilo));
        _loadAssets();
        _virtual();
        _floorShares(SEED);
        _take(actorA, 1, SEED);
        _captureAssets();
        if (flow.actual != flow.formula || flow.assetsAfter != SEED) revert BugForgeProperty("seed_accounting");
    }

    function _mintNonExact() internal {
        _loadAssets();
        _virtual();
        _ceilAssets(MINT_SHARES);
        if (flow.remainder == 0) revert BugForgeProperty("mint_exact");
        flow.mintAssets = flow.formula;
        flow.mintRemainder = flow.remainder;
        activeAsset.credit(address(actorB), flow.mintAssets);
        actorB.approveAll(activeAsset, address(activeSilo));
        _take(actorB, 2, MINT_SHARES);
        _captureAssets();
        flow.ratioRemainder = (flow.supplyAfter + OFFSET) % (flow.assetsAfter + 1);
        if (flow.ratioRemainder == 0) revert BugForgeProperty("ratio_exact");
        if (flow.actual != flow.mintAssets) revert BugForgeProperty("mint_assets");
        _emit("z0_", "assets_before", flow.assetsAfter);
        _emit("z0_", "supply_before", flow.supplyAfter);
        _emit("z0_", "mint_assets", flow.mintAssets);
        _emit("z0_", "mint_remainder", flow.mintRemainder);
        _emit("z0_", "ratio_remainder", flow.ratioRemainder);
        _emit("z0_", "b_shares", MINT_SHARES);
    }

    function _exit(LocalActor actor, uint256 shares, string memory prefix) internal {
        flow.amount = shares;
        _loadAssets();
        _loadOwner(actor);
        _virtual();
        _floorAssets(shares);
        if (flow.formula == 0) revert BugForgeFixture(bytes("zero_output"));
        _preview(4, shares);
        if (flow.previewed != flow.formula) revert BugForgeProperty("formula_mismatch");
        _take(actor, 4, shares);
        _captureAssets();
        _captureOwner(actor);
        if (flow.actual != flow.formula) revert BugForgeProperty("formula_mismatch");
        if (flow.ownerSharesAfter != 0) revert BugForgeProperty("exit_shares");
        if (flow.assetsAfter + flow.actual != flow.assetsBefore) revert BugForgeProperty("asset_delta");
        if (flow.supplyAfter + shares != flow.supplyBefore) revert BugForgeProperty("share_delta");
        if (flow.siloAfter + flow.actual != flow.siloBefore) revert BugForgeProperty("asset_delta");
        if (flow.ownerTokensAfter != flow.ownerTokens + flow.actual) revert BugForgeProperty("asset_delta");
        if (flow.viewAfter != flow.assetsAfter) revert BugForgeProperty("view_storage");
        _emit(prefix, "amount", shares);
        _emit(prefix, "assets_before", flow.assetsBefore);
        _emit(prefix, "supply_before", flow.supplyBefore);
        _emit(prefix, "preview", flow.previewed);
        _emit(prefix, "actual", flow.actual);
        _emit(prefix, "formula", flow.formula);
        _emit(prefix, "remainder", flow.remainder);
        _emit(prefix, "collateral_after", flow.assetsAfter);
        _emit(prefix, "supply_after", flow.supplyAfter);
    }

    function _freshDeposit() internal {
        uint256 residual = activeSilo.getTotalAssetsStorage(@@SILO@@.AssetType.Collateral);
        if (activeAsset.balanceOf(address(activeSilo)) != residual) revert BugForgeProperty("silo_balance");
        actorC = new LocalActor();
        if (address(actorC) == address(actorA) || address(actorC) == address(actorB)) {
            revert BugForgeFixture(bytes("same_actor"));
        }
        uint256 deposited = 1;
        flow.assetsBefore = residual;
        flow.supplyBefore = activeSilo.totalSupply();
        _virtual();
        _floorShares(deposited);
        uint256 resetShares = flow.formula;
        uint256 ignoredResidual = deposited * OFFSET / (residual + 1);
        _preview(1, deposited);
        if (flow.previewed != resetShares) revert BugForgeProperty("formula_mismatch");
        activeAsset.credit(address(actorC), deposited);
        actorC.approveAll(activeAsset, address(activeSilo));
        _take(actorC, 1, deposited);
        _captureAssets();
        _captureOwner(actorC);
        if (flow.actual != resetShares) revert BugForgeProperty("formula_mismatch");
        if (flow.assetsAfter != residual + deposited) revert BugForgeProperty("dust_storage");
        if (flow.supplyAfter != resetShares) revert BugForgeProperty("share_delta");
        if (flow.siloAfter != flow.assetsAfter) revert BugForgeProperty("silo_balance");
        if (residual != 0 && flow.actual == ignoredResidual) revert BugForgeProperty("reset_not_observable");
        _emit("z3_", "amount", deposited);
        _emit("z3_", "residual", residual);
        _emit("z3_", "preview", flow.previewed);
        _emit("z3_", "actual", flow.actual);
        _emit("z3_", "formula", resetShares);
        _emit("z3_", "reset_shares", resetShares);
        _emit("z3_", "stored_after", flow.assetsAfter);
        _emit("z3_", "supply_after", flow.supplyAfter);
    }
}
"""

_SEQUENCE = """
contract CollateralSequenceExplorerTest is @@KIND@@Accounting {
    uint256 internal constant SEQUENCE_LIMIT = 24;
    uint256 internal constant SEQUENCE_COUNT = @@COUNT@@;
    bytes internal constant LENGTHS = hex"@@LENGTHS@@";
    bytes internal constant OPS = hex"@@OPS@@";

    function test_collateral_sequences() public {
        if (SEQUENCE_COUNT == 0 || SEQUENCE_COUNT > SEQUENCE_LIMIT) revert BugForgeFixture(bytes("limit"));
        for (uint256 seq = 0; seq < SEQUENCE_COUNT; seq++) {
            _sequence(seq);
        }
    }

    function _sequence(uint256 seq) internal {
        delete flow;
        _setup();
        activeAsset.credit(address(actorA), FUND);
        activeAsset.credit(address(actorB), FUND);
        (uint256 start, uint256 count) = _bounds(seq);
        uint256 nonzero = 0;
        for (uint256 step = 0; step < count; step++) {
            if (_one(start + step)) nonzero += 1;
        }
        if (nonzero == 0) revert BugForgeProperty("expected_remainder");
        _emitSeq(seq, count, nonzero);
    }

    function _one(uint256 flat) internal returns (bool nonzero) {
        (uint256 actorIndex, uint256 kind, uint256 amount) = _op(flat);
        LocalActor actor = actorIndex == 0 ? actorA : actorB;
        _loadAssets();
        _loadOwner(actor);
        _loadPositions();
        _virtual();
        if (kind == 1) _floorShares(amount);
        else if (kind == 2) _ceilAssets(amount);
        else if (kind == 3) _ceilShares(amount);
        else if (kind == 4) _floorAssets(amount);
        else revert BugForgeFixture(bytes("kind"));
        if (flow.formula == 0) revert BugForgeFixture(bytes("zero_output"));
        _preview(kind, amount);
        if (flow.previewed != flow.formula) revert BugForgeProperty("formula_mismatch");
        if (kind == 1 || kind == 2) actor.approveAll(activeAsset, address(activeSilo));
        uint256 otherBefore = actorIndex == 0 ? flow.sharesB : flow.sharesA;
        _take(actor, kind, amount);
        _captureAssets();
        _captureOwner(actor);
        _capturePositions();
        _check(kind, amount, actorIndex, otherBefore);
        nonzero = flow.remainder != 0;
    }

    function _check(uint256 kind, uint256 amount, uint256 actorIndex, uint256 otherBefore) internal view {
        if (flow.actual != flow.formula) revert BugForgeProperty("formula_mismatch");
        if (kind == 1 || kind == 4) {
            if (flow.previewed > flow.actual) revert BugForgeProperty("preview_direction");
        } else if (flow.previewed < flow.actual) {
            revert BugForgeProperty("preview_direction");
        }
        if (kind == 1) _checkIn(amount, flow.actual, amount);
        else if (kind == 2) _checkIn(flow.actual, amount, flow.actual);
        else if (kind == 3) _checkOut(amount, flow.actual, amount);
        else _checkOut(flow.actual, amount, flow.actual);
        uint256 otherAfter = actorIndex == 0 ? flow.sharesBAfter : flow.sharesAAfter;
        if (otherAfter != otherBefore) revert BugForgeProperty("other_actor");
        _positions();
    }

    function _checkIn(uint256 tokenIn, uint256 sharesOut, uint256 collateralIn) internal view {
        if (flow.ownerTokensAfter + tokenIn != flow.ownerTokens) revert BugForgeProperty("asset_delta");
        if (flow.siloAfter != flow.siloBefore + collateralIn) revert BugForgeProperty("asset_delta");
        if (flow.assetsAfter != flow.assetsBefore + collateralIn) revert BugForgeProperty("asset_delta");
        if (flow.ownerSharesAfter != flow.ownerShares + sharesOut) revert BugForgeProperty("share_delta");
        if (flow.supplyAfter != flow.supplyBefore + sharesOut) revert BugForgeProperty("share_delta");
    }

    function _checkOut(uint256 tokenOut, uint256 sharesIn, uint256 collateralOut) internal view {
        if (flow.ownerTokensAfter != flow.ownerTokens + tokenOut) revert BugForgeProperty("asset_delta");
        if (flow.siloAfter + collateralOut != flow.siloBefore) revert BugForgeProperty("asset_delta");
        if (flow.assetsAfter + collateralOut != flow.assetsBefore) revert BugForgeProperty("asset_delta");
        if (flow.ownerSharesAfter + sharesIn != flow.ownerShares) revert BugForgeProperty("share_delta");
        if (flow.supplyAfter + sharesIn != flow.supplyBefore) revert BugForgeProperty("share_delta");
    }

    function _bounds(uint256 seq) internal pure returns (uint256 start, uint256 count) {
        count = uint8(LENGTHS[seq]);
        for (uint256 index = 0; index < seq; index++) start += uint8(LENGTHS[index]);
    }

    function _op(uint256 flat) internal pure returns (uint256 actor, uint256 kind, uint256 amount) {
        uint256 base = flat * 10;
        actor = uint8(OPS[base]);
        kind = uint8(OPS[base + 1]);
        for (uint256 index = 0; index < 8; index++) {
            amount = (amount << 8) | uint8(OPS[base + 2 + index]);
        }
    }

    function _emitSeq(uint256 seq, uint256 steps, uint256 nonzero) internal {
        bytes memory prefix = "q00_";
        prefix[1] = bytes1(uint8(48 + (seq / 10)));
        prefix[2] = bytes1(uint8(48 + (seq % 10)));
        _emit(string(prefix), "steps", steps);
        _emit(string(prefix), "nonzero", nonzero);
        _emit(string(prefix), "assets", flow.assetsAfter);
        _emit(string(prefix), "supply", flow.supplyAfter);
    }
}
"""
