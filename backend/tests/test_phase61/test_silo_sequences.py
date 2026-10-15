"""The Silo collateral sequence enumerator is deterministic and bounded."""

from __future__ import annotations

from app.discovery.bounty.silo_collateral_sequences import (
    generate_collateral_sequences,
    trace_round_trip,
    trace_zero_supply,
)


def test_collateral_sequences_are_a_bounded_deterministic_subset() -> None:
    first = generate_collateral_sequences()
    second = generate_collateral_sequences()
    assert first["executed"] == second["executed"]
    assert first["enumeration"] == "deterministic-beam-v1"
    assert first["limit"] == 24
    assert first["max_length"] == 6
    assert first["executed_count"] == 24
    assert first["examined"] == first["invalid_count"] + first["generated_count"]
    assert first["generated_count"] == (
        first["excluded_count"] + first["retained_prefix_count"] + first["executed_count"]
    )
    lengths = first["length_counts"]
    assert lengths == {"3": 6, "4": 6, "5": 6, "6": 6}
    assert first.get("candidate") is None
    for sequence in first["executed"]:
        steps = sequence["steps"]
        assert 3 <= len(steps) <= 6
        names = {step["op"] for step in steps}
        actors = {step["actor"] for step in steps}
        assert names & {"deposit", "mint"}
        assert names & {"withdraw", "redeem"}
        assert actors == {0, 1}
        assert any(step["remainder"] for step in steps)
        assert sequence["selection_reason"]


def test_round_trip_and_zero_supply_models_match_the_source_formula() -> None:
    round_trip = trace_round_trip()
    assert round_trip["mint_assets"] == 3
    assert round_trip["withdraw_shares"] == 1000
    assert round_trip["redeposit_shares"] == 999
    assert round_trip["redeem_assets"] == 2
    assert round_trip["final_assets"] == 1_000_001
    assert round_trip["final_shares"] == 1_000_000_000
    assert round_trip["final_b_shares"] == 0
    zero = trace_zero_supply()
    assert zero["supply_after_exit"] == 0
    assert zero["residual_assets"] == 1
    assert zero["fresh_shares"] == 1000
    assert zero["fresh_stored_assets"] == 2
    assert zero["no_reset_shares"] == 500
    assert zero["reset_observable"] is True
