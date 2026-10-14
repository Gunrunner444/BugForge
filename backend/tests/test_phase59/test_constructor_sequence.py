"""The constructor boundary sequence stays visible and is not executed as a call."""

from __future__ import annotations

from app.discovery.bounty.stateful import build_harness
from app.discovery.bounty.vfcs import ATTACKER, SequenceIdentity, Vfcs, VfcsCall
from app.parsing.solidity_research import build_research_model

SOURCE = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Box {
    struct Configuration {
        uint256 total;
    }
    uint256 public total;
    constructor(Configuration memory config) {
        total = config.total;
    }
    function poke(uint256 value) external {
        total = value;
    }
}
"""


def test_a_constructor_sequence_is_reclassified_and_not_deleted() -> None:
    call = VfcsCall(
        "Box",
        "constructor()",
        "batch",
        ATTACKER,
        arguments=(("config", "boundary_value"),),
        established_by="arithmetic.unsafe_downcast_after_arithmetic",
    )
    sequence = Vfcs(
        sequence_id="vf_constructor_boundary",
        template="boundary-batch",
        origin="arithmetic.unsafe_downcast_after_arithmetic@Box.constructor()",
        calls=(call,),
        property_under_test="totals must not wrap or truncate",
        derived_from="arithmetic.unsafe_downcast_after_arithmetic@Box.constructor()",
        identity=SequenceIdentity(campaign_id="phase59"),
    )
    model = build_research_model({"Box.sol": SOURCE})
    harness = build_harness(sequence, model, sources={"Box.sol": SOURCE})
    assert sequence.sequence_id == "vf_constructor_boundary"
    assert sequence.calls[0].function == "constructor()"
    assert harness.buildable is False
    assert harness.reason_code == "constructor_not_a_call"
    assert harness.source == ""
    assert "address(0x" not in harness.reason
    assert "boundary_value" not in harness.source
    plain = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Plain {
    function poke(uint256 value) external pure returns (uint256) { return value; }
}
"""
    poke = VfcsCall(
        "Plain", "poke(uint256)", "batch", ATTACKER, arguments=(("value", "boundary_value"),)
    )
    poke_sequence = Vfcs(
        sequence_id="vf_poke",
        template="boundary-batch",
        origin="test",
        calls=(poke,),
        property_under_test="totals must not wrap or truncate",
        derived_from="arithmetic.unsafe_downcast_after_arithmetic@Plain.poke(uint256)",
        identity=SequenceIdentity(campaign_id="phase59"),
    )
    plain_model = build_research_model({"Plain.sol": plain})
    built = build_harness(poke_sequence, plain_model, sources={"Plain.sol": plain})
    assert built.buildable, built.reason
    assert built.reason_code != "constructor_not_a_call"
