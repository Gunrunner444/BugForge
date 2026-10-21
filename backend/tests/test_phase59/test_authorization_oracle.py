"""Authorization verdicts require the source error, not an arbitrary revert."""

from __future__ import annotations

from app.discovery.bounty.constructor_profile import parse_profile, sha256_text
from app.discovery.bounty.properties import (
    OracleKind,
    OracleObservation,
    OracleSpec,
    PropertyVerdict,
    build_property,
    evaluate,
)
from app.discovery.bounty.stateful import Outcome, StatefulExecutor, build_harness
from app.discovery.bounty.vfcs import (
    ATTACKER,
    SequenceIdentity,
    Vfcs,
    VfcsCall,
    stamp_source_identity,
)
from app.parsing.keccak import function_selector
from app.parsing.solidity_research import build_research_model
from tests.test_phase52.phase52_support import requires_forge
from tests.test_phase58.test_constructor_profile import FILE, VAULT, _profile, _sequence

SELECTOR = function_selector("Unauthorized()")
OTHER = function_selector("Other()")
SIGNATURE = "pause(bool,bool,bool,bool,bool)"


def _oracle(**overrides: object) -> OracleSpec:
    raw = {
        "kind": OracleKind.CALL_MUST_FAIL,
        "probe_role": "execute",
        "probe_function": SIGNATURE,
        "getter": "isSupplyPaused()",
        "revert_selector": SELECTOR,
        "control_sender": "address(0xC0FE)",
    }
    raw.update(overrides)
    return OracleSpec(**raw)  # type: ignore[arg-type]


def _sequence_for(contract: str = "PauseVault") -> Vfcs:
    call = VfcsCall(
        contract,
        SIGNATURE,
        "execute",
        ATTACKER,
        arguments=(
            ("supplyPaused", "true"),
            ("transferPaused", "false"),
            ("withdrawPaused", "false"),
            ("absorbPaused", "false"),
            ("buyPaused", "false"),
        ),
    )
    return Vfcs(
        sequence_id="vf_auth",
        template="unauthorized-call",
        origin="test",
        calls=(call,),
        property_under_test="unauthorized pause",
        derived_from=f"profile.authorization@{contract}.{SIGNATURE}",
        identity=SequenceIdentity(campaign_id="phase59"),
    )


def _held_observation(**overrides: object) -> OracleObservation:
    raw: dict[str, object] = {
        "call_ok": (0,),
        "before": "0x" + "00" * 32,
        "after": "0x" + "00" * 32,
        "revert_selector": SELECTOR,
        "revert_data_ok": True,
        "control_ok": 1,
        "control_before": "0x" + "00" * 32,
        "control_after": "0x" + "01".rjust(64, "0"),
    }
    raw.update(overrides)
    return OracleObservation(**raw)  # type: ignore[arg-type]


def test_expected_authorization_error_and_control_change_hold() -> None:
    result = evaluate(_sequence_for(), _oracle(), _held_observation())
    assert result.verdict is PropertyVerdict.PROPERTY_HELD
    assert result.evaluated is True
    assert result.positive_control == "changed"
    assert SELECTOR in result.reason
    assert "positive control changed it" in result.reason
    assert result.as_dict()["verified"] is False


def test_a_held_authorization_does_not_invent_a_positive_control() -> None:
    oracle = _oracle(control_sender="")
    result = evaluate(
        _sequence_for(),
        oracle,
        _held_observation(control_ok=-1, control_before="", control_after=""),
    )
    assert result.verdict is PropertyVerdict.PROPERTY_HELD
    assert result.positive_control == "not_run"
    assert "no positive control was part of this test" in result.reason
    assert "changed it" not in result.reason


def test_a_different_revert_does_not_hold() -> None:
    result = evaluate(_sequence_for(), _oracle(), _held_observation(revert_selector=OTHER))
    assert result.verdict is PropertyVerdict.NOT_EVALUATED
    assert result.evaluated is False
    assert result.positive_control == "changed"


def test_missing_or_truncated_revert_data_is_not_a_verdict() -> None:
    missing = evaluate(
        _sequence_for(), _oracle(), _held_observation(revert_selector="", revert_data_ok=False)
    )
    assert missing.verdict is PropertyVerdict.NOT_EVALUATED
    short = evaluate(
        _sequence_for(), _oracle(), _held_observation(revert_selector="0x82", revert_data_ok=False)
    )
    assert short.verdict is PropertyVerdict.NOT_EVALUATED


def test_a_successful_unauthorized_call_is_a_violation() -> None:
    result = evaluate(_sequence_for(), _oracle(), _held_observation(call_ok=(1,)))
    assert result.verdict is PropertyVerdict.PROPERTY_VIOLATED
    assert result.evaluated is True
    assert result.as_dict()["verified"] is False


def test_changed_or_unreadable_state_is_not_held() -> None:
    changed = evaluate(
        _sequence_for(),
        _oracle(),
        _held_observation(before="0x" + "00" * 32, after="0x" + "01".rjust(64, "0")),
    )
    assert changed.verdict is PropertyVerdict.PROPERTY_VIOLATED
    unreadable = evaluate(_sequence_for(), _oracle(), _held_observation(readable=False))
    assert unreadable.verdict is PropertyVerdict.NOT_EVALUATED
    assert unreadable.evaluated is False


def test_failed_or_unchanged_positive_control_is_not_held() -> None:
    failed = evaluate(_sequence_for(), _oracle(), _held_observation(control_ok=0))
    assert failed.verdict is PropertyVerdict.NOT_EVALUATED
    assert failed.positive_control == "failed"
    unchanged = evaluate(
        _sequence_for(),
        _oracle(),
        _held_observation(
            control_before="0x" + "01".rjust(64, "0"), control_after="0x" + "01".rjust(64, "0")
        ),
    )
    assert unchanged.verdict is PropertyVerdict.NOT_EVALUATED
    assert unchanged.positive_control == "unchanged"


def test_selector_less_revert_still_uses_the_old_oracle() -> None:
    """A generic CALL_MUST_FAIL does not start requiring custom-error selectors."""
    oracle = _oracle(revert_selector="", control_sender="")
    held = evaluate(_sequence_for(), oracle, OracleObservation((0,), before="0x01", after="0x01"))
    assert held.verdict is PropertyVerdict.PROPERTY_HELD
    assert "expected authorization error" not in held.reason
    violated = evaluate(
        _sequence_for(), oracle, OracleObservation((1,), before="0x01", after="0x01")
    )
    assert violated.verdict is PropertyVerdict.PROPERTY_VIOLATED


def test_the_pause_selector_comes_from_the_declared_error() -> None:
    sources = {FILE: VAULT}
    model = build_research_model(sources)
    spec = build_property(_sequence(), model)
    assert spec.oracle.revert_selector == SELECTOR
    assert spec.oracle.control_sender == "address(0xC0FE)"
    assert "error Unauthorized();" in VAULT
    bare = VAULT.replace("error Unauthorized();", "error Other();").replace(
        "revert Unauthorized();", 'revert("unauthorized");'
    )
    string_model = build_research_model({FILE: bare})
    string_spec = build_property(_sequence(), string_model)
    assert string_spec.oracle.revert_selector == ""
    assert string_spec.oracle.executable


OTHER_VAULT = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract PauseVault {
    error Unauthorized();
    error Other();
    struct Configuration {
        address governor;
        address pauseGuardian;
    }
    address public governor;
    address public pauseGuardian;
    uint8 public pauseFlags;
    constructor(Configuration memory config) {
        governor = config.governor;
        pauseGuardian = config.pauseGuardian;
    }
    function pause(bool supplyPaused, bool, bool, bool, bool) external {
        if (msg.sender != governor && msg.sender != pauseGuardian) revert Other();
        pauseFlags = supplyPaused ? 1 : 0;
    }
    function isSupplyPaused() public view returns (bool) {
        return (pauseFlags & 1) != 0;
    }
}
"""

OPEN_VAULT = OTHER_VAULT.replace(
    "        if (msg.sender != governor && msg.sender != pauseGuardian) revert Other();\n",
    "",
)

LOCKED_VAULT = OTHER_VAULT.replace("revert Other();", "revert Unauthorized();").replace(
    "        pauseFlags = supplyPaused ? 1 : 0;\n",
    "",
)


def _profile_for(source: str):  # type: ignore[no-untyped-def]
    digest = sha256_text(source)
    raw = _profile()
    raw["source_sha256"] = digest
    raw["bound_files"] = [{"path": FILE, "sha256": digest}]
    return parse_profile(raw)


def _run_manual(source: str, oracle: OracleSpec):  # type: ignore[no-untyped-def]
    sources = {FILE: source}
    sequence = stamp_source_identity(_sequence_for(), sources)
    model = build_research_model(sources)
    spec = build_property(sequence, model)
    executor = StatefulExecutor(profile=_profile_for(source))
    return executor.execute(sequence, model, sources, spec=spec, oracle=oracle)


@requires_forge
def test_harness_rejects_a_different_revert_and_accepts_the_real_error() -> None:
    wrong = _run_manual(OTHER_VAULT, _oracle())
    assert wrong.outcome is not Outcome.PROPERTY_HELD
    assert wrong.verdict == PropertyVerdict.NOT_EVALUATED.value
    assert wrong.strong_candidate is False
    real = VAULT.replace("pragma solidity 0.8.15;", "pragma solidity ^0.8.20;")
    held = _run_manual(real, _oracle())
    assert held.outcome is Outcome.PROPERTY_HELD, held.reason
    assert held.evaluation is not None
    assert held.evaluation.positive_control == "changed"
    assert held.strong_candidate is False


@requires_forge
def test_an_authorized_call_that_succeeds_for_the_attacker_is_a_violation() -> None:
    violated = _run_manual(OPEN_VAULT, _oracle())
    assert violated.outcome is Outcome.PROPERTY_VIOLATED, violated.reason
    assert violated.verified is False


@requires_forge
def test_a_control_that_does_not_change_pause_state_is_not_held() -> None:
    blocked = _run_manual(LOCKED_VAULT, _oracle())
    assert blocked.outcome is not Outcome.PROPERTY_HELD
    assert blocked.verdict == PropertyVerdict.NOT_EVALUATED.value
    harness = build_harness(
        _sequence_for(),
        build_research_model({FILE: LOCKED_VAULT}),
        oracle=_oracle(),
        sources={FILE: LOCKED_VAULT},
        profile=_profile_for(LOCKED_VAULT),
    )
    assert harness.buildable, harness.reason
    assert "vm.prank(address(0xC0FE))" in harness.source
    assert harness.source.count("pause(bool,bool,bool,bool,bool)") >= 1
