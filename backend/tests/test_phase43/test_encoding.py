"""Phase 43 harness binding.

Tool runners in this file are simulated. They do not show that solc or forge
is installed. A live tool test is skipped when the binary is absent.
"""

from __future__ import annotations

import shutil
from dataclasses import replace
from pathlib import Path

import pytest

from app.domain.evidence import EvidenceKind
from app.domain.lifecycle_policy import independent_verification_items, positive_reproduction
from app.parsing.engine import parse_source, reset_syntax_registry
from app.parsing.solidity_ir import build_semantic_program
from app.parsing.solidity_spec import (
    binds,
    capability_matrix,
    generate_forge_artifact,
    generate_smt_artifact,
    parse_forge_bound,
    parse_smt_bound,
    specify,
)
from app.parsing.solidity_state_transitions import (
    analyze_accounting_transition,
    analyze_state_transitions,
)
from app.parsing.solidity_verification import (
    bridge,
    evidence_for,
    lifecycle_effect,
    run_forge,
    run_smt,
)
from app.plugins import reset_plugin_catalog

_EQUALITY = """
pragma solidity ^0.8.20;
contract Vault {
    uint256 public totalSupply;
    uint256 public balances;
    function mint() external {
        totalSupply = totalSupply + 1;
    }
}
"""

_SAFE = """
pragma solidity ^0.8.20;
contract Vault {
    uint256 public totalSupply;
    uint256 public balances;
    function mint() external {
        totalSupply = totalSupply + 1;
        balances = balances + 1;
    }
}
"""


def _program(tmp_path: Path, source: str, name: str = "Vault.sol"):
    reset_syntax_registry()
    reset_plugin_catalog()
    path = tmp_path / name
    path.write_text(source, encoding="utf-8")
    return build_semantic_program(parse_source("solidity", path, source)), source


def _encoded_spec(tmp_path: Path, source: str = _EQUALITY):
    program, text = _program(tmp_path, source)
    model = analyze_state_transitions(program)
    path = next(item for item in model.paths if item.path_id.startswith("accounting:"))
    spec = specify(path, model, program)
    return program, text, model, path, spec


def test_capability_matrix_matches_the_encoder() -> None:
    matrix = capability_matrix()
    assert matrix["equality-scalar"] == {"smt": "supported", "foundry": "supported"}
    assert matrix["monotonic-increment"] == {"smt": "supported", "foundry": "supported"}
    assert matrix["equality-mapping-sum"]["smt"] == "unsupported"
    assert matrix["asset-share"]["smt"] == "unsupported"
    assert matrix["erc4626-conservation"]["foundry"] == "unsupported"
    assert matrix["reentrancy"]["foundry"] == "unsupported"


def test_scalar_equality_harness_contains_the_predicate(tmp_path: Path) -> None:
    _program_obj, text, _model, path, spec = _encoded_spec(tmp_path)
    assert spec.smt == "supported"
    assert spec.foundry == "supported"
    assert spec.proof_scope == "contract-copy-harness"
    assert spec.predicate_lhs == "totalSupply"
    assert spec.predicate_rhs == "balances"
    smt = generate_smt_artifact(spec, text)
    forge = generate_forge_artifact(spec, text)
    assert smt.encoding_status == "encoded"
    assert forge.encoding_status == "encoded"
    assert "assert(true)" not in smt.harness
    assert "assertTrue(true)" not in forge.harness
    assert "mint();" in smt.harness
    assert "assert(totalSupply == balances);" in smt.harness
    assert spec.specification_hash in smt.harness
    assert "target.mint();" in forge.harness
    assert f'revert("bugforge-fail:{spec.specification_hash}")' in forge.harness
    assert "totalSupply" in forge.harness and "balances" in forge.harness
    assert binds(smt, spec, text)[0]
    assert binds(forge, spec, text)[0]
    assert path.invariant_id == spec.invariant_id


def test_only_a_named_smt_result_is_authoritative(tmp_path: Path) -> None:
    _program_obj, text, _model, _path, spec = _encoded_spec(tmp_path)
    artifact = generate_smt_artifact(spec, text)
    request = bridge(_program_obj, analyze_state_transitions(_program_obj)).requests[0]
    unrelated = run_smt(
        request,
        text,
        specification=spec,
        artifact=artifact,
        runner=lambda _harness: (
            0,
            "Info: CHC: Assertion violation happens here.\n\nproperty proved",
            "",
        ),
    )
    assert unrelated.status == "unknown"
    assert unrelated.bound is False
    proved = run_smt(
        request,
        text,
        specification=spec,
        artifact=artifact,
        runner=lambda _harness: (
            0,
            f"Info: {artifact.token} proved safe.",
            "",
        ),
    )
    assert proved.status == "proved_safe"
    assert proved.bound is True
    assert proved.proof_scope == "contract-copy-harness"
    assert evidence_for(proved).kind is EvidenceKind.STATIC_ANALYSIS
    assert not positive_reproduction(evidence_for(proved))
    violated = run_smt(
        request,
        text,
        specification=spec,
        artifact=artifact,
        runner=lambda _harness: (
            1,
            f"Warning: CHC: Assertion violation happens here.\nCounterexample:\n{artifact.token}\n",
            "",
        ),
    )
    assert violated.status == "counterexample"
    assert violated.bound is True
    assert violated.counterexample is not None
    assert violated.counterexample.failing_property == artifact.token
    assert evidence_for(violated).kind is EvidenceKind.STATIC_ANALYSIS
    distant = run_smt(
        request,
        text,
        specification=spec,
        artifact=artifact,
        runner=lambda _harness: (
            0,
            artifact.token + "\n" + ("\n".join(["unrelated"] * 12)) + "\nproperty proved\n",
            "",
        ),
    )
    assert distant.status == "unknown"
    other_line = run_smt(
        request,
        text,
        specification=spec,
        artifact=artifact,
        runner=lambda _harness: (
            1,
            "Other.sol:3:1: Warning: CHC: Assertion violation happens here.",
            "",
        ),
    )
    assert other_line.status == "unknown"


def test_modified_bindings_stay_non_authoritative(tmp_path: Path) -> None:
    _program_obj, text, _model, _path, spec = _encoded_spec(tmp_path)
    artifact = generate_smt_artifact(spec, text)
    request = next(
        item
        for item in bridge(_program_obj, analyze_state_transitions(_program_obj)).requests
        if item.specification_hash == spec.specification_hash
    )
    changed = run_smt(
        request,
        text,
        specification=spec,
        artifact=artifact,
        harness=artifact.harness + "\n// changed\n",
        runner=lambda _harness: (0, f"{artifact.token} proved", ""),
    )
    assert changed.status == "unknown"
    assert changed.bound is False
    stale = replace(artifact, specification_hash="0" * 64)
    assert binds(stale, spec, text)[0] is False
    wrong_source = run_smt(
        request,
        text + "\n",
        specification=spec,
        artifact=artifact,
        runner=lambda _harness: (0, f"{artifact.token} proved", ""),
    )
    assert wrong_source.status == "unknown"
    wrong_contract = replace(spec, contract="Other")
    assert binds(artifact, wrong_contract, text) == (False, "manifest contract mismatch")
    wrong_ops = replace(spec, operation_ids=("other-op",))
    assert binds(artifact, wrong_ops, text)[1] == "manifest operation mismatch"
    wrong_path = replace(spec, path_id="path:other")
    assert binds(artifact, wrong_path, text)[1] == "manifest path mismatch"
    wrong_compiler = replace(spec, compiler_config="0.7.0")
    assert binds(artifact, wrong_compiler, text)[1] == "compiler configuration mismatch"
    lied = replace(artifact, harness=artifact.harness + "\n// lied\n")
    assert binds(lied, spec, text)[1] == "harness digest mismatch"


def test_unsupported_property_has_no_assertion(tmp_path: Path) -> None:
    source = """
    pragma solidity ^0.8.20;
    contract Vault {
        uint256 totalSupply;
        mapping(address => uint256) balances;
        function mint() external { totalSupply = totalSupply + 1; }
    }
    """
    program, text = _program(tmp_path, source)
    model = analyze_state_transitions(program)
    path = next(item for item in model.paths if item.invariant_id.startswith("inv:supply-balance:"))
    spec = specify(path, model, program)
    assert spec.smt == "unsupported"
    artifact = generate_smt_artifact(spec, text)
    assert artifact.encoding_status == "unsupported"
    assert "assert(" not in artifact.harness
    assert "assert(true)" not in artifact.harness
    result = run_smt(
        bridge(program, model).requests[0],
        text,
        specification=spec,
        artifact=artifact,
        runner=lambda _harness: (0, "property proved", ""),
    )
    assert result.status == "unsupported"
    assert result.bound is False


def test_simulated_forge_reproduction_requires_the_fail_token(tmp_path: Path) -> None:
    """The runner is simulated. This does not execute forge."""
    program, text, model, _path, spec = _encoded_spec(tmp_path)
    artifact = generate_forge_artifact(spec, text)
    request = next(
        item
        for item in bridge(program, model).requests
        if item.specification_hash == spec.specification_hash
    )
    failing = f"Suite result: FAILED\n[FAIL] {artifact.fail_token}\n"
    reproduced = run_forge(
        request,
        specification=spec,
        artifact=artifact,
        source=text,
        runner=lambda _harness: (1, failing, ""),
    )
    assert reproduced.status == "reproduced"
    assert reproduced.bound is True
    assert reproduced.counterexample is not None
    assert reproduced.counterexample.failing_property == artifact.fail_token
    evidence = evidence_for(reproduced)
    assert evidence.kind is EvidenceKind.REPRODUCTION
    assert positive_reproduction(evidence)
    assert independent_verification_items((evidence,)) == ()
    assert lifecycle_effect(reproduced) == "none"
    fake = run_forge(
        request,
        specification=spec,
        artifact=artifact,
        source=text,
        runner=lambda _harness: (1, "Suite result: FAILED\n[FAIL] test_other()", ""),
    )
    assert fake.status == "unknown"
    assert fake.bound is False
    assert evidence_for(fake).kind is EvidenceKind.TOOL_STATUS
    passing = run_forge(
        request,
        specification=spec,
        artifact=artifact,
        source=text,
        runner=lambda _harness: (0, "Suite result: ok", ""),
    )
    assert passing.status == "unknown"
    assert "not a proof" in passing.diagnostics[-1]
    assert evidence_for(passing).kind is EvidenceKind.TOOL_STATUS
    assert parse_forge_bound("Suite result: FAILED", artifact) == "unknown"
    assert parse_smt_bound("property proved", "", artifact) == "unknown"


def test_paired_update_is_not_a_forge_failure(tmp_path: Path) -> None:
    """A simulated passing run stays unknown. This runner is not forge."""
    program, text = _program(tmp_path, _SAFE)
    model = analyze_state_transitions(program)
    assert analyze_accounting_transition(program, "mint").status != "potential"
    if not model.paths:
        queued = bridge(program, model)
        assert queued.results == () or all(
            item.status == "not_requested" for item in queued.results
        )
        return
    spec = specify(model.paths[0], model, program)
    artifact = generate_forge_artifact(spec, text)
    result = run_forge(
        bridge(program, model).requests[0],
        specification=spec,
        artifact=artifact,
        source=text,
        runner=lambda _harness: (0, "Suite result: ok", ""),
    )
    assert result.status in {"unknown", "unsupported"}
    assert result.status != "reproduced"
    assert result.status != "proved_safe"
    assert evidence_for(result).kind is EvidenceKind.TOOL_STATUS


@pytest.mark.skipif(shutil.which("solc") is None, reason="solc is not installed")
def test_live_solc_smt(tmp_path: Path) -> None:
    program, text, model, _path, spec = _encoded_spec(tmp_path)
    request = next(
        item
        for item in bridge(program, model).requests
        if item.specification_hash == spec.specification_hash
    )
    result = run_smt(request, text, specification=spec)
    assert result.tool == "smt"
    assert result.status in {
        "counterexample",
        "proved_safe",
        "unknown",
        "unsupported",
        "timeout",
        "failed",
    }
    if result.status in {"counterexample", "proved_safe"}:
        assert result.bound is True


@pytest.mark.skipif(shutil.which("forge") is None, reason="forge is not installed")
def test_live_forge_replay(tmp_path: Path) -> None:
    program, text, model, _path, spec = _encoded_spec(tmp_path)
    request = next(
        item
        for item in bridge(program, model).requests
        if item.specification_hash == spec.specification_hash
    )
    result = run_forge(request, specification=spec, source=text)
    assert result.tool == "forge"
    assert result.status in {
        "reproduced",
        "unknown",
        "unsupported",
        "timeout",
        "failed",
        "unavailable",
    }
    if result.status == "reproduced":
        assert result.bound is True
        assert result.counterexample is not None
        assert spec.specification_hash in result.counterexample.raw_artifact
