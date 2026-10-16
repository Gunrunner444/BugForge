"""Comet 059c1191 is the deployed cUSDCv3 implementation source, and the trace reads it.

Source identity is the pinned file hashes. The local build uses the verified
standard-JSON settings and must reproduce the recompiled runtime recorded for
the implementation (immutables unset). The custody trace and profile are checked
against that exact source; a held run elsewhere is not a statement about this one.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from hashlib import sha256

import pytest

from app.discovery.bounty.constructor_profile import (
    ProfileError,
    comet_custody_profile,
    comet_pause_profile,
    parse_profile,
    prepare_profile,
)
from app.discovery.bounty.solc_resolve import resolve_solc
from app.parsing.solidity_conservation import (
    MAX_TRACE_VISITS,
    _Walker,
    custody_pairs,
)
from app.parsing.solidity_research import build_research_model
from tests.test_compound_custody.deployed_support import (
    CLOSURE,
    CONTRACT,
    DEPLOYED_COMPILER,
    DEPLOYED_PIN,
    TARGET,
    deployed_root,
    deployed_sources,
)

# Sourcify standard-JSON settings of the verified implementation.
_YUL_STEPS = (
    "dhfoDgvulfnTUtnIf [xa[r]scLM cCTUtTOntnfDIul Lcul Vcul [j] Tpeul xa[rul] xa[r]cL gvif "
    "CTUca[r]LsTOtfDnca[r]Iulc] jmul[jul] VcTOcul jmul"
)
VERIFIED_SETTINGS = {
    "viaIR": True,
    "metadata": {"bytecodeHash": "ipfs"},
    "libraries": {},
    "optimizer": {
        "runs": 1,
        "details": {
            "cse": True,
            "yul": True,
            "inliner": True,
            "peephole": True,
            "yulDetails": {"optimizerSteps": _YUL_STEPS, "stackAllocation": True},
            "deduplicate": True,
            "orderLiterals": True,
            "jumpdestRemover": True,
            "constantOptimizer": True,
        },
    },
    "evmVersion": "london",
    "remappings": [],
}
RECOMPILED_RUNTIME_SHA256 = "6d2880e8f4e757a698fe46569fb2f7ef91af2447b72b4326eb8f58e714c8770e"
RECOMPILED_RUNTIME_BYTES = 18_599


def _line(sources: dict[str, str], pattern: str) -> int:
    text = sources[TARGET]
    match = re.search(pattern, text)
    assert match is not None, pattern
    return text.count("\n", 0, match.start()) + 1


def test_the_checkout_is_the_deployed_source_and_its_compiler_settings() -> None:
    root = deployed_root()
    sources = deployed_sources(root)
    assert tuple(sources) == CLOSURE
    config = (root / "hardhat.config.ts").read_text(encoding="utf-8")
    assert "version: '0.8.15'" in config
    assert "runs: 1," in config
    assert _YUL_STEPS in config
    assert "viaIR: process.env['OPTIMIZER_DISABLED'] ? false : true" in config
    assert DEPLOYED_COMPILER["version"] == "0.8.15"
    assert DEPLOYED_COMPILER["evm_version"] == VERIFIED_SETTINGS["evmVersion"]


def test_the_contract_graph_is_closed_over_the_pinned_files() -> None:
    sources = deployed_sources(deployed_root())
    for path, text in sources.items():
        for imported in re.findall(r'^\s*import\s+"([^"]+)"', text, re.MULTILINE):
            resolved = os.path.normpath(os.path.join(os.path.dirname(path), imported))
            assert resolved in sources, f"{path} imports {resolved}, outside the closure"
    model = build_research_model(sources)
    assert model.contracts[CONTRACT].kind == "contract"
    assert {"CometMainInterface", "CometCore", "CometStorage", "CometConfiguration"} <= set(
        model.bases_of(CONTRACT)
    )
    fields = model.struct_fields("Configuration")
    assert fields is not None
    assert "baseToken" in [param.name for param in fields]


def test_the_custody_trace_reads_the_deployed_supply_and_withdraw() -> None:
    sources = deployed_sources(deployed_root())
    model = build_research_model(sources)
    pairs, notes = custody_pairs(model, CONTRACT)
    assert [(p.deposit.signature, p.payout.signature) for p in pairs] == [
        ("supply(address,uint256)", "withdraw(address,uint256)")
    ]
    pair = pairs[0]
    assert pair.mapping == "userBasic" and pair.credit_field == "principal"
    assert pair.token_binding == "state:baseToken"
    assert pair.token_source == "constructor struct field config.baseToken"
    assert pair.deposit_token_argument == "asset" and pair.payout_token_argument == "asset"
    assert pair.deposit_amount_argument == "amount" and pair.payout_amount_argument == "amount"
    assert pair.token_must_differ_from == ""
    assert pair.getter == "balanceOf(address)"
    assert pair.initializer == "initializeStorage()"
    assert pair.incomplete == ()
    pull_line = _line(sources, r"transferFrom\(from, address\(this\)")
    pay_line = _line(sources, r"IERC20NonStandard\(asset\)\.transfer\(")
    assert pair.pull.site == f"{TARGET}:{pull_line} {CONTRACT}.doTransferIn"
    assert pair.pay.site == f"{TARGET}:{pay_line} {CONTRACT}.doTransferOut"
    assert [step.split(".")[-1].split("(")[0] for step in pair.pull.path] == [
        "supply",
        "supplyInternal",
        "supplyBase",
        "doTransferIn",
    ]
    assert [step.split(".")[-1].split("(")[0] for step in pair.pay.path] == [
        "withdraw",
        "withdrawInternal",
        "withdrawBase",
        "doTransferOut",
    ]
    assert any("state-bound token is kept" in note for note in notes)
    walker = _Walker(model, CONTRACT)
    for entry in (pair.deposit, pair.payout):
        trace = walker.trace(entry)
        assert not trace.truncated and len(trace.visited) < MAX_TRACE_VISITS


def test_the_custody_profile_binds_the_deployed_source_and_rejects_changes() -> None:
    sources = deployed_sources(deployed_root())
    profile = comet_custody_profile(sources, source_commit=DEPLOYED_PIN)
    prepared = prepare_profile(profile, sources)
    assert prepared.harness_token == "baseToken"
    assert prepared.harness_token_fields == ("baseToken",)
    assert "baseToken: address(bfToken)" in prepared.expression
    assert not any("bfToken =" in line for line in prepared.deploy_lines)
    assert {path for path, _ in profile.bound_files} >= {
        TARGET,
        "contracts/IAssetListFactory.sol",
        "contracts/IAssetListFactoryHolder.sol",
    }
    changed = dict(sources)
    changed["contracts/IAssetListFactory.sol"] += "\n"
    with pytest.raises(ProfileError, match="profile_source_mismatch"):
        prepare_profile(profile, changed)
    raw = profile.to_dict()
    raw["fixtures"] = [
        {**item, "decimals": 6} if item["kind"] == "harness_token" else item
        for item in raw["fixtures"]
    ]
    with pytest.raises(ProfileError, match="profile_fixture_incompatible"):
        parse_profile(raw)
    # The f766f515 profile names the moved interface paths, so it does not bind here.
    with pytest.raises(ProfileError, match="not in the source closure"):
        comet_pause_profile(sources)


def test_the_local_build_reproduces_the_verified_runtime() -> None:
    sources = deployed_sources(deployed_root())
    solc = resolve_solc("0.8.15")
    if solc is None:
        if os.environ.get("BUGFORGE_REQUIRE_FOUNDRY") == "1":
            pytest.fail("the Compound job requires solc 0.8.15")
        pytest.skip("solc 0.8.15 is not installed")
    settings = {
        **VERIFIED_SETTINGS,
        "outputSelection": {TARGET: {CONTRACT: ["evm.deployedBytecode.object"]}},
    }
    request = {
        "language": "Solidity",
        "sources": {path: {"content": text} for path, text in sources.items()},
        "settings": settings,
    }
    completed = subprocess.run(
        [solc.path, "--standard-json"],
        input=json.dumps(request),
        capture_output=True,
        text=True,
        timeout=600,
        check=True,
    )
    output = json.loads(completed.stdout)
    errors = [e for e in output.get("errors", []) if e.get("severity") == "error"]
    assert not errors, errors
    runtime = bytes.fromhex(
        output["contracts"][TARGET][CONTRACT]["evm"]["deployedBytecode"]["object"]
    )
    assert len(runtime) == RECOMPILED_RUNTIME_BYTES
    assert sha256(runtime).hexdigest() == RECOMPILED_RUNTIME_SHA256
