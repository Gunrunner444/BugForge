"""Pinned Yearn Tokenized Strategy 3.0.4 source replay.

The checkout is the published tag, not ``master``. IdleHost is the local harness
host already used for this replay. A missing pin fails the dedicated CI job and
skips elsewhere. Execution is the ordinary campaign service with a run cap.
"""

from __future__ import annotations

import hashlib
import os
import shutil
from pathlib import Path

import pytest

from app.discovery.bounty.campaign import BountyManifest
from app.discovery.bounty.constructor_profile import sha256_text
from app.discovery.bounty.service import BountyCampaignService, CampaignSpec
from app.parsing.solidity_research import ResearchModel, SemanticCandidate, build_research_model
from app.parsing.solidity_research_suite import run_suite

PIN = "82806289f967590c4efbf6bc3d237e4e7f0a0966"
OZ_PIN = "bd325d56b4c62c9c5c1aff048c37c6bb18ac0290"
LITERAL = "0xD377919FA87120584B21279a491F82D5265A139c"
# Every file assemble() copies. A checkout without .git still has to match these bytes.
HASHES = {
    "src/IdleHost.sol": "bf4f97bc424d5859f50d187e8ff3ecaf7d725527da468c32ac89ed17d2ce243a",
    "src/BaseStrategy.sol": "6f049ce40a56409cca0d50d5e134b096fbf5ec5e2c3b88b4fe7cadd4c177063a",
    "src/TokenizedStrategy.sol": "af2cce2ece0a80c52fa431fce193cf6557fa7533bce0486cf6c13d0f9d46a403",
    "src/interfaces/IBaseStrategy.sol": "6a45e5d4f023c192fcf3406e1bee1c565a800bf10a6a7e7b4a58dbcfd8819033",
    "src/interfaces/IFactory.sol": "9d5a324d30c11d176e028706f8dabe91c697f999337a0b4d8d5209b5cfe18547",
    "src/interfaces/ITokenizedStrategy.sol": "005721def46904d829c379704d17d8cd6890a3f728e83cb34901f3761e0a22b8",
    "src/interfaces/IEvents.sol": "5e30aebb45453435e0f1085ec4934f68951ddc2907d6a7ecdaf662e266c427f2",
    "src/interfaces/IStrategy.sol": "124ead70858aa5e53b88d29c92251883b13203c475d829228ac526caca2a1382",
    "src/test/mocks/MockFactory.sol": "a24b2cac185794feb3b951a1bbe194030e3c5625ddc6cc18fcd8e6b55173685c",
    "lib/openzeppelin-contracts/contracts/interfaces/IERC4626.sol": (
        "f02aea42886cfa5696322761f926fd4d0f133eb977da4d019911acc298386c1e"
    ),
    "lib/openzeppelin-contracts/contracts/token/ERC20/ERC20.sol": (
        "d20d52b4be98738b8aa52b5bb0f88943f62128969b33d654fbca731539a7fe0a"
    ),
    "lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol": (
        "7ebde70853ccafcf1876900dad458f46eb9444d591d39bfc58e952e2582f5587"
    ),
    "lib/openzeppelin-contracts/contracts/token/ERC20/extensions/IERC20Metadata.sol": (
        "af5c8a77965cc82c33b7ff844deb9826166689e55dc037a7f2f790d057811990"
    ),
    "lib/openzeppelin-contracts/contracts/token/ERC20/extensions/IERC20Permit.sol": (
        "bbf4d26d660ce8f9c9887af3a46bf4eab5f4c15eb8413ad89b65ecdd05dee7a9"
    ),
    "lib/openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol": (
        "82dc918d8df553e2461b96595580e565424b407d73dab8a7ce4bde479810fb2a"
    ),
    "lib/openzeppelin-contracts/contracts/utils/Address.sol": (
        "8b85a2463eda119c2f42c34fa3d942b61aee65df381f48ed436fe8edb3a7d602"
    ),
    "lib/openzeppelin-contracts/contracts/utils/Context.sol": (
        "b2cfee351bcafd0f8f27c72d76c054df9b571b62cfac4781ed12c86354e2a56c"
    ),
    "lib/openzeppelin-contracts/contracts/utils/math/Math.sol": (
        "85a2caf3bd06579fb55236398c1321e15fd524a8fe140dff748c0f73d7a52345"
    ),
}
YEARN_FILES = (
    "src/BaseStrategy.sol",
    "src/TokenizedStrategy.sol",
    "src/interfaces/IBaseStrategy.sol",
    "src/interfaces/IFactory.sol",
    "src/interfaces/ITokenizedStrategy.sol",
    "src/interfaces/IEvents.sol",
    "src/interfaces/IStrategy.sol",
    "src/test/mocks/MockFactory.sol",
)
OZ_FILES = (
    "contracts/interfaces/IERC4626.sol",
    "contracts/token/ERC20/ERC20.sol",
    "contracts/token/ERC20/IERC20.sol",
    "contracts/token/ERC20/extensions/IERC20Metadata.sol",
    "contracts/token/ERC20/extensions/IERC20Permit.sol",
    "contracts/token/ERC20/utils/SafeERC20.sol",
    "contracts/utils/Address.sol",
    "contracts/utils/Context.sol",
    "contracts/utils/math/Math.sol",
)
IDLE = Path(__file__).resolve().parents[1] / "fixtures" / "yearn_replay" / "IdleHost.sol"
DEPLOYED = Path(__file__).resolve().parents[1] / "fixtures" / "yearn_replay" / "DeployedHost.sol"


def _require(name: str) -> str:
    value = os.environ.get(name, "")
    if value:
        return value
    if os.environ.get("BUGFORGE_REQUIRE_YEARN") == "1":
        pytest.fail(f"{name} is not available and this job requires the pinned Yearn replay")
    pytest.skip(f"{name} is not set")
    return ""


def assemble(tmp_path: Path) -> dict[str, str]:
    """Copy the pinned sources into one tree and return the source map."""
    yearn = Path(_require("BUGFORGE_YEARN_ROOT"))
    oz = Path(_require("BUGFORGE_OZ_ROOT"))
    if not yearn.is_dir() or not oz.is_dir():
        if os.environ.get("BUGFORGE_REQUIRE_YEARN") == "1":
            pytest.fail("the pinned Yearn or OpenZeppelin checkout is not available")
        pytest.skip("the pinned Yearn checkout is not available")
    head = yearn / ".git"
    if head.exists():
        commit = (
            __import__("subprocess")
            .check_output(["git", "-C", str(yearn), "rev-parse", "HEAD"], text=True)
            .strip()
        )
        assert commit == PIN
        oz_commit = (
            __import__("subprocess")
            .check_output(["git", "-C", str(oz), "rev-parse", "HEAD"], text=True)
            .strip()
        )
        assert oz_commit == OZ_PIN
    root = tmp_path / "yearn-replay"
    root.mkdir()
    for relative in YEARN_FILES:
        source = yearn / relative
        assert source.is_file(), relative
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
    shutil.copyfile(IDLE, root / "src" / "IdleHost.sol")
    for relative in OZ_FILES:
        source = oz / relative
        assert source.is_file(), relative
        destination = root / "lib" / "openzeppelin-contracts" / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
    files = {path.relative_to(root).as_posix(): path.read_text() for path in root.rglob("*.sol")}
    assert set(files) == set(HASHES), sorted(set(files) ^ set(HASHES))
    for path, digest in HASHES.items():
        assert hashlib.sha256(files[path].encode()).hexdigest() == digest, path
    return files


def _profile(files: dict[str, str], *, protocol_bps: str = "0") -> dict[str, object]:
    """IdleHost profile. ``protocol_bps`` is the MockFactory constructor argument."""
    bound = tuple(HASHES)
    return {
        "profile_id": "yearn-idle-host",
        "contract": "IdleHost",
        "source_file": "src/IdleHost.sol",
        "source_sha256": sha256_text(files["src/IdleHost.sol"]),
        "parameter": "asset_",
        "model_type": "address",
        "solidity_type": "address",
        "struct_file": "src/IdleHost.sol",
        "struct_name": "address",
        "value": {"kind": "fixture", "value": "asset"},
        "fixtures": [
            {"fixture_id": "asset", "kind": "harness_token", "decimals": 18},
            {
                "fixture_id": "factory",
                "kind": "source_contract",
                "contract": "MockFactory",
                "arguments": [
                    {"kind": "uint", "value": protocol_bps},
                    {"kind": "role", "value": "governor"},
                ],
            },
            {
                "fixture_id": "implementation",
                "kind": "source_contract",
                "contract": "TokenizedStrategy",
                "depends_on": "factory",
                "place_at": LITERAL,
                "arguments": [{"kind": "fixture", "value": "factory"}],
            },
        ],
        "imports": ["src/TokenizedStrategy.sol", "src/test/mocks/MockFactory.sol"],
        "bound_files": [{"path": path, "sha256": sha256_text(files[path])} for path in bound],
        "assumptions": [
            "IdleHost is a local host whose callbacks leave funds idle",
            "TokenizedStrategy runtime is placed at the address literal in BaseStrategy",
            "MockFactory is a local factory and is not the vault factory. "
            f"Its protocol fee argument is {protocol_bps}",
            "asset() must return the harness token before token accounting runs",
            "this run is a local source replay, not deployed-runtime equivalence",
        ],
        "property_function": "asset()",
        "property_statement": "asset() returns the harness token after the host initializes",
        "property_getter": "asset()",
        "property_template": "initialization-asset",
        "source_commit": PIN,
    }


def _expect_scenarios(
    sequences: list[object],
    observations: list[dict[str, object]],
    expected: dict[str, dict[str, str]],
    *,
    excluded: dict[str, str] | None = None,
) -> None:
    """Require one observation per sequence id. A count match is not that correspondence.

    Every generated template is either an expected scenario or an intentional exclusion
    with a reason. A duplicate of one id cannot stand in for a missing id. An expected
    scenario that did not compile, did not execute, or stayed inconclusive fails here.
    """
    excluded = dict(excluded or {})
    problems: list[str] = []
    overlap = sorted(set(expected) & set(excluded))
    if overlap:
        problems.append(f"templates listed as both expected and excluded: {overlap}")
    by_template: dict[str, list[str]] = {}
    id_to_template: dict[str, str] = {}
    for item in sequences:
        template = str(item.template)  # type: ignore[attr-defined]
        sequence_id = str(item.sequence_id)  # type: ignore[attr-defined]
        by_template.setdefault(template, []).append(sequence_id)
        previous = id_to_template.get(sequence_id)
        if previous is not None:
            problems.append(f"{sequence_id}: duplicate sequence id for {previous} and {template}")
        id_to_template[sequence_id] = template
    for template, ids in by_template.items():
        if template not in expected and template not in excluded:
            problems.append(
                f"{template}: generated ({', '.join(ids)}) but neither an expected "
                "scenario nor an intentional exclusion"
            )
    for template in expected:
        if template not in by_template:
            problems.append(f"{template}: sequence was not generated")
    for template, reason in excluded.items():
        if template not in by_template:
            problems.append(f"{template}: exclusion names a sequence that was not generated")
        if not reason.strip():
            problems.append(f"{template}: an intentional exclusion needs a reason")
    observed: dict[str, list[dict[str, object]]] = {}
    for row in observations:
        observed.setdefault(str(row.get("sequence_id", "")), []).append(row)
    expected_ids = set(id_to_template)
    observed_ids = set(observed)
    if expected_ids != observed_ids:
        missing = sorted(expected_ids - observed_ids)
        extra = sorted(observed_ids - expected_ids)
        if missing:
            problems.append(f"missing observations for {missing}")
        if extra:
            problems.append(f"unexpected observations for {extra}")
    for sequence_id, rows in sorted(observed.items()):
        if len(rows) != 1:
            problems.append(
                f"{sequence_id}: {len(rows)} observations; each sequence needs exactly one"
            )
    unjudged = {
        "inconclusive",
        "sequence_executed_no_oracle",
        "compile_failed",
        "execution_failed",
        "unavailable",
    }
    for template, spec in expected.items():
        for sequence_id in by_template.get(template, []):
            rows = observed.get(sequence_id) or []
            if len(rows) != 1:
                continue
            row = rows[0]
            label = f"{template} {sequence_id}"
            if row.get("verified"):
                problems.append(f"{label}: verified was set")
            outcome = str(row.get("outcome"))
            kind = str(row.get("oracle_kind"))
            if outcome != spec.get("outcome") or kind != spec.get("oracle_kind"):
                problems.append(f"{label}: {outcome} {kind} {row.get('reason')}")
            if outcome in unjudged:
                problems.append(
                    f"{label}: {outcome} does not judge this scenario: {row.get('reason')}"
                )
            for key, needle in spec.items():
                if key in {"outcome", "oracle_kind"} or not needle:
                    continue
                if needle not in str(row.get("reason")):
                    problems.append(f"{label}: reason lacks {needle!r}: {row.get('reason')}")
    for template, reason in excluded.items():
        for sequence_id in by_template.get(template, []):
            rows = observed.get(sequence_id) or []
            if len(rows) != 1:
                continue
            row = rows[0]
            label = f"{template} {sequence_id}"
            outcome = str(row.get("outcome"))
            if outcome in {"property_held", "property_violated"}:
                problems.append(f"{label}: exclusion cannot hide a judged {outcome}")
            if reason not in str(row.get("reason")):
                problems.append(f"{label}: exclusion {reason!r} not in {row.get('reason')}")
            if row.get("verified"):
                problems.append(f"{label}: verified was set")
    if problems:
        raise AssertionError("\n".join(problems))


def _report_candidates(model: ResearchModel) -> list[SemanticCandidate]:
    return [
        item
        for item in run_suite(model).candidates
        if item.detector == "accounting.reported_balance" and item.function == "report()"
    ]


def test_the_pinned_sources_expose_a_balance_backed_report(tmp_path: Path) -> None:
    files = assemble(tmp_path)
    text = files["src/TokenizedStrategy.sol"]
    expected_line = text[: text.index("S.totalAssets = newTotalAssets;")].count("\n") + 1
    model = build_research_model(files)
    unresolved = _report_candidates(model)
    assert len(unresolved) == 1
    bare = unresolved[0]
    assert bare.contract == "TokenizedStrategy"
    assert bare.line == expected_line
    assert bare.fact("balance_backed") == "false"
    assert bare.fact("report_scope") == "unresolved"
    assert bare.fact("reported_form") == "other"
    function = model.function("TokenizedStrategy", "report")
    assert function is not None
    assert bare.line != function.line + function.body.find("newTotalAssets")
    model.reporting_host = "IdleHost"
    model.reporting_host_evidence = "validated_profile"
    found = _report_candidates(model)
    assert len(found) == 1
    hosted = found[0]
    assert hosted.fact("balance_backed") == "true"
    assert hosted.fact("reported_form") == "idle_balance"
    assert hosted.fact("report_scope") == "host"
    assert hosted.fact("reporting_host") == "IdleHost"
    assert hosted.fact("stored_getter") == "totalAssets()"
    assert hosted.fact("role_getter") == "keeper()"
    assert hosted.fact("unlock_seconds") == "864000"
    assert hosted.fact("loss_ignored") == "false"
    assert hosted.fact("store_relation") == "equal"
    assert hosted.fact("token_behavior") == "unknown"
    assert hosted.line == expected_line
    assert any("unlock formula" in item for item in hosted.missing)
    assert any("protocol-fee share split" in item for item in hosted.missing)
    assert any("performance-fee share mint" in item for item in hosted.missing)
    assert any("locked-share" in item for item in hosted.missing)


def test_yearn_replay_executes_the_report_through_the_campaign_service(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if os.environ.get("BUGFORGE_YEARN_EXECUTE") != "1":
        if os.environ.get("BUGFORGE_REQUIRE_YEARN") == "1":
            pytest.fail("the Yearn job must execute the source replay")
        pytest.skip("BUGFORGE_YEARN_EXECUTE is not set")
    from tests.test_phase52.phase52_support import _has

    if not (_has("forge") and _has("solc")):
        pytest.fail("forge and solc are required to execute the Yearn replay")
    files = assemble(tmp_path)
    root = tmp_path / "campaign"
    root.mkdir()
    for path, text in files.items():
        destination = root / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(text)
    import app.discovery.bounty.service as service_module
    from app.core.config import get_settings

    monkeypatch.setattr(
        get_settings(),
        "bounty_campaign_database_url",
        f"sqlite:///{tmp_path / 'campaigns.sqlite'}",
        raising=False,
    )
    monkeypatch.setattr(service_module, "_SERVICE", None, raising=False)
    manifest = BountyManifest.from_dict(
        {
            "platform": "local",
            "program_id": "yearn-replay",
            "program_name": "Yearn source replay",
            "rules_version": "local",
            "in_scope": [{"kind": "contract", "identifier": "TokenizedStrategy"}],
            "out_of_scope": [],
            "known_issues": [],
            "poc_requirement": "required",
            "testing_mode": "local_only",
            "repository": "https://github.com/yearn/tokenized-strategy",
            "source_commit": PIN,
            "deployments": [],
            "chain_ids": ["1"],
            "compiler": {
                "version": "0.8.18",
                "optimizer": "enabled",
                "optimizer_runs": "200",
                "via_ir": "false",
                "evm_version": "paris",
            },
            "impact_categories": [
                {
                    "name": "Direct theft of user funds",
                    "severity": "critical",
                    "weight": 90,
                    "tags": ["custody", "vault_accounting"],
                }
            ],
        }
    )
    service = BountyCampaignService()
    campaign = service.create(
        CampaignSpec(
            manifest=manifest,
            repo_root=root,
            contract="TokenizedStrategy",
            source_file="src/TokenizedStrategy.sol",
            files=tuple(sorted(files)),
            constructor_profile=_profile(files),
            address=LITERAL,
            chain_id="1",
        )
    )
    result = service.stateful_execute(campaign.campaign_id, rounds=1, max_runs=30)
    assert result["available"] is True, result.get("blocker") or result.get("reason")
    assert result["forge_runs"] <= 30
    observations = result["observations"]
    assert isinstance(observations, list)
    analysis = service._analysis(campaign)
    report_candidates = [
        item
        for item in analysis.candidates
        if item.detector == "accounting.reported_balance" and item.function == "report()"
    ]
    assert report_candidates
    assert report_candidates[0].fact("reported_form") == "idle_balance"
    assert report_candidates[0].fact("report_scope") == "host"
    report_sequences = [
        item
        for item in analysis.sequences
        if item.derived_from.startswith("accounting.reported_balance@")
        or item.derived_from.startswith("accounting.fee_shares@")
    ]
    report_ids = {item.sequence_id for item in report_sequences}
    assert report_ids
    report_obs = [item for item in observations if item["sequence_id"] in report_ids]
    held = [item for item in report_obs if item["outcome"] == "property_held"]
    violated = [item for item in report_obs if item["outcome"] == "property_violated"]
    inconclusive = [item for item in report_obs if item["outcome"] == "inconclusive"]
    unsupported = [
        item
        for item in report_obs
        if item["declaration"] == "property_unsupported"
        or item["outcome"] == "sequence_executed_no_oracle"
    ]
    role_blocked = [item for item in report_obs if item["reason_code"] == "role_unconfirmed"]
    failures = [
        item
        for item in report_obs
        if item["outcome"] in {"compile_failed", "execution_failed", "unavailable"}
    ]
    _expect_scenarios(
        report_sequences,
        report_obs,
        {
            "donate→report": {
                "outcome": "property_held",
                "oracle_kind": "credit_matches_reported",
                "reason_has": "==",
            },
            "report": {
                "outcome": "property_held",
                "oracle_kind": "credit_matches_reported",
                "reason_has": "==",
            },
            "unauthorized-report": {
                "outcome": "property_held",
                "oracle_kind": "call_must_fail",
            },
            "donate→report→warp→report": {
                "outcome": "property_held",
                "oracle_kind": "credit_matches_reported",
                "reason_has": "==",
            },
            "fee-no-change": {
                "outcome": "property_held",
                "oracle_kind": "fee_shares_match",
                "reason_has": "profit 0",
                "reason_locked": "is not a fee",
            },
            "fee-profit": {
                "outcome": "property_held",
                "oracle_kind": "fee_shares_match",
                "reason_has": "performance delta 100000000000000000 == 100000000000000000",
                "reason_protocol": "protocol delta 0 == 0",
                "reason_profit": "profit 1000000000000000000",
                "reason_locked": "is not a fee",
            },
            "fee-rounding": {
                "outcome": "property_held",
                "oracle_kind": "fee_shares_match",
                "reason_has": "performance delta 1 == 1",
                "reason_protocol": "protocol delta 0 == 0",
                "reason_profit": "profit 15",
            },
            "fee-dust": {
                "outcome": "property_held",
                "oracle_kind": "fee_shares_match",
                "reason_has": "performance delta 0 == 0",
                "reason_profit": "profit 9",
            },
        },
    )
    assert report_candidates[0].fact("store_relation") == "equal"
    missing = list(report_candidates[0].missing)
    assert any("unlock formula" in item for item in missing)
    assert any("performance-fee share mint" in item for item in missing)
    assert any("protocol-fee share split" in item for item in missing)
    assert any("locked-share" in item for item in missing)
    fees = [
        item
        for item in analysis.candidates
        if item.detector == "accounting.fee_shares" and item.function == "report()"
    ]
    assert len(fees) == 1
    assert fees[0].fact("fee_complete") == "true"
    assert fees[0].fact("host_dependence") == "observed_inputs"
    assert any("unlock formula" in item for item in fees[0].missing)
    assert any("locked-share" in item for item in fees[0].missing)
    for row in report_obs:
        reason = str(row.get("reason", "")).lower()
        assert "theft" not in reason
        if row["oracle_kind"] == "fee_shares_match":
            assert row["applicability_disposition"] == "target_applicable"
        if row["oracle_kind"] == "credit_matches_reported":
            assert row["applicability_disposition"] == "unconfirmed"
    assert not inconclusive, [(item["outcome"], item.get("reason")) for item in inconclusive]
    assert not unsupported
    assert not role_blocked
    assert not failures
    assert not violated
    assert held
    assert not any(item.get("verified") for item in observations)
    assert result["forge_runs"] >= 1


def test_deployed_host_reports_above_idle_holdings_without_a_violation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A host with a public deployed balance is not judged as an idle-only strategy."""
    if os.environ.get("BUGFORGE_YEARN_EXECUTE") != "1":
        if os.environ.get("BUGFORGE_REQUIRE_YEARN") == "1":
            pytest.fail("the Yearn job must execute the deployed-host replay")
        pytest.skip("BUGFORGE_YEARN_EXECUTE is not set")
    from tests.test_phase52.phase52_support import _has

    if not (_has("forge") and _has("solc")):
        pytest.fail("forge and solc are required to execute the Yearn replay")
    files = assemble(tmp_path)
    deployed_text = DEPLOYED.read_text()
    files["src/DeployedHost.sol"] = deployed_text
    root = tmp_path / "deployed-campaign"
    root.mkdir()
    for path, text in files.items():
        destination = root / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(text)
    import app.discovery.bounty.service as service_module
    from app.core.config import get_settings

    monkeypatch.setattr(
        get_settings(),
        "bounty_campaign_database_url",
        f"sqlite:///{tmp_path / 'deployed.sqlite'}",
        raising=False,
    )
    monkeypatch.setattr(service_module, "_SERVICE", None, raising=False)
    profile = _profile(files)
    profile["profile_id"] = "yearn-deployed-host"
    profile["contract"] = "DeployedHost"
    profile["source_file"] = "src/DeployedHost.sol"
    profile["source_sha256"] = sha256_text(deployed_text)
    profile["struct_file"] = "src/DeployedHost.sol"
    bound = list(profile["bound_files"])
    bound.append({"path": "src/DeployedHost.sol", "sha256": sha256_text(deployed_text)})
    profile["bound_files"] = bound
    profile["asset_units"] = [
        {"contract": "DeployedHost", "getter": "deployed()", "evidence": "validated_profile"},
    ]
    profile["assumptions"] = [
        "DeployedHost is a local host whose report adds a public deployed balance",
        "deployed() is asset-denominated only because this profile says validated_profile",
        "TokenizedStrategy runtime is placed at the address literal in BaseStrategy",
        "MockFactory returns a zero protocol fee and is not the vault factory",
        "this run is a local source replay, not deployed-runtime equivalence",
    ]
    manifest = BountyManifest.from_dict(
        {
            "platform": "local",
            "program_id": "yearn-deployed-replay",
            "program_name": "Yearn deployed-host replay",
            "rules_version": "local",
            "in_scope": [{"kind": "contract", "identifier": "TokenizedStrategy"}],
            "out_of_scope": [],
            "known_issues": [],
            "poc_requirement": "required",
            "testing_mode": "local_only",
            "repository": "https://github.com/yearn/tokenized-strategy",
            "source_commit": PIN,
            "deployments": [],
            "chain_ids": ["1"],
            "compiler": {
                "version": "0.8.18",
                "optimizer": "enabled",
                "optimizer_runs": "200",
                "via_ir": "false",
                "evm_version": "paris",
            },
            "impact_categories": [
                {
                    "name": "Direct theft of user funds",
                    "severity": "critical",
                    "weight": 90,
                    "tags": ["custody", "vault_accounting"],
                }
            ],
        }
    )
    service = BountyCampaignService()
    campaign = service.create(
        CampaignSpec(
            manifest=manifest,
            repo_root=root,
            contract="TokenizedStrategy",
            source_file="src/TokenizedStrategy.sol",
            files=tuple(sorted(files)),
            constructor_profile=profile,
            address=LITERAL,
            chain_id="1",
        )
    )
    result = service.stateful_execute(campaign.campaign_id, rounds=1, max_runs=30)
    assert result["available"] is True, result.get("blocker") or result.get("reason")
    analysis = service._analysis(campaign)
    report = [
        item
        for item in analysis.candidates
        if item.detector == "accounting.reported_balance" and item.function == "report()"
    ]
    assert len(report) == 1
    assert report[0].fact("reported_form") == "idle_plus_getter"
    assert report[0].fact("balance_backed") == "false"
    assert report[0].fact("external_getter") == "deployed()"
    assert report[0].fact("asset_units") == "validated_profile"
    assert report[0].fact("report_scope") == "host"
    assert report[0].fact("reporting_host") == "DeployedHost"
    observations = result["observations"]
    assert isinstance(observations, list)
    report_sequences = [
        item
        for item in analysis.sequences
        if item.derived_from.startswith("accounting.reported_balance@")
        or item.derived_from.startswith("accounting.fee_shares@")
    ]
    report_ids = {item.sequence_id for item in report_sequences}
    report_obs = [item for item in observations if item["sequence_id"] in report_ids]
    _expect_scenarios(
        report_sequences,
        report_obs,
        {
            "donate→report": {
                "outcome": "property_held",
                "oracle_kind": "credit_matches_reported",
                "reason_has": "deployed()",
            },
            "report": {
                "outcome": "property_held",
                "oracle_kind": "credit_matches_reported",
                "reason_has": "==",
            },
            "unauthorized-report": {
                "outcome": "property_held",
                "oracle_kind": "call_must_fail",
            },
            "gain→report": {
                "outcome": "property_held",
                "oracle_kind": "credit_matches_reported",
                "reason_has": "deployed()",
            },
            "donate→report→warp→report": {
                "outcome": "property_held",
                "oracle_kind": "credit_matches_reported",
                "reason_has": "==",
            },
            "fee-no-change": {
                "outcome": "property_held",
                "oracle_kind": "fee_shares_match",
                "reason_has": "profit 0",
                "reason_locked": "is not a fee",
            },
            "fee-profit": {
                "outcome": "property_held",
                "oracle_kind": "fee_shares_match",
                "reason_has": "performance delta 100000000000000000 == 100000000000000000",
                "reason_protocol": "protocol delta 0 == 0",
            },
            "fee-rounding": {
                "outcome": "property_held",
                "oracle_kind": "fee_shares_match",
                "reason_has": "performance delta 1 == 1",
                "reason_profit": "profit 15",
            },
            "fee-dust": {
                "outcome": "property_held",
                "oracle_kind": "fee_shares_match",
                "reason_has": "profit 9",
                "reason_zero": "performance delta 0 == 0",
            },
        },
    )
    assert report[0].fact("store_relation") == "equal"
    assert result["forge_runs"] <= 30
    assert not any(item.get("verified") for item in observations)


def _boot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    files: dict[str, str],
    profile: dict[str, object],
    program_id: str,
) -> tuple[BountyCampaignService, object, dict[str, object]]:
    root = tmp_path / program_id
    root.mkdir()
    for path, text in files.items():
        destination = root / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(text)
    import app.discovery.bounty.service as service_module
    from app.core.config import get_settings

    monkeypatch.setattr(
        get_settings(),
        "bounty_campaign_database_url",
        f"sqlite:///{tmp_path / program_id}.sqlite",
        raising=False,
    )
    monkeypatch.setattr(service_module, "_SERVICE", None, raising=False)
    manifest = BountyManifest.from_dict(
        {
            "platform": "local",
            "program_id": program_id,
            "program_name": program_id,
            "rules_version": "local",
            "in_scope": [{"kind": "contract", "identifier": "TokenizedStrategy"}],
            "out_of_scope": [],
            "known_issues": [],
            "poc_requirement": "required",
            "testing_mode": "local_only",
            "repository": "https://github.com/yearn/tokenized-strategy",
            "source_commit": PIN,
            "deployments": [],
            "chain_ids": ["1"],
            "compiler": {
                "version": "0.8.18",
                "optimizer": "enabled",
                "optimizer_runs": "200",
                "via_ir": "false",
                "evm_version": "paris",
            },
            "impact_categories": [
                {
                    "name": "Direct theft of user funds",
                    "severity": "critical",
                    "weight": 90,
                    "tags": ["custody", "vault_accounting"],
                }
            ],
        }
    )
    service = BountyCampaignService()
    campaign = service.create(
        CampaignSpec(
            manifest=manifest,
            repo_root=root,
            contract="TokenizedStrategy",
            source_file="src/TokenizedStrategy.sol",
            files=tuple(sorted(files)),
            constructor_profile=profile,
            address=LITERAL,
            chain_id="1",
        )
    )
    result = service.stateful_execute(campaign.campaign_id, rounds=1, max_runs=30)
    return service, campaign, result


def test_nonzero_protocol_fee_splits_performance_shares(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Protocol fee 2000 bps to the governor treasury. Supply starts at zero.

    The strategy is freshly initialized: stored total assets 0, total supply 0,
    performance fee 1000 from the pinned initializer, recipient the deploying
    harness. Profit is a token transfer into the strategy, then report(), whose
    host callback returns the idle balance. Shares equal profit because supply
    is 0. Protocol shares are floor(feeShares * 2000 / 10000). The profile label
    is not an input to the judge.
    """
    if os.environ.get("BUGFORGE_YEARN_EXECUTE") != "1":
        if os.environ.get("BUGFORGE_REQUIRE_YEARN") == "1":
            pytest.fail("the Yearn job must execute the nonzero protocol-fee replay")
        pytest.skip("BUGFORGE_YEARN_EXECUTE is not set")
    from tests.test_phase52.phase52_support import _has

    if not (_has("forge") and _has("solc")):
        pytest.fail("forge and solc are required to execute the Yearn replay")
    files = assemble(tmp_path)
    profile = _profile(files, protocol_bps="2000")
    profile["profile_id"] = "yearn-protocol-fee-host"
    service, campaign, result = _boot(tmp_path, monkeypatch, files, profile, "yearn-protocol-fee")
    assert result["available"] is True, result.get("blocker") or result.get("reason")
    assert result["forge_runs"] <= 30
    analysis = service._analysis(campaign)
    fees = [
        item
        for item in analysis.candidates
        if item.detector == "accounting.fee_shares" and item.function == "report()"
    ]
    assert len(fees) == 1
    assert fees[0].fact("fee_complete") == "true"
    assert "2000" not in " ".join(value for _key, value in fees[0].facts)
    observations = result["observations"]
    assert isinstance(observations, list)
    report_sequences = [
        item
        for item in analysis.sequences
        if item.derived_from.startswith("accounting.reported_balance@")
        or item.derived_from.startswith("accounting.fee_shares@")
    ]
    report_ids = {item.sequence_id for item in report_sequences}
    report_obs = [item for item in observations if item["sequence_id"] in report_ids]
    _expect_scenarios(
        report_sequences,
        report_obs,
        {
            "donate→report": {
                "outcome": "property_held",
                "oracle_kind": "credit_matches_reported",
                "reason_has": "==",
            },
            "report": {
                "outcome": "property_held",
                "oracle_kind": "credit_matches_reported",
                "reason_has": "==",
            },
            "unauthorized-report": {
                "outcome": "property_held",
                "oracle_kind": "call_must_fail",
            },
            "donate→report→warp→report": {
                "outcome": "property_held",
                "oracle_kind": "credit_matches_reported",
                "reason_has": "==",
            },
            "fee-no-change": {
                "outcome": "property_held",
                "oracle_kind": "fee_shares_match",
                "reason_has": "profit 0",
                "reason_locked": "is not a fee",
            },
            "fee-profit": {
                "outcome": "property_held",
                "oracle_kind": "fee_shares_match",
                "reason_has": "performance delta 80000000000000000 == 80000000000000000",
                "reason_protocol": "protocol delta 20000000000000000 == 20000000000000000",
                "reason_profit": "profit 1000000000000000000",
            },
            "fee-rounding": {
                "outcome": "property_held",
                "oracle_kind": "fee_shares_match",
                "reason_has": "performance delta 1 == 1",
                "reason_protocol": "protocol delta 0 == 0",
                "reason_profit": "profit 15",
            },
            "fee-dust": {
                "outcome": "property_held",
                "oracle_kind": "fee_shares_match",
                "reason_has": "performance delta 0 == 0",
                "reason_profit": "profit 9",
            },
        },
    )
    profit_ids = {item.sequence_id for item in report_sequences if item.template == "fee-profit"}
    assert len(profit_ids) == 1
    profit = next(row for row in report_obs if row["sequence_id"] in profit_ids)
    evaluation = profit.get("evaluation")
    assert isinstance(evaluation, dict)
    evidence = evaluation.get("evidence")
    assert isinstance(evidence, dict)
    assert evidence["fee_performance_bps"] == "1000"
    assert evidence["fee_protocol_bps"] == "2000"
    assert "theft" not in str(profit.get("reason")).lower()
    assert profit.get("verified") is False
