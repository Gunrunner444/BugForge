"""Explicit local addresses and source-declared enums."""

from __future__ import annotations

from app.discovery.bounty.constructor_profile import (
    ProfileError,
    argument_digest,
    parse_profile,
    prepare_profile,
    sha256_text,
)
from app.discovery.bounty.properties import OracleSpec
from app.discovery.bounty.stateful import _Synth, _UnbuildableError, abi_type
from app.discovery.bounty.vfcs import SequenceIdentity, Vfcs, VfcsCall
from app.parsing.solidity_research import Param, build_research_model
from tests.test_phase58.test_constructor_profile import STATEMENT, _profile

HOST = "Host.sol"
LOCAL = "0x0000000000000000000000000000000000000001"
HOST_TEXT = """// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;
interface IFactory { function id() external view returns (uint256); }
contract Host {
    enum CollateralType { Protected, Collateral }
    IFactory public factory;
    constructor(IFactory _factory) { factory = _factory; }
    function deposit(uint256 assets, address receiver, CollateralType kind) external {}
}
"""


def _address_raw(**overrides: object) -> dict[str, object]:
    value = {
        "kind": "address",
        "value": LOCAL,
        "provenance": "local_fixture",
    }
    raw = _profile(
        contract="Host",
        parameter="_factory",
        source_file=HOST,
        source_sha256=sha256_text(HOST_TEXT),
        model_type="address",
        solidity_type="IFactory",
        struct_file=HOST,
        struct_name="address",
        imports=[],
        bound_files=[{"path": HOST, "sha256": sha256_text(HOST_TEXT)}],
        fixtures=[],
        value=value,
    )
    from app.discovery.bounty.constructor_profile import ProfileValue

    raw["argument_sha256"] = argument_digest(
        "_factory", "IFactory", ProfileValue("address", LOCAL, provenance="local_fixture")
    )
    raw.update(overrides)
    return raw


def test_an_address_profile_stays_accepted_when_it_does_not_seed_a_property() -> None:
    from types import SimpleNamespace

    from app.discovery.bounty.constructor_profile import attach_profile_seed

    raw = _address_raw(source_commit="ab" * 20)
    analysis = SimpleNamespace(
        sequence_skipped={},
        sources={HOST: HOST_TEXT},
        sequence_identity=SequenceIdentity(),
        sequences=(),
        models={},
        sequence_sources={},
        candidates=(),
    )
    campaign = SimpleNamespace(
        spec=SimpleNamespace(constructor_profile=raw),
        manifest=SimpleNamespace(source_commit="ab" * 20),
        selection=SimpleNamespace(mode="explicit", selected=[HOST], role_of=lambda _path: "target"),
        cache={},
    )
    record = attach_profile_seed(campaign, analysis)
    assert record is not None
    assert record["validation"] == "accepted"
    assert record["sequence"] == "not_seeded"
    assert analysis.sequences == ()


def test_an_explicit_local_address_matches_the_constructor() -> None:
    prepared = prepare_profile(parse_profile(_address_raw()), {HOST: HOST_TEXT})
    assert prepared.expression == f"address({LOCAL})"
    assert prepared.provenance["configuration"]["provenance"] == "local_fixture"
    assert prepared.provenance["solidity_type"] == "IFactory"


def test_omitted_mistyped_and_tampered_addresses_are_rejected() -> None:
    missing = _address_raw()
    del missing["argument_sha256"]
    try:
        parse_profile(missing)
    except ProfileError as exc:
        assert exc.code == "profile_malformed"
    else:
        raise AssertionError("a missing address hash was accepted")
    tampered = _address_raw(argument_sha256="ab" * 32)
    try:
        parse_profile(tampered)
    except ProfileError as exc:
        assert exc.code == "profile_tampered"
    else:
        raise AssertionError("a modified address hash was accepted")
    wrong = _address_raw(
        value={"kind": "uint", "value": "1"},
        model_type="address",
    )
    try:
        parse_profile(wrong)
    except ProfileError as exc:
        assert exc.code == "profile_type_mismatch"
    else:
        raise AssertionError("a uint was accepted as an address")
    unproven = _address_raw()
    unproven["value"] = {"kind": "address", "value": LOCAL}
    try:
        parse_profile(unproven)
    except ProfileError as exc:
        assert exc.code == "profile_address_rejected"
    else:
        raise AssertionError("an address without provenance was accepted")


def test_enum_members_and_indexes_match_the_source_and_unknown_values_do_not() -> None:
    sources = {HOST: HOST_TEXT}
    model = build_research_model(sources)
    assert abi_type(model, "CollateralType") == "uint8"
    assert abi_type(model, "Host.CollateralType") == "uint8"
    synth = _Synth(
        model,
        Vfcs("id", "template", "origin", (), STATEMENT, "derived", SequenceIdentity()),
        "Host",
        OracleSpec(),
        sources,
    )
    call = VfcsCall("Host", "deposit(uint256,address,CollateralType)", "probe", "attacker")
    param = Param("CollateralType", "kind")
    assert synth.literal(param, call, "Collateral", False) == "1"
    assert synth.literal(param, call, "0", False) == "0"
    try:
        synth.literal(param, call, "Debt", False)
    except _UnbuildableError as exc:
        assert exc.code == "enum_member_unknown"
    else:
        raise AssertionError("an unknown enum member was accepted")
    try:
        synth.literal(param, call, "9", False)
    except _UnbuildableError as exc:
        assert exc.code == "enum_member_unknown"
    else:
        raise AssertionError("an out-of-range enum index was accepted")


def test_a_struct_field_enum_uses_the_declared_member() -> None:
    text = HOST_TEXT.replace(
        "constructor(IFactory _factory) { factory = _factory; }",
        "struct Configuration { CollateralType kind; }\n"
        "    constructor(Configuration memory config) {}",
    )
    raw = _profile(
        contract="Host",
        parameter="config",
        source_file=HOST,
        source_sha256=sha256_text(text),
        model_type="Configuration",
        solidity_type="Host.Configuration",
        struct_file=HOST,
        struct_name="Configuration",
        imports=[],
        bound_files=[{"path": HOST, "sha256": sha256_text(text)}],
        fixtures=[],
        value={
            "kind": "struct",
            "type_name": "Host.Configuration",
            "fields": [
                {
                    "name": "kind",
                    "value": {"kind": "enum", "type_name": "CollateralType", "value": "Collateral"},
                }
            ],
        },
    )
    prepared = prepare_profile(parse_profile(raw), {HOST: text})
    assert "CollateralType(1)" in prepared.expression
    raw["value"]["fields"][0]["value"] = {  # type: ignore[index]
        "kind": "enum",
        "type_name": "CollateralType",
        "value": "Debt",
    }
    try:
        prepare_profile(parse_profile(raw), {HOST: text})
    except ProfileError as exc:
        assert exc.code == "profile_enum_rejected"
    else:
        raise AssertionError("an unknown enum member was accepted in a struct")
