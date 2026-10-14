"""Constructor profiles are checked against declared types, not field names alone."""

from __future__ import annotations

from types import SimpleNamespace

from app.discovery.bounty.constructor_profile import (
    ProfileError,
    attach_profile_seed,
    parse_profile,
    prepare_profile,
    sha256_text,
)
from tests.test_phase58.test_constructor_profile import STATEMENT, _profile

HOST = "Host.sol"
OTHER = "Other.sol"
HOST_TEXT = """// SPDX-License-Identifier: MIT
pragma solidity 0.8.15;
import "./Other.sol";
contract Host {
    struct Configuration {
        address governor;
        address pauseGuardian;
        uint8 tag;
        Other.Inner extra;
        Asset[] items;
    }
    struct Asset { address token; uint64 cap; }
    constructor(Configuration memory config) { governor = config.governor; }
    address public governor;
}
"""
OTHER_TEXT = """// SPDX-License-Identifier: MIT
pragma solidity 0.8.15;
contract Other {
    struct Inner { uint8 n; bool flag; }
}
"""


def _sources(host: str = HOST_TEXT, other: str = OTHER_TEXT) -> dict[str, str]:
    return {HOST: host, OTHER: other}


def _raw(**overrides: object) -> dict[str, object]:
    sources = _sources()
    raw = _profile(
        contract="Host",
        source_file=HOST,
        source_sha256=sha256_text(sources[HOST]),
        solidity_type="Host.Configuration",
        struct_file=HOST,
        model_type="Configuration",
        imports=[OTHER],
        bound_files=[
            {"path": HOST, "sha256": sha256_text(sources[HOST])},
            {"path": OTHER, "sha256": sha256_text(sources[OTHER])},
        ],
        fixtures=[{"fixture_id": "token", "kind": "decimals_token", "decimals": 6}],
        value={
            "kind": "struct",
            "type_name": "Host.Configuration",
            "fields": [
                {"name": "governor", "value": {"kind": "role", "value": "governor"}},
                {"name": "pauseGuardian", "value": {"kind": "role", "value": "pause_guardian"}},
                {"name": "tag", "value": {"kind": "uint", "value": "7"}},
                {
                    "name": "extra",
                    "value": {
                        "kind": "struct",
                        "type_name": "Other.Inner",
                        "fields": [
                            {"name": "n", "value": {"kind": "uint", "value": "3"}},
                            {"name": "flag", "value": {"kind": "bool", "value": "true"}},
                        ],
                    },
                },
                {
                    "name": "items",
                    "value": {
                        "kind": "array",
                        "type_name": "Asset",
                        "items": [
                            {
                                "kind": "struct",
                                "type_name": "Asset",
                                "fields": [
                                    {
                                        "name": "token",
                                        "value": {"kind": "fixture", "value": "token"},
                                    },
                                    {"name": "cap", "value": {"kind": "uint", "value": "9"}},
                                ],
                            }
                        ],
                    },
                },
            ],
        },
    )
    raw.update(overrides)
    return raw


def test_nested_struct_array_and_widths_match_the_bound_sources() -> None:
    prepared = prepare_profile(parse_profile(_raw()), _sources())
    text = prepared.expression + "\n" + "\n".join(prepared.deploy_lines)
    assert "governor: address(0xC0FE)" in text
    assert "n: 3" in text
    assert "flag: true" in text
    assert "token: address(bf_token)" in text
    assert "cap: 9" in text
    assert "new Asset[](1)" in text


def _rejects(raw: dict[str, object], code: str, sources: dict[str, str] | None = None) -> None:
    try:
        prepare_profile(parse_profile(raw), sources or _sources())
    except ProfileError as exc:
        assert exc.code == code, exc
    else:
        raise AssertionError(f"{code} was not raised")


def test_wrong_width_reordered_fields_and_fixture_types_are_rejected() -> None:
    wide = _raw()
    wide["value"]["fields"][2]["value"] = {"kind": "uint", "value": "256"}  # type: ignore[index]
    _rejects(wide, "profile_integer_bounds")
    reordered = _raw()
    fields = reordered["value"]["fields"]  # type: ignore[index]
    fields[0], fields[1] = fields[1], fields[0]
    _rejects(reordered, "profile_struct_mismatch")
    fixture_on_uint = _raw()
    fixture_on_uint["value"]["fields"][2]["value"] = {"kind": "fixture", "value": "token"}  # type: ignore[index]
    _rejects(fixture_on_uint, "profile_type_mismatch")
    bool_on_uint = _raw()
    bool_on_uint["value"]["fields"][2]["value"] = {"kind": "bool", "value": "true"}  # type: ignore[index]
    _rejects(bool_on_uint, "profile_type_mismatch")


def test_a_nested_struct_from_the_wrong_file_is_rejected() -> None:
    mismatched = _sources(other=OTHER_TEXT.replace("uint8 n;", "uint256 n;"))
    profile = parse_profile(_raw())
    try:
        prepare_profile(profile, mismatched)
    except ProfileError as exc:
        assert exc.code == "profile_source_mismatch"
    else:
        raise AssertionError("a changed nested declaration reused the profile")
    ambiguous = OTHER_TEXT + "\ncontract Also { struct Inner { address who; } }\n"
    bound = _raw(
        bound_files=[
            {"path": HOST, "sha256": sha256_text(HOST_TEXT)},
            {"path": OTHER, "sha256": sha256_text(ambiguous)},
        ]
    )
    _rejects(bound, "profile_type_ambiguous", _sources(other=ambiguous))


def test_incomplete_dependency_hashes_and_enums_fail_closed() -> None:
    missing = _raw()
    missing["bound_files"] = [missing["bound_files"][0]]  # type: ignore[index]
    _rejects(missing, "profile_dependency_unbound")
    enum_host = HOST_TEXT.replace("uint8 tag;", "Mode tag;").replace(
        "contract Host {",
        "contract Host {\n    enum Mode { Off, On }",
    )
    enum_raw = _raw(
        source_sha256=sha256_text(enum_host),
        bound_files=[
            {"path": HOST, "sha256": sha256_text(enum_host)},
            {"path": OTHER, "sha256": sha256_text(OTHER_TEXT)},
        ],
    )
    enum_raw["value"]["fields"][2]["value"] = {"kind": "uint", "value": "0"}  # type: ignore[index]
    _rejects(enum_raw, "profile_type_unsupported", {HOST: enum_host, OTHER: OTHER_TEXT})


def test_source_commit_must_match_the_campaign_revision() -> None:
    raw = _raw(source_commit="ab" * 20)
    analysis = SimpleNamespace(sequence_skipped={}, sources=_sources())
    campaign = SimpleNamespace(
        spec=SimpleNamespace(constructor_profile=raw),
        manifest=SimpleNamespace(source_commit="cd" * 20),
        selection=SimpleNamespace(mode="explicit", selected=[HOST, OTHER]),
        cache={},
    )
    record = attach_profile_seed(campaign, analysis)
    assert record is not None
    assert record["reason_code"] == "profile_source_revision_mismatch"
    assert "constructor_profile:" in next(iter(analysis.sequence_skipped))


def test_profile_statement_stays_plain_text() -> None:
    assert "{" not in STATEMENT
    try:
        parse_profile(_raw(source_commit="not-a-commit"))
    except ProfileError as exc:
        assert exc.code == "profile_malformed"
    else:
        raise AssertionError("a non-revision source_commit was accepted")
