"""Fallback routing, constructor bytes, and EIP-712 signing stay generic.

The contracts here are local fixtures. They are not a protocol and not a finding.
"""

from __future__ import annotations

from app.discovery.bounty.constructor_profile import (
    ProfileError,
    parse_profile,
    prepare_profile,
    sha256_text,
)
from app.discovery.bounty.engine_adapters import _judge
from app.discovery.bounty.properties import (
    OracleKind,
    OracleObservation,
    OracleSpec,
    PropertyVerdict,
    evaluate,
)
from app.discovery.bounty.stateful import (
    SIGNER,
    Outcome,
    StatefulExecutor,
    build_harness,
)
from app.discovery.bounty.vfcs import (
    ATTACKER,
    VICTIM,
    SequenceIdentity,
    Vfcs,
    VfcsCall,
    stamp_source_identity,
)
from app.parsing.keccak import function_selector, keccak256
from app.parsing.solidity_research import build_research_model
from tests.test_phase52.phase52_support import requires_forge

FILE = "Tiny.sol"
HOST = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ExtConfig {
    struct Config {
        bytes32 name32;
        bytes32 symbol32;
    }
}

contract Factory {
    function id() external pure returns (uint256) {
        return 1;
    }
}

contract ListedExt {
    bytes32 public name32;
    address public factory;

    constructor(ExtConfig.Config memory config, address factory_) {
        name32 = config.name32;
        factory = factory_;
    }
}

contract TinyHost {
    struct Settings {
        address extension;
    }

    address public extensionDelegate;
    uint256 public poked;

    constructor(Settings memory settings) {
        extensionDelegate = settings.extension;
    }

    fallback() external payable {
        address delegate = extensionDelegate;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), delegate, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}

contract TinyExt {
    function poke(uint256 value) external {
        assembly {
            sstore(1, value)
        }
    }

    function scale() external pure returns (uint256) {
        return 7;
    }
}
"""

SIG = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract TinySig {
    string public name;
    string public constant version = "0";
    mapping(address => mapping(address => bool)) public isAllowed;
    mapping(address => uint256) public userNonce;
    error BadSignatory();
    error BadNonce();
    error SignatureExpired();
    error InvalidValueS();
    error InvalidValueV();
    uint256 internal constant MAX_S =
        0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

    constructor() {
        name = "Tiny";
    }

    function allowBySig(
        address owner,
        address manager,
        bool isAllowed_,
        uint256 nonce,
        uint256 expiry,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        if (uint256(s) > MAX_S) revert InvalidValueS();
        if (v != 27 && v != 28) revert InvalidValueV();
        bytes32 domainSeparator = keccak256(
            abi.encode(
                keccak256(
                    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                ),
                keccak256(bytes(name)),
                keccak256(bytes(version)),
                block.chainid,
                address(this)
            )
        );
        bytes32 structHash = keccak256(
            abi.encode(
                keccak256(
                    "Authorization(address owner,address manager,bool isAllowed,uint256 nonce,uint256 expiry)"
                ),
                owner,
                manager,
                isAllowed_,
                nonce,
                expiry
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\\x19\\x01", domainSeparator, structHash));
        address signatory = ecrecover(digest, v, r, s);
        if (signatory == address(0) || owner != signatory) revert BadSignatory();
        if (nonce != userNonce[signatory]++) revert BadNonce();
        if (block.timestamp >= expiry) revert SignatureExpired();
        isAllowed[signatory][manager] = isAllowed_;
    }
}
"""

NAME32 = "0x" + b"listed".ljust(32, b"\x00").hex()
SYMBOL32 = "0x" + b"lst".ljust(32, b"\x00").hex()
TYPEHASH = (
    "0x"
    + keccak256(
        b"Authorization(address owner,address manager,bool isAllowed,uint256 nonce,uint256 expiry)"
    ).hex()
)
ALLOW = "allowBySig(address,address,bool,uint256,uint256,uint8,bytes32,bytes32)"
BAD_SIGNATORY = function_selector("BadSignatory()")
BAD_NONCE = function_selector("BadNonce()")


def _host_profile(**overrides: object) -> dict[str, object]:
    digest = sha256_text(HOST)
    raw: dict[str, object] = {
        "profile_id": "tiny-host-delegate",
        "contract": "TinyHost",
        "source_file": FILE,
        "source_sha256": digest,
        "parameter": "settings",
        "model_type": "Settings",
        "solidity_type": "TinyHost.Settings",
        "struct_file": FILE,
        "struct_name": "Settings",
        "value": {
            "kind": "struct",
            "type_name": "TinyHost.Settings",
            "fields": [
                {"name": "extension", "value": {"kind": "fixture", "value": "extension"}},
            ],
        },
        "fixtures": [
            {"fixture_id": "extension", "kind": "source_contract", "contract": "TinyExt"},
        ],
        "imports": [],
        "bound_files": [{"path": FILE, "sha256": digest}],
        "assumptions": ["the extension is the pinned local delegate, not a substitute"],
        "property_function": "poke(uint256)",
        "property_statement": "a poke through the host writes the host storage",
        "property_getter": "poked()",
    }
    raw.update(overrides)
    return raw


def _listed_profile() -> dict[str, object]:
    digest = sha256_text(HOST)
    raw = _host_profile()
    raw["fixtures"] = [
        {"fixture_id": "factory", "kind": "source_contract", "contract": "Factory"},
        {
            "fixture_id": "extension",
            "kind": "source_contract",
            "contract": "ListedExt",
            "depends_on": "factory",
            "arguments": [
                {
                    "kind": "struct",
                    "type_name": "ExtConfig.Config",
                    "fields": [
                        {"name": "name32", "value": {"kind": "bytes32", "value": NAME32}},
                        {"name": "symbol32", "value": {"kind": "bytes32", "value": SYMBOL32}},
                    ],
                },
                {"kind": "fixture", "value": "factory"},
            ],
        },
    ]
    raw["bound_files"] = [{"path": FILE, "sha256": digest}]
    return raw


def _sequence(contract: str, signature: str, role: str, actor: str, arguments: tuple) -> Vfcs:
    call = VfcsCall(contract, signature, role, actor, arguments=arguments)
    return Vfcs(
        sequence_id=f"vf_{role}",
        template="unauthorized-call",
        origin="test",
        calls=(call,),
        property_under_test="delegate routing",
        derived_from=f"test@TinyHost.{signature}",
        identity=SequenceIdentity(campaign_id="delegate"),
    )


def _sig_spec(component: str, fields: str, chain: str = "current") -> str:
    return f"eip712:{component}:typehash={TYPEHASH}:signer=key:chain={chain}:fields={fields}"


def _allow_args(fields: str, **replaced: str) -> tuple[tuple[str, str], ...]:
    values = {
        "owner": "signer",
        "manager": "attacker",
        "isAllowed_": "true",
        "nonce": "0",
        "expiry": "timestamp_plus",
        "v": _sig_spec("v", fields),
        "r": _sig_spec("r", fields),
        "s": _sig_spec("s", fields),
    }
    values.update(replaced)
    return tuple(values.items())


def test_a_source_contract_accepts_bytes32_constructor_arguments() -> None:
    prepared = prepare_profile(parse_profile(_listed_profile()), {FILE: HOST})
    rendered = "\n".join(prepared.deploy_lines)
    assert f"bytes32({NAME32})" in rendered
    assert f"bytes32({SYMBOL32})" in rendered
    assert "new ListedExt(" in rendered
    assert "address(bf_factory)" in rendered
    assert rendered.index("new Factory(") < rendered.index("new ListedExt(")


def test_a_source_contract_with_a_constructor_still_requires_arguments() -> None:
    raw = _listed_profile()
    fixtures = raw["fixtures"]
    assert isinstance(fixtures, list)
    fixtures[1] = {
        "fixture_id": "extension",
        "kind": "source_contract",
        "contract": "ListedExt",
        "depends_on": "factory",
    }
    with __import__("pytest").raises(ProfileError, match="profile_fixture_incompatible"):
        prepare_profile(parse_profile(raw), {FILE: HOST})


def test_a_public_state_getter_is_called_on_the_target() -> None:
    sources = {FILE: HOST}
    sequence = stamp_source_identity(
        _sequence("TinyHost", "extensionDelegate()", "read", ATTACKER, ()),
        sources,
    )
    harness = build_harness(
        sequence,
        build_research_model(sources),
        sources=sources,
        profile=parse_profile(_host_profile()),
        oracle=OracleSpec(
            kind=OracleKind.CONFIGURED_VALUE,
            probe_role="read",
            probe_function="extensionDelegate()",
            word_index=0,
            observed_fixture="extension",
        ),
    )
    assert harness.buildable, harness.reason
    assert 'abi.encodeWithSignature("extensionDelegate()")' in harness.source
    assert "address(t).call(" in harness.source
    assert "new TinyExt" in harness.source


def test_a_private_variable_is_not_synthesized_as_a_call() -> None:
    text = HOST.replace("address public extensionDelegate;", "address extensionDelegate;")
    sources = {FILE: text}
    raw = _host_profile()
    raw["source_sha256"] = sha256_text(text)
    raw["bound_files"] = [{"path": FILE, "sha256": sha256_text(text)}]
    sequence = stamp_source_identity(
        _sequence("TinyHost", "extensionDelegate()", "read", ATTACKER, ()),
        sources,
    )
    harness = build_harness(
        sequence,
        build_research_model(sources),
        sources=sources,
        profile=parse_profile(raw),
    )
    assert not harness.buildable
    assert harness.reason_code == "call_outside_target"


def test_a_fallback_call_is_sent_to_the_target_not_the_delegate() -> None:
    sources = {FILE: HOST}
    sequence = stamp_source_identity(
        _sequence("TinyExt", "poke(uint256)", "poke", ATTACKER, (("value", "5"),)),
        sources,
    )
    harness = build_harness(
        sequence,
        build_research_model(sources),
        sources=sources,
        profile=parse_profile(_host_profile()),
        oracle=OracleSpec(
            kind=OracleKind.STATE_EQUALS,
            probe_role="poke",
            probe_function="poke(uint256)",
            getter="poked()",
            expected_before="0",
            expected_after="5",
        ),
    )
    assert harness.buildable, harness.reason
    assert 'abi.encodeWithSignature("poke(uint256)", 5)' in harness.source
    assert "address(t).call(" in harness.source
    assert "TinyExt(" not in harness.source.split("new TinyExt", 1)[-1]


def test_a_foreign_call_without_a_delegate_fallback_is_refused() -> None:
    bare = """
contract OnlyExt {
    function poke(uint256 value) external {}
}
contract NoDelegate {
    uint256 public poked;
    fallback() external payable {}
}
"""
    sources = {FILE: bare}
    sequence = Vfcs(
        sequence_id="vf_nodelegate",
        template="unauthorized-call",
        origin="test",
        calls=(VfcsCall("OnlyExt", "poke(uint256)", "poke", ATTACKER, (("value", "5"),)),),
        property_under_test="no delegate",
        derived_from="test@NoDelegate.poke(uint256)",
        identity=SequenceIdentity(campaign_id="delegate"),
    )
    sequence = stamp_source_identity(sequence, sources)
    harness = build_harness(sequence, build_research_model(sources), sources=sources)
    assert not harness.buildable
    assert harness.reason_code == "call_outside_target"


def test_two_concrete_bodies_are_not_guessed() -> None:
    text = HOST + "\ncontract OtherExt { function poke(uint256 value) external {} }\n"
    sources = {FILE: text}
    raw = _host_profile()
    raw["source_sha256"] = sha256_text(text)
    raw["bound_files"] = [{"path": FILE, "sha256": sha256_text(text)}]
    sequence = stamp_source_identity(
        Vfcs(
            sequence_id="vf_ambiguous",
            template="unauthorized-call",
            origin="test",
            calls=(VfcsCall("OtherExt", "poke(uint256)", "poke", ATTACKER, (("value", "5"),)),),
            property_under_test="ambiguous delegate",
            derived_from="test@TinyHost.poke(uint256)",
            identity=SequenceIdentity(campaign_id="delegate"),
        ),
        sources,
    )
    harness = build_harness(
        sequence,
        build_research_model(sources),
        sources=sources,
        profile=parse_profile(raw),
    )
    assert harness.reason_code == "delegate_ambiguous"


def test_an_eip712_signature_is_bound_to_the_target_address() -> None:
    fields = "address:signer,address:attacker,bool:true,uint256:0,uint256:timestamp_plus"
    sources = {"Sig.sol": SIG}
    call = VfcsCall("TinySig", ALLOW, "allow", ATTACKER, arguments=_allow_args(fields))
    sequence = stamp_source_identity(
        Vfcs(
            sequence_id="vf_sig",
            template="unauthorized-call",
            origin="test",
            calls=(call,),
            property_under_test="signed authorization",
            derived_from=f"test@TinySig.{ALLOW}",
            identity=SequenceIdentity(campaign_id="delegate"),
        ),
        sources,
    )
    harness = build_harness(sequence, build_research_model(sources), sources=sources)
    assert harness.buildable, harness.reason
    assert f"_bfSign(address(t), {TYPEHASH}" in harness.source
    assert "vm.sign" in harness.source
    assert "Authorization(" not in harness.source
    assert harness.source.count("= _bfSign(") == 1


def _obs(**overrides: object) -> OracleObservation:
    raw: dict[str, object] = {
        "call_ok": (1,),
        "before": "0x" + "00" * 32,
        "after": "0x" + "01".rjust(64, "0"),
    }
    raw.update(overrides)
    return OracleObservation(**raw)  # type: ignore[arg-type]


def _one(role: str, function: str, actor: str = ATTACKER) -> Vfcs:
    return Vfcs(
        sequence_id="vf_judge",
        template="unauthorized-call",
        origin="test",
        calls=(VfcsCall("Tiny", function, role, actor),),
        property_under_test="judge",
        derived_from=f"test@Tiny.{function}",
        identity=SequenceIdentity(),
    )


def test_the_judge_distinguishes_authorization_outcomes() -> None:
    granted = _one("allow", "allow(address,bool)", VICTIM)
    state = OracleSpec(
        kind=OracleKind.STATE_EQUALS,
        probe_role="allow",
        probe_function="allow(address,bool)",
        getter="isAllowed(address,address)",
        expected_before="0",
        expected_after="1",
    )
    held = evaluate(granted, state, _obs())
    assert held.verdict is PropertyVerdict.PROPERTY_HELD

    unauthorized = OracleSpec(
        kind=OracleKind.CALL_MUST_FAIL,
        probe_role="withdraw",
        probe_function="withdraw(uint256)",
        getter="balanceOf(address)",
        revert_selector=function_selector("Unauthorized()"),
    )
    denied = evaluate(
        _one("withdraw", "withdraw(uint256)"),
        unauthorized,
        _obs(
            call_ok=(0,),
            before="0x" + "01".rjust(64, "0"),
            after="0x" + "01".rjust(64, "0"),
            revert_selector=function_selector("Unauthorized()"),
            revert_data_ok=True,
        ),
    )
    assert denied.verdict is PropertyVerdict.PROPERTY_HELD

    stolen = evaluate(
        _one("withdraw", "withdraw(uint256)"),
        unauthorized,
        _obs(before="0x" + "01".rjust(64, "0"), after="0x" + "00" * 32),
    )
    assert stolen.verdict is PropertyVerdict.PROPERTY_VIOLATED

    revoked = Vfcs(
        sequence_id="vf_revoke",
        template="unauthorized-call",
        origin="test",
        calls=(
            VfcsCall("Tiny", "allow(address,bool)", "grant", VICTIM),
            VfcsCall("Tiny", "allow(address,bool)", "revoke", VICTIM),
            VfcsCall("Tiny", "withdraw(uint256)", "withdraw", ATTACKER),
        ),
        property_under_test="revocation",
        derived_from="test@Tiny.withdraw(uint256)",
        identity=SequenceIdentity(),
    )
    after_revoke = evaluate(
        revoked,
        OracleSpec(
            kind=OracleKind.CALL_MUST_FAIL,
            probe_role="withdraw",
            probe_function="withdraw(uint256)",
            precondition_roles=("grant", "revoke"),
            getter="balanceOf(address)",
            revert_selector=function_selector("Unauthorized()"),
        ),
        OracleObservation(
            call_ok=(1, 1, 0),
            before="0x" + "01".rjust(64, "0"),
            after="0x" + "01".rjust(64, "0"),
            revert_selector=function_selector("Unauthorized()"),
            revert_data_ok=True,
        ),
    )
    assert after_revoke.verdict is PropertyVerdict.PROPERTY_HELD

    rejected = evaluate(
        _one("allow", ALLOW),
        OracleSpec(
            kind=OracleKind.CALL_MUST_FAIL,
            probe_role="allow",
            probe_function=ALLOW,
            getter="isAllowed(address,address)",
            revert_selector=BAD_SIGNATORY,
        ),
        _obs(
            call_ok=(0,),
            before="0x" + "00" * 32,
            after="0x" + "00" * 32,
            revert_selector=BAD_SIGNATORY,
            revert_data_ok=True,
        ),
    )
    assert rejected.verdict is PropertyVerdict.PROPERTY_HELD

    replayed = Vfcs(
        sequence_id="vf_replay",
        template="unauthorized-call",
        origin="test",
        calls=(
            VfcsCall("Tiny", ALLOW, "first", ATTACKER),
            VfcsCall("Tiny", ALLOW, "replay", ATTACKER),
        ),
        property_under_test="replay",
        derived_from=f"test@Tiny.{ALLOW}",
        identity=SequenceIdentity(),
    )
    replay = evaluate(
        replayed,
        OracleSpec(
            kind=OracleKind.CALL_MUST_FAIL,
            probe_role="replay",
            probe_function=ALLOW,
            precondition_roles=("first",),
            getter="isAllowed(address,address)",
            revert_selector=BAD_NONCE,
        ),
        OracleObservation(
            call_ok=(1, 0),
            before="0x" + "01".rjust(64, "0"),
            after="0x" + "01".rjust(64, "0"),
            revert_selector=BAD_NONCE,
            revert_data_ok=True,
        ),
    )
    assert replay.verdict is PropertyVerdict.PROPERTY_HELD

    missed = evaluate(granted, state, _obs(call_ok=(-1,)))
    assert missed.verdict is PropertyVerdict.NOT_EVALUATED
    assert "not" in missed.reason


def test_the_engine_judge_uses_the_same_state_transition() -> None:
    sequence = _one("allow", "allow(address,bool)", VICTIM)
    oracle = OracleSpec(
        kind=OracleKind.STATE_EQUALS,
        probe_role="allow",
        probe_function="allow(address,bool)",
        getter="isAllowed(address,address)",
        expected_before="0",
        expected_after="1",
    )
    judged, violated = _judge(sequence, oracle) or ("", "")
    assert "!= 0" in judged
    assert "!= 1" in violated
    assert "_bfOk(0)" in judged


def _run(source: str, file: str, sequence: Vfcs, oracle: OracleSpec, profile=None):  # type: ignore[no-untyped-def]
    sources = {file: source}
    sequence = stamp_source_identity(sequence, sources)
    model = build_research_model(sources)
    executor = StatefulExecutor(profile=profile)
    return executor.execute(sequence, model, sources, oracle=oracle)


@requires_forge
def test_the_configured_delegate_address_is_the_deployed_extension() -> None:
    sequence = _sequence("TinyHost", "extensionDelegate()", "read", ATTACKER, ())
    observed = _run(
        HOST,
        FILE,
        sequence,
        OracleSpec(
            kind=OracleKind.CONFIGURED_VALUE,
            probe_role="read",
            probe_function="extensionDelegate()",
            word_index=0,
            observed_fixture="extension",
        ),
        parse_profile(_host_profile()),
    )
    assert observed.outcome is Outcome.PROPERTY_HELD, observed.reason


@requires_forge
def test_a_delegatecall_writes_the_hosts_storage() -> None:
    sources_profile = parse_profile(_host_profile())
    sequence = _sequence("TinyExt", "poke(uint256)", "poke", ATTACKER, (("value", "5"),))
    observed = _run(
        HOST,
        FILE,
        sequence,
        OracleSpec(
            kind=OracleKind.STATE_EQUALS,
            probe_role="poke",
            probe_function="poke(uint256)",
            getter="poked()",
            expected_before="0",
            expected_after="5",
        ),
        sources_profile,
    )
    assert observed.outcome is Outcome.PROPERTY_HELD, observed.reason


@requires_forge
def test_a_valid_signature_sets_permission_and_a_replay_does_not() -> None:
    fields = "address:signer,address:attacker,bool:true,uint256:0,uint256:timestamp_plus"
    first = VfcsCall("TinySig", ALLOW, "first", ATTACKER, arguments=_allow_args(fields))
    replay = VfcsCall("TinySig", ALLOW, "replay", ATTACKER, arguments=_allow_args(fields))
    sequence = Vfcs(
        sequence_id="vf_sig_replay",
        template="unauthorized-call",
        origin="test",
        calls=(first, replay),
        property_under_test="replayed signature",
        derived_from=f"test@TinySig.{ALLOW}",
        identity=SequenceIdentity(campaign_id="delegate"),
    )
    observed = _run(
        SIG,
        "Sig.sol",
        sequence,
        OracleSpec(
            kind=OracleKind.CALL_MUST_FAIL,
            probe_role="replay",
            probe_function=ALLOW,
            precondition_roles=("first",),
            getter="isAllowed(address,address)",
            getter_actor=f"{SIGNER},attacker",
            revert_selector=BAD_NONCE,
        ),
    )
    assert observed.outcome is Outcome.PROPERTY_HELD, observed.reason


@requires_forge
def test_a_signature_for_a_different_owner_is_rejected() -> None:
    fields = "address:signer,address:attacker,bool:true,uint256:0,uint256:timestamp_plus"
    call = VfcsCall(
        "TinySig",
        ALLOW,
        "allow",
        ATTACKER,
        arguments=_allow_args(fields, owner="victim"),
    )
    sequence = Vfcs(
        sequence_id="vf_bad_owner",
        template="unauthorized-call",
        origin="test",
        calls=(call,),
        property_under_test="rejected signature",
        derived_from=f"test@TinySig.{ALLOW}",
        identity=SequenceIdentity(campaign_id="delegate"),
    )
    observed = _run(
        SIG,
        "Sig.sol",
        sequence,
        OracleSpec(
            kind=OracleKind.CALL_MUST_FAIL,
            probe_role="allow",
            probe_function=ALLOW,
            getter="isAllowed(address,address)",
            getter_actor=f"{SIGNER},attacker",
            revert_selector=BAD_SIGNATORY,
        ),
    )
    assert observed.outcome is Outcome.PROPERTY_HELD, observed.reason
