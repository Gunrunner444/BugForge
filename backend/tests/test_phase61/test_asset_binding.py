"""Constructor-bound, initialization-bound, and unbound asset fixtures.

The address is the harness token only when a profile says so and the getter
returns it. A missing binding stays unbuilt. A placed runtime is the code the
host delegatecalls, at an address literal that is already in the source.
"""

from __future__ import annotations

import pytest

from app.discovery.bounty.constructor_profile import (
    ProfileError,
    parse_profile,
    prepare_profile,
    sha256_text,
)
from app.discovery.bounty.properties import build_property
from app.discovery.bounty.stateful import (
    StatefulExecutor,
    build_harness,
    delegate_execution_host,
    derived_remappings,
)
from app.discovery.bounty.vfcs import (
    SequenceIdentity,
    Vfcs,
    VfcsCall,
    generate,
    stamp_source_identity,
)
from app.parsing.solidity_research import build_research_model
from app.parsing.solidity_research_suite import run_suite
from tests.test_phase52.phase52_support import requires_forge

_ERC = """
interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}
"""

_BOX = (
    _ERC
    + """
contract Box {
    address public asset;
    mapping(address => uint256) public credit;
    constructor(address asset_) { asset = asset_; }
    function deposit(uint256 amount) external {
        require(IERC20(asset).transferFrom(msg.sender, address(this), amount));
        credit[msg.sender] += amount;
    }
    function withdraw(uint256 amount) external {
        credit[msg.sender] -= amount;
        require(IERC20(asset).transfer(msg.sender, amount));
    }
}
"""
)

_BINDER = (
    _ERC
    + """
contract Binder {
    IERC20 public token;
    address public owner;
    mapping(address => uint256) public credit;
    constructor() { owner = msg.sender; }
    function setToken(IERC20 next) external {
        require(msg.sender == owner);
        require(address(token) == address(0));
        token = next;
    }
    function deposit(uint256 amount) external {
        require(token.transferFrom(msg.sender, address(this), amount));
        credit[msg.sender] += amount;
    }
    function withdraw(uint256 amount) external {
        require(credit[msg.sender] >= amount);
        require(token.transfer(msg.sender, amount));
    }
}
"""
)

_LIE = (
    _ERC
    + """
contract Binder {
    IERC20 public token;
    address public owner;
    mapping(address => uint256) public credit;
    constructor() { owner = msg.sender; }
    function setToken(IERC20 next) external {
        require(msg.sender == owner);
        token = next;
    }
    function asset() external pure returns (address) { return address(0); }
    function deposit(uint256 amount) external {
        require(token.transferFrom(msg.sender, address(this), amount));
        credit[msg.sender] += amount;
    }
    function withdraw(uint256 amount) external {
        credit[msg.sender] -= amount;
        require(token.transfer(msg.sender, amount));
    }
}
"""
)

_LOGIC = """
contract Logic {
    function ping() external pure returns (uint256) { return 7; }
}
"""

_HOST = """
contract Host {
    address public constant logic = 0x00000000000000000000000000000000000000D3;
    address public constant unused = 0x00000000000000000000000000000000000000D4;
    address public asset;
    constructor(address asset_) { asset = asset_; }
    fallback() external payable {
        address target = logic;
        require(target.code.length > 0, "no logic");
        assembly {
            calldatacopy(0, 0, calldatasize())
            let ok := delegatecall(gas(), target, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch ok
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}
"""


def _bound(sources: dict[str, str]) -> list[dict[str, str]]:
    return [{"path": path, "sha256": sha256_text(text)} for path, text in sorted(sources.items())]


def _address_profile(sources: dict[str, str], contract: str, path: str, **extra: object) -> object:
    raw: dict[str, object] = {
        "profile_id": "asset-binding",
        "contract": contract,
        "source_file": path,
        "source_sha256": sha256_text(sources[path]),
        "parameter": "asset_",
        "model_type": "address",
        "solidity_type": "address",
        "struct_file": path,
        "struct_name": "address",
        "value": {"kind": "fixture", "value": "asset"},
        "fixtures": [{"fixture_id": "asset", "kind": "harness_token", "decimals": 18}],
        "imports": [],
        "bound_files": _bound(sources),
        "assumptions": ["the harness token is the address passed to the constructor"],
        "property_function": "asset()",
        "property_statement": "the asset getter returns the harness token after initialization",
        "property_getter": "asset()",
        "property_template": "initialization-asset",
    }
    raw.update(extra)
    return parse_profile(raw)


def _round_trip(source: str, contract: str, path: str = "vault.sol"):
    sources = {path: source}
    model = build_research_model(sources)
    hit = next(
        item
        for item in run_suite(model).candidates
        if item.detector == "conservation.round_trip_value" and item.contract == contract
    )
    sequence = generate(model, [hit], sources=sources).sequences[0]
    spec = build_property(sequence, model, hit)
    return sources, model, sequence, spec


def test_an_unbound_state_token_is_not_treated_as_held() -> None:
    sources, model, sequence, spec = _round_trip(_BINDER, "Binder")
    harness = build_harness(sequence, model, oracle=spec.oracle, sources=sources)
    assert not harness.buildable
    assert harness.reason_code == "unbound_token"


def test_a_constructor_token_parameter_still_binds_without_a_profile() -> None:
    source = _BOX.replace("address public asset", "IERC20 public asset").replace(
        "constructor(address asset_)", "constructor(IERC20 asset_)"
    )
    source = source.replace("IERC20(asset)", "asset")
    sources, model, sequence, spec = _round_trip(source, "Box")
    harness = build_harness(sequence, model, oracle=spec.oracle, sources=sources)
    assert harness.buildable, harness.reason
    assert "IERC20(address(bfToken))" in harness.source
    assert "K_SETUP" not in harness.source and "bfBound" not in harness.source


def test_place_at_must_be_a_source_literal() -> None:
    sources = {"host.sol": _HOST, "logic.sol": _LOGIC}
    profile = _address_profile(
        sources,
        "Host",
        "host.sol",
        fixtures=[
            {"fixture_id": "asset", "kind": "harness_token", "decimals": 18},
            {
                "fixture_id": "logic",
                "kind": "source_contract",
                "contract": "Logic",
                "place_at": "0x00000000000000000000000000000000000000EE",
            },
        ],
        imports=["logic.sol"],
    )
    with pytest.raises(ProfileError) as caught:
        prepare_profile(profile, sources)
    assert caught.value.code == "profile_fixture_unresolved"


def test_a_prefix_is_remapped_only_when_one_file_owns_the_suffix() -> None:
    sources = {
        "host.sol": 'import {Math} from "@lib/contracts/Math.sol";\n',
        "vendor/contracts/Math.sol": "contract Math {}",
        "other.sol": 'import {Math} from "@lib/contracts/Math.sol";\n',
    }
    assert derived_remappings(sources) == ("@lib/=src/vendor/",)
    ambiguous = {
        **sources,
        "copy/contracts/Math.sol": "contract Math {}",
    }
    assert derived_remappings(ambiguous) == ()


@requires_forge
def test_an_address_constructor_binds_only_after_the_getter_matches() -> None:
    sources, model, sequence, spec = _round_trip(_BOX, "Box")
    profile = _address_profile(sources, "Box", "vault.sol")
    held = StatefulExecutor(profile=profile).execute(sequence, model, sources, spec=spec)
    assert held.outcome.value == "property_held", held.reason
    assert held.reason_code != "asset_binding_unconfirmed"


@requires_forge
def test_initialization_binds_the_token_and_a_wrong_getter_stays_inconclusive() -> None:
    sources, model, sequence, spec = _round_trip(_BINDER, "Binder")
    profile = _address_profile(
        sources,
        "Binder",
        "vault.sol",
        parameter="next",
        initialization_function="setToken(address)",
        property_function="setToken(address)",
        property_getter="token()",
        assumptions=["the deployer calls setToken and token() must return the harness token"],
    )
    violated = StatefulExecutor(profile=profile).execute(sequence, model, sources, spec=spec)
    assert violated.outcome.value == "property_violated", violated.reason
    lie_sources, lie_model, lie_sequence, lie_spec = _round_trip(_LIE, "Binder", "lie.sol")
    lie = _address_profile(
        lie_sources,
        "Binder",
        "lie.sol",
        parameter="next",
        initialization_function="setToken(address)",
        property_function="setToken(address)",
        property_getter="asset()",
        assumptions=["asset() is the declared getter and must be the harness token"],
    )
    missed = StatefulExecutor(profile=lie).execute(
        lie_sequence, lie_model, lie_sources, spec=lie_spec
    )
    assert missed.outcome.value == "inconclusive", missed.reason
    assert missed.reason_code == "asset_binding_unconfirmed"
    assert missed.verdict == "not_evaluated"


@requires_forge
def test_delegate_placement_uses_the_source_literal_the_fallback_calls() -> None:
    sources = {"host.sol": _HOST, "logic.sol": _LOGIC}
    model = build_research_model(sources)
    sequence = Vfcs(
        sequence_id="ping",
        template="read",
        origin="test",
        calls=(VfcsCall("Logic", "ping()", "read", "attacker", ()),),
        property_under_test="the placed runtime answers through the host fallback",
        derived_from="test.ping@Logic.ping()",
        identity=SequenceIdentity(),
    )
    sequence = stamp_source_identity(sequence, sources)

    def placed(address: str) -> object:
        return _address_profile(
            sources,
            "Host",
            "host.sol",
            fixtures=[
                {"fixture_id": "asset", "kind": "harness_token", "decimals": 18},
                {
                    "fixture_id": "logic",
                    "kind": "source_contract",
                    "contract": "Logic",
                    "place_at": address,
                },
            ],
            imports=["logic.sol"],
        )

    profile = placed("0x00000000000000000000000000000000000000D3")
    assert delegate_execution_host(profile, model, "Logic", sources) == "Host"
    ran = StatefulExecutor(profile=profile).execute(sequence, model, sources)
    assert ran.outcome.value == "sequence_executed_no_oracle", ran.reason
    assert ran.harness is not None and "vm.etch(0x00000000000000000000000000000000000000D3" in (
        ran.harness.source
    )
    missed = StatefulExecutor(profile=placed("0x00000000000000000000000000000000000000D4")).execute(
        sequence, model, sources
    )
    assert missed.outcome.value == "sequence_reverted", missed.reason
