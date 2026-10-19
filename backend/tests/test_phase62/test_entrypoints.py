"""Internal helpers are planned through the exposed function that reaches them.

These tests check source structure. They do not treat a missing path as safe.
"""

from __future__ import annotations

import textwrap

from app.discovery.bounty.entrypoints import MAX_DEPTH, entrypoints_for
from app.discovery.bounty.properties import build_property
from app.discovery.bounty.vfcs import generate
from app.parsing.solidity_research import build_research_model
from app.parsing.solidity_research_suite import run_suite

_ERC = """
    interface IERC20 {
        function transfer(address to, uint256 amount) external returns (bool);
        function transferFrom(address from, address to, uint256 amount) external returns (bool);
        function balanceOf(address account) external view returns (uint256);
    }
"""


def _src(body: str) -> str:
    return textwrap.dedent(body).strip() + "\n"


def _model(body: str):
    text = _src(body)
    model = build_research_model({"Pool.sol": text})
    return model, text


def _fee(model):
    return next(
        item
        for item in run_suite(model).candidates
        if item.detector == "accounting.fee_on_transfer_mismatch"
    )


def _book(credit: str) -> str:
    return _src(
        f"""
        // SPDX-License-Identifier: MIT
        pragma solidity ^0.8.20;
        {_ERC}
        contract Pool {{
            struct Bag {{ uint256 n; }}
            Bag internal bag;
            IERC20 public immutable token;
            mapping(address => uint256) public credit;
            constructor(IERC20 token_) {{ token = token_; }}
            function deposit(uint256 amount, address receiver) external {{
                _book(bag, receiver, amount);
            }}
            function _book(Bag storage b, address receiver, uint256 amount) internal {{
                b.n = amount;
                require(token.transferFrom(msg.sender, address(this), amount));
                {credit}
            }}
        }}
        """
    )


def test_direct_wrapper_is_planned_instead_of_the_storage_helper() -> None:
    text = _book("credit[receiver] += amount;")
    model = build_research_model({"Pool.sol": text})
    candidate = _fee(model)
    assert candidate.function.startswith("_book(")
    built = generate(model, [candidate], sources={"Pool.sol": text})
    assert built.sequences
    sequence = built.sequences[0]
    assert sequence.derived_from.endswith(candidate.function)
    assert sequence.calls[0].function.startswith("deposit(")
    assert sequence.calls[0].entrypoint_for == candidate.function
    assert sequence.calls[0].contract == "Pool"
    assert sequence.execution_contract == ""
    assert any("_book" in line and "deposit" in line for line in sequence.call_path)
    assert any("amount<=param:amount" in line for line in sequence.call_path)
    spec = build_property(sequence, model, candidate)
    assert spec.provenance.file == candidate.file
    assert 0 < spec.provenance.line_start <= candidate.line
    assert candidate.function in spec.provenance.functions
    assert sequence.calls[0].function in spec.provenance.functions
    assert spec.oracle.probe_function.startswith("deposit(")
    assert spec.oracle.probe_role == "deposit"
    assert spec.oracle.executable


def test_external_candidate_is_not_rewritten() -> None:
    text = _src(
        f"""
        // SPDX-License-Identifier: MIT
        pragma solidity ^0.8.20;
        {_ERC}
        contract Pool {{
            IERC20 public immutable token;
            mapping(address => uint256) public credit;
            constructor(IERC20 token_) {{ token = token_; }}
            function deposit(uint256 amount) external {{
                require(token.transferFrom(msg.sender, address(this), amount));
                credit[msg.sender] += amount;
            }}
        }}
        """
    )
    model = build_research_model({"Pool.sol": text})
    candidate = _fee(model)
    sequence = generate(model, [candidate], sources={"Pool.sol": text}).sequences[0]
    assert sequence.calls[0].function == candidate.function
    assert sequence.calls[0].entrypoint_for == ""
    assert sequence.call_path == ()


def test_multilevel_path_keeps_source_locations_and_forwarded_arguments() -> None:
    text = _src(
        f"""
        // SPDX-License-Identifier: MIT
        pragma solidity ^0.8.20;
        {_ERC}
        contract Pool {{
            struct Bag {{ uint256 n; }}
            Bag internal bag;
            IERC20 public immutable token;
            mapping(address => uint256) public credit;
            constructor(IERC20 token_) {{ token = token_; }}
            function deposit(uint256 amount, address receiver) external {{
                _stage(bag, receiver, amount);
            }}
            function _stage(Bag storage b, address receiver, uint256 amount) internal {{
                _book(b, receiver, amount);
            }}
            function _book(Bag storage b, address receiver, uint256 amount) internal {{
                require(token.transferFrom(msg.sender, address(this), amount));
                credit[receiver] += amount;
            }}
        }}
        """
    )
    model = build_research_model({"Pool.sol": text})
    candidate = _fee(model)
    sequence = generate(model, [candidate], sources={"Pool.sol": text}).sequences[0]
    assert sequence.calls[0].function.startswith("deposit(")
    assert sequence.calls[0].entrypoint_for.startswith("_book(")
    assert len(sequence.call_path) == 2
    assert "_stage" in sequence.call_path[0] and "Pool.sol:" in sequence.call_path[0]
    assert "_book" in sequence.call_path[1]
    assert "amount<=param:amount" in sequence.call_path[0]
    assert "receiver<=param:receiver" in sequence.call_path[1]
    assert "b=derived:bag" in sequence.call_path[0] or "b=derived:" in sequence.call_path[0]


def test_library_call_resolves_to_the_contract_entrypoint() -> None:
    text = _src(
        f"""
        // SPDX-License-Identifier: MIT
        pragma solidity ^0.8.20;
        {_ERC}
        library BookLib {{
            struct Bag {{ uint256 n; }}
            function pull(Bag storage b, IERC20 token, address receiver, uint256 amount) internal {{
                require(token.transferFrom(msg.sender, address(this), amount));
                credit[receiver] += amount;
            }}
        }}
        contract Shelf {{
            BookLib.Bag internal bag;
            IERC20 public immutable token;
            mapping(address => uint256) public credit;
            constructor(IERC20 token_) {{ token = token_; }}
            function deposit(uint256 amount, address receiver) external {{
                BookLib.pull(bag, token, receiver, amount);
            }}
        }}
        """
    )
    model = build_research_model({"Shelf.sol": text})
    candidate = _fee(model)
    assert candidate.contract == "BookLib"
    sequence = generate(model, [candidate], sources={"Shelf.sol": text}).sequences[0]
    assert sequence.derived_from.startswith("accounting.fee_on_transfer_mismatch@BookLib.")
    assert sequence.calls[0].contract == "Shelf"
    assert sequence.calls[0].function.startswith("deposit(")
    assert sequence.calls[0].entrypoint_for == candidate.function
    assert sequence.execution_contract == "Shelf"
    assert any("BookLib.pull" in line and "Shelf.deposit" in line for line in sequence.call_path)
    assert any("amount<=param:amount" in line for line in sequence.call_path)


def test_inheritance_and_exact_overload_resolve_only_when_unambiguous() -> None:
    text = _src(
        f"""
        // SPDX-License-Identifier: MIT
        pragma solidity ^0.8.20;
        {_ERC}
        contract Base {{
            struct Bag {{ uint256 n; }}
            Bag internal bag;
            IERC20 public immutable token;
            mapping(address => uint256) public credit;
            constructor(IERC20 token_) {{ token = token_; }}
            function _book(Bag storage b, address receiver, uint256 amount) internal {{
                require(token.transferFrom(msg.sender, address(this), amount));
                credit[receiver] += amount;
            }}
            function deposit(uint256 amount, address receiver) public virtual {{
                _book(bag, receiver, amount);
            }}
        }}
        contract Child is Base {{
            constructor(IERC20 token_) Base(token_) {{}}
            function deposit(uint256 amount, address receiver) public override {{
                _book(bag, receiver, amount);
            }}
        }}
        """
    )
    model = build_research_model({"Family.sol": text})
    helper = next(item for item in model.functions_of("Base") if item.name == "_book")
    found = entrypoints_for(model, helper)
    entries = {(path.entry_contract, path.entry_signature) for path in found.paths}
    assert ("Base", "deposit(uint256,address)") in entries
    assert ("Child", "deposit(uint256,address)") in entries
    assert not found.truncated
    child = next(path for path in found.paths if path.entry_contract == "Child")
    assert child.edges[-1].callee.startswith("Base._book")

    exact = _src(
        f"""
        // SPDX-License-Identifier: MIT
        pragma solidity ^0.8.20;
        {_ERC}
        contract Pool {{
            struct Bag {{ uint256 n; }}
            Bag internal bag;
            IERC20 public immutable token;
            mapping(address => uint256) public credit;
            constructor(IERC20 token_) {{ token = token_; }}
            function deposit(uint256 amount) external {{ _book(bag, amount); }}
            function _book(Bag storage b, uint256 amount) internal {{
                require(token.transferFrom(msg.sender, address(this), amount));
                credit[msg.sender] += amount;
            }}
            function _book(Bag storage b, uint256 amount, address receiver) internal {{
                receiver = receiver;
                b.n = amount;
            }}
        }}
        """
    )
    exact_model = build_research_model({"Exact.sol": exact})
    sequence = generate(exact_model, [_fee(exact_model)], sources={"Exact.sol": exact}).sequences[0]
    assert sequence.calls[0].function == "deposit(uint256)"
    assert sequence.calls[0].entrypoint_for.startswith("_book(Bag,uint256)")


def test_ambiguous_unreachable_and_truncated_paths_are_not_promoted() -> None:
    ambiguous = _src(
        f"""
        // SPDX-License-Identifier: MIT
        pragma solidity ^0.8.20;
        {_ERC}
        contract Pool {{
            struct Bag {{ uint256 n; }}
            Bag internal bag;
            IERC20 public immutable token;
            mapping(address => uint256) public credit;
            constructor(IERC20 token_) {{ token = token_; }}
            function deposit(uint256 amount) external {{ _book(bag, amount); }}
            function _book(Bag storage b, uint256 amount) internal {{
                require(token.transferFrom(msg.sender, address(this), amount));
                credit[msg.sender] += amount;
            }}
            function _book(Bag storage b, address who) internal {{
                b.n = uint256(uint160(who));
            }}
        }}
        """
    )
    model = build_research_model({"Amb.sol": ambiguous})
    sequence = generate(model, [_fee(model)], sources={"Amb.sol": ambiguous}).sequences[0]
    assert sequence.calls[0].function.startswith("_book(")
    assert sequence.call_path == ()
    assert any("ambiguous" in note for note in sequence.path_notes)
    assert not any("safe" in note.lower() for note in sequence.path_notes)

    private = _src(
        f"""
        // SPDX-License-Identifier: MIT
        pragma solidity ^0.8.20;
        {_ERC}
        contract Pool {{
            struct Bag {{ uint256 n; }}
            Bag internal bag;
            IERC20 public immutable token;
            mapping(address => uint256) public credit;
            constructor(IERC20 token_) {{ token = token_; }}
            function _secret(Bag storage b, uint256 amount) private {{
                require(token.transferFrom(msg.sender, address(this), amount));
                credit[msg.sender] += amount;
            }}
        }}
        """
    )
    private_model = build_research_model({"Secret.sol": private})
    secret = generate(
        private_model, [_fee(private_model)], sources={"Secret.sol": private}
    ).sequences[0]
    assert secret.calls[0].function.startswith("_secret(")
    assert secret.call_path == ()
    assert any("no resolved caller" in note for note in secret.path_notes)

    hops = MAX_DEPTH
    internals = [
        f"""
            function _h{index + 1}(Bag storage b, uint256 amount) internal {{
                _h{index}(b, amount);
            }}
        """
        for index in range(hops)
    ]
    deep = _src(
        f"""
        // SPDX-License-Identifier: MIT
        pragma solidity ^0.8.20;
        {_ERC}
        contract Pool {{
            struct Bag {{ uint256 n; }}
            Bag internal bag;
            IERC20 public immutable token;
            mapping(address => uint256) public credit;
            constructor(IERC20 token_) {{ token = token_; }}
            function deposit(uint256 amount) external {{ _h{hops}(bag, amount); }}
            function _h0(Bag storage b, uint256 amount) internal {{
                require(token.transferFrom(msg.sender, address(this), amount));
                credit[msg.sender] += amount;
            }}
            {"".join(internals)}
        }}
        """
    )
    deep_model = build_research_model({"Deep.sol": deep})
    helper = next(item for item in deep_model.functions_of("Pool") if item.name == "_h0")
    found = entrypoints_for(deep_model, helper)
    assert found.paths == ()
    assert found.truncated
    assert any("depth limit" in note for note in found.incomplete)
    kept = generate(deep_model, [_fee(deep_model)], sources={"Deep.sol": deep}).sequences[0]
    assert kept.calls[0].function.startswith("_h0(")
    assert kept.call_path == ()


def test_a_cycle_does_not_hide_a_real_entrypoint() -> None:
    text = _src(
        f"""
        // SPDX-License-Identifier: MIT
        pragma solidity ^0.8.20;
        {_ERC}
        contract Pool {{
            struct Bag {{ uint256 n; }}
            Bag internal bag;
            IERC20 public immutable token;
            mapping(address => uint256) public credit;
            constructor(IERC20 token_) {{ token = token_; }}
            function deposit(uint256 amount) external {{ _left(bag, amount); }}
            function _left(Bag storage b, uint256 amount) internal {{
                _right(b, amount);
            }}
            function _right(Bag storage b, uint256 amount) internal {{
                require(token.transferFrom(msg.sender, address(this), amount));
                credit[msg.sender] += amount;
                _left(b, amount);
            }}
        }}
        """
    )
    model = build_research_model({"Cycle.sol": text})
    sequence = generate(model, [_fee(model)], sources={"Cycle.sol": text}).sequences[0]
    assert sequence.calls[0].function.startswith("deposit(")
    assert any("cycle" in note for note in sequence.path_notes)
    assert sequence.call_path
