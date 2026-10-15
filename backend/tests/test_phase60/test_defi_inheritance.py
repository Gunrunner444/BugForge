"""Token-kind inheritance must stop when two bases disagree."""

from app.parsing.model import SyntaxEvent, SyntaxGraph
from app.parsing.solidity_defi import _contract_profiles


def _graph(events: tuple[SyntaxEvent, ...]) -> SyntaxGraph:
    return SyntaxGraph(
        language="solidity",
        file_path="Child.sol",
        source="",
        lines=(),
        events=events,
    )


def test_multiple_inheritance_does_not_oscillate() -> None:
    graph = _graph(
        (
            SyntaxEvent("sol_contract", 1, "Child", extra="bases=ERC20, ERC721"),
            SyntaxEvent("sol_contract", 2, "ERC20", extra="bases="),
            SyntaxEvent("sol_contract", 3, "ERC721", extra="bases="),
        )
    )
    kinds, _confidence = _contract_profiles(graph)
    assert "Child" not in kinds
    assert kinds["ERC20"] == "erc20"
    assert kinds["ERC721"] == "erc721"


def test_a_single_token_base_is_still_inherited() -> None:
    graph = _graph(
        (
            SyntaxEvent("sol_contract", 1, "Vault", extra="bases=ERC20"),
            SyntaxEvent("sol_contract", 2, "ERC20", extra="bases="),
        )
    )
    kinds, _confidence = _contract_profiles(graph)
    assert kinds["Vault"] == "erc20"
