"""Named targets resolve their own import graph and do not census the repository."""

from __future__ import annotations

from pathlib import Path

from app.discovery.bounty.import_closure import resolve_import_closure
from app.discovery.bounty.source_selection import select_named


def _write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_relative_transitive_and_duplicate_imports_stay_in_one_closure(tmp_path: Path) -> None:
    _write(tmp_path, "src/Target.sol", 'import "./mid/Child.sol";\ncontract Target {}')
    _write(tmp_path, "src/mid/Child.sol", 'import "../lib/Shared.sol";\ncontract Child {}')
    _write(
        tmp_path,
        "src/lib/Shared.sol",
        'import "./Leaf.sol";\nimport "./Leaf.sol";\ncontract Shared {}',
    )
    _write(tmp_path, "src/lib/Leaf.sol", "contract Leaf {}")
    _write(tmp_path, "src/Unrelated.sol", "contract Unrelated {}")
    _write(tmp_path, "gitmodules/other/Noise.sol", "contract Noise {}")
    closure = resolve_import_closure(tmp_path, ("src/Target.sol",))
    assert closure.closure_complete
    assert closure.dependencies == (
        "src/mid/Child.sol",
        "src/lib/Shared.sol",
        "src/lib/Leaf.sol",
    )
    assert "src/Unrelated.sol" not in closure.dependencies
    assert "gitmodules/other/Noise.sol" not in closure.dependencies
    leaf_edges = [edge for edge in closure.edges if edge.spec == "./Leaf.sol"]
    assert len(leaf_edges) == 1
    again = resolve_import_closure(tmp_path, ("src/Target.sol",))
    assert again.as_dict() == closure.as_dict()


def test_remapping_alias_resolves_and_a_missing_import_is_an_edge(tmp_path: Path) -> None:
    _write(tmp_path, "remappings.txt", "alias/=vendor/pkg/\n")
    _write(tmp_path, "src/Target.sol", 'import "alias/Token.sol";\nimport "alias/Missing.sol";\n')
    _write(tmp_path, "vendor/pkg/Token.sol", "contract Token {}")
    closure = resolve_import_closure(tmp_path, ("src/Target.sol",))
    assert "vendor/pkg/Token.sol" in closure.dependencies
    missing = [edge for edge in closure.unresolved if edge.spec == "alias/Missing.sol"]
    assert missing and missing[0].reason == "not_found"
    assert closure.closure_complete is False


def test_cycles_are_recorded_once_and_the_file_limit_is_explicit(tmp_path: Path) -> None:
    _write(tmp_path, "A.sol", 'import "./B.sol";\ncontract A {}')
    _write(tmp_path, "B.sol", 'import "./A.sol";\nimport "./C.sol";\ncontract B {}')
    _write(tmp_path, "C.sol", "contract C {}")
    closure = resolve_import_closure(tmp_path, ("A.sol",), file_limit=2)
    assert any(edge.status == "cycle" and edge.resolved == "A.sol" for edge in closure.edges)
    assert any(edge.status == "omitted" and edge.resolved == "C.sol" for edge in closure.edges)
    assert "C.sol" not in closure.dependencies
    assert closure.closure_complete is False
    assert any("file_limit" in note or "stopped at 2" in note for note in closure.notes)


def test_an_excluded_submodule_import_is_reported_and_not_crawled(tmp_path: Path) -> None:
    _write(tmp_path, "src/Target.sol", 'import "oz/Used.sol";\ncontract Target {}')
    _write(tmp_path, "gitmodules/oz/Used.sol", 'import "./Next.sol";\ncontract Used {}')
    _write(tmp_path, "gitmodules/oz/Next.sol", "contract Next {}")
    _write(tmp_path, "gitmodules/oz/Unused.sol", "contract Unused {}")
    _write(tmp_path, "remappings.txt", "oz/=gitmodules/oz/\n")
    blocked = resolve_import_closure(
        tmp_path, ("src/Target.sol",), excluded_roots=("gitmodules/oz",)
    )
    assert blocked.dependencies == ()
    assert blocked.unresolved[0].reason == "excluded_root"
    assert blocked.closure_complete is False
    allowed = resolve_import_closure(tmp_path, ("src/Target.sol",))
    assert allowed.dependencies == ("gitmodules/oz/Used.sol", "gitmodules/oz/Next.sol")
    assert "gitmodules/oz/Unused.sol" not in allowed.dependencies


def test_named_selection_keeps_targets_distinct_from_dependencies(tmp_path: Path) -> None:
    _write(tmp_path, "Target.sol", 'import "./Dep.sol";\ncontract Target {}')
    _write(tmp_path, "Dep.sol", "contract Dep {}")
    _write(tmp_path, "Other.sol", "contract Other {}")
    selection = select_named(tmp_path, ("Target.sol",))
    assert selection.role_of("Target.sol") == "target"
    assert selection.role_of("Dep.sol") == "compile_dependency"
    assert "Other.sol" not in selection.selected
    assert selection.repository_candidates == 2
    assert selection.enumeration_capped is False
    assert selection.dependency_status() == "traced"
    assert selection.closure_complete is True
