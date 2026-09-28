"""Documented local corpora. Nothing here contacts the network."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class BenchmarkFixture:
    fixture_id: str
    corpus: str
    vulnerability_class: str
    expected_behavior: str
    expected_detector: str
    sequence_length: int | None
    regression_status: str
    engines: tuple[str, ...]


RECOMMENDED: tuple[BenchmarkFixture, ...] = (
    BenchmarkFixture(
        "damn-vulnerable-defi",
        "Damn Vulnerable DeFi",
        "defi",
        "a local authorized checkout can be scored offline",
        "accounting",
        None,
        "not-vendored",
        ("forge", "ityfuzz"),
    ),
    BenchmarkFixture(
        "smartbugs-curated",
        "SmartBugs Curated",
        "mixed",
        "curated samples stay outside the production scanner",
        "static",
        None,
        "not-vendored",
        ("bugforge-static",),
    ),
    BenchmarkFixture(
        "cve-smart-contracts",
        "CVE-Smart-Contracts",
        "cve",
        "historical cases are fixtures, not a live claim",
        "candidate",
        None,
        "not-vendored",
        ("bugforge-static",),
    ),
    BenchmarkFixture(
        "erc4626-properties",
        "ERC-4626 property tests",
        "erc4626",
        "property scenarios need a local harness",
        "asset-share",
        None,
        "not-vendored",
        ("foundry",),
    ),
)


def load_local(root: Path) -> tuple[BenchmarkFixture, ...]:
    """Read a local catalog. A missing directory is empty, not a download."""
    if not root.is_dir():
        return ()
    found: list[BenchmarkFixture] = []
    for item in RECOMMENDED:
        marker = root / item.fixture_id
        if marker.exists():
            found.append(item)
    return tuple(found)
