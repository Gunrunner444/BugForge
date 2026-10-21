"""The deployed cUSDCv3 implementation source (Comet 059c1191). Never vendored.

The closure hashes are the Sourcify standard-JSON input of the verified
implementation; a checkout whose files differ is not the deployed source.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

DEPLOYED_PIN = "059c11917f75049b41756d5c5fd44eb3dc716385"
TARGET = "contracts/CometWithExtendedAssetList.sol"
CONTRACT = "CometWithExtendedAssetList"
CLOSURE_SHA256 = {
    "contracts/CometWithExtendedAssetList.sol": (
        "bcb7b2337bedd370d678cffb4f1adb80a12140b355097f22fd10db2b475a49a2"
    ),
    "contracts/CometMainInterface.sol": (
        "8dab837c9ef1d3805413b2d5c948d8c1f5b009da4e4f9505795b2a1535ec0d1b"
    ),
    "contracts/CometCore.sol": "1d80f0d12c101d01c2e1f38e8662cfcf350299b1c78188f8c501bb1c51b5ec78",
    "contracts/CometConfiguration.sol": (
        "e055b1588dcd7d24ba8dd79b2fec7bcb8132b1bfbf8670448ad37d7150cc75b4"
    ),
    "contracts/CometStorage.sol": (
        "7475e03d2945a35e9bbd93fa96ba8bc18d50f60cdb9ea992e6742efbc199850c"
    ),
    "contracts/CometMath.sol": "b649c9c7bdc945ed7901da3454a526deb8e73400243069e36670bf8a89267a0f",
    "contracts/IERC20NonStandard.sol": (
        "520c9275eeecb6867afd1afe765aa58a29e8789cc2c0e396252e36047ca389b3"
    ),
    "contracts/IPriceFeed.sol": "785123d77415efc00f8aee4e1cf600b8bebc46813412283d3dd5673bd23d53f8",
    "contracts/IAssetListFactory.sol": (
        "2a161d7ed50b23e514db7c20bcf9da404002aef70c9cbed835f4120136cd8408"
    ),
    "contracts/IAssetListFactoryHolder.sol": (
        "f2c5452a18a2339f9a3ac65060ebf717daa1b931211a5b1909772962065f0d11"
    ),
    "contracts/IAssetList.sol": "b8151abf7b8b64d240efa57c24fbe4136124befe90052ff1fe0a3018529802c7",
}
CLOSURE = tuple(CLOSURE_SHA256)
# The verified settings. Foundry does not receive the custom Yul optimizer steps.
DEPLOYED_COMPILER = {
    "version": "0.8.15",
    "optimizer": "enabled",
    "optimizer_runs": "1",
    "via_ir": "true",
    "evm_version": "london",
}


def deployed_root() -> Path:
    """The 059c1191 checkout, or skip. A wrong commit or a changed file fails closed."""
    raw = os.environ.get("BUGFORGE_COMET_DEPLOYED_ROOT", "/tmp/comet-059c1191")
    root = Path(raw)
    if not (root / TARGET).is_file():
        if os.environ.get("BUGFORGE_REQUIRE_COMET") == "1":
            pytest.fail(f"{root / TARGET} is not available")
        pytest.skip("Comet 059c1191 is not available; set BUGFORGE_COMET_DEPLOYED_ROOT")
    sha = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
    if sha != DEPLOYED_PIN:
        pytest.fail(f"Comet checkout is {sha}, expected {DEPLOYED_PIN}")
    return root


def deployed_sources(root: Path) -> dict[str, str]:
    import hashlib

    sources: dict[str, str] = {}
    for path, expected in CLOSURE_SHA256.items():
        file = root / path
        if not file.is_file():
            pytest.fail(f"{path} is missing from the 059c1191 checkout")
        data = file.read_bytes()
        actual = hashlib.sha256(data).hexdigest()
        if actual != expected:
            pytest.fail(f"{path} is {actual}, not the deployed source {expected}")
        sources[path] = data.decode("utf-8")
    return sources
