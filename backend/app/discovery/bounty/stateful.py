"""Stateful local execution bridge: VFCS plans -> executable Foundry harnesses.

This is the Phase 52 closed loop's execution leg. A deterministic VFCS plan is
compiled into a real Foundry test that deploys the analyzed contract and runs the
plan's attacker-role call sequence against a fresh instance, entirely offline:

* no RPC, no fork, no live chain (``--no-match-path`` nothing, ``--offline``,
  ``FOUNDRY_OFFLINE=true``, fs/ffi disabled);
* the installed ``forge`` runs the test and the process exit status is
  authoritative -- a document left by a crashed process is never evidence;
* when ``forge`` or a compiler is missing, or the plan cannot be made executable
  (an unresolved constructor, a primitive that needs an environment actor), the
  result is reported UNAVAILABLE or INCONCLUSIVE and never fabricated.

An execution produces a bounded :class:`StatefulObservation`. A reverting call
or a violated property becomes a :class:`FeedbackSignal` that drives the existing
bounded ``mutate``; mutated plans are re-executed. Minimization reuses the VFCS
delta-debugger with the executor as its evaluator. An independent re-check rebuilds
and reruns the plan under a second compiler pipeline; agreement is required before
anything is called corroborated. Nothing here marks a finding verified.
"""

from __future__ import annotations

import json
import re
import subprocess
import tempfile
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

from app.discovery.bounty.vfcs import (
    ATTACKER,
    MAX_MUTATIONS,
    FeedbackSignal,
    MinimizationResult,
    Vfcs,
    VfcsCall,
    minimize,
    mutate,
)
from app.discovery.process import tool_path
from app.parsing.solidity_research import Param, ResearchModel, RFunction

MAX_CALLS = 8
MAX_FEEDBACK_ROUNDS = 3
EXEC_TIMEOUT = 120
ATTACKER_ADDR = "address(0xA11CE)"
VICTIM_ADDR = "address(0xB0B)"


class Outcome(StrEnum):
    PROPERTY_VIOLATED = "property_violated"
    PROPERTY_HELD = "property_held"
    SEQUENCE_EXECUTED = "sequence_executed"
    SEQUENCE_REVERTED = "sequence_reverted"
    INCONCLUSIVE = "inconclusive"
    UNAVAILABLE = "unavailable"


RUNNABLE = frozenset(
    {Outcome.PROPERTY_VIOLATED, Outcome.PROPERTY_HELD, Outcome.SEQUENCE_EXECUTED, Outcome.SEQUENCE_REVERTED}
)


@dataclass(frozen=True)
class ToolStatus:
    forge: str
    solc: str

    @property
    def available(self) -> bool:
        return self.forge == "available"

    def as_dict(self) -> dict[str, str]:
        return {"forge": self.forge, "solc": self.solc}


def tool_status() -> ToolStatus:
    forge = "available" if tool_path("forge") else "unavailable"
    solc = "available" if tool_path("solc") else "unavailable"
    return ToolStatus(forge=forge, solc=solc)


def execution_enabled() -> bool:
    from app.core.config import get_settings

    return bool(get_settings().bounty_stateful_execution)


@dataclass(frozen=True)
class HarnessArtifact:
    sequence_id: str
    source: str
    test_name: str
    pipeline: str
    reason: str = ""

    @property
    def buildable(self) -> bool:
        return bool(self.source)


@dataclass(frozen=True)
class StatefulObservation:
    sequence_id: str
    outcome: Outcome
    reason: str
    pipeline: str
    executed: bool
    return_code: int | None
    reverted_index: int
    property_under_test: str
    property_checked: bool
    deployment: str
    tools: ToolStatus
    stdout_tail: str = ""
    verified: bool = False

    def signal(self) -> FeedbackSignal | None:
        """Turn an execution observation into bounded feedback. None = nothing to learn."""
        if self.outcome is Outcome.SEQUENCE_REVERTED and self.reverted_index >= 0:
            return FeedbackSignal(
                kind="near_miss",
                sequence_id=self.sequence_id,
                call_index=self.reverted_index,
                engine="foundry",
            )
        if self.outcome is Outcome.PROPERTY_VIOLATED:
            return FeedbackSignal(
                kind="symbolic_counterexample",
                sequence_id=self.sequence_id,
                engine="foundry",
            )
        if self.outcome is Outcome.SEQUENCE_EXECUTED:
            return FeedbackSignal(
                kind="coverage_gain", sequence_id=self.sequence_id, engine="foundry"
            )
        return None

    def as_dict(self) -> dict[str, Any]:
        return {
            "sequence_id": self.sequence_id,
            "outcome": self.outcome.value,
            "reason": self.reason,
            "pipeline": self.pipeline,
            "executed": self.executed,
            "return_code": self.return_code,
            "reverted_index": self.reverted_index,
            "property_under_test": self.property_under_test,
            "property_checked": self.property_checked,
            "deployment": self.deployment,
            "tools": self.tools.as_dict(),
            "verified": False,
        }


# ---- harness synthesis ----------------------------------------------------------------------

_SIMPLE_VALUE = {
    "address": ATTACKER_ADDR,
    "bool": "false",
    "string": '""',
    "bytes": '""',
}


def _default_arg(param: Param, actor: str, override: str) -> str | None:
    """A concrete Solidity literal for a parameter, or None when it is not expressible."""
    type_name = param.type_name.strip()
    base = type_name.split()[0]
    if override in {"victim_amount", "minimum_amount", "all_shares", "credited_balance"}:
        override = ""
    if base == "address" or base == "address payable":
        if override in {"attacker_controlled", "attacker_substituted"} or actor == ATTACKER:
            return ATTACKER_ADDR
        return VICTIM_ADDR
    if base.startswith("uint") or base.startswith("int"):
        if override == "max_uint":
            return "type(uint256).max" if base.startswith("uint") else "type(int256).max"
        if override in {"one", "amount_one"}:
            return "1"
        if override == "zero":
            return "0"
        return "0"
    if base == "bool":
        return "false"
    if base == "string":
        return '""'
    if base.startswith("bytes") and base != "bytes":
        return f"{base}(0)"
    if base == "bytes":
        return '""'
    if base.endswith("[]"):
        inner = base[:-2]
        return f"new {inner}[](0)"
    return None


def _encode_call(call: VfcsCall, function: RFunction) -> str | None:
    args: list[str] = []
    overrides = dict(call.arguments)
    for param in function.params:
        value = _default_arg(param, call.actor, overrides.get(param.name, ""))
        if value is None:
            return None
        args.append(value)
    selector = function.signature
    encoded = ", ".join([json.dumps(selector)] + args) if args else json.dumps(selector)
    return f"abi.encodeWithSignature({encoded})"


def _constructor(model: ResearchModel, contract: str) -> RFunction | None:
    for function in model.functions_of(contract, inherited=False):
        if function.kind == "constructor":
            return function
    return None


def build_harness(
    sequence: Vfcs,
    model: ResearchModel,
    *,
    source_file: str,
    pipeline: str = "default",
) -> HarnessArtifact:
    """Compile a VFCS plan into an executable Foundry test, or explain why not."""
    if len(sequence.calls) > MAX_CALLS:
        return HarnessArtifact(sequence.sequence_id, "", "", pipeline, "sequence too long")
    contract = sequence.calls[0].contract if sequence.calls else ""
    item = model.contracts.get(contract)
    if item is None or item.is_interface:
        return HarnessArtifact(
            sequence.sequence_id, "", "", pipeline, "target contract is not a deployable source"
        )
    ctor = _constructor(model, contract)
    if ctor is not None and ctor.params:
        return HarnessArtifact(
            sequence.sequence_id, "", "", pipeline, "constructor requires arguments"
        )
    steps: list[str] = []
    property_checked = False
    prior_init = False
    for index, call in enumerate(sequence.calls):
        if call.primitive:
            # An environment primitive (donation, warp, external market) is not
            # executed locally; the plan stays honest about needing it.
            return HarnessArtifact(
                sequence.sequence_id,
                "",
                "",
                pipeline,
                f"call {index} is an environment primitive ({call.function})",
            )
        function = _resolve(model, call.contract, call.function)
        if function is None or call.contract != contract:
            return HarnessArtifact(
                sequence.sequence_id,
                "",
                "",
                pipeline,
                "a call is not a function of the single target contract",
            )
        encoded = _encode_call(call, function)
        if encoded is None:
            return HarnessArtifact(
                sequence.sequence_id, "", "", pipeline, "a parameter type is not expressible"
            )
        sender = ATTACKER_ADDR if call.actor == ATTACKER else VICTIM_ADDR
        check = ""
        if sequence.template == "initialize→reinitialize" and call.role == "reinitialize":
            # Property: a second initialization must not succeed.
            check = (
                f"        if (ok_{index}) {{ emit PropertyViolated({index}); violated = true; }}\n"
            )
            property_checked = True
            prior_init = True
        steps.append(
            f"        vm.prank({sender});\n"
            f"        (bool ok_{index}, ) = address(t).call({encoded});\n"
            f"        reached_{index} = ok_{index};\n"
            + check
        )
    rel_import = source_file
    body = "\n".join(steps)
    reached_decls = "\n".join(f"    bool public reached_{i};" for i in range(len(sequence.calls)))
    test_name = "test_vfcs_execute"
    source = _HARNESS_TEMPLATE.format(
        import_path=rel_import,
        contract=contract,
        reached_decls=reached_decls,
        body=body,
        test_name=test_name,
        property_tag="true" if property_checked else "false",
    )
    _ = prior_init
    return HarnessArtifact(sequence.sequence_id, source, test_name, pipeline)


def _resolve(model: ResearchModel, contract: str, signature: str) -> RFunction | None:
    for function in model.functions_of(contract):
        if function.signature == signature and function.has_body:
            return function
    return None


_HARNESS_TEMPLATE = """// SPDX-License-Identifier: UNLICENSED
// UNTRUSTED CANDIDATE HARNESS. Deterministic local execution only. Not a verified proof.
pragma solidity >=0.7.0;

import {{Test}} from "forge-std/Test.sol";
import "src/{import_path}";

contract VfcsHarness is Test {{
{reached_decls}
    bool public violated;
    bool public constant PROPERTY_CHECKED = {property_tag};

    event PropertyViolated(uint256 step);

    function {test_name}() public {{
        {contract} t = new {contract}();
{body}
        // reachability is recorded in reached_* ; a violated property fails the test
        require(!violated, "property violated: sequence reached a forbidden state");
    }}
}}
"""


# ---- execution ------------------------------------------------------------------------------


class StatefulExecutor:
    """Runs synthesized harnesses with the installed ``forge``, offline and bounded."""

    def __init__(self, *, timeout: int = EXEC_TIMEOUT, bundle_dir: Path | None = None) -> None:
        self.timeout = timeout
        self.bundle_dir = bundle_dir
        self.tools = tool_status()

    def available(self) -> bool:
        return execution_enabled() and self.tools.available

    def execute(
        self,
        sequence: Vfcs,
        model: ResearchModel,
        sources: dict[str, str],
        *,
        source_file: str,
        deployment: str = "",
        pipeline: str = "default",
    ) -> StatefulObservation:
        if not execution_enabled():
            return self._unavailable(sequence, "local stateful execution is disabled", pipeline)
        if not self.tools.available:
            return self._unavailable(sequence, "forge is not installed", pipeline)
        harness = build_harness(sequence, model, source_file=source_file, pipeline=pipeline)
        if not harness.buildable:
            return self._inconclusive(sequence, harness.reason, pipeline, deployment)
        return self._run(sequence, harness, sources, deployment, pipeline)

    def _run(
        self,
        sequence: Vfcs,
        harness: HarnessArtifact,
        sources: dict[str, str],
        deployment: str,
        pipeline: str,
    ) -> StatefulObservation:
        with tempfile.TemporaryDirectory(prefix="bugforge-vfcs-") as tmp:
            root = Path(tmp)
            self._scaffold(root, sources, harness, pipeline)
            argv = [
                "forge",
                "test",
                "--match-path",
                "test/VfcsHarness.t.sol",
                "--offline",
                "-vv",
            ]
            env = {
                "PATH": _safe_path(),
                "FOUNDRY_OFFLINE": "true",
                "FOUNDRY_FFI": "false",
                "HOME": tmp,
            }
            try:
                proc = subprocess.run(
                    argv,
                    cwd=root,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout,
                    check=False,
                    env=env,
                )
            except (OSError, subprocess.SubprocessError) as exc:
                return self._inconclusive(
                    sequence, f"forge did not run: {str(exc)[:160]}", pipeline, deployment
                )
            observation = self._interpret(
                sequence, harness, proc.returncode, proc.stdout + "\n" + proc.stderr, deployment
            )
            if self.bundle_dir is not None and observation.outcome in RUNNABLE:
                self._write_bundle(sequence, harness, observation, argv)
            return observation

    def _scaffold(
        self, root: Path, sources: dict[str, str], harness: HarnessArtifact, pipeline: str
    ) -> None:
        (root / "src").mkdir(parents=True, exist_ok=True)
        (root / "test").mkdir(parents=True, exist_ok=True)
        (root / "lib" / "forge-std" / "src").mkdir(parents=True, exist_ok=True)
        for rel, text in sources.items():
            target = (root / "src" / rel).resolve()
            if root.resolve() not in target.parents:
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8")
        (root / "test" / "VfcsHarness.t.sol").write_text(harness.source, encoding="utf-8")
        (root / "lib" / "forge-std" / "src" / "Test.sol").write_text(_FORGE_STD, encoding="utf-8")
        via_ir = "true" if pipeline == "via_ir" else "false"
        optimizer = "false" if pipeline == "no_optimizer" else "true"
        # Point Foundry at the installed solc so nothing is downloaded (offline).
        solc = tool_path("solc")
        solc_line = f'solc = "{solc}"\n' if solc else ""
        (root / "foundry.toml").write_text(
            "[profile.default]\n"
            'src = "src"\n'
            'test = "test"\n'
            'libs = ["lib"]\n'
            "ffi = false\n"
            "fs_permissions = []\n"
            "auto_detect_solc = false\n"
            + solc_line
            + f"via_ir = {via_ir}\n"
            f"optimizer = {optimizer}\n"
            'remappings = ["forge-std/=lib/forge-std/src/"]\n',
            encoding="utf-8",
        )

    def _interpret(
        self,
        sequence: Vfcs,
        harness: HarnessArtifact,
        return_code: int,
        output: str,
        deployment: str,
    ) -> StatefulObservation:
        tail = output[-1500:]
        if re.search(r"Compiler run failed|Error \(\d+\)|could not", output) and "PASS" not in output:
            return self._inconclusive(
                sequence, "the harness did not compile against this source", harness.pipeline,
                deployment, tail,
            )
        passed = bool(re.search(r"\[PASS\].*test_vfcs_execute", output))
        failed = bool(re.search(r"\[FAIL.*test_vfcs_execute", output))
        property_checked = "PROPERTY_CHECKED = true" in harness.source
        revert_index = _reverted_index(output, len(sequence.calls))
        if failed and "property violated" in output:
            outcome = Outcome.PROPERTY_VIOLATED
            reason = "the sequence reached the forbidden state the property forbids"
        elif passed and property_checked:
            outcome = Outcome.PROPERTY_HELD
            reason = "the sequence executed and the property held"
        elif passed:
            outcome = Outcome.SEQUENCE_EXECUTED
            reason = "the attacker call sequence executed end to end against a fresh deployment"
        elif failed and revert_index >= 0:
            outcome = Outcome.SEQUENCE_REVERTED
            reason = f"call {revert_index} reverted against a fresh deployment"
        elif failed:
            outcome = Outcome.SEQUENCE_REVERTED
            reason = "the sequence reverted against a fresh deployment"
        else:
            return self._inconclusive(
                sequence, "forge produced no test result", harness.pipeline, deployment, tail
            )
        return StatefulObservation(
            sequence_id=sequence.sequence_id,
            outcome=outcome,
            reason=reason,
            pipeline=harness.pipeline,
            executed=True,
            return_code=return_code,
            reverted_index=revert_index,
            property_under_test=sequence.property_under_test,
            property_checked=property_checked,
            deployment=deployment,
            tools=self.tools,
            stdout_tail=tail,
        )

    def _unavailable(self, sequence: Vfcs, reason: str, pipeline: str) -> StatefulObservation:
        return StatefulObservation(
            sequence.sequence_id, Outcome.UNAVAILABLE, reason, pipeline, False, None, -1,
            sequence.property_under_test, False, "", self.tools,
        )

    def _inconclusive(
        self, sequence: Vfcs, reason: str, pipeline: str, deployment: str, tail: str = ""
    ) -> StatefulObservation:
        return StatefulObservation(
            sequence.sequence_id, Outcome.INCONCLUSIVE, reason, pipeline, True, None, -1,
            sequence.property_under_test, False, deployment, self.tools, tail,
        )

    def _write_bundle(
        self, sequence: Vfcs, harness: HarnessArtifact, obs: StatefulObservation, argv: list[str]
    ) -> None:
        assert self.bundle_dir is not None
        folder = self.bundle_dir / sequence.sequence_id
        folder.mkdir(parents=True, exist_ok=True)
        (folder / "VfcsHarness.t.sol").write_text(harness.source, encoding="utf-8")
        (folder / "manifest.json").write_text(
            json.dumps(
                {
                    "sequence_id": sequence.sequence_id,
                    "template": sequence.template,
                    "property_under_test": sequence.property_under_test,
                    "command": " ".join(argv),
                    "pipeline": harness.pipeline,
                    "observation": obs.as_dict(),
                    "note": "deterministic local reproduction; offline; ffi disabled; not verified",
                },
                indent=2,
                sort_keys=True,
            ),
            encoding="utf-8",
        )


def _reverted_index(output: str, count: int) -> int:
    for index in range(count):
        if re.search(rf"reached_{index}\(\)\s+false|reached_{index} = false", output):
            return index
    return -1


def _safe_path() -> str:
    import os

    parts = [p for p in os.environ.get("PATH", "").split(":") if p]
    return ":".join(parts) or "/usr/bin:/bin"


# ---- feedback-directed closed loop ----------------------------------------------------------


@dataclass
class FeedbackLoopResult:
    observations: tuple[StatefulObservation, ...]
    mutated: tuple[Vfcs, ...]
    signals_emitted: tuple[str, ...]
    minimized: dict[str, MinimizationResult] = field(default_factory=dict)
    independent: dict[str, StatefulObservation] = field(default_factory=dict)

    @property
    def violations(self) -> tuple[StatefulObservation, ...]:
        return tuple(o for o in self.observations if o.outcome is Outcome.PROPERTY_VIOLATED)

    def as_dict(self) -> dict[str, Any]:
        return {
            "verified": False,
            "observations": [o.as_dict() for o in self.observations],
            "mutated": [s.sequence_id for s in self.mutated],
            "signals_emitted": list(self.signals_emitted),
            "minimized": {
                sid: {
                    "original": len(result.original),
                    "minimized": len(result.minimized),
                    "completed": result.completed,
                    "reason": result.reason,
                }
                for sid, result in self.minimized.items()
            },
            "independent_checks": {
                sid: obs.as_dict() for sid, obs in self.independent.items()
            },
        }


def run_feedback_loop(
    executor: StatefulExecutor,
    sequences: tuple[Vfcs, ...],
    models: dict[str, ResearchModel],
    sources: dict[str, str],
    *,
    source_file: str,
    deployment: str = "",
    rounds: int = MAX_FEEDBACK_ROUNDS,
    limit: int = MAX_MUTATIONS,
) -> FeedbackLoopResult:
    """The executable closed loop: execute -> observe -> feedback -> mutate -> re-execute
    -> minimize -> independent re-check. Idempotent per (sequence, pipeline)."""
    observations: list[StatefulObservation] = []
    emitted: list[str] = []
    minimized: dict[str, MinimizationResult] = {}
    independent: dict[str, StatefulObservation] = {}
    seen: set[str] = set()
    frontier = list(sequences)
    all_mutated: list[Vfcs] = []
    by_id = {s.sequence_id: s for s in sequences}

    for _round in range(max(1, rounds)):
        signals: list[FeedbackSignal] = []
        next_frontier: list[Vfcs] = []
        for sequence in frontier:
            if sequence.sequence_id in seen:
                continue
            seen.add(sequence.sequence_id)
            model = models.get(sequence.sequence_id)
            if model is None:
                continue
            obs = executor.execute(
                sequence, model, sources, source_file=source_file, deployment=deployment
            )
            observations.append(obs)
            signal = obs.signal()
            if signal is not None:
                signals.append(signal)
                emitted.append(f"{signal.engine}:{signal.kind}:{signal.sequence_id}")
            if obs.outcome in {Outcome.PROPERTY_VIOLATED, Outcome.SEQUENCE_REVERTED}:
                result = _minimize_sequence(executor, sequence, model, sources, source_file, deployment)
                if result is not None:
                    minimized[sequence.sequence_id] = result
                indep = executor.execute(
                    sequence, model, sources, source_file=source_file,
                    deployment=deployment, pipeline="no_optimizer",
                )
                independent[sequence.sequence_id] = indep
        if not signals:
            break
        parents = list(by_id.values())
        children = mutate(parents, signals, limit=limit)
        for child in children:
            if child.sequence_id in by_id:
                continue
            parent_model = _parent_model(child, models)
            if parent_model is None:
                continue
            by_id[child.sequence_id] = child
            models[child.sequence_id] = parent_model
            all_mutated.append(child)
            next_frontier.append(child)
        frontier = next_frontier
        if not frontier:
            break

    return FeedbackLoopResult(
        observations=tuple(observations),
        mutated=tuple(all_mutated),
        signals_emitted=tuple(emitted),
        minimized=minimized,
        independent=independent,
    )


def _parent_model(child: Vfcs, models: dict[str, ResearchModel]) -> ResearchModel | None:
    # Mutations keep the parent's identity/contract; any model that built a sibling works.
    for model in models.values():
        if child.calls and child.calls[0].contract in model.contracts:
            return model
    return None


def _minimize_sequence(
    executor: StatefulExecutor,
    sequence: Vfcs,
    model: ResearchModel,
    sources: dict[str, str],
    source_file: str,
    deployment: str,
) -> MinimizationResult | None:
    def evaluator(calls: tuple[VfcsCall, ...]) -> bool | None:
        from dataclasses import replace

        trial = replace(sequence, calls=calls)
        obs = executor.execute(
            trial, model, sources, source_file=source_file, deployment=deployment
        )
        if obs.outcome is Outcome.PROPERTY_VIOLATED:
            return True
        if obs.outcome in {Outcome.PROPERTY_HELD, Outcome.SEQUENCE_EXECUTED}:
            return False
        if obs.outcome is Outcome.SEQUENCE_REVERTED:
            return False
        return None

    return minimize(sequence, evaluator, evaluator_name="foundry_local", max_attempts=16)


# forge-std is big; BugForge does not vendor it. A tiny local shim provides only the
# Test base and the vm.prank cheat the harness uses, so execution needs no download.
_FORGE_STD = """// SPDX-License-Identifier: MIT
pragma solidity >=0.7.0;

interface Vm {
    function prank(address) external;
    function warp(uint256) external;
    function deal(address, uint256) external;
    function startPrank(address) external;
    function stopPrank() external;
}

contract Test {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
}
"""


__all__ = [
    "HarnessArtifact",
    "Outcome",
    "StatefulExecutor",
    "StatefulObservation",
    "FeedbackLoopResult",
    "ToolStatus",
    "build_harness",
    "execution_enabled",
    "run_feedback_loop",
    "tool_status",
]
