"""Verification specifications and bound harnesses.

A harness is authoritative only when BugForge generated it for one
specification and the tool output names that specification. ``encoded=True``
on a request is not authority. A banner string is not a predicate.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path

from app.parsing.solidity_ir import SemanticProgram
from app.parsing.solidity_state_transitions import (
    AbstractPredicate,
    CandidatePath,
    TransitionModel,
)

SCHEMA = "phase43.1"
MAX_HARNESS = 16_000
MAX_SEQUENCE = 8
MAX_ACTORS = 4
MAX_ATTEMPTS = 8
SMT_TIMEOUT_SECONDS = 30
FORGE_TIMEOUT_SECONDS = 60
_MATRIX = {
    "equality-scalar": {"smt": "supported", "foundry": "supported"},
    "equality-mapping-sum": {"smt": "unsupported", "foundry": "unsupported"},
    "monotonic-increment": {"smt": "supported", "foundry": "supported"},
    "asset-share": {"smt": "unsupported", "foundry": "unsupported"},
    "authorization": {"smt": "unsupported", "foundry": "unsupported"},
    "reentrancy": {"smt": "unsupported", "foundry": "unsupported"},
    "external-call-preservation": {"smt": "unsupported", "foundry": "unsupported"},
    "allowance": {"smt": "unsupported", "foundry": "unsupported"},
    "debt": {"smt": "unsupported", "foundry": "unsupported"},
    "reserve": {"smt": "unsupported", "foundry": "unsupported"},
    "pause": {"smt": "unsupported", "foundry": "unsupported"},
    "erc4626-conservation": {"smt": "unsupported", "foundry": "unsupported"},
    "unspecified": {"smt": "unsupported", "foundry": "unsupported"},
}


@dataclass(frozen=True)
class VerificationSpecification:
    specification_id: str
    path_id: str
    invariant_id: str
    property_category: str
    predicate_type: str
    predicate_lhs: str
    predicate_rhs: str
    predicate_subject: str
    contract: str
    function_ids: tuple[str, ...]
    operation_ids: tuple[str, ...]
    state_variables: tuple[str, ...]
    declaration_ids: tuple[str, ...]
    assumptions: tuple[str, ...]
    preconditions: tuple[str, ...]
    postconditions: tuple[str, ...]
    sequence: tuple[str, ...]
    actors: tuple[str, ...]
    source_id: str
    source_digest: str
    compiler_config: str
    smt: str
    foundry: str
    proof_scope: str
    specification_hash: str
    unsupported: tuple[str, ...] = ()


@dataclass(frozen=True)
class GeneratedArtifact:
    verification_id: str
    specification_hash: str
    source_digest: str
    compiler_config: str
    harness: str
    harness_digest: str
    manifest: str
    manifest_digest: str
    tool: str
    encoding_status: str
    token: str
    fail_token: str
    assert_line: int
    proof_scope: str
    command: tuple[str, ...]
    schema: str = SCHEMA


def bounds() -> dict[str, int]:
    return {
        "harness_chars": MAX_HARNESS,
        "sequence": MAX_SEQUENCE,
        "actors": MAX_ACTORS,
        "attempts": MAX_ATTEMPTS,
        "smt_timeout_seconds": SMT_TIMEOUT_SECONDS,
        "forge_timeout_seconds": FORGE_TIMEOUT_SECONDS,
    }


def capability_matrix() -> dict[str, dict[str, str]]:
    return {key: dict(value) for key, value in _MATRIX.items()}


def source_text(program: SemanticProgram) -> str:
    path = Path(program.file)
    if path.is_file():
        return path.read_text(encoding="utf-8")
    return "\n".join(function.source for function in program.functions)


def specify(
    path: CandidatePath, model: TransitionModel, program: SemanticProgram
) -> VerificationSpecification:
    invariant = next(
        (item for item in model.invariants if item.invariant_id == path.invariant_id),
        None,
    )
    predicate = invariant.predicate if invariant is not None else None
    source = source_text(program)
    contract = (
        invariant.contract if invariant else (path.contract_ids[0] if path.contract_ids else "")
    )
    smt, foundry, scope, unsupported = _capabilities(predicate, source, contract, path.function_ids)
    sequence = path.function_ids[:MAX_SEQUENCE]
    extra_unsupported = unsupported
    if len(path.function_ids) > MAX_SEQUENCE:
        extra_unsupported = (*unsupported, "transaction sequence was truncated")
    variables = invariant.state_variables if invariant else ()
    declarations = invariant.declarations if invariant else ()
    compiler = model.compiler_version or "unspecified"
    source_digest = _digest(source)
    payload = {
        "assumptions": path.assumptions,
        "category": invariant.category if invariant else path.path_id,
        "compiler": compiler,
        "contract": contract,
        "declarations": declarations,
        "foundry": foundry,
        "functions": sequence,
        "invariant": path.invariant_id,
        "operations": path.operation_ids,
        "path": path.path_id,
        "predicate": _predicate_payload(predicate),
        "schema": SCHEMA,
        "smt": smt,
        "source": source_digest,
        "source_id": program.file,
        "variables": variables,
    }
    spec_hash = _digest(json.dumps(payload, sort_keys=True, separators=(",", ":")))
    return VerificationSpecification(
        f"spec:{spec_hash[:16]}",
        path.path_id,
        path.invariant_id,
        invariant.category if invariant else "unspecified",
        predicate.predicate_type if predicate else "",
        predicate.lhs if predicate else "",
        predicate.rhs if predicate else "",
        predicate.subject if predicate else "",
        contract,
        sequence,
        path.operation_ids,
        variables,
        declarations,
        path.assumptions,
        path.conditions,
        (invariant.relation,) if invariant else (),
        sequence,
        (),
        program.file,
        source_digest,
        compiler,
        smt,
        foundry,
        scope,
        spec_hash,
        extra_unsupported,
    )


def generate_smt_artifact(spec: VerificationSpecification, source: str) -> GeneratedArtifact:
    token = f"bugforge_{spec.specification_hash[:8]}"
    fail_token = f"bugforge-fail:{spec.specification_hash}"
    command = (
        "solc",
        "--model-checker-engine",
        "chc",
        "--model-checker-show-proved-safe",
        "Harness.sol",
    )
    if spec.smt != "supported":
        plain = _unsupported_harness(spec, "smt")
        return _artifact(spec, source, plain, "smt", "unsupported", token, fail_token, 0, command)
    encoded = _encoded_smt_harness(spec, source, token)
    if encoded is None or "assert(true)" in encoded or len(encoded) > MAX_HARNESS:
        plain = _unsupported_harness(spec, "smt")
        return _artifact(spec, source, plain, "smt", "unsupported", token, fail_token, 0, command)
    harness = encoded
    return _artifact(
        spec, source, harness, "smt", "encoded", token, fail_token, _assert_line(harness), command
    )


def generate_forge_artifact(spec: VerificationSpecification, source: str) -> GeneratedArtifact:
    token = f"bugforge_{spec.specification_hash[:8]}"
    fail_token = f"bugforge-fail:{spec.specification_hash}"
    if spec.foundry != "supported":
        plain = _unsupported_harness(spec, "forge")
        return _artifact(spec, source, plain, "forge", "unsupported", token, fail_token, 0, ())
    encoded = _encoded_forge_harness(spec, source, fail_token)
    if (
        encoded is None
        or len(encoded) > MAX_HARNESS
        or "assert(true)" in encoded
        or "assertTrue(true)" in encoded
    ):
        plain = _unsupported_harness(spec, "forge")
        return _artifact(spec, source, plain, "forge", "unsupported", token, fail_token, 0, ())
    harness = encoded
    command = ("forge", "test", "--match-contract", "BugforgeReplay")
    return _artifact(
        spec, source, harness, "forge", "encoded", token, fail_token, _assert_line(harness), command
    )


def foundry_root(start: str) -> str:
    if not start:
        return ""
    current = Path(start)
    if current.is_file():
        current = current.parent
    for parent in (current, *current.parents):
        if (parent / "foundry.toml").is_file():
            return str(parent)
    return ""


def binds(
    artifact: GeneratedArtifact, spec: VerificationSpecification, source: str
) -> tuple[bool, str]:
    if artifact.specification_hash != spec.specification_hash:
        return False, "specification hash mismatch"
    if artifact.source_digest != _digest(source):
        return False, "source digest mismatch"
    if artifact.compiler_config != spec.compiler_config:
        return False, "compiler configuration mismatch"
    if artifact.harness_digest != _digest(artifact.harness):
        return False, "harness digest mismatch"
    if artifact.encoding_status != "encoded":
        return False, "property is not encoded"
    try:
        manifest = json.loads(artifact.manifest)
    except json.JSONDecodeError:
        return False, "manifest is not JSON"
    if manifest.get("harness_digest") != artifact.harness_digest:
        return False, "manifest harness digest mismatch"
    if manifest.get("specification_hash") != spec.specification_hash:
        return False, "manifest specification mismatch"
    if manifest.get("source_digest") != artifact.source_digest:
        return False, "manifest source mismatch"
    if manifest.get("schema") != SCHEMA:
        return False, "manifest schema mismatch"
    if manifest.get("contract") != spec.contract:
        return False, "manifest contract mismatch"
    if tuple(manifest.get("function_ids") or ()) != spec.function_ids:
        return False, "manifest function mismatch"
    if tuple(manifest.get("operation_ids") or ()) != spec.operation_ids:
        return False, "manifest operation mismatch"
    if manifest.get("path_id") != spec.path_id:
        return False, "manifest path mismatch"
    if manifest.get("invariant_id") != spec.invariant_id:
        return False, "manifest property mismatch"
    if spec.specification_hash not in artifact.harness:
        return False, "harness does not contain the specification hash"
    if artifact.encoding_status == "encoded" and "assert(true)" in artifact.harness:
        return False, "encoded harness contains a trivial assertion"
    if artifact.encoding_status == "encoded" and "assertTrue(true)" in artifact.harness:
        return False, "encoded harness contains a trivial assertion"
    return True, ""


def parse_smt_bound(stdout: str, stderr: str, artifact: GeneratedArtifact) -> str:
    """Accept a proof or counterexample only inside a stanza that names this artifact."""
    text = f"{stdout}\n{stderr}"
    if not text.strip():
        return "unknown"
    if re.search(r"time-?out|timed out|out of resources", text, re.IGNORECASE):
        return "timeout"
    relevant = _relevant_stanzas(text, artifact)
    if re.search(r"assertion violation|counterexample", relevant, re.IGNORECASE):
        return "counterexample"
    if re.search(r"\bproved\b", relevant, re.IGNORECASE):
        return "proved_safe"
    if re.search(r"unsupported|not yet implemented|cannot handle", text, re.IGNORECASE):
        return "unsupported"
    if "Error:" in text:
        return "failed"
    return "unknown"


def _relevant_stanzas(text: str, artifact: GeneratedArtifact) -> str:
    """Keep a few lines around the artifact token or its assert line.

    A diagnostic that merely shares a compiler log with the harness is not
    evidence for this property.
    """
    lines = text.splitlines()
    marker = f":{artifact.assert_line}:" if artifact.assert_line else ""
    kept: list[str] = []
    for index, line in enumerate(lines):
        if artifact.token in line or (marker and marker in line):
            start = max(0, index - 3)
            kept.extend(lines[start : index + 4])
    return "\n".join(kept)


def parse_forge_bound(text: str, artifact: GeneratedArtifact) -> str:
    if not text.strip():
        return "unknown"
    if re.search(r"time-?out|timed out", text, re.IGNORECASE):
        return "timeout"
    if re.search(r"Compiler run failed|Error \(", text):
        return "failed"
    failed = re.search(r"\[FAIL|Suite result: FAILED|Test result: FAILED", text, re.IGNORECASE)
    if failed and artifact.fail_token in text:
        return "reproduced"
    return "unknown"


def _capabilities(
    predicate: AbstractPredicate | None,
    source: str,
    contract: str,
    function_ids: tuple[str, ...],
) -> tuple[str, str, str, tuple[str, ...]]:
    if predicate is None:
        return "unsupported", "unsupported", "none", ("no predicate",)
    if "mapping aggregation" in " ".join(predicate.unsupported):
        return "unsupported", "unsupported", "none", predicate.unsupported
    callable_seq = _sequence_in_contract(function_ids, contract) and (
        _parameterless_name_in(source, function_ids) is not None
    )
    if predicate.predicate_type == "equality" and predicate.representation_status == "exact":
        readable = _state_names_in(source, contract, (predicate.lhs, predicate.rhs))
        smt_ok = callable_seq and readable and not _has_import(source)
        forge_ok = smt_ok and _forge_can_read(source, contract, predicate)
        notes = () if smt_ok else ("the transition cannot be called and read back",)
        scope = "contract-copy-harness" if smt_ok else "none"
        return (
            "supported" if smt_ok else "unsupported",
            "supported" if forge_ok else "unsupported",
            scope,
            notes,
        )
    if (
        predicate.predicate_type == "monotonic"
        and callable_seq
        and _increment_in(source, predicate.subject)
        and _state_names_in(source, contract, (predicate.subject,))
        and not _has_import(source)
    ):
        forge_ok = _public_names(source, (predicate.subject,))
        note = ("the property is the state value after the calls compared with the value before",)
        return (
            "supported",
            "supported" if forge_ok else "unsupported",
            "contract-copy-harness",
            note,
        )
    if predicate.representation_status == "partial":
        return (
            "unsupported",
            "unsupported",
            "none",
            predicate.unsupported or ("partial predicate is not encoded",),
        )
    return (
        "unsupported",
        "unsupported",
        "none",
        predicate.unsupported or ("predicate is not encodable",),
    )


def _has_import(source: str) -> bool:
    return re.search(r"^\s*import\b", source, re.MULTILINE) is not None


def _sequence_in_contract(function_ids: tuple[str, ...], contract: str) -> bool:
    if not function_ids or not contract:
        return False
    for function_id in function_ids:
        head = function_id.split(":")[0]
        if "." not in head or head.split(".")[0] != contract:
            return False
    return True


def _state_names_in(source: str, contract: str, names: tuple[str, ...]) -> bool:
    body = _contract_body(source, contract)
    if body is None:
        return False
    for name in names:
        if not name or name.startswith("sum("):
            return False
        if not re.search(rf"\b{re.escape(name)}\b", body):
            return False
    return True


def _public_names(source: str, names: tuple[str, ...]) -> bool:
    for name in names:
        if not name or name.startswith("sum("):
            return False
        if not re.search(
            rf"\b{re.escape(name)}\b[^;]*\bpublic\b|\bpublic\b[^;]*\b{re.escape(name)}\b",
            source,
        ):
            return False
    return True


def _contract_body(source: str, contract: str) -> str | None:
    match = re.search(rf"\bcontract\s+{re.escape(contract)}\b", source)
    if match is None:
        return None
    start = source.find("{", match.end())
    if start < 0:
        return None
    end = _close_brace(source, start)
    if end < 0:
        return None
    return source[start:end]


def _forge_can_read(source: str, contract: str, predicate: AbstractPredicate) -> bool:
    if _has_import(source):
        return False
    return _public_names(source, (predicate.lhs, predicate.rhs)) and _state_names_in(
        source, contract, (predicate.lhs, predicate.rhs)
    )


def _increment_in(source: str, symbol: str) -> bool:
    if not symbol:
        return False
    pattern = rf"\b{re.escape(symbol)}\s*(\+=\s*1|=\s*{re.escape(symbol)}\s*\+\s*1)\b"
    return re.search(pattern, source) is not None


def _encoded_smt_harness(spec: VerificationSpecification, source: str, token: str) -> str | None:
    names = _parameterless_names(source, spec.sequence)
    if not names or len(names) != len(spec.sequence):
        return None
    calls = "\n        ".join(f"{name}();" for name in names)
    if spec.predicate_type == "monotonic" and spec.predicate_subject:
        injected = (
            f"function {token}() external {{\n"
            f"        uint256 previous = {spec.predicate_subject};\n"
            f"        {calls}\n"
            f"        uint256 next = {spec.predicate_subject};\n"
            "        assert(next > previous);\n"
            "    }\n"
        )
    elif (
        spec.predicate_type == "equality"
        and re.fullmatch(r"[A-Za-z_]\w*", spec.predicate_lhs or "")
        and re.fullmatch(r"[A-Za-z_]\w*", spec.predicate_rhs or "")
    ):
        injected = (
            f"function {token}() external {{\n"
            f"        {calls}\n"
            f"        assert({spec.predicate_lhs} == {spec.predicate_rhs});\n"
            "    }\n"
        )
    else:
        return None
    copied = _inject(source, spec.contract, injected)
    if copied is None:
        return None
    return _header(spec, "smt") + copied


def _encoded_forge_harness(
    spec: VerificationSpecification, source: str, fail_token: str
) -> str | None:
    names = _parameterless_names(source, spec.sequence)
    if not names or len(names) != len(spec.sequence) or not spec.contract:
        return None
    calls = "\n        ".join(f"target.{item}();" for item in names)
    if spec.predicate_type == "equality" and spec.predicate_lhs and spec.predicate_rhs:
        body = (
            f"{calls}\n"
            f"        if (target.{spec.predicate_lhs}() != target.{spec.predicate_rhs}()) "
            f'revert("{fail_token}");'
        )
    elif spec.predicate_type == "monotonic" and spec.predicate_subject:
        body = (
            f"uint256 previous = target.{spec.predicate_subject}();\n"
            f"        {calls}\n"
            f"        if (target.{spec.predicate_subject}() <= previous) "
            f'revert("{fail_token}");'
        )
    else:
        return None
    test = (
        "contract BugforgeReplay {\n"
        f"    function test_{spec.specification_hash[:8]}() external {{\n"
        f"        {spec.contract} target = new {spec.contract}();\n"
        f"        {body}\n"
        "    }\n"
        "}\n"
    )
    return _header(spec, "forge") + source + "\n" + test


def _parameterless_names(source: str, function_ids: tuple[str, ...]) -> tuple[str, ...]:
    names: list[str] = []
    for function_id in function_ids:
        name = function_id.split(":")[0].split(".")[-1]
        if re.search(rf"function\s+{re.escape(name)}\s*\(\s*\)", source):
            names.append(name)
    return tuple(names)


def _parameterless_name_in(source: str, function_ids: tuple[str, ...]) -> str | None:
    names = _parameterless_names(source, function_ids)
    if len(names) == len(function_ids) and names:
        return names[-1]
    return None


def _inject(source: str, contract: str, function_text: str) -> str | None:
    match = re.search(rf"\bcontract\s+{re.escape(contract)}\b", source)
    if match is None:
        return None
    start = source.find("{", match.end())
    if start < 0:
        return None
    end = _close_brace(source, start)
    if end < 0:
        return None
    return source[: end - 1] + "\n" + function_text + source[end - 1 :]


def _close_brace(source: str, start: int) -> int:
    depth = 0
    index = start
    while index < len(source):
        char = source[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index + 1
        index += 1
    return -1


def _unsupported_harness(spec: VerificationSpecification, tool: str) -> str:
    reason = ", ".join(spec.unsupported) or spec.smt
    return (
        f"// BUGFORGE_VERIFICATION_SPEC {spec.specification_hash}\n"
        f"// tool: {tool}\n"
        f"// encoding: unsupported\n"
        f"// {reason[:240]}\n"
        "// This file contains no assertion. Unsupported is not success.\n"
    )


def _header(spec: VerificationSpecification, tool: str) -> str:
    return (
        f"// BUGFORGE_VERIFICATION_SPEC {spec.specification_hash}\n"
        f"// verification_id: ver:{spec.path_id}\n"
        f"// candidate_id: {spec.path_id}\n"
        f"// property_id: {spec.invariant_id}\n"
        f"// source_digest: {spec.source_digest}\n"
        f"// proof_scope: {spec.proof_scope}\n"
        f"// tool: {tool}\n"
        "// Generated verification harness. Not production source.\n"
    )


def _artifact(
    spec: VerificationSpecification,
    source: str,
    harness: str,
    tool: str,
    encoding_status: str,
    token: str,
    fail_token: str,
    assert_line: int,
    command: tuple[str, ...],
) -> GeneratedArtifact:
    harness_digest = _digest(harness)
    verification_id = f"ver:{spec.path_id}"
    source_digest = _digest(source)
    manifest_body = {
        "assert_line": assert_line,
        "command": command,
        "compiler_config": spec.compiler_config,
        "contract": spec.contract,
        "encoding_status": encoding_status,
        "fail_token": fail_token,
        "function_ids": spec.function_ids,
        "harness_digest": harness_digest,
        "invariant_id": spec.invariant_id,
        "operation_ids": spec.operation_ids,
        "path_id": spec.path_id,
        "proof_scope": spec.proof_scope,
        "schema": SCHEMA,
        "source_digest": source_digest,
        "specification_hash": spec.specification_hash,
        "token": token,
        "tool": tool,
        "verification_id": verification_id,
    }
    manifest = json.dumps(manifest_body, sort_keys=True, separators=(",", ":"))
    return GeneratedArtifact(
        verification_id,
        spec.specification_hash,
        source_digest,
        spec.compiler_config,
        harness,
        harness_digest,
        manifest,
        _digest(manifest),
        tool,
        encoding_status,
        token,
        fail_token,
        assert_line,
        spec.proof_scope,
        command,
    )


def _predicate_payload(predicate: AbstractPredicate | None) -> dict[str, str]:
    if predicate is None:
        return {}
    return {
        "lhs": predicate.lhs,
        "operator": predicate.operator,
        "rhs": predicate.rhs,
        "status": predicate.representation_status,
        "subject": predicate.subject,
        "type": predicate.predicate_type,
    }


def _assert_line(harness: str) -> int:
    for index, line in enumerate(harness.splitlines(), start=1):
        if "assert(" in line:
            return index
    return 0


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()
