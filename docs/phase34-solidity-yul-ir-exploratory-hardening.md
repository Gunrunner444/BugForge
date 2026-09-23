# Phase 34 — Yul/IR analysis and exploratory-testing hardening

Phase 34 keeps the Phase 33 exploratory and cross-contract behavior and adds a
bounded Yul model plus an optional compiler overlay. BugForge remains the
policy and execution authority. Cursor remains the external planner. Selecting
a Cursor model name does not call Grok or xAI, and it does not add an API key.

Findings stay potential. A Yul pattern, a compiler layout, or a sandbox test
does not mark a finding verified and does not mark code safe.

## 1. Yul model

`app/parsing/solidity_yul.py` walks assembly blocks inside function text. It
records variables, assignments, loads, stores, calls, branches, returns, and
short traces. It is not an EVM interpreter and it does not evaluate arbitrary
arithmetic.

A slot is `known` only for a literal or for a constant whose single literal
value is unambiguous. `namespaced` is used for a string `keccak256("...")` or
an expression that mentions ERC-7201. `computed` is used for arithmetic and
for Yul helpers such as `add`. Anything else, including a duplicated constant
name, stays `unknown`. EIP-1967 implementation, admin, and beacon constants are
recognized only when the bytes are exactly those slots.

Local copies are direct. `let impl := sload(SLOT)` followed by
`delegatecall(gas(), impl, ...)` becomes one trace from the storage load to
the delegatecall target. A later `sstore` of that same loaded value keeps the
link. An unknown name is not guessed into a state variable.

`if`, `else`, and `switch` bodies are branch-dependent. A store or call inside
one of them is not treated as unconditional. A call inside a branch does not
make a later store in a different branch a definite write-after-call.

Hostile strings are structural evidence only:

- `sstore` into an implementation, admin, or beacon slot
- a computed storage write
- a dynamic `call`, `delegatecall`, `staticcall`, or `callcode` target
- `delegatecall` to `calldataload`, `caller`, or `origin`
- an ignored call success bit
- `returndatacopy` after an ignored success bit
- a storage write that follows an external control transfer in the same block

`sol.yul` reports those strings as potential observations. The benign
`sload`/`mstore` fixture does not match them, and `sol.assembly_sensitive`
is unchanged. A node or block limit sets `incomplete` and says the rest is
unknown. Incomplete is not safe.

Comments are stripped before the walk. Quoted strings are not scanned as
opcodes. A word inside a comment or a Solidity string is not a call.

## 2. Compiler integration

`solc` and `forge` are optional. This environment does not have `solc`,
`forge`, Slither, Echidna, Medusa, Halmos, or Wake installed. Tests inject
standard JSON or monkeypatch the compiler lookup. They do not require a host
compiler.

`interpret_standard_json` covers:

- malformed JSON
- a compiler error
- an object with none of the requested outputs
- an AST with no storage layout
- storage layout
- IR, including a truncated IR over 65,536 characters
- method identifiers

A missing compiler is `UNAVAILABLE` and invents no slots, types, selectors, or
IR. An invocation failure is `FAILED`. Forge without a standard-JSON runner
does not invent a layout. The flat storage list remains `{label, slot}`.
Richer layout rows carry contract, source, offset, and type beside it. Parser
slots are never replaced. Tree-sitter remains the syntax graph.

## 3. Parser/compiler reconciliation

`SemanticDisagreement` stores a category, contract, symbol, parser value,
compiler value, severity, and confidence. Categories are storage slot, offset,
type, source location, selector, and inherited layout. Confidence is
`unresolved`. The function records the pair and does not choose a winner.

A source-location comparison is skipped when one path is only a suffix of the
other. A selector is compared only when both sides produced one. A missing
selector is not filled in from the other side.

## 4. Proxy and storage interaction

The older `YulAccess` list is still produced. `StorageModel.yul_detail` adds
the Phase 34 model beside it. Proxy provenance for a direct `sload` of a known
slot is unchanged.

When a scan has compiler output, the layout is applied to the cached storage
model before rules run. If at least one variable was compared, none of those
comparisons disagree, and Yul loaded the EIP-1967 implementation slot, the
proxy notes say confidence can rise and the proxy is still not verified. An
empty compiler result does not count as agreement. A disagreement keeps both values.
DeFi uses a compiler storage type only when the parser type is empty or
`address`. `IERC20` can raise a transfer to the existing strong token class.
A non-token compiler type such as `uint256` stops the address-usage heuristic
from calling that variable an ERC-20. No compiler means that path is unused.

Language notes for checked arithmetic and `selfdestruct` come from an exact
compiler version, an exact `pragma solidity` version, or a single `^0.8.x`
pragma. A comment is not a version. A wide range such as `>=0.4.0 <0.9.0`
stays unknown. These notes do not replace the existing arithmetic rules.

## 5. Exploratory persistence

Phase 33 stores attempts in `research_exploratory_attempts`. Reconstruct
restores the session, the evidence graph, and those rows, then drops the
in-memory engine cache. Dedup, parent checks, replay, flaky history, and
dashboard counts read the restored rows. Host secrets, provider secrets, and
the process environment are not stored. Generated test code is kept as a
research artifact and redacted on the way into the database.

The runtime cache is bounded and is released when a session stops or is
reconstructed. The table remains.

## 6. Candidate identity

The candidate hash is a server-side SHA-256 of a JSON object. The fields are
commit, expected behavior, framework, hypothesis, language, oracle, profile,
project, session, snapshot, target file, target symbol, and test code.
A hash supplied by the model is overwritten. Different hypotheses, files,
oracles, or expected behavior produce different hashes.

## 7. Replay

Replay rebuilds the original target file, symbol, language, framework, test
code, expected behavior, oracle, hypothesis, project, session, snapshot,
commit, and profile. The target is not replaced with the project id. A
different snapshot or commit is a different execution target, and replay
returns no candidate.

## 8. Artifact security

The Docker output collector reads only regular files whose resolved path stays
inside the output directory. Symlinks are not followed, including a symlink to
`/etc/passwd` or a path outside the root. Names and relative paths longer than
128 characters are skipped. File bytes are capped. Docker isolation does not
excuse a host collector that follows a container-created symlink.

## 9. Python profile

The default image `python:3.12-slim` does not contain pytest. BugForge does
not pip-install requirements and does not enable the network to fetch them.
`security_agent_exploratory_pytest_ready` defaults to false.
`security_agent_exploratory_python_image` may name an operator-built offline
image that already contains pytest. Until that image is attested, the Python
profile is `UNAVAILABLE`, not a failing test. Unsupported languages are
`UNSUPPORTED`.

## 10. Foundry profile

BugForge builds the Foundry command. The model supplies test code, the target,
the hypothesis, the expected behavior, and the oracle. It cannot supply
`--root`, `--out`, `--cache-path`, a fork URL, or any other flag. The command
is `forge test --root /bugforge-repo --match-path {test} --offline` with the
output and cache paths under `/bugforge-output`. The validator rejects `vm.ffi`,
fork creation and selection, `vm.rpc`, `vm.env*` / `getEnv` / `setEnv`,
filesystem cheatcodes, `process`, and forge-config fork, ffi, or filesystem
permissions. The validator is one boundary. Docker with the network off and
the resource limits remain mandatory. This environment does not run forge.

## 11. Budget semantics

`exploratory_tests`, `exploratory_iterations`, and `exploratory_seconds` are
their own planned, reserved, consumed, and remaining buckets. Planning an
exploratory test does not increment the generic tool bucket. The model cannot
raise those caps.

## 12. Evidence semantics

An exploratory attempt links the hypothesis to the generated test with
`motivates`, and the test to the attempt with `executes`. A meaningful failure
can `support` the hypothesis. A pass can `contradicted_by` it. The execution
provenance is `sandbox_execution`. That value is not in the live verification
set. A sandbox failure is not `VERIFIED`. A sandbox pass is not `SAFE`.
`verified` on the attempt stays false. The model cannot mark a finding
verified, approve a report, submit it, change scope, or grant budget.

## 13. Known limitations

The Yul walk is a bounded scanner. It does not model memory, calldata layout,
full switch fall-through, or computed hashes. A state-variable name used as a
delegatecall target stays unknown unless it was loaded with `sload` in that
block. Duplicate constants are unknown rather than resolved. Nested assembly is
walked as part of the outer block; it is not a second interpreter.

Compiler IR is stored and truncated. It is not executed and it is not compared
instruction-by-instruction with the parser. There is no UUPS, beacon, or
diamond certificate. Storage comparison is still not the Solidity compiler.

Exploratory Python execution needs an operator image that already contains
pytest. Foundry execution needs Docker and a forge binary inside the sandbox.
Neither is installed here. Generated code is not run on the host. No generated
test enables the network. External analyzers that are not installed stay
unavailable, and BugForge does not invent their results.
