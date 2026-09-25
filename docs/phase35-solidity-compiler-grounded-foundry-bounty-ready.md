# Phase 35 — Compiler-grounded Solidity analysis and Foundry lab readiness

Phase 35 makes the existing Solidity path consistent enough to try on an
explicitly authorized source tree. It does not add a live bounty client, a
model provider, or a new vulnerability class.

## What Phase 34 got wrong

The scan rewrote `file_path` to a repository-relative display path and then
opened that relative path from the process working directory. A missing file
became `source=""`, which could look like a compiler run. Compiler input was
one synthetic file named `BugForge.sol`, so imports and repeated contract
names were not project identities. Version checks used the first version-shaped
substring, so a range that includes 0.7 and 0.8 could be labeled from the
lowest number. Selectors were keyed by function name, so overloads collapsed.
Yul treated “the success name appears later in the text” as a check. Every
cross-contract observation was labeled reentrancy. Foundry was invoked with
`--root /bugforge-repo` while the generated test lived under the output mount,
so the test was not inside the project. Replay persisted redacted test text.
The generic identical-tool guard could reject an exploratory retry before the
exploratory engine classified it.

## Project compiler model

`CompilerProjectModel` is the scan-scoped compiler picture. It records status,
tool, version, source-bundle identity, configuration identity, diagnostics,
contracts, source paths, storage, selectors, AST availability, IR availability,
IR text, IR truncation, language facts, completeness, and unsupported
configuration. The bundle is the `.sol` files already being analyzed, plus
other `.sol` files under the repository up to a file and byte limit. Paths are
resolved with the repository root. A path that escapes the root, or a symlink
that leaves it, is rejected and is not read. Embedded parser bytes are used
only after that check. An empty or unreadable source is a diagnostic, not a
successful compile of `""`.

`remappings.txt` is read only as static `prefix=path` lines. `foundry.toml`
and Hardhat configuration are not executed. A `lib/` directory is recorded as
unsupported package resolution. The default research path does not run host
`solc`. `solidity_host_compiler` is an explicit developer switch and is false
by default. When it is false, or when no compiler exists, status is
`UNAVAILABLE` and no storage, selector, or IR fact is invented. A compiler
failure is `FAILED` with a bounded diagnostic. An incomplete bundle is
`INCOMPLETE` and is not applied as proof.

The model is installed for the scan and cleared in `finally`. A later scan
gets a new cache. The cache key is the source bundle, remappings, and compiler
identity.

The default caps stay 40 files, 200,000 bytes, 48 contracts, and 240 call
edges. Optional settings can raise those caps without making them unlimited.
When dependency inclusion is enabled, the bundle is the analyzed sources plus
their import closure, and files past the cap are omitted and keep the model
`INCOMPLETE`. Exact `pragma solidity =x.y.z` files are compiled with that
`solc`. A dynamic `calldataload` whose argument is not a numeric literal, and
whose block does not contain `calldatasize`, is reported as potential Yul
structure. A literal offset such as `calldataload(0)` is not that pattern.

## Version, selectors, storage, and Yul

`solidity_language_facts` is the only version interpreter. A property is known
only when every pragma-allowed version has it. `^0.8.20` is checked arithmetic.
`^0.7.5` wraps. `>=0.7.0 <0.9.0` and `0.8.20 || 0.7.0` stay unknown. Comments
and strings are not pragmas. An exact compiler version is used only when the
source has no pragma; a disagreement stays unknown.

Selectors are keyed by canonical signature (`transfer(address,uint256)`).
Overloads both survive. A type that cannot be canonicalized does not get a
guessed selector. Compiler and parser selectors are compared by that signature.

Storage matching requires the contract, the variable, and, when the compiler
names a file, the normalized source path. `owner` in `src/a/C.sol` is not
`owner` in `src/b/C.sol`. Parser slots are not replaced.

The Yul walker is still not an EVM interpreter. It is the supplementary model
when compiler IR is absent. When IR is present, the model records
`available` or `truncated` and does not execute the IR. Call success is a
binding: the variable, the call that produced it, an `if`/`switch` condition
that reads it, reassignment, and shadowing. A use in another branch, a string,
or a comment is not a check. `ignored call success` is reported only when that
binding is never checked in its scope.

## Foundry workspace and replay

The server writes a disposable project under the sandbox output mount. The
source repository stays read-only. The generated test is
`project/test/Exploratory.t.sol` inside `--root /bugforge-output/project`.
The command is fixed: `forge test`, `--match-path test/Exploratory.t.sol`,
`--offline`, and server output and cache paths. The model cannot supply a
command, root, fork URL, RPC, environment, or other flags. Docker network
stays disabled.

Classifications distinguish a passing test, an assertion failure, a compiler
failure (`COMPILATION_FAILED`), a timeout, a sandbox error, an invalid test,
a blocked cheatcode, and a missing tool (`UNAVAILABLE`). A compiler failure
is not a product bug and cannot support a hypothesis. A missing `forge` or
`solc` is skipped in optional integration tests with the executable name in
the skip reason. It is not reported as a pass.

Replay stores the exact test only when redaction would not change a byte.
Otherwise `replayable` is false, the stored test is empty, the original hash
is kept, and replay returns nothing. The candidate hash is recomputed by the
server and includes the session, project, hypothesis, commit, snapshot,
target, language, framework, profile, test hash, expected behavior, and oracle.
Toolchain fields on the evidence node are the profile, timeout, memory, CPU,
network state, and the configured sandbox image name when the executor has
one. Foundry and compiler versions stay empty until that toolchain reports
them. Secrets and the process environment are not stored.

The generic identical-call guard does not consume `exploratory_test`. The
exploratory engine still rejects accidental duplicates, bounds follow-ups, and
enforces its own budget. Deliberate replay, confirmation, and negative-control
follow-ups remain engine decisions.

## Scope

`TargetManifest` is fail closed. Live Solidity testing requires an explicit
smart-contract asset, an allowed live mode, operator approval, and active
testing permission. A company name, a public URL, or a web/API asset does not
grant that permission. Phase 35 does not turn live testing on and does not
submit anywhere.

## Limits

This phase does not prove a vulnerability. Compiler output, Yul structure, and
a sandbox result stay potential evidence. There is no EVM interpreter. Dynamic
package resolution is unsupported. Host `solc` is off unless an operator sets
`solidity_host_compiler`. Foundry runs only when `forge` exists in the
sandbox image; otherwise the attempt is `UNAVAILABLE`.
