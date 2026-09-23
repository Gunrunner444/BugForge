# Phase 32 — Solidity proxy, storage, and upgradeability

Phase 32 adds a storage and upgradeability model on top of the Phase 30 CFG
and the Phase 31 initializer, modifier, and token work. It does not add
another language. Findings stay potential evidence. Nothing in this phase
marks a finding verified, confirmed, or exploited.

This is not compiler-equivalent storage layout, not EVM symbolic execution,
and not a certificate of UUPS, transparent-proxy, beacon, or diamond
compliance.

## Storage model

`analyze_storage` builds one layout per contract from state-variable
declaration order and a C3-style inheritance order. Each variable can carry:

- contract and the contract that declared it
- type, visibility, and mutability
- slot, offset, and packing group, when those are determined
- mapping key and value types
- struct member types taken from a same-file struct definition

Elementary values pack into a slot until 32 bytes are used. A struct, a
fixed array, a dynamic array, a mapping, `bytes`, and `string` start a new
slot, and the next variable starts a new slot after them. Constants and
immutables are recorded and do not take a storage slot.

The order is most-base-first. `contract Child is A, B` places `A`, then `B`,
then `Child`, including variables inherited through those bases. A base that
is missing, a base name that is defined more than once, or a C3 merge that
does not produce one order marks that contract uncertain. Uncertain variables
keep their names and types and have no slot. The analyzer does not invent one.

## Compiler overlay

`solc` and `forge` stay optional. `compiler_semantics` still reports
`UNAVAILABLE` when no compiler is installed, `FAILED` when the invocation or
the JSON fails, and `AVAILABLE` for a version-only result or a parsed layout.
The flat `storage` list is still label and slot. A `layouts` list adds the
contract name and, when the compiler JSON has them, offset and type.

`apply_compiler_layout` does not replace parser slots. A compiler entry matches
a parser variable only when the contract and the label agree. Source file is
used when both sides have one. A label that appears in more than one contract,
or a compiler entry with no contract, is ambiguous and is not matched. Slot,
offset, and source type are compared when the compiler provides them. A
disagreement is recorded and both layouts are kept. A missing compiler does
not become a layout. A scan calls `compiler_semantics_for_scan`: unavailable
stays unavailable, `forge` without a safe standard-JSON runner does not invent
slots, and `solc` is invoked only with `--standard-json` and a minimal
environment.

## Layout comparison

`compare_storage_layouts` compares any two storage models. It returns a
`StorageLayoutComparison` with the relationship, compatibility, confidence,
and typed changes: `added_before_existing`, `removed_existing`, `reordered`,
`type_changed`, `slot_changed`, `offset_changed`, `packing_changed`,
`inheritance_changed`, `mapping_changed`, `struct_changed`, or `unknown`.
Names are supporting evidence, not identity. A variable appended after the
existing layout can stay compatible. An uncertain layout stays unknown.
Namespaced slots are `StorageNamespace` values and are not compared as
sequential slot 0.

## Collisions

`sol.storage_collision` still reports a delegatecall whose target is a
mutable `implementation` or `impl` in normal storage when no compatible
layout comparison covers that file. An EIP-1967 constant elsewhere does not
remove that indicator.

A same-slot note is emitted only when the proxy and another contract have an
incompatible layout and the proxy contains a delegatecall. Two contracts that
share slot numbers with the same types, offsets, and order are not a
collision. A business field named `implementation` that is never the target
of a delegatecall is not a collision. An uncertain layout does not become an
overlap.

## Delegatecall

Each delegatecall is classified by its target:

- `address(this)` is self
- an `immutable` or `constant` state variable is fixed
- a storage variable is state-backed
- a function parameter is caller-controlled
- an assembly target is classified the same way when the argument is recoverable
- a Yul `let` that is a direct `sload` of a literal or constant slot is `storage_slot`
- anything else stays unknown

Unknown assembly is not treated as a vulnerable delegatecall. It remains
`sol.assembly_sensitive` when the opcode is one of the sensitive Yul
operations. A caller-controlled target and a mutable target that is not
written only by authorized upgrades stay `sol.arbitrary_delegatecall`. A
fixed target does not.

## Upgrade authorization

An upgrade is a public write of a delegatecall target, a write of a storage
variable named `implementation` or `impl`, an `sstore` of a known
implementation-slot constant, or a write of a beacon or selector map in a
contract that already delegatecalls. A function named `upgradeCounter` or
`upgradeUserRecord` is not an upgrade. The name is supporting evidence only.

The write is authorized only when a resolved modifier, or a check in the
function, dominates it. The modifier body has to be the Phase 31
authorization shape (`msg.sender` or `hasRole` before `_;`). A modifier that
is only `_;` does not count. An inherited modifier counts when exactly one
body is found. Two base bodies are ambiguous and do not suppress the finding.

## Proxy shapes and initializers

The model can label a contract `uups-like`, `fallback-proxy`,
`delegatecall-proxy`, `beacon-like`, `transparent-like`, or `diamond-like`.
UUPS-like requires `proxiableUUID` together with an implementation upgrade,
slot, or delegatecall. Beacon-like requires a beacon address whose
`implementation()` is read beside a delegatecall. Transparent-like requires
an admin sender check and a fallback delegatecall. Diamond-like requires a
`bytes4 => address` map that is both written and used for delegatecall.
The words beacon, admin, facet, and diamond are not enough. Those labels are
structural evidence with a confidence, not standard compliance, and they do
not mark the proxy secure. A newly appended variable that an initializer
does not write is noted as potentially uninitialized. `initialize` by itself
is still not protection.

Initializer protection is still the Phase 31 check: a prior state check that
dominates a real write before `_;`. An implementation with an unprotected
`initialize` or `reinitialize` stays `sol.initializer`. An upgrade that also
performs a call is noted as something that may run initialization in the new
context. That note is not a proof that the call is an initializer, and it
does not say the new storage was initialized.

## Yul storage

`sload`, `sstore`, and `delegatecall` inside an assembly block are linked
when the slot or target argument is a numeric literal or a constant whose
declaration is a literal. A constant equal to the EIP-1967 implementation
slot is reported as that slot. `sload(add(SLOT, 1))` and any other computed
expression stay unknown. The hash of a namespaced string is not evaluated.

## Cache

Storage layouts and proxy models are cached for the graphs in one scan and
cleared when the scan finishes. The cache is a context variable, not a
process-wide map. One repository scan cannot leave layouts behind for the
next scan.

## Known limitations

- Parser slots follow the packing rules implemented here. They are not a
  substitute for `solc --storage-layout`.
- Structs are packed only when every member is an elementary value known from
  a same-file definition. Nested structs, enums, and user-defined value types
  inside storage leave the contract uncertain.
- Imported bases are used only when the scan contains exactly one contract of
  that name. A missing file leaves the child uncertain.
- Assembly targets are recovered from the argument text. A target held in a
  Yul local that was loaded earlier is unknown unless that local's name is
  itself a state variable or parameter.
- Diamond and beacon recognition is lexical and structural. It does not
  resolve facet selectors or beacon storage.
- Upgrade authorization does not understand a timelock or a multisig beyond
  a `msg.sender` or `hasRole` check that dominates the write.
- Cross-contract delegatecall into an implementation defined in another
  repository is not executed. Overlap is reported only for contracts visible
  in the scanned graphs.
