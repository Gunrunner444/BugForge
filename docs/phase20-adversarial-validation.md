# Phase 20 — Adversarial validation

Phase 20 stresses the existing semantic engine. It does not add another
taint engine or mark static results verified.

The tests cover:

- comments and strings that mention a sink
- dynamic dict keys and `getattr` calls
- field reassignment before a use
- an import cycle that must finish
- removing an import, renaming a callee, and replacing a sink
- zero and one-step limits, and rejected negative settings
- repeated scans with the same finding key
- a malformed `tsconfig.json`
- AI-only and static-only findings, which still cannot call `verify`
- analysis identity that does not include secrets

A bare builtin sink is hidden only when a definition of that name reaches the
call. `eval(...)` before `def eval` is still the builtin. `def eval(value):
return value` followed by `eval(...)` is not a dynamic-execution finding, and
neither is `eval = keep` followed by `eval(...)`. If that function calls
`exec`, the finding stays on `exec`. A qualified call such as `obj.eval` is
unchanged. A nested function hides the builtin only inside its enclosing
scope.

Static findings remain `POTENTIAL` or `CORROBORATED`.
