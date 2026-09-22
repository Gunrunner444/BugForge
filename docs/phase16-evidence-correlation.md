# Phase 16 — Evidence correlation

Phase 16 links static findings with tests, reproductions, and AI hypotheses
through the existing `SecurityFinding` and `Evidence` types. It does not add
a second evidence store. Correlation never calls `verify`.

Static analysis remains static evidence. AI text remains an AI hypothesis.
A test or reproduction can be attached when it names the same file, line, and
vulnerability class. That attachment does not change finding status.

If a test says the path was not reached (`contradicts` or `reached=false`),
the static observation stays. The explanation says the results disagree.

`explain_confidence` answers, from metadata that is already stored:

- which source reached which sink
- which semantic relationship, route, or field path was used
- which parser produced the graph
- whether the flow crossed files
- whether runtime evidence supports the location, contradicts it, or is absent
- whether the only extra evidence is AI text

Unrelated files and vulnerability classes are not merged. Identical evidence
is not stored twice. Evidence order does not depend on input order.

`correlate_finding` is a pure matching helper. Phase 21 wires it through
`FindingLifecycleService`, which loads a persisted finding, attaches only
matching evidence, and applies an explicit domain transition when asked.
Correlation still never calls `verify`. A public JSON body cannot mark a
finding verified.

`SecurityFinding.verify` is unchanged. AI-only evidence still cannot verify.
Human acceptance still requires a reproduced or verified finding.
