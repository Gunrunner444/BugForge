# Phase 18 — Finding intelligence

Phase 18 makes static findings easier to read without raising their status.

Findings from the security engine now carry:

- `finding_key`, a SHA-256 prefix of the vulnerability class, file, scope, sink, field path, argument, source family, and sink text
- `related_group`, a coarser key of class, sink, field, and source family
- `flow_summary`, built only from recorded source, field, relationship, helper, and sink metadata
- `flow_source`, `flow_sink`, `field_path`, and `files_crossed`
- `parser_completeness` and `analysis_incomplete`
- `evidence_summary`, which states that the result is static and not verified

`finding_key` does not include the line number or a parser byte offset. Inserting blank lines above a sink keeps the key. Two different sink texts, fields, or callee sinks stay separate findings. Two observations of the same sink text, source, and occurrence still collapse into one finding. Distinct identical call sites stay separate by `sink_occurrence`, the ordinal of the same callee and argument structure in that scope. A harmless `eval("constant")` does not change the key of a later tainted `eval(...)`. Inserting another identical finding before existing ones does shift later ordinals. Distinct vulnerabilities are not merged just because they share a file.

The dedicated `security_findings.finding_key` column is authoritative. A NULL column is not reconstructed from `intelligence_json`. The API adds these fields on `SecurityFindingResponse`. Older fields stay. A later scan of the same project reuses that row. `CORROBORATED`, `VERIFIED`, `HUMAN_ACCEPTED`, `REPRODUCED`, and `REJECTED` status, human review state, and verification evidence survive a rescan; only static location and flow fields are refreshed. `analysis_id` is the latest scan that observed the row.

The findings panel shows the flow, field, files, parser completeness, incomplete analysis, evidence summary, and confidence. Potential and corroborated results are labeled “Not verified”. A verified badge is shown only when the stored status is verified.

## Limits

The explanation does not invent alias, re-export, or helper steps. Those words appear only when the observation metadata recorded them. Profile fallback is described as not being dataflow. A partial callee is described as partial.

Static analysis still cannot mark a finding `VERIFIED`. AI text still cannot mark a finding `VERIFIED`.
