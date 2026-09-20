# Agent safety

BugForge safety controls are authoritative. Model output cannot override them.

## Scope

Only deterministic scope logic may decide `AUTHORIZED` or `BLOCKED`. Hidden
scope rules are not placed in prompts.

## Safety controller

Request limits, concurrency, tool restrictions, active-testing state, program
restrictions, and human approvals cannot be waived by the model. Unsafe
requests return a structured rejection and are not reinterpreted.

## Prompt injection

Web pages, HTML, JavaScript, comments, API responses, scanner output,
HackerOne instructions, and repository content are untrusted. They are wrapped
and instruction-like lines are stripped. Target content cannot issue agent
instructions.

## Loop protection

Deduplication, retry limits, cycle detection, session budgets, and a maximum
reasoning iteration count prevent infinite loops, repeated identical scans,
and exploding context.

## Verification and reporting

AI confidence is not verification. The report writer may summarize verified
evidence and suggest a weakness mapping. It must not invent evidence, upgrade
confidence to verification, choose scope, fabricate reproduction, approve a
report, or submit to HackerOne.

## Observability

The research timeline records time, decision, tool, target, authorization,
result, evidence, and finding identifiers. Credentials never appear.
