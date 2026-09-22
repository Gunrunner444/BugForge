# Phase 26 — Polyglot security coverage and semantic precision

Phase 26 finishes the Phase 25 target-binding gaps and expands security
fixtures for languages other than Python. The coverage matrix in
`backend/app/security/coverage.py` is the source of truth. A cell is `tested`
only when a dedicated security fixture asserts it.

AI remains non-authoritative. It cannot corroborate, reproduce, verify, or
accept a finding.

## Target binding

Runtime corroboration requires the finding id, finding key, project id, and
`observed_target` of the **current** semantic target. The observation's own
target is not the expected value.

Static and source observations created by analysis are stamped with that
target. A later material change leaves the stamp behind. The old record stays
in evidence and does not corroborate the new target. Legacy static evidence
with no stamp still counts; new analysis does not emit that shape.

Reproduction is a separate trust class from verification. A successful record
establishes `REPRODUCED` only when `observed_target` is the current target.
`reproduce()` stamps new successful records. Historical records keep their
original target. An empty stamp does not match. `HUMAN_ACCEPTED` uses the
same reproduction rule, or a trusted verification observation.

Research promotion copies the session `project_id` onto the finding before
`issue_for_finding()`.

## Command arguments

`CallArgument.keyword` is part of the language-neutral call. Keyword
arguments use index `-1` and do not shift positional indexes. Python records
`ast.Call.keywords`. Tree-sitter records keyword, named, and argument nodes.

`shell=True` disables argv suppression. A fixed non-shell program name does
not become shell injection because a later argument is tainted. An
attacker-controlled program, a shell wrapper (`sh`, `bash`, and the other
names in the shell set), and `shell=True` stay findings when taint reaches
the call. This is not a whole-file substring search.

## Framework names

A local binding hides a name only when that name was imported. `req.query`
stays a source when `req` is a parameter. `from fastapi import Query` is a
source. A nested `def Query` or an assignment `Query = ...` hides it in that
function. `import fastapi as fa` binds `fa.Query`. Rebinding `fa` hides it.
`notfastapi` and `from app.local import Query` are not inferred. A framework
manifest does not turn an unbound bare name into a source.

NestJS `@Query()` on a parameter is a source when the import is `@nestjs`
and the decorator is the previous parameter-list sibling, including the
JavaScript grammar's recovered error node. A later `function` declaration
does not hide an earlier bare call; JavaScript hoisting is not modeled.

## Secrets and crypto

Evidence text redacts PEM blocks, assignment values, quoted dictionary keys,
connection strings, bearer tokens, and AWS-style key ids on the same line as
the marker. Weak crypto matches a callee name or a parsed literal. `not-md5`
is one token. `AES/ECB/PKCS5Padding` matches the `ECB` segment. A variable
algorithm name is not resolved.

## What the priority languages actually flag

The Phase 26 corpus requires source, then a tainted value, then the relevant
sink argument.

| Language | Covered by fixtures | Explicit gaps |
|---|---|---|
| JavaScript / TypeScript | SQL, shell vs argv commands, path, fetch/axios/http, innerHTML, eval/Function, redirect, JSON.parse as an indicator, secrets | `textContent` is not XSS. Parameterized SQL is not a finding. A local `function query` hides a bare `query()` call. `db.query` still matches. |
| Go | database/sql, `exec.Command` program vs argv, path, `http.Get` / `NewRequest`, `template.HTML`, `http.Redirect`, `json.Unmarshal` as an indicator, secrets | `w.Write` is not XSS. Dynamic execution is unsupported. |
| Java | JDBC execution, `Runtime.exec` and `ProcessBuilder`, `File`, `URL`, `sendRedirect`, `ScriptEngine.eval`, `ObjectInputStream` when its argument is tainted, secrets | `print` is not XSS (`xss` stays `limited`). `readObject()` with an untainted stream is not a finding. |
| Kotlin | request parameters to SQL, exec, `File`, `URL`, `respondRedirect`, `respondText`, secrets | Dynamic execution is unsupported. Untyped deserialization is `limited`. |
| PHP | mysqli/PDO raw query, `system`, `include`, `file_get_contents`, `unserialize`, `eval`, `header`, `echo` only when the file looks like HTML, secrets | `curl_setopt` is not tied to `curl_exec`. Plain PHP `echo` is not XSS. |
| C# | `ExecuteReader`, `FromSqlRaw`, `Process.Start`, `File.ReadAllText`, `GetAsync`, `Html.Raw`, `Redirect`, secrets | `BinaryFormatter.Deserialize` on a local receiver is not tied to the constructor. Dynamic compilation is unsupported. |
| Ruby | `execute` / string `where` / `find_by_sql`, `system`, `File.read`, `Net::HTTP.get`, `html_safe`, `Marshal.load`, `YAML.load`, `eval`, `redirect_to`, secrets | `where(name: value)` is not raw SQL. `system('git', user)` is argv. `send` is not code execution. |
| Rust | `sqlx::query`, `Command::new`, `File::open`, `reqwest::get`, `Html::from_string_unchecked`, `serde_json::from_str` as an indicator, `bincode::deserialize`, `Redirect::to`, secrets | `client.get` is not assumed to be reqwest. `Html::new` is not XSS. Dynamic execution is unsupported. |

Unknown wrappers do not propagate taint. Ambiguous callees are not resolved.
Profile fallback is not full AST. Sink occurrence still changes when an
identical call is inserted earlier in the same scope. Anyone who can use the
server secret can issue observations in process. The HTTP API does not accept
an evidence body.
