# Phase 15 — Framework-aware analysis

Phase 15 adds declarative framework facts to the existing syntax graph and
taint engine. It does not import frameworks, execute decorators, or start a
second dataflow engine. Static observations remain `POTENTIAL` or
`CORROBORATED`. They are never `VERIFIED`.

## Sources

Existing attribute sources stay in place: `request.args`, `request.GET`,
`req.query`, `req.body`, and `req.params`. A variable that is merely named
`request` is not a source.

A path parameter is a source only when a decorator declares it:

```python
@app.get("/item/{id}")
def item(id: str):
    eval(id)
```

`@app.route("/item/<int:id>", methods=["GET"])` is the same idea. The path
must be a string literal starting with `/`. `@cache.get("user")` is not a
route. A function with the same signature and no decorator is not a route.
The decorator is not called.

JavaScript and TypeScript record `app.get("/search", handler)` as route
metadata. A bare `get("/search", handler)` is not a route. Callback
parameters are not inferred from the path, so `function (id) { eval(id) }`
stays unresolved even when it is passed to `app.get`.

## Sinks

New or tightened call identities:

| Call | Result |
|---|---|
| `cursor.execute("... %s", params)` | parameterized, not injection |
| `cursor.execute("..." + user)` | SQL injection |
| `session.execute(text("... :id"), params)` | parameterized |
| `session.execute(text("SELECT " + user))` | SQL injection |
| `User.objects.filter(...)` | not a SQL sink |
| `User.objects.raw(user)` and `User.objects.extra(user)` | SQL injection |
| `render_template("page.html", ...)` | not a sink |
| `render_template_string(user)` | dynamic execution |
| `mark_safe(html.escape(user))` | HTML sanitizer clears XSS only |
| `redirect(url_has_allowed_host_and_scheme(user))` | redirect sanitizer |
| `mystery.render(user)` | unknown |

`text()` is transparent only while checking SQL sinks. It does not preserve
taint into `eval` or other vulnerability classes. Query-builder methods such
as `filter` are not treated as injection because the name is not enough.

## Metadata

Findings inside a decorated handler include additive fields `route`,
`route_method`, and `endpoint`. JavaScript route calls are stored on the
graph and are not copied onto every other function in the file.

## Limits

- Keyword arguments are still not separate taint slots; tests use positional
  arguments.
- Express path parameters are not mapped onto anonymous callback arguments.
- `methods=` is recorded only when every entry is a string literal. Otherwise
  the method is `ROUTE`.
- Unknown frameworks stay unknown.
- Partial parses still do not become complete summaries.
