# Scope Model

Closed scope is the safe default. Unknown targets are denied.

Matching is **not** naive substring search: `evil-example.com` does not
match `example.com`.

## Normalized target

`TargetNormalizer` produces:

- scheme, hostname (lowercase, trailing-dot stripped, IDN/punycode)
- default ports (http 80, https 443)
- path, URL, query
- IP or CIDR when appropriate
- asset type and optional program/project association

## Rule types

A `ProgramScope` contains structured include and exclude `ScopeRule`s:

- exact domain
- wildcard domain (`*.example.com` matches subdomains and the apex, not
  `evil-example.com`)
- URL + path prefix (segment-aware: `/api` does not match `/apiary`)
- IP and CIDR
- HTTP method restrictions
- asset-specific instructions and testing restrictions
  (`passive_only`, `no_automated_scanning`, `no_destructive`)
- exclusions (host, URL, or path)

HackerOne-oriented fields are imported by Phase 4 (`HackerOneScopeProvider`
+ `HackerOneScopeEvaluator`). AI never decides HackerOne scope.

Path comparison uses canonicalization (dot segments, duplicate slashes,
bounded percent-decoding including encoded slashes). Exclusions go through
the same `TargetNormalizer` as includes.

Closed HackerOne programs deny unknown assets. Open programs still do not
auto-authorize unknown assets.

## Authorization decision

Every check returns:

- allowed / denied
- reason
- matched scope rule
- program
- target
- method
- tool
- dry-run and approval state

Defaults:

- **No include rules → deny**
- **No active-testing permission → deny**
- **Unknown target → deny**
- Exclusions win over includes

## Local lab

Lab mode additionally requires a loopback or configured lab host. Live
mode refuses a lab-mode scope document.
