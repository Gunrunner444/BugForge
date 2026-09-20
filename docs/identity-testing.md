# Identity testing

Two-identity research uses isolated security contexts, not cookie-value
comparisons.

Each `ResearchIdentity` has:

- identity id
- credential reference (secret store id, never a raw token)
- browser-context id
- HTTP session/client context id
- storage namespace
- authentication state
- credential provenance

`IdentityPair.isolated()` is true when those context identifiers differ,
even if cookie or header *values* happen to be identical.

## Secrets

Raw cookies, `Authorization` headers, API tokens, session tokens, passwords,
and refresh tokens are **not** persisted in research-session database rows.

Database snapshots store:

- sanitized metadata (names, states, namespaces)
- secret reference IDs

Execution credentials live in the in-memory `SecretStore` (or the in-memory
identity object for the current process). Restore of headers **fails closed**
if a required secret reference is unavailable.

The identity workbench never displays raw credentials.

## Authorization oracle

A body/status difference is not a vulnerability. Comparisons produce a
structured `AuthorizationHypothesis` with:

- status / structure / resource / ownership / sensitive-field / permission differences
- expected authorization rule
- actual authorization result
- oracle (`OWNER_ONLY`, `ROLE_REQUIRED`, `TENANT_ISOLATION`,
  `AUTHENTICATED_USER_ONLY`, `PUBLIC_RESOURCE`, `CUSTOM_EXPECTATION`)

Dynamic fields (timestamps, request IDs, tracing headers, CSRF tokens,
random values) are normalized. `is_vulnerability` is always false until a
human and deterministic verification say otherwise.
