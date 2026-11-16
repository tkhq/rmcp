# Design: server-side OAuth resource-server layer (`server-auth`)

Status: draft for discussion with the maintainers. Not proposed as a PR yet.

## Problem

rmcp has a full OAuth client (`auth` feature), but an HTTP MCP server that
must act as an OAuth resource server has to write its own middleware. The
examples (`simple_auth_streamhttp`, `complex_auth_streamhttp`) check a static
token and answer a bare 401. That answer has no `WWW-Authenticate` challenge,
so MCP clients cannot start discovery. Every server re-implements bearer
extraction, RFC 9728 metadata, challenges, and audience checks, and each
implementation differs in small ways.

## What this adds

Two cargo features, both off by default:

| Feature | Adds | New dependencies |
| --- | --- | --- |
| `server-auth` | `transport::server_auth`: `TokenValidator`, `AuthenticatedPrincipal`, `AuthError`, `ResourceServerLayer`, `ProtectedResourceMetadata`, `ProtectedResourceMetadataService`, `canonical_resource`, `constant_time_eq` | `tower-layer` (0.3, no dependencies). The others (`http`, `http-body`, `http-body-util`, `bytes`, `url`, `async-trait`) are already optional dependencies. |
| `server-auth-introspection` | `server_auth::introspection::IntrospectionValidator` (RFC 7662) | None. It uses the existing optional `reqwest`, `base64`, and `zeroize`. |

`server-auth` turns on `server`, because `transport` only exists with
`client` or `server`.

There is one example, `servers_resource_server_auth_streamhttp`. It uses an
in-memory validator and a `whoami` tool that reads the principal.

### Request flow

`ResourceServerLayer` wraps any tower service, including
`StreamableHttpService`. For each request it:

1. Reads the one `Authorization` header. It never reads the query string.
   Two or more `Authorization` fields get 401 `invalid_token`.
2. Matches the scheme case-insensitively against `TokenValidator::schemes()`
   (default `Bearer`). An unknown scheme counts as no credential.
3. Calls `TokenValidator::validate` with the request parts, the credential,
   the public request URL (base URL plus path, no query), and the time.
4. Checks that one of the principal's audiences is this resource. Both sides
   go through `canonical_resource`: lowercase scheme and host, no default
   port, no query or fragment, no trailing `/`.
5. Checks `expires_at`, with a configurable leeway (default zero).
6. Refuses a principal with a `cnf` confirmation that the validator did not
   mark as verified, so a key-bound token is never accepted as a plain bearer
   token.
7. Checks the required scopes, and answers 403 `insufficient_scope` when one
   is missing.
8. Inserts `AuthenticatedPrincipal` into the request extensions. rmcp already
   copies `http::request::Parts` into the MCP request context, so tools read
   it from `parts.extensions`.

Refusals:

- 401 with no `error` code when there is no credential (RFC 6750 section 3.1).
- 401 `invalid_token`, or a validator-defined code such as
  `invalid_dpop_proof` or `use_dpop_nonce`.
- 403 `insufficient_scope`.
- 503 or 500 when the validator reports an outage or a failure. These get no
  challenge, and the reason is only logged.

Every 4xx challenge has `resource_metadata`. It also has `scope` when the
layer requires scopes, plus any parameters the validator adds (for example
`algs` for DPoP). When the request used no known scheme, the response has one
challenge per accepted scheme (RFC 9449 section 7.1). Parameter values are
quoted, and characters that a header cannot hold become `?`. 4xx responses
with an error code have the JSON body `{"error", "error_description"}`.

### Validator hooks

`TokenValidator` has one required method, `validate`. Optional hooks let a
validator take part in the HTTP exchange without owning the middleware:

- `schemes()`: for example `["Bearer", "DPoP"]`.
- `challenge_params(scheme)`: extra auth-params.
- `on_challenge(status, headers, now)`: for example a fresh `DPoP-Nonce` on
  every 401.
- `on_response(principal, headers, now)`: for example the current
  `DPoP-Nonce` on success.

`AuthError::with_header` adds headers to one refusal.

### Introspection validator

`IntrospectionValidator`:

- Client authentication: `client_secret_basic` (with RFC 6749 section 2.3.1
  form-encoding), `client_secret_post`, or a bearer token. Secrets are held
  in `Zeroizing`, sent as sensitive header values, and redacted from `Debug`.
- Request timeout (default 5 s) and response body limit (default 64 KiB,
  enforced while streaming).
- Two bounded caches keyed by the SHA-256 of the token: active answers
  (default TTL 60 s, never past `exp`) and inactive answers (default 5 s).
  The caches are separate, so a flood of bad tokens cannot evict good ones.
  Each holds at most 10,000 entries and drops the oldest insertion first.
  Outages are never cached.
- `active: true` with an expired `exp`, a future `nbf`, or a malformed member
  counts as inactive. An answer without a boolean `active` is an outage.
- A token with `cnf` is refused unless the caller calls
  `allow_confirmed_tokens()`. Even then the confirmation is unverified, so the
  layer refuses it unless a wrapping validator checks the proof.

Constant-time comparison: the library never compares a presented secret with
a stored one. Cache lookups use a hash of the token. `constant_time_eq` is
exported for validators that do compare secrets, and the example uses it.

## What is generic, and what stays in user code

In rmcp (generic):

- Credential extraction from the header, scheme matching, and malformed
  credential checks.
- RFC 9728 metadata: the document, the well-known path and URL, and a service
  that serves it with CORS.
- The challenges and error responses.
- Audience, expiry, confirmation, and scope checks on the principal.
- Putting the principal in the request extensions.
- Opaque-token validation by RFC 7662 introspection.

In user code (format- or deployment-specific):

- Token formats and signature checks (JWT profiles, issuer pinning, JWKS).
- Proof-of-possession checks (DPoP proof verification, nonce and replay
  stores, mTLS).
- Mapping a principal to application state, such as tenants or signing keys.
- Binding MCP sessions to principals.
- Per-tool authorization beyond scopes.
- The authorization server itself.

## Specification references

- MCP authorization (2025-11-25 and draft), "Authorization Server
  Discovery": protected resource metadata, and `WWW-Authenticate` with
  `resource_metadata` on 401.
- MCP authorization, "Scope Selection Strategy" and "Scope Challenge
  Handling": `scope` in the challenge, 403 `insufficient_scope`.
- MCP authorization, "Access Token Usage" (header only, never in the URI
  query) and "Token Audience Binding and Validation".
- MCP security best practices, "Token Passthrough" (validate the audience).
- RFC 9728: section 2 (metadata members), section 3 and 3.1 (well-known path
  insertion), section 5.1 (`resource_metadata` challenge parameter).
- RFC 6750: section 2.1 (header method), section 3 and 3.1 (challenges and
  error codes).
- RFC 8707: resource indicators, compared as canonical URIs.
- RFC 7662: section 2.1 (request and client authentication), section 2.2
  (response), section 4 (caching and security considerations).
- RFC 9449: section 5.2 (metadata), section 7.1 (challenges and `algs`),
  section 8 (nonces). These are only hooks here; DPoP checks stay in the
  validator.
- RFC 7800: `cnf`.

## Open questions for the maintainers

1. Naming: the `server-auth` feature, the `transport::server_auth` module, and
   `server_auth::AuthError`, which has the same name as the client-side
   `transport::AuthError`. Should it be `ResourceAuthError` or similar?
2. `async-trait` or return-position `impl Future` for `TokenValidator`. This
   draft uses `async-trait` (as the session store does) so that
   `Arc<dyn TokenValidator>` works.
3. Missing credentials: follow RFC 6750 (no `error`), or match the TypeScript
   SDK (`invalid_token`)? Duplicate `Authorization` headers: 401
   `invalid_token` (this draft) or 400 `invalid_request`?
4. Audience: the layer requires an audience that matches. Some
   introspection endpoints leave out `aud`. Should there be an opt-out for
   validators that check the audience themselves?
5. Session binding: the streamable HTTP session managers do not bind
   `Mcp-Session-Id` to a principal (MCP security best practices, "Session
   Hijacking"). Should `StreamableHttpService` record the principal's
   subject on the first request and refuse a different principal later? That
   needs a small hook in the session layer.
6. Typed principal data: should a validator be able to add its own typed
   extensions (for example a verified JWT struct), through an
   `http::Extensions` field on the principal or a hook?
7. Per-tool scopes and step-up: a tool cannot answer HTTP 403 today. Should
   rmcp give tools a way to raise `insufficient_scope` that the transport
   turns into a 403 challenge?
8. Introspection: add single-flight for concurrent requests with the same
   token? Should the default active TTL be shorter, since it delays
   revocation?
9. Should rmcp also ship a JWT validator on the existing optional
   `jsonwebtoken` dependency, or leave token formats to other crates?
10. Should the conformance suite's server `auth/*` scenarios run against the
    example in CI?
