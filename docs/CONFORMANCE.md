# Conformance testing

ShieldGate is checked against the OAuth 2.0 and OpenID Connect specifications
in two ways:

1. **Black-box conformance tests** in this repository (`tests/conformance`),
   which run in a minute against a real server and database.
2. **The OpenID Foundation conformance suite**, the suite used for OpenID
   certification, run locally in Docker (`scripts/conformance/oidf`).

Both use the same test data, created by `tests/conformance/seed` (one tenant,
two users, four clients; fixed credentials, for test databases only; see
`tests/conformance/fixture`).

## 1. Black-box conformance tests

```bash
make conformance          # or: scripts/conformance/run.sh [-run TestRefresh -v]
```

The script starts a throwaway PostgreSQL container, builds and starts the
server with a fresh RS256 key (`scripts/conformance/serve.sh`), seeds it and
runs `go test -tags conformance ./tests/conformance/`. To run against a server
you started yourself:

```bash
DATABASE_URL=postgres://... scripts/conformance/serve.sh
SHIELDGATE_CONFORMANCE_URL=http://127.0.0.1:18100 go test -tags conformance ./tests/conformance/
```

The tests act as a browser and a relying party over HTTP only. Each test names
the section it checks:

| Area | What is checked |
|---|---|
| Discovery, JWKS | Required metadata, issuer equals the discovery URL, RS256, PKCE `S256` only, RFC 9207 flag; JWKS has `kid`s and no private key members |
| Authorization endpoint | Unknown client / unregistered `redirect_uri` are never redirected (open redirector); other errors return to the client with `state` and `iss`; PKCE required for public clients; `prompt` (`none`, `login`, `consent`), `max_age`; form POST (OIDC Core §3.1.2.1); request objects rejected as unsupported; login CSRF; consent denial |
| Code flow | Token response (`no-store`, `Bearer`, `expires_in`); the ID token verified as an RP must (OIDC Core §3.1.3.7: signature via JWKS, `iss`, `aud`, `exp`, `iat`, `nonce`, `at_hash`, `auth_time`); both `client_secret_basic` and `client_secret_post` |
| Codes | Single use; replay revokes the tokens issued for the code; bound to client and `redirect_uri`; PKCE verifier checked |
| Token endpoint errors | `invalid_client` with `WWW-Authenticate`, `unsupported_grant_type`, `unauthorized_client`, `invalid_grant`, `invalid_scope` |
| UserInfo | `sub` matches the ID token, claims follow the granted scopes, RFC 6750 bearer challenges |
| Refresh | Rotation, scope narrowing (not widening), `sub`/`auth_time` kept, no `nonce`; replay revokes the whole grant; **concurrent replay cannot fork the grant** |
| Revocation, introspection | RFC 7009 (grant revoked with its refresh token, other clients' tokens untouched, client auth required); RFC 7662 (public `client_id`, inactive responses reveal nothing) |
| Logout | RP-Initiated Logout with `id_token_hint`, registered `post_logout_redirect_uri` only, confirmation without a hint |

## 2. OpenID Foundation conformance suite

```bash
make conformance-oidf     # or: scripts/conformance/oidf/run.sh
```

The script starts the suite (version 5.3.3, pinned by digest in
`scripts/conformance/oidf/compose.yml`), a throwaway PostgreSQL and a seeded
ShieldGate, then runs a test plan through the suite's REST API with
`run_plan.py`. The suite reaches ShieldGate as `https://shieldgate.test`, a
Caddy TLS proxy inside the suite's network, because OIDC Discovery requires
https endpoints. The suite's headless browser logs in and approves consent
using the `browser` section of `oidcc-basic.json`.

Choose another plan with `PLAN=... VARIANT='{...}'`; keep the suite running
to read the detailed logs with `KEEP_SUITE=1`, then open
https://localhost.emobix.co.uk:8443 (a public DNS name for 127.0.0.1).

### Results (2026-10-26, ShieldGate at this commit)

| Plan | Variant | Result |
|---|---|---|
| `oidcc-config-certification-test-plan` | — | 1 PASSED |
| `oidcc-basic-certification-test-plan` | discovery, static client, `client_secret_basic` | **0 FAILED**: 21 PASSED, 7 WARNING, 4 REVIEW, 3 SKIPPED |
| `oidcc-rp-initiated-logout-certification-test-plan` | discovery, static client | **0 FAILED**: 3 PASSED, 8 REVIEW |

**REVIEW** modules passed every automated check and wait only for a person to
look at a captured page: `oidcc-prompt-login` and `oidcc-max-age-1` (the
second login page), `oidcc-ensure-registered-redirect-uri` and
`oidcc-ensure-request-object-with-redirect-uri` (the "invalid redirect URI"
error page, which ShieldGate shows instead of redirecting). The suite's
browser captures these pages automatically.

The logout REVIEW modules capture the page ShieldGate shows instead of
redirecting: "post_logout_redirect_uri is not registered" (unregistered URI,
or one with `?foo=bar` added), "Invalid id_token_hint" (signed by someone
else, or changed to `alg: none`), "requires client_id or id_token_hint"
(redirect URI without a hint), and "You have signed out" (no parameters,
only `state`, or no redirect URI; without a hint the user confirms first).
The logout plan uses `oidcc-rp-initiated-logout.json`:

```bash
PLAN=oidcc-rp-initiated-logout-certification-test-plan \
VARIANT='{"client_registration":"static_client","response_type":"code"}' \
CONFIG=scripts/conformance/oidf/oidcc-rp-initiated-logout.json \
scripts/conformance/oidf/run.sh
```

**SKIPPED**: `oidcc-scope-address` and `oidcc-scope-all` (ShieldGate has no
address claim), and `oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported`,
which the suite skips because ShieldGate correctly answers
`request_not_supported`.

**WARNING**s, all deliberate:

| Module | Warning | Why it stays |
|---|---|---|
| `oidcc-server` | ID token has the non-standard claim `tenant_id` | ShieldGate is multi-tenant; RP-initiated logout uses it to check that an `id_token_hint` belongs to the tenant |
| `oidcc-scope-email`, `oidcc-alternate-happy-flow` | `email` (and profile claims) also in the ID token for the code flow | OIDC Core §5.4 returns them from UserInfo for the code flow but does not forbid the ID token; many RPs read them there |
| `oidcc-scope-profile`, `oidcc-claims-essential` | Not every `profile` claim is returned (no `gender`, `birthdate`, `website`…); `claims` parameter not supported | Claims are returned when ShieldGate stores them (§5.4: "if available"); `claims_parameter_supported` is `false` |
| `oidcc-userinfo-post-body` | Access token in a POST body not accepted | RFC 6750 §2.2 is optional and discouraged; the `Authorization` header works for GET and POST |
| `oidcc-ensure-request-with-acr-values-succeeds` | No `acr` claim | ShieldGate does not define authentication context classes; `amr` is returned |

### Before certification

Running the suite locally is not certification. To certify, deploy ShieldGate
at a public https URL, run the same plans on https://www.certification.openid.net,
upload the REVIEW screenshots, and submit the results to the OpenID Foundation.

## Bugs found by conformance testing (roadmap 4.6)

| Spec | Bug | Fix |
|---|---|---|
| RFC 9700 §4.14.2 | Refresh token rotation was not atomic: concurrent requests with one refresh token each got a new token chain (19 of 20 in a test) and none was detected as reuse | The old token is claimed with a conditional `UPDATE` before new tokens are issued; losers are treated as replays and revoke the grant; the winner re-checks after issuing, so a revocation racing it cannot leave a live chain |
| OIDC Core §3.1.2.1 | `POST /oauth/authorize` did not exist | Authorization requests are accepted as a form POST |
| OIDC Core §6.1, §6.2 | `request` / `request_uri` were silently ignored, so the server processed a request other than the one the client sent | Rejected with `request_not_supported` / `request_uri_not_supported` |
| RFC 6749 §5.1 | Token responses had no `Cache-Control: no-store` / `Pragma: no-cache` | Added to the token, introspection and device authorization endpoints |
| RFC 7662 §2.2 | Introspection returned the internal UUID as `client_id`, and an expired token's metadata alongside `active: false` | Public `client_id`, `sub`, `token_type`, `iss`; inactive tokens return only `{"active": false}` |

The access token JWT still carries the client's internal UUID in `client_id`
and `aud`. It is ShieldGate's own format (not RFC 9068) and the
authentication middleware relies on it; changing it is a separate task.
