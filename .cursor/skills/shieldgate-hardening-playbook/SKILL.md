---
name: shieldgate-hardening-playbook
description: Guides the agent through applying ShieldGate’s phased security hardening plan, including critical middleware fixes, JWKS/email completion, and security-focused test coverage.
---

# ShieldGate Hardening Playbook

## Purpose

This skill encodes the phased security plan for ShieldGate so agents can:
- Fix critical authentication and tenant-isolation bugs.
- Implement missing JWKS/email functionality and configuration.
- Raise test coverage on security-critical paths.

Use this skill when working on auth/middleware, JWKS/OIDC endpoints, email delivery, or security-related tests.

## Phases Overview

### Phase 1 — Critical Security Fixes

Focus on these first; they are production-breaking if wrong:

1. **`RequireAuth()` middleware (JWT validation)**
   - File: `internal/middleware/middleware.go`
   - Requirements:
     - Parse `Authorization: Bearer <token>` header.
     - Validate JWT signature using `config.Config.JWT.Secret` and `golang-jwt/jwt v5`.
     - Check `exp`, `iat`, `iss` claims.
     - Extract `sub` (user ID), `client_id`, `tenant_id`, and `scope` from claims.
     - Store them on `gin.Context` using existing keys (`UserIDKey`, `ClientIDKey`, etc.).
     - On any validation failure, return `401 Unauthorized` with a safe error body.

2. **`extractTenantFromJWT()` implementation**
   - File: `internal/middleware/middleware.go`
   - Requirements:
     - Reuse the JWT parsing/validation logic above.
     - Return the `tenant_id` claim from the validated token.
     - If not present and no header override is available, treat as an error (no silent "not implemented").

3. **JWKS endpoint implementation**
   - File: `internal/handlers/oauth_handler.go`
   - Requirements:
     - Implement `/.well-known/jwks.json` to return real key material, not `{"keys":[]}`.
     - For HMAC (HS256): publish a JWK entry with fields like `kty`, `use`, `alg`, and `kid` (no raw secret exposure).
     - For RSA (RS256, if/when introduced): publish the public key fields in JWK format.
     - Cache JWKS in memory and reuse across requests.
     - Ensure `jwks_uri` is present and correct in the OIDC discovery document.

4. **Remove hardcoded tenant IDs**
   - File: `internal/handlers/oauth_handler.go`
   - Requirements:
     - Remove `tenantID := "test-tenant"` or similar fallbacks.
     - Rely on tenant context derived from middleware (header or JWT claim).
     - If tenant is missing, respond with `400 Bad Request` and a clear error.

### Phase 2 — Email & Configuration Completion

1. **SMTP email sending**
   - File: `internal/services/email_service_impl.go`
   - Requirements:
     - Implement `sendEmail()` using SMTP settings from config; do not silently mark emails as sent.
     - Use standard library `net/smtp` or a small mail library if already present.
     - Support TLS/STARTTLS as appropriate for the configured port.
     - On failure: mark email as failed and respect `max_attempts`/retry queue semantics already modeled in DB.

2. **Configurable email sender**
   - Files:
     - `config/config.go`
     - `config.yaml` and `.env.example`
     - `internal/services/email_service_impl.go`
   - Requirements:
     - Define SMTP config fields: `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM`, `SMTP_FROM_NAME`.
     - Load them into `config.Config` using the existing Viper pattern.
     - Replace hardcoded `"noreply@shieldgate.com"` / `"ShieldGate"` with values from config.

### Phase 3 — Test Coverage for Security-Critical Paths

Targets:
- ≥ 95% coverage on auth/middleware.
- ≥ 80% coverage elsewhere.

Key areas and test files:

1. **Middleware authentication tests**
   - File: `internal/middleware/middleware_test.go`
   - Cases:
     - Valid JWT → correct `UserID` / `ClientID` / `TenantID` set in context.
     - Missing `Authorization` header → `401`.
     - Malformed Bearer token → `401`.
     - Expired token → `401`.
     - Tampered signature → `401`.
     - Missing tenant claim → fallback to header-based tenant if available.

2. **PKCE edge cases**
   - File: `internal/services/tests/auth_service_test.go`
   - Cases:
     - `code_verifier` shorter than 43 chars → rejected.
     - `code_verifier` longer than 128 chars → rejected.
     - Unsupported `code_challenge_method` → rejected.
     - Wrong `code_verifier` for stored challenge (`S256`) → rejected.

3. **Token security tests**
   - File: `internal/services/tests/auth_service_test.go`
   - Cases:
     - Revoked token reuse → rejected.
     - Expired access token → introspection returns `active: false`.
     - Forged/modified token → validation fails.
     - Authorization code reuse after exchange → rejected.

4. **OIDC compliance tests**
   - File: `internal/handlers/tests/oidc_handler_test.go`
   - Cases:
     - JWKS endpoint returns a well-formed JWK set with at least one key.
     - ID token contains correct `sub`, `aud`, `iss`, `iat`, `exp`.
     - UserInfo endpoint returns profile claims for valid token.
     - UserInfo endpoint returns `401` for invalid/expired token.
     - Discovery document includes required OIDC fields, including `jwks_uri`.

5. **Multi-tenant isolation tests**
   - File: `internal/handlers/tests/tenant_isolation_test.go`
   - Cases:
     - Tenant A’s authorization code cannot be redeemed under Tenant B.
     - A user from Tenant A cannot be retrieved with a Tenant B token.
     - A client from Tenant A is not visible to Tenant B requests.

6. **Test infrastructure helpers**
   - File: `tests/utils/test_helpers.go`
   - Helpers:
     - `SetupTestDB()` (via testcontainers-go PostgreSQL or SQLite in-memory fallback).
     - `CreateTestJWT()`, `CreateExpiredJWT()`, `CreateTamperedJWT()` with the same signing config as the app.

## Additional Implementation Tasks

When applicable, also prioritize:
- Fixing `setupRoutes()` in `cmd/auth-server/main.go` to accept `*config.Config` so `RequireAuth(cfg)` and `TenantContext(cfg)` compile.
- Starting the email queue/background worker from `main.go` using a context tied to graceful shutdown.
- Enforcing account lockout logic based on failed login attempts in `user_service_impl.go`.
- Enhancing `/health` to check DB and Redis status and respond with `"ok"` vs `"degraded"` accordingly.

## Working Style

When using this playbook:
- Implement changes phase by phase, verifying `go build ./...` and `go test ./...` successfully before moving on.
- Keep security-sensitive logic centralized and well-tested.
- Avoid introducing new hard-coded secrets, test-only tenants, or dummy auth shortcuts in production paths.

