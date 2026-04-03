---
name: shieldgate-authz-workflow
description: Guides the agent through adding or modifying OAuth2/OIDC features in the ShieldGate authorization server using the established layered architecture and project conventions.
---

# ShieldGate AuthZ/OIDC Workflow

## When to Use This Skill

Use this skill whenever:
- Implementing or changing OAuth2/OIDC flows (authorization code, PKCE, client credentials, token introspection, revocation, userinfo).
- Adding new management APIs under `/v1/*` (tenants, users, clients, etc.).
- Extending token handling, JWT claims, or discovery metadata.

The goal is to keep all changes consistent with ShieldGate’s architecture and security expectations.

## High-Level Workflow

1. **Clarify the feature**
   - Identify which flow or endpoint is affected (e.g., `/oauth/authorize`, `/oauth/token`, `/oauth/introspect`, `/v1/clients`).
   - Determine whether the change is domain logic, storage-related, or purely HTTP-level (validation/shape).

2. **Locate the relevant layer(s)**
   - **Handlers** live under `internal/handlers/` and wire HTTP routes to services.
   - **Services** live under `internal/services/` and implement business logic behind interfaces.
   - **Repositories** live under `internal/repo/gorm/` and manage persistence in Postgres (and optionally Redis).
   - **Models** are defined in `internal/models/models.go` and should match DB schema expectations.

3. **Follow the “new feature” pattern**
   - If a new domain concept is needed:
     1. Add/update the model in `internal/models/models.go`.
     2. Declare/update repository interfaces and add a GORM implementation under `internal/repo/gorm/`.
     3. Declare/update the service interface in `internal/services/interfaces.go`.
     4. Implement or adjust the service in `internal/services/<domain>_service_impl.go`.
     5. Add or update the HTTP handler under `internal/handlers/<domain>_handler.go`.
     6. Register or adjust routes in `cmd/auth-server/main.go`.

4. **Respect security boundaries**
   - Keep token verification, signing, and parsing in well-defined helpers/services; do not duplicate crypto logic ad hoc.
   - Ensure handlers never log sensitive data (tokens, secrets, passwords).
   - Enforce tenant and RBAC checks in services where business decisions are made.

5. **Add tests**
   - For handlers: add HTTP-level tests validating input, status codes, and response payloads.
   - For services: add unit tests covering success paths, error paths, and edge cases (expired tokens, invalid clients, etc.).
   - For repositories: add tests that validate query behavior when appropriate (or rely on integration tests if the project already does so).

## Detailed Steps for Common Tasks

### A. Adding a New Protected Management Endpoint

1. **Design the API**
   - Determine URL, HTTP method, request/response schema, and required permissions/scopes.

2. **Update models and services**
   - If a new entity or field is needed, update `internal/models/models.go`.
   - Extend or add service methods in `internal/services/interfaces.go` and the corresponding implementation file.

3. **Update repositories**
   - Add methods in the relevant GORM repository to support the new query or update operations.
   - Use parameterized queries and avoid raw SQL built from user input.

4. **Implement the handler**
   - Add a function in the appropriate `internal/handlers/*_handler.go` file.
   - Validate and bind incoming JSON/query params.
   - Call the service and translate domain errors to HTTP responses.

5. **Wire the route**
   - Register the new handler in `cmd/auth-server/main.go`, attaching any required middleware (auth, rate limiting, request ID).

6. **Test**
   - Add handler tests for success, validation failure, and authorization failure.
   - Add service tests for business rules and edge cases.

### B. Modifying an OAuth2/OIDC Flow

1. **Understand the existing flow**
   - Locate the existing handler(s) under `internal/handlers/` (e.g., token, authorize, introspection handlers).
   - Find the corresponding services and token utilities used by those handlers.

2. **Make changes in the correct layer**
   - Prefer changes in services if the behavior is domain logic (grant validation, token issuance rules).
   - Limit handler changes to input parsing, basic validation, and HTTP concerns.

3. **Update discovery or metadata if needed**
   - If the change affects discovery (e.g., supported scopes, grant types, endpoints), update the OIDC discovery handler and tests accordingly.

4. **Re-run security checks**
   - Consider implications for token lifetime, revocation, and replay protection.
   - Ensure changes do not weaken validation (e.g., required parameters, PKCE checks, client authentication).

5. **Add regression tests**
   - Add tests that cover the modified flow end-to-end where possible, verifying correct tokens, claims, and error responses.

## Tips and Best Practices

- Prefer small, focused changes per feature or endpoint.
- Keep configuration (e.g., token TTLs, URLs) in `config.yaml`/env-backed config rather than hard-coded.
- Reuse existing patterns for logging, error handling, and responses to maintain consistency.

