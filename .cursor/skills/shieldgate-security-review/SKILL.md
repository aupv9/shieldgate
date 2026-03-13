---
name: shieldgate-security-review
description: Reviews ShieldGate changes for security, correctness, and compliance with OAuth2/OIDC and project-specific authZ/authN standards; use when assessing sensitive flows, token handling, or permission checks.
---

# ShieldGate Security Review

## When to Use This Skill

Use this skill whenever:
- Reviewing changes to OAuth2/OIDC flows, token endpoints, or discovery.
- Modifying authentication, authorization, RBAC, tenant isolation, or client management.
- Touching token creation, verification, storage, or revocation logic.
- Introducing new external integrations that use ShieldGate-issued tokens.

The goal is to catch security, privacy, and correctness issues early.

## Core Review Checklist

Walk through these questions for any change:

1. **Authentication & Authorization**
   - Are all protected endpoints guarded by the correct middleware and checks?
   - Are tenant, client, and user identities validated and propagated correctly?
   - Are RBAC decisions and scope checks implemented in services (not just handlers)?

2. **Token Handling**
   - Are access/refresh tokens, client secrets, and passwords never logged or returned unintentionally?
   - Are tokens always validated (signature, audience, issuer, expiry, and other claims) before use?
   - Are token lifetimes, revocation, and rotation behaviors consistent with project policy?

3. **Input Validation**
   - Are all user-controlled inputs validated and sanitized before use?
   - Are grant parameters (redirect_uri, code_verifier, client_id, scopes, etc.) checked according to specs and project rules?
   - Are error messages informative but not leaking sensitive implementation details?

4. **Data Access & Persistence**
   - Does the change keep all DB access within repository layers (using GORM safely)?
   - Are queries parameterized, with no raw SQL built directly from user input?
   - Are multi-tenant constraints and data isolation enforced at the service/repo level?

5. **Logging & Observability**
   - Are logs structured (Logrus) and do they include safe identifiers (request ID, tenant ID, client ID) where needed?
   - Do logs avoid secrets, full tokens, or PII beyond what is necessary?
   - Are error logs placed at clear boundaries to avoid duplicates for the same failure?

6. **Configuration & Secrets**
   - Are new secrets or URLs added via configuration (config + environment variables), not hard-coded?
   - Are defaults safe (e.g., no debug modes or weak crypto in production paths)?

## Review Process

1. **Identify Sensitive Areas**
   - Locate changes under `internal/handlers/`, `internal/services/`, token utilities, and repo implementations that touch security.

2. **Trace the Flow**
   - For each changed handler, trace the call path: handler → service → repository → external systems.
   - Verify that identity and authorization context (tenant, user, client, scopes) is correctly passed and enforced.

3. **Apply the Checklist**
   - For each changed file, run through the core checklist sections above.
   - Note any missing checks, logging problems, or over-permissive behavior.

4. **Recommend Fixes**
   - When issues are found, propose concrete, minimal changes consistent with existing project patterns (e.g., reuse existing middleware, helpers, and error types).
   - Encourage adding or expanding tests to cover newly fixed behavior.

## Output Format

When presenting a security review, structure feedback as:

- **Summary**
  - Short paragraph summarizing overall security posture of the change.

- **Findings**
  - **Critical**: Must fix before merge (e.g., bypassed authZ checks, token leakage).
  - **High**: Strongly recommended fixes (e.g., missing validation on important fields).
  - **Medium/Low**: Defense-in-depth and clarity improvements (e.g., log field improvements, more specific errors).

- **Suggested Tests**
  - List specific tests (unit or integration) that should be added or updated to guard against regression.

