---
inclusion: always
---

# Backend Quality Bar (Tech Lead / Staff)

## Correctness & domain integrity
- Enforce invariants in service/usecase (not in handlers/controllers).
- Use optimistic locking or equivalent when concurrent updates can happen.
- Avoid “stringly-typed” business logic; prefer typed enums/constants for states and error codes.

## Multi-tenancy & authorization (non-negotiable)
- Every request resolves `tenant_id` and every query filters by it.
- Authorization is deny-by-default; checks live in service/usecase.
- Never trust client-provided `tenant_id` payload fields when auth context exists.

## API design
- Keep API contracts stable and versioned; no breaking changes inside `/v1`.
- Ensure idempotency for retryable create/command endpoints (at least where duplicates are costly).
- Provide consistent pagination and sorting; avoid unbounded list endpoints.

## Error handling
- Map internal errors to stable error `code` values and safe client messages.
- Include `request_id` in error responses and logs for correlation.
- Log internal errors with enough context for debugging, without leaking secrets/PII.

## Reliability
- Timeouts on outbound calls and DB operations; no unbounded waits.
- Retries only when safe and bounded; use jitter/backoff; avoid retry storms.
- Handle partial failures explicitly (circuit breaker / fallback where appropriate).

## Data & migrations
- Schema changes must be migration-based and backward compatible when possible.
- Add indexes for common access paths, especially `(tenant_id, ...)`.
- Avoid N+1 query patterns and accidental full table scans.

## Observability
- Structured logs and tracing around inbound requests, DB calls, and external calls.
- Add metrics for latency/error rates and critical business operations.

## Testing strategy (minimum bar)
- Unit tests for service/usecase business logic with repo mocked.
- At least one integration test path covering DB + migrations (or a documented TODO with plan).
- Tests must include at least: auth/tenant enforcement, not-found, conflict, validation failure.
