---
inclusion: always
---

# SaaS Core Standards

## Architecture (mandatory)
- Use layering: transport (HTTP/gRPC) -> service/usecase -> repository/dao -> db.
- Handlers/controllers must be thin (DTO mapping, validation, calling service).
- Do not access DB from handlers/controllers.
- Prefer pure domain logic in service/usecase; repos should be side-effecting boundaries.

## Multi-tenancy (mandatory)
- Every request must resolve `tenant_id` from auth context (JWT claims or gateway-injected header).
- Every repo query MUST filter by `tenant_id` (reads and writes).
- Missing `tenant_id` is unauthorized. Never allow cross-tenant access.

## API contracts (mandatory)
- Versioned routes under `/v1`.
- List endpoints must support pagination (cursor+limit or offset+limit) and stable sorting.
- Validate request DTOs at the boundary; enforce business rules in service/usecase.

## Error contract (mandatory)
- Return a stable error schema: `{ code, message, request_id, details? }`.
- `code` is UPPER_SNAKE and maps cleanly to HTTP status.
- Never leak stack traces, SQL strings, or internal exception messages to clients.

## Observability (mandatory)
- Structured logs with `request_id`, `tenant_id`, `service`, `operation`.
- Do not log secrets (tokens, passwords, API keys) or sensitive PII.
- Add tracing spans/attributes for inbound requests and external calls.

## Data & migrations (mandatory)
- Schema changes must be done via migrations and be backward compatible when possible.
- Prefer optimistic locking for concurrent updates.

## Security defaults (mandatory)
- Authorization checks are deny-by-default and enforced in service/usecase layer.
- Apply input size limits and rate limiting for public-facing endpoints.
