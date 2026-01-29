---
inclusion: fileMatch
fileMatchPattern: ['**/*.go']
---

# Go Service Conventions

## Context
- Always pass `context.Context` from handler -> service -> repo.
- Never store request-scoped data in globals.

## Errors
- Use typed/sentinel errors in service/repo; map to API `code` in one place (transport layer).
- Wrap errors with context; keep client messages stable and safe.

## Repositories
- Define repo interfaces in `internal/repo` and implementations in `internal/repo/<driver>`.
- Keep SQL and DB plumbing out of service/usecase.

## Testing
- Use table-driven tests.
- Mock repo interfaces for service tests; integration tests cover repo + migrations.
