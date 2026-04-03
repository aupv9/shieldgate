---
inclusion: fileMatch
fileMatchPattern: ['**/*.java']
---

# Java Service Conventions (Spring Boot)

## Layering
- Controllers handle HTTP + DTO mapping + validation only.
- Business rules live in application/service layer.
- Persistence logic lives in repository/DAO layer.

## Validation
- Use bean validation for request DTOs; enforce business rules in service layer.

## Error mapping
- Map exceptions to `{ code, message, request_id, details? }` via `@ControllerAdvice`.
- Do not leak stack traces or raw exception messages to clients.

## Concurrency
- Prefer optimistic locking (`@Version`) on write models.
