---
inclusion: always
---

# API Contracts

## Versioning (mandatory)
- **All external HTTP endpoints MUST be under `/v1`** (e.g., `/v1/users`, `/v1/organizations`)
- **Breaking changes require `/v2`** - never introduce breaking changes within `/v1`
- Use semantic versioning for API documentation and client SDKs
- Maintain backward compatibility within major versions

## Request/Response Format (mandatory)
- **Content-Type**: `application/json` for all endpoints
- **Accept JSON only** - do not support XML or other formats
- **Field naming**: Use `snake_case` consistently across all APIs
- **Date/Time**: Use ISO 8601 format (`2024-01-21T10:30:00Z`)
- **IDs**: Use UUIDs for all resource identifiers

## Pagination (mandatory for list endpoints)
- **MUST support**: `limit` parameter (default: 20, max: 100)
- **MUST support**: `cursor` (preferred) OR `offset` parameter
- **Response envelope**:
  ```json
  {
    "items": [...],
    "page": {
      "limit": 20,
      "cursor": "eyJ...",
      "has_more": true,
      "total_count": 150
    }
  }
  ```
- **Stable sorting**: Always include consistent ordering (e.g., by `created_at`, `id`)

## Idempotency (mandatory for create/update operations)
- **Support `Idempotency-Key` header** for POST/PUT/PATCH operations
- **Scope**: `(tenant_id, idempotency_key, route)` combination must be unique
- **Behavior**: Return original response (status + body) for duplicate requests
- **Key format**: Client-generated UUID or similar unique string
- **TTL**: Store idempotency keys for 24 hours minimum

## Error Handling (mandatory)
- **Standard error schema**:
  ```json
  {
    "code": "RESOURCE_NOT_FOUND",
    "message": "User with ID 123 not found",
    "request_id": "req_abc123",
    "details": {
      "resource_type": "user",
      "resource_id": "123"
    }
  }
  ```
- **Error codes**: Use stable `UPPER_SNAKE_CASE` values that map to HTTP status
- **Never expose**: Stack traces, SQL queries, or internal system details
- **Always include**: `request_id` for correlation with logs
- **HTTP status mapping**:
  - `400`: `INVALID_REQUEST`, `VALIDATION_FAILED`
  - `401`: `UNAUTHORIZED`, `TOKEN_EXPIRED`
  - `403`: `FORBIDDEN`, `INSUFFICIENT_PERMISSIONS`
  - `404`: `RESOURCE_NOT_FOUND`
  - `409`: `RESOURCE_CONFLICT`, `DUPLICATE_RESOURCE`
  - `422`: `BUSINESS_RULE_VIOLATION`
  - `429`: `RATE_LIMIT_EXCEEDED`
  - `500`: `INTERNAL_ERROR`

## Authentication & Authorization Headers
- **Authorization**: `Bearer <jwt_token>` for authenticated requests
- **X-Tenant-I
