# ShieldGate — Claude Code Guide

## Project Overview

ShieldGate is a production-grade **OAuth 2.0 and OpenID Connect (OIDC) Authorization Server** written in **Go 1.21+**. It provides centralized authentication and authorization for multiple client types (web apps, SPAs, mobile, machine-to-machine).

Key capabilities: Authorization Code + PKCE flow, Client Credentials, multi-tenancy, RBAC, audit logging, JWT token management, Redis caching, and OIDC discovery.

## Tech Stack

| Layer | Technology |
|---|---|
| Language | Go 1.21+ (toolchain 1.24.2) |
| Web framework | Gin v1.9.1 |
| Database | PostgreSQL 13+ via GORM |
| Cache | Redis 6+ (optional) |
| Auth tokens | golang-jwt/jwt v5 |
| Config | Viper (YAML + env vars) |
| Logging | Logrus (structured JSON) |
| Testing | Go standard + testify |
| Containers | Docker + Docker Compose |

## Environment Setup

```bash
cp .env.example .env          # fill in secrets
make start                     # starts Postgres, Redis, auth-server via Docker Compose
make health                    # verify all services are up
make logs                      # tail container logs
```

For local (non-Docker) development:
```bash
go mod download
# edit config.yaml with local DB/Redis URLs
go run cmd/auth-server/main.go
```

## Common Commands

```bash
# Build
go build -o bin/auth-server ./cmd/auth-server/main.go
make build-prod                # production Docker image

# Run
make start                     # Docker Compose (recommended)
go run cmd/auth-server/main.go # local run

# Test
go test ./...                  # all tests
go test -v -cover ./...        # with verbose output and coverage
make test-coverage             # coverage report (minimum 80%)
go test -v ./internal/services/    # single package
go test -v ./internal/handlers/tests/

# Code quality
go fmt ./...                   # format
go vet ./...                   # static analysis
make lint                      # golangci-lint
make security                  # gosec security scan
```

## Architecture

Four-layer pattern:

```
HTTP Handlers  (internal/handlers/)
     ↓
Services       (internal/services/)
     ↓
Repositories   (internal/repo/gorm/)
     ↓
Database       PostgreSQL + Redis
```

### Important Directories

```
cmd/auth-server/main.go        # entry point — server init, routes, graceful shutdown
config/config.go               # Viper config loader
internal/handlers/             # Gin HTTP handlers (one file per domain)
internal/services/interfaces.go  # service interfaces — read before modifying services
internal/services/             # business logic implementations
internal/repo/gorm/            # GORM repository implementations
internal/models/models.go      # all GORM entity definitions
internal/middleware/middleware.go  # CORS, rate limiting, auth, request ID
internal/database/database.go  # Postgres connection + auto-migrations
internal/database/redis.go     # Redis client setup
```

### Key Routes

```
GET  /health                            health check
GET  /oauth/authorize                   authorization endpoint
POST /oauth/token                       token endpoint
POST /oauth/introspect                  token introspection
POST /oauth/revoke                      token revocation
GET  /.well-known/openid-configuration  OIDC discovery
GET  /userinfo                          user info (protected)
/v1/tenants, /v1/users, /v1/clients     management APIs (protected)
```

## Coding Conventions

- **Naming**: `camelCase` for unexported, `PascalCase` for exported identifiers
- **Errors**: explicit error returns with custom error types; never swallow errors silently
- **Logging**: use Logrus with structured fields (`logrus.WithField(...)`)
- **DB queries**: always use parameterized queries via GORM; never build raw SQL strings from user input
- **Tests**: Arrange-Act-Assert pattern; name tests `TestFunctionName_Scenario_ExpectedResult`
- **Coverage**: maintain ≥ 80% test coverage per package
- **Context**: pass `*gin.Context` or `context.Context` as the first parameter

## Configuration

Primary config file: `config.yaml` (loaded by Viper).
Environment variables override YAML values.
See `.env.example` for all supported env vars.

Critical values to set before running:
- `JWT_SECRET` — minimum 32 characters
- `POSTGRES_*` — database credentials
- `SERVER_URL` — public-facing base URL

## Adding a New Feature

1. Define the model in `internal/models/models.go` (add GORM migration if needed)
2. Add the repository interface + GORM implementation in `internal/repo/gorm/`
3. Add the service interface in `internal/services/interfaces.go`
4. Implement the service in `internal/services/<domain>_service_impl.go`
5. Add the HTTP handler in `internal/handlers/<domain>_handler.go`
6. Register routes in `cmd/auth-server/main.go`
7. Write unit tests alongside each layer
