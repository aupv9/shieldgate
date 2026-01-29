# Project Structure

## Root Directory Layout
```
shieldgate/
├── cmd/auth-server/          # Application entry point
├── internal/                 # Private application code
├── config/                   # Configuration management
├── docs/                     # Documentation (EN/VI)
├── templates/                # HTML templates
├── tests/                    # Test utilities
├── .kiro/                    # Kiro steering files
├── docker-compose.yml        # Development environment
├── Dockerfile               # Container build
├── go.mod/go.sum           # Go module dependencies
└── config.yaml             # Application configuration
```

## Internal Package Organization

### `/internal` - Private Application Code
- **handlers/**: HTTP request handlers (controllers)
  - `auth_handler.go` - OAuth 2.0/OIDC endpoints
  - `client_handler.go` - Client management API
  - `user_handler.go` - User management API
  - `tests/` - Handler unit tests

- **services/**: Business logic layer
  - `auth_service.go` - Core OAuth/OIDC logic
  - `client_service.go` - Client management
  - `user_service.go` - User management
  - `tests/` - Service unit and integration tests

- **models/**: Data models and database schemas
  - `models.go` - GORM models and structs
  - `tests/` - Model validation tests

- **database/**: Database connection and utilities
  - `database.go` - PostgreSQL connection with GORM
  - `redis.go` - Redis client setup

- **middleware/**: HTTP middleware components
  - `middleware.go` - CORS, rate limiting, logging

## Architecture Patterns

### Layered Architecture
1. **Transport Layer** (`handlers/`): HTTP request/response handling
2. **Business Layer** (`services/`): OAuth logic, validation, token management
3. **Data Layer** (`models/`, `database/`): Database operations and models

### Dependency Flow
- Handlers depend on Services
- Services depend on Models/Database
- No circular dependencies
- Dependency injection in main.go

### Package Responsibilities
- **handlers/**: Thin controllers, DTO mapping, HTTP concerns only
- **services/**: Business rules, OAuth flows, token validation
- **models/**: Data structures, GORM models, database schemas
- **database/**: Connection management, migrations
- **middleware/**: Cross-cutting concerns (auth, logging, CORS)

## Configuration Structure
- **config/**: Configuration loading and validation
- **config.yaml**: Main configuration file
- **Environment variables**: Override for containerized deployments
- **Viper**: Configuration management with hot reload

## Documentation Organization
- **docs/**: Comprehensive documentation in English and Vietnamese
- **README.md**: Quick start and overview
- **API documentation**: OpenAPI/Swagger specs
- **Architecture diagrams**: Mermaid diagrams for flows

## Testing Structure
- **Unit tests**: Co-located with source code (`*_test.go`)
- **Integration tests**: In `tests/` directory
- **Test utilities**: Shared helpers in `tests/utils/`
- **Coverage**: Minimum 80% line coverage requirement

## Build Artifacts
- **bin/**: Compiled binaries
- **Docker images**: Multi-stage builds for production
- **Migrations**: Database schema changes
- **Static assets**: Templates, CSS, JavaScript