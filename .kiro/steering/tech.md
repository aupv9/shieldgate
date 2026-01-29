# Technology Stack

## Core Technologies
- **Language**: Go 1.21+
- **Web Framework**: Gin (github.com/gin-gonic/gin)
- **Database**: PostgreSQL 13+ with GORM ORM
- **Cache**: Redis 6+ (optional)
- **Authentication**: JWT tokens with golang-jwt/jwt/v5
- **Password Hashing**: bcrypt (golang.org/x/crypto)

## Key Dependencies
- **Configuration**: Viper for YAML/environment config management
- **Logging**: Logrus with structured JSON logging
- **UUID**: Google UUID for unique identifiers
- **Testing**: Testify for comprehensive test suites
- **Containerization**: Docker with multi-stage builds

## Build System & Commands

### Development Setup
```bash
# Install dependencies
go mod download

# Run locally (requires PostgreSQL and Redis)
go run cmd/auth-server/main.go

# Using Docker Compose (recommended)
docker-compose up -d
```

### Testing
```bash
# Run all tests
go test ./...

# Run tests with coverage
go test -cover ./...

# Run tests with race detection
go test -race ./...

# Run specific package tests
go test -v ./internal/services/
```

### Build & Deployment
```bash
# Build binary
go build -o bin/auth-server cmd/auth-server/main.go

# Build Docker image
docker build -t shieldgate/auth-server .

# Production deployment
docker-compose -f docker-compose.prod.yml up -d
```

### Code Quality
```bash
# Format code
go fmt ./...

# Static analysis
go vet ./...

# Linting (requires golangci-lint)
golangci-lint run

# Security scan (requires gosec)
gosec ./...
```

### Database Operations
```bash
# Database migrations (using golang-migrate)
migrate -path migrations -database "postgres://..." up
migrate -path migrations -database "postgres://..." down 1
```

## Configuration Management
- **Primary**: YAML configuration files (config.yaml)
- **Fallback**: Environment variables for Docker/K8s
- **Hierarchy**: CLI flags > ENV vars > config.yaml > defaults
- **Hot Reload**: Viper supports configuration reloading

## Deployment Targets
- **Development**: Local with Docker Compose
- **Production**: Kubernetes with Helm charts
- **Cloud**: AWS, GCP, Azure with container services
- **On-Premise**: Docker Swarm or standalone containers