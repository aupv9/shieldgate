# Development Workflow cho ShieldGate

## Git Workflow

### Branch Strategy
- **main**: Production-ready code
- **develop**: Integration branch cho features
- **feature/***: Feature development branches
- **hotfix/***: Critical production fixes
- **release/***: Release preparation branches

### Commit Message Convention
```
type(scope): description

Types:
- feat: New feature
- fix: Bug fix
- docs: Documentation changes
- style: Code style changes (formatting, etc.)
- refactor: Code refactoring
- test: Adding or updating tests
- chore: Maintenance tasks

Examples:
feat(auth): implement PKCE validation for public clients
fix(token): resolve JWT expiration validation bug
docs(api): update OAuth 2.0 endpoint documentation
test(service): add unit tests for user authentication
```

### Pull Request Process
1. Create feature branch từ `develop`
2. Implement feature với tests
3. Run full test suite: `go test ./...`
4. Run security scan: `gosec ./...`
5. Update documentation nếu cần
6. Create PR với detailed description
7. Code review và approval
8. Merge vào `develop`

## Development Commands

### Common Development Tasks
```bash
# Start development environment
docker-compose up -d postgres redis
go run cmd/auth-server/main.go

# Run tests
go test ./...                    # All tests
go test -v ./internal/services/  # Specific package
go test -cover ./...             # With coverage
go test -race ./...              # Race condition detection

# Code quality checks
go fmt ./...                     # Format code
go vet ./...                     # Static analysis
golangci-lint run               # Comprehensive linting
gosec ./...                     # Security scan

# Build và deployment
go build -o bin/auth-server cmd/auth-server/main.go
docker build -t shieldgate/auth-server .
docker-compose -f docker-compose.prod.yml up -d
```

### Database Operations
```bash
# Create migration
migrate create -ext sql -dir migrations add_new_table

# Run migrations
migrate -path migrations -database "postgres://..." up

# Rollback migration
migrate -path migrations -database "postgres://..." down 1

# Reset database (development only)
migrate -path migrations -database "postgres://..." drop
migrate -path migrations -database "postgres://..." up
```

## Code Review Guidelines

### Review Checklist
- [ ] Code follows Go conventions và project standards
- [ ] All functions have appropriate error handling
- [ ] Security best practices được tuân thủ
- [ ] Input validation được implement đúng cách
- [ ] Tests cover new functionality
- [ ] Documentation được update
- [ ] No hardcoded secrets hoặc credentials
- [ ] Logging được implement cho important events
- [ ] Performance implications được consider

### Security Review Points
- [ ] OAuth 2.0 flows implement đúng spec
- [ ] PKCE validation cho public clients
- [ ] JWT tokens được sign và validate đúng cách
- [ ] Password hashing sử dụng bcrypt
- [ ] Rate limiting cho sensitive endpoints
- [ ] Input sanitization để prevent injection
- [ ] Proper error messages (không leak sensitive info)

## IDE Setup và Tools

### VS Code Extensions
```json
{
  "recommendations": [
    "golang.go",
    "ms-vscode.vscode-json",
    "redhat.vscode-yaml",
    "ms-vscode.docker",
    "github.copilot",
    "streetsidesoftware.code-spell-checker"
  ]
}
```

### Go Tools Setup
```bash
# Install essential Go tools
go install golang.org/x/tools/cmd/goimports@latest
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest
go install github.com/golang-migrate/migrate/v4/cmd/migrate@latest

# Install test tools
go install github.com/onsi/ginkgo/v2/ginkgo@latest
go install gotest.tools/gotestsum@latest
```

### Pre-commit Hooks
```bash
# Install pre-commit
pip install pre-commit

# Setup hooks
cat > .pre-commit-config.yaml << EOF
repos:
  - repo: local
    hooks:
      - id: go-fmt
        name: go fmt
        entry: gofmt
        language: system
        args: [-w]
        files: \.go$
      - id: go-vet
        name: go vet
        entry: go vet
        language: system
        files: \.go$
        pass_filenames: false
      - id: go-test
        name: go test
        entry: go test
        language: system
        args: [./...]
        pass_filenames: false
EOF

pre-commit install
```

## Debugging Guidelines

### Local Debugging
```go
// Use delve debugger
go install github.com/go-delve/delve/cmd/dlv@latest

// Debug specific test
dlv test ./internal/services/tests -- -test.run TestAuthService

// Debug running application
dlv debug cmd/auth-server/main.go

// Remote debugging (in container)
dlv debug --headless --listen=:2345 --api-version=2 cmd/auth-server/main.go
```

### Logging for Debugging
```go
// Add debug logging
log.WithFields(logrus.Fields{
    "function": "GenerateAccessToken",
    "user_id": userID,
    "client_id": clientID,
    "scopes": scopes,
}).Debug("generating access token")

// Trace request flow
log.WithField("request_id", requestID).Info("processing OAuth authorization request")
```

### Common Issues và Solutions

#### JWT Token Issues
```go
// Debug JWT parsing
token, err := jwt.ParseWithClaims(tokenString, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
    log.Debugf("Token method: %v", token.Method)
    log.Debugf("Token header: %v", token.Header)
    return []byte(secret), nil
})

if err != nil {
    log.WithError(err).Error("JWT parsing failed")
    // Check: secret key, signing method, token format
}
```

#### Database Connection Issues
```go
// Debug database connection
sqlDB, err := db.DB()
if err != nil {
    log.WithError(err).Fatal("failed to get database instance")
}

if err := sqlDB.Ping(); err != nil {
    log.WithError(err).Fatal("database ping failed")
    // Check: connection string, network, credentials
}

log.Infof("Database stats: %+v", sqlDB.Stats())
```

#### OAuth Flow Debugging
```go
// Log OAuth request parameters
log.WithFields(logrus.Fields{
    "client_id": req.ClientID,
    "redirect_uri": req.RedirectURI,
    "scope": req.Scope,
    "response_type": req.ResponseType,
    "code_challenge": req.CodeChallenge != "",
    "code_challenge_method": req.CodeChallengeMethod,
}).Debug("OAuth authorization request received")
```

## Performance Profiling

### CPU Profiling
```go
import _ "net/http/pprof"

// Add to main.go
go func() {
    log.Println(http.ListenAndServe("localhost:6060", nil))
}()

// Profile CPU usage
go tool pprof http://localhost:6060/debug/pprof/profile?seconds=30
```

### Memory Profiling
```bash
# Memory profile
go tool pprof http://localhost:6060/debug/pprof/heap

# Goroutine profile
go tool pprof http://localhost:6060/debug/pprof/goroutine

# Block profile
go tool pprof http://localhost:6060/debug/pprof/block
```

### Load Testing
```bash
# Install hey tool
go install github.com/rakyll/hey@latest

# Test OAuth token endpoint
hey -n 1000 -c 10 -m POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=test&client_secret=secret" \
  http://localhost:8080/oauth/token

# Test authorization endpoint
hey -n 1000 -c 10 \
  "http://localhost:8080/oauth/authorize?response_type=code&client_id=test&redirect_uri=http://localhost:3000/callback"
```

## Release Process

### Version Management
```bash
# Tag release
git tag -a v1.0.0 -m "Release version 1.0.0"
git push origin v1.0.0

# Build release
goreleaser release --rm-dist

# Docker release
docker build -t shieldgate/auth-server:v1.0.0 .
docker push shieldgate/auth-server:v1.0.0
```

### Deployment Checklist
- [ ] All tests pass
- [ ] Security scan clean
- [ ] Documentation updated
- [ ] Configuration reviewed
- [ ] Database migrations tested
- [ ] Backup procedures verified
- [ ] Monitoring alerts configured
- [ ] Rollback plan prepared