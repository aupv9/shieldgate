# ShieldGate Makefile
# Provides convenient commands for development and deployment

.PHONY: help setup build start stop restart logs clean test lint fmt vet security backup restore deploy

# Default target
help: ## Show this help message
	@echo "ShieldGate OAuth 2.0 Authorization Server"
	@echo ""
	@echo "Available commands:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# Development commands
setup: ## Setup development environment
	@echo "🚀 Setting up development environment..."
	@chmod +x scripts/*.sh
	@./scripts/setup.sh

build: ## Build the application
	@echo "🔨 Building application..."
	@docker-compose build

start: ## Start all services
	@echo "▶️  Starting services..."
	@docker-compose up -d

start-dev: ## Start services in development mode
	@echo "🔧 Starting development environment..."
	@docker-compose -f docker-compose.yml -f docker-compose.dev.yml up -d

start-monitoring: ## Start services with monitoring
	@echo "📊 Starting services with monitoring..."
	@docker-compose --profile monitoring up -d

stop: ## Stop all services
	@echo "⏹️  Stopping services..."
	@docker-compose down

restart: ## Restart all services
	@echo "🔄 Restarting services..."
	@docker-compose restart

logs: ## Show logs for all services
	@docker-compose logs -f

logs-auth: ## Show logs for auth server only
	@docker-compose logs -f auth-server

status: ## Show service status
	@docker-compose ps

# Database commands
db-shell: ## Connect to database shell
	@docker-compose exec postgres psql -U ${POSTGRES_USER:-authuser} -d ${POSTGRES_DB:-authdb}

db-migrate: ## Run database migrations
	@echo "🗄️  Running database migrations..."
	@docker-compose exec auth-server ./main migrate

db-seed: ## Seed database with test data
	@echo "🌱 Seeding database..."
	@docker-compose exec postgres psql -U ${POSTGRES_USER:-authuser} -d ${POSTGRES_DB:-authdb} -f /docker-entrypoint-initdb.d/01-init.sql

# Backup and restore
backup: ## Create database and configuration backup
	@echo "💾 Creating backup..."
	@./scripts/backup.sh

restore-db: ## Restore database from backup (requires BACKUP_FILE)
	@echo "🔄 Restoring database..."
	@./scripts/restore.sh database $(BACKUP_FILE)

restore-config: ## Restore configuration from backup (requires BACKUP_FILE)
	@echo "🔄 Restoring configuration..."
	@./scripts/restore.sh config $(BACKUP_FILE)

# Development tools
test: ## Run tests
	@echo "🧪 Running tests..."
	@go test -v ./...

test-coverage: ## Run tests with coverage
	@echo "📊 Running tests with coverage..."
	@go test -cover ./...
	@go test -coverprofile=coverage.out ./...
	@go tool cover -html=coverage.out -o coverage.html

lint: ## Run linter
	@echo "🔍 Running linter..."
	@golangci-lint run

fmt: ## Format code
	@echo "✨ Formatting code..."
	@go fmt ./...

vet: ## Run go vet
	@echo "🔍 Running go vet..."
	@go vet ./...

security: ## Run security scan
	@echo "🔒 Running security scan..."
	@gosec ./...

# Build and deployment
build-prod: ## Build production image
	@echo "🏗️  Building production image..."
	@docker build -t shieldgate/auth-server:latest .

deploy-prod: ## Deploy to production
	@echo "🚀 Deploying to production..."
	@docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d

# Cleanup commands
clean: ## Clean up containers and volumes
	@echo "🧹 Cleaning up..."
	@docker-compose down -v
	@docker system prune -f

clean-all: ## Clean up everything including images
	@echo "🧹 Cleaning up everything..."
	@docker-compose down -v --rmi all
	@docker system prune -af

# Utility commands
shell: ## Access auth server shell
	@docker-compose exec auth-server sh

redis-cli: ## Access Redis CLI
	@docker-compose exec redis redis-cli

generate-secret: ## Generate a new JWT secret
	@echo "🔑 Generated JWT secret:"
	@openssl rand -base64 64 | tr -d "=+/" | cut -c1-64

health: ## Check service health
	@echo "🏥 Checking service health..."
	@curl -f http://localhost:8080/health || echo "❌ Auth server is not healthy"
	@docker-compose exec postgres pg_isready -U ${POSTGRES_USER:-authuser} -d ${POSTGRES_DB:-authdb} || echo "❌ Database is not ready"
	@docker-compose exec redis redis-cli ping || echo "❌ Redis is not ready"

# OAuth testing
test-oauth: ## Test OAuth flow
	@echo "🔐 Testing OAuth flow..."
	@echo "Authorization URL:"
	@echo "http://localhost:8080/oauth/authorize?response_type=code&client_id=shieldgate-dev-client&redirect_uri=http://localhost:3000/callback&scope=read%20openid&state=test123&code_challenge=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk&code_challenge_method=S256"

# Documentation
docs: ## Generate documentation
	@echo "📚 Generating documentation..."
	@godoc -http=:6060 &
	@echo "Documentation available at http://localhost:6060"

# Environment management
env-example: ## Create .env from example
	@cp .env.example .env
	@echo "📝 Created .env file from example"

env-validate: ## Validate environment configuration
	@echo "✅ Validating environment configuration..."
	@docker-compose config > /dev/null && echo "✅ Docker Compose configuration is valid" || echo "❌ Docker Compose configuration is invalid"

# Monitoring
monitor: ## Open monitoring dashboards
	@echo "📊 Opening monitoring dashboards..."
	@echo "Prometheus: http://localhost:9090"
	@echo "Grafana: http://localhost:3000 (admin/admin)"

# Quick start
quick-start: setup start health test-oauth ## Quick start for development
	@echo ""
	@echo "🎉 ShieldGate is ready!"
	@echo ""
	@echo "📋 Service URLs:"
	@echo "   • Auth Server: http://localhost:8080"
	@echo "   • Health Check: http://localhost:8080/health"
	@echo ""
	@echo "🔐 Test OAuth flow:"
	@echo "   http://localhost:8080/oauth/authorize?response_type=code&client_id=shieldgate-dev-client&redirect_uri=http://localhost:3000/callback&scope=read%20openid&state=test123"