# ShieldGate Infrastructure Documentation

## Overview

ShieldGate sử dụng Docker Compose để quản lý infrastructure với các service chính:
- **PostgreSQL**: Database chính cho lưu trữ dữ liệu
- **Redis**: Cache và session storage
- **Auth Server**: OAuth 2.0 Authorization Server
- **Nginx**: Reverse proxy và load balancer (production)
- **Prometheus**: Monitoring và metrics (optional)
- **Grafana**: Dashboard và visualization (optional)

## Quick Start

### 1. Setup Development Environment

```bash
# Clone repository và setup
git clone <repository-url>
cd shieldgate

# Setup development environment (tự động tạo .env, SSL certs, etc.)
make setup

# Hoặc chạy manual
chmod +x scripts/setup.sh
./scripts/setup.sh
```

### 2. Start Services

```bash
# Start tất cả services
make start

# Hoặc start development mode
make start-dev

# Start với monitoring
make start-monitoring
```

### 3. Verify Installation

```bash
# Check health
make health

# View logs
make logs

# Test OAuth flow
make test-oauth
```

## Environment Configurations

### Development (.env)

```bash
# Database
POSTGRES_DB=authdb
POSTGRES_USER=authuser
POSTGRES_PASSWORD=generated_secure_password
POSTGRES_PORT=5432

# Redis
REDIS_PASSWORD=generated_redis_password
REDIS_PORT=6379

# Server
SERVER_URL=http://localhost:8080
SERVER_PORT=8080
GIN_MODE=debug

# JWT (auto-generated 64-char secret)
JWT_SECRET=generated_jwt_secret

# Security
BCRYPT_COST=12
ACCESS_TOKEN_DURATION=3600
REFRESH_TOKEN_DURATION=2592000

# Logging
LOG_LEVEL=debug
LOG_FORMAT=text
```

### Production Environment Variables

```bash
# Override for production
GIN_MODE=release
LOG_LEVEL=warn
LOG_FORMAT=json
SERVER_URL=https://auth.yourdomain.com

# Use strong passwords
POSTGRES_PASSWORD=your_production_password
REDIS_PASSWORD=your_production_redis_password
JWT_SECRET=your_production_jwt_secret_64_chars_minimum
```

## Service Architecture

### Core Services

#### 1. PostgreSQL Database
- **Image**: `postgres:15-alpine`
- **Port**: 5432
- **Features**:
  - Automatic initialization với schema
  - Performance tuning cho production
  - Health checks
  - Backup support

#### 2. Redis Cache
- **Image**: `redis:7-alpine`
- **Port**: 6379
- **Features**:
  - Persistent storage với AOF
  - Memory optimization
  - Password protection
  - Rate limiting support

#### 3. Auth Server
- **Build**: Multi-stage Dockerfile
- **Port**: 8080
- **Features**:
  - OAuth 2.0 & OpenID Connect
  - Multi-tenant support
  - JWT token management
  - Health checks

### Optional Services

#### 4. Nginx (Production)
- **Image**: `nginx:alpine`
- **Ports**: 80, 443
- **Features**:
  - SSL/TLS termination
  - Rate limiting
  - Security headers
  - Load balancing

#### 5. Prometheus (Monitoring)
- **Image**: `prom/prometheus:latest`
- **Port**: 9090
- **Features**:
  - Metrics collection
  - Alerting rules
  - Data retention

#### 6. Grafana (Dashboards)
- **Image**: `grafana/grafana:latest`
- **Port**: 3000
- **Features**:
  - Pre-configured dashboards
  - Prometheus integration
  - User management

## Docker Compose Profiles

### Development Profile
```bash
# Start development environment
docker-compose -f docker-compose.yml -f docker-compose.dev.yml up -d

# Features:
# - Hot reload
# - Debug mode
# - Exposed ports
# - Development tools
```

### Production Profile
```bash
# Start production environment
docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d

# Features:
# - Resource limits
# - Replicas
# - Optimized configuration
# - Security hardening
```

### Monitoring Profile
```bash
# Start with monitoring
docker-compose --profile monitoring up -d

# Includes:
# - Prometheus
# - Grafana
# - Metrics collection
```

## Database Schema

### Automatic Initialization

Database được tự động khởi tạo với:

1. **Schema Creation** (`scripts/init-db.sql`):
   - Tables: tenants, users, clients, authorization_codes, access_tokens, refresh_tokens
   - Constraints và relationships
   - Default data cho development

2. **Performance Indexes** (`scripts/create-indexes.sql`):
   - Optimized indexes cho multi-tenant queries
   - Composite indexes cho common patterns
   - Partial indexes cho cleanup operations

### Default Data

Development environment bao gồm:
- **Default Tenant**: `localhost` domain
- **Admin User**: `admin@localhost` / `admin123`
- **Dev Client**: `shieldgate-dev-client` (confidential)
- **SPA Client**: `shieldgate-spa-client` (public)

## Security Configuration

### SSL/TLS Setup

#### Development (Self-signed)
```bash
# Auto-generated trong setup script
openssl req -x509 -newkey rsa:4096 -keyout config/ssl/key.pem -out config/ssl/cert.pem -days 365 -nodes
```

#### Production (Let's Encrypt)
```bash
# Sử dụng certbot hoặc cloud provider SSL
# Update nginx.conf với proper certificates
```

### Security Headers

Nginx được cấu hình với security headers:
- HSTS
- X-Frame-Options
- X-Content-Type-Options
- CSP (Content Security Policy)
- Referrer Policy

### Rate Limiting

- **OAuth endpoints**: 10 requests/minute
- **API endpoints**: 100 requests/minute
- **Redis-based**: Distributed rate limiting

## Monitoring & Observability

### Health Checks

Tất cả services có health checks:
```bash
# Check all services
make health

# Individual checks
curl http://localhost:8080/health
docker-compose exec postgres pg_isready
docker-compose exec redis redis-cli ping
```

### Logging

#### Structured Logging
- **Format**: JSON (production), Text (development)
- **Levels**: ERROR, WARN, INFO, DEBUG
- **Fields**: request_id, tenant_id, user_id, client_id

#### Log Aggregation
```bash
# View logs
make logs
make logs-auth

# Follow specific service
docker-compose logs -f auth-server
```

### Metrics (Prometheus)

Available metrics:
- HTTP request duration và count
- OAuth token generation
- Database connection pool
- Redis operations
- System resources

### Dashboards (Grafana)

Pre-configured dashboards:
- Application performance
- OAuth flow metrics
- Database performance
- System resources

## Backup & Recovery

### Automated Backups

```bash
# Create backup
make backup

# Includes:
# - Database dump (compressed)
# - Configuration files
# - SSL certificates
```

### Restore Process

```bash
# List available backups
./scripts/restore.sh

# Restore database
make restore-db BACKUP_FILE=backups/database_backup_20240122_120000.sql.gz

# Restore configuration
make restore-config BACKUP_FILE=backups/config_backup_20240122_120000.tar.gz
```

### Backup Strategy

- **Frequency**: Daily automated backups
- **Retention**: 7 days local, longer in cloud storage
- **Verification**: Automatic backup validation
- **Recovery**: Tested restore procedures

## Performance Tuning

### PostgreSQL Optimization

Production settings:
```sql
max_connections = 200
shared_buffers = 256MB
effective_cache_size = 1GB
maintenance_work_mem = 64MB
checkpoint_completion_target = 0.9
wal_buffers = 16MB
```

### Redis Optimization

```conf
maxmemory 256mb
maxmemory-policy allkeys-lru
appendonly yes
appendfsync everysec
```

### Application Optimization

- Connection pooling
- Query optimization
- Caching strategies
- Resource limits

## Deployment Strategies

### Development Deployment

```bash
# Quick start
make quick-start

# Manual steps
make setup
make start
make health
```

### Staging Deployment

```bash
# Build production image
make build-prod

# Deploy with production config
docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

### Production Deployment

```bash
# With CI/CD pipeline
make deploy-prod

# Manual deployment
docker-compose -f docker-compose.prod.yml up -d --scale auth-server=3
```

## Troubleshooting

### Common Issues

#### 1. Database Connection Failed
```bash
# Check database status
docker-compose exec postgres pg_isready

# Check logs
docker-compose logs postgres

# Restart database
docker-compose restart postgres
```

#### 2. Auth Server Not Starting
```bash
# Check logs
make logs-auth

# Verify environment
make env-validate

# Check health
curl http://localhost:8080/health
```

#### 3. Redis Connection Issues
```bash
# Check Redis
docker-compose exec redis redis-cli ping

# Check password
docker-compose exec redis redis-cli -a $REDIS_PASSWORD ping
```

### Debug Mode

```bash
# Start in debug mode
GIN_MODE=debug LOG_LEVEL=debug make start-dev

# Access container shell
make shell

# Check configuration
docker-compose config
```

## Maintenance

### Regular Tasks

1. **Daily**:
   - Check service health
   - Review logs for errors
   - Monitor resource usage

2. **Weekly**:
   - Create backups
   - Update dependencies
   - Review security logs

3. **Monthly**:
   - Update base images
   - Review performance metrics
   - Test disaster recovery

### Updates

```bash
# Update images
docker-compose pull

# Rebuild application
make build

# Rolling update
docker-compose up -d --no-deps auth-server
```

## Support

### Getting Help

1. **Documentation**: Check this file và README.md
2. **Logs**: `make logs` để xem chi tiết
3. **Health Checks**: `make health` để verify services
4. **Configuration**: `make env-validate` để check config

### Useful Commands

```bash
# Quick reference
make help

# Service status
make status

# Generate new secrets
make generate-secret

# Test OAuth flow
make test-oauth
```

---

**Note**: Infrastructure này được thiết kế để scale từ development đến production với minimal changes. Tất cả configurations đều được externalized qua environment variables và có thể customize theo needs cụ thể.