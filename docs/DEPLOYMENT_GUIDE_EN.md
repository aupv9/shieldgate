# ShieldGate Deployment Guide (English Summary)

> **Note**: This is an English summary of the comprehensive Vietnamese deployment guide. For complete details, refer to [Hướng dẫn Triển khai và Sử dụng Authorization Server.md](Hướng%20dẫn%20Triển%20khai%20và%20Sử%20dụng%20Authorization%20Server.md).

## Overview

This guide provides comprehensive instructions for deploying and using the ShieldGate Authorization Server in production environments. The server is designed to provide centralized authentication and authorization services following OAuth 2.0 and OpenID Connect standards.

## System Requirements

### Minimum Hardware Requirements
- **CPU**: 2 cores minimum, 4+ cores recommended
- **RAM**: 2GB minimum, 4GB+ recommended  
- **Storage**: 20GB SSD minimum
- **Network**: Stable internet connection with 100Mbps+ bandwidth

### Software Requirements
- **OS**: Linux (Ubuntu 20.04+, CentOS 8+, or equivalent)
- **Docker**: Version 20.10+ (recommended deployment method)
- **Docker Compose**: Version 2.0+
- **PostgreSQL**: Version 13+ (if not using Docker)
- **Redis**: Version 6+ (optional, for caching)

### Development Environment
- **Go**: Version 1.21+
- **Git**: For source code management
- **Postman or curl**: For API testing

## Deployment Methods

### Method 1: Docker Compose (Recommended)

This is the simplest way to deploy the Authorization Server with all required dependencies.

#### Step 1: Environment Setup
```bash
mkdir -p /opt/authorization-server
cd /opt/authorization-server
git clone <repository-url> .
```

#### Step 2: Configuration
```bash
cp .env.example .env
# Edit .env with your environment-specific values
```

Key configuration values:
```bash
DATABASE_URL=postgres://authuser:secure_password@postgres:5432/authdb?sslmode=disable
JWT_SECRET=your-super-secret-jwt-key-minimum-32-characters-long
SERVER_URL=https://your-domain.com
PORT=8080
REDIS_URL=redis://redis:6379
```

#### Step 3: Start Services
```bash
docker-compose up -d
```

This will:
- Create and start PostgreSQL database
- Create and start Redis cache
- Build and start the Authorization Server
- Set up networking between containers

#### Step 4: Verify Installation
```bash
# Check service status
docker-compose ps

# Test health endpoint
curl http://localhost:8080/health

# Check logs
docker-compose logs auth-server
```

### Method 2: Manual Installation

For development or custom deployment scenarios.

#### Prerequisites Installation
```bash
# Install Go
wget https://golang.org/dl/go1.21.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin

# Install PostgreSQL
sudo apt update
sudo apt install postgresql postgresql-contrib

# Install Redis (optional)
sudo apt install redis-server
```

#### Application Setup
```bash
# Clone and build
git clone <repository-url>
cd shieldgate
go mod download
go build -o auth-server cmd/auth-server/main.go

# Configure
cp config.yaml.example config.yaml
# Edit config.yaml with your settings

# Run
./auth-server
```

## Configuration Management

The application supports both YAML configuration files and environment variables. Configuration is loaded in this order:

1. YAML configuration file
2. Environment variables (override YAML)
3. `.env` file (if present)

### Configuration File Locations
1. `./config.yaml`
2. `./config/config.yaml`
3. `/etc/auth-server/config.yaml`

## Client Management

### Registering OAuth Clients
```bash
curl -X POST http://localhost:8080/api/v1/clients \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My Application",
    "redirect_uris": ["https://myapp.com/callback"],
    "grant_types": ["authorization_code", "refresh_token"],
    "scopes": ["read", "write", "openid"],
    "is_public": false
  }'
```

### Client Types
- **Confidential Clients**: Web applications that can securely store client secrets
- **Public Clients**: Mobile apps and SPAs that cannot securely store secrets

## User Management

### User Registration
```bash
curl -X POST http://localhost:8080/api/v1/users \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john_doe",
    "email": "john@example.com",
    "password": "secure_password123"
  }'
```

### User Authentication
Users authenticate through the OAuth 2.0 authorization flow or direct login endpoints.

## OAuth 2.0 Integration

### Supported Grant Types
- **Authorization Code**: For web applications
- **Authorization Code with PKCE**: For mobile and SPA applications
- **Client Credentials**: For service-to-service authentication
- **Refresh Token**: For token renewal

### Example Authorization Flow
1. Redirect user to authorization endpoint
2. User authenticates and grants permission
3. Authorization server redirects back with authorization code
4. Exchange authorization code for access token
5. Use access token to access protected resources

## OpenID Connect Integration

### Supported Features
- **ID Tokens**: JWT tokens containing user identity information
- **UserInfo Endpoint**: Retrieve user profile information
- **Discovery Endpoint**: Automatic configuration discovery
- **Standard Claims**: Support for standard OIDC claims

### Discovery Endpoint
```bash
curl http://localhost:8080/.well-known/openid-configuration
```

## Security Features

### Built-in Security Measures
- **HTTPS/TLS**: Mandatory for all communications
- **PKCE**: Protection against authorization code interception
- **JWT Tokens**: Secure, stateless token format
- **Password Hashing**: bcrypt with configurable cost
- **Rate Limiting**: Protection against brute-force attacks
- **CORS**: Configurable cross-origin policies
- **Input Validation**: Comprehensive request validation
- **Audit Logging**: Security event logging

### Security Best Practices
- Use strong, unique JWT secrets
- Enable HTTPS in production
- Implement proper CORS policies
- Regular security updates
- Monitor and audit access logs

## Monitoring and Logging

### Health Monitoring
```bash
# Health check endpoint
curl http://localhost:8080/health

# Metrics endpoint (if enabled)
curl http://localhost:8080/metrics
```

### Log Management
- Structured JSON logging
- Configurable log levels
- Request/response logging
- Security event logging
- Performance metrics

### Integration with Monitoring Tools
- Prometheus metrics support
- Grafana dashboard templates
- ELK stack compatibility
- Custom alerting rules

## Troubleshooting

### Common Issues

#### Database Connection Issues
```bash
# Check database connectivity
docker-compose exec postgres psql -U authuser -d authdb -c "SELECT 1;"

# Check database logs
docker-compose logs postgres
```

#### Token Validation Errors
- Verify JWT secret configuration
- Check token expiration settings
- Validate client credentials

#### Performance Issues
- Enable Redis caching
- Check database query performance
- Monitor resource usage
- Scale horizontally if needed

### Debug Mode
```bash
# Enable debug logging
export LOGGING_LEVEL=debug
# or in config.yaml:
logging:
  level: debug
```

## Production Deployment

### Load Balancing
- Use reverse proxy (nginx, HAProxy)
- Implement health checks
- Configure SSL termination
- Set up session affinity if needed

### Database Optimization
- Connection pooling
- Read replicas for scaling
- Regular maintenance and backups
- Performance monitoring

### Security Hardening
- Regular security updates
- Network segmentation
- Access control policies
- Security scanning

### Backup and Recovery
- Database backups
- Configuration backups
- Disaster recovery procedures
- Testing recovery processes

## API Reference

### Core Endpoints
- `GET /health` - Health check
- `GET /oauth/authorize` - Authorization endpoint
- `POST /oauth/token` - Token endpoint
- `POST /oauth/introspect` - Token introspection
- `POST /oauth/revoke` - Token revocation
- `GET /.well-known/openid-configuration` - OIDC discovery
- `GET /userinfo` - User information

### Management Endpoints
- `POST /api/v1/clients` - Create client
- `GET /api/v1/clients/{id}` - Get client
- `PUT /api/v1/clients/{id}` - Update client
- `DELETE /api/v1/clients/{id}` - Delete client
- `POST /api/v1/users` - Create user
- `GET /api/v1/users/{id}` - Get user
- `PUT /api/v1/users/{id}` - Update user
- `DELETE /api/v1/users/{id}` - Delete user

## Support and Maintenance

### Regular Maintenance Tasks
- Database cleanup of expired tokens
- Log rotation and archival
- Security updates
- Performance monitoring
- Backup verification

### Getting Help
- Check the comprehensive Vietnamese documentation for detailed information
- Review API documentation and examples
- Monitor application logs for errors
- Use health check endpoints for status verification

---

**Note**: This is a summary of the main deployment concepts. For complete step-by-step instructions, detailed configuration options, and advanced topics, please refer to the full Vietnamese documentation.