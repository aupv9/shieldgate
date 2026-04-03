# Configuration Migration Guide

## Overview

The Authorization Server configuration system has been migrated from environment variables to YAML-based configuration using Viper. This provides better organization, validation, and easier management of configuration settings.

## Migration from Environment Variables to YAML

### Before (Environment Variables)
```bash
export DATABASE_URL="postgres://authuser:password@localhost:5432/authdb?sslmode=disable"
export JWT_SECRET="your-super-secret-jwt-key-minimum-32-characters-long"
export PORT="8080"
export GIN_MODE="release"
# ... and many more environment variables
```

### After (YAML Configuration)
Create a `config.yaml` file in your project root:

```yaml
# Authorization Server Configuration

# Database configuration
database:
  url: "postgres://authuser:password@localhost:5432/authdb?sslmode=disable"

# Redis configuration
redis:
  url: ""

# Server configuration
server:
  url: "http://localhost:8080"
  port: "8080"
  gin_mode: "release"

# JWT configuration
jwt:
  secret: "your-super-secret-jwt-key-minimum-32-characters-long"

# Security configuration
security:
  bcrypt_cost: 12
  access_token_duration: 3600  # seconds
  refresh_token_duration: 2592000  # seconds (30 days)
  authorization_code_duration: 600  # seconds (10 minutes)

# CORS configuration
cors:
  allowed_origins: "*"
  allowed_methods: "GET,POST,PUT,DELETE,OPTIONS"
  allowed_headers: "Origin,Content-Type,Accept,Authorization"

# Rate limiting configuration
rate_limit:
  requests_per_minute: 60

# Logging configuration
logging:
  level: "info"
  format: "json"
```

## Configuration File Locations

The application will search for the configuration file in the following locations (in order):
1. Current directory (`./config.yaml`)
2. Config subdirectory (`./config/config.yaml`)
3. System config directory (`/etc/auth-server/config.yaml`)

## Environment Variable Override

Environment variables can still be used to override YAML configuration values. Viper automatically maps environment variables to configuration keys using the following pattern:

- YAML: `database.url` → Environment: `DATABASE_URL`
- YAML: `server.port` → Environment: `SERVER_PORT`
- YAML: `jwt.secret` → Environment: `JWT_SECRET`

## Configuration Mapping

| YAML Path | Environment Variable | Description |
|-----------|---------------------|-------------|
| `database.url` | `DATABASE_URL` | PostgreSQL connection string |
| `redis.url` | `REDIS_URL` | Redis connection string |
| `server.url` | `SERVER_URL` | Server base URL |
| `server.port` | `SERVER_PORT` | Server port |
| `server.gin_mode` | `SERVER_GIN_MODE` | Gin framework mode |
| `jwt.secret` | `JWT_SECRET` | JWT signing secret |
| `security.bcrypt_cost` | `SECURITY_BCRYPT_COST` | Bcrypt hashing cost |
| `security.access_token_duration` | `SECURITY_ACCESS_TOKEN_DURATION` | Access token duration (seconds) |
| `security.refresh_token_duration` | `SECURITY_REFRESH_TOKEN_DURATION` | Refresh token duration (seconds) |
| `security.authorization_code_duration` | `SECURITY_AUTHORIZATION_CODE_DURATION` | Auth code duration (seconds) |
| `cors.allowed_origins` | `CORS_ALLOWED_ORIGINS` | CORS allowed origins |
| `cors.allowed_methods` | `CORS_ALLOWED_METHODS` | CORS allowed methods |
| `cors.allowed_headers` | `CORS_ALLOWED_HEADERS` | CORS allowed headers |
| `rate_limit.requests_per_minute` | `RATE_LIMIT_REQUESTS_PER_MINUTE` | Rate limit per minute |
| `logging.level` | `LOGGING_LEVEL` | Log level |
| `logging.format` | `LOGGING_FORMAT` | Log format |

## Benefits of YAML Configuration

1. **Better Organization**: Hierarchical structure makes configuration easier to understand
2. **Comments**: YAML supports comments for documentation
3. **Type Safety**: Better handling of different data types
4. **Validation**: Easier to validate configuration structure
5. **Version Control**: Configuration files can be versioned and tracked
6. **Environment Specific**: Different config files for different environments

## Example Usage

### Development Environment
```yaml
# config.yaml
server:
  gin_mode: "debug"
logging:
  level: "debug"
  format: "text"
```

### Production Environment
```yaml
# config.yaml
server:
  gin_mode: "release"
logging:
  level: "info"
  format: "json"
security:
  bcrypt_cost: 14
```

## Backward Compatibility

The application still supports `.env` files for backward compatibility. The loading order is:
1. YAML configuration file
2. Environment variables (override YAML values)
3. `.env` file (if present)

## Error Handling

If the configuration file is not found, the application will:
1. Display a warning message
2. Use default values for all configuration options
3. Continue running normally

If the configuration file exists but contains errors:
1. The application will fail to start
2. Display a detailed error message
3. Exit with a non-zero status code

## Migration Checklist

- [ ] Create `config.yaml` file with your current configuration
- [ ] Test the application with the new configuration
- [ ] Update deployment scripts to use YAML configuration
- [ ] Update documentation and README files
- [ ] Remove old environment variable exports (optional)
- [ ] Update CI/CD pipelines if necessary