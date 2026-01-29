# Deployment & Operations Guide

## Development Environment Setup

### Local Development với Docker Compose
```bash
# Clone và setup
git clone <repository-url>
cd shieldgate
cp .env.example .env

# Edit .env với local configuration
# Start services
docker-compose up -d

# Verify health
curl http://localhost:8080/health
```

### Manual Development Setup
```bash
# Install Go dependencies
go mod download

# Setup PostgreSQL database
createdb authdb
psql authdb < migrations/init.sql

# Setup Redis (optional)
redis-server

# Configure application
cp config.yaml.example config.yaml
# Edit config.yaml với database connections

# Run application
go run cmd/auth-server/main.go
```

## Configuration Management

### Environment Variables Priority
1. Command line flags
2. Environment variables
3. config.yaml file
4. Default values

### Critical Configuration Items
```yaml
# Database - REQUIRED
database:
  url: "postgres://user:pass@localhost:5432/authdb?sslmode=disable"

# Server - REQUIRED  
server:
  url: "https://auth.yourdomain.com"  # Must be HTTPS in production
  port: "8080"
  gin_mode: "release"  # "debug" for development

# JWT - REQUIRED
jwt:
  secret: "your-super-secret-jwt-key-minimum-32-characters-long"

# Security - REQUIRED
security:
  bcrypt_cost: 12  # Higher for production
  access_token_duration: 3600    # 1 hour
  refresh_token_duration: 2592000 # 30 days

# Redis - OPTIONAL
redis:
  url: "redis://localhost:6379"
  password: ""
  db: 0
```

### Environment-Specific Configurations
```bash
# Development
export GIN_MODE=debug
export LOG_LEVEL=debug
export JWT_SECRET=dev-secret-key-32-chars-minimum

# Staging
export GIN_MODE=release
export LOG_LEVEL=info
export JWT_SECRET=staging-secret-key-from-vault

# Production
export GIN_MODE=release
export LOG_LEVEL=warn
export JWT_SECRET=production-secret-from-vault
export DATABASE_URL=postgres://...
export REDIS_URL=redis://...
```

## Docker Deployment

### Production Dockerfile
```dockerfile
FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main cmd/auth-server/main.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/

COPY --from=builder /app/main .
COPY --from=builder /app/templates ./templates/
COPY --from=builder /app/config.yaml ./

CMD ["./main"]
```

### Docker Compose Production
```yaml
version: '3.8'

services:
  auth-server:
    build: .
    ports:
      - "8080:8080"
    environment:
      - DATABASE_URL=postgres://authuser:${DB_PASSWORD}@postgres:5432/authdb?sslmode=disable
      - REDIS_URL=redis://redis:6379
      - JWT_SECRET=${JWT_SECRET}
      - GIN_MODE=release
    depends_on:
      - postgres
      - redis
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  postgres:
    image: postgres:13
    environment:
      - POSTGRES_DB=authdb
      - POSTGRES_USER=authuser
      - POSTGRES_PASSWORD=${DB_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./migrations:/docker-entrypoint-initdb.d
    restart: unless-stopped

  redis:
    image: redis:6-alpine
    restart: unless-stopped
    volumes:
      - redis_data:/data

volumes:
  postgres_data:
  redis_data:
```

## Kubernetes Deployment

### Deployment Manifest
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: shieldgate-auth
  labels:
    app: shieldgate-auth
spec:
  replicas: 3
  selector:
    matchLabels:
      app: shieldgate-auth
  template:
    metadata:
      labels:
        app: shieldgate-auth
    spec:
      containers:
      - name: auth-server
        image: shieldgate/auth-server:latest
        ports:
        - containerPort: 8080
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: auth-secrets
              key: database-url
        - name: JWT_SECRET
          valueFrom:
            secretKeyRef:
              name: auth-secrets
              key: jwt-secret
        - name: REDIS_URL
          value: "redis://redis-service:6379"
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
        resources:
          requests:
            memory: "128Mi"
            cpu: "100m"
          limits:
            memory: "512Mi"
            cpu: "500m"
---
apiVersion: v1
kind: Service
metadata:
  name: auth-service
spec:
  selector:
    app: shieldgate-auth
  ports:
  - protocol: TCP
    port: 80
    targetPort: 8080
  type: ClusterIP
```

## Monitoring & Observability

### Health Check Endpoint
```go
func (h *HealthHandler) CheckHealth(c *gin.Context) {
    health := gin.H{
        "status": "healthy",
        "timestamp": time.Now().UTC(),
        "version": version.Version,
    }
    
    // Check database connection
    if err := h.db.Ping(); err != nil {
        health["status"] = "unhealthy"
        health["database"] = "disconnected"
        c.JSON(503, health)
        return
    }
    health["database"] = "connected"
    
    // Check Redis connection (if configured)
    if h.redis != nil {
        if err := h.redis.Ping(context.Background()).Err(); err != nil {
            health["redis"] = "disconnected"
        } else {
            health["redis"] = "connected"
        }
    }
    
    c.JSON(200, health)
}
```

### Prometheus Metrics
```go
var (
    httpRequestsTotal = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "http_requests_total",
            Help: "Total number of HTTP requests",
        },
        []string{"method", "endpoint", "status"},
    )
    
    tokenGenerationTotal = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "oauth_tokens_generated_total",
            Help: "Total number of OAuth tokens generated",
        },
        []string{"grant_type", "client_id"},
    )
    
    authenticationAttempts = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "authentication_attempts_total",
            Help: "Total number of authentication attempts",
        },
        []string{"result"},
    )
)

func init() {
    prometheus.MustRegister(httpRequestsTotal)
    prometheus.MustRegister(tokenGenerationTotal)
    prometheus.MustRegister(authenticationAttempts)
}
```

### Structured Logging
```go
func setupLogger() *logrus.Logger {
    logger := logrus.New()
    
    // Set log format
    logger.SetFormatter(&logrus.JSONFormatter{
        TimestampFormat: time.RFC3339,
    })
    
    // Set log level based on environment
    level, err := logrus.ParseLevel(os.Getenv("LOG_LEVEL"))
    if err != nil {
        level = logrus.InfoLevel
    }
    logger.SetLevel(level)
    
    return logger
}

// Security event logging
func (s *AuthService) logSecurityEvent(event string, userID, clientID, details string) {
    s.logger.WithFields(logrus.Fields{
        "event_type": "security",
        "event":      event,
        "user_id":    userID,
        "client_id":  clientID,
        "details":    details,
        "timestamp":  time.Now().UTC(),
        "ip_address": s.getClientIP(),
    }).Warn("Security event occurred")
}
```

## Security Operations

### SSL/TLS Configuration
```go
func setupTLSServer(addr string, handler http.Handler) *http.Server {
    tlsConfig := &tls.Config{
        MinVersion:               tls.VersionTLS12,
        CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
        PreferServerCipherSuites: true,
        CipherSuites: []uint16{
            tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
            tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        },
    }
    
    server := &http.Server{
        Addr:         addr,
        Handler:      handler,
        TLSConfig:    tlsConfig,
        ReadTimeout:  15 * time.Second,
        WriteTimeout: 15 * time.Second,
        IdleTimeout:  60 * time.Second,
    }
    
    return server
}
```

### Secret Management
```bash
# Using Kubernetes Secrets
kubectl create secret generic auth-secrets \
  --from-literal=jwt-secret="your-super-secret-jwt-key" \
  --from-literal=database-url="postgres://..." \
  --from-literal=redis-url="redis://..."

# Using HashiCorp Vault
vault kv put secret/shieldgate \
  jwt_secret="your-super-secret-jwt-key" \
  database_url="postgres://..." \
  redis_url="redis://..."
```

## Backup & Recovery

### Database Backup
```bash
# Daily backup script
#!/bin/bash
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/backups"
DB_NAME="authdb"

# Create backup
pg_dump $DB_NAME > $BACKUP_DIR/authdb_backup_$DATE.sql

# Compress backup
gzip $BACKUP_DIR/authdb_backup_$DATE.sql

# Remove backups older than 30 days
find $BACKUP_DIR -name "authdb_backup_*.sql.gz" -mtime +30 -delete

# Upload to S3 (optional)
aws s3 cp $BACKUP_DIR/authdb_backup_$DATE.sql.gz s3://your-backup-bucket/
```

### Disaster Recovery
```bash
# Restore from backup
gunzip authdb_backup_20240122_120000.sql.gz
psql authdb < authdb_backup_20240122_120000.sql

# Verify data integrity
psql authdb -c "SELECT COUNT(*) FROM users;"
psql authdb -c "SELECT COUNT(*) FROM clients;"
```

## Performance Tuning

### Database Optimization
```sql
-- Add indexes for performance
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_clients_client_id ON clients(client_id);
CREATE INDEX idx_access_tokens_token ON access_tokens(token);
CREATE INDEX idx_authorization_codes_code ON authorization_codes(code);
CREATE INDEX idx_authorization_codes_expires_at ON authorization_codes(expires_at);

-- Cleanup expired tokens (run periodically)
DELETE FROM access_tokens WHERE expires_at < NOW();
DELETE FROM authorization_codes WHERE expires_at < NOW();
DELETE FROM refresh_tokens WHERE expires_at < NOW();
```

### Connection Pool Configuration
```go
func setupDatabase(databaseURL string) (*gorm.DB, error) {
    db, err := gorm.Open(postgres.Open(databaseURL), &gorm.Config{})
    if err != nil {
        return nil, err
    }
    
    sqlDB, err := db.DB()
    if err != nil {
        return nil, err
    }
    
    // Configure connection pool
    sqlDB.SetMaxIdleConns(10)
    sqlDB.SetMaxOpenConns(100)
    sqlDB.SetConnMaxLifetime(time.Hour)
    
    return db, nil
}
```