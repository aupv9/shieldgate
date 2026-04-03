# Multi-stage build for production optimization
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build \
    -a -installsuffix cgo \
    -ldflags '-extldflags "-static"' \
    -o main cmd/auth-server/main.go

# Production stage
FROM alpine:latest AS production

# Install runtime dependencies
RUN apk --no-cache add ca-certificates curl tzdata && \
    addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup

# Set timezone
ENV TZ=UTC

# Create app directory
WORKDIR /app

# Copy binary from builder stage
COPY --from=builder /app/main .

# Copy templates and static files
COPY --from=builder /app/templates ./templates/
COPY --from=builder /app/static ./static/

# Create logs directory
RUN mkdir -p logs && chown -R appuser:appgroup /app

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Run the application
CMD ["./main"]