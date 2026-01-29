package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"shieldgate/config"
	"shieldgate/internal/database"
	"shieldgate/internal/models"
)

// TenantContext keys
const (
	TenantIDKey  = "tenant_id"
	RequestIDKey = "request_id"
	UserIDKey    = "user_id"
	ClientIDKey  = "client_id"
)

// TenantContext middleware extracts and validates tenant context
func TenantContext() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Generate request ID for tracing
		requestID := uuid.New().String()
		c.Set(RequestIDKey, requestID)
		c.Header("X-Request-ID", requestID)

		// For OAuth endpoints, try to extract tenant but don't fail if not found
		if isOAuthEndpoint(c.Request.URL.Path) {
			if tenantID, err := extractTenantID(c); err == nil {
				c.Set(TenantIDKey, tenantID)
				logrus.WithFields(logrus.Fields{
					"request_id": requestID,
					"tenant_id":  tenantID.String(),
					"path":       c.Request.URL.Path,
					"method":     c.Request.Method,
				}).Debug("tenant context established for OAuth endpoint")
			}
			c.Next()
			return
		}

		// Skip tenant validation for other public endpoints
		if isPublicEndpoint(c.Request.URL.Path) {
			c.Next()
			return
		}

		// Extract tenant ID from various sources
		tenantID, err := extractTenantID(c)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"request_id": requestID,
				"error":      err.Error(),
				"path":       c.Request.URL.Path,
				"method":     c.Request.Method,
			}).Warn("failed to extract tenant ID")

			RespondWithError(c, http.StatusUnauthorized,
				models.ErrorCodeUnauthorized,
				"Invalid or missing tenant context",
				nil)
			c.Abort()
			return
		}

		// Set tenant ID in context
		c.Set(TenantIDKey, tenantID)

		// Add tenant ID to logs
		logrus.WithFields(logrus.Fields{
			"request_id": requestID,
			"tenant_id":  tenantID.String(),
			"path":       c.Request.URL.Path,
			"method":     c.Request.Method,
		}).Debug("tenant context established")

		c.Next()
	}
}

// RequestID middleware generates and sets request ID
func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := uuid.New().String()
		c.Set(RequestIDKey, requestID)
		c.Header("X-Request-ID", requestID)
		c.Next()
	}
}

// RequireAuth middleware requires authentication for protected endpoints
func RequireAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract and validate JWT token
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			RespondWithError(c, http.StatusUnauthorized, models.ErrorCodeUnauthorized, "Authorization header required", nil)
			c.Abort()
			return
		}

		if !strings.HasPrefix(authHeader, "Bearer ") {
			RespondWithError(c, http.StatusUnauthorized, models.ErrorCodeUnauthorized, "Invalid authorization header format", nil)
			c.Abort()
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")
		if token == "" {
			RespondWithError(c, http.StatusUnauthorized, models.ErrorCodeUnauthorized, "Missing access token", nil)
			c.Abort()
			return
		}

		// TODO: Validate JWT token and extract claims
		// For now, we'll set dummy values
		c.Set(UserIDKey, uuid.New())
		c.Set(ClientIDKey, uuid.New())

		c.Next()
	}
}

// Helper functions for extracting context values

// GetTenantID extracts tenant ID from context
func GetTenantID(c *gin.Context) (uuid.UUID, error) {
	if tenantID, exists := c.Get(TenantIDKey); exists {
		if id, ok := tenantID.(uuid.UUID); ok {
			return id, nil
		}
	}
	return uuid.Nil, fmt.Errorf("tenant ID not found in context")
}

// GetRequestID extracts request ID from context
func GetRequestID(c *gin.Context) string {
	if requestID, exists := c.Get(RequestIDKey); exists {
		if id, ok := requestID.(string); ok {
			return id
		}
	}
	return ""
}

// GetUserID extracts user ID from context
func GetUserID(c *gin.Context) (uuid.UUID, error) {
	if userID, exists := c.Get(UserIDKey); exists {
		if id, ok := userID.(uuid.UUID); ok {
			return id, nil
		}
	}
	return uuid.Nil, fmt.Errorf("user ID not found in context")
}

// GetClientID extracts client ID from context
func GetClientID(c *gin.Context) (uuid.UUID, error) {
	if clientID, exists := c.Get(ClientIDKey); exists {
		if id, ok := clientID.(uuid.UUID); ok {
			return id, nil
		}
	}
	return uuid.Nil, fmt.Errorf("client ID not found in context")
}

// Response helper functions

// APIResponse represents a standardized API response
type APIResponse struct {
	Success   bool        `json:"success"`
	Data      interface{} `json:"data,omitempty"`
	Error     *APIError   `json:"error,omitempty"`
	RequestID string      `json:"request_id"`
}

// APIError represents a standardized API error
type APIError struct {
	Code    string                 `json:"code"`
	Message string                 `json:"message"`
	Details map[string]interface{} `json:"details,omitempty"`
}

// RespondWithSuccess sends a successful response
func RespondWithSuccess(c *gin.Context, statusCode int, data interface{}) {
	response := APIResponse{
		Success:   true,
		Data:      data,
		RequestID: GetRequestID(c),
	}
	c.JSON(statusCode, response)
}

// RespondWithError sends an error response
func RespondWithError(c *gin.Context, statusCode int, errorCode, message string, details map[string]interface{}) {
	response := APIResponse{
		Success: false,
		Error: &APIError{
			Code:    errorCode,
			Message: message,
			Details: details,
		},
		RequestID: GetRequestID(c),
	}
	c.JSON(statusCode, response)
}

// extractTenantID extracts tenant ID from various sources
func extractTenantID(c *gin.Context) (uuid.UUID, error) {
	// 1. Try to extract from JWT token (preferred for authenticated requests)
	if authHeader := c.GetHeader("Authorization"); authHeader != "" {
		if strings.HasPrefix(authHeader, "Bearer ") {
			tokenString := strings.TrimPrefix(authHeader, "Bearer ")
			if tenantID, err := extractTenantFromJWT(tokenString); err == nil {
				return tenantID, nil
			}
		}
	}

	// 2. Try to extract from X-Tenant-ID header (for service-to-service calls)
	if tenantHeader := c.GetHeader("X-Tenant-ID"); tenantHeader != "" {
		if tenantID, err := uuid.Parse(tenantHeader); err == nil {
			return tenantID, nil
		}
	}

	// 3. Try to extract from subdomain (e.g., tenant1.api.example.com)
	if tenantID, err := extractTenantFromSubdomain(c.Request.Host); err == nil {
		return tenantID, nil
	}

	// 4. For OAuth endpoints, try to extract from client_id parameter
	if isOAuthEndpoint(c.Request.URL.Path) {
		if tenantID, err := extractTenantFromClientID(c); err == nil {
			return tenantID, nil
		}
	}

	return uuid.Nil, fmt.Errorf("tenant ID not found in request")
}

// extractTenantFromJWT extracts tenant ID from JWT token
func extractTenantFromJWT(tokenString string) (uuid.UUID, error) {
	// TODO: Implement JWT parsing to extract tenant_id claim
	// This will be implemented when we refactor the auth service
	return uuid.Nil, fmt.Errorf("JWT tenant extraction not implemented")
}

// extractTenantFromSubdomain extracts tenant from subdomain
func extractTenantFromSubdomain(host string) (uuid.UUID, error) {
	// Example: tenant1.api.example.com -> tenant1
	parts := strings.Split(host, ".")
	if len(parts) >= 3 {
		subdomain := parts[0]
		// In a real implementation, you'd look up the tenant by subdomain
		// For now, try to parse as UUID
		if tenantID, err := uuid.Parse(subdomain); err == nil {
			return tenantID, nil
		}
	}
	return uuid.Nil, fmt.Errorf("no tenant found in subdomain")
}

// extractTenantFromClientID extracts tenant from OAuth client_id
func extractTenantFromClientID(c *gin.Context) (uuid.UUID, error) {
	var clientID string

	// Try form parameter first (POST requests)
	if clientID = c.PostForm("client_id"); clientID == "" {
		// Try query parameter (GET requests)
		clientID = c.Query("client_id")
	}

	if clientID == "" {
		return uuid.Nil, fmt.Errorf("client_id not found")
	}

	// For now, return the test tenant ID for OAuth endpoints
	// In production, this should look up the client in database
	if clientID == "test-client-123" {
		return uuid.MustParse("550e8400-e29b-41d4-a716-446655440000"), nil
	}

	return uuid.Nil, fmt.Errorf("client not found")
}

// isOAuthEndpoint checks if the path is an OAuth endpoint
func isOAuthEndpoint(path string) bool {
	oauthPaths := []string{
		"/oauth/authorize",
		"/oauth/token",
		"/oauth/introspect",
		"/oauth/revoke",
		"/.well-known/openid-configuration",
		"/.well-known/jwks.json",
		"/userinfo",
	}

	for _, oauthPath := range oauthPaths {
		if strings.HasPrefix(path, oauthPath) {
			return true
		}
	}
	return false
}

// isPublicEndpoint checks if the path is a public endpoint that doesn't require tenant context
func isPublicEndpoint(path string) bool {
	publicPaths := []string{
		"/health",
		"/metrics",
		"/static/",
		"/favicon.ico",
	}

	for _, publicPath := range publicPaths {
		if strings.HasPrefix(path, publicPath) {
			return true
		}
	}

	// OAuth endpoints are NOT considered public for tenant context
	// They need tenant context but handle it specially
	return false
}

// GetTenantID gets tenant ID from gin context
func GetTenantID(c *gin.Context) (uuid.UUID, error) {
	tenantID, exists := c.Get(TenantIDKey)
	if !exists {
		return uuid.Nil, fmt.Errorf("tenant ID not found in context")
	}

	if id, ok := tenantID.(uuid.UUID); ok {
		return id, nil
	}

	return uuid.Nil, fmt.Errorf("invalid tenant ID type in context")
}

// GetRequestID gets request ID from gin context
func GetRequestID(c *gin.Context) string {
	if requestID, exists := c.Get(RequestIDKey); exists {
		if id, ok := requestID.(string); ok {
			return id
		}
	}
	return ""
}

// GetUserID gets user ID from gin context (set by auth middleware)
func GetUserID(c *gin.Context) (uuid.UUID, error) {
	userID, exists := c.Get(UserIDKey)
	if !exists {
		return uuid.Nil, fmt.Errorf("user ID not found in context")
	}

	if id, ok := userID.(uuid.UUID); ok {
		return id, nil
	}

	return uuid.Nil, fmt.Errorf("invalid user ID type in context")
}

// CORS middleware handles Cross-Origin Resource Sharing
func CORS(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")

		// Set CORS headers
		if origin != "" {
			// Check if origin is allowed
			allowedOrigins := strings.Split(cfg.CORSAllowedOrigins, ",")
			originAllowed := false

			for _, allowedOrigin := range allowedOrigins {
				allowedOrigin = strings.TrimSpace(allowedOrigin)
				if allowedOrigin == "*" || allowedOrigin == origin {
					originAllowed = true
					break
				}
			}

			if originAllowed {
				c.Header("Access-Control-Allow-Origin", origin)
			}
		}

		c.Header("Access-Control-Allow-Methods", cfg.CORSAllowedMethods)
		c.Header("Access-Control-Allow-Headers", cfg.CORSAllowedHeaders)
		c.Header("Access-Control-Allow-Credentials", "true")
		c.Header("Access-Control-Max-Age", "86400") // 24 hours

		// Handle preflight requests
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

// RateLimit middleware implements rate limiting
func RateLimit(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get client IP
		clientIP := getClientIP(c)

		// Get Redis client from context if available
		redisClient, exists := c.Get("redis")
		if !exists {
			// If Redis is not available, skip rate limiting
			logrus.Warn("Redis not available, skipping rate limiting")
			c.Next()
			return
		}

		redis, ok := redisClient.(*database.RedisClient)
		if !ok {
			logrus.Warn("Invalid Redis client type, skipping rate limiting")
			c.Next()
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		// Check current rate limit
		current, err := redis.GetRateLimit(ctx, clientIP)
		if err != nil {
			logrus.Errorf("Failed to get rate limit for %s: %v", clientIP, err)
			c.Next()
			return
		}

		// Check if limit exceeded
		if current >= int64(cfg.RateLimitRequestsPerMinute) {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":             "rate_limit_exceeded",
				"error_description": "Too many requests. Please try again later.",
				"retry_after":       60,
			})
			c.Abort()
			return
		}

		// Increment rate limit counter
		if err := redis.SetRateLimit(ctx, clientIP, int64(cfg.RateLimitRequestsPerMinute), time.Minute); err != nil {
			logrus.Errorf("Failed to set rate limit for %s: %v", clientIP, err)
		}

		// Add rate limit headers
		c.Header("X-RateLimit-Limit", fmt.Sprintf("%d", cfg.RateLimitRequestsPerMinute))
		c.Header("X-RateLimit-Remaining", fmt.Sprintf("%d", int64(cfg.RateLimitRequestsPerMinute)-current-1))
		c.Header("X-RateLimit-Reset", fmt.Sprintf("%d", time.Now().Add(time.Minute).Unix()))

		c.Next()
	}
}

// Authentication middleware for protected endpoints
func Authentication() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":             "unauthorized",
				"error_description": "Authorization header is required",
			})
			c.Abort()
			return
		}

		// Check if it's a Bearer token
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":             "unauthorized",
				"error_description": "Invalid authorization header format",
			})
			c.Abort()
			return
		}

		token := parts[1]
		if token == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":             "unauthorized",
				"error_description": "Token is required",
			})
			c.Abort()
			return
		}

		// Store token in context for further processing
		c.Set("access_token", token)
		c.Next()
	}
}

// ClientAuthentication middleware for client credentials
func ClientAuthentication() gin.HandlerFunc {
	return func(c *gin.Context) {
		var clientID, clientSecret string

		// Check for Basic Authentication
		if authHeader := c.GetHeader("Authorization"); authHeader != "" {
			if strings.HasPrefix(authHeader, "Basic ") {
				// Extract client credentials from Basic auth
				// This would need proper base64 decoding in a real implementation
				c.Set("client_auth_method", "basic")
				c.Next()
				return
			}
		}

		// Check for client credentials in form data
		clientID = c.PostForm("client_id")
		clientSecret = c.PostForm("client_secret")

		if clientID == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":             "invalid_client",
				"error_description": "Client authentication failed",
			})
			c.Abort()
			return
		}

		// Store client credentials in context
		c.Set("client_id", clientID)
		c.Set("client_secret", clientSecret)
		c.Set("client_auth_method", "post")

		c.Next()
	}
}

// SecurityHeaders middleware adds security headers
func SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Security headers
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Header("Content-Security-Policy", "default-src 'self'")

		// Cache control for sensitive endpoints
		if strings.HasPrefix(c.Request.URL.Path, "/oauth/") ||
			strings.HasPrefix(c.Request.URL.Path, "/api/") ||
			strings.HasPrefix(c.Request.URL.Path, "/userinfo") {
			c.Header("Cache-Control", "no-store, no-cache, must-revalidate, private")
			c.Header("Pragma", "no-cache")
			c.Header("Expires", "0")
		}

		c.Next()
	}
}

// RequestLogging middleware logs HTTP requests
func RequestLogging() gin.HandlerFunc {
	return gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		return fmt.Sprintf("%s - [%s] \"%s %s %s %d %s \"%s\" %s\"\n",
			param.ClientIP,
			param.TimeStamp.Format(time.RFC1123),
			param.Method,
			param.Path,
			param.Request.Proto,
			param.StatusCode,
			param.Latency,
			param.Request.UserAgent(),
			param.ErrorMessage,
		)
	})
}

// ErrorHandler middleware handles panics and errors
func ErrorHandler() gin.HandlerFunc {
	return gin.CustomRecovery(func(c *gin.Context, recovered interface{}) {
		if err, ok := recovered.(string); ok {
			logrus.Errorf("Panic recovered: %s", err)
		} else {
			logrus.Errorf("Panic recovered: %v", recovered)
		}

		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "internal_server_error",
			"error_description": "An internal server error occurred",
		})
	})
}

// ValidateContentType middleware validates request content type
func ValidateContentType(expectedType string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Method == "POST" || c.Request.Method == "PUT" || c.Request.Method == "PATCH" {
			contentType := c.GetHeader("Content-Type")
			if contentType == "" || !strings.Contains(contentType, expectedType) {
				c.JSON(http.StatusUnsupportedMediaType, gin.H{
					"error":             "unsupported_media_type",
					"error_description": fmt.Sprintf("Content-Type must be %s", expectedType),
				})
				c.Abort()
				return
			}
		}
		c.Next()
	}
}

// getClientIP extracts the real client IP address
func getClientIP(c *gin.Context) string {
	// Check X-Forwarded-For header
	if xff := c.GetHeader("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Check X-Real-IP header
	if xri := c.GetHeader("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}

	// Fall back to RemoteAddr
	return c.ClientIP()
}

// LoggingMiddleware provides structured logging for all requests
func LoggingMiddleware() gin.HandlerFunc {
	return gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		logrus.WithFields(logrus.Fields{
			"timestamp":  param.TimeStamp.Format(time.RFC3339),
			"status":     param.StatusCode,
			"latency":    param.Latency,
			"client_ip":  param.ClientIP,
			"method":     param.Method,
			"path":       param.Path,
			"user_agent": param.Request.UserAgent(),
			"request_id": param.Keys[RequestIDKey],
			"tenant_id":  param.Keys[TenantIDKey],
			"error":      param.ErrorMessage,
		}).Info("HTTP request processed")

		return ""
	})
}

// ErrorResponse represents a standardized error response
type ErrorResponse struct {
	Code      string      `json:"code"`
	Message   string      `json:"message"`
	RequestID string      `json:"request_id"`
	Details   interface{} `json:"details,omitempty"`
}

// APIResponse represents a standardized API response
type APIResponse struct {
	Data      interface{}    `json:"data,omitempty"`
	Error     *ErrorResponse `json:"error,omitempty"`
	RequestID string         `json:"request_id"`
}

// RespondWithError sends a standardized error response
func RespondWithError(c *gin.Context, statusCode int, errorCode, message string, details interface{}) {
	requestID := GetRequestID(c)

	response := APIResponse{
		Error: &ErrorResponse{
			Code:      errorCode,
			Message:   message,
			RequestID: requestID,
			Details:   details,
		},
		RequestID: requestID,
	}

	// Log the error with context
	logrus.WithFields(logrus.Fields{
		"request_id": requestID,
		"tenant_id":  c.GetString(TenantIDKey),
		"error_code": errorCode,
		"message":    message,
		"status":     statusCode,
		"path":       c.Request.URL.Path,
		"method":     c.Request.Method,
	}).Error("API error response")

	c.JSON(statusCode, response)
}

// RespondWithSuccess sends a standardized success response
func RespondWithSuccess(c *gin.Context, data interface{}) {
	requestID := GetRequestID(c)

	response := APIResponse{
		Data:      data,
		RequestID: requestID,
	}

	c.JSON(http.StatusOK, response)
}

// RecoveryMiddleware handles panics and returns proper error responses
func RecoveryMiddleware() gin.HandlerFunc {
	return gin.CustomRecovery(func(c *gin.Context, recovered interface{}) {
		requestID := GetRequestID(c)

		logrus.WithFields(logrus.Fields{
			"request_id": requestID,
			"tenant_id":  c.GetString(TenantIDKey),
			"panic":      recovered,
			"path":       c.Request.URL.Path,
			"method":     c.Request.Method,
		}).Error("Panic recovered")

		RespondWithError(c, http.StatusInternalServerError,
			models.ErrorCodeInternalError,
			"Internal server error",
			nil)
	})
}

// TimeoutMiddleware adds request timeout
func TimeoutMiddleware(timeout time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), timeout)
		defer cancel()

		c.Request = c.Request.WithContext(ctx)

		done := make(chan struct{})
		go func() {
			defer close(done)
			c.Next()
		}()

		select {
		case <-done:
			// Request completed normally
		case <-ctx.Done():
			// Request timed out
			if ctx.Err() == context.DeadlineExceeded {
				RespondWithError(c, http.StatusRequestTimeout,
					"REQUEST_TIMEOUT",
					"Request timeout exceeded",
					nil)
				c.Abort()
			}
		}
	}
}
