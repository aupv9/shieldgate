package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"shieldgate/config"
	"shieldgate/internal/database"
	"shieldgate/internal/models"
	"shieldgate/internal/repo"
	"shieldgate/internal/services"
)

// TenantContext keys
const (
	TenantIDKey  = "tenant_id"
	RequestIDKey = "request_id"
	UserIDKey    = "user_id"
	ClientIDKey  = "client_id"
)

// TenantContext middleware extracts and validates tenant context
func TenantContext(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Generate request ID for tracing
		requestID := uuid.New().String()
		c.Set(RequestIDKey, requestID)
		c.Header("X-Request-ID", requestID)

		// For OAuth endpoints, try to extract tenant but don't fail if not found
		if isOAuthEndpoint(c.Request.URL.Path) {
			if tenantID, err := extractTenantID(c, cfg.JWTSecret); err == nil {
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

		// Skip tenant validation for public endpoints
		if isPublicEndpoint(c.Request.URL.Path) {
			c.Next()
			return
		}

		// Extract tenant ID from various sources
		tenantID, err := extractTenantID(c, cfg.JWTSecret)
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

// RequireAuth middleware validates JWT token, checks the token blacklist (DB),
// and sets user/client/tenant context.
//
// tokenRepo is optional. When provided, each request performs a DB lookup to
// verify the token has not been revoked via logout. Pass nil to skip that
// check (stateless JWT-only validation).
func RequireAuth(cfg *config.Config, tokenRepo repo.AccessTokenRepository) gin.HandlerFunc {
	return func(c *gin.Context) {
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

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == "" {
			RespondWithError(c, http.StatusUnauthorized, models.ErrorCodeUnauthorized, "Missing access token", nil)
			c.Abort()
			return
		}

		token, err := jwt.ParseWithClaims(tokenString, &models.JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(cfg.JWTSecret), nil
		})

		if err != nil || !token.Valid {
			RespondWithError(c, http.StatusUnauthorized, models.ErrorCodeUnauthorized, "Invalid or expired token", nil)
			c.Abort()
			return
		}

		claims, ok := token.Claims.(*models.JWTClaims)
		if !ok {
			RespondWithError(c, http.StatusUnauthorized, models.ErrorCodeUnauthorized, "Invalid token claims", nil)
			c.Abort()
			return
		}

		// Token blacklist check: verify the token was not revoked via logout.
		// CleanupExpiredTokens only removes tokens past their expires_at, so a
		// valid (non-expired) JWT that has been explicitly revoked will be absent
		// from the DB.
		if tokenRepo != nil {
			tenantID, tenantErr := uuid.Parse(claims.TenantID)
			if tenantErr == nil {
				if _, dbErr := tokenRepo.GetByToken(c.Request.Context(), tenantID, tokenString); dbErr != nil {
					RespondWithError(c, http.StatusUnauthorized, models.ErrorCodeUnauthorized, "Token has been revoked", nil)
					c.Abort()
					return
				}
			}
		}

		// Set authenticated context values from JWT claims
		if userID, err := uuid.Parse(claims.UserID); err == nil {
			c.Set(UserIDKey, userID)
		}
		if clientID, err := uuid.Parse(claims.ClientID); err == nil {
			c.Set(ClientIDKey, clientID)
		}
		if tenantID, err := uuid.Parse(claims.TenantID); err == nil {
			c.Set(TenantIDKey, tenantID)
		}

		c.Next()
	}
}

// RequirePermission middleware enforces that the authenticated user holds the
// specified resource+action permission via their assigned roles.
//
// RequireAuth must run before this middleware so that UserID and TenantID are
// set in the gin context.
func RequirePermission(permService services.PermissionService, resource, action string) gin.HandlerFunc {
	return func(c *gin.Context) {
		tenantID, err := GetTenantID(c)
		if err != nil {
			RespondWithError(c, http.StatusUnauthorized, models.ErrorCodeUnauthorized, "Invalid tenant context", nil)
			c.Abort()
			return
		}

		// uuid.Nil means the request came from a service account (client credentials)
		// — those are granted access without a role check.
		userID, _ := GetUserID(c)

		has, err := permService.HasPermission(c.Request.Context(), tenantID, userID, resource, action)
		if err != nil {
			logrus.WithError(err).WithFields(logrus.Fields{
				"tenant_id": tenantID,
				"user_id":   userID,
				"resource":  resource,
				"action":    action,
			}).Error("permission check failed")
			RespondWithError(c, http.StatusInternalServerError, models.ErrorCodeInternalError, "Permission check failed", nil)
			c.Abort()
			return
		}

		if !has {
			RespondWithError(c, http.StatusForbidden, models.ErrorCodePermissionDenied, "Insufficient permissions", nil)
			c.Abort()
			return
		}

		c.Next()
	}
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

// GetUserID gets user ID from gin context (set by RequireAuth middleware)
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

// GetClientID gets client ID from gin context (set by RequireAuth middleware)
func GetClientID(c *gin.Context) (uuid.UUID, error) {
	clientID, exists := c.Get(ClientIDKey)
	if !exists {
		return uuid.Nil, fmt.Errorf("client ID not found in context")
	}
	if id, ok := clientID.(uuid.UUID); ok {
		return id, nil
	}
	return uuid.Nil, fmt.Errorf("invalid client ID type in context")
}

// extractTenantID extracts tenant ID from various request sources
func extractTenantID(c *gin.Context, jwtSecret string) (uuid.UUID, error) {
	// 1. Try to extract from JWT token (preferred for authenticated requests)
	if authHeader := c.GetHeader("Authorization"); authHeader != "" {
		if strings.HasPrefix(authHeader, "Bearer ") {
			tokenString := strings.TrimPrefix(authHeader, "Bearer ")
			if tenantID, err := extractTenantFromJWT(tokenString, jwtSecret); err == nil {
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

	// 3. Try to extract from subdomain (e.g., <uuid>.api.example.com)
	if tenantID, err := extractTenantFromSubdomain(c.Request.Host); err == nil {
		return tenantID, nil
	}

	return uuid.Nil, fmt.Errorf("tenant ID not found in request")
}

// extractTenantFromJWT parses a JWT token and extracts the tenant_id claim
func extractTenantFromJWT(tokenString, jwtSecret string) (uuid.UUID, error) {
	token, err := jwt.ParseWithClaims(tokenString, &models.JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(jwtSecret), nil
	})
	if err != nil || !token.Valid {
		return uuid.Nil, fmt.Errorf("invalid token")
	}

	claims, ok := token.Claims.(*models.JWTClaims)
	if !ok || claims.TenantID == "" {
		return uuid.Nil, fmt.Errorf("tenant_id claim not found in token")
	}

	return uuid.Parse(claims.TenantID)
}

// extractTenantFromSubdomain extracts tenant from UUID-based subdomains
func extractTenantFromSubdomain(host string) (uuid.UUID, error) {
	parts := strings.Split(host, ".")
	if len(parts) >= 3 {
		if tenantID, err := uuid.Parse(parts[0]); err == nil {
			return tenantID, nil
		}
	}
	return uuid.Nil, fmt.Errorf("no tenant found in subdomain")
}

// isOAuthEndpoint checks if the path is an OAuth/OIDC endpoint
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

// isPublicEndpoint checks if the path requires no tenant context
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
	return false
}

// CORS middleware handles Cross-Origin Resource Sharing
func CORS(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")

		if origin != "" {
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
		c.Header("Access-Control-Max-Age", "86400")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

// RateLimit middleware implements per-IP rate limiting via Redis.
//
// Fail-closed behaviour: if redisClient is non-nil (rate limiting is
// configured) but the Redis operation returns an error, the request is
// rejected with 503 rather than being silently allowed through. This prevents
// an attacker from taking Redis offline to bypass rate-limiting.
//
// If redisClient is nil (Redis not configured) the middleware logs a one-time
// warning at startup and passes all requests through without limiting.
func RateLimit(cfg *config.Config, redisClient *database.RedisClient) gin.HandlerFunc {
	if redisClient == nil {
		logrus.Warn("Redis not configured — rate limiting is disabled")
		return func(c *gin.Context) { c.Next() }
	}

	return func(c *gin.Context) {
		clientIP := getClientIP(c)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		current, err := redisClient.GetRateLimit(ctx, clientIP)
		if err != nil {
			logrus.WithError(err).Errorf("rate limit check failed for %s — rejecting request (fail-closed)", clientIP)
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"error":             "service_unavailable",
				"error_description": "Rate limiting service is temporarily unavailable. Please try again later.",
			})
			c.Abort()
			return
		}

		if current >= int64(cfg.RateLimitRequestsPerMinute) {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":             "rate_limit_exceeded",
				"error_description": "Too many requests. Please try again later.",
				"retry_after":       60,
			})
			c.Abort()
			return
		}

		if err := redisClient.SetRateLimit(ctx, clientIP, int64(cfg.RateLimitRequestsPerMinute), time.Minute); err != nil {
			logrus.WithError(err).Errorf("rate limit increment failed for %s — rejecting request (fail-closed)", clientIP)
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"error":             "service_unavailable",
				"error_description": "Rate limiting service is temporarily unavailable. Please try again later.",
			})
			c.Abort()
			return
		}

		c.Header("X-RateLimit-Limit", fmt.Sprintf("%d", cfg.RateLimitRequestsPerMinute))
		c.Header("X-RateLimit-Remaining", fmt.Sprintf("%d", int64(cfg.RateLimitRequestsPerMinute)-current-1))
		c.Header("X-RateLimit-Reset", fmt.Sprintf("%d", time.Now().Add(time.Minute).Unix()))

		c.Next()
	}
}

// Authentication middleware stores Bearer token in context for downstream use
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

		c.Set("access_token", token)
		c.Next()
	}
}

// ClientAuthentication middleware extracts client credentials from request
func ClientAuthentication() gin.HandlerFunc {
	return func(c *gin.Context) {
		if authHeader := c.GetHeader("Authorization"); authHeader != "" {
			if strings.HasPrefix(authHeader, "Basic ") {
				c.Set("client_auth_method", "basic")
				c.Next()
				return
			}
		}

		clientID := c.PostForm("client_id")
		clientSecret := c.PostForm("client_secret")

		if clientID == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":             "invalid_client",
				"error_description": "Client authentication failed",
			})
			c.Abort()
			return
		}

		c.Set("client_id", clientID)
		c.Set("client_secret", clientSecret)
		c.Set("client_auth_method", "post")

		c.Next()
	}
}

// SecurityHeaders middleware adds security-related HTTP headers
func SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Header("Content-Security-Policy", "default-src 'self'")

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

// RequestLogging middleware logs HTTP requests using Gin's built-in logger
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

// ErrorHandler middleware handles panics and returns a JSON error response
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

// ValidateContentType middleware enforces a specific Content-Type on mutating requests
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

// LoggingMiddleware provides structured logging for all requests via Logrus
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

// RecoveryMiddleware handles panics and returns standardized error responses
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

// TimeoutMiddleware cancels requests that exceed the given duration
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
		case <-ctx.Done():
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

// getClientIP extracts the real client IP, respecting proxy headers
func getClientIP(c *gin.Context) string {
	if xff := c.GetHeader("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}
	if xri := c.GetHeader("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}
	return c.ClientIP()
}
