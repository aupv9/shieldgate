package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"

	"shield1/config"
	"shield1/internal/database"
)

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