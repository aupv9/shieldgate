package middleware

import (
	"net/http"
	"strings"

	"shieldgate/internal/models"
	"shieldgate/internal/services"

	"github.com/gin-gonic/gin"
)

// APIKeyAuth returns a middleware that authenticates requests using an API key.
// It accepts the key via the X-API-Key header or the api_key query parameter.
// On success it sets UserIDKey and TenantIDKey in the gin context.
func APIKeyAuth(apiKeySvc services.APIKeyService) gin.HandlerFunc {
	return func(c *gin.Context) {
		rawKey := extractAPIKey(c)
		if rawKey == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "API key required",
				"code":  models.ErrorCodeUnauthorized,
			})
			return
		}

		apiKey, err := apiKeySvc.Validate(c.Request.Context(), rawKey)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "invalid or revoked API key",
				"code":  models.ErrorCodeUnauthorized,
			})
			return
		}

		c.Set(TenantIDKey, apiKey.TenantID)
		if apiKey.UserID != nil {
			c.Set(UserIDKey, *apiKey.UserID)
		}
		c.Set("api_key_id", apiKey.ID)
		c.Next()
	}
}

// RequireAuthOrAPIKey accepts either a JWT Bearer token or an API key.
// It tries JWT first; if absent or invalid it falls back to X-API-Key.
func RequireAuthOrAPIKey(cfg interface{ GetJWTSecret() string }, apiKeySvc services.APIKeyService) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check for Bearer token first
		authHeader := c.GetHeader("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") {
			c.Next()
			return
		}

		// Fall back to API key
		rawKey := extractAPIKey(c)
		if rawKey == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "authentication required (Bearer token or X-API-Key)",
				"code":  models.ErrorCodeUnauthorized,
			})
			return
		}

		apiKey, err := apiKeySvc.Validate(c.Request.Context(), rawKey)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "invalid or revoked API key",
				"code":  models.ErrorCodeUnauthorized,
			})
			return
		}

		c.Set(TenantIDKey, apiKey.TenantID)
		if apiKey.UserID != nil {
			c.Set(UserIDKey, *apiKey.UserID)
		}
		c.Set("api_key_id", apiKey.ID)
		c.Next()
	}
}

func extractAPIKey(c *gin.Context) string {
	if key := c.GetHeader("X-API-Key"); key != "" {
		return key
	}
	return c.Query("api_key")
}
