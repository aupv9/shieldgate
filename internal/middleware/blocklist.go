package middleware

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"shieldgate/internal/models"
)

// TokenBlocklistChecker is the minimal interface required by TokenRevocationCheck.
// Using a local interface keeps this package decoupled from the blocklist package.
type TokenBlocklistChecker interface {
	IsBlocked(ctx context.Context, token string) (bool, error)
}

// TokenRevocationCheck rejects requests carrying an explicitly revoked JWT.
// Apply this middleware after RequireAuth in the chain.
func TokenRevocationCheck(bl TokenBlocklistChecker) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			c.Next()
			return
		}
		token := strings.TrimPrefix(authHeader, "Bearer ")
		ctx, cancel := context.WithTimeout(c.Request.Context(), 100*time.Millisecond)
		defer cancel()
		blocked, err := bl.IsBlocked(ctx, token)
		if err == nil && blocked {
			RespondWithError(c, http.StatusUnauthorized, models.ErrorCodeUnauthorized, "Token has been revoked", nil)
			c.Abort()
			return
		}
		c.Next()
	}
}
