package middleware

import (
	"context"
	"net/http"
	"strings"

	"shieldgate/internal/models"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// ScopeKey is the gin context key under which the token scope string is stored.
const ScopeKey = "token_scope"

// PermissionChecker is the subset of PermissionService used by RequirePermission.
// Defined here to avoid an import cycle between middleware and services packages.
type PermissionChecker interface {
	HasPermission(ctx context.Context, tenantID, userID uuid.UUID, resource, action string) (bool, error)
}

// scopeEnforcer checks whether required is present as a space-delimited token in scope.
func scopeEnforcer(scope, required string) bool {
	for _, s := range strings.Fields(scope) {
		if s == required {
			return true
		}
	}
	return false
}

// RequireScope middleware enforces that the authenticated caller holds at least
// one of the listed OAuth 2.0 scopes. RequireAuth must run before this middleware
// so that "jwt_claims" is already set in the context.
//
// Example:
//
//	api.Use(middleware.RequireScope("admin"))
//	api.Use(middleware.RequireScope("read", "write"))  // any of these is sufficient
func RequireScope(requiredScopes ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		raw, exists := c.Get("jwt_claims")
		if !exists {
			RespondWithError(c, http.StatusUnauthorized,
				models.ErrorCodeUnauthorized,
				"Authentication required",
				nil)
			c.Abort()
			return
		}

		claims, ok := raw.(*models.JWTClaims)
		if !ok || claims == nil {
			RespondWithError(c, http.StatusUnauthorized,
				models.ErrorCodeUnauthorized,
				"Invalid token claims",
				nil)
			c.Abort()
			return
		}

		scope := claims.Scope
		c.Set(ScopeKey, scope)

		for _, req := range requiredScopes {
			if scopeEnforcer(scope, req) {
				c.Next()
				return
			}
		}

		logrus.WithFields(logrus.Fields{
			"user_id":        claims.UserID,
			"tenant_id":      claims.TenantID,
			"token_scope":    scope,
			"required_scope": requiredScopes,
			"path":           c.Request.URL.Path,
		}).Warn("scope enforcement: access denied")

		RespondWithError(c, http.StatusForbidden,
			models.ErrorCodeInsufficientPermissions,
			"Insufficient scope",
			nil)
		c.Abort()
	}
}

// RequirePermission middleware enforces fine-grained RBAC by delegating to
// PermissionChecker.HasPermission. It must run after RequireAuth.
//
// When checker is nil the middleware is a no-op — this lets routes be registered
// before the full RBAC data layer is available (Phase 2 merge) without breaking
// compilation or tests.
func RequirePermission(checker PermissionChecker, resource, action string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if checker == nil {
			logrus.WithFields(logrus.Fields{
				"resource": resource,
				"action":   action,
			}).Debug("RBAC: permission checker not configured, skipping enforcement")
			c.Next()
			return
		}

		tenantID, err := GetTenantID(c)
		if err != nil {
			RespondWithError(c, http.StatusUnauthorized,
				models.ErrorCodeUnauthorized,
				"Tenant context required",
				nil)
			c.Abort()
			return
		}

		userID, err := GetUserID(c)
		if err != nil {
			RespondWithError(c, http.StatusUnauthorized,
				models.ErrorCodeUnauthorized,
				"Authentication required",
				nil)
			c.Abort()
			return
		}

		allowed, err := checker.HasPermission(c.Request.Context(), tenantID, userID, resource, action)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"tenant_id": tenantID,
				"user_id":   userID,
				"resource":  resource,
				"action":    action,
				"error":     err.Error(),
			}).Error("RBAC: permission check failed")
			RespondWithError(c, http.StatusInternalServerError,
				models.ErrorCodeInternalError,
				"Permission check failed",
				nil)
			c.Abort()
			return
		}

		if !allowed {
			logrus.WithFields(logrus.Fields{
				"tenant_id": tenantID,
				"user_id":   userID,
				"resource":  resource,
				"action":    action,
				"path":      c.Request.URL.Path,
			}).Warn("RBAC: access denied")
			RespondWithError(c, http.StatusForbidden,
				models.ErrorCodePermissionDenied,
				"Permission denied",
				nil)
			c.Abort()
			return
		}

		c.Next()
	}
}
