package middleware

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"shieldgate/internal/models"
)

// PermissionChecker resolves whether a user holds a permission through RBAC.
// services.PermissionService satisfies it.
type PermissionChecker interface {
	HasPermission(ctx context.Context, tenantID, userID uuid.UUID, resource, action string) (bool, error)
}

// Authorizer builds per-route authorization middleware. It must run after
// RequireAuth, which populates the user and tenant context it reads.
//
// Super admins (configured by user ID) bypass every check and are the only
// principals allowed on cross-tenant resources such as tenants and the global
// permission catalog. Tokens without a user (client_credentials) are denied.
type Authorizer struct {
	checker     PermissionChecker
	superAdmins map[uuid.UUID]struct{}
	logger      *logrus.Logger
}

// NewAuthorizer creates an Authorizer backed by the given permission checker
func NewAuthorizer(checker PermissionChecker, superAdminIDs []uuid.UUID, logger *logrus.Logger) *Authorizer {
	superAdmins := make(map[uuid.UUID]struct{}, len(superAdminIDs))
	for _, id := range superAdminIDs {
		superAdmins[id] = struct{}{}
	}
	return &Authorizer{checker: checker, superAdmins: superAdmins, logger: logger}
}

// Require allows the request when the user holds resource/action in its tenant
func (a *Authorizer) Require(resource, action string) gin.HandlerFunc {
	return a.authorize(resource, action, "")
}

// RequireOrSelf behaves like Require but also allows the request when the
// user ID in path parameter userParam is the caller's own ID
func (a *Authorizer) RequireOrSelf(resource, action, userParam string) gin.HandlerFunc {
	return a.authorize(resource, action, userParam)
}

// RequireSuperAdmin allows only configured super admins
func (a *Authorizer) RequireSuperAdmin() gin.HandlerFunc {
	return a.authorize("", "", "")
}

func (a *Authorizer) authorize(resource, action, selfParam string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, err := GetUserID(c)
		if err != nil || userID == uuid.Nil {
			a.deny(c, uuid.Nil, resource, action, "user identity required")
			return
		}

		if _, ok := a.superAdmins[userID]; ok {
			c.Next()
			return
		}

		if selfParam != "" {
			if target, err := uuid.Parse(c.Param(selfParam)); err == nil && target == userID {
				c.Next()
				return
			}
		}

		if resource == "" {
			a.deny(c, userID, resource, action, "super admin required")
			return
		}

		tenantID, err := GetTenantID(c)
		if err != nil {
			RespondWithError(c, http.StatusUnauthorized, models.ErrorCodeUnauthorized, "Invalid tenant context", nil)
			c.Abort()
			return
		}

		allowed, err := a.checker.HasPermission(c.Request.Context(), tenantID, userID, resource, action)
		if err != nil {
			a.logger.WithError(err).WithFields(logrus.Fields{
				"request_id": GetRequestID(c),
				"tenant_id":  tenantID,
				"user_id":    userID,
				"resource":   resource,
				"action":     action,
			}).Error("permission check failed")
			RespondWithError(c, http.StatusInternalServerError, models.ErrorCodeInternalError, "Permission check failed", nil)
			c.Abort()
			return
		}
		if !allowed {
			a.deny(c, userID, resource, action, "missing permission")
			return
		}

		c.Next()
	}
}

func (a *Authorizer) deny(c *gin.Context, userID uuid.UUID, resource, action, reason string) {
	a.logger.WithFields(logrus.Fields{
		"request_id": GetRequestID(c),
		"user_id":    userID,
		"resource":   resource,
		"action":     action,
		"path":       c.FullPath(),
		"reason":     reason,
	}).Warn("authorization denied")

	RespondWithError(c, http.StatusForbidden, models.ErrorCodeInsufficientPermissions, "Insufficient permissions", nil)
	c.Abort()
}
