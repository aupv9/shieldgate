package tests

// route_registration_test.go guards against Gin route conflicts when the RBAC
// and audit handlers share the /v1 group with the user handler.

import (
	"io"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"shieldgate/internal/handlers"
	"shieldgate/internal/middleware"
)

func TestRegisterRoutes_RBACAndAuditUnderV1_NoConflictAndPathsExposed(t *testing.T) {
	// Arrange
	gin.SetMode(gin.TestMode)
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	router := gin.New()
	api := router.Group("/v1")
	authz := middleware.NewAuthorizer(nil, nil, logger)

	// Act
	require.NotPanics(t, func() {
		handlers.NewTenantHandler(nil, logger).RegisterRoutes(api.Group("/tenants"), authz)
		handlers.NewUserHandler(nil, logger).RegisterRoutes(api.Group("/users"), authz)
		handlers.NewClientHandler(nil, logger).RegisterRoutes(api.Group("/clients"), authz)
		handlers.NewRBACHandler(nil, nil, nil, logger).RegisterRoutes(api, authz)
		handlers.NewAuditHandler(nil, logger).RegisterRoutes(api, authz)
	})

	// Assert
	registered := map[string]bool{}
	for _, r := range router.Routes() {
		registered[r.Method+" "+r.Path] = true
	}
	for _, want := range []string{
		"POST /v1/roles",
		"POST /v1/roles/:role_id/users",
		"GET /v1/permissions",
		"GET /v1/users/:user_id",
		"GET /v1/users/:user_id/roles",
		"GET /v1/users/:user_id/permissions",
		"GET /v1/audit/logs",
		"GET /v1/audit/compliance-report",
		"POST /v1/tenants/admin/tenants",
	} {
		assert.True(t, registered[want], "missing route %s", want)
	}
}
