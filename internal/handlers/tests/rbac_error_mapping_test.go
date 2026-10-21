package tests

// rbac_error_mapping_test.go checks that wrapped service errors still map to
// the right HTTP status instead of falling through to 500.

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	"shieldgate/internal/handlers"
	"shieldgate/internal/middleware"
	"shieldgate/internal/models"
	"shieldgate/internal/services"
)

// wrappingRoleService fails AddPermission with a wrapped sentinel error;
// every other method is unused and panics via the nil embedded interface
type wrappingRoleService struct {
	services.RoleService
	err error
}

func (s *wrappingRoleService) AddPermission(ctx context.Context, tenantID, roleID, permissionID, grantedBy uuid.UUID) error {
	return fmt.Errorf("failed to get role: %w", s.err)
}

func TestRBACHandler_WrappedServiceError_MapsToSentinelStatus(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"role not found", models.ErrRoleNotFound, http.StatusNotFound},
		{"permission not found", models.ErrPermissionNotFound, http.StatusNotFound},
		{"duplicate", models.ErrDuplicateResource, http.StatusConflict},
		{"business rule", models.ErrBusinessRuleViolation, http.StatusUnprocessableEntity},
		{"unexpected", fmt.Errorf("db down"), http.StatusInternalServerError},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Arrange
			gin.SetMode(gin.TestMode)
			logger := logrus.New()
			logger.SetOutput(io.Discard)
			admin := uuid.New()
			h := handlers.NewRBACHandler(&wrappingRoleService{err: tc.err}, nil, nil, logger)

			r := gin.New()
			r.Use(func(c *gin.Context) {
				c.Set(middleware.UserIDKey, admin)
				c.Set(middleware.TenantIDKey, uuid.New())
			})
			h.RegisterRoutes(r.Group("/v1"), middleware.NewAuthorizer(nil, []uuid.UUID{admin}, logger))

			body := bytes.NewBufferString(fmt.Sprintf(`{"permission_id":%q}`, uuid.New()))
			req := httptest.NewRequest(http.MethodPost, "/v1/roles/"+uuid.New().String()+"/permissions", body)
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			// Act
			r.ServeHTTP(w, req)

			// Assert
			assert.Equal(t, tc.want, w.Code, w.Body.String())
		})
	}
}
