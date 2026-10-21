package middleware

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

type stubChecker struct {
	allowed bool
	err     error
	calls   int
}

func (s *stubChecker) HasPermission(ctx context.Context, tenantID, userID uuid.UUID, resource, action string) (bool, error) {
	s.calls++
	return s.allowed, s.err
}

// authzRouter mounts guard on GET /users/:user_id behind a stand-in for
// RequireAuth that sets the caller's identity
func authzRouter(guard gin.HandlerFunc, userID uuid.UUID) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set(UserIDKey, userID)
		c.Set(TenantIDKey, uuid.New())
		c.Next()
	})
	r.GET("/users/:user_id", guard, func(c *gin.Context) { c.Status(http.StatusOK) })
	return r
}

func newTestAuthorizer(checker PermissionChecker, superAdmins ...uuid.UUID) *Authorizer {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	return NewAuthorizer(checker, superAdmins, logger)
}

func serve(r *gin.Engine, path string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
	return w
}

func TestRequire_UserHasPermission_Allows(t *testing.T) {
	// Arrange
	checker := &stubChecker{allowed: true}
	r := authzRouter(newTestAuthorizer(checker).Require("user", "read"), uuid.New())

	// Act
	w := serve(r, "/users/"+uuid.New().String())

	// Assert
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, 1, checker.calls)
}

func TestRequire_UserLacksPermission_Returns403(t *testing.T) {
	// Arrange
	r := authzRouter(newTestAuthorizer(&stubChecker{allowed: false}).Require("user", "read"), uuid.New())

	// Act
	w := serve(r, "/users/"+uuid.New().String())

	// Assert
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "INSUFFICIENT_PERMISSIONS")
}

func TestRequire_CheckerError_Returns500(t *testing.T) {
	// Arrange
	r := authzRouter(newTestAuthorizer(&stubChecker{err: errors.New("db down")}).Require("user", "read"), uuid.New())

	// Act
	w := serve(r, "/users/"+uuid.New().String())

	// Assert
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestRequire_ClientCredentialsToken_Returns403WithoutLookup(t *testing.T) {
	// Arrange: client_credentials tokens carry a nil user ID
	checker := &stubChecker{allowed: true}
	r := authzRouter(newTestAuthorizer(checker).Require("user", "read"), uuid.Nil)

	// Act
	w := serve(r, "/users/"+uuid.New().String())

	// Assert
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Zero(t, checker.calls)
}

func TestRequire_SuperAdmin_BypassesCheck(t *testing.T) {
	// Arrange
	admin := uuid.New()
	checker := &stubChecker{allowed: false}
	r := authzRouter(newTestAuthorizer(checker, admin).Require("user", "delete"), admin)

	// Act
	w := serve(r, "/users/"+uuid.New().String())

	// Assert
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Zero(t, checker.calls)
}

func TestRequireOrSelf_OwnUserID_AllowsWithoutPermission(t *testing.T) {
	// Arrange
	self := uuid.New()
	checker := &stubChecker{allowed: false}
	r := authzRouter(newTestAuthorizer(checker).RequireOrSelf("user", "read", "user_id"), self)

	// Act
	w := serve(r, "/users/"+self.String())

	// Assert
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Zero(t, checker.calls)
}

func TestRequireOrSelf_OtherUserID_FallsBackToPermission(t *testing.T) {
	// Arrange
	r := authzRouter(newTestAuthorizer(&stubChecker{allowed: false}).RequireOrSelf("user", "read", "user_id"), uuid.New())

	// Act
	w := serve(r, "/users/"+uuid.New().String())

	// Assert
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestRequireSuperAdmin_RegularUserWithPermissions_Returns403(t *testing.T) {
	// Arrange
	checker := &stubChecker{allowed: true}
	r := authzRouter(newTestAuthorizer(checker, uuid.New()).RequireSuperAdmin(), uuid.New())

	// Act
	w := serve(r, "/users/"+uuid.New().String())

	// Assert
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Zero(t, checker.calls)
}

func TestRequireSuperAdmin_SuperAdmin_Allows(t *testing.T) {
	// Arrange
	admin := uuid.New()
	r := authzRouter(newTestAuthorizer(&stubChecker{}, admin).RequireSuperAdmin(), admin)

	// Act
	w := serve(r, "/users/"+uuid.New().String())

	// Assert
	assert.Equal(t, http.StatusOK, w.Code)
}
