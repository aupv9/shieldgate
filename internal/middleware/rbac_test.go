package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"shieldgate/internal/models"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// --- helpers ---

func buildContextWithClaims(scope string) (*gin.Context, *httptest.ResponseRecorder) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest(http.MethodGet, "/", nil)

	userID := uuid.New()
	tenantID := uuid.New()

	claims := &models.JWTClaims{
		Sub:      userID.String(),
		UserID:   userID.String(),
		TenantID: tenantID.String(),
		Scope:    scope,
	}
	c.Set("jwt_claims", claims)
	c.Set(UserIDKey, userID)
	c.Set(TenantIDKey, tenantID)

	return c, w
}

// --- RequireScope ---

func TestRequireScope_Allowed(t *testing.T) {
	c, w := buildContextWithClaims("openid read write")

	RequireScope("read")(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.False(t, c.IsAborted())
}

func TestRequireScope_AnyOf_Allowed(t *testing.T) {
	c, w := buildContextWithClaims("openid admin")

	RequireScope("read", "admin")(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.False(t, c.IsAborted())
}

func TestRequireScope_Denied(t *testing.T) {
	c, w := buildContextWithClaims("openid read")

	RequireScope("admin")(c)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.True(t, c.IsAborted())
}

func TestRequireScope_NoClaims(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest(http.MethodGet, "/", nil)
	// no jwt_claims set

	RequireScope("read")(c)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.True(t, c.IsAborted())
}

func TestRequireScope_EmptyScope_Denied(t *testing.T) {
	c, w := buildContextWithClaims("")

	RequireScope("read")(c)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestRequireScope_SetsTokenScopeKey(t *testing.T) {
	c, _ := buildContextWithClaims("openid read")

	RequireScope("read")(c)

	scope, exists := c.Get(ScopeKey)
	assert.True(t, exists)
	assert.Equal(t, "openid read", scope)
}

// --- RequirePermission ---

type allowPermissionChecker struct{}

func (a *allowPermissionChecker) HasPermission(_ context.Context, _, _ uuid.UUID, _, _ string) (bool, error) {
	return true, nil
}

type denyPermissionChecker struct{}

func (d *denyPermissionChecker) HasPermission(_ context.Context, _, _ uuid.UUID, _, _ string) (bool, error) {
	return false, nil
}

func TestRequirePermission_NilChecker_Passthrough(t *testing.T) {
	c, w := buildContextWithClaims("read")

	RequirePermission(nil, "user", "read")(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.False(t, c.IsAborted())
}

func TestRequirePermission_Allowed(t *testing.T) {
	c, w := buildContextWithClaims("read")

	RequirePermission(&allowPermissionChecker{}, "user", "read")(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.False(t, c.IsAborted())
}

func TestRequirePermission_Denied(t *testing.T) {
	c, w := buildContextWithClaims("read")

	RequirePermission(&denyPermissionChecker{}, "user", "delete")(c)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.True(t, c.IsAborted())
}

func TestRequirePermission_NoTenantContext(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest(http.MethodGet, "/", nil)
	// No tenant set

	RequirePermission(&allowPermissionChecker{}, "user", "read")(c)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// --- scopeEnforcer ---

func TestScopeEnforcer(t *testing.T) {
	tests := []struct {
		scope    string
		required string
		want     bool
	}{
		{"read write openid", "read", true},
		{"read write openid", "admin", false},
		{"", "read", false},
		{"read", "read", true},
		{"readmore", "read", false}, // must be exact token
	}

	for _, tt := range tests {
		got := scopeEnforcer(tt.scope, tt.required)
		assert.Equal(t, tt.want, got, "scope=%q required=%q", tt.scope, tt.required)
	}
}
