package tests

import (
	"encoding/json"
	"html/template"
	"net/http"
	"net/http/httptest"
	"testing"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"shieldgate/internal/handlers"
	"shieldgate/internal/middleware"
	"shieldgate/internal/models"
	"shieldgate/tests/utils"
)

// newOIDCRouter builds a router wired up with mock services for OIDC endpoint tests.
func newOIDCRouter(
	mockTenant *MockTenantService,
	mockUser *MockUserService,
	mockClient *MockClientService,
	mockAuth *MockAuthService,
) *gin.Engine {
	gin.SetMode(gin.TestMode)
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)

	handler := handlers.NewOAuthHandler(mockTenant, mockUser, mockClient, mockAuth, logger)
	r := gin.New()
	r.SetFuncMap(template.FuncMap{
		"contains": func(s, substr string) bool { return strings.Contains(s, substr) },
	})
	r.LoadHTMLGlob("../../../templates/*")
	handler.RegisterRoutes(r.Group(""))
	return r
}

// --- HandleJWKS ---

func TestHandleJWKS_ReturnsWellFormedJWK(t *testing.T) {
	r := newOIDCRouter(new(MockTenantService), new(MockUserService), new(MockClientService), new(MockAuthService))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var result map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))

	keys, ok := result["keys"].([]interface{})
	require.True(t, ok, "response must have 'keys' array")
	require.NotEmpty(t, keys, "keys array must not be empty")

	key, ok := keys[0].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "oct", key["kty"])
	assert.Equal(t, "sig", key["use"])
	assert.Equal(t, "HS256", key["alg"])
	assert.NotEmpty(t, key["kid"])
}

// --- HandleDiscovery ---

func TestHandleDiscovery_ReturnsRequiredFields(t *testing.T) {
	mockAuth := new(MockAuthService)
	mockAuth.On("GetDiscoveryDocument", mock.Anything).Return(&models.OpenIDConfiguration{
		Issuer:                           "http://localhost:8080",
		AuthorizationEndpoint:            "http://localhost:8080/oauth/authorize",
		TokenEndpoint:                    "http://localhost:8080/oauth/token",
		UserInfoEndpoint:                 "http://localhost:8080/userinfo",
		JwksURI:                          "http://localhost:8080/.well-known/jwks.json",
		ResponseTypesSupported:           []string{"code"},
		SubjectTypesSupported:            []string{"public"},
		IDTokenSigningAlgValuesSupported: []string{"HS256"},
		ScopesSupported:                  []string{"openid", "profile", "email"},
		ClaimsSupported:                  []string{"sub", "email", "name"},
	}, nil)

	r := newOIDCRouter(new(MockTenantService), new(MockUserService), new(MockClientService), mockAuth)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var doc models.OpenIDConfiguration
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &doc))

	assert.NotEmpty(t, doc.Issuer)
	assert.NotEmpty(t, doc.AuthorizationEndpoint)
	assert.NotEmpty(t, doc.TokenEndpoint)
	assert.NotEmpty(t, doc.UserInfoEndpoint)
	assert.NotEmpty(t, doc.JwksURI)
	assert.NotEmpty(t, doc.ResponseTypesSupported)
	assert.NotEmpty(t, doc.IDTokenSigningAlgValuesSupported)
}

// --- HandleUserInfo ---

func TestHandleUserInfo_ValidToken_ReturnsClaims(t *testing.T) {
	cfg := utils.CreateTestConfig()
	tenantID := uuid.New()
	userID := uuid.New()
	clientID := uuid.New()
	token := utils.CreateTestJWT(cfg, userID, clientID, tenantID, "openid profile email")

	mockAuth := new(MockAuthService)
	mockAuth.On("GetUserInfo", mock.Anything, tenantID, token).Return(&models.UserInfo{
		Sub:           userID.String(),
		Name:          "Test User",
		Email:         "test@example.com",
		EmailVerified: true,
	}, nil)

	gin.SetMode(gin.TestMode)
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)
	handler := handlers.NewOAuthHandler(new(MockTenantService), new(MockUserService), new(MockClientService), mockAuth, logger)

	r := gin.New()
	// Pre-inject tenant context (simulates TenantContext middleware with JWT)
	r.Use(func(c *gin.Context) {
		c.Set(middleware.TenantIDKey, tenantID)
		c.Next()
	})
	handler.RegisterRoutes(r.Group(""))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var info models.UserInfo
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &info))
	assert.Equal(t, userID.String(), info.Sub)
	assert.Equal(t, "test@example.com", info.Email)
}

func TestHandleUserInfo_MissingToken_Returns401(t *testing.T) {
	tenantID := uuid.New()

	gin.SetMode(gin.TestMode)
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)
	handler := handlers.NewOAuthHandler(new(MockTenantService), new(MockUserService), new(MockClientService), new(MockAuthService), logger)

	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set(middleware.TenantIDKey, tenantID)
		c.Next()
	})
	handler.RegisterRoutes(r.Group(""))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/userinfo", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestHandleUserInfo_NoTenantContext_Returns401(t *testing.T) {
	r := newOIDCRouter(new(MockTenantService), new(MockUserService), new(MockClientService), new(MockAuthService))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer sometoken")
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// --- HandleAuthorize — missing tenant context ---

func TestHandleAuthorize_MissingTenantContext_ReturnsError(t *testing.T) {
	// After removing hardcoded fallback, missing tenant should return an error
	r := newOIDCRouter(new(MockTenantService), new(MockUserService), new(MockClientService), new(MockAuthService))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/oauth/authorize?response_type=code&client_id=some-client&redirect_uri=http://localhost:3000/callback&scope=openid", nil)
	r.ServeHTTP(w, req)

	// Should NOT return 200 anymore (no hardcoded tenant fallback)
	// Renders error template (4xx or redirect with error)
	assert.NotEqual(t, http.StatusOK, w.Code)
}

// --- HandleToken — missing tenant context ---

func TestHandleToken_MissingTenantContext_ReturnsBadRequest(t *testing.T) {
	r := newOIDCRouter(new(MockTenantService), new(MockUserService), new(MockClientService), new(MockAuthService))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/oauth/token", nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}
