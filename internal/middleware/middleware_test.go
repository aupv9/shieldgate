package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"shieldgate/config"
	"shieldgate/tests/utils"
)

func testConfig() *config.Config {
	return utils.CreateTestConfig()
}

func setupRouter(cfg *config.Config) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(RequireAuth(cfg))
	r.GET("/protected", func(c *gin.Context) {
		userID, err := GetUserID(c)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "user_id missing"})
			return
		}
		tenantID, _ := GetTenantID(c)
		c.JSON(http.StatusOK, gin.H{
			"user_id":   userID.String(),
			"tenant_id": tenantID.String(),
		})
	})
	return r
}

// --- RequireAuth tests ---

func TestRequireAuth_MissingHeader(t *testing.T) {
	r := setupRouter(testConfig())
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/protected", nil)
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRequireAuth_InvalidHeaderFormat(t *testing.T) {
	r := setupRouter(testConfig())
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRequireAuth_EmptyBearerToken(t *testing.T) {
	r := setupRouter(testConfig())
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer ")
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRequireAuth_MalformedToken(t *testing.T) {
	r := setupRouter(testConfig())
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer not.a.valid.jwt.token")
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRequireAuth_ValidToken(t *testing.T) {
	cfg := testConfig()
	userID := uuid.New()
	clientID := uuid.New()
	tenantID := uuid.New()
	token := utils.CreateTestJWT(cfg, userID, clientID, tenantID, "read write")

	r := setupRouter(cfg)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), userID.String())
	assert.Contains(t, w.Body.String(), tenantID.String())
}

func TestRequireAuth_ExpiredToken(t *testing.T) {
	cfg := testConfig()
	userID := uuid.New()
	clientID := uuid.New()
	tenantID := uuid.New()
	token := utils.CreateExpiredJWT(cfg, userID, clientID, tenantID)

	r := setupRouter(cfg)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRequireAuth_TamperedSignature(t *testing.T) {
	cfg := testConfig()
	userID := uuid.New()
	clientID := uuid.New()
	tenantID := uuid.New()
	token := utils.CreateTamperedJWT(cfg, userID, clientID, tenantID)

	r := setupRouter(cfg)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// --- TenantContext / extractTenantFromJWT tests ---

func TestExtractTenantFromJWT_ValidToken(t *testing.T) {
	cfg := testConfig()
	tenantID := uuid.New()
	token := utils.CreateTestJWT(cfg, uuid.New(), uuid.New(), tenantID, "read")

	result, err := extractTenantFromJWT(token, cfg.JWTSecret)
	require.NoError(t, err)
	assert.Equal(t, tenantID, result)
}

func TestExtractTenantFromJWT_InvalidToken(t *testing.T) {
	cfg := testConfig()
	_, err := extractTenantFromJWT("garbage.token.here", cfg.JWTSecret)
	assert.Error(t, err)
}

func TestExtractTenantFromJWT_WrongSecret(t *testing.T) {
	cfg := testConfig()
	token := utils.CreateTamperedJWT(cfg, uuid.New(), uuid.New(), uuid.New())
	_, err := extractTenantFromJWT(token, cfg.JWTSecret)
	assert.Error(t, err)
}

func TestExtractTenantFromJWT_ExpiredToken(t *testing.T) {
	cfg := testConfig()
	token := utils.CreateExpiredJWT(cfg, uuid.New(), uuid.New(), uuid.New())
	_, err := extractTenantFromJWT(token, cfg.JWTSecret)
	assert.Error(t, err)
}

// --- TenantContext middleware with X-Tenant-ID header ---

func TestTenantContext_XTenantIDHeader(t *testing.T) {
	cfg := testConfig()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(TenantContext(cfg))
	r.GET("/api/resource", func(c *gin.Context) {
		id, err := GetTenantID(c)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"tenant_id": id.String()})
	})

	tenantID := uuid.New()
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/api/resource", nil)
	req.Header.Set("X-Tenant-ID", tenantID.String())
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), tenantID.String())
}

func TestTenantContext_MissingTenant_ReturnsUnauthorized(t *testing.T) {
	cfg := testConfig()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(TenantContext(cfg))
	r.GET("/api/resource", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/api/resource", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestTenantContext_JWTExtractsTenant(t *testing.T) {
	cfg := testConfig()
	tenantID := uuid.New()
	token := utils.CreateTestJWT(cfg, uuid.New(), uuid.New(), tenantID, "read")

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(TenantContext(cfg))
	r.GET("/api/resource", func(c *gin.Context) {
		id, err := GetTenantID(c)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"tenant_id": id.String()})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/api/resource", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), tenantID.String())
}

// --- isOAuthEndpoint / isPublicEndpoint ---

func TestIsOAuthEndpoint(t *testing.T) {
	assert.True(t, isOAuthEndpoint("/oauth/authorize"))
	assert.True(t, isOAuthEndpoint("/oauth/token"))
	assert.True(t, isOAuthEndpoint("/.well-known/openid-configuration"))
	assert.True(t, isOAuthEndpoint("/.well-known/jwks.json"))
	assert.True(t, isOAuthEndpoint("/userinfo"))
	assert.False(t, isOAuthEndpoint("/v1/users"))
	assert.False(t, isOAuthEndpoint("/health"))
}

func TestIsPublicEndpoint(t *testing.T) {
	assert.True(t, isPublicEndpoint("/health"))
	assert.True(t, isPublicEndpoint("/metrics"))
	assert.True(t, isPublicEndpoint("/static/app.css"))
	assert.False(t, isPublicEndpoint("/v1/users"))
	assert.False(t, isPublicEndpoint("/oauth/token"))
}

// --- extractTenantFromSubdomain ---

func TestExtractTenantFromSubdomain_ValidUUID(t *testing.T) {
	id := uuid.New()
	result, err := extractTenantFromSubdomain(id.String() + ".api.example.com")
	require.NoError(t, err)
	assert.Equal(t, id, result)
}

func TestExtractTenantFromSubdomain_InvalidSubdomain(t *testing.T) {
	_, err := extractTenantFromSubdomain("api.example.com")
	assert.Error(t, err)
}

func TestExtractTenantFromSubdomain_NonUUIDSubdomain(t *testing.T) {
	_, err := extractTenantFromSubdomain("mycompany.api.example.com")
	assert.Error(t, err)
}

// Ensure test helpers produce tokens that expire at the right time
func TestCreateTestJWT_ExpiresCorrectly(t *testing.T) {
	cfg := testConfig()
	token := utils.CreateTestJWT(cfg, uuid.New(), uuid.New(), uuid.New(), "read")

	r := setupRouter(cfg)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// Temporarily shorten access token duration to verify expiry
	shortCfg := *cfg
	shortCfg.AccessTokenDuration = -1 * time.Second
	expiredToken := utils.CreateExpiredJWT(&shortCfg, uuid.New(), uuid.New(), uuid.New())

	r2 := setupRouter(cfg)
	w2 := httptest.NewRecorder()
	req2, _ := http.NewRequest(http.MethodGet, "/protected", nil)
	req2.Header.Set("Authorization", "Bearer "+expiredToken)
	r2.ServeHTTP(w2, req2)
	assert.Equal(t, http.StatusUnauthorized, w2.Code)
}
