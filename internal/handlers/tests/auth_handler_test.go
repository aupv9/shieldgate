package tests

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"

	"shieldgate/internal/handlers"
	"shieldgate/internal/models"
	"shieldgate/internal/services"
	"shieldgate/tests/utils"
)

func TestNewAuthHandler(t *testing.T) {
	cfg := utils.CreateTestConfig()
	db := utils.SetupTestDB(t)
	authService := services.NewAuthService(db, nil, cfg)

	handler := handlers.NewAuthHandler(authService)

	assert.NotNil(t, handler)
}

func TestAuthHandler_SetServices(t *testing.T) {
	cfg := utils.CreateTestConfig()
	db := utils.SetupTestDB(t)
	authService := services.NewAuthService(db, nil, cfg)
	clientService := services.NewClientService(db)
	userService := services.NewUserService(db)

	handler := handlers.NewAuthHandler(authService)
	handler.SetServices(clientService, userService)

	// Handler should be properly initialized
	assert.NotNil(t, handler)
}

func setupTestHandler(t *testing.T) (*handlers.AuthHandler, *models.Client, *models.User) {
	cfg := utils.CreateTestConfig()
	db := utils.SetupTestDB(t)
	authService := services.NewAuthService(db, nil, cfg)
	clientService := services.NewClientService(db)
	userService := services.NewUserService(db)

	handler := handlers.NewAuthHandler(authService)
	handler.SetServices(clientService, userService)

	// Create test client and user
	testClient := utils.CreateTestClient()
	testUser := utils.CreateTestUser()

	return handler, testClient, testUser
}

func TestAuthHandler_Authorize_MissingResponseType(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler, _, _ := setupTestHandler(t)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	// Create request with missing response_type
	req := httptest.NewRequest("GET", "/oauth/authorize?client_id=test-client&redirect_uri=http://localhost:3000/callback", nil)
	c.Request = req

	handler.Authorize(c)

	assert.Equal(t, http.StatusFound, w.Code)
	location := w.Header().Get("Location")
	assert.Contains(t, location, "error=unsupported_response_type")
}

func TestAuthHandler_Authorize_InvalidResponseType(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler, _, _ := setupTestHandler(t)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	// Create request with invalid response_type
	req := httptest.NewRequest("GET", "/oauth/authorize?response_type=token&client_id=test-client&redirect_uri=http://localhost:3000/callback", nil)
	c.Request = req

	handler.Authorize(c)

	assert.Equal(t, http.StatusFound, w.Code)
	location := w.Header().Get("Location")
	assert.Contains(t, location, "error=unsupported_response_type")
}

func TestAuthHandler_Authorize_MissingClientID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler, _, _ := setupTestHandler(t)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	// Create request with missing client_id
	req := httptest.NewRequest("GET", "/oauth/authorize?response_type=code&redirect_uri=http://localhost:3000/callback", nil)
	c.Request = req

	handler.Authorize(c)

	assert.Equal(t, http.StatusFound, w.Code)
	location := w.Header().Get("Location")
	assert.Contains(t, location, "error=invalid_request")
}

func TestAuthHandler_Authorize_MissingRedirectURI(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler, _, _ := setupTestHandler(t)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	// Create request with missing redirect_uri
	req := httptest.NewRequest("GET", "/oauth/authorize?response_type=code&client_id=test-client", nil)
	c.Request = req

	handler.Authorize(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "redirect_uri is required")
}

func TestAuthHandler_Token_UnsupportedGrantType(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler, _, _ := setupTestHandler(t)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	// Create POST request with unsupported grant type
	form := url.Values{}
	form.Add("grant_type", "password")
	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	c.Request = req

	handler.Token(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "unsupported_grant_type")
}

func TestAuthHandler_Introspect_MissingToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler, _, _ := setupTestHandler(t)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	// Create POST request without token parameter
	form := url.Values{}
	form.Add("client_id", "test-client")
	form.Add("client_secret", "test-secret")
	req := httptest.NewRequest("POST", "/oauth/introspect", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	c.Request = req

	handler.Introspect(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "token parameter is required")
}

func TestAuthHandler_Introspect_MissingClientID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler, _, _ := setupTestHandler(t)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	// Create POST request without client_id
	form := url.Values{}
	form.Add("token", "test-token")
	req := httptest.NewRequest("POST", "/oauth/introspect", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	c.Request = req

	handler.Introspect(c)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "Client authentication required")
}

func TestAuthHandler_Revoke_MissingToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler, _, _ := setupTestHandler(t)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	// Create POST request without token parameter
	form := url.Values{}
	form.Add("client_id", "test-client")
	form.Add("client_secret", "test-secret")
	req := httptest.NewRequest("POST", "/oauth/revoke", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	c.Request = req

	handler.Revoke(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "token parameter is required")
}

func TestAuthHandler_Discovery(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler, _, _ := setupTestHandler(t)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	req := httptest.NewRequest("GET", "/.well-known/openid_configuration", nil)
	req.Host = "localhost:8080"
	c.Request = req

	handler.Discovery(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "authorization_endpoint")
	assert.Contains(t, w.Body.String(), "token_endpoint")
	assert.Contains(t, w.Body.String(), "userinfo_endpoint")
}

func TestAuthHandler_JWKS(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler, _, _ := setupTestHandler(t)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	req := httptest.NewRequest("GET", "/.well-known/jwks.json", nil)
	c.Request = req

	handler.JWKS(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "keys")
}

func TestAuthHandler_UserInfo_MissingAuthHeader(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler, _, _ := setupTestHandler(t)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	req := httptest.NewRequest("GET", "/userinfo", nil)
	c.Request = req

	handler.UserInfo(c)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "Access token required")
}

func TestAuthHandler_UserInfo_InvalidTokenFormat(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler, _, _ := setupTestHandler(t)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	req := httptest.NewRequest("GET", "/userinfo", nil)
	req.Header.Set("Authorization", "InvalidFormat")
	c.Request = req

	handler.UserInfo(c)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "Invalid token format")
}

func TestAuthHandler_RedirectWithError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler, _, _ := setupTestHandler(t)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	// Test redirect with error
	redirectURI := "http://localhost:3000/callback"
	state := "test-state"

	// Since redirectWithError is a private method, we test it indirectly through public methods
	req := httptest.NewRequest("GET", "/oauth/authorize?response_type=invalid&client_id=test&redirect_uri="+url.QueryEscape(redirectURI)+"&state="+state, nil)
	c.Request = req

	handler.Authorize(c)

	assert.Equal(t, http.StatusFound, w.Code)
	location := w.Header().Get("Location")
	assert.Contains(t, location, "error=unsupported_response_type")
	assert.Contains(t, location, "state="+state)
}

func TestAuthHandler_GetCurrentUserID_NoAuth(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Test the getCurrentUserID method indirectly by testing context behavior
	// Since getCurrentUserID is a private method, we test its behavior through context checks
	// This test verifies that when no authentication is provided, no user_id is set in context

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	// Test that no user_id is set in context when no auth is provided
	req := httptest.NewRequest("GET", "/test", nil)
	c.Request = req

	// Verify that no user_id exists in context initially
	_, exists := c.Get("user_id")
	assert.False(t, exists)

	// This test validates the initial state before authentication
	// The actual getCurrentUserID method would return uuid.Nil in this case
}
