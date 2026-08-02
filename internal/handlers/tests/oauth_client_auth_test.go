package tests

// oauth_client_auth_test.go covers Phase 1 endpoint hardening: mandatory client
// authentication on introspection/revocation, client_secret_basic support, and
// grant-type/scope enforcement at the token endpoint.

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"shieldgate/internal/handlers"
	"shieldgate/internal/models"
	"shieldgate/tests/utils"
)

type handlerFixture struct {
	tenantID      uuid.UUID
	router        *gin.Engine
	tenantService *MockTenantService
	userService   *MockUserService
	clientService *MockClientService
	authService   *MockAuthService
}

func newHandlerFixture() *handlerFixture {
	gin.SetMode(gin.TestMode)
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)

	f := &handlerFixture{
		tenantID:      uuid.New(),
		tenantService: new(MockTenantService),
		userService:   new(MockUserService),
		clientService: new(MockClientService),
		authService:   new(MockAuthService),
	}

	handler := handlers.NewOAuthHandler(
		utils.CreateTestConfig(),
		f.tenantService,
		f.userService,
		f.clientService,
		f.authService,
		logger,
	)

	f.router = gin.New()
	f.router.Use(func(c *gin.Context) {
		c.Set("tenant_id", f.tenantID)
		c.Next()
	})
	handler.RegisterRoutes(f.router.Group(""))
	return f
}

func (f *handlerFixture) postForm(path string, form url.Values, basicAuth ...string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if len(basicAuth) == 2 {
		req.SetBasicAuth(basicAuth[0], basicAuth[1])
	}
	w := httptest.NewRecorder()
	f.router.ServeHTTP(w, req)
	return w
}

func confidentialClient(tenantID uuid.UUID, grantTypes, scopes []string) *models.Client {
	return &models.Client{
		ID:         uuid.New(),
		TenantID:   tenantID,
		ClientID:   "conf-client",
		GrantTypes: models.StringArray(grantTypes),
		Scopes:     models.StringArray(scopes),
		IsPublic:   false,
	}
}

// ---- Introspection requires client authentication (RFC 7662) ----

func TestHandleIntrospect_NoClientCredentials_Returns401(t *testing.T) {
	f := newHandlerFixture()

	form := url.Values{}
	form.Set("token", "some-token")
	w := f.postForm("/oauth/introspect", form)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "invalid_client")
	f.authService.AssertNotCalled(t, "IntrospectToken", mock.Anything, mock.Anything, mock.Anything)
}

func TestHandleIntrospect_PublicClient_Returns401(t *testing.T) {
	f := newHandlerFixture()
	publicClient := &models.Client{ID: uuid.New(), TenantID: f.tenantID, ClientID: "spa-client", IsPublic: true}
	f.clientService.On("ValidateClient", mock.Anything, f.tenantID, "spa-client", "").Return(publicClient, nil)

	form := url.Values{}
	form.Set("token", "some-token")
	form.Set("client_id", "spa-client")
	w := f.postForm("/oauth/introspect", form)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	f.authService.AssertNotCalled(t, "IntrospectToken", mock.Anything, mock.Anything, mock.Anything)
}

func TestHandleIntrospect_BasicAuth_Succeeds(t *testing.T) {
	f := newHandlerFixture()
	client := confidentialClient(f.tenantID, []string{"client_credentials"}, []string{"read"})
	f.clientService.On("ValidateClient", mock.Anything, f.tenantID, "conf-client", "s3cret").Return(client, nil)
	f.authService.On("IntrospectToken", mock.Anything, f.tenantID, "some-token").Return(&models.IntrospectionResponse{Active: true}, nil)

	form := url.Values{}
	form.Set("token", "some-token")
	w := f.postForm("/oauth/introspect", form, "conf-client", "s3cret")

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"active":true`)
	f.clientService.AssertExpectations(t)
	f.authService.AssertExpectations(t)
}

// ---- Revocation requires client authentication (RFC 7009) ----

func TestHandleRevoke_NoClientCredentials_Returns401(t *testing.T) {
	f := newHandlerFixture()

	form := url.Values{}
	form.Set("token", "some-token")
	w := f.postForm("/oauth/revoke", form)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	f.authService.AssertNotCalled(t, "RevokeToken", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

func TestHandleRevoke_AuthenticatedClient_PassesClientIdentity(t *testing.T) {
	f := newHandlerFixture()
	client := confidentialClient(f.tenantID, []string{"authorization_code"}, []string{"read"})
	f.clientService.On("ValidateClient", mock.Anything, f.tenantID, "conf-client", "s3cret").Return(client, nil)
	f.authService.On("RevokeToken", mock.Anything, f.tenantID, "some-token", "refresh_token", client.ID).Return(nil)

	form := url.Values{}
	form.Set("token", "some-token")
	form.Set("token_type_hint", "refresh_token")
	w := f.postForm("/oauth/revoke", form, "conf-client", "s3cret")

	assert.Equal(t, http.StatusOK, w.Code)
	f.authService.AssertExpectations(t)
}

// ---- Token endpoint: grant type and scope enforcement ----

func TestHandleToken_ClientCredentials_PublicClientRejected(t *testing.T) {
	f := newHandlerFixture()
	publicClient := &models.Client{ID: uuid.New(), TenantID: f.tenantID, ClientID: "spa-client", IsPublic: true,
		GrantTypes: models.StringArray{"client_credentials"}}
	f.clientService.On("ValidateClient", mock.Anything, f.tenantID, "spa-client", "").Return(publicClient, nil)

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", "spa-client")
	w := f.postForm("/oauth/token", form)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	f.authService.AssertNotCalled(t, "GenerateClientCredentialsTokens", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

func TestHandleToken_ClientCredentials_GrantTypeNotRegistered_Rejected(t *testing.T) {
	f := newHandlerFixture()
	client := confidentialClient(f.tenantID, []string{"authorization_code"}, []string{"read"})
	f.clientService.On("ValidateClient", mock.Anything, f.tenantID, "conf-client", "s3cret").Return(client, nil)

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	w := f.postForm("/oauth/token", form, "conf-client", "s3cret")

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "unauthorized_client")
}

func TestHandleToken_ClientCredentials_ScopeOutsideRegistration_Rejected(t *testing.T) {
	f := newHandlerFixture()
	client := confidentialClient(f.tenantID, []string{"client_credentials"}, []string{"read"})
	f.clientService.On("ValidateClient", mock.Anything, f.tenantID, "conf-client", "s3cret").Return(client, nil)

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("scope", "read admin")
	w := f.postForm("/oauth/token", form, "conf-client", "s3cret")

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid_scope")
}

func TestHandleToken_ClientCredentials_Success_NoRefreshToken(t *testing.T) {
	f := newHandlerFixture()
	client := confidentialClient(f.tenantID, []string{"client_credentials"}, []string{"read", "write"})
	f.clientService.On("ValidateClient", mock.Anything, f.tenantID, "conf-client", "s3cret").Return(client, nil)
	f.authService.On("GenerateClientCredentialsTokens", mock.Anything, f.tenantID, client, "read").
		Return(&models.TokenResponse{AccessToken: "at", TokenType: "Bearer", ExpiresIn: 3600, Scope: "read"}, nil)

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("scope", "read")
	w := f.postForm("/oauth/token", form, "conf-client", "s3cret")

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NotContains(t, w.Body.String(), "refresh_token")
	f.authService.AssertExpectations(t)
}

func TestHandleToken_RefreshGrant_UsesBasicAuthAndScope(t *testing.T) {
	f := newHandlerFixture()
	client := confidentialClient(f.tenantID, []string{"refresh_token"}, []string{"read"})
	f.clientService.On("ValidateClient", mock.Anything, f.tenantID, "conf-client", "s3cret").Return(client, nil)
	f.authService.On("RefreshTokens", mock.Anything, f.tenantID, "rt-1", "conf-client", "read").
		Return(&models.TokenResponse{AccessToken: "at2", TokenType: "Bearer", ExpiresIn: 3600, RefreshToken: "rt-2", Scope: "read"}, nil)

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", "rt-1")
	form.Set("scope", "read")
	w := f.postForm("/oauth/token", form, "conf-client", "s3cret")

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "rt-2")
	f.authService.AssertExpectations(t)
}
