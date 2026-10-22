package tests

// oidc_compliance_handler_test.go covers the HTTP side of roadmap Phase 2:
// nonce carried through the login form, error and success redirects that
// include state and iss (RFC 9207), no redirects to unvalidated URIs, RFC 6750
// errors on UserInfo, and the RFC 8414 metadata alias.

import (
	"errors"
	"html/template"
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
	"github.com/stretchr/testify/require"

	"shieldgate/internal/handlers"
	"shieldgate/internal/middleware"
	"shieldgate/internal/models"
	"shieldgate/tests/utils"
)

const (
	oidcTestClientID    = "web-app"
	oidcTestRedirectURI = "https://app.example/cb"
)

type oidcHandlerFixture struct {
	tenantID uuid.UUID
	client   *models.Client
	tenants  *MockTenantService
	users    *MockUserService
	clients  *MockClientService
	auth     *MockAuthService
	router   *gin.Engine
}

func newOIDCHandlerFixture(t *testing.T) *oidcHandlerFixture {
	t.Helper()
	gin.SetMode(gin.TestMode)
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)

	f := &oidcHandlerFixture{
		tenantID: uuid.New(),
		tenants:  new(MockTenantService),
		users:    new(MockUserService),
		clients:  new(MockClientService),
		auth:     new(MockAuthService),
	}
	f.client = &models.Client{
		ID: uuid.New(), TenantID: f.tenantID, ClientID: oidcTestClientID, Name: "Web",
		RedirectURIs: models.StringArray{oidcTestRedirectURI},
		GrantTypes:   models.StringArray{"authorization_code"},
		Scopes:       models.StringArray{"openid", "profile"},
	}
	f.tenants.On("GetByID", mock.Anything, f.tenantID).Return(&models.Tenant{ID: f.tenantID, Name: "T"}, nil)
	f.clients.On("GetByClientID", mock.Anything, f.tenantID, oidcTestClientID).Return(f.client, nil)
	f.clients.On("GetByClientID", mock.Anything, f.tenantID, mock.Anything).Return(nil, models.ErrClientNotFound)
	f.clients.On("ValidateRedirectURI", mock.Anything, f.client, oidcTestRedirectURI).Return(nil)
	f.clients.On("ValidateRedirectURI", mock.Anything, f.client, mock.Anything).Return(errors.New("redirect_uri not registered"))

	handler := handlers.NewOAuthHandler(utils.CreateTestConfig(), f.tenants, f.users, f.clients, f.auth, preConsented(), nil, logger)
	f.router = gin.New()
	f.router.SetFuncMap(template.FuncMap{
		"contains": func(s, substr string) bool { return strings.Contains(s, substr) },
	})
	f.router.LoadHTMLGlob("../../../templates/*")
	f.router.Use(func(c *gin.Context) {
		c.Set(middleware.TenantIDKey, f.tenantID)
		c.Next()
	})
	handler.RegisterRoutes(f.router.Group(""))
	return f
}

func (f *oidcHandlerFixture) get(path string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	f.router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
	return w
}

func authorizeURL(params map[string]string) string {
	q := url.Values{}
	for k, v := range params {
		q.Set(k, v)
	}
	return "/oauth/authorize?" + q.Encode()
}

func redirectQuery(t *testing.T, w *httptest.ResponseRecorder) url.Values {
	t.Helper()
	require.Equal(t, http.StatusFound, w.Code, w.Body.String())
	loc, err := url.Parse(w.Header().Get("Location"))
	require.NoError(t, err)
	return loc.Query()
}

func TestAuthorize_UnknownClient_ShowsErrorPageInsteadOfRedirecting(t *testing.T) {
	// Arrange
	f := newOIDCHandlerFixture(t)

	// Act
	w := f.get(authorizeURL(map[string]string{
		"response_type": "code", "client_id": "nope", "redirect_uri": "https://evil.example/steal", "state": "s",
	}))

	// Assert
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Empty(t, w.Header().Get("Location"))
}

func TestAuthorize_BadResponseTypeWithUnregisteredRedirect_DoesNotRedirect(t *testing.T) {
	// Arrange: response_type used to be checked first and redirected to any URI
	f := newOIDCHandlerFixture(t)

	// Act
	w := f.get(authorizeURL(map[string]string{
		"response_type": "token", "client_id": oidcTestClientID, "redirect_uri": "https://evil.example/steal",
	}))

	// Assert
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Empty(t, w.Header().Get("Location"))
}

func TestAuthorize_BadResponseTypeWithValidRedirect_RedirectsErrorWithStateAndIss(t *testing.T) {
	// Arrange
	f := newOIDCHandlerFixture(t)

	// Act
	w := f.get(authorizeURL(map[string]string{
		"response_type": "token", "client_id": oidcTestClientID, "redirect_uri": oidcTestRedirectURI, "state": "st-123",
	}))

	// Assert
	q := redirectQuery(t, w)
	assert.Equal(t, "unsupported_response_type", q.Get("error"))
	assert.Equal(t, "st-123", q.Get("state"))
	assert.Equal(t, utils.CreateTestConfig().ServerURL, q.Get("iss"))
}

func TestAuthorize_OversizedNonce_Rejected(t *testing.T) {
	// Arrange
	f := newOIDCHandlerFixture(t)

	// Act
	w := f.get(authorizeURL(map[string]string{
		"response_type": "code", "client_id": oidcTestClientID, "redirect_uri": oidcTestRedirectURI,
		"scope": "openid", "nonce": strings.Repeat("n", 513),
	}))

	// Assert
	assert.Equal(t, "invalid_request", redirectQuery(t, w).Get("error"))
}

func TestLogin_NonceFromAuthorizeRequest_ReachesAuthorizationCodeAndRedirectHasIss(t *testing.T) {
	// Arrange
	f := newOIDCHandlerFixture(t)
	user := &models.User{ID: uuid.New(), TenantID: f.tenantID, Email: "a@example.com"}
	f.users.On("Authenticate", mock.Anything, f.tenantID, "a@example.com", "pw-123456").Return(user, nil)
	f.auth.On("GenerateAuthorizationCode", mock.Anything, f.tenantID, f.client.ID, user.ID, oidcTestRedirectURI,
		"openid profile", "", "", "n-0S6_WzA2Mj", mock.AnythingOfType("time.Time"), mock.Anything).
		Return(&models.AuthorizationCode{Code: "the-code"}, nil)

	page := f.get(authorizeURL(map[string]string{
		"response_type": "code", "client_id": oidcTestClientID, "redirect_uri": oidcTestRedirectURI,
		"scope": "openid profile", "state": "st", "nonce": "n-0S6_WzA2Mj",
	}))
	require.Equal(t, http.StatusOK, page.Code)
	require.Contains(t, page.Body.String(), `name="nonce" value="n-0S6_WzA2Mj"`)

	form := url.Values{
		"username": {"a@example.com"}, "password": {"pw-123456"},
		"client_id": {oidcTestClientID}, "redirect_uri": {oidcTestRedirectURI},
		"scope": {"openid profile"}, "state": {"st"}, "nonce": {"n-0S6_WzA2Mj"},
		"response_type": {"code"}, "csrf_token": {extractCSRFToken(t, page.Body.String())},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(extractCookie(page, "sg_csrf"))
	w := httptest.NewRecorder()

	// Act
	f.router.ServeHTTP(w, req)

	// Assert
	q := redirectQuery(t, w)
	assert.Equal(t, "the-code", q.Get("code"))
	assert.Equal(t, "st", q.Get("state"))
	assert.Equal(t, utils.CreateTestConfig().ServerURL, q.Get("iss"))
	f.auth.AssertExpectations(t)
}

func TestUserInfo_Errors_FollowRFC6750(t *testing.T) {
	cases := []struct {
		name       string
		serviceErr error
		wantStatus int
		wantError  string
	}{
		{"token lacks openid scope", models.ErrInsufficientScope, http.StatusForbidden, "insufficient_scope"},
		{"invalid token", models.ErrRevokedToken, http.StatusUnauthorized, "invalid_token"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Arrange
			f := newOIDCHandlerFixture(t)
			f.auth.On("GetUserInfo", mock.Anything, f.tenantID, "tok").Return((*models.UserInfo)(nil), tc.serviceErr)
			req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
			req.Header.Set("Authorization", "Bearer tok")
			w := httptest.NewRecorder()

			// Act
			f.router.ServeHTTP(w, req)

			// Assert
			assert.Equal(t, tc.wantStatus, w.Code)
			assert.Contains(t, w.Header().Get("WWW-Authenticate"), `error="`+tc.wantError+`"`)
		})
	}
}

func TestUserInfo_POST_Supported(t *testing.T) {
	// Arrange
	f := newOIDCHandlerFixture(t)
	f.auth.On("GetUserInfo", mock.Anything, f.tenantID, "tok").Return(&models.UserInfo{Sub: "u1"}, nil)
	req := httptest.NewRequest(http.MethodPost, "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer tok")
	w := httptest.NewRecorder()

	// Act
	f.router.ServeHTTP(w, req)

	// Assert
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"sub":"u1"`)
}

func TestUserInfo_NoBearer_ChallengeWithoutErrorCode(t *testing.T) {
	// Arrange
	f := newOIDCHandlerFixture(t)

	// Act
	w := f.get("/userinfo")

	// Assert (RFC 6750 §3.1: no error code when no credentials were sent)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.True(t, strings.HasPrefix(w.Header().Get("WWW-Authenticate"), "Bearer "))
	assert.NotContains(t, w.Header().Get("WWW-Authenticate"), "error=")
}

func TestOAuthAuthorizationServerMetadata_ServedAtRFC8414Path(t *testing.T) {
	// Arrange
	f := newOIDCHandlerFixture(t)
	f.auth.On("GetDiscoveryDocument", mock.Anything).Return(&models.OpenIDConfiguration{Issuer: "https://issuer"}, nil)

	// Act
	w := f.get("/.well-known/oauth-authorization-server")

	// Assert
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"issuer":"https://issuer"`)
}
