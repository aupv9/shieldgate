package tests

// oauth_session_handler_test.go covers Phase 3 HTTP behavior: SSO on the
// authorize endpoint, prompt/max_age handling, the consent screen, and logout.

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"shieldgate/internal/handlers"
	"shieldgate/internal/models"
	"shieldgate/tests/utils"
)

// newBrowserFixture is a handlerFixture with HTML templates loaded (needed
// for login/consent page rendering)
func newBrowserFixture(t *testing.T) *handlerFixture {
	t.Helper()
	f := newHandlerFixture()

	gin.SetMode(gin.TestMode)
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)

	handler := handlers.NewOAuthHandler(
		utils.CreateTestConfig(),
		f.tenantService,
		f.userService,
		f.clientService,
		f.authService,
		logger,
	)

	f.router = gin.New()
	f.router.SetFuncMap(template.FuncMap{
		"contains": func(s, substr string) bool { return strings.Contains(s, substr) },
	})
	f.router.LoadHTMLGlob("../../../templates/*")
	f.router.Use(func(c *gin.Context) {
		c.Set("tenant_id", f.tenantID)
		c.Next()
	})
	handler.RegisterRoutes(f.router.Group(""))
	return f
}

func authorizeURL(clientID, redirectURI, extra string) string {
	u := "/oauth/authorize?response_type=code&client_id=" + clientID +
		"&redirect_uri=" + url.QueryEscape(redirectURI) + "&scope=read&state=xyz"
	if extra != "" {
		u += "&" + extra
	}
	return u
}

func ssoClient(tenantID uuid.UUID) *models.Client {
	return &models.Client{
		ID:           uuid.New(),
		TenantID:     tenantID,
		ClientID:     "web-app",
		Name:         "Web App",
		RedirectURIs: models.StringArray{"http://localhost:3000/callback"},
		GrantTypes:   models.StringArray{"authorization_code"},
		Scopes:       models.StringArray{"read", "write"},
		IsPublic:     false,
	}
}

func stubAuthorizeMocks(f *handlerFixture, client *models.Client) {
	f.clientService.On("GetByClientID", mock.Anything, f.tenantID, client.ClientID).Return(client, nil)
	f.clientService.On("ValidateRedirectURI", mock.Anything, mock.AnythingOfType("*models.Client"), client.RedirectURIs[0]).Return(nil)
	f.tenantService.On("GetByID", mock.Anything, f.tenantID).Return(&models.Tenant{ID: f.tenantID, Name: "T"}, nil)
}

func withSessionCookie(req *http.Request) {
	req.AddCookie(&http.Cookie{Name: "sg_session", Value: "sess-token"})
}

// ---- SSO on /oauth/authorize ----

func TestAuthorize_WithSessionAndConsent_IssuesCodeWithoutLogin(t *testing.T) {
	f := newBrowserFixture(t)
	client := ssoClient(f.tenantID)
	userID := uuid.New()
	session := &models.UserSession{ID: uuid.New(), TenantID: f.tenantID, UserID: userID, AuthTime: time.Now()}

	stubAuthorizeMocks(f, client)
	f.authService.On("GetSession", mock.Anything, f.tenantID, "sess-token").Return(session, nil)
	f.authService.On("HasConsent", mock.Anything, f.tenantID, userID, client.ID, "read").Return(true, nil)
	f.authService.On("GenerateAuthorizationCode", mock.Anything, f.tenantID, client.ID, userID,
		client.RedirectURIs[0], "read", "", "", "", mock.AnythingOfType("time.Time")).
		Return(&models.AuthorizationCode{Code: "sso-code"}, nil)

	req := httptest.NewRequest("GET", authorizeURL(client.ClientID, client.RedirectURIs[0], ""), nil)
	withSessionCookie(req)
	w := httptest.NewRecorder()
	f.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusFound, w.Code, "valid session must skip the login form")
	location := w.Header().Get("Location")
	assert.Contains(t, location, "code=sso-code")
	assert.Contains(t, location, "state=xyz")
}

func TestAuthorize_WithSessionNoConsent_ShowsConsentScreen(t *testing.T) {
	f := newBrowserFixture(t)
	client := ssoClient(f.tenantID)
	userID := uuid.New()
	session := &models.UserSession{ID: uuid.New(), TenantID: f.tenantID, UserID: userID, AuthTime: time.Now()}

	stubAuthorizeMocks(f, client)
	f.authService.On("GetSession", mock.Anything, f.tenantID, "sess-token").Return(session, nil)
	f.authService.On("HasConsent", mock.Anything, f.tenantID, userID, client.ID, "read").Return(false, nil)

	req := httptest.NewRequest("GET", authorizeURL(client.ClientID, client.RedirectURIs[0], ""), nil)
	withSessionCookie(req)
	w := httptest.NewRecorder()
	f.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "/oauth/consent", "consent form must be rendered")
	assert.Contains(t, w.Body.String(), "Allow Access")
}

func TestAuthorize_NoSession_ShowsLoginForm(t *testing.T) {
	f := newBrowserFixture(t)
	client := ssoClient(f.tenantID)
	stubAuthorizeMocks(f, client)

	req := httptest.NewRequest("GET", authorizeURL(client.ClientID, client.RedirectURIs[0], ""), nil)
	w := httptest.NewRecorder()
	f.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "/oauth/login")
}

// ---- prompt / max_age ----

func TestAuthorize_PromptNone_NoSession_LoginRequired(t *testing.T) {
	f := newBrowserFixture(t)
	client := ssoClient(f.tenantID)
	stubAuthorizeMocks(f, client)

	req := httptest.NewRequest("GET", authorizeURL(client.ClientID, client.RedirectURIs[0], "prompt=none"), nil)
	w := httptest.NewRecorder()
	f.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
	location := w.Header().Get("Location")
	assert.Contains(t, location, "error=login_required")
	assert.Contains(t, location, "state=xyz")
}

func TestAuthorize_PromptNone_SessionButNoConsent_ConsentRequired(t *testing.T) {
	f := newBrowserFixture(t)
	client := ssoClient(f.tenantID)
	userID := uuid.New()
	session := &models.UserSession{ID: uuid.New(), TenantID: f.tenantID, UserID: userID, AuthTime: time.Now()}

	stubAuthorizeMocks(f, client)
	f.authService.On("GetSession", mock.Anything, f.tenantID, "sess-token").Return(session, nil)
	f.authService.On("HasConsent", mock.Anything, f.tenantID, userID, client.ID, "read").Return(false, nil)

	req := httptest.NewRequest("GET", authorizeURL(client.ClientID, client.RedirectURIs[0], "prompt=none"), nil)
	withSessionCookie(req)
	w := httptest.NewRecorder()
	f.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Contains(t, w.Header().Get("Location"), "error=consent_required")
}

func TestAuthorize_PromptLogin_ForcesReauthentication(t *testing.T) {
	f := newBrowserFixture(t)
	client := ssoClient(f.tenantID)
	session := &models.UserSession{ID: uuid.New(), TenantID: f.tenantID, UserID: uuid.New(), AuthTime: time.Now()}

	stubAuthorizeMocks(f, client)
	f.authService.On("GetSession", mock.Anything, f.tenantID, "sess-token").Return(session, nil)

	req := httptest.NewRequest("GET", authorizeURL(client.ClientID, client.RedirectURIs[0], "prompt=login"), nil)
	withSessionCookie(req)
	w := httptest.NewRecorder()
	f.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "/oauth/login", "prompt=login must show the login form despite a session")
}

func TestAuthorize_MaxAgeExceeded_ForcesReauthentication(t *testing.T) {
	f := newBrowserFixture(t)
	client := ssoClient(f.tenantID)
	oldSession := &models.UserSession{ID: uuid.New(), TenantID: f.tenantID, UserID: uuid.New(),
		AuthTime: time.Now().Add(-2 * time.Hour)}

	stubAuthorizeMocks(f, client)
	f.authService.On("GetSession", mock.Anything, f.tenantID, "sess-token").Return(oldSession, nil)

	req := httptest.NewRequest("GET", authorizeURL(client.ClientID, client.RedirectURIs[0], "max_age=60"), nil)
	withSessionCookie(req)
	w := httptest.NewRecorder()
	f.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "/oauth/login", "stale authentication must trigger re-login")
}

// ---- Consent endpoint ----

func TestConsent_ApproveAndDeny(t *testing.T) {
	f := newBrowserFixture(t)
	client := ssoClient(f.tenantID)
	userID := uuid.New()
	session := &models.UserSession{ID: uuid.New(), TenantID: f.tenantID, UserID: userID, AuthTime: time.Now()}

	stubAuthorizeMocks(f, client)
	f.authService.On("GetSession", mock.Anything, f.tenantID, "sess-token").Return(session, nil)
	f.authService.On("HasConsent", mock.Anything, f.tenantID, userID, client.ID, "read").Return(false, nil)
	f.authService.On("GrantConsent", mock.Anything, f.tenantID, userID, client.ID, "read").Return(nil)
	f.authService.On("GenerateAuthorizationCode", mock.Anything, f.tenantID, client.ID, userID,
		client.RedirectURIs[0], "read", "", "", "", mock.AnythingOfType("time.Time")).
		Return(&models.AuthorizationCode{Code: "consent-code"}, nil)

	// Step 1: authorize renders the consent page with a CSRF token
	authorizeReq := httptest.NewRequest("GET", authorizeURL(client.ClientID, client.RedirectURIs[0], ""), nil)
	withSessionCookie(authorizeReq)
	authorizeResp := httptest.NewRecorder()
	f.router.ServeHTTP(authorizeResp, authorizeReq)
	require.Equal(t, http.StatusOK, authorizeResp.Code)

	csrfToken := extractCSRFToken(t, authorizeResp.Body.String())
	csrfCookie := extractCookie(authorizeResp, "sg_csrf")
	require.NotNil(t, csrfCookie)

	// Step 2a: approve
	form := url.Values{}
	form.Set("client_id", client.ClientID)
	form.Set("redirect_uri", client.RedirectURIs[0])
	form.Set("scope", "read")
	form.Set("state", "xyz")
	form.Set("csrf_token", csrfToken)
	form.Set("action", "approve")

	req := httptest.NewRequest("POST", "/oauth/consent", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(csrfCookie)
	withSessionCookie(req)
	w := httptest.NewRecorder()
	f.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Contains(t, w.Header().Get("Location"), "code=consent-code")
	f.authService.AssertCalled(t, "GrantConsent", mock.Anything, f.tenantID, userID, client.ID, "read")

	// Step 2b: deny → access_denied, no consent stored
	form.Set("action", "deny")
	req = httptest.NewRequest("POST", "/oauth/consent", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(csrfCookie)
	withSessionCookie(req)
	w = httptest.NewRecorder()
	f.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Contains(t, w.Header().Get("Location"), "error=access_denied")
}

func TestConsent_WithoutSession_Rejected(t *testing.T) {
	f := newBrowserFixture(t)

	form := url.Values{}
	form.Set("client_id", "web-app")
	form.Set("action", "approve")
	req := httptest.NewRequest("POST", "/oauth/consent", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	f.router.ServeHTTP(w, req)

	// No CSRF cookie/token → rejected before any consent processing
	assert.Equal(t, http.StatusBadRequest, w.Code)
	f.authService.AssertNotCalled(t, "GrantConsent", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

// ---- Logout ----

func TestLogout_RevokesSessionAndRedirects(t *testing.T) {
	f := newBrowserFixture(t)
	client := ssoClient(f.tenantID)

	f.authService.On("RevokeSession", mock.Anything, f.tenantID, "sess-token").Return(nil)
	f.clientService.On("GetByClientID", mock.Anything, f.tenantID, client.ClientID).Return(client, nil)

	req := httptest.NewRequest("GET", "/oauth/logout?client_id="+client.ClientID+
		"&post_logout_redirect_uri="+url.QueryEscape(client.RedirectURIs[0])+"&state=bye", nil)
	withSessionCookie(req)
	w := httptest.NewRecorder()
	f.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
	location := w.Header().Get("Location")
	assert.Contains(t, location, client.RedirectURIs[0])
	assert.Contains(t, location, "state=bye")
	f.authService.AssertCalled(t, "RevokeSession", mock.Anything, f.tenantID, "sess-token")

	// Session cookie cleared
	cleared := extractCookie(w, "sg_session")
	require.NotNil(t, cleared)
	assert.True(t, cleared.MaxAge < 0 || cleared.Value == "")
}

func TestLogout_UnregisteredRedirectURI_ShowsLoggedOutPage(t *testing.T) {
	f := newBrowserFixture(t)
	client := ssoClient(f.tenantID)

	f.authService.On("RevokeSession", mock.Anything, f.tenantID, "sess-token").Return(nil)
	f.clientService.On("GetByClientID", mock.Anything, f.tenantID, client.ClientID).Return(client, nil)

	req := httptest.NewRequest("GET", "/oauth/logout?client_id="+client.ClientID+
		"&post_logout_redirect_uri="+url.QueryEscape("https://evil.example.com/phish"), nil)
	withSessionCookie(req)
	w := httptest.NewRecorder()
	f.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "unregistered redirect URIs must not be followed")
	assert.Contains(t, w.Body.String(), "signed out")
}
