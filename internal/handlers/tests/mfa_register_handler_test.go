package tests

// mfa_register_handler_test.go covers the MFA login step and Dynamic Client
// Registration (RFC 7591).

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"shieldgate/internal/models"
	"shieldgate/tests/utils"
)

func extractHiddenField(t *testing.T, body, name string) string {
	t.Helper()
	re := regexp.MustCompile(`name="` + name + `" value="([^"]+)"`)
	matches := re.FindStringSubmatch(body)
	if len(matches) != 2 {
		t.Fatalf("hidden field %s not found", name)
	}
	return matches[1]
}

// ---- MFA login step ----

func TestLogin_MFAEnabledUser_RequiresTOTPStep(t *testing.T) {
	f := newBrowserFixture(t)
	client := ssoClient(f.tenantID)
	userID := uuid.New()
	user := &models.User{ID: userID, TenantID: f.tenantID, Email: "bob@example.com", Username: "bob", MFAEnabled: true}
	session := &models.UserSession{ID: uuid.New(), TenantID: f.tenantID, UserID: userID, AuthTime: time.Now()}

	stubAuthorizeMocks(f, client)
	f.userService.On("Authenticate", mock.Anything, f.tenantID, "bob@example.com", "pw").Return(user, nil)
	f.userService.On("VerifyMFA", mock.Anything, f.tenantID, userID, "123456").Return(nil)
	f.authService.On("CreateSession", mock.Anything, f.tenantID, userID, mock.Anything, mock.Anything).Return("sess", session, nil)
	f.authService.On("HasConsent", mock.Anything, f.tenantID, userID, client.ID, "read").Return(true, nil)
	f.authService.On("GenerateAuthorizationCode", mock.Anything, f.tenantID, client.ID, userID,
		client.RedirectURIs[0], "read", "", "", "", mock.AnythingOfType("time.Time")).
		Return(&models.AuthorizationCode{Code: "mfa-code"}, nil)

	// Step 1: authorize → login page with CSRF
	authorizeResp := httptest.NewRecorder()
	f.router.ServeHTTP(authorizeResp, httptest.NewRequest("GET", authorizeURL(client.ClientID, client.RedirectURIs[0], ""), nil))
	require.Equal(t, http.StatusOK, authorizeResp.Code)
	csrf1 := extractCSRFToken(t, authorizeResp.Body.String())
	cookie1 := extractCookie(authorizeResp, "sg_csrf")

	// Step 2: login with password → MFA page, NOT a code redirect
	loginForm := url.Values{}
	loginForm.Set("username", "bob@example.com")
	loginForm.Set("password", "pw")
	loginForm.Set("client_id", client.ClientID)
	loginForm.Set("redirect_uri", client.RedirectURIs[0])
	loginForm.Set("scope", "read")
	loginForm.Set("csrf_token", csrf1)

	loginReq := httptest.NewRequest("POST", "/oauth/login", strings.NewReader(loginForm.Encode()))
	loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginReq.AddCookie(cookie1)
	loginResp := httptest.NewRecorder()
	f.router.ServeHTTP(loginResp, loginReq)

	require.Equal(t, http.StatusOK, loginResp.Code, "MFA user must not be redirected after password alone")
	body := loginResp.Body.String()
	assert.Contains(t, body, "/oauth/mfa", "MFA form must be rendered")
	f.authService.AssertNotCalled(t, "CreateSession", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)

	mfaToken := extractHiddenField(t, body, "mfa_token")
	csrf2 := extractCSRFToken(t, body)
	cookie2 := extractCookie(loginResp, "sg_csrf")
	require.NotNil(t, cookie2)

	// Step 3: TOTP code → session + code redirect
	mfaForm := url.Values{}
	mfaForm.Set("mfa_token", mfaToken)
	mfaForm.Set("code", "123456")
	mfaForm.Set("client_id", client.ClientID)
	mfaForm.Set("redirect_uri", client.RedirectURIs[0])
	mfaForm.Set("scope", "read")
	mfaForm.Set("csrf_token", csrf2)

	mfaReq := httptest.NewRequest("POST", "/oauth/mfa", strings.NewReader(mfaForm.Encode()))
	mfaReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	mfaReq.AddCookie(cookie2)
	mfaResp := httptest.NewRecorder()
	f.router.ServeHTTP(mfaResp, mfaReq)

	assert.Equal(t, http.StatusFound, mfaResp.Code)
	assert.Contains(t, mfaResp.Header().Get("Location"), "code=mfa-code")
	f.authService.AssertCalled(t, "CreateSession", mock.Anything, f.tenantID, userID, mock.Anything, mock.Anything)
}

func TestMFAVerify_TamperedStateToken_Rejected(t *testing.T) {
	f := newBrowserFixture(t)
	client := ssoClient(f.tenantID)
	stubAuthorizeMocks(f, client)

	// Get a CSRF token from the authorize step
	authorizeResp := httptest.NewRecorder()
	f.router.ServeHTTP(authorizeResp, httptest.NewRequest("GET", authorizeURL(client.ClientID, client.RedirectURIs[0], ""), nil))
	csrf := extractCSRFToken(t, authorizeResp.Body.String())
	cookie := extractCookie(authorizeResp, "sg_csrf")

	form := url.Values{}
	form.Set("mfa_token", "forged.token")
	form.Set("code", "123456")
	form.Set("csrf_token", csrf)

	req := httptest.NewRequest("POST", "/oauth/mfa", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	f.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	f.userService.AssertNotCalled(t, "VerifyMFA", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

// ---- Dynamic Client Registration ----

func TestRegisterClient_RequiresToken_AndCreatesClient(t *testing.T) {
	f := newBrowserFixture(t)
	cfg := utils.CreateTestConfig()

	// Without a bearer token → 401
	noAuth := httptest.NewRequest("POST", "/oauth/register", strings.NewReader(`{"client_name":"App","redirect_uris":["https://app/cb"]}`))
	noAuth.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	f.router.ServeHTTP(w, noAuth)
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	// With a valid management token → 201 with one-time client_secret
	adminID, adminClient := uuid.New(), uuid.New()
	token := utils.CreateTestJWT(cfg, adminID, adminClient, f.tenantID, "write")
	claims := &models.JWTClaims{TenantID: f.tenantID.String(), UserID: adminID.String(), Sub: adminID.String()}
	f.authService.On("ValidateAccessToken", mock.Anything, f.tenantID, token).Return(claims, nil)

	created := &models.Client{
		ID:                uuid.New(),
		TenantID:          f.tenantID,
		ClientID:          "client_new",
		PlainClientSecret: "secret_plaintext_once",
		Name:              "App",
		RedirectURIs:      models.StringArray{"https://app/cb"},
		GrantTypes:        models.StringArray{"authorization_code"},
		Scopes:            models.StringArray{"read"},
	}
	f.clientService.On("Create", mock.Anything, f.tenantID, mock.AnythingOfType("*models.CreateClientRequest")).Return(created, nil)

	req := httptest.NewRequest("POST", "/oauth/register",
		strings.NewReader(`{"client_name":"App","redirect_uris":["https://app/cb"],"scope":"read"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	f.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	assert.Contains(t, w.Body.String(), "client_new")
	assert.Contains(t, w.Body.String(), "secret_plaintext_once")
	assert.Contains(t, w.Body.String(), "client_id_issued_at")
}
