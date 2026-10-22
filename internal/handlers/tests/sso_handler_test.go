package tests

// sso_handler_test.go covers roadmap Phase 3: SSO sessions, remembered
// consent, prompt and max_age handling, and RP-initiated logout.

import (
	"errors"
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
	"shieldgate/internal/middleware"
	"shieldgate/internal/models"
	"shieldgate/tests/utils"
)

const (
	ssoClientID    = "web-app"
	ssoRedirectURI = "https://app.example/cb"
	ssoLogoutURI   = "https://app.example/signed-out"
	ssoEmail       = "alice@example.com"
	ssoPassword    = "pw-123456"
)

type ssoFixture struct {
	tenantID uuid.UUID
	user     *models.User
	client   *models.Client
	store    *sessionStore
	auth     *MockAuthService
	users    *MockUserService
	router   *gin.Engine
	// authTimes records the auth_time passed for each issued code
	authTimes []time.Time
}

func newSSOFixture(t *testing.T) *ssoFixture {
	t.Helper()
	gin.SetMode(gin.TestMode)
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)

	f := &ssoFixture{tenantID: uuid.New(), store: newSessionStore(), auth: new(MockAuthService)}
	f.user = &models.User{ID: uuid.New(), TenantID: f.tenantID, Email: ssoEmail}
	f.client = &models.Client{
		ID: uuid.New(), TenantID: f.tenantID, ClientID: ssoClientID, Name: "Web App",
		RedirectURIs:           models.StringArray{ssoRedirectURI},
		PostLogoutRedirectURIs: models.StringArray{ssoLogoutURI},
		GrantTypes:             models.StringArray{"authorization_code"},
		Scopes:                 models.StringArray{"openid", "profile", "email"},
	}

	tenants, users, clients := new(MockTenantService), new(MockUserService), new(MockClientService)
	f.users = users
	tenants.On("GetByID", mock.Anything, f.tenantID).Return(&models.Tenant{ID: f.tenantID, Name: "T"}, nil)
	users.On("Authenticate", mock.Anything, f.tenantID, ssoEmail, ssoPassword).Return(f.user, nil)
	users.On("Authenticate", mock.Anything, f.tenantID, mock.Anything, mock.Anything).Return(nil, models.ErrInvalidCredentials)
	users.On("GetByID", mock.Anything, f.tenantID, f.user.ID).Return(f.user, nil)
	clients.On("GetByClientID", mock.Anything, f.tenantID, ssoClientID).Return(f.client, nil)
	clients.On("GetByClientID", mock.Anything, f.tenantID, mock.Anything).Return(nil, models.ErrClientNotFound)
	clients.On("ValidateRedirectURI", mock.Anything, f.client, ssoRedirectURI).Return(nil)
	clients.On("ValidateRedirectURI", mock.Anything, f.client, mock.Anything).Return(errors.New("not registered"))
	f.auth.On("GenerateAuthorizationCode", mock.Anything, f.tenantID, f.client.ID, f.user.ID, ssoRedirectURI,
		mock.Anything, "", "", mock.Anything, mock.AnythingOfType("time.Time")).
		Run(func(args mock.Arguments) { f.authTimes = append(f.authTimes, args.Get(9).(time.Time)) }).
		Return(&models.AuthorizationCode{Code: "the-code"}, nil)

	handler := handlers.NewOAuthHandler(utils.CreateTestConfig(), tenants, users, clients, f.auth, f.store, logger)
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

// deleteUser makes the user service report the fixture user as gone
func (f *ssoFixture) deleteUser() {
	for _, call := range f.users.ExpectedCalls {
		if call.Method == "GetByID" {
			call.ReturnArguments = mock.Arguments{nil, models.ErrUserNotFound}
		}
	}
}

// browser carries cookies between requests like a user agent
type browser struct {
	t       *testing.T
	f       *ssoFixture
	cookies map[string]*http.Cookie
}

func (f *ssoFixture) newBrowser(t *testing.T) *browser {
	return &browser{t: t, f: f, cookies: map[string]*http.Cookie{}}
}

func (b *browser) do(req *http.Request) *httptest.ResponseRecorder {
	for _, c := range b.cookies {
		req.AddCookie(c)
	}
	w := httptest.NewRecorder()
	b.f.router.ServeHTTP(w, req)
	for _, c := range w.Result().Cookies() {
		if c.MaxAge < 0 {
			delete(b.cookies, c.Name)
		} else {
			b.cookies[c.Name] = c
		}
	}
	return w
}

func (b *browser) get(path string) *httptest.ResponseRecorder {
	return b.do(httptest.NewRequest(http.MethodGet, path, nil))
}

func (b *browser) post(path string, form url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return b.do(req)
}

// authorize starts an authorization request with extra query parameters
func (b *browser) authorize(scope string, extra map[string]string) *httptest.ResponseRecorder {
	q := url.Values{"response_type": {"code"}, "client_id": {ssoClientID}, "redirect_uri": {ssoRedirectURI},
		"scope": {scope}, "state": {"st"}}
	for k, v := range extra {
		q.Set(k, v)
	}
	return b.get("/oauth/authorize?" + q.Encode())
}

// submit posts the page's form (login or consent) with its hidden fields
func (b *browser) submit(page *httptest.ResponseRecorder, action string, fields map[string]string) *httptest.ResponseRecorder {
	b.t.Helper()
	form := hiddenFields(b.t, page.Body.String())
	for k, v := range fields {
		form.Set(k, v)
	}
	return b.post(action, form)
}

// login completes a login page with valid credentials
func (b *browser) login(page *httptest.ResponseRecorder) *httptest.ResponseRecorder {
	return b.submit(page, "/oauth/login", map[string]string{"username": ssoEmail, "password": ssoPassword})
}

func hiddenFields(t *testing.T, body string) url.Values {
	t.Helper()
	form := url.Values{}
	for _, chunk := range strings.Split(body, `<input type="hidden" name="`)[1:] {
		name := chunk[:strings.Index(chunk, `"`)]
		rest := chunk[strings.Index(chunk, `value="`)+len(`value="`):]
		form.Set(name, htmlUnescape(rest[:strings.Index(rest, `"`)]))
	}
	require.NotEmpty(t, form.Get("csrf_token"), "page has no CSRF token")
	return form
}

func htmlUnescape(s string) string {
	return strings.NewReplacer("&amp;", "&", "&#43;", "+", "&#34;", `"`, "&lt;", "<", "&gt;", ">", "&#39;", "'").Replace(s)
}

func isLoginPage(w *httptest.ResponseRecorder) bool {
	return w.Code == http.StatusOK && strings.Contains(w.Body.String(), `action="/oauth/login"`)
}

func isConsentPage(w *httptest.ResponseRecorder) bool {
	return w.Code == http.StatusOK && strings.Contains(w.Body.String(), `action="/oauth/consent"`)
}

// signIn runs a full first-time flow (login + allow) for scope
func (b *browser) signIn(scope string) {
	b.t.Helper()
	consent := b.login(b.authorize(scope, nil))
	require.True(b.t, isConsentPage(consent), consent.Body.String())
	require.Equal(b.t, "the-code", redirectQuery(b.t, b.submit(consent, "/oauth/consent", map[string]string{"decision": "allow"})).Get("code"))
}

func TestSSO_FirstVisit_LoginThenConsentThenCode(t *testing.T) {
	// Arrange
	f := newSSOFixture(t)
	b := f.newBrowser(t)

	// Act
	loginPage := b.authorize("openid profile", nil)
	consentPage := b.login(loginPage)
	callback := b.submit(consentPage, "/oauth/consent", map[string]string{"decision": "allow"})

	// Assert
	assert.True(t, isLoginPage(loginPage))
	assert.True(t, isConsentPage(consentPage))
	assert.Contains(t, consentPage.Body.String(), ssoEmail)
	q := redirectQuery(t, callback)
	assert.Equal(t, "the-code", q.Get("code"))
	assert.Equal(t, "st", q.Get("state"))
	session := b.cookies["sg_session"]
	require.NotNil(t, session)
	assert.True(t, session.HttpOnly)
	assert.Equal(t, http.SameSiteLaxMode, session.SameSite)
}

func TestSSO_ReturningUser_SkipsLoginAndConsentKeepingAuthTime(t *testing.T) {
	// Arrange
	f := newSSOFixture(t)
	b := f.newBrowser(t)
	b.signIn("openid profile")

	// Act
	w := b.authorize("openid profile", nil)

	// Assert
	assert.Equal(t, "the-code", redirectQuery(t, w).Get("code"))
	require.Len(t, f.authTimes, 2)
	assert.Equal(t, f.authTimes[0], f.authTimes[1], "auth_time is the original login, not the SSO hit")
}

func TestSSO_NewScope_AsksConsentAgainOnlyForUngrantedScope(t *testing.T) {
	// Arrange
	f := newSSOFixture(t)
	b := f.newBrowser(t)
	b.signIn("openid profile")

	// Act
	subset := b.authorize("openid", nil)
	wider := b.authorize("openid email", nil)

	// Assert
	assert.Equal(t, http.StatusFound, subset.Code, "previously granted scopes need no consent")
	assert.True(t, isConsentPage(wider))
}

func TestSSO_ConsentDenied_RedirectsAccessDenied(t *testing.T) {
	// Arrange
	f := newSSOFixture(t)
	b := f.newBrowser(t)
	consent := b.login(b.authorize("openid", nil))

	// Act
	w := b.submit(consent, "/oauth/consent", map[string]string{"decision": "deny"})

	// Assert
	q := redirectQuery(t, w)
	assert.Equal(t, "access_denied", q.Get("error"))
	assert.Equal(t, "st", q.Get("state"))
	assert.True(t, isConsentPage(b.authorize("openid", nil)), "a denial is not remembered as consent")
}

func TestSSO_ConsentWithoutCSRFOrSession_Rejected(t *testing.T) {
	// Arrange
	f := newSSOFixture(t)
	b := f.newBrowser(t)
	consent := b.login(b.authorize("openid", nil))
	fields := hiddenFields(t, consent.Body.String())
	fields.Set("decision", "allow")

	// Act
	forged := fields
	forged.Set("csrf_token", "forged")
	noCSRF := b.post("/oauth/consent", forged)
	stranger := f.newBrowser(t)
	stranger.cookies["sg_csrf"] = b.cookies["sg_csrf"]
	noSession := stranger.submit(consent, "/oauth/consent", map[string]string{"decision": "allow"})

	// Assert
	assert.Equal(t, http.StatusBadRequest, noCSRF.Code)
	assert.True(t, isLoginPage(noSession), "consent requires the user's own session")
	assert.Empty(t, f.authTimes)
}

func TestPrompt_None(t *testing.T) {
	f := newSSOFixture(t)

	t.Run("no session yields login_required", func(t *testing.T) {
		w := f.newBrowser(t).authorize("openid", map[string]string{"prompt": "none"})
		assert.Equal(t, "login_required", redirectQuery(t, w).Get("error"))
	})
	t.Run("session without consent yields consent_required", func(t *testing.T) {
		b := f.newBrowser(t)
		b.login(b.authorize("openid", nil)) // logged in, consent page left unanswered
		w := b.authorize("openid", map[string]string{"prompt": "none"})
		assert.Equal(t, "consent_required", redirectQuery(t, w).Get("error"))
	})
	t.Run("session and consent yield a code silently", func(t *testing.T) {
		b := f.newBrowser(t)
		b.signIn("openid")
		w := b.authorize("openid", map[string]string{"prompt": "none"})
		assert.Equal(t, "the-code", redirectQuery(t, w).Get("code"))
	})
	t.Run("none combined with login is invalid", func(t *testing.T) {
		w := f.newBrowser(t).authorize("openid", map[string]string{"prompt": "none login"})
		assert.Equal(t, "invalid_request", redirectQuery(t, w).Get("error"))
	})
}

func TestPrompt_LoginAndConsent_ForceTheirStepsDespiteSession(t *testing.T) {
	// Arrange
	f := newSSOFixture(t)
	b := f.newBrowser(t)
	b.signIn("openid")

	// Act
	forceLogin := b.authorize("openid", map[string]string{"prompt": "login"})
	forceConsent := b.authorize("openid", map[string]string{"prompt": "consent"})

	// Assert
	assert.True(t, isLoginPage(forceLogin))
	assert.True(t, isConsentPage(forceConsent))
}

func TestMaxAge_StaleAuthentication_RequiresLogin(t *testing.T) {
	// Arrange
	f := newSSOFixture(t)
	b := f.newBrowser(t)
	b.signIn("openid")
	f.store.sessions.ageAll(10 * time.Minute)

	// Act
	tooOld := b.authorize("openid", map[string]string{"max_age": "60"})
	fresh := b.authorize("openid", map[string]string{"max_age": "3600"})
	invalid := b.authorize("openid", map[string]string{"max_age": "-5"})

	// Assert
	assert.True(t, isLoginPage(tooOld))
	assert.Equal(t, "the-code", redirectQuery(t, fresh).Get("code"))
	assert.Equal(t, "invalid_request", redirectQuery(t, invalid).Get("error"))
}

func TestLogin_RotatesSessionToken(t *testing.T) {
	// Arrange
	f := newSSOFixture(t)
	b := f.newBrowser(t)
	b.signIn("openid")
	first := b.cookies["sg_session"].Value

	// Act: authenticate again in the same browser
	b.login(b.authorize("openid", map[string]string{"prompt": "login"}))

	// Assert
	assert.NotEqual(t, first, b.cookies["sg_session"].Value)
	assert.Equal(t, 1, f.store.sessions.count(), "the previous session is deleted, not left alive")
}

func TestLogout_ValidHintForSessionUser_EndsSessionAndRedirects(t *testing.T) {
	// Arrange
	f := newSSOFixture(t)
	b := f.newBrowser(t)
	b.signIn("openid")
	f.auth.On("ParseIDTokenHint", mock.Anything, "hint").
		Return(&models.IDTokenClaims{UserInfo: models.UserInfo{Sub: f.user.ID.String()}, Aud: ssoClientID, TenantID: f.tenantID.String()}, nil)

	// Act
	w := b.get("/oauth/logout?" + url.Values{"id_token_hint": {"hint"}, "post_logout_redirect_uri": {ssoLogoutURI}, "state": {"bye"}}.Encode())

	// Assert
	require.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, ssoLogoutURI+"?state=bye", w.Header().Get("Location"))
	assert.Nil(t, b.cookies["sg_session"])
	assert.Equal(t, 0, f.store.sessions.count())
	assert.True(t, isLoginPage(b.authorize("openid", nil)), "SSO ends with the session")
}

func TestLogout_WithoutHint_AsksConfirmationBeforeEndingSession(t *testing.T) {
	// Arrange
	f := newSSOFixture(t)
	b := f.newBrowser(t)
	b.signIn("openid")

	// Act
	confirm := b.get("/oauth/logout?" + url.Values{"client_id": {ssoClientID}, "post_logout_redirect_uri": {ssoLogoutURI}}.Encode())
	sessionsAfterGet := f.store.sessions.count()
	done := b.submit(confirm, "/oauth/logout", nil)

	// Assert
	assert.Equal(t, http.StatusOK, confirm.Code)
	assert.Contains(t, confirm.Body.String(), "Sign out?")
	assert.Equal(t, 1, sessionsAfterGet, "a bare GET must not sign the user out (logout CSRF)")
	assert.Equal(t, ssoLogoutURI, done.Header().Get("Location"))
	assert.Equal(t, 0, f.store.sessions.count())
}

func TestLogout_HintForAnotherUser_AsksConfirmation(t *testing.T) {
	// Arrange
	f := newSSOFixture(t)
	b := f.newBrowser(t)
	b.signIn("openid")
	f.auth.On("ParseIDTokenHint", mock.Anything, "other").
		Return(&models.IDTokenClaims{UserInfo: models.UserInfo{Sub: uuid.NewString()}, Aud: ssoClientID, TenantID: f.tenantID.String()}, nil)

	// Act
	w := b.get("/oauth/logout?id_token_hint=other")

	// Assert
	assert.Contains(t, w.Body.String(), "Sign out?")
	assert.Equal(t, 1, f.store.sessions.count())
}

func TestLogout_UnregisteredRedirect_RefusedWithoutEndingSession(t *testing.T) {
	// Arrange
	f := newSSOFixture(t)
	b := f.newBrowser(t)
	b.signIn("openid")

	// Act
	w := b.get("/oauth/logout?" + url.Values{"client_id": {ssoClientID}, "post_logout_redirect_uri": {"https://evil.example/"}}.Encode())
	noClient := b.get("/oauth/logout?" + url.Values{"post_logout_redirect_uri": {ssoLogoutURI}}.Encode())

	// Assert
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Empty(t, w.Header().Get("Location"))
	assert.Equal(t, http.StatusBadRequest, noClient.Code)
	assert.Equal(t, 1, f.store.sessions.count())
}

func TestLogout_POSTWithoutCSRF_Rejected(t *testing.T) {
	// Arrange
	f := newSSOFixture(t)
	b := f.newBrowser(t)
	b.signIn("openid")

	// Act
	w := b.post("/oauth/logout", url.Values{"csrf_token": {"forged"}})

	// Assert
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, 1, f.store.sessions.count())
}

func TestLogout_NoSession_ShowsSignedOutPage(t *testing.T) {
	// Arrange
	f := newSSOFixture(t)

	// Act
	w := f.newBrowser(t).get("/oauth/logout")

	// Assert
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "You have signed out")
}

func TestSSO_SuspendedUser_SessionEndedAndLoginRequired(t *testing.T) {
	// Arrange
	f := newSSOFixture(t)
	b := f.newBrowser(t)
	b.signIn("openid")
	f.user.Status = models.UserStatusSuspended

	// Act
	w := b.authorize("openid", nil)

	// Assert
	assert.True(t, isLoginPage(w), "a suspended user's session must not issue codes")
	assert.Equal(t, 0, f.store.sessions.count())
	assert.Len(t, f.authTimes, 1)
}

func TestSSO_DeletedUser_PromptNoneReturnsLoginRequired(t *testing.T) {
	// Arrange
	f := newSSOFixture(t)
	b := f.newBrowser(t)
	b.signIn("openid")
	f.deleteUser()

	// Act
	w := b.authorize("openid", map[string]string{"prompt": "none"})

	// Assert
	assert.Equal(t, "login_required", redirectQuery(t, w).Get("error"))
	assert.Equal(t, 0, f.store.sessions.count())
}
