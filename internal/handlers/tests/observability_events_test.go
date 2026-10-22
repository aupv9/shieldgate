package tests

// observability_events_test.go covers roadmap 4.5 in the browser and token
// flows: what is audited and counted, and what is not.

import (
	"context"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"shieldgate/internal/models"
)

type fakeAuditLog struct {
	mu      sync.Mutex
	entries []*models.AuditLog
}

func (f *fakeAuditLog) Log(ctx context.Context, entry *models.AuditLog) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.entries = append(f.entries, entry)
	return nil
}

// actions lists the audited actions in order
func (f *fakeAuditLog) actions() []models.AuditAction {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]models.AuditAction, len(f.entries))
	for i, e := range f.entries {
		out[i] = e.Action
	}
	return out
}

func (f *fakeAuditLog) find(t *testing.T, action models.AuditAction) *models.AuditLog {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, e := range f.entries {
		if e.Action == action {
			return e
		}
	}
	t.Fatalf("no %s audit entry", action)
	return nil
}

// scrape returns the Prometheus exposition of the fixture's metrics
func (f *ssoFixture) scrape(t *testing.T) string {
	t.Helper()
	w := httptest.NewRecorder()
	f.metrics.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	return w.Body.String()
}

func TestEvents_LoginConsentLogout_Audited(t *testing.T) {
	// Arrange
	f := newSSOFixture(t)
	b := f.newBrowser(t)

	// Act
	b.signIn("openid profile")
	b.get("/oauth/logout?" + url.Values{"id_token_hint": {""}}.Encode())
	logoutPage := b.get("/oauth/logout")
	b.submit(logoutPage, "/oauth/logout", nil)

	// Assert
	assert.Equal(t, []models.AuditAction{
		models.AuditActionUserLogin, models.AuditActionConsentGranted, models.AuditActionUserLogout,
	}, f.audit.actions())
	login := f.audit.find(t, models.AuditActionUserLogin)
	assert.Equal(t, &f.user.ID, login.UserID)
	assert.Equal(t, &f.client.ID, login.ClientID)
	assert.True(t, login.Success)
	assert.Equal(t, []string{"pwd"}, login.Metadata["amr"])
	assert.Equal(t, "openid profile", f.audit.find(t, models.AuditActionConsentGranted).Metadata["scope"])
	metrics := f.scrape(t)
	assert.Contains(t, metrics, `shieldgate_auth_events_total{event="login",result="success"} 1`)
	assert.Contains(t, metrics, `shieldgate_auth_events_total{event="consent",result="granted"} 1`)
	assert.Contains(t, metrics, `shieldgate_auth_events_total{event="logout",result="success"} 1`)
}

func TestEvents_FailedLogin_AuditedWithAttemptedUsername(t *testing.T) {
	// Arrange
	f := newSSOFixture(t)
	b := f.newBrowser(t)

	// Act
	b.submit(b.authorize("openid", nil), "/oauth/login", map[string]string{"username": "mallory@example.com", "password": "guess"})

	// Assert
	entry := f.audit.find(t, models.AuditActionUserLoginFailed)
	assert.False(t, entry.Success)
	assert.Nil(t, entry.UserID)
	assert.Equal(t, "mallory@example.com", entry.Metadata["username"])
	assert.Equal(t, "invalid_credentials", entry.ErrorCode)
	for _, e := range f.audit.entries {
		assert.NotContains(t, e.Metadata, "password", "passwords are never audited")
	}
	assert.Contains(t, f.scrape(t), `shieldgate_auth_events_total{event="login",result="invalid_credentials"} 1`)
}

func TestEvents_MFAFailureAndSuccess(t *testing.T) {
	// Arrange
	f := newSSOFixture(t)
	f.mfa.enabled = true
	b := f.newBrowser(t)
	mfaPage := b.login(b.authorize("openid", nil))

	// Act
	retry := b.submit(mfaPage, "/oauth/login/mfa", map[string]string{"code": "000000"})
	b.submit(retry, "/oauth/login/mfa", map[string]string{"code": goodTOTP})

	// Assert
	assert.Equal(t, []models.AuditAction{models.AuditActionMFAFailed, models.AuditActionUserLogin}, f.audit.actions(),
		"the password step alone is not a login")
	assert.Equal(t, []string{"pwd", "otp", "mfa"}, f.audit.find(t, models.AuditActionUserLogin).Metadata["amr"])
	metrics := f.scrape(t)
	assert.Contains(t, metrics, `shieldgate_auth_events_total{event="login",result="mfa_required"} 1`)
	assert.Contains(t, metrics, `shieldgate_auth_events_total{event="mfa",result="invalid_code"} 1`)
	assert.Contains(t, metrics, `shieldgate_auth_events_total{event="mfa",result="success"} 1`)
}

func TestEvents_TokenEndpoint_CountsOutcomeByOAuthError(t *testing.T) {
	// Arrange
	f := newSSOFixture(t)
	f.clients.On("ValidateClient", mock.Anything, f.tenantID, "nope", "").Return(nil, models.ErrInvalidClient)
	post := func(form url.Values) {
		req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		f.router.ServeHTTP(httptest.NewRecorder(), req)
	}

	// Act
	post(url.Values{"grant_type": {"password"}})
	post(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"x"}, "client_id": {"nope"}})

	// Assert
	metrics := f.scrape(t)
	require.Contains(t, metrics, "shieldgate_token_requests_total")
	assert.Contains(t, metrics, `shieldgate_token_requests_total{grant_type="other",result="unsupported_grant_type"} 1`)
	assert.Contains(t, metrics, `shieldgate_token_requests_total{grant_type="refresh_token",result="invalid_client"} 1`)
	assert.Empty(t, f.audit.entries, "failed token requests are counted, not written to the audit log")
}
