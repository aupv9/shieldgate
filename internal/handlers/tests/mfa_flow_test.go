package tests

// mfa_flow_test.go covers roadmap 4.1 in the browser flows: the second
// factor between password and session for /oauth/login and /oauth/device,
// the amr it records, and attempts to skip or forge the step.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
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
)

const (
	goodTOTP     = "123456"
	goodRecovery = "ABCDE-FGHJK"
)

// fakeMFAService accepts goodTOTP and goodRecovery when enabled
type fakeMFAService struct {
	mu      sync.Mutex
	enabled bool
	locked  bool
	verifys int
}

func (m *fakeMFAService) Status(ctx context.Context, tenantID, userID uuid.UUID) (*models.MFAStatus, error) {
	return &models.MFAStatus{Enabled: m.enabled}, nil
}

func (m *fakeMFAService) IsEnabled(ctx context.Context, tenantID, userID uuid.UUID) (bool, error) {
	return m.enabled, nil
}

func (m *fakeMFAService) BeginTOTPEnrollment(ctx context.Context, tenantID, userID uuid.UUID) (*models.TOTPEnrollment, error) {
	return &models.TOTPEnrollment{Secret: "SECRET", OTPAuthURI: "otpauth://totp/x"}, nil
}

func (m *fakeMFAService) ConfirmTOTPEnrollment(ctx context.Context, tenantID, userID uuid.UUID, code string) ([]string, error) {
	return []string{goodRecovery}, nil
}

func (m *fakeMFAService) Verify(ctx context.Context, tenantID, userID uuid.UUID, code string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.verifys++
	switch {
	case !m.enabled:
		return "", models.ErrMFANotEnabled
	case m.locked:
		return "", models.ErrMFALocked
	case code == goodTOTP:
		return models.MFAMethodTOTP, nil
	case code == goodRecovery:
		return models.MFAMethodRecoveryCode, nil
	}
	return "", models.ErrInvalidMFACode
}

func (m *fakeMFAService) RegenerateRecoveryCodes(ctx context.Context, tenantID, userID uuid.UUID) ([]string, error) {
	return []string{goodRecovery}, nil
}

func (m *fakeMFAService) Disable(ctx context.Context, tenantID, userID uuid.UUID) error {
	m.enabled = false
	return nil
}

func isMFAPage(w *httptest.ResponseRecorder) bool {
	return w.Code == http.StatusOK && strings.Contains(w.Body.String(), "Two-step verification")
}

func TestMFALogin_PasswordThenCode_SessionAndCodeCarryAMR(t *testing.T) {
	tests := []struct {
		name    string
		code    string
		wantAMR []string
	}{
		{"authenticator code", goodTOTP, []string{"pwd", "otp", "mfa"}},
		{"recovery code", goodRecovery, []string{"pwd", "mfa"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			f := newSSOFixture(t)
			f.mfa.enabled = true
			b := f.newBrowser(t)

			// Act
			mfaPage := b.login(b.authorize("openid", nil))
			_, sessionAfterPassword := b.cookies["sg_session"]
			consent := b.submit(mfaPage, "/oauth/login/mfa", map[string]string{"code": tt.code})
			callback := b.submit(consent, "/oauth/consent", map[string]string{"decision": "allow"})

			// Assert
			assert.True(t, isMFAPage(mfaPage), mfaPage.Body.String())
			assert.False(t, sessionAfterPassword, "the password alone must not create a session")
			assert.True(t, isConsentPage(consent), consent.Body.String())
			assert.Equal(t, "the-code", redirectQuery(t, callback).Get("code"))
			require.Len(t, f.amrs, 1)
			assert.Equal(t, tt.wantAMR, f.amrs[0])
			assert.Equal(t, "st", hiddenFields(t, mfaPage.Body.String()).Get("state"), "the authorization request survives the MFA step")
		})
	}
}

func TestMFALogin_NoMFA_AMRIsPassword(t *testing.T) {
	// Arrange
	f := newSSOFixture(t)
	b := f.newBrowser(t)

	// Act
	b.signIn("openid")

	// Assert
	require.Len(t, f.amrs, 1)
	assert.Equal(t, []string{"pwd"}, f.amrs[0])
}

func TestMFALogin_WrongCode_AsksAgainWithoutSession(t *testing.T) {
	// Arrange
	f := newSSOFixture(t)
	f.mfa.enabled = true
	b := f.newBrowser(t)
	mfaPage := b.login(b.authorize("openid", nil))

	// Act
	retry := b.submit(mfaPage, "/oauth/login/mfa", map[string]string{"code": "000000"})
	then := b.submit(retry, "/oauth/login/mfa", map[string]string{"code": goodTOTP})

	// Assert
	assert.True(t, isMFAPage(retry))
	assert.Contains(t, retry.Body.String(), "Invalid code")
	assert.True(t, isConsentPage(then), "the user can retry with the right code")
}

func TestMFALogin_Locked_BackToLogin(t *testing.T) {
	// Arrange
	f := newSSOFixture(t)
	f.mfa.enabled = true
	b := f.newBrowser(t)
	mfaPage := b.login(b.authorize("openid", nil))
	f.mfa.locked = true

	// Act
	w := b.submit(mfaPage, "/oauth/login/mfa", map[string]string{"code": goodTOTP})

	// Assert
	assert.True(t, isLoginPage(w))
	assert.Contains(t, w.Body.String(), "Too many incorrect codes")
	assert.NotContains(t, b.cookies, "sg_session")
}

func TestMFALogin_SkippingOrForgingTheStep_Rejected(t *testing.T) {
	tests := []struct {
		name   string
		tamper func(form url.Values, f *ssoFixture)
	}{
		{"no pending token", func(form url.Values, f *ssoFixture) { form.Del("mfa_token") }},
		{"forged pending token", func(form url.Values, f *ssoFixture) {
			payload, _, _ := strings.Cut(form.Get("mfa_token"), ".")
			form.Set("mfa_token", payload+".forged-signature")
		}},
		{"pending token for another user", func(form url.Values, f *ssoFixture) {
			// Re-signing needs the server secret; swapping the payload
			// keeps the old signature, which no longer matches
			_, sig, _ := strings.Cut(form.Get("mfa_token"), ".")
			form.Set("mfa_token", "eyJ0IjoiIiwidSI6IiIsInAiOiJsb2dpbiIsImUiOjk5OTk5OTk5OTl9."+sig)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			f := newSSOFixture(t)
			f.mfa.enabled = true
			b := f.newBrowser(t)
			mfaPage := b.login(b.authorize("openid", nil))
			form := hiddenFields(t, mfaPage.Body.String())
			form.Set("code", goodTOTP)
			tt.tamper(form, f)

			// Act
			w := b.post("/oauth/login/mfa", form)

			// Assert
			assert.True(t, isLoginPage(w), w.Body.String())
			assert.NotContains(t, b.cookies, "sg_session")
			assert.Zero(t, f.mfa.verifys, "the code is not even checked")
			assert.Empty(t, f.amrs)
		})
	}
}

func TestMFALogin_WithoutCSRF_Rejected(t *testing.T) {
	// Arrange
	f := newSSOFixture(t)
	f.mfa.enabled = true
	b := f.newBrowser(t)
	form := hiddenFields(t, b.login(b.authorize("openid", nil)).Body.String())
	form.Set("code", goodTOTP)
	form.Set("csrf_token", "forged")

	// Act
	w := b.post("/oauth/login/mfa", form)

	// Assert
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Zero(t, f.mfa.verifys)
}

func TestMFALogin_SuspendedSinceThePassword_Rejected(t *testing.T) {
	// Arrange
	f := newSSOFixture(t)
	f.mfa.enabled = true
	b := f.newBrowser(t)
	mfaPage := b.login(b.authorize("openid", nil))
	f.user.Status = models.UserStatusSuspended

	// Act
	w := b.submit(mfaPage, "/oauth/login/mfa", map[string]string{"code": goodTOTP})

	// Assert
	assert.True(t, isLoginPage(w))
	assert.NotContains(t, b.cookies, "sg_session")
}

// devicePage starts device verification with the fixture user's password
func (b *browser) approveDevice(userCode string) *httptest.ResponseRecorder {
	page := b.get("/oauth/device?user_code=" + userCode)
	return b.submit(page, "/oauth/device", map[string]string{
		"user_code": userCode, "username": ssoEmail, "password": ssoPassword, "action": "approve",
	})
}

func TestMFADevice_PasswordThenCode_ApprovesWithAMR(t *testing.T) {
	// Arrange
	f := newSSOFixture(t)
	f.mfa.enabled = true
	var gotAMR []string
	f.auth.On("ApproveDeviceCode", mock.Anything, f.tenantID, "WDJB-MJHT", f.user.ID, mock.Anything).
		Run(func(args mock.Arguments) { gotAMR = args.Get(4).([]string) }).Return(nil)
	b := f.newBrowser(t)

	// Act
	mfaPage := b.approveDevice("WDJB-MJHT")
	done := b.submit(mfaPage, "/oauth/device/mfa", map[string]string{"code": goodTOTP})

	// Assert
	assert.True(t, isMFAPage(mfaPage), mfaPage.Body.String())
	assert.Contains(t, done.Body.String(), "Device approved")
	assert.Equal(t, []string{"pwd", "otp", "mfa"}, gotAMR)
}

func TestMFADevice_PasswordAlone_DoesNotApprove(t *testing.T) {
	// Arrange
	f := newSSOFixture(t)
	f.mfa.enabled = true
	b := f.newBrowser(t)

	// Act
	b.approveDevice("WDJB-MJHT")

	// Assert
	f.auth.AssertNotCalled(t, "ApproveDeviceCode", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

func TestMFA_PendingTokenFromOtherFlow_Rejected(t *testing.T) {
	// Arrange: pass the password on the device page, then present that
	// device-flow token to the login MFA endpoint
	f := newSSOFixture(t)
	f.mfa.enabled = true
	b := f.newBrowser(t)
	deviceToken := hiddenFields(t, b.approveDevice("WDJB-MJHT").Body.String()).Get("mfa_token")
	mfaPage := b.login(b.authorize("openid", nil))
	form := hiddenFields(t, mfaPage.Body.String())
	form.Set("mfa_token", deviceToken)
	form.Set("code", goodTOTP)

	// Act
	w := b.post("/oauth/login/mfa", form)

	// Assert
	assert.True(t, isLoginPage(w))
	assert.NotContains(t, b.cookies, "sg_session")
}

func TestMFAManagement_OnlyTheUserCanEnrollOrDisable(t *testing.T) {
	// Arrange
	gin.SetMode(gin.TestMode)
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)
	tenantID, owner, admin := uuid.New(), uuid.New(), uuid.New()
	svc := &fakeMFAService{enabled: true}
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set(middleware.TenantIDKey, tenantID)
		c.Set(middleware.UserIDKey, uuid.MustParse(c.GetHeader("X-Test-User")))
		c.Next()
	})
	handlers.NewMFAHandler(svc, logger).RegisterRoutes(router.Group("/v1/users"), middleware.NewAuthorizer(denyAll{}, []uuid.UUID{admin}, logger))
	call := func(method, path, caller, body string) int {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("X-Test-User", caller)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w.Code
	}
	base := "/v1/users/" + owner.String() + "/mfa"

	// Act / Assert: even a super admin cannot enroll, read a secret or
	// disable with a code for someone else
	assert.Equal(t, http.StatusForbidden, call(http.MethodPost, base+"/totp", admin.String(), ""))
	assert.Equal(t, http.StatusForbidden, call(http.MethodPost, base+"/disable", admin.String(), `{"code":"123456"}`))
	assert.Equal(t, http.StatusForbidden, call(http.MethodPost, base+"/recovery-codes", admin.String(), `{"code":"123456"}`))
	assert.Equal(t, http.StatusCreated, call(http.MethodPost, base+"/totp", owner.String(), ""))
	assert.Equal(t, http.StatusBadRequest, call(http.MethodPost, base+"/disable", owner.String(), `{"code":"000000"}`))
	assert.Equal(t, http.StatusNoContent, call(http.MethodPost, base+"/disable", owner.String(), `{"code":"123456"}`))

	// An administrator may reset a lost authenticator
	svc.enabled = true
	assert.Equal(t, http.StatusNoContent, call(http.MethodDelete, base, admin.String(), ""))
	assert.Equal(t, http.StatusForbidden, call(http.MethodDelete, base, owner.String(), ""), "reset needs user:update")
}

func TestMFAManagement_ErrorMapping(t *testing.T) {
	// Arrange
	errs := map[error]int{
		models.ErrMFALocked:         http.StatusTooManyRequests,
		models.ErrMFAAlreadyEnabled: http.StatusConflict,
		models.ErrInvalidMFACode:    http.StatusBadRequest,
		errors.New("db down"):       http.StatusInternalServerError,
	}
	for err, want := range errs {
		t.Run(err.Error(), func(t *testing.T) {
			gin.SetMode(gin.TestMode)
			logger := logrus.New()
			logger.SetLevel(logrus.FatalLevel)
			user := uuid.New()
			router := gin.New()
			router.Use(func(c *gin.Context) {
				c.Set(middleware.TenantIDKey, uuid.New())
				c.Set(middleware.UserIDKey, user)
				c.Next()
			})
			handlers.NewMFAHandler(&erroringMFAService{err: err}, logger).
				RegisterRoutes(router.Group("/v1/users"), middleware.NewAuthorizer(nil, nil, logger))

			// Act
			w := httptest.NewRecorder()
			router.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/v1/users/"+user.String()+"/mfa/totp", nil))

			// Assert
			assert.Equal(t, want, w.Code)
		})
	}
}

// erroringMFAService fails enrollment with a fixed error
type erroringMFAService struct {
	fakeMFAService
	err error
}

func (m *erroringMFAService) BeginTOTPEnrollment(ctx context.Context, tenantID, userID uuid.UUID) (*models.TOTPEnrollment, error) {
	return nil, m.err
}

// denyAll grants no permissions
type denyAll struct{}

func (denyAll) HasPermission(ctx context.Context, tenantID, userID uuid.UUID, resource, action string) (bool, error) {
	return false, nil
}
