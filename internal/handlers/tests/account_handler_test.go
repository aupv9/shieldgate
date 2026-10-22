package tests

// account_handler_test.go covers roadmap 4.3: the email verification and
// password reset pages opened from account emails.

import (
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
	"shieldgate/internal/services"
	"shieldgate/tests/utils"
)

type accountFixture struct {
	tenantID uuid.UUID
	users    *MockUserService
	router   *gin.Engine
	cookies  map[string]*http.Cookie
}

// newAccountFixture serves the account pages; withTenant controls whether
// the request resolves to a tenant
func newAccountFixture(t *testing.T, withTenant bool) *accountFixture {
	t.Helper()
	gin.SetMode(gin.TestMode)
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)

	f := &accountFixture{tenantID: uuid.New(), users: new(MockUserService), cookies: map[string]*http.Cookie{}}
	f.router = gin.New()
	f.router.SetFuncMap(template.FuncMap{
		"contains": func(s, substr string) bool { return strings.Contains(s, substr) },
	})
	f.router.LoadHTMLGlob("../../../templates/*")
	if withTenant {
		f.router.Use(func(c *gin.Context) {
			c.Set(middleware.TenantIDKey, f.tenantID)
			c.Next()
		})
	}
	handlers.NewAccountHandler(utils.CreateTestConfig(), f.users, logger).RegisterRoutes(f.router.Group(""))
	return f
}

func (f *accountFixture) do(req *http.Request) *httptest.ResponseRecorder {
	for _, c := range f.cookies {
		req.AddCookie(c)
	}
	w := httptest.NewRecorder()
	f.router.ServeHTTP(w, req)
	for _, c := range w.Result().Cookies() {
		f.cookies[c.Name] = c
	}
	return w
}

func (f *accountFixture) get(path string) *httptest.ResponseRecorder {
	return f.do(httptest.NewRequest(http.MethodGet, path, nil))
}

func (f *accountFixture) post(path string, form url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return f.do(req)
}

// submit posts a page's form with its hidden fields plus fields
func (f *accountFixture) submit(t *testing.T, page *httptest.ResponseRecorder, action string, fields map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	form := hiddenFields(t, page.Body.String())
	for k, v := range fields {
		form.Set(k, v)
	}
	return f.post(action, form)
}

func TestAccountVerifyEmail_Outcomes(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantStatus int
		wantText   string
	}{
		{"verified", nil, http.StatusOK, "Email verified"},
		{"expired", models.ErrVerificationExpired, http.StatusBadRequest, "Link expired"},
		{"invalid", models.ErrInvalidVerificationCode, http.StatusBadRequest, "Invalid link"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			f := newAccountFixture(t, true)
			var user *models.User
			if tt.err == nil {
				user = &models.User{}
			}
			f.users.On("VerifyEmail", mock.Anything, f.tenantID, "the-code").Return(user, tt.err)

			// Act
			w := f.get("/account/verify-email?code=the-code")

			// Assert
			assert.Equal(t, tt.wantStatus, w.Code)
			assert.Contains(t, w.Body.String(), tt.wantText)
			assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
			assert.Equal(t, "no-referrer", w.Header().Get("Referrer-Policy"), "the code must not leak via Referer")
		})
	}
}

func TestAccountForgotPassword_SameResponseAndCallsService(t *testing.T) {
	// Arrange
	f := newAccountFixture(t, true)
	f.users.On("RequestPasswordReset", mock.Anything, f.tenantID, "erin@example.com").Return(nil)
	form := f.get("/account/forgot-password")
	require.Equal(t, http.StatusOK, form.Code)

	// Act
	w := f.submit(t, form, "/account/forgot-password", map[string]string{"email": " erin@example.com "})

	// Assert
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "If an account exists")
	f.users.AssertExpectations(t)
}

func TestAccountForgotPassword_WithoutCSRF_Rejected(t *testing.T) {
	// Arrange
	f := newAccountFixture(t, true)

	// Act
	w := f.post("/account/forgot-password", url.Values{"email": {"erin@example.com"}})

	// Assert
	assert.Equal(t, http.StatusBadRequest, w.Code)
	f.users.AssertNotCalled(t, "RequestPasswordReset", mock.Anything, mock.Anything, mock.Anything)
}

func TestAccountResetPassword_FormDoesNotConsumeToken(t *testing.T) {
	// Arrange
	f := newAccountFixture(t, true)

	// Act
	w := f.get("/account/reset-password?token=tok-1")

	// Assert
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "tok-1", hiddenFields(t, w.Body.String()).Get("token"))
	f.users.AssertNotCalled(t, "ResetPassword", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

func TestAccountResetPassword_Submit(t *testing.T) {
	tests := []struct {
		name       string
		confirm    string
		err        error
		wantStatus int
		wantText   string
		wantCall   bool
	}{
		{"success", "new-password-1", nil, http.StatusOK, "Password changed", true},
		{"mismatch", "something-else", nil, http.StatusBadRequest, "do not match", false},
		{"too short", "new-password-1", services.ErrPasswordTooShort, http.StatusBadRequest, "at least", true},
		{"used token", "new-password-1", models.ErrInvalidVerificationCode, http.StatusBadRequest, "Invalid link", true},
		{"expired token", "new-password-1", models.ErrVerificationExpired, http.StatusBadRequest, "Link expired", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			f := newAccountFixture(t, true)
			var user *models.User
			if tt.err == nil {
				user = &models.User{}
			}
			f.users.On("ResetPassword", mock.Anything, f.tenantID, "tok-1", "new-password-1").Return(user, tt.err)
			form := f.get("/account/reset-password?token=tok-1")

			// Act
			w := f.submit(t, form, "/account/reset-password",
				map[string]string{"password": "new-password-1", "password_confirm": tt.confirm})

			// Assert
			assert.Equal(t, tt.wantStatus, w.Code)
			assert.Contains(t, w.Body.String(), tt.wantText)
			if tt.wantCall {
				f.users.AssertExpectations(t)
			} else {
				f.users.AssertNotCalled(t, "ResetPassword", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
			}
		})
	}
}

func TestAccountResetPassword_WithoutCSRF_Rejected(t *testing.T) {
	// Arrange
	f := newAccountFixture(t, true)

	// Act
	w := f.post("/account/reset-password", url.Values{
		"token": {"tok-1"}, "password": {"new-password-1"}, "password_confirm": {"new-password-1"},
	})

	// Assert
	assert.Equal(t, http.StatusBadRequest, w.Code)
	f.users.AssertNotCalled(t, "ResetPassword", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

func TestAccountPages_NoTenant_ShowsError(t *testing.T) {
	// Arrange
	f := newAccountFixture(t, false)

	// Act
	w := f.get("/account/verify-email?code=x")

	// Assert
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "Unknown organization")
}
