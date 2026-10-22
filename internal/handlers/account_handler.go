package handlers

import (
	"errors"
	"net/http"
	"strings"

	"shieldgate/config"
	"shieldgate/internal/middleware"
	"shieldgate/internal/models"
	"shieldgate/internal/observability"
	"shieldgate/internal/services"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// accountCSRFPath scopes the CSRF cookie to the account pages
const accountCSRFPath = "/account"

// account.html views
const (
	accountViewMessage = "message"
	accountViewForgot  = "forgot"
	accountViewReset   = "reset"
)

// AccountHandler serves the self-service pages that email links open:
// email verification and password reset
type AccountHandler struct {
	cfg         *config.Config
	userService services.UserService
	events      *observability.Recorder
	logger      *logrus.Logger
}

// WithRecorder makes the handler audit account recovery events
func (h *AccountHandler) WithRecorder(events *observability.Recorder) *AccountHandler {
	h.events = events
	return h
}

// NewAccountHandler creates a new AccountHandler instance
func NewAccountHandler(cfg *config.Config, userService services.UserService, logger *logrus.Logger) *AccountHandler {
	return &AccountHandler{cfg: cfg, userService: userService, logger: logger}
}

// RegisterRoutes registers the account pages. The tenant comes from the
// request's domain (or X-Tenant-ID), like the other browser flows.
func (h *AccountHandler) RegisterRoutes(router *gin.RouterGroup) {
	account := router.Group("/account", noStoreNoReferrer)
	account.GET("/verify-email", h.VerifyEmail)
	account.GET("/forgot-password", h.ForgotPasswordForm)
	account.POST("/forgot-password", h.ForgotPassword)
	account.GET("/reset-password", h.ResetPasswordForm)
	account.POST("/reset-password", h.ResetPassword)
}

// noStoreNoReferrer keeps one-time codes in URLs out of caches and out of
// the Referer header sent to other sites
func noStoreNoReferrer(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	c.Header("Referrer-Policy", "no-referrer")
	c.Next()
}

// VerifyEmail handles GET /account/verify-email?code=...
func (h *AccountHandler) VerifyEmail(c *gin.Context) {
	tenantID, ok := h.tenant(c)
	if !ok {
		return
	}

	user, err := h.userService.VerifyEmail(c.Request.Context(), tenantID, c.Query("code"))
	switch {
	case err == nil:
		h.events.Record(c.Request.Context(), observability.Event{
			Action: models.AuditActionEmailVerified, TenantID: tenantID, UserID: &user.ID, Success: true,
			Name: "email_verification", Result: "success",
		})
		h.message(c, http.StatusOK, "Email verified", "Your email address is confirmed. You can close this window.")
	case errors.Is(err, models.ErrVerificationExpired):
		h.message(c, http.StatusBadRequest, "Link expired", "This verification link has expired. Ask for a new one and try again.")
	case errors.Is(err, models.ErrInvalidVerificationCode):
		h.message(c, http.StatusBadRequest, "Invalid link", "This verification link is invalid or has already been used.")
	default:
		h.logger.WithError(err).WithField("tenant_id", tenantID).Error("email verification failed")
		h.message(c, http.StatusInternalServerError, "Something went wrong", "We could not verify your email. Please try again later.")
	}
}

// ForgotPasswordForm handles GET /account/forgot-password
func (h *AccountHandler) ForgotPasswordForm(c *gin.Context) {
	if _, ok := h.tenant(c); !ok {
		return
	}
	h.render(c, http.StatusOK, gin.H{"view": accountViewForgot})
}

// ForgotPassword handles POST /account/forgot-password. The response is the
// same whether or not the email belongs to an account.
func (h *AccountHandler) ForgotPassword(c *gin.Context) {
	tenantID, ok := h.tenant(c)
	if !ok {
		return
	}
	if !h.validCSRF(c) {
		h.render(c, http.StatusBadRequest, gin.H{"view": accountViewForgot, "error": "Your form expired. Please try again."})
		return
	}

	email := strings.TrimSpace(c.PostForm("email"))
	if email == "" {
		h.render(c, http.StatusBadRequest, gin.H{"view": accountViewForgot, "error": "Enter your email address."})
		return
	}

	if err := h.userService.RequestPasswordReset(c.Request.Context(), tenantID, email); err != nil {
		h.logger.WithError(err).WithField("tenant_id", tenantID).Error("password reset request failed")
		h.message(c, http.StatusInternalServerError, "Something went wrong", "We could not send the email. Please try again later.")
		return
	}
	// The account may not exist; the attempt is still audited (by email)
	h.events.Record(c.Request.Context(), observability.Event{
		Action: models.AuditActionPasswordResetRequested, TenantID: tenantID, Success: true,
		Metadata: map[string]interface{}{"email": email}, Name: "password_reset", Result: "requested",
	})
	h.message(c, http.StatusOK, "Check your email",
		"If an account exists for that address, we sent a link to reset the password. The link expires in one hour.")
}

// ResetPasswordForm handles GET /account/reset-password?token=... It only
// shows the form; the token is consumed on submit, so link scanners that
// prefetch URLs cannot burn it.
func (h *AccountHandler) ResetPasswordForm(c *gin.Context) {
	if _, ok := h.tenant(c); !ok {
		return
	}
	token := c.Query("token")
	if token == "" {
		h.message(c, http.StatusBadRequest, "Invalid link", "This password reset link is invalid.")
		return
	}
	h.render(c, http.StatusOK, gin.H{"view": accountViewReset, "token": token})
}

// ResetPassword handles POST /account/reset-password
func (h *AccountHandler) ResetPassword(c *gin.Context) {
	tenantID, ok := h.tenant(c)
	if !ok {
		return
	}

	token := c.PostForm("token")
	retry := func(status int, msg string) {
		h.render(c, status, gin.H{"view": accountViewReset, "token": token, "error": msg})
	}
	if !h.validCSRF(c) {
		retry(http.StatusBadRequest, "Your form expired. Please try again.")
		return
	}
	password := c.PostForm("password")
	if password != c.PostForm("password_confirm") {
		retry(http.StatusBadRequest, "The passwords do not match.")
		return
	}

	user, err := h.userService.ResetPassword(c.Request.Context(), tenantID, token, password)
	switch {
	case err == nil:
		h.events.Record(c.Request.Context(), observability.Event{
			Action: models.AuditActionPasswordReset, TenantID: tenantID, UserID: &user.ID, Success: true,
			Name: "password_reset", Result: "completed",
		})
		h.message(c, http.StatusOK, "Password changed",
			"Your password has been changed and you have been signed out everywhere. Sign in again with your new password.")
	case errors.Is(err, services.ErrPasswordTooShort):
		retry(http.StatusBadRequest, err.Error())
	case errors.Is(err, models.ErrVerificationExpired):
		h.message(c, http.StatusBadRequest, "Link expired", "This password reset link has expired. Ask for a new one.")
	case errors.Is(err, models.ErrInvalidVerificationCode), errors.Is(err, models.ErrUserSuspended):
		h.message(c, http.StatusBadRequest, "Invalid link", "This password reset link is invalid or has already been used.")
	default:
		h.logger.WithError(err).WithField("tenant_id", tenantID).Error("password reset failed")
		h.message(c, http.StatusInternalServerError, "Something went wrong", "We could not change your password. Please try again later.")
	}
}

// tenant returns the request's tenant, rendering an error page if missing
func (h *AccountHandler) tenant(c *gin.Context) (uuid.UUID, bool) {
	tenantID, err := middleware.GetTenantID(c)
	if err != nil {
		h.message(c, http.StatusBadRequest, "Unknown organization",
			"This page must be opened from your organization's sign-in address.")
		return uuid.Nil, false
	}
	return tenantID, true
}

func (h *AccountHandler) message(c *gin.Context, status int, title, text string) {
	c.HTML(status, "account.html", gin.H{"view": accountViewMessage, "title": title, "message": text})
}

// render shows a form view with a fresh CSRF token
func (h *AccountHandler) render(c *gin.Context, status int, data gin.H) {
	csrfToken, err := newCSRFToken(h.cfg.JWTSecret)
	if err != nil {
		h.logger.WithError(err).Error("failed to generate CSRF token")
		h.message(c, http.StatusInternalServerError, "Something went wrong", "Please try again later.")
		return
	}
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(csrfCookieName, csrfToken, 600, accountCSRFPath, "", strings.HasPrefix(h.cfg.ServerURL, "https://"), true)
	data["csrf_token"] = csrfToken
	c.HTML(status, "account.html", data)
}

func (h *AccountHandler) validCSRF(c *gin.Context) bool {
	cookieToken, _ := c.Cookie(csrfCookieName)
	return validateCSRFToken(h.cfg.JWTSecret, c.PostForm("csrf_token"), cookieToken)
}
