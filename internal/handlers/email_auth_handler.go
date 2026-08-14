package handlers

// email_auth_handler.go exposes the email verification and password reset
// flows implemented by EmailService.

import (
	"net/http"

	"shieldgate/internal/middleware"
	"shieldgate/internal/models"
	"shieldgate/internal/services"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// EmailAuthHandler handles email verification and password reset endpoints
type EmailAuthHandler struct {
	emailService services.EmailService
	logger       *logrus.Logger
}

// NewEmailAuthHandler creates a new email auth handler
func NewEmailAuthHandler(emailService services.EmailService, logger *logrus.Logger) *EmailAuthHandler {
	return &EmailAuthHandler{emailService: emailService, logger: logger}
}

// RegisterPublicRoutes registers the unauthenticated endpoints under /auth
func (h *EmailAuthHandler) RegisterPublicRoutes(router *gin.RouterGroup) {
	router.POST("/verify-email", h.HandleVerifyEmail)
	router.POST("/request-password-reset", h.HandleRequestPasswordReset)
	router.POST("/reset-password", h.HandleResetPassword)
}

// RegisterProtectedRoutes registers management endpoints (behind RequireAuth)
func (h *EmailAuthHandler) RegisterProtectedRoutes(router *gin.RouterGroup) {
	router.POST("/users/:user_id/send-verification", h.HandleSendVerification)
}

func (h *EmailAuthHandler) tenantID(c *gin.Context) (uuid.UUID, bool) {
	tenantID, err := middleware.GetTenantID(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "Tenant context required — provide X-Tenant-ID header or use the tenant domain",
		})
		return uuid.Nil, false
	}
	return tenantID, true
}

// HandleVerifyEmail handles POST /auth/verify-email {"code": "..."}
func (h *EmailAuthHandler) HandleVerifyEmail(c *gin.Context) {
	tenantID, ok := h.tenantID(c)
	if !ok {
		return
	}

	var req models.VerifyEmailRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": err.Error()})
		return
	}

	user, err := h.emailService.VerifyEmail(c.Request.Context(), tenantID, req.Code)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_code",
			"error_description": "Verification code is invalid or expired",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Email verified successfully", "user_id": user.ID})
}

// HandleRequestPasswordReset handles POST /auth/request-password-reset {"email": "..."}.
// Always responds 200 so the endpoint cannot be used to probe for accounts.
func (h *EmailAuthHandler) HandleRequestPasswordReset(c *gin.Context) {
	tenantID, ok := h.tenantID(c)
	if !ok {
		return
	}

	var req models.RequestPasswordResetRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": err.Error()})
		return
	}

	if err := h.emailService.SendPasswordResetEmail(c.Request.Context(), tenantID, req.Email); err != nil {
		// Log but do not reveal whether the account exists
		h.logger.WithError(err).WithField("tenant_id", tenantID).Debug("password reset request failed")
	}

	c.JSON(http.StatusOK, gin.H{"message": "If the account exists, a password reset email has been sent"})
}

// HandleResetPassword handles POST /auth/reset-password {"token": "...", "new_password": "..."}
func (h *EmailAuthHandler) HandleResetPassword(c *gin.Context) {
	tenantID, ok := h.tenantID(c)
	if !ok {
		return
	}

	var req models.ResetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": err.Error()})
		return
	}

	if _, err := h.emailService.ResetPassword(c.Request.Context(), tenantID, req.Token, req.NewPassword); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_token",
			"error_description": "Reset token is invalid or expired",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Password reset successfully"})
}

// HandleSendVerification handles POST /v1/users/:user_id/send-verification
func (h *EmailAuthHandler) HandleSendVerification(c *gin.Context) {
	tenantID, ok := h.tenantID(c)
	if !ok {
		return
	}

	userID, err := uuid.Parse(c.Param("user_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "Invalid user ID"})
		return
	}

	if err := h.emailService.SendVerificationEmail(c.Request.Context(), tenantID, userID); err != nil {
		h.logger.WithError(err).Error("failed to send verification email")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Verification email queued"})
}
