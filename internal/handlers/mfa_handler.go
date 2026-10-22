package handlers

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"shieldgate/internal/middleware"
	"shieldgate/internal/models"
	"shieldgate/internal/services"
)

// MFAHandler manages a user's second factors through the management API
type MFAHandler struct {
	mfaService services.MFAService
	logger     *logrus.Logger
}

// NewMFAHandler creates a new MFAHandler instance
func NewMFAHandler(mfaService services.MFAService, logger *logrus.Logger) *MFAHandler {
	return &MFAHandler{mfaService: mfaService, logger: logger}
}

// RegisterRoutes registers MFA routes under /v1/users. Enrolling, viewing
// the secret, regenerating recovery codes and disabling are for the user
// themselves only: an administrator who could enroll a secret for someone
// else could sign in as them. Administrators may reset MFA for a user who
// lost their device.
func (h *MFAHandler) RegisterRoutes(router *gin.RouterGroup, authz *middleware.Authorizer) {
	router.GET("/:user_id/mfa", authz.RequireOrSelf("user", "read", "user_id"), h.GetStatus)
	router.POST("/:user_id/mfa/totp", requireSelf, h.BeginTOTP)
	router.POST("/:user_id/mfa/totp/confirm", requireSelf, h.ConfirmTOTP)
	router.POST("/:user_id/mfa/recovery-codes", requireSelf, h.RegenerateRecoveryCodes)
	router.POST("/:user_id/mfa/disable", requireSelf, h.Disable)
	router.DELETE("/:user_id/mfa", authz.Require("user", "update"), h.Reset)
}

// requireSelf allows only the user named by :user_id
func requireSelf(c *gin.Context) {
	caller, err := middleware.GetUserID(c)
	if err != nil || caller == uuid.Nil || caller.String() != c.Param("user_id") {
		middleware.RespondWithError(c, http.StatusForbidden, models.ErrorCodeForbidden,
			"Only the user can manage their own authenticator", nil)
		c.Abort()
		return
	}
	c.Next()
}

// target returns the tenant and the :user_id of the request
func (h *MFAHandler) target(c *gin.Context) (uuid.UUID, uuid.UUID, bool) {
	tenantID, err := middleware.GetTenantID(c)
	if err != nil {
		middleware.RespondWithError(c, http.StatusUnauthorized, models.ErrorCodeUnauthorized, "Invalid tenant context", nil)
		return uuid.Nil, uuid.Nil, false
	}
	userID, err := uuid.Parse(c.Param("user_id"))
	if err != nil {
		middleware.RespondWithError(c, http.StatusBadRequest, models.ErrorCodeInvalidRequest, "Invalid user ID format", nil)
		return uuid.Nil, uuid.Nil, false
	}
	return tenantID, userID, true
}

// GetStatus handles GET /v1/users/:user_id/mfa
func (h *MFAHandler) GetStatus(c *gin.Context) {
	tenantID, userID, ok := h.target(c)
	if !ok {
		return
	}
	status, err := h.mfaService.Status(c.Request.Context(), tenantID, userID)
	if err != nil {
		h.fail(c, err, "failed to get MFA status")
		return
	}
	middleware.RespondWithSuccess(c, http.StatusOK, status)
}

// BeginTOTP handles POST /v1/users/:user_id/mfa/totp. It returns the secret
// and otpauth URI to add to an authenticator app; MFA is enabled only after
// ConfirmTOTP.
func (h *MFAHandler) BeginTOTP(c *gin.Context) {
	tenantID, userID, ok := h.target(c)
	if !ok {
		return
	}
	enrollment, err := h.mfaService.BeginTOTPEnrollment(c.Request.Context(), tenantID, userID)
	if err != nil {
		h.fail(c, err, "failed to begin TOTP enrollment")
		return
	}
	middleware.RespondWithSuccess(c, http.StatusCreated, enrollment)
}

// ConfirmTOTP handles POST /v1/users/:user_id/mfa/totp/confirm. A valid code
// from the new authenticator enables MFA; the response carries the recovery
// codes, shown only this once.
func (h *MFAHandler) ConfirmTOTP(c *gin.Context) {
	tenantID, userID, ok := h.target(c)
	if !ok {
		return
	}
	code, ok := bindCode(c)
	if !ok {
		return
	}
	codes, err := h.mfaService.ConfirmTOTPEnrollment(c.Request.Context(), tenantID, userID, code)
	if err != nil {
		h.fail(c, err, "failed to confirm TOTP enrollment")
		return
	}
	middleware.RespondWithSuccess(c, http.StatusOK, models.MFARecoveryCodes{RecoveryCodes: codes})
}

// RegenerateRecoveryCodes handles POST /v1/users/:user_id/mfa/recovery-codes.
// It requires a current code and invalidates all previous recovery codes.
func (h *MFAHandler) RegenerateRecoveryCodes(c *gin.Context) {
	tenantID, userID, ok := h.target(c)
	if !ok {
		return
	}
	if !h.verify(c, tenantID, userID) {
		return
	}
	codes, err := h.mfaService.RegenerateRecoveryCodes(c.Request.Context(), tenantID, userID)
	if err != nil {
		h.fail(c, err, "failed to regenerate recovery codes")
		return
	}
	middleware.RespondWithSuccess(c, http.StatusOK, models.MFARecoveryCodes{RecoveryCodes: codes})
}

// Disable handles POST /v1/users/:user_id/mfa/disable. It requires a current
// code, so a stolen access token alone cannot turn MFA off.
func (h *MFAHandler) Disable(c *gin.Context) {
	tenantID, userID, ok := h.target(c)
	if !ok {
		return
	}
	if !h.verify(c, tenantID, userID) {
		return
	}
	if err := h.mfaService.Disable(c.Request.Context(), tenantID, userID); err != nil {
		h.fail(c, err, "failed to disable MFA")
		return
	}
	c.Status(http.StatusNoContent)
}

// Reset handles DELETE /v1/users/:user_id/mfa: an administrator removes a
// user's second factor, e.g. after a lost device
func (h *MFAHandler) Reset(c *gin.Context) {
	tenantID, userID, ok := h.target(c)
	if !ok {
		return
	}
	if err := h.mfaService.Disable(c.Request.Context(), tenantID, userID); err != nil {
		h.fail(c, err, "failed to reset MFA")
		return
	}
	admin, _ := middleware.GetUserID(c)
	h.logger.WithFields(logrus.Fields{
		"tenant_id": tenantID,
		"user_id":   userID,
		"admin_id":  admin,
	}).Warn("MFA reset by administrator")
	c.Status(http.StatusNoContent)
}

// verify checks the code in the request body, responding on failure
func (h *MFAHandler) verify(c *gin.Context, tenantID, userID uuid.UUID) bool {
	code, ok := bindCode(c)
	if !ok {
		return false
	}
	if _, err := h.mfaService.Verify(c.Request.Context(), tenantID, userID, code); err != nil {
		h.fail(c, err, "MFA verification failed")
		return false
	}
	return true
}

func bindCode(c *gin.Context) (string, bool) {
	var req models.MFACodeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		middleware.RespondWithError(c, http.StatusBadRequest, models.ErrorCodeValidationFailed,
			"Request body must contain code", nil)
		return "", false
	}
	return req.Code, true
}

// fail maps service errors to responses
func (h *MFAHandler) fail(c *gin.Context, err error, msg string) {
	switch {
	case errors.Is(err, models.ErrUserNotFound):
		middleware.RespondWithError(c, http.StatusNotFound, models.ErrorCodeResourceNotFound, "User not found", nil)
	case errors.Is(err, models.ErrMFANotEnabled):
		middleware.RespondWithError(c, http.StatusNotFound, models.ErrorCodeResourceNotFound, "MFA is not enabled", nil)
	case errors.Is(err, models.ErrMFAAlreadyEnabled):
		middleware.RespondWithError(c, http.StatusConflict, models.ErrorCodeResourceConflict, "MFA is already enabled", nil)
	case errors.Is(err, models.ErrMFANotEnrolling):
		middleware.RespondWithError(c, http.StatusConflict, models.ErrorCodeResourceConflict,
			"No pending enrollment — start again", nil)
	case errors.Is(err, models.ErrInvalidMFACode):
		middleware.RespondWithError(c, http.StatusBadRequest, models.ErrorCodeInvalidVerificationCode, "Invalid code", nil)
	case errors.Is(err, models.ErrMFALocked):
		middleware.RespondWithError(c, http.StatusTooManyRequests, models.ErrorCodeRateLimitExceeded,
			"Too many incorrect codes — try again later", nil)
	default:
		h.logger.WithError(err).WithField("request_id", middleware.GetRequestID(c)).Error(msg)
		middleware.RespondWithError(c, http.StatusInternalServerError, models.ErrorCodeInternalError, "Internal server error", nil)
	}
}
