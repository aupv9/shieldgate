package handlers

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"shieldgate/internal/middleware"
	"shieldgate/internal/models"
	"shieldgate/internal/services"
)

// UserHandler handles user management endpoints
type UserHandler struct {
	userService services.UserService
	logger      *logrus.Logger
}

// NewUserHandler creates a new UserHandler instance
func NewUserHandler(userService services.UserService, logger *logrus.Logger) *UserHandler {
	return &UserHandler{
		userService: userService,
		logger:      logger,
	}
}

// RegisterRoutes registers user management routes
func (h *UserHandler) RegisterRoutes(router *gin.RouterGroup) {
	router.POST("", h.CreateUser)
	router.GET("/:user_id", h.GetUser)
	router.PUT("/:user_id", h.UpdateUser)
	router.DELETE("/:user_id", h.DeleteUser)
	router.GET("", h.ListUsers)
	router.POST("/:user_id/change-password", h.ChangePassword)

	// MFA (TOTP) management
	router.POST("/:user_id/mfa/enroll", h.EnrollMFA)
	router.POST("/:user_id/mfa/activate", h.ActivateMFA)
	router.POST("/:user_id/mfa/disable", h.DisableMFA)
}

// mfaCodeRequest carries a TOTP code for activation/disable
type mfaCodeRequest struct {
	Code string `json:"code" binding:"required"`
}

// EnrollMFA handles POST /v1/users/:user_id/mfa/enroll
func (h *UserHandler) EnrollMFA(c *gin.Context) {
	tenantID, userID, ok := h.tenantAndUser(c)
	if !ok {
		return
	}

	secret, otpauthURI, err := h.userService.EnrollMFA(c.Request.Context(), tenantID, userID)
	if err != nil {
		if err == models.ErrMFAAlreadyActive {
			middleware.RespondWithError(c, http.StatusConflict,
				models.ErrorCodeBusinessRuleViolation, "MFA is already enabled for this user", nil)
			return
		}
		h.logger.WithError(err).Error("MFA enrollment failed")
		middleware.RespondWithError(c, http.StatusInternalServerError,
			models.ErrorCodeInternalError, "Failed to enroll MFA", nil)
		return
	}

	// The secret is returned exactly once, for the authenticator app
	c.JSON(http.StatusOK, gin.H{"secret": secret, "otpauth_uri": otpauthURI})
}

// ActivateMFA handles POST /v1/users/:user_id/mfa/activate
func (h *UserHandler) ActivateMFA(c *gin.Context) {
	tenantID, userID, ok := h.tenantAndUser(c)
	if !ok {
		return
	}

	var req mfaCodeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		middleware.RespondWithError(c, http.StatusBadRequest,
			models.ErrorCodeValidationFailed, "Invalid request body", nil)
		return
	}

	if err := h.userService.ActivateMFA(c.Request.Context(), tenantID, userID, req.Code); err != nil {
		status, code := http.StatusBadRequest, models.ErrorCodeValidationFailed
		switch err {
		case models.ErrMFAInvalidCode:
			status, code = http.StatusUnauthorized, models.ErrorCodeUnauthorized
		case models.ErrMFAAlreadyActive:
			status, code = http.StatusConflict, models.ErrorCodeBusinessRuleViolation
		}
		middleware.RespondWithError(c, status, code, err.Error(), nil)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "MFA enabled"})
}

// DisableMFA handles POST /v1/users/:user_id/mfa/disable
func (h *UserHandler) DisableMFA(c *gin.Context) {
	tenantID, userID, ok := h.tenantAndUser(c)
	if !ok {
		return
	}

	var req mfaCodeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		middleware.RespondWithError(c, http.StatusBadRequest,
			models.ErrorCodeValidationFailed, "Invalid request body", nil)
		return
	}

	if err := h.userService.DisableMFA(c.Request.Context(), tenantID, userID, req.Code); err != nil {
		status, code := http.StatusBadRequest, models.ErrorCodeValidationFailed
		if err == models.ErrMFAInvalidCode {
			status, code = http.StatusUnauthorized, models.ErrorCodeUnauthorized
		}
		middleware.RespondWithError(c, status, code, err.Error(), nil)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "MFA disabled"})
}

// tenantAndUser extracts the tenant context and the :user_id path parameter
func (h *UserHandler) tenantAndUser(c *gin.Context) (uuid.UUID, uuid.UUID, bool) {
	tenantID, err := middleware.GetTenantID(c)
	if err != nil {
		middleware.RespondWithError(c, http.StatusUnauthorized,
			models.ErrorCodeUnauthorized, "Invalid tenant context", nil)
		return uuid.Nil, uuid.Nil, false
	}
	userID, err := uuid.Parse(c.Param("user_id"))
	if err != nil {
		middleware.RespondWithError(c, http.StatusBadRequest,
			models.ErrorCodeValidationFailed, "Invalid user ID", nil)
		return uuid.Nil, uuid.Nil, false
	}
	return tenantID, userID, true
}

// CreateUser handles POST /v1/users
func (h *UserHandler) CreateUser(c *gin.Context) {
	tenantID, err := middleware.GetTenantID(c)
	if err != nil {
		middleware.RespondWithError(c, http.StatusUnauthorized,
			models.ErrorCodeUnauthorized, "Invalid tenant context", nil)
		return
	}

	var req models.CreateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		middleware.RespondWithError(c, http.StatusBadRequest,
			models.ErrorCodeValidationFailed, "Invalid request body", map[string]interface{}{"validation_errors": err.Error()})
		return
	}

	user, err := h.userService.Create(c.Request.Context(), tenantID, &req)
	if err != nil {
		h.logger.WithError(err).WithFields(logrus.Fields{
			"tenant_id": tenantID,
			"username":  req.Username,
			"email":     req.Email,
		}).Error("failed to create user")

		middleware.RespondWithError(c, http.StatusInternalServerError,
			models.ErrorCodeInternalError, "Failed to create user", nil)
		return
	}

	// Don't expose password hash
	user.PasswordHash = ""
	middleware.RespondWithSuccess(c, http.StatusCreated, user)
}

// GetUser handles GET /v1/users/:user_id
func (h *UserHandler) GetUser(c *gin.Context) {
	tenantID, err := middleware.GetTenantID(c)
	if err != nil {
		middleware.RespondWithError(c, http.StatusUnauthorized,
			models.ErrorCodeUnauthorized, "Invalid tenant context", nil)
		return
	}

	userIDStr := c.Param("user_id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		middleware.RespondWithError(c, http.StatusBadRequest,
			models.ErrorCodeInvalidRequest, "Invalid user ID format", nil)
		return
	}

	user, err := h.userService.GetByID(c.Request.Context(), tenantID, userID)
	if err != nil {
		if err == models.ErrUserNotFound {
			middleware.RespondWithError(c, http.StatusNotFound,
				models.ErrorCodeResourceNotFound, "User not found", nil)
			return
		}

		h.logger.WithError(err).WithFields(logrus.Fields{
			"tenant_id": tenantID,
			"user_id":   userID,
		}).Error("failed to get user")

		middleware.RespondWithError(c, http.StatusInternalServerError,
			models.ErrorCodeInternalError, "Failed to get user", nil)
		return
	}

	// Don't expose password hash
	user.PasswordHash = ""
	middleware.RespondWithSuccess(c, http.StatusOK, user)
}

// UpdateUser handles PUT /v1/users/:user_id
func (h *UserHandler) UpdateUser(c *gin.Context) {
	tenantID, err := middleware.GetTenantID(c)
	if err != nil {
		middleware.RespondWithError(c, http.StatusUnauthorized,
			models.ErrorCodeUnauthorized, "Invalid tenant context", nil)
		return
	}

	userIDStr := c.Param("user_id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		middleware.RespondWithError(c, http.StatusBadRequest,
			models.ErrorCodeInvalidRequest, "Invalid user ID format", nil)
		return
	}

	var req models.UpdateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		middleware.RespondWithError(c, http.StatusBadRequest,
			models.ErrorCodeValidationFailed, "Invalid request body", map[string]interface{}{"validation_errors": err.Error()})
		return
	}

	user, err := h.userService.Update(c.Request.Context(), tenantID, userID, &req)
	if err != nil {
		if err == models.ErrUserNotFound {
			middleware.RespondWithError(c, http.StatusNotFound,
				models.ErrorCodeResourceNotFound, "User not found", nil)
			return
		}

		h.logger.WithError(err).WithFields(logrus.Fields{
			"tenant_id": tenantID,
			"user_id":   userID,
		}).Error("failed to update user")

		middleware.RespondWithError(c, http.StatusInternalServerError,
			models.ErrorCodeInternalError, "Failed to update user", nil)
		return
	}

	// Don't expose password hash
	user.PasswordHash = ""
	middleware.RespondWithSuccess(c, http.StatusOK, user)
}

// DeleteUser handles DELETE /v1/users/:user_id
func (h *UserHandler) DeleteUser(c *gin.Context) {
	tenantID, err := middleware.GetTenantID(c)
	if err != nil {
		middleware.RespondWithError(c, http.StatusUnauthorized,
			models.ErrorCodeUnauthorized, "Invalid tenant context", nil)
		return
	}

	userIDStr := c.Param("user_id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		middleware.RespondWithError(c, http.StatusBadRequest,
			models.ErrorCodeInvalidRequest, "Invalid user ID format", nil)
		return
	}

	err = h.userService.Delete(c.Request.Context(), tenantID, userID)
	if err != nil {
		if err == models.ErrUserNotFound {
			middleware.RespondWithError(c, http.StatusNotFound,
				models.ErrorCodeResourceNotFound, "User not found", nil)
			return
		}

		h.logger.WithError(err).WithFields(logrus.Fields{
			"tenant_id": tenantID,
			"user_id":   userID,
		}).Error("failed to delete user")

		middleware.RespondWithError(c, http.StatusInternalServerError,
			models.ErrorCodeInternalError, "Failed to delete user", nil)
		return
	}

	middleware.RespondWithSuccess(c, http.StatusOK, gin.H{"message": "User deleted successfully"})
}

// ListUsers handles GET /v1/users
func (h *UserHandler) ListUsers(c *gin.Context) {
	tenantID, err := middleware.GetTenantID(c)
	if err != nil {
		middleware.RespondWithError(c, http.StatusUnauthorized,
			models.ErrorCodeUnauthorized, "Invalid tenant context", nil)
		return
	}

	// Parse pagination parameters
	limitStr := c.DefaultQuery("limit", "20")
	offsetStr := c.DefaultQuery("offset", "0")

	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit < 1 || limit > 100 {
		limit = 20
	}

	offset, err := strconv.Atoi(offsetStr)
	if err != nil || offset < 0 {
		offset = 0
	}

	response, err := h.userService.List(c.Request.Context(), tenantID, limit, offset)
	if err != nil {
		h.logger.WithError(err).WithField("tenant_id", tenantID).Error("failed to list users")
		middleware.RespondWithError(c, http.StatusInternalServerError,
			models.ErrorCodeInternalError, "Failed to list users", nil)
		return
	}

	middleware.RespondWithSuccess(c, http.StatusOK, response)
}

// ChangePassword handles POST /v1/users/:user_id/change-password
func (h *UserHandler) ChangePassword(c *gin.Context) {
	tenantID, err := middleware.GetTenantID(c)
	if err != nil {
		middleware.RespondWithError(c, http.StatusUnauthorized,
			models.ErrorCodeUnauthorized, "Invalid tenant context", nil)
		return
	}

	userIDStr := c.Param("user_id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		middleware.RespondWithError(c, http.StatusBadRequest,
			models.ErrorCodeInvalidRequest, "Invalid user ID format", nil)
		return
	}

	var req models.ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		middleware.RespondWithError(c, http.StatusBadRequest,
			models.ErrorCodeValidationFailed, "Invalid request body", map[string]interface{}{"validation_errors": err.Error()})
		return
	}

	err = h.userService.ChangePassword(c.Request.Context(), tenantID, userID, req.OldPassword, req.NewPassword)
	if err != nil {
		if err == models.ErrUserNotFound {
			middleware.RespondWithError(c, http.StatusNotFound,
				models.ErrorCodeResourceNotFound, "User not found", nil)
			return
		}
		if err == models.ErrInvalidCredentials {
			middleware.RespondWithError(c, http.StatusBadRequest,
				models.ErrorCodeValidationFailed, "Current password is incorrect", nil)
			return
		}

		h.logger.WithError(err).WithFields(logrus.Fields{
			"tenant_id": tenantID,
			"user_id":   userID,
		}).Error("failed to change password")

		middleware.RespondWithError(c, http.StatusInternalServerError,
			models.ErrorCodeInternalError, "Failed to change password", nil)
		return
	}

	middleware.RespondWithSuccess(c, http.StatusOK, gin.H{"message": "Password changed successfully"})
}
