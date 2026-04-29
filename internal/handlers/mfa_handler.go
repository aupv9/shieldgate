package handlers

import (
	"net/http"

	"shieldgate/internal/middleware"
	"shieldgate/internal/models"
	"shieldgate/internal/services"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

// MFAHandler handles TOTP multi-factor authentication endpoints.
type MFAHandler struct {
	mfa    services.MFAService
	logger *logrus.Logger
}

func NewMFAHandler(mfa services.MFAService, logger *logrus.Logger) *MFAHandler {
	return &MFAHandler{mfa: mfa, logger: logger}
}

// RegisterRoutes attaches MFA routes under the given router group.
// The group must already have RequireAuth applied.
func (h *MFAHandler) RegisterRoutes(rg *gin.RouterGroup) {
	rg.POST("/setup", h.Setup)
	rg.POST("/verify", h.Verify)
	rg.POST("/disable", h.Disable)
	rg.GET("/backup-codes", h.ListBackupCodes)
	rg.POST("/backup-codes/regenerate", h.RegenerateBackupCodes)
}

// Setup initiates TOTP MFA setup for the authenticated user.
// POST /v1/mfa/setup
func (h *MFAHandler) Setup(c *gin.Context) {
	tenantID, err := middleware.GetTenantID(c)
	if err != nil {
		respondError(c, http.StatusUnauthorized, models.ErrorCodeUnauthorized, "tenant required")
		return
	}
	userID, err := middleware.GetUserID(c)
	if err != nil {
		respondError(c, http.StatusUnauthorized, models.ErrorCodeUnauthorized, "authentication required")
		return
	}

	issuer := c.GetHeader("X-Issuer")
	if issuer == "" {
		issuer = "ShieldGate"
	}

	resp, err := h.mfa.Setup(c.Request.Context(), tenantID, userID, issuer, userID.String())
	if err != nil {
		switch err {
		case models.ErrMFAAlreadyEnabled:
			respondError(c, http.StatusConflict, "MFA_ALREADY_ENABLED", err.Error())
		default:
			h.logger.WithError(err).Error("MFA setup failed")
			respondError(c, http.StatusInternalServerError, models.ErrorCodeInternalError, "MFA setup failed")
		}
		return
	}
	c.JSON(http.StatusOK, resp)
}

// Verify validates the first TOTP code and enables MFA.
// POST /v1/mfa/verify
func (h *MFAHandler) Verify(c *gin.Context) {
	tenantID, err := middleware.GetTenantID(c)
	if err != nil {
		respondError(c, http.StatusUnauthorized, models.ErrorCodeUnauthorized, "tenant required")
		return
	}
	userID, err := middleware.GetUserID(c)
	if err != nil {
		respondError(c, http.StatusUnauthorized, models.ErrorCodeUnauthorized, "authentication required")
		return
	}

	var req models.MFAVerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, models.ErrorCodeInvalidRequest, err.Error())
		return
	}

	if err := h.mfa.VerifyAndEnable(c.Request.Context(), tenantID, userID, req.Code); err != nil {
		switch err {
		case models.ErrMFAInvalidCode:
			respondError(c, http.StatusUnprocessableEntity, "MFA_INVALID_CODE", "invalid TOTP code")
		case models.ErrMFAAlreadyEnabled:
			respondError(c, http.StatusConflict, "MFA_ALREADY_ENABLED", err.Error())
		case models.ErrMFANotSetup:
			respondError(c, http.StatusBadRequest, "MFA_NOT_SETUP", "call /mfa/setup first")
		default:
			h.logger.WithError(err).Error("MFA verify failed")
			respondError(c, http.StatusInternalServerError, models.ErrorCodeInternalError, "verification failed")
		}
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "MFA enabled successfully"})
}

// Disable disables MFA after verifying a TOTP or backup code.
// POST /v1/mfa/disable
func (h *MFAHandler) Disable(c *gin.Context) {
	tenantID, _ := middleware.GetTenantID(c)
	userID, err := middleware.GetUserID(c)
	if err != nil {
		respondError(c, http.StatusUnauthorized, models.ErrorCodeUnauthorized, "authentication required")
		return
	}

	var req models.MFADisableRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, models.ErrorCodeInvalidRequest, err.Error())
		return
	}

	if err := h.mfa.Disable(c.Request.Context(), tenantID, userID, req.Code); err != nil {
		switch err {
		case models.ErrMFAInvalidCode:
			respondError(c, http.StatusUnprocessableEntity, "MFA_INVALID_CODE", "invalid code")
		case models.ErrMFANotEnabled:
			respondError(c, http.StatusBadRequest, "MFA_NOT_ENABLED", err.Error())
		default:
			h.logger.WithError(err).Error("MFA disable failed")
			respondError(c, http.StatusInternalServerError, models.ErrorCodeInternalError, "disable failed")
		}
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "MFA disabled"})
}

// ListBackupCodes returns the current backup code records (hashes hidden).
// GET /v1/mfa/backup-codes
func (h *MFAHandler) ListBackupCodes(c *gin.Context) {
	tenantID, _ := middleware.GetTenantID(c)
	userID, err := middleware.GetUserID(c)
	if err != nil {
		respondError(c, http.StatusUnauthorized, models.ErrorCodeUnauthorized, "authentication required")
		return
	}

	codes, err := h.mfa.GetBackupCodes(c.Request.Context(), tenantID, userID)
	if err != nil {
		respondError(c, http.StatusInternalServerError, models.ErrorCodeInternalError, "failed to retrieve backup codes")
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"total":    len(codes),
		"used":     countUsed(codes),
		"available": len(codes) - countUsed(codes),
	})
}

// RegenerateBackupCodes replaces all backup codes and returns plain-text values.
// POST /v1/mfa/backup-codes/regenerate
func (h *MFAHandler) RegenerateBackupCodes(c *gin.Context) {
	tenantID, _ := middleware.GetTenantID(c)
	userID, err := middleware.GetUserID(c)
	if err != nil {
		respondError(c, http.StatusUnauthorized, models.ErrorCodeUnauthorized, "authentication required")
		return
	}

	plainCodes, err := h.mfa.RegenerateBackupCodes(c.Request.Context(), tenantID, userID)
	if err != nil {
		h.logger.WithError(err).Error("backup code regeneration failed")
		respondError(c, http.StatusInternalServerError, models.ErrorCodeInternalError, "regeneration failed")
		return
	}
	c.JSON(http.StatusOK, models.MFABackupCodesResponse{
		Codes: plainCodes,
	})
}

func countUsed(codes []*models.MFABackupCode) int {
	n := 0
	for _, c := range codes {
		if c.IsUsed() {
			n++
		}
	}
	return n
}

func respondError(c *gin.Context, status int, code, msg string) {
	c.JSON(status, gin.H{"error": code, "error_description": msg})
}
