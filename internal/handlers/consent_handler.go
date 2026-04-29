package handlers

import (
	"net/http"

	"shieldgate/internal/middleware"
	"shieldgate/internal/models"
	"shieldgate/internal/services"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// ConsentHandler exposes endpoints for managing a user's OAuth2 consent records.
type ConsentHandler struct {
	consent services.ConsentService
	logger  *logrus.Logger
}

// NewConsentHandler creates a new ConsentHandler.
func NewConsentHandler(consent services.ConsentService, logger *logrus.Logger) *ConsentHandler {
	return &ConsentHandler{consent: consent, logger: logger}
}

// RegisterRoutes attaches consent routes to the given authenticated group.
func (h *ConsentHandler) RegisterRoutes(rg *gin.RouterGroup) {
	rg.GET("", h.ListConsents)
	rg.DELETE("/:client_id", h.RevokeConsent)
}

// ListConsents returns all active consent records for the authenticated user.
// GET /v1/consents
func (h *ConsentHandler) ListConsents(c *gin.Context) {
	tenantID, err := middleware.GetTenantID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant context required", "code": models.ErrorCodeUnauthorized})
		return
	}
	userID, err := middleware.GetUserID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required", "code": models.ErrorCodeUnauthorized})
		return
	}
	records, err := h.consent.ListConsents(c.Request.Context(), tenantID, userID)
	if err != nil {
		h.logger.WithError(err).Error("list consents failed")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error", "code": models.ErrorCodeInternalError})
		return
	}
	c.JSON(http.StatusOK, gin.H{"consents": records, "total": len(records)})
}

// RevokeConsent removes a user's consent for a specific OAuth2 client.
// DELETE /v1/consents/:client_id
func (h *ConsentHandler) RevokeConsent(c *gin.Context) {
	tenantID, err := middleware.GetTenantID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant context required", "code": models.ErrorCodeUnauthorized})
		return
	}
	userID, err := middleware.GetUserID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required", "code": models.ErrorCodeUnauthorized})
		return
	}
	clientID, err := uuid.Parse(c.Param("client_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid client_id", "code": models.ErrorCodeInvalidRequest})
		return
	}
	if err := h.consent.RevokeConsent(c.Request.Context(), tenantID, userID, clientID); err != nil {
		h.logger.WithError(err).Error("revoke consent failed")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error", "code": models.ErrorCodeInternalError})
		return
	}
	c.Status(http.StatusNoContent)
}
