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

// SocialHandler handles social login provider configuration and account-linking endpoints.
type SocialHandler struct {
	social services.SocialLoginService
	logger *logrus.Logger
}

// NewSocialHandler creates a new SocialHandler.
func NewSocialHandler(social services.SocialLoginService, logger *logrus.Logger) *SocialHandler {
	return &SocialHandler{social: social, logger: logger}
}

// RegisterRoutes attaches social routes under the given group.
func (h *SocialHandler) RegisterRoutes(rg *gin.RouterGroup) {
	rg.POST("/providers", h.ConfigureProvider)
	rg.GET("/providers", h.ListProviders)
	rg.GET("/providers/:provider", h.GetProvider)
	rg.PUT("/providers/:provider", h.UpdateProvider)
	rg.DELETE("/providers/:provider", h.DeleteProvider)
	rg.GET("/accounts", h.ListLinkedAccounts)
	rg.DELETE("/accounts/:provider", h.UnlinkAccount)
}

type configureProviderRequest struct {
	Provider     string   `json:"provider" binding:"required"`
	ClientID     string   `json:"client_id" binding:"required"`
	ClientSecret string   `json:"client_secret" binding:"required"`
	Scopes       []string `json:"scopes"`
}

// ConfigureProvider creates social provider config for a tenant.
// POST /v1/social/providers
func (h *SocialHandler) ConfigureProvider(c *gin.Context) {
	tenantID, _ := middleware.GetTenantID(c)
	var req configureProviderRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error(), "code": models.ErrorCodeInvalidRequest})
		return
	}
	p, err := h.social.ConfigureProvider(c.Request.Context(), tenantID, req.Provider, req.ClientID, req.ClientSecret, req.Scopes)
	if err != nil {
		h.logger.WithError(err).Error("configure social provider failed")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to configure provider", "code": models.ErrorCodeInternalError})
		return
	}
	c.JSON(http.StatusCreated, p)
}

// ListProviders returns all configured social providers for the tenant.
// GET /v1/social/providers
func (h *SocialHandler) ListProviders(c *gin.Context) {
	tenantID, _ := middleware.GetTenantID(c)
	providers, err := h.social.ListProviders(c.Request.Context(), tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list providers", "code": models.ErrorCodeInternalError})
		return
	}
	c.JSON(http.StatusOK, gin.H{"providers": providers})
}

// GetProvider returns a single social provider config.
// GET /v1/social/providers/:provider
func (h *SocialHandler) GetProvider(c *gin.Context) {
	tenantID, _ := middleware.GetTenantID(c)
	p, err := h.social.GetProvider(c.Request.Context(), tenantID, c.Param("provider"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "provider not found", "code": models.ErrorCodeResourceNotFound})
		return
	}
	c.JSON(http.StatusOK, p)
}

type updateProviderRequest struct {
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	Scopes       []string `json:"scopes"`
	IsActive     bool     `json:"is_active"`
}

// UpdateProvider updates a social provider config.
// PUT /v1/social/providers/:provider
func (h *SocialHandler) UpdateProvider(c *gin.Context) {
	tenantID, _ := middleware.GetTenantID(c)
	var req updateProviderRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error(), "code": models.ErrorCodeInvalidRequest})
		return
	}
	p, err := h.social.UpdateProvider(c.Request.Context(), tenantID, c.Param("provider"), req.ClientID, req.ClientSecret, req.Scopes, req.IsActive)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "provider not found", "code": models.ErrorCodeResourceNotFound})
		return
	}
	c.JSON(http.StatusOK, p)
}

// DeleteProvider removes a social provider config.
// DELETE /v1/social/providers/:provider
func (h *SocialHandler) DeleteProvider(c *gin.Context) {
	tenantID, _ := middleware.GetTenantID(c)
	if err := h.social.DeleteProvider(c.Request.Context(), tenantID, c.Param("provider")); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "provider not found", "code": models.ErrorCodeResourceNotFound})
		return
	}
	c.Status(http.StatusNoContent)
}

// ListLinkedAccounts returns social accounts linked to a user.
// GET /v1/social/accounts
func (h *SocialHandler) ListLinkedAccounts(c *gin.Context) {
	tenantID, _ := middleware.GetTenantID(c)
	userID, err := socialResolveUserID(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user_id required", "code": models.ErrorCodeInvalidRequest})
		return
	}
	accounts, err := h.social.ListLinkedAccounts(c.Request.Context(), tenantID, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list accounts", "code": models.ErrorCodeInternalError})
		return
	}
	c.JSON(http.StatusOK, gin.H{"accounts": accounts})
}

// UnlinkAccount removes a social account link.
// DELETE /v1/social/accounts/:provider
func (h *SocialHandler) UnlinkAccount(c *gin.Context) {
	tenantID, _ := middleware.GetTenantID(c)
	userID, err := socialResolveUserID(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user_id required", "code": models.ErrorCodeInvalidRequest})
		return
	}
	if err := h.social.UnlinkAccount(c.Request.Context(), tenantID, userID, c.Param("provider")); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "account not found", "code": models.ErrorCodeResourceNotFound})
		return
	}
	c.Status(http.StatusNoContent)
}

// socialResolveUserID returns user_id from query param, falling back to the JWT claims.
func socialResolveUserID(c *gin.Context) (uuid.UUID, error) {
	if raw := c.Query("user_id"); raw != "" {
		return uuid.Parse(raw)
	}
	return middleware.GetUserID(c)
}
