package handlers

import (
	"net/http"
	"strconv"

	"shieldgate/internal/middleware"
	"shieldgate/internal/models"
	"shieldgate/internal/services"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// APIKeyHandler handles API key lifecycle endpoints.
type APIKeyHandler struct {
	apikeys services.APIKeyService
	logger  *logrus.Logger
}

// NewAPIKeyHandler creates a new APIKeyHandler.
func NewAPIKeyHandler(apikeys services.APIKeyService, logger *logrus.Logger) *APIKeyHandler {
	return &APIKeyHandler{apikeys: apikeys, logger: logger}
}

// RegisterRoutes attaches API key routes under the given group.
func (h *APIKeyHandler) RegisterRoutes(rg *gin.RouterGroup) {
	rg.POST("", h.Create)
	rg.GET("", h.List)
	rg.GET("/:id", h.Get)
	rg.POST("/:id/revoke", h.Revoke)
	rg.DELETE("/:id", h.Delete)
}

// Create generates a new API key.
// POST /v1/apikeys
func (h *APIKeyHandler) Create(c *gin.Context) {
	tenantID, _ := middleware.GetTenantID(c)
	var userIDPtr *uuid.UUID
	if userID, err := middleware.GetUserID(c); err == nil {
		userIDPtr = &userID
	}
	var req models.CreateAPIKeyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error(), "code": models.ErrorCodeInvalidRequest})
		return
	}
	resp, err := h.apikeys.Create(c.Request.Context(), tenantID, userIDPtr, &req)
	if err != nil {
		h.logger.WithError(err).Error("create API key failed")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create API key", "code": models.ErrorCodeInternalError})
		return
	}
	c.JSON(http.StatusCreated, resp)
}

// List returns API keys for the tenant, optionally filtered by user_id.
// GET /v1/apikeys
func (h *APIKeyHandler) List(c *gin.Context) {
	tenantID, _ := middleware.GetTenantID(c)
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))

	var userIDPtr *uuid.UUID
	if raw := c.Query("user_id"); raw != "" {
		id, err := uuid.Parse(raw)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user_id", "code": models.ErrorCodeInvalidRequest})
			return
		}
		userIDPtr = &id
	}

	resp, err := h.apikeys.List(c.Request.Context(), tenantID, userIDPtr, limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list API keys", "code": models.ErrorCodeInternalError})
		return
	}
	c.JSON(http.StatusOK, resp)
}

// Get returns a single API key (without the secret).
// GET /v1/apikeys/:id
func (h *APIKeyHandler) Get(c *gin.Context) {
	tenantID, _ := middleware.GetTenantID(c)
	keyID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid key ID"})
		return
	}
	key, err := h.apikeys.GetByID(c.Request.Context(), tenantID, keyID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "API key not found", "code": models.ErrorCodeResourceNotFound})
		return
	}
	c.JSON(http.StatusOK, key)
}

// Revoke marks an API key as revoked without deleting it.
// POST /v1/apikeys/:id/revoke
func (h *APIKeyHandler) Revoke(c *gin.Context) {
	tenantID, _ := middleware.GetTenantID(c)
	keyID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid key ID"})
		return
	}
	if err := h.apikeys.Revoke(c.Request.Context(), tenantID, keyID); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "API key not found", "code": models.ErrorCodeResourceNotFound})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "API key revoked"})
}

// Delete permanently deletes an API key.
// DELETE /v1/apikeys/:id
func (h *APIKeyHandler) Delete(c *gin.Context) {
	tenantID, _ := middleware.GetTenantID(c)
	keyID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid key ID"})
		return
	}
	if err := h.apikeys.Delete(c.Request.Context(), tenantID, keyID); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "API key not found", "code": models.ErrorCodeResourceNotFound})
		return
	}
	c.Status(http.StatusNoContent)
}
