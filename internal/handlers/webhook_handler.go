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

// WebhookHandler handles webhook endpoint management.
type WebhookHandler struct {
	webhooks services.WebhookService
	logger   *logrus.Logger
}

// NewWebhookHandler creates a new WebhookHandler.
func NewWebhookHandler(webhooks services.WebhookService, logger *logrus.Logger) *WebhookHandler {
	return &WebhookHandler{webhooks: webhooks, logger: logger}
}

// RegisterRoutes attaches webhook routes under the given group.
func (h *WebhookHandler) RegisterRoutes(rg *gin.RouterGroup) {
	rg.POST("", h.Create)
	rg.GET("", h.List)
	rg.GET("/:id", h.Get)
	rg.PUT("/:id", h.Update)
	rg.DELETE("/:id", h.Delete)
	rg.GET("/:id/deliveries", h.ListDeliveries)
}

// Create registers a new webhook endpoint.
// POST /v1/webhooks
func (h *WebhookHandler) Create(c *gin.Context) {
	tenantID, _ := middleware.GetTenantID(c)
	var req models.CreateWebhookRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error(), "code": models.ErrorCodeInvalidRequest})
		return
	}
	w, err := h.webhooks.Create(c.Request.Context(), tenantID, &req)
	if err != nil {
		h.logger.WithError(err).Error("create webhook failed")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create webhook", "code": models.ErrorCodeInternalError})
		return
	}
	c.JSON(http.StatusCreated, w)
}

// List returns all webhook endpoints for the tenant.
// GET /v1/webhooks
func (h *WebhookHandler) List(c *gin.Context) {
	tenantID, _ := middleware.GetTenantID(c)
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	resp, err := h.webhooks.List(c.Request.Context(), tenantID, limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list webhooks", "code": models.ErrorCodeInternalError})
		return
	}
	c.JSON(http.StatusOK, resp)
}

// Get returns a single webhook endpoint.
// GET /v1/webhooks/:id
func (h *WebhookHandler) Get(c *gin.Context) {
	tenantID, _ := middleware.GetTenantID(c)
	webhookID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid webhook ID"})
		return
	}
	w, err := h.webhooks.GetByID(c.Request.Context(), tenantID, webhookID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "webhook not found", "code": models.ErrorCodeResourceNotFound})
		return
	}
	c.JSON(http.StatusOK, w)
}

// Update updates a webhook endpoint.
// PUT /v1/webhooks/:id
func (h *WebhookHandler) Update(c *gin.Context) {
	tenantID, _ := middleware.GetTenantID(c)
	webhookID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid webhook ID"})
		return
	}
	var req models.UpdateWebhookRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error(), "code": models.ErrorCodeInvalidRequest})
		return
	}
	w, err := h.webhooks.Update(c.Request.Context(), tenantID, webhookID, &req)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "webhook not found", "code": models.ErrorCodeResourceNotFound})
		return
	}
	c.JSON(http.StatusOK, w)
}

// Delete removes a webhook endpoint.
// DELETE /v1/webhooks/:id
func (h *WebhookHandler) Delete(c *gin.Context) {
	tenantID, _ := middleware.GetTenantID(c)
	webhookID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid webhook ID"})
		return
	}
	if err := h.webhooks.Delete(c.Request.Context(), tenantID, webhookID); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "webhook not found", "code": models.ErrorCodeResourceNotFound})
		return
	}
	c.Status(http.StatusNoContent)
}

// ListDeliveries returns delivery records for a webhook.
// GET /v1/webhooks/:id/deliveries
func (h *WebhookHandler) ListDeliveries(c *gin.Context) {
	tenantID, _ := middleware.GetTenantID(c)
	webhookID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid webhook ID"})
		return
	}
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	resp, err := h.webhooks.ListDeliveries(c.Request.Context(), tenantID, webhookID, limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list deliveries", "code": models.ErrorCodeInternalError})
		return
	}
	c.JSON(http.StatusOK, resp)
}
