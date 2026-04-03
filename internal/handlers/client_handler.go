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

// ClientHandler handles client management endpoints
type ClientHandler struct {
	clientService services.ClientService
	logger        *logrus.Logger
}

// NewClientHandler creates a new ClientHandler instance
func NewClientHandler(clientService services.ClientService, logger *logrus.Logger) *ClientHandler {
	return &ClientHandler{
		clientService: clientService,
		logger:        logger,
	}
}

// RegisterRoutes registers client management routes
func (h *ClientHandler) RegisterRoutes(router *gin.RouterGroup) {
	router.POST("", h.CreateClient)
	router.GET("/:client_id", h.GetClient)
	router.PUT("/:client_id", h.UpdateClient)
	router.DELETE("/:client_id", h.DeleteClient)
	router.GET("", h.ListClients)
}

// CreateClient handles POST /v1/clients
func (h *ClientHandler) CreateClient(c *gin.Context) {
	tenantID, err := middleware.GetTenantID(c)
	if err != nil {
		middleware.RespondWithError(c, http.StatusUnauthorized,
			models.ErrorCodeUnauthorized, "Invalid tenant context", nil)
		return
	}

	var req models.CreateClientRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		middleware.RespondWithError(c, http.StatusBadRequest,
			models.ErrorCodeValidationFailed, "Invalid request body", map[string]interface{}{"validation_errors": err.Error()})
		return
	}

	client, err := h.clientService.Create(c.Request.Context(), tenantID, &req)
	if err != nil {
		h.logger.WithError(err).WithFields(logrus.Fields{
			"tenant_id": tenantID,
			"name":      req.Name,
		}).Error("failed to create client")

		middleware.RespondWithError(c, http.StatusInternalServerError,
			models.ErrorCodeInternalError, "Failed to create client", nil)
		return
	}

	middleware.RespondWithSuccess(c, http.StatusCreated, client)
}

// GetClient handles GET /v1/clients/:client_id
func (h *ClientHandler) GetClient(c *gin.Context) {
	tenantID, err := middleware.GetTenantID(c)
	if err != nil {
		middleware.RespondWithError(c, http.StatusUnauthorized,
			models.ErrorCodeUnauthorized, "Invalid tenant context", nil)
		return
	}

	clientIDStr := c.Param("client_id")
	clientID, err := uuid.Parse(clientIDStr)
	if err != nil {
		middleware.RespondWithError(c, http.StatusBadRequest,
			models.ErrorCodeInvalidRequest, "Invalid client ID format", nil)
		return
	}

	client, err := h.clientService.GetByID(c.Request.Context(), tenantID, clientID)
	if err != nil {
		if err == models.ErrClientNotFound {
			middleware.RespondWithError(c, http.StatusNotFound,
				models.ErrorCodeResourceNotFound, "Client not found", nil)
			return
		}

		h.logger.WithError(err).WithFields(logrus.Fields{
			"tenant_id": tenantID,
			"client_id": clientID,
		}).Error("failed to get client")

		middleware.RespondWithError(c, http.StatusInternalServerError,
			models.ErrorCodeInternalError, "Failed to get client", nil)
		return
	}

	// Don't expose client secret
	client.ClientSecret = ""
	middleware.RespondWithSuccess(c, http.StatusOK, client)
}

// UpdateClient handles PUT /v1/clients/:client_id
func (h *ClientHandler) UpdateClient(c *gin.Context) {
	tenantID, err := middleware.GetTenantID(c)
	if err != nil {
		middleware.RespondWithError(c, http.StatusUnauthorized,
			models.ErrorCodeUnauthorized, "Invalid tenant context", nil)
		return
	}

	clientIDStr := c.Param("client_id")
	clientID, err := uuid.Parse(clientIDStr)
	if err != nil {
		middleware.RespondWithError(c, http.StatusBadRequest,
			models.ErrorCodeInvalidRequest, "Invalid client ID format", nil)
		return
	}

	var req models.UpdateClientRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		middleware.RespondWithError(c, http.StatusBadRequest,
			models.ErrorCodeValidationFailed, "Invalid request body", map[string]interface{}{"validation_errors": err.Error()})
		return
	}

	client, err := h.clientService.Update(c.Request.Context(), tenantID, clientID, &req)
	if err != nil {
		if err == models.ErrClientNotFound {
			middleware.RespondWithError(c, http.StatusNotFound,
				models.ErrorCodeResourceNotFound, "Client not found", nil)
			return
		}

		h.logger.WithError(err).WithFields(logrus.Fields{
			"tenant_id": tenantID,
			"client_id": clientID,
		}).Error("failed to update client")

		middleware.RespondWithError(c, http.StatusInternalServerError,
			models.ErrorCodeInternalError, "Failed to update client", nil)
		return
	}

	// Don't expose client secret
	client.ClientSecret = ""
	middleware.RespondWithSuccess(c, http.StatusOK, client)
}

// DeleteClient handles DELETE /v1/clients/:client_id
func (h *ClientHandler) DeleteClient(c *gin.Context) {
	tenantID, err := middleware.GetTenantID(c)
	if err != nil {
		middleware.RespondWithError(c, http.StatusUnauthorized,
			models.ErrorCodeUnauthorized, "Invalid tenant context", nil)
		return
	}

	clientIDStr := c.Param("client_id")
	clientID, err := uuid.Parse(clientIDStr)
	if err != nil {
		middleware.RespondWithError(c, http.StatusBadRequest,
			models.ErrorCodeInvalidRequest, "Invalid client ID format", nil)
		return
	}

	err = h.clientService.Delete(c.Request.Context(), tenantID, clientID)
	if err != nil {
		if err == models.ErrClientNotFound {
			middleware.RespondWithError(c, http.StatusNotFound,
				models.ErrorCodeResourceNotFound, "Client not found", nil)
			return
		}

		h.logger.WithError(err).WithFields(logrus.Fields{
			"tenant_id": tenantID,
			"client_id": clientID,
		}).Error("failed to delete client")

		middleware.RespondWithError(c, http.StatusInternalServerError,
			models.ErrorCodeInternalError, "Failed to delete client", nil)
		return
	}

	middleware.RespondWithSuccess(c, http.StatusOK, gin.H{"message": "Client deleted successfully"})
}

// ListClients handles GET /v1/clients
func (h *ClientHandler) ListClients(c *gin.Context) {
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

	response, err := h.clientService.List(c.Request.Context(), tenantID, limit, offset)
	if err != nil {
		h.logger.WithError(err).WithField("tenant_id", tenantID).Error("failed to list clients")
		middleware.RespondWithError(c, http.StatusInternalServerError,
			models.ErrorCodeInternalError, "Failed to list clients", nil)
		return
	}

	middleware.RespondWithSuccess(c, http.StatusOK, response)
}
