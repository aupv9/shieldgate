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

// TenantHandler handles tenant-related HTTP requests
type TenantHandler struct {
	tenantService services.TenantService
	logger        *logrus.Logger
}

// NewTenantHandler creates a new tenant handler
func NewTenantHandler(tenantService services.TenantService, logger *logrus.Logger) *TenantHandler {
	return &TenantHandler{
		tenantService: tenantService,
		logger:        logger,
	}
}

// RegisterRoutes registers tenant routes with the router
func (h *TenantHandler) RegisterRoutes(router *gin.RouterGroup) {
	// Admin routes for tenant management (no tenant context required)
	admin := router.Group("/admin")
	{
		admin.POST("/tenants", h.CreateTenant)
		admin.GET("/tenants", h.ListTenants)
		admin.GET("/tenants/:id", h.GetTenant)
		admin.PUT("/tenants/:id", h.UpdateTenant)
		admin.DELETE("/tenants/:id", h.DeleteTenant)
	}
}

// CreateTenant creates a new tenant
// @Summary Create a new tenant
// @Description Create a new tenant with name and domain
// @Tags tenants
// @Accept json
// @Produce json
// @Param request body models.CreateTenantRequest true "Tenant creation request"
// @Param Idempotency-Key header string false "Idempotency key for safe retries"
// @Success 201 {object} middleware.APIResponse{data=models.Tenant}
// @Failure 400 {object} middleware.APIResponse{error=middleware.ErrorResponse}
// @Failure 409 {object} middleware.APIResponse{error=middleware.ErrorResponse}
// @Failure 500 {object} middleware.APIResponse{error=middleware.ErrorResponse}
// @Router /v1/admin/tenants [post]
func (h *TenantHandler) CreateTenant(c *gin.Context) {
	var req models.CreateTenantRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.WithFields(logrus.Fields{
			"request_id": middleware.GetRequestID(c),
			"error":      err.Error(),
		}).Warn("invalid tenant creation request")

		middleware.RespondWithError(c, http.StatusBadRequest,
			models.ErrorCodeValidationFailed,
			"Invalid request format",
			map[string]interface{}{"validation_error": err.Error()})
		return
	}

	// TODO: Check idempotency key
	// idempotencyKey := c.GetHeader("Idempotency-Key")

	tenant, err := h.tenantService.Create(c.Request.Context(), &req)
	if err != nil {
		h.logger.WithFields(logrus.Fields{
			"request_id": middleware.GetRequestID(c),
			"error":      err.Error(),
			"name":       req.Name,
			"domain":     req.Domain,
		}).Error("failed to create tenant")

		// Map service errors to HTTP errors
		if err.Error() == "tenant with domain "+req.Domain+" already exists" {
			middleware.RespondWithError(c, http.StatusConflict,
				models.ErrorCodeDuplicateResource,
				"Tenant with this domain already exists",
				map[string]interface{}{"domain": req.Domain})
			return
		}

		middleware.RespondWithError(c, http.StatusInternalServerError,
			models.ErrorCodeInternalError,
			"Failed to create tenant",
			nil)
		return
	}

	h.logger.WithFields(logrus.Fields{
		"request_id": middleware.GetRequestID(c),
		"tenant_id":  tenant.ID,
		"name":       tenant.Name,
		"domain":     tenant.Domain,
	}).Info("tenant created successfully")

	c.JSON(http.StatusCreated, middleware.APIResponse{
		Data:      tenant,
		RequestID: middleware.GetRequestID(c),
	})
}

// GetTenant retrieves a tenant by ID
// @Summary Get tenant by ID
// @Description Get a tenant by its UUID
// @Tags tenants
// @Produce json
// @Param id path string true "Tenant ID (UUID)"
// @Success 200 {object} middleware.APIResponse{data=models.Tenant}
// @Failure 400 {object} middleware.APIResponse{error=middleware.ErrorResponse}
// @Failure 404 {object} middleware.APIResponse{error=middleware.ErrorResponse}
// @Failure 500 {object} middleware.APIResponse{error=middleware.ErrorResponse}
// @Router /v1/admin/tenants/{id} [get]
func (h *TenantHandler) GetTenant(c *gin.Context) {
	idStr := c.Param("id")
	tenantID, err := uuid.Parse(idStr)
	if err != nil {
		middleware.RespondWithError(c, http.StatusBadRequest,
			models.ErrorCodeInvalidRequest,
			"Invalid tenant ID format",
			map[string]interface{}{"tenant_id": idStr})
		return
	}

	tenant, err := h.tenantService.GetByID(c.Request.Context(), tenantID)
	if err != nil {
		if err == models.ErrTenantNotFound {
			middleware.RespondWithError(c, http.StatusNotFound,
				models.ErrorCodeResourceNotFound,
				"Tenant not found",
				map[string]interface{}{
					"resource_type": "tenant",
					"resource_id":   tenantID.String(),
				})
			return
		}

		h.logger.WithFields(logrus.Fields{
			"request_id": middleware.GetRequestID(c),
			"tenant_id":  tenantID,
			"error":      err.Error(),
		}).Error("failed to get tenant")

		middleware.RespondWithError(c, http.StatusInternalServerError,
			models.ErrorCodeInternalError,
			"Failed to retrieve tenant",
			nil)
		return
	}

	middleware.RespondWithSuccess(c, http.StatusCreated, tenant)
}

// ListTenants retrieves a paginated list of tenants
// @Summary List tenants
// @Description Get a paginated list of all tenants
// @Tags tenants
// @Produce json
// @Param limit query int false "Number of items per page (default: 20, max: 100)"
// @Param offset query int false "Number of items to skip (default: 0)"
// @Success 200 {object} middleware.APIResponse{data=models.PaginatedResponse}
// @Failure 400 {object} middleware.APIResponse{error=middleware.ErrorResponse}
// @Failure 500 {object} middleware.APIResponse{error=middleware.ErrorResponse}
// @Router /v1/admin/tenants [get]
func (h *TenantHandler) ListTenants(c *gin.Context) {
	// Parse pagination parameters
	limit := 20 // default
	if limitStr := c.Query("limit"); limitStr != "" {
		if parsedLimit, err := strconv.Atoi(limitStr); err == nil {
			if parsedLimit > 0 && parsedLimit <= 100 {
				limit = parsedLimit
			}
		}
	}

	offset := 0 // default
	if offsetStr := c.Query("offset"); offsetStr != "" {
		if parsedOffset, err := strconv.Atoi(offsetStr); err == nil && parsedOffset >= 0 {
			offset = parsedOffset
		}
	}

	result, err := h.tenantService.List(c.Request.Context(), limit, offset)
	if err != nil {
		h.logger.WithFields(logrus.Fields{
			"request_id": middleware.GetRequestID(c),
			"limit":      limit,
			"offset":     offset,
			"error":      err.Error(),
		}).Error("failed to list tenants")

		middleware.RespondWithError(c, http.StatusInternalServerError,
			models.ErrorCodeInternalError,
			"Failed to retrieve tenants",
			nil)
		return
	}

	middleware.RespondWithSuccess(c, http.StatusOK, result)
}

// UpdateTenant updates an existing tenant
// @Summary Update tenant
// @Description Update an existing tenant's information
// @Tags tenants
// @Accept json
// @Produce json
// @Param id path string true "Tenant ID (UUID)"
// @Param request body models.UpdateTenantRequest true "Tenant update request"
// @Success 200 {object} middleware.APIResponse{data=models.Tenant}
// @Failure 400 {object} middleware.APIResponse{error=middleware.ErrorResponse}
// @Failure 404 {object} middleware.APIResponse{error=middleware.ErrorResponse}
// @Failure 409 {object} middleware.APIResponse{error=middleware.ErrorResponse}
// @Failure 500 {object} middleware.APIResponse{error=middleware.ErrorResponse}
// @Router /v1/admin/tenants/{id} [put]
func (h *TenantHandler) UpdateTenant(c *gin.Context) {
	idStr := c.Param("id")
	tenantID, err := uuid.Parse(idStr)
	if err != nil {
		middleware.RespondWithError(c, http.StatusBadRequest,
			models.ErrorCodeInvalidRequest,
			"Invalid tenant ID format",
			map[string]interface{}{"tenant_id": idStr})
		return
	}

	var req models.UpdateTenantRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		middleware.RespondWithError(c, http.StatusBadRequest,
			models.ErrorCodeValidationFailed,
			"Invalid request format",
			map[string]interface{}{"validation_error": err.Error()})
		return
	}

	tenant, err := h.tenantService.Update(c.Request.Context(), tenantID, &req)
	if err != nil {
		if err == models.ErrTenantNotFound {
			middleware.RespondWithError(c, http.StatusNotFound,
				models.ErrorCodeResourceNotFound,
				"Tenant not found",
				map[string]interface{}{
					"resource_type": "tenant",
					"resource_id":   tenantID.String(),
				})
			return
		}

		// Check for domain conflict
		if err.Error() == "tenant with domain "+req.Domain+" already exists" {
			middleware.RespondWithError(c, http.StatusConflict,
				models.ErrorCodeDuplicateResource,
				"Tenant with this domain already exists",
				map[string]interface{}{"domain": req.Domain})
			return
		}

		h.logger.WithFields(logrus.Fields{
			"request_id": middleware.GetRequestID(c),
			"tenant_id":  tenantID,
			"error":      err.Error(),
		}).Error("failed to update tenant")

		middleware.RespondWithError(c, http.StatusInternalServerError,
			models.ErrorCodeInternalError,
			"Failed to update tenant",
			nil)
		return
	}

	h.logger.WithFields(logrus.Fields{
		"request_id": middleware.GetRequestID(c),
		"tenant_id":  tenant.ID,
		"name":       tenant.Name,
		"domain":     tenant.Domain,
	}).Info("tenant updated successfully")

	middleware.RespondWithSuccess(c, http.StatusOK, tenant)
}

// DeleteTenant deletes a tenant
// @Summary Delete tenant
// @Description Delete a tenant by ID
// @Tags tenants
// @Produce json
// @Param id path string true "Tenant ID (UUID)"
// @Success 204 "No Content"
// @Failure 400 {object} middleware.APIResponse{error=middleware.ErrorResponse}
// @Failure 404 {object} middleware.APIResponse{error=middleware.ErrorResponse}
// @Failure 500 {object} middleware.APIResponse{error=middleware.ErrorResponse}
// @Router /v1/admin/tenants/{id} [delete]
func (h *TenantHandler) DeleteTenant(c *gin.Context) {
	idStr := c.Param("id")
	tenantID, err := uuid.Parse(idStr)
	if err != nil {
		middleware.RespondWithError(c, http.StatusBadRequest,
			models.ErrorCodeInvalidRequest,
			"Invalid tenant ID format",
			map[string]interface{}{"tenant_id": idStr})
		return
	}

	err = h.tenantService.Delete(c.Request.Context(), tenantID)
	if err != nil {
		if err == models.ErrTenantNotFound {
			middleware.RespondWithError(c, http.StatusNotFound,
				models.ErrorCodeResourceNotFound,
				"Tenant not found",
				map[string]interface{}{
					"resource_type": "tenant",
					"resource_id":   tenantID.String(),
				})
			return
		}

		h.logger.WithFields(logrus.Fields{
			"request_id": middleware.GetRequestID(c),
			"tenant_id":  tenantID,
			"error":      err.Error(),
		}).Error("failed to delete tenant")

		middleware.RespondWithError(c, http.StatusInternalServerError,
			models.ErrorCodeInternalError,
			"Failed to delete tenant",
			nil)
		return
	}

	h.logger.WithFields(logrus.Fields{
		"request_id": middleware.GetRequestID(c),
		"tenant_id":  tenantID,
	}).Info("tenant deleted successfully")

	c.Status(http.StatusNoContent)
}
