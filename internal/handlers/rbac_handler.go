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

// RBACHandler handles RBAC-related HTTP requests
type RBACHandler struct {
	roleService       services.RoleService
	permissionService services.PermissionService
	auditService      services.AuditService
	logger            *logrus.Logger
}

// NewRBACHandler creates a new RBAC handler
func NewRBACHandler(
	roleService services.RoleService,
	permissionService services.PermissionService,
	auditService services.AuditService,
	logger *logrus.Logger,
) *RBACHandler {
	return &RBACHandler{
		roleService:       roleService,
		permissionService: permissionService,
		auditService:      auditService,
		logger:            logger,
	}
}

// RegisterRoutes registers RBAC routes
func (h *RBACHandler) RegisterRoutes(router *gin.RouterGroup) {
	// Role management endpoints
	roles := router.Group("/v1/roles")
	roles.Use(middleware.RequireAuth())
	{
		roles.POST("", h.CreateRole)
		roles.GET("", h.ListRoles)
		roles.GET("/:role_id", h.GetRole)
		roles.PUT("/:role_id", h.UpdateRole)
		roles.DELETE("/:role_id", h.DeleteRole)

		// Role permissions
		roles.POST("/:role_id/permissions", h.AddPermissionToRole)
		roles.DELETE("/:role_id/permissions/:permission_id", h.RemovePermissionFromRole)
		roles.GET("/:role_id/permissions", h.GetRolePermissions)

		// Role assignments
		roles.POST("/:role_id/users", h.AssignRoleToUser)
		roles.DELETE("/:role_id/users/:user_id", h.RevokeRoleFromUser)
	}

	// Permission management endpoints
	permissions := router.Group("/v1/permissions")
	permissions.Use(middleware.RequireAuth())
	{
		permissions.POST("", h.CreatePermission)
		permissions.GET("", h.ListPermissions)
		permissions.GET("/:permission_id", h.GetPermission)
		permissions.PUT("/:permission_id", h.UpdatePermission)
		permissions.DELETE("/:permission_id", h.DeletePermission)
	}

	// User role endpoints
	users := router.Group("/v1/users")
	users.Use(middleware.RequireAuth())
	{
		users.GET("/:user_id/roles", h.GetUserRoles)
		users.GET("/:user_id/permissions", h.GetUserPermissions)
	}
}

// CreateRole creates a new role
func (h *RBACHandler) CreateRole(c *gin.Context) {
	tenantID, err := middleware.GetTenantID(c)
	if err != nil {
		middleware.RespondWithError(c, http.StatusUnauthorized, models.ErrorCodeUnauthorized, "Invalid tenant context", nil)
		return
	}

	var req models.CreateRoleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		middleware.RespondWithError(c, http.StatusBadRequest, models.ErrorCodeValidationFailed, "Invalid request format", map[string]interface{}{
			"validation_errors": err.Error(),
		})
		return
	}

	role, err := h.roleService.Create(c.Request.Context(), tenantID, &req)
	if err != nil {
		h.handleServiceError(c, err, "Failed to create role")
		return
	}

	middleware.RespondWithSuccess(c, http.StatusCreated, role)
}

// ListRoles lists roles with pagination
func (h *RBACHandler) ListRoles(c *gin.Context) {
	tenantID, err := middleware.GetTenantID(c)
	if err != nil {
		middleware.RespondWithError(c, http.StatusUnauthorized, models.ErrorCodeUnauthorized, "Invalid tenant context", nil)
		return
	}

	limit, offset := h.getPaginationParams(c)

	response, err := h.roleService.List(c.Request.Context(), tenantID, limit, offset)
	if err != nil {
		h.handleServiceError(c, err, "Failed to list roles")
		return
	}

	middleware.RespondWithSuccess(c, http.StatusOK, response)
}

// GetRole retrieves a role by ID
func (h *RBACHandler) GetRole(c *gin.Context) {
	tenantID, err := middleware.GetTenantID(c)
	if err != nil {
		middleware.RespondWithError(c, http.StatusUnauthorized, models.ErrorCodeUnauthorized, "Invalid tenant context", nil)
		return
	}

	roleID, err := uuid.Parse(c.Param("role_id"))
	if err != nil {
		middleware.RespondWithError(c, http.StatusBadRequest, models.ErrorCodeInvalidRequest, "Invalid role ID", nil)
		return
	}

	role, err := h.roleService.GetByID(c.Request.Context(), tenantID, roleID)
	if err != nil {
		h.handleServiceError(c, err, "Failed to get role")
		return
	}

	middleware.RespondWithSuccess(c, http.StatusOK, role)
}

// UpdateRole updates an existing role
func (h *RBACHandler) UpdateRole(c *gin.Context) {
	tenantID, err := middleware.GetTenantID(c)
	if err != nil {
		middleware.RespondWithError(c, http.StatusUnauthorized, models.ErrorCodeUnauthorized, "Invalid tenant context", nil)
		return
	}

	roleID, err := uuid.Parse(c.Param("role_id"))
	if err != nil {
		middleware.RespondWithError(c, http.StatusBadRequest, models.ErrorCodeInvalidRequest, "Invalid role ID", nil)
		return
	}

	var req models.UpdateRoleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		middleware.RespondWithError(c, http.StatusBadRequest, models.ErrorCodeValidationFailed, "Invalid request format", map[string]interface{}{
			"validation_errors": err.Error(),
		})
		return
	}

	role, err := h.roleService.Update(c.Request.Context(), tenantID, roleID, &req)
	if err != nil {
		h.handleServiceError(c, err, "Failed to update role")
		return
	}

	middleware.RespondWithSuccess(c, http.StatusOK, role)
}

// DeleteRole deletes a role
func (h *RBACHandler) DeleteRole(c *gin.Context) {
	tenantID, err := middleware.GetTenantID(c)
	if err != nil {
		middleware.RespondWithError(c, http.StatusUnauthorized, models.ErrorCodeUnauthorized, "Invalid tenant context", nil)
		return
	}

	roleID, err := uuid.Parse(c.Param("role_id"))
	if err != nil {
		middleware.RespondWithError(c, http.StatusBadRequest, models.ErrorCodeInvalidRequest, "Invalid role ID", nil)
		return
	}

	if err := h.roleService.Delete(c.Request.Context(), tenantID, roleID); err != nil {
		h.handleServiceError(c, err, "Failed to delete role")
		return
	}

	middleware.RespondWithSuccess(c, http.StatusNoContent, nil)
}

// AddPermissionToRole adds a permission to a role
func (h *RBACHandler) AddPermissionToRole(c *gin.Context) {
	tenantID, err := middleware.GetTenantID(c)
	if err != nil {
		middleware.RespondWithError(c, http.StatusUnauthorized, models.ErrorCodeUnauthorized, "Invalid tenant context", nil)
		return
	}

	roleID, err := uuid.Parse(c.Param("role_id"))
	if err != nil {
		middleware.RespondWithError(c, http.StatusBadRequest, models.ErrorCodeInvalidRequest, "Invalid role ID", nil)
		return
	}

	var req struct {
		PermissionID uuid.UUID `json:"permission_id" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		middleware.RespondWithError(c, http.StatusBadRequest, models.ErrorCodeValidationFailed, "Invalid request format", map[string]interface{}{
			"validation_errors": err.Error(),
		})
		return
	}

	// Get current user ID for audit
	userID, _ := middleware.GetUserID(c)

	if err := h.roleService.AddPermission(c.Request.Context(), tenantID, roleID, req.PermissionID, userID); err != nil {
		h.handleServiceError(c, err, "Failed to add permission to role")
		return
	}

	middleware.RespondWithSuccess(c, http.StatusNoContent, nil)
}

// RemovePermissionFromRole removes a permission from a role
func (h *RBACHandler) RemovePermissionFromRole(c *gin.Context) {
	tenantID, err := middleware.GetTenantID(c)
	if err != nil {
		middleware.RespondWithError(c, http.StatusUnauthorized, models.ErrorCodeUnauthorized, "Invalid tenant context", nil)
		return
	}

	roleID, err := uuid.Parse(c.Param("role_id"))
	if err != nil {
		middleware.RespondWithError(c, http.StatusBadRequest, models.ErrorCodeInvalidRequest, "Invalid role ID", nil)
		return
	}

	permissionID, err := uuid.Parse(c.Param("permission_id"))
	if err != nil {
		middleware.RespondWithError(c, http.StatusBadRequest, models.ErrorCodeInvalidRequest, "Invalid permission ID", nil)
		return
	}

	if err := h.roleService.RemovePermission(c.Request.Context(), tenantID, roleID, permissionID); err != nil {
		h.handleServiceError(c, err, "Failed to remove permission from role")
		return
	}

	middleware.RespondWithSuccess(c, http.StatusNoContent, nil)
}

// GetRolePermissions gets all permissions for a role
func (h *RBACHandler) GetRolePermissions(c *gin.Context) {
	tenantID, err := middleware.GetTenantID(c)
	if err != nil {
		middleware.RespondWithError(c, http.StatusUnauthorized, models.ErrorCodeUnauthorized, "Invalid tenant context", nil)
		return
	}

	roleID, err := uuid.Parse(c.Param("role_id"))
	if err != nil {
		middleware.RespondWithError(c, http.StatusBadRequest, models.ErrorCodeInvalidRequest, "Invalid role ID", nil)
		return
	}

	permissions, err := h.roleService.GetPermissions(c.Request.Context(), tenantID, roleID)
	if err != nil {
		h.handleServiceError(c, err, "Failed to get role permissions")
		return
	}

	middleware.RespondWithSuccess(c, http.StatusOK, map[string]interface{}{
		"permissions": permissions,
	})
}

// AssignRoleToUser assigns a role to a user
func (h *RBACHandler) AssignRoleToUser(c *gin.Context) {
	tenantID, err := middleware.GetTenantID(c)
	if err != nil {
		middleware.RespondWithError(c, http.StatusUnauthorized, models.ErrorCodeUnauthorized, "Invalid tenant context", nil)
		return
	}

	roleID, err := uuid.Parse(c.Param("role_id"))
	if err != nil {
		middleware.RespondWithError(c, http.StatusBadRequest, models.ErrorCodeInvalidRequest, "Invalid role ID", nil)
		return
	}

	var req models.AssignRoleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		middleware.RespondWithError(c, http.StatusBadRequest, models.ErrorCodeValidationFailed, "Invalid request format", map[string]interface{}{
			"validation_errors": err.Error(),
		})
		return
	}

	// Get current user ID for audit
	grantedBy, _ := middleware.GetUserID(c)

	if err := h.roleService.AssignToUser(c.Request.Context(), tenantID, roleID, req.UserID, grantedBy, req.ExpiresAt); err != nil {
		h.handleServiceError(c, err, "Failed to assign role to user")
		return
	}

	middleware.RespondWithSuccess(c, http.StatusNoContent, nil)
}

// RevokeRoleFromUser revokes a role from a user
func (h *RBACHandler) RevokeRoleFromUser(c *gin.Context) {
	tenantID, err := middleware.GetTenantID(c)
	if err != nil {
		middleware.RespondWithError(c, http.StatusUnauthorized, models.ErrorCodeUnauthorized, "Invalid tenant context", nil)
		return
	}

	roleID, err := uuid.Parse(c.Param("role_id"))
	if err != nil {
		middleware.RespondWithError(c, http.StatusBadRequest, models.ErrorCodeInvalidRequest, "Invalid role ID", nil)
		return
	}

	userID, err := uuid.Parse(c.Param("user_id"))
	if err != nil {
		middleware.RespondWithError(c, http.StatusBadRequest, models.ErrorCodeInvalidRequest, "Invalid user ID", nil)
		return
	}

	if err := h.roleService.RevokeFromUser(c.Request.Context(), tenantID, roleID, userID); err != nil {
		h.handleServiceError(c, err, "Failed to revoke role from user")
		return
	}

	middleware.RespondWithSuccess(c, http.StatusNoContent, nil)
}

// CreatePermission creates a new permission
func (h *RBACHandler) CreatePermission(c *gin.Context) {
	var req models.CreatePermissionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		middleware.RespondWithError(c, http.StatusBadRequest, models.ErrorCodeValidationFailed, "Invalid request format", map[string]interface{}{
			"validation_errors": err.Error(),
		})
		return
	}

	permission, err := h.permissionService.Create(c.Request.Context(), &req)
	if err != nil {
		h.handleServiceError(c, err, "Failed to create permission")
		return
	}

	middleware.RespondWithSuccess(c, http.StatusCreated, permission)
}

// ListPermissions lists permissions with pagination
func (h *RBACHandler) ListPermissions(c *gin.Context) {
	limit, offset := h.getPaginationParams(c)

	response, err := h.permissionService.List(c.Request.Context(), limit, offset)
	if err != nil {
		h.handleServiceError(c, err, "Failed to list permissions")
		return
	}

	middleware.RespondWithSuccess(c, http.StatusOK, response)
}

// GetPermission retrieves a permission by ID
func (h *RBACHandler) GetPermission(c *gin.Context) {
	permissionID, err := uuid.Parse(c.Param("permission_id"))
	if err != nil {
		middleware.RespondWithError(c, http.StatusBadRequest, models.ErrorCodeInvalidRequest, "Invalid permission ID", nil)
		return
	}

	permission, err := h.permissionService.GetByID(c.Request.Context(), permissionID)
	if err != nil {
		h.handleServiceError(c, err, "Failed to get permission")
		return
	}

	middleware.RespondWithSuccess(c, http.StatusOK, permission)
}

// UpdatePermission updates an existing permission
func (h *RBACHandler) UpdatePermission(c *gin.Context) {
	permissionID, err := uuid.Parse(c.Param("permission_id"))
	if err != nil {
		middleware.RespondWithError(c, http.StatusBadRequest, models.ErrorCodeInvalidRequest, "Invalid permission ID", nil)
		return
	}

	var req models.UpdatePermissionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		middleware.RespondWithError(c, http.StatusBadRequest, models.ErrorCodeValidationFailed, "Invalid request format", map[string]interface{}{
			"validation_errors": err.Error(),
		})
		return
	}

	permission, err := h.permissionService.Update(c.Request.Context(), permissionID, &req)
	if err != nil {
		h.handleServiceError(c, err, "Failed to update permission")
		return
	}

	middleware.RespondWithSuccess(c, http.StatusOK, permission)
}

// DeletePermission deletes a permission
func (h *RBACHandler) DeletePermission(c *gin.Context) {
	permissionID, err := uuid.Parse(c.Param("permission_id"))
	if err != nil {
		middleware.RespondWithError(c, http.StatusBadRequest, models.ErrorCodeInvalidRequest, "Invalid permission ID", nil)
		return
	}

	if err := h.permissionService.Delete(c.Request.Context(), permissionID); err != nil {
		h.handleServiceError(c, err, "Failed to delete permission")
		return
	}

	middleware.RespondWithSuccess(c, http.StatusNoContent, nil)
}

// GetUserRoles gets all roles for a user
func (h *RBACHandler) GetUserRoles(c *gin.Context) {
	tenantID, err := middleware.GetTenantID(c)
	if err != nil {
		middleware.RespondWithError(c, http.StatusUnauthorized, models.ErrorCodeUnauthorized, "Invalid tenant context", nil)
		return
	}

	userID, err := uuid.Parse(c.Param("user_id"))
	if err != nil {
		middleware.RespondWithError(c, http.StatusBadRequest, models.ErrorCodeInvalidRequest, "Invalid user ID", nil)
		return
	}

	roles, err := h.roleService.GetUserRoles(c.Request.Context(), tenantID, userID)
	if err != nil {
		h.handleServiceError(c, err, "Failed to get user roles")
		return
	}

	middleware.RespondWithSuccess(c, http.StatusOK, map[string]interface{}{
		"roles": roles,
	})
}

// GetUserPermissions gets all permissions for a user
func (h *RBACHandler) GetUserPermissions(c *gin.Context) {
	tenantID, err := middleware.GetTenantID(c)
	if err != nil {
		middleware.RespondWithError(c, http.StatusUnauthorized, models.ErrorCodeUnauthorized, "Invalid tenant context", nil)
		return
	}

	userID, err := uuid.Parse(c.Param("user_id"))
	if err != nil {
		middleware.RespondWithError(c, http.StatusBadRequest, models.ErrorCodeInvalidRequest, "Invalid user ID", nil)
		return
	}

	permissions, err := h.permissionService.GetUserPermissions(c.Request.Context(), tenantID, userID)
	if err != nil {
		h.handleServiceError(c, err, "Failed to get user permissions")
		return
	}

	middleware.RespondWithSuccess(c, http.StatusOK, map[string]interface{}{
		"permissions": permissions,
	})
}

// Helper methods

func (h *RBACHandler) getPaginationParams(c *gin.Context) (int, int) {
	limit := 20 // default
	offset := 0 // default

	if l := c.Query("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 100 {
			limit = parsed
		}
	}

	if o := c.Query("offset"); o != "" {
		if parsed, err := strconv.Atoi(o); err == nil && parsed >= 0 {
			offset = parsed
		}
	}

	return limit, offset
}

func (h *RBACHandler) handleServiceError(c *gin.Context, err error, message string) {
	requestID := middleware.GetRequestID(c)

	h.logger.WithError(err).WithField("request_id", requestID).Error(message)

	switch err {
	case models.ErrRoleNotFound, models.ErrPermissionNotFound:
		middleware.RespondWithError(c, http.StatusNotFound, models.ErrorCodeResourceNotFound, err.Error(), nil)
	case models.ErrDuplicateResource:
		middleware.RespondWithError(c, http.StatusConflict, models.ErrorCodeDuplicateResource, "Resource already exists", nil)
	case models.ErrBusinessRuleViolation:
		middleware.RespondWithError(c, http.StatusUnprocessableEntity, models.ErrorCodeBusinessRuleViolation, "Business rule violation", nil)
	case models.ErrInsufficientPermissions:
		middleware.RespondWithError(c, http.StatusForbidden, models.ErrorCodeInsufficientPermissions, "Insufficient permissions", nil)
	default:
		middleware.RespondWithError(c, http.StatusInternalServerError, models.ErrorCodeInternalError, "Internal server error", nil)
	}
}
