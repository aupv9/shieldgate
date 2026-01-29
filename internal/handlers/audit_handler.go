package handlers

import (
	"net/http"
	"strconv"
	"time"

	"shieldgate/internal/middleware"
	"shieldgate/internal/models"
	"shieldgate/internal/services"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// AuditHandler handles audit log HTTP requests
type AuditHandler struct {
	auditService services.AuditService
	logger       *logrus.Logger
}

// NewAuditHandler creates a new audit handler
func NewAuditHandler(
	auditService services.AuditService,
	logger *logrus.Logger,
) *AuditHandler {
	return &AuditHandler{
		auditService: auditService,
		logger:       logger,
	}
}

// RegisterRoutes registers audit routes
func (h *AuditHandler) RegisterRoutes(router *gin.RouterGroup) {
	// Audit log endpoints
	audit := router.Group("/v1/audit")
	audit.Use(middleware.RequireAuth())
	{
		audit.GET("/logs", h.QueryAuditLogs)
		audit.GET("/logs/:audit_id", h.GetAuditLog)
		audit.GET("/users/:user_id/activity", h.GetUserActivity)
		audit.GET("/resources/:resource/:resource_id/activity", h.GetResourceActivity)
		audit.GET("/security-events", h.GetSecurityEvents)
		audit.GET("/compliance-report", h.GetComplianceReport)
	}
}

// QueryAuditLogs queries audit logs with filters
func (h *AuditHandler) QueryAuditLogs(c *gin.Context) {
	tenantID, err := middleware.GetTenantID(c)
	if err != nil {
		middleware.RespondWithError(c, http.StatusUnauthorized, models.ErrorCodeUnauthorized, "Invalid tenant context", nil)
		return
	}

	// Parse query parameters
	query := &models.AuditLogQuery{
		TenantID: tenantID,
		Limit:    20, // default
		Offset:   0,  // default
	}

	// Parse pagination
	if l := c.Query("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 100 {
			query.Limit = parsed
		}
	}

	if o := c.Query("offset"); o != "" {
		if parsed, err := strconv.Atoi(o); err == nil && parsed >= 0 {
			query.Offset = parsed
		}
	}

	// Parse filters
	if userID := c.Query("user_id"); userID != "" {
		if parsed, err := uuid.Parse(userID); err == nil {
			query.UserID = &parsed
		}
	}

	if clientID := c.Query("client_id"); clientID != "" {
		if parsed, err := uuid.Parse(clientID); err == nil {
			query.ClientID = &parsed
		}
	}

	if action := c.Query("action"); action != "" {
		actionEnum := models.AuditAction(action)
		query.Action = &actionEnum
	}

	if resource := c.Query("resource"); resource != "" {
		query.Resource = resource
	}

	if resourceID := c.Query("resource_id"); resourceID != "" {
		if parsed, err := uuid.Parse(resourceID); err == nil {
			query.ResourceID = &parsed
		}
	}

	if ipAddress := c.Query("ip_address"); ipAddress != "" {
		query.IPAddress = ipAddress
	}

	if success := c.Query("success"); success != "" {
		if parsed, err := strconv.ParseBool(success); err == nil {
			query.Success = &parsed
		}
	}

	// Parse date range
	if startDate := c.Query("start_date"); startDate != "" {
		if parsed, err := time.Parse(time.RFC3339, startDate); err == nil {
			query.StartDate = &parsed
		}
	}

	if endDate := c.Query("end_date"); endDate != "" {
		if parsed, err := time.Parse(time.RFC3339, endDate); err == nil {
			query.EndDate = &parsed
		}
	}

	response, err := h.auditService.Query(c.Request.Context(), query)
	if err != nil {
		h.handleServiceError(c, err, "Failed to query audit logs")
		return
	}

	middleware.RespondWithSuccess(c, http.StatusOK, response)
}

// GetAuditLog retrieves a specific audit log entry
func (h *AuditHandler) GetAuditLog(c *gin.Context) {
	tenantID, err := middleware.GetTenantID(c)
	if err != nil {
		middleware.RespondWithError(c, http.StatusUnauthorized, models.ErrorCodeUnauthorized, "Invalid tenant context", nil)
		return
	}

	auditID, err := uuid.Parse(c.Param("audit_id"))
	if err != nil {
		middleware.RespondWithError(c, http.StatusBadRequest, models.ErrorCodeInvalidRequest, "Invalid audit ID", nil)
		return
	}

	auditLog, err := h.auditService.GetByID(c.Request.Context(), tenantID, auditID)
	if err != nil {
		h.handleServiceError(c, err, "Failed to get audit log")
		return
	}

	middleware.RespondWithSuccess(c, http.StatusOK, auditLog)
}

// GetUserActivity retrieves audit logs for a specific user
func (h *AuditHandler) GetUserActivity(c *gin.Context) {
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

	limit, offset := h.getPaginationParams(c)

	response, err := h.auditService.GetUserActivity(c.Request.Context(), tenantID, userID, limit, offset)
	if err != nil {
		h.handleServiceError(c, err, "Failed to get user activity")
		return
	}

	middleware.RespondWithSuccess(c, http.StatusOK, response)
}

// GetResourceActivity retrieves audit logs for a specific resource
func (h *AuditHandler) GetResourceActivity(c *gin.Context) {
	tenantID, err := middleware.GetTenantID(c)
	if err != nil {
		middleware.RespondWithError(c, http.StatusUnauthorized, models.ErrorCodeUnauthorized, "Invalid tenant context", nil)
		return
	}

	resource := c.Param("resource")
	if resource == "" {
		middleware.RespondWithError(c, http.StatusBadRequest, models.ErrorCodeInvalidRequest, "Resource parameter is required", nil)
		return
	}

	resourceID, err := uuid.Parse(c.Param("resource_id"))
	if err != nil {
		middleware.RespondWithError(c, http.StatusBadRequest, models.ErrorCodeInvalidRequest, "Invalid resource ID", nil)
		return
	}

	limit, offset := h.getPaginationParams(c)

	response, err := h.auditService.GetResourceActivity(c.Request.Context(), tenantID, resource, resourceID, limit, offset)
	if err != nil {
		h.handleServiceError(c, err, "Failed to get resource activity")
		return
	}

	middleware.RespondWithSuccess(c, http.StatusOK, response)
}

// GetSecurityEvents retrieves security-related audit events
func (h *AuditHandler) GetSecurityEvents(c *gin.Context) {
	tenantID, err := middleware.GetTenantID(c)
	if err != nil {
		middleware.RespondWithError(c, http.StatusUnauthorized, models.ErrorCodeUnauthorized, "Invalid tenant context", nil)
		return
	}

	limit, offset := h.getPaginationParams(c)

	// Create query for security events
	query := &models.AuditLogQuery{
		TenantID: tenantID,
		Limit:    limit,
		Offset:   offset,
	}

	// Add date filter if provided
	if startDate := c.Query("start_date"); startDate != "" {
		if parsed, err := time.Parse(time.RFC3339, startDate); err == nil {
			query.StartDate = &parsed
		}
	}

	if endDate := c.Query("end_date"); endDate != "" {
		if parsed, err := time.Parse(time.RFC3339, endDate); err == nil {
			query.EndDate = &parsed
		}
	}

	response, err := h.auditService.Query(c.Request.Context(), query)
	if err != nil {
		h.handleServiceError(c, err, "Failed to get security events")
		return
	}

	// Filter for security-related events
	securityActions := map[models.AuditAction]bool{
		models.AuditActionUserLoginFailed:   true,
		models.AuditActionUserLocked:        true,
		models.AuditActionUserSuspended:     true,
		models.AuditActionTokenRevoked:      true,
		models.AuditActionPermissionGranted: true,
		models.AuditActionPermissionRevoked: true,
		models.AuditActionRoleAssigned:      true,
		models.AuditActionRoleRevoked:       true,
	}

	filteredItems := make([]interface{}, 0)
	if response != nil && response.Items != nil {
		for _, item := range response.Items {
			if auditLog, ok := item.(*models.AuditLog); ok {
				if securityActions[auditLog.Action] || !auditLog.Success {
					filteredItems = append(filteredItems, item)
				}
			}
		}
	}

	// Update response with filtered items
	if response != nil {
		response.Items = filteredItems
		response.Page.TotalCount = int64(len(filteredItems))
	}

	middleware.RespondWithSuccess(c, http.StatusOK, response)
}

// GetComplianceReport generates a compliance report
func (h *AuditHandler) GetComplianceReport(c *gin.Context) {
	tenantID, err := middleware.GetTenantID(c)
	if err != nil {
		middleware.RespondWithError(c, http.StatusUnauthorized, models.ErrorCodeUnauthorized, "Invalid tenant context", nil)
		return
	}

	// Parse date range (required for compliance reports)
	startDateStr := c.Query("start_date")
	endDateStr := c.Query("end_date")

	if startDateStr == "" || endDateStr == "" {
		middleware.RespondWithError(c, http.StatusBadRequest, models.ErrorCodeInvalidRequest, "start_date and end_date parameters are required", nil)
		return
	}

	startDate, err := time.Parse(time.RFC3339, startDateStr)
	if err != nil {
		middleware.RespondWithError(c, http.StatusBadRequest, models.ErrorCodeInvalidRequest, "Invalid start_date format, use RFC3339", nil)
		return
	}

	endDate, err := time.Parse(time.RFC3339, endDateStr)
	if err != nil {
		middleware.RespondWithError(c, http.StatusBadRequest, models.ErrorCodeInvalidRequest, "Invalid end_date format, use RFC3339", nil)
		return
	}

	// Validate date range
	if endDate.Before(startDate) {
		middleware.RespondWithError(c, http.StatusBadRequest, models.ErrorCodeInvalidRequest, "end_date must be after start_date", nil)
		return
	}

	// Limit report to maximum 90 days
	if endDate.Sub(startDate) > 90*24*time.Hour {
		middleware.RespondWithError(c, http.StatusBadRequest, models.ErrorCodeInvalidRequest, "Date range cannot exceed 90 days", nil)
		return
	}

	// Generate compliance report (this would be implemented in the audit service)
	query := &models.AuditLogQuery{
		TenantID:  tenantID,
		StartDate: &startDate,
		EndDate:   &endDate,
		Limit:     10000, // Large limit for report generation
		Offset:    0,
	}

	response, err := h.auditService.Query(c.Request.Context(), query)
	if err != nil {
		h.handleServiceError(c, err, "Failed to generate compliance report")
		return
	}

	// Generate report summary
	report := h.generateComplianceReportSummary(response, startDate, endDate)

	middleware.RespondWithSuccess(c, http.StatusOK, report)
}

// Helper methods

func (h *AuditHandler) getPaginationParams(c *gin.Context) (int, int) {
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

func (h *AuditHandler) generateComplianceReportSummary(response *models.PaginatedResponse, startDate, endDate time.Time) map[string]interface{} {
	report := map[string]interface{}{
		"period": map[string]interface{}{
			"start_date": startDate.Format(time.RFC3339),
			"end_date":   endDate.Format(time.RFC3339),
		},
		"total_events": response.Page.TotalCount,
		"summary": map[string]interface{}{
			"successful_events": 0,
			"failed_events":     0,
			"user_actions":      0,
			"client_actions":    0,
			"system_actions":    0,
		},
		"actions":   make(map[string]int),
		"resources": make(map[string]int),
		"users":     make(map[string]int),
	}

	if response.Items == nil {
		return report
	}

	summary := report["summary"].(map[string]interface{})
	actions := report["actions"].(map[string]int)
	resources := report["resources"].(map[string]int)
	users := report["users"].(map[string]int)

	for _, item := range response.Items {
		if auditLog, ok := item.(*models.AuditLog); ok {
			// Count success/failure
			if auditLog.Success {
				summary["successful_events"] = summary["successful_events"].(int) + 1
			} else {
				summary["failed_events"] = summary["failed_events"].(int) + 1
			}

			// Count by actor type
			if auditLog.UserID != nil {
				summary["user_actions"] = summary["user_actions"].(int) + 1
				users[auditLog.UserID.String()]++
			} else if auditLog.ClientID != nil {
				summary["client_actions"] = summary["client_actions"].(int) + 1
			} else {
				summary["system_actions"] = summary["system_actions"].(int) + 1
			}

			// Count by action and resource
			actions[string(auditLog.Action)]++
			resources[auditLog.Resource]++
		}
	}

	return report
}

func (h *AuditHandler) handleServiceError(c *gin.Context, err error, message string) {
	requestID := middleware.GetRequestID(c)

	h.logger.WithError(err).WithField("request_id", requestID).Error(message)

	switch err {
	case models.ErrResourceNotFound:
		middleware.RespondWithError(c, http.StatusNotFound, models.ErrorCodeResourceNotFound, err.Error(), nil)
	case models.ErrInsufficientPermissions:
		middleware.RespondWithError(c, http.StatusForbidden, models.ErrorCodeInsufficientPermissions, "Insufficient permissions", nil)
	default:
		middleware.RespondWithError(c, http.StatusInternalServerError, models.ErrorCodeInternalError, "Internal server error", nil)
	}
}
