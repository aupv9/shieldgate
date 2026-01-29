package services

import (
	"context"
	"fmt"
	"time"

	"shieldgate/internal/models"
	"shieldgate/internal/repo"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// AuditServiceImpl implements the AuditService interface
type AuditServiceImpl struct {
	auditRepo repo.AuditLogRepository
	logger    *logrus.Logger
}

// NewAuditService creates a new audit service instance
func NewAuditService(
	auditRepo repo.AuditLogRepository,
	logger *logrus.Logger,
) AuditService {
	return &AuditServiceImpl{
		auditRepo: auditRepo,
		logger:    logger,
	}
}

// Log logs an audit entry
func (s *AuditServiceImpl) Log(ctx context.Context, entry *models.AuditLog) error {
	// Set creation time if not set
	if entry.CreatedAt.IsZero() {
		entry.CreatedAt = time.Now()
	}

	// Generate ID if not set
	if entry.ID == uuid.Nil {
		entry.ID = uuid.New()
	}

	// Extract request context if available
	if entry.RequestID == "" {
		if requestID := ctx.Value("request_id"); requestID != nil {
			if reqID, ok := requestID.(string); ok {
				entry.RequestID = reqID
			}
		}
	}

	if entry.IPAddress == "" {
		if ipAddress := ctx.Value("ip_address"); ipAddress != nil {
			if ip, ok := ipAddress.(string); ok {
				entry.IPAddress = ip
			}
		}
	}

	if entry.UserAgent == "" {
		if userAgent := ctx.Value("user_agent"); userAgent != nil {
			if ua, ok := userAgent.(string); ok {
				entry.UserAgent = ua
			}
		}
	}

	if err := s.auditRepo.Create(ctx, entry); err != nil {
		s.logger.WithError(err).WithFields(logrus.Fields{
			"tenant_id":   entry.TenantID,
			"user_id":     entry.UserID,
			"client_id":   entry.ClientID,
			"action":      entry.Action,
			"resource":    entry.Resource,
			"resource_id": entry.ResourceID,
		}).Error("failed to create audit log entry")
		return fmt.Errorf("failed to create audit log: %w", err)
	}

	// Also log to structured logger for immediate visibility
	logLevel := logrus.InfoLevel
	if !entry.Success {
		logLevel = logrus.WarnLevel
	}

	s.logger.WithFields(logrus.Fields{
		"audit_id":    entry.ID,
		"tenant_id":   entry.TenantID,
		"user_id":     entry.UserID,
		"client_id":   entry.ClientID,
		"action":      entry.Action,
		"resource":    entry.Resource,
		"resource_id": entry.ResourceID,
		"ip_address":  entry.IPAddress,
		"request_id":  entry.RequestID,
		"success":     entry.Success,
		"error_code":  entry.ErrorCode,
		"metadata":    entry.Metadata,
	}).Log(logLevel, "audit event")

	return nil
}

// LogUserAction logs a user action
func (s *AuditServiceImpl) LogUserAction(ctx context.Context, tenantID, userID uuid.UUID, action models.AuditAction, resource string, resourceID *uuid.UUID, success bool, metadata map[string]interface{}) error {
	entry := &models.AuditLog{
		TenantID:   tenantID,
		UserID:     &userID,
		Action:     action,
		Resource:   resource,
		ResourceID: resourceID,
		Success:    success,
		Metadata:   metadata,
	}

	return s.Log(ctx, entry)
}

// LogClientAction logs a client action
func (s *AuditServiceImpl) LogClientAction(ctx context.Context, tenantID, clientID uuid.UUID, action models.AuditAction, resource string, resourceID *uuid.UUID, success bool, metadata map[string]interface{}) error {
	entry := &models.AuditLog{
		TenantID:   tenantID,
		ClientID:   &clientID,
		Action:     action,
		Resource:   resource,
		ResourceID: resourceID,
		Success:    success,
		Metadata:   metadata,
	}

	return s.Log(ctx, entry)
}

// LogSystemAction logs a system action
func (s *AuditServiceImpl) LogSystemAction(ctx context.Context, tenantID uuid.UUID, action models.AuditAction, resource string, resourceID *uuid.UUID, success bool, metadata map[string]interface{}) error {
	entry := &models.AuditLog{
		TenantID:   tenantID,
		Action:     action,
		Resource:   resource,
		ResourceID: resourceID,
		Success:    success,
		Metadata:   metadata,
	}

	return s.Log(ctx, entry)
}

// Query queries audit logs with filters
func (s *AuditServiceImpl) Query(ctx context.Context, query *models.AuditLogQuery) (*models.PaginatedResponse, error) {
	// Set default pagination if not provided
	if query.Limit <= 0 {
		query.Limit = 20
	}
	if query.Limit > 100 {
		query.Limit = 100
	}

	auditLogs, totalCount, err := s.auditRepo.Query(ctx, query)
	if err != nil {
		s.logger.WithError(err).WithFields(logrus.Fields{
			"tenant_id": query.TenantID,
			"user_id":   query.UserID,
			"client_id": query.ClientID,
			"action":    query.Action,
			"resource":  query.Resource,
		}).Error("failed to query audit logs")
		return nil, fmt.Errorf("failed to query audit logs: %w", err)
	}

	items := make([]interface{}, len(auditLogs))
	for i, log := range auditLogs {
		items[i] = log
	}

	return models.NewPaginatedResponse(items, query.Limit, query.Offset, totalCount), nil
}

// GetByID retrieves an audit log by ID
func (s *AuditServiceImpl) GetByID(ctx context.Context, tenantID, auditID uuid.UUID) (*models.AuditLog, error) {
	auditLog, err := s.auditRepo.GetByID(ctx, tenantID, auditID)
	if err != nil {
		if err == models.ErrResourceNotFound {
			return nil, err
		}
		s.logger.WithError(err).WithFields(logrus.Fields{
			"tenant_id": tenantID,
			"audit_id":  auditID,
		}).Error("failed to get audit log")
		return nil, fmt.Errorf("failed to get audit log: %w", err)
	}

	return auditLog, nil
}

// GetUserActivity retrieves audit logs for a specific user
func (s *AuditServiceImpl) GetUserActivity(ctx context.Context, tenantID, userID uuid.UUID, limit, offset int) (*models.PaginatedResponse, error) {
	// Set default pagination
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}

	auditLogs, totalCount, err := s.auditRepo.GetUserActivity(ctx, tenantID, userID, limit, offset)
	if err != nil {
		s.logger.WithError(err).WithFields(logrus.Fields{
			"tenant_id": tenantID,
			"user_id":   userID,
		}).Error("failed to get user activity")
		return nil, fmt.Errorf("failed to get user activity: %w", err)
	}

	items := make([]interface{}, len(auditLogs))
	for i, log := range auditLogs {
		items[i] = log
	}

	return models.NewPaginatedResponse(items, limit, offset, totalCount), nil
}

// GetResourceActivity retrieves audit logs for a specific resource
func (s *AuditServiceImpl) GetResourceActivity(ctx context.Context, tenantID uuid.UUID, resource string, resourceID uuid.UUID, limit, offset int) (*models.PaginatedResponse, error) {
	// Set default pagination
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}

	auditLogs, totalCount, err := s.auditRepo.GetResourceActivity(ctx, tenantID, resource, resourceID, limit, offset)
	if err != nil {
		s.logger.WithError(err).WithFields(logrus.Fields{
			"tenant_id":   tenantID,
			"resource":    resource,
			"resource_id": resourceID,
		}).Error("failed to get resource activity")
		return nil, fmt.Errorf("failed to get resource activity: %w", err)
	}

	items := make([]interface{}, len(auditLogs))
	for i, log := range auditLogs {
		items[i] = log
	}

	return models.NewPaginatedResponse(items, limit, offset, totalCount), nil
}

// CleanupOldLogs removes audit logs older than the specified duration
func (s *AuditServiceImpl) CleanupOldLogs(ctx context.Context, olderThan time.Duration) error {
	cutoffTime := time.Now().Add(-olderThan)

	if err := s.auditRepo.DeleteOldLogs(ctx, cutoffTime); err != nil {
		s.logger.WithError(err).WithField("cutoff_time", cutoffTime).Error("failed to cleanup old audit logs")
		return fmt.Errorf("failed to cleanup old audit logs: %w", err)
	}

	s.logger.WithField("cutoff_time", cutoffTime).Info("old audit logs cleaned up successfully")
	return nil
}

// GetSecurityEvents retrieves security-related audit events
func (s *AuditServiceImpl) GetSecurityEvents(ctx context.Context, tenantID uuid.UUID, limit, offset int) (*models.PaginatedResponse, error) {
	securityActions := []models.AuditAction{
		models.AuditActionUserLoginFailed,
		models.AuditActionUserLocked,
		models.AuditActionUserSuspended,
		models.AuditActionTokenRevoked,
		models.AuditActionPermissionGranted,
		models.AuditActionPermissionRevoked,
		models.AuditActionRoleAssigned,
		models.AuditActionRoleRevoked,
	}

	query := &models.AuditLogQuery{
		TenantID: tenantID,
		Success:  &[]bool{false}[0], // Failed events are more security-relevant
		Limit:    limit,
		Offset:   offset,
	}

	// This would need to be enhanced to filter by multiple actions
	// For now, we'll use the general query method
	return s.Query(ctx, query)
}

// GetComplianceReport generates a compliance report for audit logs
func (s *AuditServiceImpl) GetComplianceReport(ctx context.Context, tenantID uuid.UUID, startDate, endDate time.Time) (map[string]interface{}, error) {
	query := &models.AuditLogQuery{
		TenantID:  tenantID,
		StartDate: &startDate,
		EndDate:   &endDate,
		Limit:     1000, // Large limit for report
		Offset:    0,
	}

	auditLogs, totalCount, err := s.auditRepo.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to get audit logs for compliance report: %w", err)
	}

	// Generate report statistics
	report := map[string]interface{}{
		"period": map[string]interface{}{
			"start_date": startDate,
			"end_date":   endDate,
		},
		"total_events": totalCount,
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

	summary := report["summary"].(map[string]interface{})
	actions := report["actions"].(map[string]int)
	resources := report["resources"].(map[string]int)
	users := report["users"].(map[string]int)

	for _, log := range auditLogs {
		// Count success/failure
		if log.Success {
			summary["successful_events"] = summary["successful_events"].(int) + 1
		} else {
			summary["failed_events"] = summary["failed_events"].(int) + 1
		}

		// Count by actor type
		if log.UserID != nil {
			summary["user_actions"] = summary["user_actions"].(int) + 1
			users[log.UserID.String()]++
		} else if log.ClientID != nil {
			summary["client_actions"] = summary["client_actions"].(int) + 1
		} else {
			summary["system_actions"] = summary["system_actions"].(int) + 1
		}

		// Count by action and resource
		actions[string(log.Action)]++
		resources[log.Resource]++
	}

	return report, nil
}
