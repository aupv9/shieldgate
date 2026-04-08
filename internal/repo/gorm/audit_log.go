package gorm

import (
	"context"
	"errors"
	"fmt"
	"time"

	"shieldgate/internal/models"
	"shieldgate/internal/repo"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type auditLogRepository struct {
	db *gorm.DB
}

// NewAuditLogRepository creates a new audit log repository
func NewAuditLogRepository(db *gorm.DB) repo.AuditLogRepository {
	return &auditLogRepository{db: db}
}

func (r *auditLogRepository) Create(ctx context.Context, auditLog *models.AuditLog) error {
	if err := r.db.WithContext(ctx).Create(auditLog).Error; err != nil {
		return fmt.Errorf("failed to create audit log: %w", err)
	}
	return nil
}

func (r *auditLogRepository) GetByID(ctx context.Context, tenantID, auditID uuid.UUID) (*models.AuditLog, error) {
	var auditLog models.AuditLog
	if err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND id = ?", tenantID, auditID).
		First(&auditLog).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, models.ErrResourceNotFound
		}
		return nil, fmt.Errorf("failed to get audit log by ID: %w", err)
	}
	return &auditLog, nil
}

func (r *auditLogRepository) Query(ctx context.Context, query *models.AuditLogQuery) ([]*models.AuditLog, int64, error) {
	var auditLogs []*models.AuditLog
	var total int64

	db := r.db.WithContext(ctx).Model(&models.AuditLog{}).Where("tenant_id = ?", query.TenantID)

	if query.UserID != nil {
		db = db.Where("user_id = ?", query.UserID)
	}
	if query.ClientID != nil {
		db = db.Where("client_id = ?", query.ClientID)
	}
	if query.Action != nil {
		db = db.Where("action = ?", query.Action)
	}
	if query.Resource != "" {
		db = db.Where("resource = ?", query.Resource)
	}
	if query.ResourceID != nil {
		db = db.Where("resource_id = ?", query.ResourceID)
	}
	if query.IPAddress != "" {
		db = db.Where("ip_address = ?", query.IPAddress)
	}
	if query.Success != nil {
		db = db.Where("success = ?", query.Success)
	}
	if query.StartDate != nil {
		db = db.Where("created_at >= ?", query.StartDate)
	}
	if query.EndDate != nil {
		db = db.Where("created_at <= ?", query.EndDate)
	}

	if err := db.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("failed to count audit logs: %w", err)
	}

	limit := query.Limit
	if limit <= 0 {
		limit = 50
	}

	if err := db.Order("created_at DESC").
		Limit(limit).
		Offset(query.Offset).
		Find(&auditLogs).Error; err != nil {
		return nil, 0, fmt.Errorf("failed to query audit logs: %w", err)
	}

	return auditLogs, total, nil
}

func (r *auditLogRepository) GetUserActivity(ctx context.Context, tenantID, userID uuid.UUID, limit, offset int) ([]*models.AuditLog, int64, error) {
	var auditLogs []*models.AuditLog
	var total int64

	db := r.db.WithContext(ctx).
		Model(&models.AuditLog{}).
		Where("tenant_id = ? AND user_id = ?", tenantID, userID)

	if err := db.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("failed to count user activity: %w", err)
	}

	if err := db.Order("created_at DESC").
		Limit(limit).
		Offset(offset).
		Find(&auditLogs).Error; err != nil {
		return nil, 0, fmt.Errorf("failed to get user activity: %w", err)
	}

	return auditLogs, total, nil
}

func (r *auditLogRepository) GetResourceActivity(ctx context.Context, tenantID uuid.UUID, resource string, resourceID uuid.UUID, limit, offset int) ([]*models.AuditLog, int64, error) {
	var auditLogs []*models.AuditLog
	var total int64

	db := r.db.WithContext(ctx).
		Model(&models.AuditLog{}).
		Where("tenant_id = ? AND resource = ? AND resource_id = ?", tenantID, resource, resourceID)

	if err := db.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("failed to count resource activity: %w", err)
	}

	if err := db.Order("created_at DESC").
		Limit(limit).
		Offset(offset).
		Find(&auditLogs).Error; err != nil {
		return nil, 0, fmt.Errorf("failed to get resource activity: %w", err)
	}

	return auditLogs, total, nil
}

func (r *auditLogRepository) DeleteOldLogs(ctx context.Context, olderThan time.Time) error {
	if err := r.db.WithContext(ctx).
		Where("created_at < ?", olderThan).
		Delete(&models.AuditLog{}).Error; err != nil {
		return fmt.Errorf("failed to delete old audit logs: %w", err)
	}
	return nil
}
