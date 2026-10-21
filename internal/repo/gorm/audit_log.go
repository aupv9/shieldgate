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
	"gorm.io/gorm/clause"
)

type auditLogRepository struct {
	db *gorm.DB
}

// NewAuditLogRepository creates a new audit log repository
func NewAuditLogRepository(db *gorm.DB) repo.AuditLogRepository {
	return &auditLogRepository{db: db}
}

func (r *auditLogRepository) Create(ctx context.Context, auditLog *models.AuditLog) error {
	if err := r.db.WithContext(ctx).Omit(clause.Associations).Create(auditLog).Error; err != nil {
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

	filtered := r.applyFilters(r.db.WithContext(ctx).Model(&models.AuditLog{}), query)
	if err := filtered.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("failed to count audit logs: %w", err)
	}

	if err := r.applyFilters(r.db.WithContext(ctx), query).
		Order("created_at DESC").
		Limit(query.Limit).
		Offset(query.Offset).
		Find(&auditLogs).Error; err != nil {
		return nil, 0, fmt.Errorf("failed to query audit logs: %w", err)
	}

	return auditLogs, total, nil
}

func (r *auditLogRepository) GetUserActivity(ctx context.Context, tenantID, userID uuid.UUID, limit, offset int) ([]*models.AuditLog, int64, error) {
	return r.Query(ctx, &models.AuditLogQuery{
		TenantID: tenantID,
		UserID:   &userID,
		Limit:    limit,
		Offset:   offset,
	})
}

func (r *auditLogRepository) GetResourceActivity(ctx context.Context, tenantID uuid.UUID, resource string, resourceID uuid.UUID, limit, offset int) ([]*models.AuditLog, int64, error) {
	return r.Query(ctx, &models.AuditLogQuery{
		TenantID:   tenantID,
		Resource:   resource,
		ResourceID: &resourceID,
		Limit:      limit,
		Offset:     offset,
	})
}

func (r *auditLogRepository) DeleteOldLogs(ctx context.Context, olderThan time.Time) error {
	if err := r.db.WithContext(ctx).
		Delete(&models.AuditLog{}, "created_at < ?", olderThan).Error; err != nil {
		return fmt.Errorf("failed to delete old audit logs: %w", err)
	}
	return nil
}

// applyFilters scopes a query to the tenant and every non-empty filter field
func (r *auditLogRepository) applyFilters(db *gorm.DB, query *models.AuditLogQuery) *gorm.DB {
	db = db.Where("tenant_id = ?", query.TenantID)

	if query.UserID != nil {
		db = db.Where("user_id = ?", *query.UserID)
	}
	if query.ClientID != nil {
		db = db.Where("client_id = ?", *query.ClientID)
	}
	if query.Action != nil {
		db = db.Where("action = ?", *query.Action)
	}
	if query.Resource != "" {
		db = db.Where("resource = ?", query.Resource)
	}
	if query.ResourceID != nil {
		db = db.Where("resource_id = ?", *query.ResourceID)
	}
	if query.IPAddress != "" {
		db = db.Where("ip_address = ?", query.IPAddress)
	}
	if query.Success != nil {
		db = db.Where("success = ?", *query.Success)
	}
	if query.StartDate != nil {
		db = db.Where("created_at >= ?", *query.StartDate)
	}
	if query.EndDate != nil {
		db = db.Where("created_at <= ?", *query.EndDate)
	}

	return db
}
