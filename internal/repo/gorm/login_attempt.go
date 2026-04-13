package gorm

import (
	"context"
	"time"

	"shieldgate/internal/models"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type loginAttemptRepo struct{ db *gorm.DB }

func NewLoginAttemptRepository(db *gorm.DB) *loginAttemptRepo { return &loginAttemptRepo{db: db} }

func (r *loginAttemptRepo) Create(ctx context.Context, a *models.LoginAttempt) error {
	return r.db.WithContext(ctx).Create(a).Error
}

func (r *loginAttemptRepo) CountRecent(ctx context.Context, tenantID uuid.UUID, ipAddress, email string, since time.Time) (int64, error) {
	var count int64
	err := r.db.WithContext(ctx).
		Model(&models.LoginAttempt{}).
		Where("tenant_id = ? AND ip_address = ? AND email = ? AND success = false AND created_at >= ?",
			tenantID, ipAddress, email, since).
		Count(&count).Error
	return count, err
}

func (r *loginAttemptRepo) DeleteOld(ctx context.Context, before time.Time) error {
	return r.db.WithContext(ctx).
		Where("created_at < ?", before).
		Delete(&models.LoginAttempt{}).Error
}
