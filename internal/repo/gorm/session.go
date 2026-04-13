package gorm

import (
	"context"
	"time"

	"shieldgate/internal/models"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type sessionRepo struct{ db *gorm.DB }

func NewSessionRepository(db *gorm.DB) *sessionRepo { return &sessionRepo{db: db} }

func (r *sessionRepo) Create(ctx context.Context, s *models.Session) error {
	return r.db.WithContext(ctx).Create(s).Error
}

func (r *sessionRepo) GetByID(ctx context.Context, tenantID, sessionID uuid.UUID) (*models.Session, error) {
	var s models.Session
	err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND id = ?", tenantID, sessionID).
		First(&s).Error
	if err != nil {
		return nil, err
	}
	return &s, nil
}

func (r *sessionRepo) GetByTokenID(ctx context.Context, tokenID string) (*models.Session, error) {
	var s models.Session
	err := r.db.WithContext(ctx).
		Where("token_id = ?", tokenID).
		First(&s).Error
	if err != nil {
		return nil, err
	}
	return &s, nil
}

func (r *sessionRepo) ListByUser(ctx context.Context, tenantID, userID uuid.UUID, limit, offset int) ([]*models.Session, int64, error) {
	var sessions []*models.Session
	var total int64
	base := r.db.WithContext(ctx).Model(&models.Session{}).
		Where("tenant_id = ? AND user_id = ?", tenantID, userID)
	if err := base.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	if err := base.Order("last_active_at DESC").Limit(limit).Offset(offset).Find(&sessions).Error; err != nil {
		return nil, 0, err
	}
	return sessions, total, nil
}

func (r *sessionRepo) Update(ctx context.Context, s *models.Session) error {
	return r.db.WithContext(ctx).Save(s).Error
}

func (r *sessionRepo) Revoke(ctx context.Context, tenantID, sessionID uuid.UUID) error {
	now := time.Now()
	return r.db.WithContext(ctx).
		Model(&models.Session{}).
		Where("tenant_id = ? AND id = ?", tenantID, sessionID).
		Update("revoked_at", now).Error
}

func (r *sessionRepo) RevokeAll(ctx context.Context, tenantID, userID uuid.UUID) error {
	now := time.Now()
	return r.db.WithContext(ctx).
		Model(&models.Session{}).
		Where("tenant_id = ? AND user_id = ? AND revoked_at IS NULL", tenantID, userID).
		Update("revoked_at", now).Error
}

func (r *sessionRepo) DeleteExpired(ctx context.Context) error {
	return r.db.WithContext(ctx).
		Where("expires_at < ?", time.Now()).
		Delete(&models.Session{}).Error
}
