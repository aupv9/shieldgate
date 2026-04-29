package gorm

import (
	"context"
	"time"

	"shieldgate/internal/models"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type apiKeyRepo struct{ db *gorm.DB }

// NewAPIKeyRepository creates a GORM-backed APIKeyRepository.
func NewAPIKeyRepository(db *gorm.DB) *apiKeyRepo {
	return &apiKeyRepo{db: db}
}

func (r *apiKeyRepo) Create(ctx context.Context, key *models.APIKey) error {
	return r.db.WithContext(ctx).Create(key).Error
}

func (r *apiKeyRepo) GetByID(ctx context.Context, tenantID, keyID uuid.UUID) (*models.APIKey, error) {
	var key models.APIKey
	err := r.db.WithContext(ctx).
		Where("id = ? AND tenant_id = ? AND deleted_at IS NULL", keyID, tenantID).
		First(&key).Error
	if err == gorm.ErrRecordNotFound {
		return nil, models.ErrAPIKeyNotFound
	}
	return &key, err
}

func (r *apiKeyRepo) GetByHash(ctx context.Context, hash string) (*models.APIKey, error) {
	var key models.APIKey
	err := r.db.WithContext(ctx).
		Where("key_hash = ? AND deleted_at IS NULL", hash).
		First(&key).Error
	if err == gorm.ErrRecordNotFound {
		return nil, models.ErrAPIKeyNotFound
	}
	return &key, err
}

func (r *apiKeyRepo) List(ctx context.Context, tenantID uuid.UUID, userID *uuid.UUID, limit, offset int) ([]*models.APIKey, int64, error) {
	var keys []*models.APIKey
	var count int64
	q := r.db.WithContext(ctx).Where("tenant_id = ? AND deleted_at IS NULL", tenantID)
	if userID != nil {
		q = q.Where("user_id = ?", *userID)
	}
	if err := q.Count(&count).Error; err != nil {
		return nil, 0, err
	}
	if err := q.Order("created_at DESC").Limit(limit).Offset(offset).Find(&keys).Error; err != nil {
		return nil, 0, err
	}
	return keys, count, nil
}

func (r *apiKeyRepo) Revoke(ctx context.Context, tenantID, keyID uuid.UUID) error {
	now := time.Now()
	return r.db.WithContext(ctx).Model(&models.APIKey{}).
		Where("id = ? AND tenant_id = ?", keyID, tenantID).
		Update("revoked_at", &now).Error
}

func (r *apiKeyRepo) UpdateLastUsed(ctx context.Context, keyID uuid.UUID) error {
	now := time.Now()
	return r.db.WithContext(ctx).Model(&models.APIKey{}).
		Where("id = ?", keyID).
		Update("last_used_at", &now).Error
}

func (r *apiKeyRepo) Delete(ctx context.Context, tenantID, keyID uuid.UUID) error {
	return r.db.WithContext(ctx).
		Where("id = ? AND tenant_id = ?", keyID, tenantID).
		Delete(&models.APIKey{}).Error
}
