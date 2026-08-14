package gorm

import (
	"context"
	"errors"
	"fmt"

	"shieldgate/internal/models"
	"shieldgate/internal/repo"

	"gorm.io/gorm"
)

type signingKeyRepository struct {
	db *gorm.DB
}

// NewSigningKeyRepository creates a new signing key repository
func NewSigningKeyRepository(db *gorm.DB) repo.SigningKeyRepository {
	return &signingKeyRepository{db: db}
}

func (r *signingKeyRepository) Create(ctx context.Context, key *models.SigningKey) error {
	if err := r.db.WithContext(ctx).Create(key).Error; err != nil {
		return fmt.Errorf("failed to create signing key: %w", err)
	}
	return nil
}

func (r *signingKeyRepository) GetActive(ctx context.Context) (*models.SigningKey, error) {
	var key models.SigningKey
	if err := r.db.WithContext(ctx).
		Where("is_active = true AND retired_at IS NULL").
		Order("created_at DESC").
		First(&key).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, models.ErrSigningKeyNotFound
		}
		return nil, fmt.Errorf("failed to get active signing key: %w", err)
	}
	return &key, nil
}

func (r *signingKeyRepository) GetByKID(ctx context.Context, kid string) (*models.SigningKey, error) {
	var key models.SigningKey
	if err := r.db.WithContext(ctx).
		Where("kid = ? AND retired_at IS NULL", kid).
		First(&key).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, models.ErrSigningKeyNotFound
		}
		return nil, fmt.Errorf("failed to get signing key by kid: %w", err)
	}
	return &key, nil
}

func (r *signingKeyRepository) ListServing(ctx context.Context) ([]*models.SigningKey, error) {
	var keys []*models.SigningKey
	if err := r.db.WithContext(ctx).
		Where("retired_at IS NULL").
		Order("created_at DESC").
		Find(&keys).Error; err != nil {
		return nil, fmt.Errorf("failed to list signing keys: %w", err)
	}
	return keys, nil
}

func (r *signingKeyRepository) DeactivateAll(ctx context.Context) error {
	if err := r.db.WithContext(ctx).
		Model(&models.SigningKey{}).
		Where("is_active = true").
		Update("is_active", false).Error; err != nil {
		return fmt.Errorf("failed to deactivate signing keys: %w", err)
	}
	return nil
}
