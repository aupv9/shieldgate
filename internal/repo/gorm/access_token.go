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

type accessTokenRepository struct {
	db *gorm.DB
}

// NewAccessTokenRepository creates a new access token repository
func NewAccessTokenRepository(db *gorm.DB) repo.AccessTokenRepository {
	return &accessTokenRepository{db: db}
}

func (r *accessTokenRepository) Create(ctx context.Context, token *models.AccessToken) error {
	if err := r.db.WithContext(ctx).Create(token).Error; err != nil {
		return fmt.Errorf("failed to create access token: %w", err)
	}
	return nil
}

func (r *accessTokenRepository) GetByToken(ctx context.Context, tenantID uuid.UUID, token string) (*models.AccessToken, error) {
	var accessToken models.AccessToken
	if err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND token = ?", tenantID, token).
		First(&accessToken).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, models.ErrAccessTokenNotFound
		}
		return nil, fmt.Errorf("failed to get access token: %w", err)
	}
	return &accessToken, nil
}

func (r *accessTokenRepository) Delete(ctx context.Context, tenantID uuid.UUID, token string) error {
	if err := r.db.WithContext(ctx).
		Delete(&models.AccessToken{}, "tenant_id = ? AND token = ?", tenantID, token).Error; err != nil {
		return fmt.Errorf("failed to delete access token: %w", err)
	}
	return nil
}

func (r *accessTokenRepository) DeleteExpired(ctx context.Context) error {
	if err := r.db.WithContext(ctx).
		Delete(&models.AccessToken{}, "expires_at < ?", time.Now()).Error; err != nil {
		return fmt.Errorf("failed to delete expired access tokens: %w", err)
	}
	return nil
}

func (r *accessTokenRepository) DeleteByUserID(ctx context.Context, tenantID, userID uuid.UUID) error {
	if err := r.db.WithContext(ctx).
		Delete(&models.AccessToken{}, "tenant_id = ? AND user_id = ?", tenantID, userID).Error; err != nil {
		return fmt.Errorf("failed to delete access tokens by user ID: %w", err)
	}
	return nil
}
