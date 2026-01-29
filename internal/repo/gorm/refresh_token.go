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

type refreshTokenRepository struct {
	db *gorm.DB
}

// NewRefreshTokenRepository creates a new refresh token repository
func NewRefreshTokenRepository(db *gorm.DB) repo.RefreshTokenRepository {
	return &refreshTokenRepository{db: db}
}

func (r *refreshTokenRepository) Create(ctx context.Context, token *models.RefreshToken) error {
	if err := r.db.WithContext(ctx).Create(token).Error; err != nil {
		return fmt.Errorf("failed to create refresh token: %w", err)
	}
	return nil
}

func (r *refreshTokenRepository) GetByToken(ctx context.Context, tenantID uuid.UUID, token string) (*models.RefreshToken, error) {
	var refreshToken models.RefreshToken
	if err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND token = ?", tenantID, token).
		First(&refreshToken).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, models.ErrRefreshTokenNotFound
		}
		return nil, fmt.Errorf("failed to get refresh token: %w", err)
	}
	return &refreshToken, nil
}

func (r *refreshTokenRepository) Delete(ctx context.Context, tenantID uuid.UUID, token string) error {
	if err := r.db.WithContext(ctx).
		Delete(&models.RefreshToken{}, "tenant_id = ? AND token = ?", tenantID, token).Error; err != nil {
		return fmt.Errorf("failed to delete refresh token: %w", err)
	}
	return nil
}

func (r *refreshTokenRepository) DeleteExpired(ctx context.Context) error {
	if err := r.db.WithContext(ctx).
		Delete(&models.RefreshToken{}, "expires_at < ?", time.Now()).Error; err != nil {
		return fmt.Errorf("failed to delete expired refresh tokens: %w", err)
	}
	return nil
}

func (r *refreshTokenRepository) DeleteByUserID(ctx context.Context, tenantID, userID uuid.UUID) error {
	if err := r.db.WithContext(ctx).
		Delete(&models.RefreshToken{}, "tenant_id = ? AND user_id = ?", tenantID, userID).Error; err != nil {
		return fmt.Errorf("failed to delete refresh tokens by user ID: %w", err)
	}
	return nil
}
