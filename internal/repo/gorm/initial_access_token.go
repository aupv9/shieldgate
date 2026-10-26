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

type initialAccessTokenRepository struct {
	db *gorm.DB
}

// NewInitialAccessTokenRepository creates a new initial access token repository
func NewInitialAccessTokenRepository(db *gorm.DB) repo.InitialAccessTokenRepository {
	return &initialAccessTokenRepository{db: db}
}

func (r *initialAccessTokenRepository) Create(ctx context.Context, token *models.InitialAccessToken) error {
	if err := r.db.WithContext(ctx).Create(token).Error; err != nil {
		return fmt.Errorf("failed to create initial access token: %w", err)
	}
	return nil
}

func (r *initialAccessTokenRepository) GetByHash(ctx context.Context, tenantID uuid.UUID, tokenHash string) (*models.InitialAccessToken, error) {
	var token models.InitialAccessToken
	if err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND token_hash = ?", tenantID, tokenHash).
		First(&token).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, models.ErrInitialAccessTokenNotFound
		}
		return nil, fmt.Errorf("failed to get initial access token: %w", err)
	}
	return &token, nil
}

// Consume counts a use in the same statement that checks the token is
// live, so a single-use token cannot register two clients concurrently
func (r *initialAccessTokenRepository) Consume(ctx context.Context, tenantID uuid.UUID, tokenHash string) (*models.InitialAccessToken, error) {
	var tokens []models.InitialAccessToken
	err := r.db.WithContext(ctx).Raw(`
		UPDATE initial_access_tokens SET uses = uses + 1
		WHERE tenant_id = ? AND token_hash = ? AND revoked_at IS NULL AND expires_at > ? AND uses < max_uses
		RETURNING *`,
		tenantID, tokenHash, time.Now(),
	).Scan(&tokens).Error
	if err != nil {
		return nil, fmt.Errorf("failed to use initial access token: %w", err)
	}
	if len(tokens) == 0 {
		return nil, models.ErrInitialAccessTokenNotFound
	}
	return &tokens[0], nil
}

func (r *initialAccessTokenRepository) List(ctx context.Context, tenantID uuid.UUID) ([]*models.InitialAccessToken, error) {
	var tokens []*models.InitialAccessToken
	if err := r.db.WithContext(ctx).
		Where("tenant_id = ?", tenantID).
		Order("created_at DESC").
		Limit(100).
		Find(&tokens).Error; err != nil {
		return nil, fmt.Errorf("failed to list initial access tokens: %w", err)
	}
	return tokens, nil
}

func (r *initialAccessTokenRepository) Revoke(ctx context.Context, tenantID, id uuid.UUID) error {
	result := r.db.WithContext(ctx).Model(&models.InitialAccessToken{}).
		Where("tenant_id = ? AND id = ? AND revoked_at IS NULL", tenantID, id).
		Update("revoked_at", time.Now())
	if result.Error != nil {
		return fmt.Errorf("failed to revoke initial access token: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return models.ErrInitialAccessTokenNotFound
	}
	return nil
}
