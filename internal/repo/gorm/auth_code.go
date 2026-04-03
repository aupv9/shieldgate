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

type authCodeRepository struct {
	db *gorm.DB
}

// NewAuthCodeRepository creates a new authorization code repository
func NewAuthCodeRepository(db *gorm.DB) repo.AuthCodeRepository {
	return &authCodeRepository{db: db}
}

func (r *authCodeRepository) Create(ctx context.Context, code *models.AuthorizationCode) error {
	if err := r.db.WithContext(ctx).Create(code).Error; err != nil {
		return fmt.Errorf("failed to create authorization code: %w", err)
	}
	return nil
}

func (r *authCodeRepository) GetByCode(ctx context.Context, tenantID uuid.UUID, code string) (*models.AuthorizationCode, error) {
	var authCode models.AuthorizationCode
	if err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND code = ?", tenantID, code).
		First(&authCode).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, models.ErrAuthCodeNotFound
		}
		return nil, fmt.Errorf("failed to get authorization code: %w", err)
	}
	return &authCode, nil
}

func (r *authCodeRepository) Delete(ctx context.Context, tenantID uuid.UUID, code string) error {
	if err := r.db.WithContext(ctx).
		Delete(&models.AuthorizationCode{}, "tenant_id = ? AND code = ?", tenantID, code).Error; err != nil {
		return fmt.Errorf("failed to delete authorization code: %w", err)
	}
	return nil
}

func (r *authCodeRepository) DeleteExpired(ctx context.Context) error {
	if err := r.db.WithContext(ctx).
		Delete(&models.AuthorizationCode{}, "expires_at < ?", time.Now()).Error; err != nil {
		return fmt.Errorf("failed to delete expired authorization codes: %w", err)
	}
	return nil
}
