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

type deviceCodeRepository struct {
	db *gorm.DB
}

// NewDeviceCodeRepository creates a new device code repository
func NewDeviceCodeRepository(db *gorm.DB) repo.DeviceCodeRepository {
	return &deviceCodeRepository{db: db}
}

func (r *deviceCodeRepository) Create(ctx context.Context, code *models.DeviceCode) error {
	if err := r.db.WithContext(ctx).Create(code).Error; err != nil {
		return fmt.Errorf("failed to create device code: %w", err)
	}
	return nil
}

func (r *deviceCodeRepository) GetByDeviceCode(ctx context.Context, tenantID uuid.UUID, deviceCode string) (*models.DeviceCode, error) {
	var code models.DeviceCode
	if err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND device_code = ?", tenantID, deviceCode).
		First(&code).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, models.ErrDeviceCodeNotFound
		}
		return nil, fmt.Errorf("failed to get device code: %w", err)
	}
	return &code, nil
}

func (r *deviceCodeRepository) GetByUserCode(ctx context.Context, tenantID uuid.UUID, userCode string) (*models.DeviceCode, error) {
	var code models.DeviceCode
	if err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND user_code = ?", tenantID, userCode).
		First(&code).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, models.ErrDeviceCodeNotFound
		}
		return nil, fmt.Errorf("failed to get device code by user code: %w", err)
	}
	return &code, nil
}

func (r *deviceCodeRepository) Update(ctx context.Context, code *models.DeviceCode) error {
	if err := r.db.WithContext(ctx).Save(code).Error; err != nil {
		return fmt.Errorf("failed to update device code: %w", err)
	}
	return nil
}

func (r *deviceCodeRepository) Delete(ctx context.Context, tenantID uuid.UUID, deviceCode string) error {
	if err := r.db.WithContext(ctx).
		Delete(&models.DeviceCode{}, "tenant_id = ? AND device_code = ?", tenantID, deviceCode).Error; err != nil {
		return fmt.Errorf("failed to delete device code: %w", err)
	}
	return nil
}

func (r *deviceCodeRepository) DeleteExpired(ctx context.Context) error {
	if err := r.db.WithContext(ctx).
		Delete(&models.DeviceCode{}, "expires_at < ?", time.Now()).Error; err != nil {
		return fmt.Errorf("failed to delete expired device codes: %w", err)
	}
	return nil
}
