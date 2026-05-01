package gorm

import (
	"context"
	"time"

	"shieldgate/internal/models"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type deviceCodeRepository struct {
	db *gorm.DB
}

func NewDeviceCodeRepository(db *gorm.DB) *deviceCodeRepository {
	return &deviceCodeRepository{db: db}
}

func (r *deviceCodeRepository) Create(ctx context.Context, dc *models.DeviceCode) error {
	return r.db.WithContext(ctx).Create(dc).Error
}

func (r *deviceCodeRepository) GetByDeviceCode(ctx context.Context, deviceCode string) (*models.DeviceCode, error) {
	var dc models.DeviceCode
	err := r.db.WithContext(ctx).Where("device_code = ?", deviceCode).First(&dc).Error
	if err == gorm.ErrRecordNotFound {
		return nil, models.ErrDeviceCodeNotFound
	}
	return &dc, err
}

func (r *deviceCodeRepository) GetByUserCode(ctx context.Context, userCode string) (*models.DeviceCode, error) {
	var dc models.DeviceCode
	err := r.db.WithContext(ctx).Where("user_code = ?", userCode).First(&dc).Error
	if err == gorm.ErrRecordNotFound {
		return nil, models.ErrDeviceCodeNotFound
	}
	return &dc, err
}

func (r *deviceCodeRepository) Authorize(ctx context.Context, userCode string, userID uuid.UUID) error {
	return r.db.WithContext(ctx).Model(&models.DeviceCode{}).
		Where("user_code = ? AND status = ?", userCode, models.DeviceCodeStatusPending).
		Updates(map[string]interface{}{
			"status":  models.DeviceCodeStatusAuthorized,
			"user_id": userID,
		}).Error
}

func (r *deviceCodeRepository) Deny(ctx context.Context, userCode string) error {
	return r.db.WithContext(ctx).Model(&models.DeviceCode{}).
		Where("user_code = ? AND status = ?", userCode, models.DeviceCodeStatusPending).
		Update("status", models.DeviceCodeStatusDenied).Error
}

func (r *deviceCodeRepository) UpdateLastPolled(ctx context.Context, deviceCode string, polledAt time.Time) error {
	return r.db.WithContext(ctx).Model(&models.DeviceCode{}).
		Where("device_code = ?", deviceCode).
		Update("last_polled_at", polledAt).Error
}

func (r *deviceCodeRepository) DeleteExpired(ctx context.Context) error {
	return r.db.WithContext(ctx).
		Where("expires_at < ?", time.Now()).
		Delete(&models.DeviceCode{}).Error
}
