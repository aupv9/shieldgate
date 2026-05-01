package repo

import (
	"context"
	"time"

	"shieldgate/internal/models"

	"github.com/google/uuid"
)

// DeviceCodeRepository manages RFC 8628 device authorization code pairs.
type DeviceCodeRepository interface {
	Create(ctx context.Context, dc *models.DeviceCode) error
	GetByDeviceCode(ctx context.Context, deviceCode string) (*models.DeviceCode, error)
	GetByUserCode(ctx context.Context, userCode string) (*models.DeviceCode, error)
	Authorize(ctx context.Context, userCode string, userID uuid.UUID) error
	Deny(ctx context.Context, userCode string) error
	UpdateLastPolled(ctx context.Context, deviceCode string, polledAt time.Time) error
	DeleteExpired(ctx context.Context) error
}
