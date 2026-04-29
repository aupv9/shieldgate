package gorm

import (
	"context"
	"fmt"

	"shieldgate/internal/models"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type webhookRepo struct{ db *gorm.DB }

// NewWebhookRepository creates a GORM-backed WebhookRepository.
func NewWebhookRepository(db *gorm.DB) *webhookRepo {
	return &webhookRepo{db: db}
}

func (r *webhookRepo) Create(ctx context.Context, w *models.WebhookEndpoint) error {
	return r.db.WithContext(ctx).Create(w).Error
}

func (r *webhookRepo) GetByID(ctx context.Context, tenantID, webhookID uuid.UUID) (*models.WebhookEndpoint, error) {
	var w models.WebhookEndpoint
	err := r.db.WithContext(ctx).
		Where("id = ? AND tenant_id = ? AND deleted_at IS NULL", webhookID, tenantID).
		First(&w).Error
	if err == gorm.ErrRecordNotFound {
		return nil, models.ErrWebhookNotFound
	}
	return &w, err
}

func (r *webhookRepo) Update(ctx context.Context, w *models.WebhookEndpoint) error {
	return r.db.WithContext(ctx).Save(w).Error
}

func (r *webhookRepo) Delete(ctx context.Context, tenantID, webhookID uuid.UUID) error {
	return r.db.WithContext(ctx).
		Where("id = ? AND tenant_id = ?", webhookID, tenantID).
		Delete(&models.WebhookEndpoint{}).Error
}

func (r *webhookRepo) List(ctx context.Context, tenantID uuid.UUID, limit, offset int) ([]*models.WebhookEndpoint, int64, error) {
	var webhooks []*models.WebhookEndpoint
	var count int64
	q := r.db.WithContext(ctx).Where("tenant_id = ? AND deleted_at IS NULL", tenantID)
	if err := q.Count(&count).Error; err != nil {
		return nil, 0, err
	}
	if err := q.Order("created_at DESC").Limit(limit).Offset(offset).Find(&webhooks).Error; err != nil {
		return nil, 0, err
	}
	return webhooks, count, nil
}

func (r *webhookRepo) ListActive(ctx context.Context, tenantID uuid.UUID, event string) ([]*models.WebhookEndpoint, error) {
	var webhooks []*models.WebhookEndpoint
	// jsonb_build_array is SQL-injection safe for the event name
	err := r.db.WithContext(ctx).
		Where(
			"tenant_id = ? AND is_active = true AND deleted_at IS NULL AND events @> jsonb_build_array(?::text)",
			tenantID,
			fmt.Sprintf("%s", event),
		).
		Find(&webhooks).Error
	return webhooks, err
}

func (r *webhookRepo) CreateDelivery(ctx context.Context, d *models.WebhookDelivery) error {
	return r.db.WithContext(ctx).Create(d).Error
}

func (r *webhookRepo) ListDeliveries(ctx context.Context, tenantID, webhookID uuid.UUID, limit, offset int) ([]*models.WebhookDelivery, int64, error) {
	var deliveries []*models.WebhookDelivery
	var count int64
	q := r.db.WithContext(ctx).Where("tenant_id = ? AND webhook_id = ?", tenantID, webhookID)
	if err := q.Count(&count).Error; err != nil {
		return nil, 0, err
	}
	if err := q.Order("created_at DESC").Limit(limit).Offset(offset).Find(&deliveries).Error; err != nil {
		return nil, 0, err
	}
	return deliveries, count, nil
}
