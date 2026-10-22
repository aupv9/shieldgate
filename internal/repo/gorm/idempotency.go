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
	"gorm.io/gorm/clause"
)

type idempotencyRepository struct {
	db *gorm.DB
}

// NewIdempotencyRepository creates a new Idempotency-Key repository
func NewIdempotencyRepository(db *gorm.DB) repo.IdempotencyRepository {
	return &idempotencyRepository{db: db}
}

func (r *idempotencyRepository) Begin(ctx context.Context, record *models.IdempotencyKey, staleBefore time.Time) (bool, *models.IdempotencyKey, error) {
	now := time.Now()
	record.CreatedAt = now
	// Insert, or take over a dead record in the same statement so two
	// concurrent requests cannot both win
	result := r.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "tenant_id"}, {Name: "principal"}, {Name: "idem_key"}},
		DoUpdates: clause.AssignmentColumns([]string{
			"id", "method", "path", "request_hash", "status_code",
			"response_content_type", "response_body", "created_at", "expires_at",
		}),
		Where: clause.Where{Exprs: []clause.Expression{clause.Or(
			clause.Expr{SQL: "idempotency_keys.expires_at < ?", Vars: []interface{}{now}},
			clause.Expr{SQL: "idempotency_keys.status_code = 0 AND idempotency_keys.created_at < ?", Vars: []interface{}{staleBefore}},
		)}},
	}).Create(record)
	if result.Error != nil {
		return false, nil, fmt.Errorf("failed to store idempotency key: %w", result.Error)
	}
	if result.RowsAffected == 1 {
		return true, nil, nil
	}

	var existing models.IdempotencyKey
	if err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND principal = ? AND idem_key = ?", record.TenantID, record.Principal, record.Key).
		First(&existing).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// Released between the insert and this read; the caller retries
			return false, nil, models.ErrResourceConflict
		}
		return false, nil, fmt.Errorf("failed to get idempotency key: %w", err)
	}
	return false, &existing, nil
}

func (r *idempotencyRepository) Complete(ctx context.Context, id uuid.UUID, statusCode int, contentType string, body []byte) error {
	if err := r.db.WithContext(ctx).Model(&models.IdempotencyKey{}).
		Where("id = ?", id).
		Updates(map[string]interface{}{
			"status_code":           statusCode,
			"response_content_type": contentType,
			"response_body":         body,
		}).Error; err != nil {
		return fmt.Errorf("failed to complete idempotency key: %w", err)
	}
	return nil
}

func (r *idempotencyRepository) Delete(ctx context.Context, id uuid.UUID) error {
	if err := r.db.WithContext(ctx).Delete(&models.IdempotencyKey{}, "id = ?", id).Error; err != nil {
		return fmt.Errorf("failed to delete idempotency key: %w", err)
	}
	return nil
}

func (r *idempotencyRepository) DeleteExpired(ctx context.Context) error {
	if err := r.db.WithContext(ctx).
		Delete(&models.IdempotencyKey{}, "expires_at < ?", time.Now()).Error; err != nil {
		return fmt.Errorf("failed to delete expired idempotency keys: %w", err)
	}
	return nil
}
