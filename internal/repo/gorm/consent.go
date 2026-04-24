package gorm

import (
	"context"
	"time"

	"shieldgate/internal/models"
	"shieldgate/internal/repo"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type consentRepository struct {
	db *gorm.DB
}

// NewConsentRepository creates a GORM-backed ConsentRepository.
func NewConsentRepository(db *gorm.DB) repo.ConsentRepository {
	return &consentRepository{db: db}
}

func (r *consentRepository) Upsert(ctx context.Context, consent *models.ConsentRecord) error {
	return r.db.WithContext(ctx).
		Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "tenant_id"}, {Name: "user_id"}, {Name: "client_id"}},
			DoUpdates: clause.AssignmentColumns([]string{"scopes", "expires_at", "updated_at"}),
		}).
		Create(consent).Error
}

func (r *consentRepository) GetByUserAndClient(ctx context.Context, tenantID, userID, clientID uuid.UUID) (*models.ConsentRecord, error) {
	var c models.ConsentRecord
	err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND user_id = ? AND client_id = ?", tenantID, userID, clientID).
		First(&c).Error
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func (r *consentRepository) ListByUser(ctx context.Context, tenantID, userID uuid.UUID) ([]*models.ConsentRecord, error) {
	var records []*models.ConsentRecord
	err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND user_id = ?", tenantID, userID).
		Order("updated_at DESC").
		Find(&records).Error
	return records, err
}

func (r *consentRepository) Delete(ctx context.Context, tenantID, userID, clientID uuid.UUID) error {
	return r.db.WithContext(ctx).
		Where("tenant_id = ? AND user_id = ? AND client_id = ?", tenantID, userID, clientID).
		Delete(&models.ConsentRecord{}).Error
}

func (r *consentRepository) DeleteExpired(ctx context.Context) error {
	return r.db.WithContext(ctx).
		Where("expires_at IS NOT NULL AND expires_at < ?", time.Now()).
		Delete(&models.ConsentRecord{}).Error
}
