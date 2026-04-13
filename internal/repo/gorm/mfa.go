package gorm

import (
	"context"
	"time"

	"shieldgate/internal/models"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// ── MFASecret repo ─────────────────────────────────────────────────────────────────

type mfaSecretRepo struct{ db *gorm.DB }

func NewMFASecretRepository(db *gorm.DB) *mfaSecretRepo { return &mfaSecretRepo{db: db} }

func (r *mfaSecretRepo) Create(ctx context.Context, s *models.MFASecret) error {
	return r.db.WithContext(ctx).Create(s).Error
}

func (r *mfaSecretRepo) GetByUserID(ctx context.Context, tenantID, userID uuid.UUID) (*models.MFASecret, error) {
	var s models.MFASecret
	err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND user_id = ?", tenantID, userID).
		First(&s).Error
	if err != nil {
		return nil, err
	}
	return &s, nil
}

func (r *mfaSecretRepo) Update(ctx context.Context, s *models.MFASecret) error {
	return r.db.WithContext(ctx).Save(s).Error
}

func (r *mfaSecretRepo) Delete(ctx context.Context, tenantID, userID uuid.UUID) error {
	return r.db.WithContext(ctx).
		Where("tenant_id = ? AND user_id = ?", tenantID, userID).
		Delete(&models.MFASecret{}).Error
}

// ── MFABackupCode repo ──────────────────────────────────────────────────────────

type mfaBackupCodeRepo struct{ db *gorm.DB }

func NewMFABackupCodeRepository(db *gorm.DB) *mfaBackupCodeRepo { return &mfaBackupCodeRepo{db: db} }

func (r *mfaBackupCodeRepo) CreateBatch(ctx context.Context, codes []*models.MFABackupCode) error {
	return r.db.WithContext(ctx).Create(&codes).Error
}

func (r *mfaBackupCodeRepo) GetByUserID(ctx context.Context, tenantID, userID uuid.UUID) ([]*models.MFABackupCode, error) {
	var codes []*models.MFABackupCode
	err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND user_id = ?", tenantID, userID).
		Order("created_at DESC").
		Find(&codes).Error
	return codes, err
}

func (r *mfaBackupCodeRepo) GetByCodeHash(ctx context.Context, tenantID, userID uuid.UUID, hash string) (*models.MFABackupCode, error) {
	var code models.MFABackupCode
	err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND user_id = ? AND code_hash = ?", tenantID, userID, hash).
		First(&code).Error
	if err != nil {
		return nil, err
	}
	return &code, nil
}

func (r *mfaBackupCodeRepo) MarkUsed(ctx context.Context, id uuid.UUID) error {
	now := time.Now()
	return r.db.WithContext(ctx).
		Model(&models.MFABackupCode{}).
		Where("id = ?", id).
		Update("used_at", now).Error
}

func (r *mfaBackupCodeRepo) DeleteByUserID(ctx context.Context, tenantID, userID uuid.UUID) error {
	return r.db.WithContext(ctx).
		Where("tenant_id = ? AND user_id = ?", tenantID, userID).
		Delete(&models.MFABackupCode{}).Error
}
