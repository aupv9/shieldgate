package gorm

import (
	"context"

	"shieldgate/internal/models"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type socialAccountRepo struct{ db *gorm.DB }

// NewSocialAccountRepository creates a GORM-backed SocialAccountRepository.
func NewSocialAccountRepository(db *gorm.DB) *socialAccountRepo {
	return &socialAccountRepo{db: db}
}

func (r *socialAccountRepo) Create(ctx context.Context, account *models.SocialAccount) error {
	return r.db.WithContext(ctx).Create(account).Error
}

func (r *socialAccountRepo) GetByProviderAndExternalID(ctx context.Context, provider, externalID string) (*models.SocialAccount, error) {
	var a models.SocialAccount
	err := r.db.WithContext(ctx).
		Where("provider = ? AND external_id = ?", provider, externalID).
		First(&a).Error
	if err == gorm.ErrRecordNotFound {
		return nil, models.ErrSocialAccountNotFound
	}
	return &a, err
}

func (r *socialAccountRepo) GetByUserAndProvider(ctx context.Context, tenantID, userID uuid.UUID, provider string) (*models.SocialAccount, error) {
	var a models.SocialAccount
	err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND user_id = ? AND provider = ?", tenantID, userID, provider).
		First(&a).Error
	if err == gorm.ErrRecordNotFound {
		return nil, models.ErrSocialAccountNotFound
	}
	return &a, err
}

func (r *socialAccountRepo) ListByUser(ctx context.Context, tenantID, userID uuid.UUID) ([]*models.SocialAccount, error) {
	var accounts []*models.SocialAccount
	err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND user_id = ?", tenantID, userID).
		Find(&accounts).Error
	return accounts, err
}

func (r *socialAccountRepo) Update(ctx context.Context, account *models.SocialAccount) error {
	return r.db.WithContext(ctx).Save(account).Error
}

func (r *socialAccountRepo) Delete(ctx context.Context, tenantID, userID uuid.UUID, provider string) error {
	return r.db.WithContext(ctx).
		Where("tenant_id = ? AND user_id = ? AND provider = ?", tenantID, userID, provider).
		Delete(&models.SocialAccount{}).Error
}

// ─── SocialProvider repo ──────────────────────────────────────────────────────

type socialProviderRepo struct{ db *gorm.DB }

// NewSocialProviderRepository creates a GORM-backed SocialProviderRepository.
func NewSocialProviderRepository(db *gorm.DB) *socialProviderRepo {
	return &socialProviderRepo{db: db}
}

func (r *socialProviderRepo) Create(ctx context.Context, p *models.SocialProvider) error {
	return r.db.WithContext(ctx).Create(p).Error
}

func (r *socialProviderRepo) GetByTenantAndProvider(ctx context.Context, tenantID uuid.UUID, provider string) (*models.SocialProvider, error) {
	var p models.SocialProvider
	err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND provider = ? AND deleted_at IS NULL", tenantID, provider).
		First(&p).Error
	if err == gorm.ErrRecordNotFound {
		return nil, models.ErrSocialProviderNotConfigured
	}
	return &p, err
}

func (r *socialProviderRepo) List(ctx context.Context, tenantID uuid.UUID) ([]*models.SocialProvider, error) {
	var providers []*models.SocialProvider
	err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND deleted_at IS NULL", tenantID).
		Find(&providers).Error
	return providers, err
}

func (r *socialProviderRepo) Update(ctx context.Context, p *models.SocialProvider) error {
	return r.db.WithContext(ctx).Save(p).Error
}

func (r *socialProviderRepo) Delete(ctx context.Context, tenantID uuid.UUID, provider string) error {
	return r.db.WithContext(ctx).
		Where("tenant_id = ? AND provider = ?", tenantID, provider).
		Delete(&models.SocialProvider{}).Error
}
