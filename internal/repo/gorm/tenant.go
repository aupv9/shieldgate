package gorm

import (
	"context"
	"errors"
	"fmt"

	"shieldgate/internal/models"
	"shieldgate/internal/repo"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type tenantRepository struct {
	db *gorm.DB
}

// NewTenantRepository creates a new tenant repository
func NewTenantRepository(db *gorm.DB) repo.TenantRepository {
	return &tenantRepository{db: db}
}

func (r *tenantRepository) Create(ctx context.Context, tenant *models.Tenant) error {
	if err := r.db.WithContext(ctx).Create(tenant).Error; err != nil {
		return fmt.Errorf("failed to create tenant: %w", err)
	}
	return nil
}

func (r *tenantRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.Tenant, error) {
	var tenant models.Tenant
	if err := r.db.WithContext(ctx).Where("id = ?", id).First(&tenant).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, models.ErrTenantNotFound
		}
		return nil, fmt.Errorf("failed to get tenant by ID: %w", err)
	}
	return &tenant, nil
}

func (r *tenantRepository) GetByDomain(ctx context.Context, domain string) (*models.Tenant, error) {
	var tenant models.Tenant
	if err := r.db.WithContext(ctx).Where("domain = ?", domain).First(&tenant).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, models.ErrTenantNotFound
		}
		return nil, fmt.Errorf("failed to get tenant by domain: %w", err)
	}
	return &tenant, nil
}

func (r *tenantRepository) Update(ctx context.Context, tenant *models.Tenant) error {
	if err := r.db.WithContext(ctx).Save(tenant).Error; err != nil {
		return fmt.Errorf("failed to update tenant: %w", err)
	}
	return nil
}

func (r *tenantRepository) Delete(ctx context.Context, id uuid.UUID) error {
	if err := r.db.WithContext(ctx).Delete(&models.Tenant{}, "id = ?", id).Error; err != nil {
		return fmt.Errorf("failed to delete tenant: %w", err)
	}
	return nil
}

func (r *tenantRepository) List(ctx context.Context, limit, offset int) ([]*models.Tenant, int64, error) {
	var tenants []*models.Tenant
	var total int64

	// Get total count
	if err := r.db.WithContext(ctx).Model(&models.Tenant{}).Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("failed to count tenants: %w", err)
	}

	// Get paginated results
	if err := r.db.WithContext(ctx).
		Order("created_at DESC").
		Limit(limit).
		Offset(offset).
		Find(&tenants).Error; err != nil {
		return nil, 0, fmt.Errorf("failed to list tenants: %w", err)
	}

	return tenants, total, nil
}
