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

type roleRepository struct {
	db *gorm.DB
}

// NewRoleRepository creates a new role repository
func NewRoleRepository(db *gorm.DB) repo.RoleRepository {
	return &roleRepository{db: db}
}

func (r *roleRepository) Create(ctx context.Context, role *models.Role) error {
	if err := r.db.WithContext(ctx).Create(role).Error; err != nil {
		return fmt.Errorf("failed to create role: %w", err)
	}
	return nil
}

func (r *roleRepository) GetByID(ctx context.Context, tenantID, roleID uuid.UUID) (*models.Role, error) {
	var role models.Role
	if err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND id = ?", tenantID, roleID).
		First(&role).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, models.ErrRoleNotFound
		}
		return nil, fmt.Errorf("failed to get role: %w", err)
	}
	return &role, nil
}

func (r *roleRepository) GetByName(ctx context.Context, tenantID uuid.UUID, name string) (*models.Role, error) {
	var role models.Role
	if err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND name = ?", tenantID, name).
		First(&role).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, models.ErrRoleNotFound
		}
		return nil, fmt.Errorf("failed to get role by name: %w", err)
	}
	return &role, nil
}

func (r *roleRepository) Update(ctx context.Context, role *models.Role) error {
	if err := r.db.WithContext(ctx).Save(role).Error; err != nil {
		return fmt.Errorf("failed to update role: %w", err)
	}
	return nil
}

func (r *roleRepository) Delete(ctx context.Context, tenantID, roleID uuid.UUID) error {
	if err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND id = ?", tenantID, roleID).
		Delete(&models.Role{}).Error; err != nil {
		return fmt.Errorf("failed to delete role: %w", err)
	}
	return nil
}

func (r *roleRepository) List(ctx context.Context, tenantID uuid.UUID, limit, offset int) ([]*models.Role, int64, error) {
	var roles []*models.Role
	var total int64

	query := r.db.WithContext(ctx).Model(&models.Role{}).Where("tenant_id = ?", tenantID)
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("failed to count roles: %w", err)
	}
	if err := query.Limit(limit).Offset(offset).Find(&roles).Error; err != nil {
		return nil, 0, fmt.Errorf("failed to list roles: %w", err)
	}
	return roles, total, nil
}

func (r *roleRepository) GetWithPermissions(ctx context.Context, tenantID, roleID uuid.UUID) (*models.Role, error) {
	var role models.Role
	if err := r.db.WithContext(ctx).
		Preload("Permissions.Permission").
		Where("tenant_id = ? AND id = ?", tenantID, roleID).
		First(&role).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, models.ErrRoleNotFound
		}
		return nil, fmt.Errorf("failed to get role with permissions: %w", err)
	}
	return &role, nil
}
