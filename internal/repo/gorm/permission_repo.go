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

type permissionRepository struct {
	db *gorm.DB
}

// NewPermissionRepository creates a new permission repository
func NewPermissionRepository(db *gorm.DB) repo.PermissionRepository {
	return &permissionRepository{db: db}
}

func (r *permissionRepository) Create(ctx context.Context, permission *models.Permission) error {
	if err := r.db.WithContext(ctx).Create(permission).Error; err != nil {
		return fmt.Errorf("failed to create permission: %w", err)
	}
	return nil
}

func (r *permissionRepository) GetByID(ctx context.Context, permissionID uuid.UUID) (*models.Permission, error) {
	var permission models.Permission
	if err := r.db.WithContext(ctx).Where("id = ?", permissionID).First(&permission).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, models.ErrPermissionNotFound
		}
		return nil, fmt.Errorf("failed to get permission: %w", err)
	}
	return &permission, nil
}

func (r *permissionRepository) GetByName(ctx context.Context, name string) (*models.Permission, error) {
	var permission models.Permission
	if err := r.db.WithContext(ctx).Where("name = ?", name).First(&permission).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, models.ErrPermissionNotFound
		}
		return nil, fmt.Errorf("failed to get permission by name: %w", err)
	}
	return &permission, nil
}

func (r *permissionRepository) Update(ctx context.Context, permission *models.Permission) error {
	if err := r.db.WithContext(ctx).Save(permission).Error; err != nil {
		return fmt.Errorf("failed to update permission: %w", err)
	}
	return nil
}

func (r *permissionRepository) Delete(ctx context.Context, permissionID uuid.UUID) error {
	if err := r.db.WithContext(ctx).Where("id = ?", permissionID).Delete(&models.Permission{}).Error; err != nil {
		return fmt.Errorf("failed to delete permission: %w", err)
	}
	return nil
}

func (r *permissionRepository) List(ctx context.Context, limit, offset int) ([]*models.Permission, int64, error) {
	var permissions []*models.Permission
	var total int64

	query := r.db.WithContext(ctx).Model(&models.Permission{})
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("failed to count permissions: %w", err)
	}
	if err := query.Limit(limit).Offset(offset).Find(&permissions).Error; err != nil {
		return nil, 0, fmt.Errorf("failed to list permissions: %w", err)
	}
	return permissions, total, nil
}

func (r *permissionRepository) GetByResource(ctx context.Context, resource string) ([]*models.Permission, error) {
	var permissions []*models.Permission
	if err := r.db.WithContext(ctx).Where("resource = ?", resource).Find(&permissions).Error; err != nil {
		return nil, fmt.Errorf("failed to get permissions by resource: %w", err)
	}
	return permissions, nil
}
