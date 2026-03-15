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

type rolePermissionRepository struct {
	db *gorm.DB
}

// NewRolePermissionRepository creates a new role-permission repository
func NewRolePermissionRepository(db *gorm.DB) repo.RolePermissionRepository {
	return &rolePermissionRepository{db: db}
}

func (r *rolePermissionRepository) Create(ctx context.Context, rolePermission *models.RolePermission) error {
	if err := r.db.WithContext(ctx).Create(rolePermission).Error; err != nil {
		return fmt.Errorf("failed to create role permission: %w", err)
	}
	return nil
}

func (r *rolePermissionRepository) GetByID(ctx context.Context, rolePermissionID uuid.UUID) (*models.RolePermission, error) {
	var rp models.RolePermission
	if err := r.db.WithContext(ctx).Where("id = ?", rolePermissionID).First(&rp).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, models.ErrPermissionNotFound
		}
		return nil, fmt.Errorf("failed to get role permission: %w", err)
	}
	return &rp, nil
}

func (r *rolePermissionRepository) GetByRoleAndPermission(ctx context.Context, roleID, permissionID uuid.UUID) (*models.RolePermission, error) {
	var rp models.RolePermission
	if err := r.db.WithContext(ctx).
		Where("role_id = ? AND permission_id = ?", roleID, permissionID).
		First(&rp).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, models.ErrPermissionNotFound
		}
		return nil, fmt.Errorf("failed to get role permission assignment: %w", err)
	}
	return &rp, nil
}

func (r *rolePermissionRepository) Delete(ctx context.Context, roleID, permissionID uuid.UUID) error {
	if err := r.db.WithContext(ctx).
		Where("role_id = ? AND permission_id = ?", roleID, permissionID).
		Delete(&models.RolePermission{}).Error; err != nil {
		return fmt.Errorf("failed to delete role permission: %w", err)
	}
	return nil
}

func (r *rolePermissionRepository) GetRolePermissions(ctx context.Context, roleID uuid.UUID) ([]*models.RolePermission, error) {
	var rps []*models.RolePermission
	if err := r.db.WithContext(ctx).
		Where("role_id = ?", roleID).
		Find(&rps).Error; err != nil {
		return nil, fmt.Errorf("failed to get role permissions: %w", err)
	}
	return rps, nil
}

func (r *rolePermissionRepository) GetPermissionRoles(ctx context.Context, permissionID uuid.UUID) ([]*models.RolePermission, error) {
	var rps []*models.RolePermission
	if err := r.db.WithContext(ctx).
		Where("permission_id = ?", permissionID).
		Find(&rps).Error; err != nil {
		return nil, fmt.Errorf("failed to get permission roles: %w", err)
	}
	return rps, nil
}
