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

type roleRepository struct {
	db *gorm.DB
}

// NewRoleRepository creates a new role repository
func NewRoleRepository(db *gorm.DB) repo.RoleRepository {
	return &roleRepository{db: db}
}

func (r *roleRepository) Create(ctx context.Context, role *models.Role) error {
	if err := r.db.WithContext(ctx).Omit(clause.Associations).Create(role).Error; err != nil {
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
		return nil, fmt.Errorf("failed to get role by ID: %w", err)
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
	if err := r.db.WithContext(ctx).Omit(clause.Associations).Save(role).Error; err != nil {
		return fmt.Errorf("failed to update role: %w", err)
	}
	return nil
}

func (r *roleRepository) Delete(ctx context.Context, tenantID, roleID uuid.UUID) error {
	if err := r.db.WithContext(ctx).
		Delete(&models.Role{}, "tenant_id = ? AND id = ?", tenantID, roleID).Error; err != nil {
		return fmt.Errorf("failed to delete role: %w", err)
	}
	return nil
}

func (r *roleRepository) List(ctx context.Context, tenantID uuid.UUID, limit, offset int) ([]*models.Role, int64, error) {
	var roles []*models.Role
	var total int64

	if err := r.db.WithContext(ctx).
		Model(&models.Role{}).
		Where("tenant_id = ?", tenantID).
		Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("failed to count roles: %w", err)
	}

	if err := r.db.WithContext(ctx).
		Where("tenant_id = ?", tenantID).
		Order("created_at DESC").
		Limit(limit).
		Offset(offset).
		Find(&roles).Error; err != nil {
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

type permissionRepository struct {
	db *gorm.DB
}

// NewPermissionRepository creates a new permission repository
func NewPermissionRepository(db *gorm.DB) repo.PermissionRepository {
	return &permissionRepository{db: db}
}

func (r *permissionRepository) Create(ctx context.Context, permission *models.Permission) error {
	if err := r.db.WithContext(ctx).Omit(clause.Associations).Create(permission).Error; err != nil {
		return fmt.Errorf("failed to create permission: %w", err)
	}
	return nil
}

func (r *permissionRepository) GetByID(ctx context.Context, permissionID uuid.UUID) (*models.Permission, error) {
	var permission models.Permission
	if err := r.db.WithContext(ctx).
		Where("id = ?", permissionID).
		First(&permission).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, models.ErrPermissionNotFound
		}
		return nil, fmt.Errorf("failed to get permission by ID: %w", err)
	}
	return &permission, nil
}

func (r *permissionRepository) GetByName(ctx context.Context, name string) (*models.Permission, error) {
	var permission models.Permission
	if err := r.db.WithContext(ctx).
		Where("name = ?", name).
		First(&permission).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, models.ErrPermissionNotFound
		}
		return nil, fmt.Errorf("failed to get permission by name: %w", err)
	}
	return &permission, nil
}

func (r *permissionRepository) Update(ctx context.Context, permission *models.Permission) error {
	if err := r.db.WithContext(ctx).Omit(clause.Associations).Save(permission).Error; err != nil {
		return fmt.Errorf("failed to update permission: %w", err)
	}
	return nil
}

func (r *permissionRepository) Delete(ctx context.Context, permissionID uuid.UUID) error {
	if err := r.db.WithContext(ctx).
		Delete(&models.Permission{}, "id = ?", permissionID).Error; err != nil {
		return fmt.Errorf("failed to delete permission: %w", err)
	}
	return nil
}

func (r *permissionRepository) List(ctx context.Context, limit, offset int) ([]*models.Permission, int64, error) {
	var permissions []*models.Permission
	var total int64

	if err := r.db.WithContext(ctx).
		Model(&models.Permission{}).
		Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("failed to count permissions: %w", err)
	}

	if err := r.db.WithContext(ctx).
		Order("resource ASC, action ASC").
		Limit(limit).
		Offset(offset).
		Find(&permissions).Error; err != nil {
		return nil, 0, fmt.Errorf("failed to list permissions: %w", err)
	}

	return permissions, total, nil
}

func (r *permissionRepository) GetByResource(ctx context.Context, resource string) ([]*models.Permission, error) {
	var permissions []*models.Permission
	if err := r.db.WithContext(ctx).
		Where("resource = ?", resource).
		Order("action ASC").
		Find(&permissions).Error; err != nil {
		return nil, fmt.Errorf("failed to get permissions by resource: %w", err)
	}
	return permissions, nil
}

type userRoleRepository struct {
	db *gorm.DB
}

// NewUserRoleRepository creates a new user-role repository
func NewUserRoleRepository(db *gorm.DB) repo.UserRoleRepository {
	return &userRoleRepository{db: db}
}

func (r *userRoleRepository) Create(ctx context.Context, userRole *models.UserRole) error {
	if err := r.db.WithContext(ctx).Omit(clause.Associations).Create(userRole).Error; err != nil {
		return fmt.Errorf("failed to create user role: %w", err)
	}
	return nil
}

// GetByID returns models.ErrRoleNotFound when the assignment does not exist,
// which is the sentinel RoleService checks for
func (r *userRoleRepository) GetByID(ctx context.Context, tenantID, userRoleID uuid.UUID) (*models.UserRole, error) {
	var userRole models.UserRole
	if err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND id = ?", tenantID, userRoleID).
		First(&userRole).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, models.ErrRoleNotFound
		}
		return nil, fmt.Errorf("failed to get user role by ID: %w", err)
	}
	return &userRole, nil
}

func (r *userRoleRepository) GetByUserAndRole(ctx context.Context, tenantID, userID, roleID uuid.UUID) (*models.UserRole, error) {
	var userRole models.UserRole
	if err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND user_id = ? AND role_id = ?", tenantID, userID, roleID).
		First(&userRole).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, models.ErrRoleNotFound
		}
		return nil, fmt.Errorf("failed to get user role: %w", err)
	}
	return &userRole, nil
}

func (r *userRoleRepository) Delete(ctx context.Context, tenantID, userID, roleID uuid.UUID) error {
	if err := r.db.WithContext(ctx).
		Delete(&models.UserRole{}, "tenant_id = ? AND user_id = ? AND role_id = ?", tenantID, userID, roleID).Error; err != nil {
		return fmt.Errorf("failed to delete user role: %w", err)
	}
	return nil
}

func (r *userRoleRepository) GetUserRoles(ctx context.Context, tenantID, userID uuid.UUID) ([]*models.UserRole, error) {
	var userRoles []*models.UserRole
	if err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND user_id = ?", tenantID, userID).
		Find(&userRoles).Error; err != nil {
		return nil, fmt.Errorf("failed to get user roles: %w", err)
	}
	return userRoles, nil
}

func (r *userRoleRepository) GetRoleUsers(ctx context.Context, tenantID, roleID uuid.UUID) ([]*models.UserRole, error) {
	var userRoles []*models.UserRole
	if err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND role_id = ?", tenantID, roleID).
		Find(&userRoles).Error; err != nil {
		return nil, fmt.Errorf("failed to get role users: %w", err)
	}
	return userRoles, nil
}

func (r *userRoleRepository) DeleteExpired(ctx context.Context) error {
	if err := r.db.WithContext(ctx).
		Delete(&models.UserRole{}, "expires_at IS NOT NULL AND expires_at < ?", time.Now()).Error; err != nil {
		return fmt.Errorf("failed to delete expired user roles: %w", err)
	}
	return nil
}

type rolePermissionRepository struct {
	db *gorm.DB
}

// NewRolePermissionRepository creates a new role-permission repository
func NewRolePermissionRepository(db *gorm.DB) repo.RolePermissionRepository {
	return &rolePermissionRepository{db: db}
}

func (r *rolePermissionRepository) Create(ctx context.Context, rolePermission *models.RolePermission) error {
	if err := r.db.WithContext(ctx).Omit(clause.Associations).Create(rolePermission).Error; err != nil {
		return fmt.Errorf("failed to create role permission: %w", err)
	}
	return nil
}

// GetByID returns models.ErrPermissionNotFound when the grant does not exist,
// which is the sentinel RoleService checks for
func (r *rolePermissionRepository) GetByID(ctx context.Context, rolePermissionID uuid.UUID) (*models.RolePermission, error) {
	var rolePermission models.RolePermission
	if err := r.db.WithContext(ctx).
		Where("id = ?", rolePermissionID).
		First(&rolePermission).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, models.ErrPermissionNotFound
		}
		return nil, fmt.Errorf("failed to get role permission by ID: %w", err)
	}
	return &rolePermission, nil
}

func (r *rolePermissionRepository) GetByRoleAndPermission(ctx context.Context, roleID, permissionID uuid.UUID) (*models.RolePermission, error) {
	var rolePermission models.RolePermission
	if err := r.db.WithContext(ctx).
		Where("role_id = ? AND permission_id = ?", roleID, permissionID).
		First(&rolePermission).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, models.ErrPermissionNotFound
		}
		return nil, fmt.Errorf("failed to get role permission: %w", err)
	}
	return &rolePermission, nil
}

func (r *rolePermissionRepository) Delete(ctx context.Context, roleID, permissionID uuid.UUID) error {
	if err := r.db.WithContext(ctx).
		Delete(&models.RolePermission{}, "role_id = ? AND permission_id = ?", roleID, permissionID).Error; err != nil {
		return fmt.Errorf("failed to delete role permission: %w", err)
	}
	return nil
}

func (r *rolePermissionRepository) GetRolePermissions(ctx context.Context, roleID uuid.UUID) ([]*models.RolePermission, error) {
	var rolePermissions []*models.RolePermission
	if err := r.db.WithContext(ctx).
		Where("role_id = ?", roleID).
		Find(&rolePermissions).Error; err != nil {
		return nil, fmt.Errorf("failed to get role permissions: %w", err)
	}
	return rolePermissions, nil
}

func (r *rolePermissionRepository) GetPermissionRoles(ctx context.Context, permissionID uuid.UUID) ([]*models.RolePermission, error) {
	var rolePermissions []*models.RolePermission
	if err := r.db.WithContext(ctx).
		Where("permission_id = ?", permissionID).
		Find(&rolePermissions).Error; err != nil {
		return nil, fmt.Errorf("failed to get permission roles: %w", err)
	}
	return rolePermissions, nil
}
