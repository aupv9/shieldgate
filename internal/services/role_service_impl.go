package services

import (
	"context"
	"fmt"
	"time"

	"shieldgate/internal/models"
	"shieldgate/internal/repo"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// RoleServiceImpl implements the RoleService interface
type RoleServiceImpl struct {
	roleRepo           repo.RoleRepository
	permissionRepo     repo.PermissionRepository
	userRoleRepo       repo.UserRoleRepository
	rolePermissionRepo repo.RolePermissionRepository
	auditService       AuditService
	logger             *logrus.Logger
}

// NewRoleService creates a new role service instance
func NewRoleService(
	roleRepo repo.RoleRepository,
	permissionRepo repo.PermissionRepository,
	userRoleRepo repo.UserRoleRepository,
	rolePermissionRepo repo.RolePermissionRepository,
	auditService AuditService,
	logger *logrus.Logger,
) RoleService {
	return &RoleServiceImpl{
		roleRepo:           roleRepo,
		permissionRepo:     permissionRepo,
		userRoleRepo:       userRoleRepo,
		rolePermissionRepo: rolePermissionRepo,
		auditService:       auditService,
		logger:             logger,
	}
}

// Create creates a new role
func (s *RoleServiceImpl) Create(ctx context.Context, tenantID uuid.UUID, req *models.CreateRoleRequest) (*models.Role, error) {
	s.logger.WithFields(logrus.Fields{
		"tenant_id": tenantID,
		"role_name": req.Name,
	}).Info("creating new role")

	// Check if role with same name already exists
	existingRole, err := s.roleRepo.GetByName(ctx, tenantID, req.Name)
	if err != nil && err != models.ErrRoleNotFound {
		return nil, fmt.Errorf("failed to check existing role: %w", err)
	}
	if existingRole != nil {
		return nil, models.ErrDuplicateResource
	}

	// Create role
	role := &models.Role{
		ID:          uuid.New(),
		TenantID:    tenantID,
		Name:        req.Name,
		DisplayName: req.DisplayName,
		Description: req.Description,
		IsSystem:    false,
		IsActive:    true,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	if err := s.roleRepo.Create(ctx, role); err != nil {
		s.logger.WithError(err).Error("failed to create role")
		return nil, fmt.Errorf("failed to create role: %w", err)
	}

	// Add permissions if specified
	if len(req.Permissions) > 0 {
		for _, permissionName := range req.Permissions {
			permission, err := s.permissionRepo.GetByName(ctx, permissionName)
			if err != nil {
				s.logger.WithError(err).WithField("permission", permissionName).Warn("permission not found, skipping")
				continue
			}

			rolePermission := &models.RolePermission{
				ID:           uuid.New(),
				RoleID:       role.ID,
				PermissionID: permission.ID,
				GrantedBy:    tenantID, // System granted
				GrantedAt:    time.Now(),
			}

			if err := s.rolePermissionRepo.Create(ctx, rolePermission); err != nil {
				s.logger.WithError(err).WithField("permission", permissionName).Error("failed to assign permission to role")
			}
		}
	}

	// Audit log
	if s.auditService != nil {
		s.auditService.LogSystemAction(ctx, tenantID, models.AuditActionRoleCreated, "role", &role.ID, true, map[string]interface{}{
			"role_name":    role.Name,
			"display_name": role.DisplayName,
			"permissions":  req.Permissions,
		})
	}

	s.logger.WithFields(logrus.Fields{
		"tenant_id": tenantID,
		"role_id":   role.ID,
		"role_name": role.Name,
	}).Info("role created successfully")

	return role, nil
}

// GetByID retrieves a role by ID
func (s *RoleServiceImpl) GetByID(ctx context.Context, tenantID, roleID uuid.UUID) (*models.Role, error) {
	role, err := s.roleRepo.GetByID(ctx, tenantID, roleID)
	if err != nil {
		if err == models.ErrRoleNotFound {
			return nil, err
		}
		return nil, fmt.Errorf("failed to get role: %w", err)
	}

	return role, nil
}

// GetByName retrieves a role by name
func (s *RoleServiceImpl) GetByName(ctx context.Context, tenantID uuid.UUID, name string) (*models.Role, error) {
	role, err := s.roleRepo.GetByName(ctx, tenantID, name)
	if err != nil {
		if err == models.ErrRoleNotFound {
			return nil, err
		}
		return nil, fmt.Errorf("failed to get role: %w", err)
	}

	return role, nil
}

// Update updates an existing role
func (s *RoleServiceImpl) Update(ctx context.Context, tenantID, roleID uuid.UUID, req *models.UpdateRoleRequest) (*models.Role, error) {
	s.logger.WithFields(logrus.Fields{
		"tenant_id": tenantID,
		"role_id":   roleID,
	}).Info("updating role")

	// Get existing role
	role, err := s.roleRepo.GetByID(ctx, tenantID, roleID)
	if err != nil {
		return nil, fmt.Errorf("failed to get role: %w", err)
	}

	// Check if it's a system role
	if role.IsSystem {
		return nil, models.ErrBusinessRuleViolation
	}

	// Update fields
	if req.DisplayName != "" {
		role.DisplayName = req.DisplayName
	}
	if req.Description != "" {
		role.Description = req.Description
	}
	if req.IsActive != nil {
		role.IsActive = *req.IsActive
	}
	role.UpdatedAt = time.Now()

	if err := s.roleRepo.Update(ctx, role); err != nil {
		s.logger.WithError(err).Error("failed to update role")
		return nil, fmt.Errorf("failed to update role: %w", err)
	}

	// Update permissions if specified
	if req.Permissions != nil {
		// Remove existing permissions
		existingPermissions, err := s.rolePermissionRepo.GetRolePermissions(ctx, roleID)
		if err != nil {
			s.logger.WithError(err).Error("failed to get existing permissions")
		} else {
			for _, rp := range existingPermissions {
				if err := s.rolePermissionRepo.Delete(ctx, roleID, rp.PermissionID); err != nil {
					s.logger.WithError(err).Error("failed to remove existing permission")
				}
			}
		}

		// Add new permissions
		for _, permissionName := range req.Permissions {
			permission, err := s.permissionRepo.GetByName(ctx, permissionName)
			if err != nil {
				s.logger.WithError(err).WithField("permission", permissionName).Warn("permission not found, skipping")
				continue
			}

			rolePermission := &models.RolePermission{
				ID:           uuid.New(),
				RoleID:       roleID,
				PermissionID: permission.ID,
				GrantedBy:    tenantID, // System granted
				GrantedAt:    time.Now(),
			}

			if err := s.rolePermissionRepo.Create(ctx, rolePermission); err != nil {
				s.logger.WithError(err).WithField("permission", permissionName).Error("failed to assign permission to role")
			}
		}
	}

	// Audit log
	if s.auditService != nil {
		s.auditService.LogSystemAction(ctx, tenantID, models.AuditActionRoleUpdated, "role", &roleID, true, map[string]interface{}{
			"role_name":    role.Name,
			"display_name": role.DisplayName,
			"is_active":    role.IsActive,
		})
	}

	s.logger.WithFields(logrus.Fields{
		"tenant_id": tenantID,
		"role_id":   roleID,
		"role_name": role.Name,
	}).Info("role updated successfully")

	return role, nil
}

// Delete deletes a role
func (s *RoleServiceImpl) Delete(ctx context.Context, tenantID, roleID uuid.UUID) error {
	s.logger.WithFields(logrus.Fields{
		"tenant_id": tenantID,
		"role_id":   roleID,
	}).Info("deleting role")

	// Get role to check if it's a system role
	role, err := s.roleRepo.GetByID(ctx, tenantID, roleID)
	if err != nil {
		return fmt.Errorf("failed to get role: %w", err)
	}

	if role.IsSystem {
		return models.ErrBusinessRuleViolation
	}

	// Check if role is assigned to any users
	userRoles, err := s.userRoleRepo.GetRoleUsers(ctx, tenantID, roleID)
	if err != nil {
		return fmt.Errorf("failed to check role assignments: %w", err)
	}

	if len(userRoles) > 0 {
		return models.ErrBusinessRuleViolation
	}

	// Delete role permissions first
	rolePermissions, err := s.rolePermissionRepo.GetRolePermissions(ctx, roleID)
	if err != nil {
		s.logger.WithError(err).Error("failed to get role permissions")
	} else {
		for _, rp := range rolePermissions {
			if err := s.rolePermissionRepo.Delete(ctx, roleID, rp.PermissionID); err != nil {
				s.logger.WithError(err).Error("failed to delete role permission")
			}
		}
	}

	// Delete role
	if err := s.roleRepo.Delete(ctx, tenantID, roleID); err != nil {
		s.logger.WithError(err).Error("failed to delete role")
		return fmt.Errorf("failed to delete role: %w", err)
	}

	// Audit log
	if s.auditService != nil {
		s.auditService.LogSystemAction(ctx, tenantID, models.AuditActionRoleDeleted, "role", &roleID, true, map[string]interface{}{
			"role_name": role.Name,
		})
	}

	s.logger.WithFields(logrus.Fields{
		"tenant_id": tenantID,
		"role_id":   roleID,
		"role_name": role.Name,
	}).Info("role deleted successfully")

	return nil
}

// List lists roles with pagination
func (s *RoleServiceImpl) List(ctx context.Context, tenantID uuid.UUID, limit, offset int) (*models.PaginatedResponse, error) {
	roles, totalCount, err := s.roleRepo.List(ctx, tenantID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to list roles: %w", err)
	}

	items := make([]interface{}, len(roles))
	for i, role := range roles {
		items[i] = role
	}

	return models.NewPaginatedResponse(items, limit, offset, totalCount), nil
}

// AddPermission adds a permission to a role
func (s *RoleServiceImpl) AddPermission(ctx context.Context, tenantID, roleID, permissionID, grantedBy uuid.UUID) error {
	s.logger.WithFields(logrus.Fields{
		"tenant_id":     tenantID,
		"role_id":       roleID,
		"permission_id": permissionID,
		"granted_by":    grantedBy,
	}).Info("adding permission to role")

	// Check if role exists
	role, err := s.roleRepo.GetByID(ctx, tenantID, roleID)
	if err != nil {
		return fmt.Errorf("failed to get role: %w", err)
	}

	// Check if permission exists
	permission, err := s.permissionRepo.GetByID(ctx, permissionID)
	if err != nil {
		return fmt.Errorf("failed to get permission: %w", err)
	}

	// Check if permission is already assigned
	existing, err := s.rolePermissionRepo.GetByRoleAndPermission(ctx, roleID, permissionID)
	if err != nil && err != models.ErrPermissionNotFound {
		return fmt.Errorf("failed to check existing permission: %w", err)
	}
	if existing != nil {
		return models.ErrDuplicateResource
	}

	// Create role permission
	rolePermission := &models.RolePermission{
		ID:           uuid.New(),
		RoleID:       roleID,
		PermissionID: permissionID,
		GrantedBy:    grantedBy,
		GrantedAt:    time.Now(),
	}

	if err := s.rolePermissionRepo.Create(ctx, rolePermission); err != nil {
		s.logger.WithError(err).Error("failed to add permission to role")
		return fmt.Errorf("failed to add permission to role: %w", err)
	}

	// Audit log
	if s.auditService != nil {
		s.auditService.LogUserAction(ctx, tenantID, grantedBy, models.AuditActionPermissionGranted, "role", &roleID, true, map[string]interface{}{
			"role_name":       role.Name,
			"permission_name": permission.Name,
		})
	}

	s.logger.WithFields(logrus.Fields{
		"tenant_id":       tenantID,
		"role_id":         roleID,
		"permission_id":   permissionID,
		"role_name":       role.Name,
		"permission_name": permission.Name,
	}).Info("permission added to role successfully")

	return nil
}

// RemovePermission removes a permission from a role
func (s *RoleServiceImpl) RemovePermission(ctx context.Context, tenantID, roleID, permissionID uuid.UUID) error {
	s.logger.WithFields(logrus.Fields{
		"tenant_id":     tenantID,
		"role_id":       roleID,
		"permission_id": permissionID,
	}).Info("removing permission from role")

	// Check if role exists
	role, err := s.roleRepo.GetByID(ctx, tenantID, roleID)
	if err != nil {
		return fmt.Errorf("failed to get role: %w", err)
	}

	// Check if permission exists
	permission, err := s.permissionRepo.GetByID(ctx, permissionID)
	if err != nil {
		return fmt.Errorf("failed to get permission: %w", err)
	}

	// Delete role permission
	if err := s.rolePermissionRepo.Delete(ctx, roleID, permissionID); err != nil {
		s.logger.WithError(err).Error("failed to remove permission from role")
		return fmt.Errorf("failed to remove permission from role: %w", err)
	}

	// Audit log
	if s.auditService != nil {
		s.auditService.LogSystemAction(ctx, tenantID, models.AuditActionPermissionRevoked, "role", &roleID, true, map[string]interface{}{
			"role_name":       role.Name,
			"permission_name": permission.Name,
		})
	}

	s.logger.WithFields(logrus.Fields{
		"tenant_id":       tenantID,
		"role_id":         roleID,
		"permission_id":   permissionID,
		"role_name":       role.Name,
		"permission_name": permission.Name,
	}).Info("permission removed from role successfully")

	return nil
}

// GetPermissions gets all permissions for a role
func (s *RoleServiceImpl) GetPermissions(ctx context.Context, tenantID, roleID uuid.UUID) ([]*models.Permission, error) {
	// Check if role exists
	_, err := s.roleRepo.GetByID(ctx, tenantID, roleID)
	if err != nil {
		return nil, fmt.Errorf("failed to get role: %w", err)
	}

	// Get role permissions
	rolePermissions, err := s.rolePermissionRepo.GetRolePermissions(ctx, roleID)
	if err != nil {
		return nil, fmt.Errorf("failed to get role permissions: %w", err)
	}

	permissions := make([]*models.Permission, 0, len(rolePermissions))
	for _, rp := range rolePermissions {
		permission, err := s.permissionRepo.GetByID(ctx, rp.PermissionID)
		if err != nil {
			s.logger.WithError(err).WithField("permission_id", rp.PermissionID).Error("failed to get permission")
			continue
		}
		permissions = append(permissions, permission)
	}

	return permissions, nil
}

// AssignToUser assigns a role to a user
func (s *RoleServiceImpl) AssignToUser(ctx context.Context, tenantID, roleID, userID, grantedBy uuid.UUID, expiresAt *time.Time) error {
	s.logger.WithFields(logrus.Fields{
		"tenant_id":  tenantID,
		"role_id":    roleID,
		"user_id":    userID,
		"granted_by": grantedBy,
		"expires_at": expiresAt,
	}).Info("assigning role to user")

	// Check if role exists
	role, err := s.roleRepo.GetByID(ctx, tenantID, roleID)
	if err != nil {
		return fmt.Errorf("failed to get role: %w", err)
	}

	// Check if user role already exists
	existing, err := s.userRoleRepo.GetByUserAndRole(ctx, tenantID, userID, roleID)
	if err != nil && err != models.ErrRoleNotFound {
		return fmt.Errorf("failed to check existing user role: %w", err)
	}
	if existing != nil {
		return models.ErrDuplicateResource
	}

	// Create user role
	userRole := &models.UserRole{
		ID:        uuid.New(),
		TenantID:  tenantID,
		UserID:    userID,
		RoleID:    roleID,
		GrantedBy: grantedBy,
		GrantedAt: time.Now(),
		ExpiresAt: expiresAt,
	}

	if err := s.userRoleRepo.Create(ctx, userRole); err != nil {
		s.logger.WithError(err).Error("failed to assign role to user")
		return fmt.Errorf("failed to assign role to user: %w", err)
	}

	// Audit log
	if s.auditService != nil {
		s.auditService.LogUserAction(ctx, tenantID, grantedBy, models.AuditActionRoleAssigned, "user", &userID, true, map[string]interface{}{
			"role_name":  role.Name,
			"expires_at": expiresAt,
		})
	}

	s.logger.WithFields(logrus.Fields{
		"tenant_id": tenantID,
		"role_id":   roleID,
		"user_id":   userID,
		"role_name": role.Name,
	}).Info("role assigned to user successfully")

	return nil
}

// RevokeFromUser revokes a role from a user
func (s *RoleServiceImpl) RevokeFromUser(ctx context.Context, tenantID, roleID, userID uuid.UUID) error {
	s.logger.WithFields(logrus.Fields{
		"tenant_id": tenantID,
		"role_id":   roleID,
		"user_id":   userID,
	}).Info("revoking role from user")

	// Check if role exists
	role, err := s.roleRepo.GetByID(ctx, tenantID, roleID)
	if err != nil {
		return fmt.Errorf("failed to get role: %w", err)
	}

	// Delete user role
	if err := s.userRoleRepo.Delete(ctx, tenantID, userID, roleID); err != nil {
		s.logger.WithError(err).Error("failed to revoke role from user")
		return fmt.Errorf("failed to revoke role from user: %w", err)
	}

	// Audit log
	if s.auditService != nil {
		s.auditService.LogSystemAction(ctx, tenantID, models.AuditActionRoleRevoked, "user", &userID, true, map[string]interface{}{
			"role_name": role.Name,
		})
	}

	s.logger.WithFields(logrus.Fields{
		"tenant_id": tenantID,
		"role_id":   roleID,
		"user_id":   userID,
		"role_name": role.Name,
	}).Info("role revoked from user successfully")

	return nil
}

// GetUserRoles gets all roles for a user
func (s *RoleServiceImpl) GetUserRoles(ctx context.Context, tenantID, userID uuid.UUID) ([]*models.Role, error) {
	// Get user roles
	userRoles, err := s.userRoleRepo.GetUserRoles(ctx, tenantID, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user roles: %w", err)
	}

	roles := make([]*models.Role, 0, len(userRoles))
	for _, ur := range userRoles {
		// Skip expired roles
		if ur.IsExpired() {
			continue
		}

		role, err := s.roleRepo.GetByID(ctx, tenantID, ur.RoleID)
		if err != nil {
			s.logger.WithError(err).WithField("role_id", ur.RoleID).Error("failed to get role")
			continue
		}

		// Skip inactive roles
		if !role.IsActive {
			continue
		}

		roles = append(roles, role)
	}

	return roles, nil
}
