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

// PermissionActionManage grants every action on its resource
const PermissionActionManage = "manage"

// PermissionServiceImpl implements the PermissionService interface
type PermissionServiceImpl struct {
	permissionRepo     repo.PermissionRepository
	roleRepo           repo.RoleRepository
	userRoleRepo       repo.UserRoleRepository
	rolePermissionRepo repo.RolePermissionRepository
	logger             *logrus.Logger
}

// NewPermissionService creates a new permission service instance
func NewPermissionService(
	permissionRepo repo.PermissionRepository,
	roleRepo repo.RoleRepository,
	userRoleRepo repo.UserRoleRepository,
	rolePermissionRepo repo.RolePermissionRepository,
	logger *logrus.Logger,
) PermissionService {
	return &PermissionServiceImpl{
		permissionRepo:     permissionRepo,
		roleRepo:           roleRepo,
		userRoleRepo:       userRoleRepo,
		rolePermissionRepo: rolePermissionRepo,
		logger:             logger,
	}
}

// Create creates a new permission
func (s *PermissionServiceImpl) Create(ctx context.Context, req *models.CreatePermissionRequest) (*models.Permission, error) {
	s.logger.WithField("permission_name", req.Name).Info("creating new permission")

	existing, err := s.permissionRepo.GetByName(ctx, req.Name)
	if err != nil && err != models.ErrPermissionNotFound {
		return nil, fmt.Errorf("failed to check existing permission: %w", err)
	}
	if existing != nil {
		return nil, models.ErrDuplicateResource
	}

	permission := &models.Permission{
		ID:          uuid.New(),
		Name:        req.Name,
		DisplayName: req.DisplayName,
		Description: req.Description,
		Resource:    req.Resource,
		Action:      req.Action,
		IsSystem:    false,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	if err := s.permissionRepo.Create(ctx, permission); err != nil {
		s.logger.WithError(err).Error("failed to create permission")
		return nil, fmt.Errorf("failed to create permission: %w", err)
	}

	s.logger.WithFields(logrus.Fields{
		"permission_id":   permission.ID,
		"permission_name": permission.Name,
	}).Info("permission created successfully")

	return permission, nil
}

// GetByID retrieves a permission by ID
func (s *PermissionServiceImpl) GetByID(ctx context.Context, permissionID uuid.UUID) (*models.Permission, error) {
	permission, err := s.permissionRepo.GetByID(ctx, permissionID)
	if err != nil {
		if err == models.ErrPermissionNotFound {
			return nil, err
		}
		return nil, fmt.Errorf("failed to get permission: %w", err)
	}

	return permission, nil
}

// GetByName retrieves a permission by name
func (s *PermissionServiceImpl) GetByName(ctx context.Context, name string) (*models.Permission, error) {
	permission, err := s.permissionRepo.GetByName(ctx, name)
	if err != nil {
		if err == models.ErrPermissionNotFound {
			return nil, err
		}
		return nil, fmt.Errorf("failed to get permission: %w", err)
	}

	return permission, nil
}

// Update updates an existing permission
func (s *PermissionServiceImpl) Update(ctx context.Context, permissionID uuid.UUID, req *models.UpdatePermissionRequest) (*models.Permission, error) {
	s.logger.WithField("permission_id", permissionID).Info("updating permission")

	permission, err := s.permissionRepo.GetByID(ctx, permissionID)
	if err != nil {
		if err == models.ErrPermissionNotFound {
			return nil, err
		}
		return nil, fmt.Errorf("failed to get permission: %w", err)
	}

	if permission.IsSystem {
		return nil, models.ErrBusinessRuleViolation
	}

	if req.DisplayName != "" {
		permission.DisplayName = req.DisplayName
	}
	if req.Description != "" {
		permission.Description = req.Description
	}
	if req.Resource != "" {
		permission.Resource = req.Resource
	}
	if req.Action != "" {
		permission.Action = req.Action
	}
	permission.UpdatedAt = time.Now()

	if err := s.permissionRepo.Update(ctx, permission); err != nil {
		s.logger.WithError(err).Error("failed to update permission")
		return nil, fmt.Errorf("failed to update permission: %w", err)
	}

	s.logger.WithFields(logrus.Fields{
		"permission_id":   permissionID,
		"permission_name": permission.Name,
	}).Info("permission updated successfully")

	return permission, nil
}

// Delete deletes a permission and detaches it from every role
func (s *PermissionServiceImpl) Delete(ctx context.Context, permissionID uuid.UUID) error {
	s.logger.WithField("permission_id", permissionID).Info("deleting permission")

	permission, err := s.permissionRepo.GetByID(ctx, permissionID)
	if err != nil {
		if err == models.ErrPermissionNotFound {
			return err
		}
		return fmt.Errorf("failed to get permission: %w", err)
	}

	if permission.IsSystem {
		return models.ErrBusinessRuleViolation
	}

	rolePermissions, err := s.rolePermissionRepo.GetPermissionRoles(ctx, permissionID)
	if err != nil {
		return fmt.Errorf("failed to get permission roles: %w", err)
	}
	for _, rp := range rolePermissions {
		if err := s.rolePermissionRepo.Delete(ctx, rp.RoleID, permissionID); err != nil {
			return fmt.Errorf("failed to detach permission from role: %w", err)
		}
	}

	if err := s.permissionRepo.Delete(ctx, permissionID); err != nil {
		s.logger.WithError(err).Error("failed to delete permission")
		return fmt.Errorf("failed to delete permission: %w", err)
	}

	s.logger.WithFields(logrus.Fields{
		"permission_id":   permissionID,
		"permission_name": permission.Name,
	}).Info("permission deleted successfully")

	return nil
}

// List lists permissions with pagination
func (s *PermissionServiceImpl) List(ctx context.Context, limit, offset int) (*models.PaginatedResponse, error) {
	permissions, totalCount, err := s.permissionRepo.List(ctx, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to list permissions: %w", err)
	}

	items := make([]interface{}, len(permissions))
	for i, permission := range permissions {
		items[i] = permission
	}

	return models.NewPaginatedResponse(items, limit, offset, totalCount), nil
}

// HasPermission reports whether the user holds a permission on resource/action
// through any active, unexpired role; a "manage" permission covers every action
func (s *PermissionServiceImpl) HasPermission(ctx context.Context, tenantID, userID uuid.UUID, resource, action string) (bool, error) {
	permissions, err := s.GetUserPermissions(ctx, tenantID, userID)
	if err != nil {
		return false, err
	}

	for _, permission := range permissions {
		if permission.Resource == resource && (permission.Action == action || permission.Action == PermissionActionManage) {
			return true, nil
		}
	}

	return false, nil
}

// GetUserPermissions returns the de-duplicated permissions granted to a user
// through active, unexpired roles
func (s *PermissionServiceImpl) GetUserPermissions(ctx context.Context, tenantID, userID uuid.UUID) ([]*models.Permission, error) {
	userRoles, err := s.userRoleRepo.GetUserRoles(ctx, tenantID, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user roles: %w", err)
	}

	seen := make(map[uuid.UUID]struct{})
	permissions := make([]*models.Permission, 0)

	for _, ur := range userRoles {
		if ur.IsExpired() {
			continue
		}

		role, err := s.roleRepo.GetByID(ctx, tenantID, ur.RoleID)
		if err != nil {
			if err == models.ErrRoleNotFound {
				continue
			}
			return nil, fmt.Errorf("failed to get role: %w", err)
		}
		if !role.IsActive {
			continue
		}

		rolePermissions, err := s.rolePermissionRepo.GetRolePermissions(ctx, role.ID)
		if err != nil {
			return nil, fmt.Errorf("failed to get role permissions: %w", err)
		}

		for _, rp := range rolePermissions {
			if _, ok := seen[rp.PermissionID]; ok {
				continue
			}

			permission, err := s.permissionRepo.GetByID(ctx, rp.PermissionID)
			if err != nil {
				if err == models.ErrPermissionNotFound {
					continue
				}
				return nil, fmt.Errorf("failed to get permission: %w", err)
			}

			seen[rp.PermissionID] = struct{}{}
			permissions = append(permissions, permission)
		}
	}

	return permissions, nil
}
