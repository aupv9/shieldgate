package services

import (
	"context"
	"fmt"

	"shieldgate/internal/models"
	"shieldgate/internal/repo"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type permissionServiceImpl struct {
	permissionRepo     repo.PermissionRepository
	userRoleRepo       repo.UserRoleRepository
	rolePermissionRepo repo.RolePermissionRepository
	logger             *logrus.Logger
}

// NewPermissionService creates a new permission service instance
func NewPermissionService(
	permissionRepo repo.PermissionRepository,
	userRoleRepo repo.UserRoleRepository,
	rolePermissionRepo repo.RolePermissionRepository,
	logger *logrus.Logger,
) PermissionService {
	return &permissionServiceImpl{
		permissionRepo:     permissionRepo,
		userRoleRepo:       userRoleRepo,
		rolePermissionRepo: rolePermissionRepo,
		logger:             logger,
	}
}

func (s *permissionServiceImpl) Create(ctx context.Context, req *models.CreatePermissionRequest) (*models.Permission, error) {
	// Check for duplicate
	if _, err := s.permissionRepo.GetByName(ctx, req.Name); err == nil {
		return nil, models.ErrDuplicateResource
	}

	permission := &models.Permission{
		ID:          uuid.New(),
		Name:        req.Name,
		DisplayName: req.DisplayName,
		Description: req.Description,
		Resource:    req.Resource,
		Action:      req.Action,
	}
	if err := s.permissionRepo.Create(ctx, permission); err != nil {
		return nil, fmt.Errorf("failed to create permission: %w", err)
	}
	return permission, nil
}

func (s *permissionServiceImpl) GetByID(ctx context.Context, permissionID uuid.UUID) (*models.Permission, error) {
	return s.permissionRepo.GetByID(ctx, permissionID)
}

func (s *permissionServiceImpl) GetByName(ctx context.Context, name string) (*models.Permission, error) {
	return s.permissionRepo.GetByName(ctx, name)
}

func (s *permissionServiceImpl) Update(ctx context.Context, permissionID uuid.UUID, req *models.UpdatePermissionRequest) (*models.Permission, error) {
	permission, err := s.permissionRepo.GetByID(ctx, permissionID)
	if err != nil {
		return nil, err
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
	if err := s.permissionRepo.Update(ctx, permission); err != nil {
		return nil, fmt.Errorf("failed to update permission: %w", err)
	}
	return permission, nil
}

func (s *permissionServiceImpl) Delete(ctx context.Context, permissionID uuid.UUID) error {
	return s.permissionRepo.Delete(ctx, permissionID)
}

func (s *permissionServiceImpl) List(ctx context.Context, limit, offset int) (*models.PaginatedResponse, error) {
	permissions, total, err := s.permissionRepo.List(ctx, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to list permissions: %w", err)
	}
	items := make([]interface{}, len(permissions))
	for i, p := range permissions {
		items[i] = p
	}
	return models.NewPaginatedResponse(items, limit, offset, total), nil
}

// HasPermission checks whether a user has the given resource+action permission via any of their active roles.
func (s *permissionServiceImpl) HasPermission(ctx context.Context, tenantID, userID uuid.UUID, resource, action string) (bool, error) {
	// uuid.Nil means a service-account (client-credentials) — grant access
	if userID == uuid.Nil {
		return true, nil
	}

	userRoles, err := s.userRoleRepo.GetUserRoles(ctx, tenantID, userID)
	if err != nil {
		return false, fmt.Errorf("failed to get user roles: %w", err)
	}

	for _, ur := range userRoles {
		if ur.IsExpired() {
			continue
		}

		rolePerms, err := s.rolePermissionRepo.GetRolePermissions(ctx, ur.RoleID)
		if err != nil {
			s.logger.WithError(err).WithField("role_id", ur.RoleID).Warn("failed to get role permissions")
			continue
		}

		for _, rp := range rolePerms {
			perm, err := s.permissionRepo.GetByID(ctx, rp.PermissionID)
			if err != nil {
				continue
			}
			if perm.Resource == resource && perm.Action == action {
				return true, nil
			}
		}
	}

	return false, nil
}

// GetUserPermissions returns all permissions for a user across all their active roles.
func (s *permissionServiceImpl) GetUserPermissions(ctx context.Context, tenantID, userID uuid.UUID) ([]*models.Permission, error) {
	userRoles, err := s.userRoleRepo.GetUserRoles(ctx, tenantID, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user roles: %w", err)
	}

	seen := make(map[uuid.UUID]bool)
	var permissions []*models.Permission

	for _, ur := range userRoles {
		if ur.IsExpired() {
			continue
		}

		rolePerms, err := s.rolePermissionRepo.GetRolePermissions(ctx, ur.RoleID)
		if err != nil {
			continue
		}

		for _, rp := range rolePerms {
			if seen[rp.PermissionID] {
				continue
			}
			perm, err := s.permissionRepo.GetByID(ctx, rp.PermissionID)
			if err != nil {
				continue
			}
			seen[rp.PermissionID] = true
			permissions = append(permissions, perm)
		}
	}

	return permissions, nil
}
