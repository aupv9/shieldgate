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

// PermissionServiceImpl implements the PermissionService interface
type PermissionServiceImpl struct {
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
	return &PermissionServiceImpl{
		permissionRepo:     permissionRepo,
		userRoleRepo:       userRoleRepo,
		rolePermissionRepo: rolePermissionRepo,
		logger:             logger,
	}
}

func (s *PermissionServiceImpl) Create(ctx context.Context, req *models.CreatePermissionRequest) (*models.Permission, error) {
	s.logger.WithFields(logrus.Fields{
		"name":     req.Name,
		"resource": req.Resource,
		"action":   req.Action,
	}).Info("creating new permission")

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
	}

	if err := s.permissionRepo.Create(ctx, permission); err != nil {
		return nil, fmt.Errorf("failed to create permission: %w", err)
	}

	return permission, nil
}

func (s *PermissionServiceImpl) GetByID(ctx context.Context, permissionID uuid.UUID) (*models.Permission, error) {
	permission, err := s.permissionRepo.GetByID(ctx, permissionID)
	if err != nil {
		return nil, err
	}
	return permission, nil
}

func (s *PermissionServiceImpl) GetByName(ctx context.Context, name string) (*models.Permission, error) {
	permission, err := s.permissionRepo.GetByName(ctx, name)
	if err != nil {
		return nil, err
	}
	return permission, nil
}

func (s *PermissionServiceImpl) Update(ctx context.Context, permissionID uuid.UUID, req *models.UpdatePermissionRequest) (*models.Permission, error) {
	permission, err := s.permissionRepo.GetByID(ctx, permissionID)
	if err != nil {
		return nil, err
	}

	if permission.IsSystem {
		return nil, fmt.Errorf("system permissions cannot be modified: %w", models.ErrBusinessRuleViolation)
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

func (s *PermissionServiceImpl) Delete(ctx context.Context, permissionID uuid.UUID) error {
	permission, err := s.permissionRepo.GetByID(ctx, permissionID)
	if err != nil {
		return err
	}

	if permission.IsSystem {
		return fmt.Errorf("system permissions cannot be deleted: %w", models.ErrBusinessRuleViolation)
	}

	return s.permissionRepo.Delete(ctx, permissionID)
}

func (s *PermissionServiceImpl) List(ctx context.Context, limit, offset int) (*models.PaginatedResponse, error) {
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

// HasPermission checks whether a user has the given resource+action permission
// by traversing their assigned roles → role permissions chain.
func (s *PermissionServiceImpl) HasPermission(ctx context.Context, tenantID, userID uuid.UUID, resource, action string) (bool, error) {
	userRoles, err := s.userRoleRepo.GetUserRoles(ctx, tenantID, userID)
	if err != nil {
		return false, fmt.Errorf("failed to get user roles: %w", err)
	}

	for _, ur := range userRoles {
		// Skip expired role assignments
		if ur.ExpiresAt != nil && time.Now().After(*ur.ExpiresAt) {
			continue
		}

		rolePerms, err := s.rolePermissionRepo.GetRolePermissions(ctx, ur.RoleID)
		if err != nil {
			s.logger.WithError(err).WithField("role_id", ur.RoleID).Warn("failed to get role permissions")
			continue
		}

		for _, rp := range rolePerms {
			if rp.Permission.Resource == resource && rp.Permission.Action == action {
				return true, nil
			}
			// "manage" action grants all actions on the resource
			if rp.Permission.Resource == resource && rp.Permission.Action == "manage" {
				return true, nil
			}
		}
	}

	return false, nil
}

// GetUserPermissions returns all permissions a user has across all their roles
func (s *PermissionServiceImpl) GetUserPermissions(ctx context.Context, tenantID, userID uuid.UUID) ([]*models.Permission, error) {
	userRoles, err := s.userRoleRepo.GetUserRoles(ctx, tenantID, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user roles: %w", err)
	}

	seen := make(map[uuid.UUID]struct{})
	var permissions []*models.Permission

	for _, ur := range userRoles {
		rolePerms, err := s.rolePermissionRepo.GetRolePermissions(ctx, ur.RoleID)
		if err != nil {
			s.logger.WithError(err).WithField("role_id", ur.RoleID).Warn("failed to get role permissions")
			continue
		}

		for _, rp := range rolePerms {
			if _, exists := seen[rp.PermissionID]; !exists {
				seen[rp.PermissionID] = struct{}{}
				p := rp.Permission
				permissions = append(permissions, &p)
			}
		}
	}

	return permissions, nil
}
