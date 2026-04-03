package services

import (
	"context"
	"fmt"

	"shieldgate/internal/models"
	"shieldgate/internal/repo"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type tenantService struct {
	repos  *repo.Repositories
	logger *logrus.Logger
}

// NewTenantService creates a new tenant service
func NewTenantService(repos *repo.Repositories, logger *logrus.Logger) TenantService {
	return &tenantService{
		repos:  repos,
		logger: logger,
	}
}

func (s *tenantService) Create(ctx context.Context, req *models.CreateTenantRequest) (*models.Tenant, error) {
	// Validate request
	if req.Name == "" {
		return nil, fmt.Errorf("tenant name is required")
	}
	if req.Domain == "" {
		return nil, fmt.Errorf("tenant domain is required")
	}

	// Check if domain already exists
	if _, err := s.repos.Tenant.GetByDomain(ctx, req.Domain); err == nil {
		return nil, fmt.Errorf("tenant with domain %s already exists", req.Domain)
	}

	// Create tenant
	tenant := &models.Tenant{
		ID:       uuid.New(),
		Name:     req.Name,
		Domain:   req.Domain,
		IsActive: true,
	}

	if err := s.repos.Tenant.Create(ctx, tenant); err != nil {
		s.logger.WithError(err).Error("failed to create tenant")
		return nil, fmt.Errorf("failed to create tenant: %w", err)
	}

	s.logger.WithFields(logrus.Fields{
		"tenant_id": tenant.ID,
		"name":      tenant.Name,
		"domain":    tenant.Domain,
	}).Info("tenant created successfully")

	return tenant, nil
}

func (s *tenantService) GetByID(ctx context.Context, id uuid.UUID) (*models.Tenant, error) {
	tenant, err := s.repos.Tenant.GetByID(ctx, id)
	if err != nil {
		s.logger.WithError(err).WithField("tenant_id", id).Error("failed to get tenant by ID")
		return nil, err
	}
	return tenant, nil
}

func (s *tenantService) GetByDomain(ctx context.Context, domain string) (*models.Tenant, error) {
	tenant, err := s.repos.Tenant.GetByDomain(ctx, domain)
	if err != nil {
		s.logger.WithError(err).WithField("domain", domain).Error("failed to get tenant by domain")
		return nil, err
	}
	return tenant, nil
}

func (s *tenantService) Update(ctx context.Context, id uuid.UUID, req *models.UpdateTenantRequest) (*models.Tenant, error) {
	// Get existing tenant
	tenant, err := s.repos.Tenant.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	// Update fields
	if req.Name != "" {
		tenant.Name = req.Name
	}
	if req.Domain != "" {
		// Check if new domain already exists
		if existing, err := s.repos.Tenant.GetByDomain(ctx, req.Domain); err == nil && existing.ID != id {
			return nil, fmt.Errorf("tenant with domain %s already exists", req.Domain)
		}
		tenant.Domain = req.Domain
	}
	if req.IsActive != nil {
		tenant.IsActive = *req.IsActive
	}

	if err := s.repos.Tenant.Update(ctx, tenant); err != nil {
		s.logger.WithError(err).WithField("tenant_id", id).Error("failed to update tenant")
		return nil, fmt.Errorf("failed to update tenant: %w", err)
	}

	s.logger.WithFields(logrus.Fields{
		"tenant_id": tenant.ID,
		"name":      tenant.Name,
		"domain":    tenant.Domain,
	}).Info("tenant updated successfully")

	return tenant, nil
}

func (s *tenantService) Delete(ctx context.Context, id uuid.UUID) error {
	// Check if tenant exists
	if _, err := s.repos.Tenant.GetByID(ctx, id); err != nil {
		return err
	}

	if err := s.repos.Tenant.Delete(ctx, id); err != nil {
		s.logger.WithError(err).WithField("tenant_id", id).Error("failed to delete tenant")
		return fmt.Errorf("failed to delete tenant: %w", err)
	}

	s.logger.WithField("tenant_id", id).Info("tenant deleted successfully")
	return nil
}

func (s *tenantService) List(ctx context.Context, limit, offset int) (*models.PaginatedResponse, error) {
	// Validate pagination parameters
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	if offset < 0 {
		offset = 0
	}

	tenants, total, err := s.repos.Tenant.List(ctx, limit, offset)
	if err != nil {
		s.logger.WithError(err).Error("failed to list tenants")
		return nil, fmt.Errorf("failed to list tenants: %w", err)
	}

	return models.NewPaginatedResponse(
		models.TenantsToInterface(tenants),
		limit,
		offset,
		total,
	), nil
}
