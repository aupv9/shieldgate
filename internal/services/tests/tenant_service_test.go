package tests

import (
	"context"
	"testing"

	"shieldgate/internal/models"
	"shieldgate/internal/repo"
	"shieldgate/internal/services"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockTenantRepository is a mock implementation of TenantRepository
type MockTenantRepository struct {
	mock.Mock
}

func (m *MockTenantRepository) Create(ctx context.Context, tenant *models.Tenant) error {
	args := m.Called(ctx, tenant)
	return args.Error(0)
}

func (m *MockTenantRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.Tenant, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Tenant), args.Error(1)
}

func (m *MockTenantRepository) GetByDomain(ctx context.Context, domain string) (*models.Tenant, error) {
	args := m.Called(ctx, domain)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Tenant), args.Error(1)
}

func (m *MockTenantRepository) Update(ctx context.Context, tenant *models.Tenant) error {
	args := m.Called(ctx, tenant)
	return args.Error(0)
}

func (m *MockTenantRepository) Delete(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockTenantRepository) List(ctx context.Context, limit, offset int) ([]*models.Tenant, int64, error) {
	args := m.Called(ctx, limit, offset)
	return args.Get(0).([]*models.Tenant), args.Get(1).(int64), args.Error(2)
}

func TestTenantService_Create_ValidRequest_Success(t *testing.T) {
	// Arrange
	mockTenantRepo := &MockTenantRepository{}
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel) // Suppress logs during tests

	repos := &repo.Repositories{
		Tenant: mockTenantRepo,
	}

	service := services.NewTenantService(repos, logger)

	ctx := context.Background()
	req := &models.CreateTenantRequest{
		Name:   "Test Tenant",
		Domain: "test.example.com",
	}

	// Mock expectations
	mockTenantRepo.On("GetByDomain", ctx, req.Domain).Return((*models.Tenant)(nil), models.ErrTenantNotFound)
	mockTenantRepo.On("Create", ctx, mock.AnythingOfType("*models.Tenant")).Return(nil)

	// Act
	tenant, err := service.Create(ctx, req)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, tenant)
	assert.Equal(t, req.Name, tenant.Name)
	assert.Equal(t, req.Domain, tenant.Domain)
	assert.True(t, tenant.IsActive)
	assert.NotEqual(t, uuid.Nil, tenant.ID)

	mockTenantRepo.AssertExpectations(t)
}

func TestTenantService_Create_DuplicateDomain_ReturnsError(t *testing.T) {
	// Arrange
	mockTenantRepo := &MockTenantRepository{}
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)

	repos := &repo.Repositories{
		Tenant: mockTenantRepo,
	}

	service := services.NewTenantService(repos, logger)

	ctx := context.Background()
	req := &models.CreateTenantRequest{
		Name:   "Test Tenant",
		Domain: "test.example.com",
	}

	existingTenant := &models.Tenant{
		ID:     uuid.New(),
		Name:   "Existing Tenant",
		Domain: req.Domain,
	}

	// Mock expectations - domain already exists
	mockTenantRepo.On("GetByDomain", ctx, req.Domain).Return(existingTenant, nil)

	// Act
	tenant, err := service.Create(ctx, req)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, tenant)
	assert.Contains(t, err.Error(), "already exists")

	mockTenantRepo.AssertExpectations(t)
}

func TestTenantService_Create_EmptyName_ReturnsError(t *testing.T) {
	// Arrange
	mockTenantRepo := &MockTenantRepository{}
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)

	repos := &repo.Repositories{
		Tenant: mockTenantRepo,
	}

	service := services.NewTenantService(repos, logger)

	ctx := context.Background()
	req := &models.CreateTenantRequest{
		Name:   "", // Empty name
		Domain: "test.example.com",
	}

	// Act
	tenant, err := service.Create(ctx, req)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, tenant)
	assert.Contains(t, err.Error(), "name is required")

	// No repository calls should be made
	mockTenantRepo.AssertNotCalled(t, "GetByDomain")
	mockTenantRepo.AssertNotCalled(t, "Create")
}

func TestTenantService_GetByID_ExistingTenant_Success(t *testing.T) {
	// Arrange
	mockTenantRepo := &MockTenantRepository{}
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)

	repos := &repo.Repositories{
		Tenant: mockTenantRepo,
	}

	service := services.NewTenantService(repos, logger)

	ctx := context.Background()
	tenantID := uuid.New()
	expectedTenant := &models.Tenant{
		ID:     tenantID,
		Name:   "Test Tenant",
		Domain: "test.example.com",
	}

	// Mock expectations
	mockTenantRepo.On("GetByID", ctx, tenantID).Return(expectedTenant, nil)

	// Act
	tenant, err := service.GetByID(ctx, tenantID)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, tenant)
	assert.Equal(t, expectedTenant.ID, tenant.ID)
	assert.Equal(t, expectedTenant.Name, tenant.Name)
	assert.Equal(t, expectedTenant.Domain, tenant.Domain)

	mockTenantRepo.AssertExpectations(t)
}

func TestTenantService_GetByID_NonExistentTenant_ReturnsError(t *testing.T) {
	// Arrange
	mockTenantRepo := &MockTenantRepository{}
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)

	repos := &repo.Repositories{
		Tenant: mockTenantRepo,
	}

	service := services.NewTenantService(repos, logger)

	ctx := context.Background()
	tenantID := uuid.New()

	// Mock expectations
	mockTenantRepo.On("GetByID", ctx, tenantID).Return((*models.Tenant)(nil), models.ErrTenantNotFound)

	// Act
	tenant, err := service.GetByID(ctx, tenantID)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, tenant)
	assert.Equal(t, models.ErrTenantNotFound, err)

	mockTenantRepo.AssertExpectations(t)
}
