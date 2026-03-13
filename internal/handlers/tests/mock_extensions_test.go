package tests

// mock_extensions_test.go completes mock implementations for the extended service
// interfaces. These were added when the service interfaces grew beyond what the
// original oauth_handler_test.go mocks covered.

import (
	"context"
	"time"

	"github.com/google/uuid"

	"shieldgate/internal/models"
)

// --- MockUserService extended methods ---

func (m *MockUserService) UpdateStatus(ctx context.Context, tenantID, userID uuid.UUID, status models.UserStatus) error {
	args := m.Called(ctx, tenantID, userID, status)
	return args.Error(0)
}

func (m *MockUserService) LockUser(ctx context.Context, tenantID, userID uuid.UUID, reason string, lockedUntil *time.Time) error {
	args := m.Called(ctx, tenantID, userID, reason, lockedUntil)
	return args.Error(0)
}

func (m *MockUserService) UnlockUser(ctx context.Context, tenantID, userID uuid.UUID) error {
	args := m.Called(ctx, tenantID, userID)
	return args.Error(0)
}

func (m *MockUserService) SuspendUser(ctx context.Context, tenantID, userID uuid.UUID, reason string) error {
	args := m.Called(ctx, tenantID, userID, reason)
	return args.Error(0)
}

func (m *MockUserService) ActivateUser(ctx context.Context, tenantID, userID uuid.UUID) error {
	args := m.Called(ctx, tenantID, userID)
	return args.Error(0)
}

func (m *MockUserService) SendVerificationEmail(ctx context.Context, tenantID, userID uuid.UUID) error {
	args := m.Called(ctx, tenantID, userID)
	return args.Error(0)
}

func (m *MockUserService) VerifyEmail(ctx context.Context, tenantID uuid.UUID, code string) (*models.User, error) {
	args := m.Called(ctx, tenantID, code)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserService) RequestPasswordReset(ctx context.Context, tenantID uuid.UUID, email string) error {
	args := m.Called(ctx, tenantID, email)
	return args.Error(0)
}

func (m *MockUserService) ResetPassword(ctx context.Context, tenantID uuid.UUID, token, newPassword string) (*models.User, error) {
	args := m.Called(ctx, tenantID, token, newPassword)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserService) RecordLoginAttempt(ctx context.Context, tenantID uuid.UUID, email, ipAddress string, success bool) error {
	args := m.Called(ctx, tenantID, email, ipAddress, success)
	return args.Error(0)
}

func (m *MockUserService) GetLoginHistory(ctx context.Context, tenantID, userID uuid.UUID, limit, offset int) (*models.PaginatedResponse, error) {
	args := m.Called(ctx, tenantID, userID, limit, offset)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.PaginatedResponse), args.Error(1)
}
