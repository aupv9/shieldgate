package services

import (
	"context"
	"fmt"

	"shieldgate/internal/models"
	"shieldgate/internal/repo"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
)

type userServiceImpl struct {
	repos  *repo.Repositories
	logger *logrus.Logger
}

// NewUserService creates a new user service implementation
func NewUserService(repos *repo.Repositories, logger *logrus.Logger) UserService {
	return &userServiceImpl{
		repos:  repos,
		logger: logger,
	}
}

func (s *userServiceImpl) Create(ctx context.Context, tenantID uuid.UUID, req *models.CreateUserRequest) (*models.User, error) {
	// Validate request
	if req.Username == "" {
		return nil, fmt.Errorf("username is required")
	}
	if req.Email == "" {
		return nil, fmt.Errorf("email is required")
	}
	if req.Password == "" {
		return nil, fmt.Errorf("password is required")
	}

	// Check if username already exists in tenant
	if _, err := s.repos.User.GetByUsername(ctx, tenantID, req.Username); err == nil {
		return nil, fmt.Errorf("username already exists")
	}

	// Check if email already exists in tenant
	if _, err := s.repos.User.GetByEmail(ctx, tenantID, req.Email); err == nil {
		return nil, fmt.Errorf("email already exists")
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Create user
	user := &models.User{
		ID:           uuid.New(),
		TenantID:     tenantID,
		Username:     req.Username,
		Email:        req.Email,
		PasswordHash: string(hashedPassword),
	}

	if err := s.repos.User.Create(ctx, user); err != nil {
		s.logger.WithError(err).Error("failed to create user")
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	s.logger.WithFields(logrus.Fields{
		"tenant_id": tenantID,
		"user_id":   user.ID,
		"username":  user.Username,
		"email":     user.Email,
	}).Info("user created successfully")

	return user, nil
}

func (s *userServiceImpl) GetByID(ctx context.Context, tenantID, userID uuid.UUID) (*models.User, error) {
	user, err := s.repos.User.GetByID(ctx, tenantID, userID)
	if err != nil {
		s.logger.WithError(err).WithFields(logrus.Fields{
			"tenant_id": tenantID,
			"user_id":   userID,
		}).Error("failed to get user by ID")
		return nil, err
	}
	return user, nil
}

func (s *userServiceImpl) GetByEmail(ctx context.Context, tenantID uuid.UUID, email string) (*models.User, error) {
	user, err := s.repos.User.GetByEmail(ctx, tenantID, email)
	if err != nil {
		s.logger.WithError(err).WithFields(logrus.Fields{
			"tenant_id": tenantID,
			"email":     email,
		}).Error("failed to get user by email")
		return nil, err
	}
	return user, nil
}

func (s *userServiceImpl) GetByUsername(ctx context.Context, tenantID uuid.UUID, username string) (*models.User, error) {
	user, err := s.repos.User.GetByUsername(ctx, tenantID, username)
	if err != nil {
		s.logger.WithError(err).WithFields(logrus.Fields{
			"tenant_id": tenantID,
			"username":  username,
		}).Error("failed to get user by username")
		return nil, err
	}
	return user, nil
}

func (s *userServiceImpl) Update(ctx context.Context, tenantID, userID uuid.UUID, req *models.UpdateUserRequest) (*models.User, error) {
	// Get existing user
	user, err := s.repos.User.GetByID(ctx, tenantID, userID)
	if err != nil {
		return nil, err
	}

	// Update fields
	if req.Username != "" && req.Username != user.Username {
		// Check if new username already exists
		if _, err := s.repos.User.GetByUsername(ctx, tenantID, req.Username); err == nil {
			return nil, fmt.Errorf("username already exists")
		}
		user.Username = req.Username
	}

	if req.Email != "" && req.Email != user.Email {
		// Check if new email already exists
		if _, err := s.repos.User.GetByEmail(ctx, tenantID, req.Email); err == nil {
			return nil, fmt.Errorf("email already exists")
		}
		user.Email = req.Email
	}

	if req.Password != "" {
		// Hash new password
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			return nil, fmt.Errorf("failed to hash password: %w", err)
		}
		user.PasswordHash = string(hashedPassword)
	}

	if err := s.repos.User.Update(ctx, user); err != nil {
		s.logger.WithError(err).WithFields(logrus.Fields{
			"tenant_id": tenantID,
			"user_id":   userID,
		}).Error("failed to update user")
		return nil, fmt.Errorf("failed to update user: %w", err)
	}

	s.logger.WithFields(logrus.Fields{
		"tenant_id": tenantID,
		"user_id":   user.ID,
		"username":  user.Username,
		"email":     user.Email,
	}).Info("user updated successfully")

	return user, nil
}

func (s *userServiceImpl) Delete(ctx context.Context, tenantID, userID uuid.UUID) error {
	// Check if user exists
	if _, err := s.repos.User.GetByID(ctx, tenantID, userID); err != nil {
		return err
	}

	if err := s.repos.User.Delete(ctx, tenantID, userID); err != nil {
		s.logger.WithError(err).WithFields(logrus.Fields{
			"tenant_id": tenantID,
			"user_id":   userID,
		}).Error("failed to delete user")
		return fmt.Errorf("failed to delete user: %w", err)
	}

	s.logger.WithFields(logrus.Fields{
		"tenant_id": tenantID,
		"user_id":   userID,
	}).Info("user deleted successfully")

	return nil
}

func (s *userServiceImpl) List(ctx context.Context, tenantID uuid.UUID, limit, offset int) (*models.PaginatedResponse, error) {
	// Validate pagination parameters
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	if offset < 0 {
		offset = 0
	}

	users, total, err := s.repos.User.List(ctx, tenantID, limit, offset)
	if err != nil {
		s.logger.WithError(err).WithField("tenant_id", tenantID).Error("failed to list users")
		return nil, fmt.Errorf("failed to list users: %w", err)
	}

	return models.NewPaginatedResponse(
		models.UsersToInterface(users),
		limit,
		offset,
		total,
	), nil
}

func (s *userServiceImpl) Authenticate(ctx context.Context, tenantID uuid.UUID, email, password string) (*models.User, error) {
	// Get user by email
	user, err := s.repos.User.GetByEmail(ctx, tenantID, email)
	if err != nil {
		s.logger.WithFields(logrus.Fields{
			"tenant_id": tenantID,
			"email":     email,
		}).Warn("authentication failed - user not found")
		return nil, models.ErrInvalidCredentials
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		s.logger.WithFields(logrus.Fields{
			"tenant_id": tenantID,
			"user_id":   user.ID,
			"email":     email,
		}).Warn("authentication failed - invalid password")
		return nil, models.ErrInvalidCredentials
	}

	s.logger.WithFields(logrus.Fields{
		"tenant_id": tenantID,
		"user_id":   user.ID,
		"email":     email,
	}).Info("user authenticated successfully")

	return user, nil
}

func (s *userServiceImpl) ChangePassword(ctx context.Context, tenantID, userID uuid.UUID, oldPassword, newPassword string) error {
	// Get user
	user, err := s.repos.User.GetByID(ctx, tenantID, userID)
	if err != nil {
		return err
	}

	// Verify old password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(oldPassword)); err != nil {
		return models.ErrInvalidCredentials
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// Update password
	user.PasswordHash = string(hashedPassword)
	if err := s.repos.User.Update(ctx, user); err != nil {
		s.logger.WithError(err).WithFields(logrus.Fields{
			"tenant_id": tenantID,
			"user_id":   userID,
		}).Error("failed to change password")
		return fmt.Errorf("failed to change password: %w", err)
	}

	s.logger.WithFields(logrus.Fields{
		"tenant_id": tenantID,
		"user_id":   userID,
	}).Info("password changed successfully")

	return nil
}
