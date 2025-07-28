package services

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"shieldgate/internal/models"
)

// UserService handles user management
type UserService struct {
	db *gorm.DB
}

// NewUserService creates a new UserService instance
func NewUserService(db *gorm.DB) *UserService {
	return &UserService{
		db: db,
	}
}

// CreateUser creates a new user
func (s *UserService) CreateUser(req *models.CreateUserRequest) (*models.User, error) {
	// Check if username already exists
	if exists, err := s.usernameExists(req.Username); err != nil {
		return nil, fmt.Errorf("failed to check username: %w", err)
	} else if exists {
		return nil, fmt.Errorf("username already exists")
	}

	// Check if email already exists
	if exists, err := s.emailExists(req.Email); err != nil {
		return nil, fmt.Errorf("failed to check email: %w", err)
	} else if exists {
		return nil, fmt.Errorf("email already exists")
	}

	// Hash password
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	user := &models.User{
		ID:           uuid.New(),
		Username:     req.Username,
		Email:        req.Email,
		PasswordHash: string(passwordHash),
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	// Store in database using GORM
	if err := s.db.Create(user).Error; err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	logrus.Infof("Created new user: %s (%s)", user.Username, user.Email)
	return user, nil
}

// GetUser retrieves a user by ID
func (s *UserService) GetUser(userID uuid.UUID) (*models.User, error) {
	var user models.User
	err := s.db.Where("id = ?", userID).First(&user).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return &user, nil
}

// GetUserByUsername retrieves a user by username
func (s *UserService) GetUserByUsername(username string) (*models.User, error) {
	var user models.User
	err := s.db.Where("username = ?", username).First(&user).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return &user, nil
}

// GetUserByEmail retrieves a user by email
func (s *UserService) GetUserByEmail(email string) (*models.User, error) {
	var user models.User
	err := s.db.Where("email = ?", email).First(&user).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return &user, nil
}

// UpdateUser updates an existing user
func (s *UserService) UpdateUser(userID uuid.UUID, req *models.UpdateUserRequest) (*models.User, error) {
	// Get existing user
	user, err := s.GetUser(userID)
	if err != nil {
		return nil, err
	}

	// Update fields if provided
	if req.Username != "" {
		// Check if new username already exists (excluding current user)
		if exists, err := s.usernameExistsExcluding(req.Username, userID); err != nil {
			return nil, fmt.Errorf("failed to check username: %w", err)
		} else if exists {
			return nil, fmt.Errorf("username already exists")
		}
		user.Username = req.Username
	}

	if req.Email != "" {
		// Check if new email already exists (excluding current user)
		if exists, err := s.emailExistsExcluding(req.Email, userID); err != nil {
			return nil, fmt.Errorf("failed to check email: %w", err)
		} else if exists {
			return nil, fmt.Errorf("email already exists")
		}
		user.Email = req.Email
	}

	if req.Password != "" {
		// Hash new password
		passwordHash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			return nil, fmt.Errorf("failed to hash password: %w", err)
		}
		user.PasswordHash = string(passwordHash)
	}

	user.UpdatedAt = time.Now()

	// Save changes using GORM
	if err := s.db.Save(user).Error; err != nil {
		return nil, fmt.Errorf("failed to update user: %w", err)
	}

	logrus.Infof("Updated user: %s (%s)", user.Username, user.Email)
	return user, nil
}

// DeleteUser deletes a user
func (s *UserService) DeleteUser(userID uuid.UUID) error {
	result := s.db.Where("id = ?", userID).Delete(&models.User{})
	if result.Error != nil {
		return fmt.Errorf("failed to delete user: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return fmt.Errorf("user not found")
	}

	logrus.Infof("Deleted user: %s", userID)
	return nil
}

// ListUsers retrieves all users with pagination
func (s *UserService) ListUsers(limit, offset int) ([]*models.User, int, error) {
	var total int64
	var users []*models.User

	// Get total count
	if err := s.db.Model(&models.User{}).Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("failed to get user count: %w", err)
	}

	// Get users with pagination
	err := s.db.Order("created_at DESC").Limit(limit).Offset(offset).Find(&users).Error
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list users: %w", err)
	}

	// Don't expose password hash
	for _, user := range users {
		user.PasswordHash = ""
	}

	return users, int(total), nil
}

// AuthenticateUser authenticates a user with username/email and password
func (s *UserService) AuthenticateUser(usernameOrEmail, password string) (*models.User, error) {
	var user models.User
	err := s.db.Where("username = ? OR email = ?", usernameOrEmail, usernameOrEmail).First(&user).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("invalid credentials")
		}
		return nil, fmt.Errorf("failed to authenticate user: %w", err)
	}

	// Verify password
	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
	if err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	// Clear password hash before returning
	user.PasswordHash = ""
	return &user, nil
}

// ChangePassword changes a user's password
func (s *UserService) ChangePassword(userID uuid.UUID, currentPassword, newPassword string) error {
	// Get user
	user, err := s.GetUser(userID)
	if err != nil {
		return err
	}

	// Verify current password
	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(currentPassword))
	if err != nil {
		return fmt.Errorf("invalid current password")
	}

	// Hash new password
	newPasswordHash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash new password: %w", err)
	}

	// Update password using GORM
	if err := s.db.Model(user).Updates(map[string]interface{}{
		"password_hash": string(newPasswordHash),
		"updated_at":    time.Now(),
	}).Error; err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	logrus.Infof("Password changed for user: %s", userID)
	return nil
}

// ValidateUser validates if a user exists and is active
func (s *UserService) ValidateUser(userID uuid.UUID) (*models.User, error) {
	user, err := s.GetUser(userID)
	if err != nil {
		return nil, err
	}

	// Additional validation logic can be added here
	// For example, checking if user is active, not suspended, etc.

	return user, nil
}

// GetUserStats returns user statistics
func (s *UserService) GetUserStats() (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	// Total users
	var totalUsers int64
	if err := s.db.Model(&models.User{}).Count(&totalUsers).Error; err != nil {
		return nil, fmt.Errorf("failed to get total users: %w", err)
	}
	stats["total_users"] = totalUsers

	// Users created today
	var usersToday int64
	today := time.Now().Truncate(24 * time.Hour)
	if err := s.db.Model(&models.User{}).Where("created_at >= ?", today).Count(&usersToday).Error; err != nil {
		return nil, fmt.Errorf("failed to get users created today: %w", err)
	}
	stats["users_created_today"] = usersToday

	// Users created this week
	var usersThisWeek int64
	weekStart := time.Now().AddDate(0, 0, -int(time.Now().Weekday()))
	weekStart = weekStart.Truncate(24 * time.Hour)
	if err := s.db.Model(&models.User{}).Where("created_at >= ?", weekStart).Count(&usersThisWeek).Error; err != nil {
		return nil, fmt.Errorf("failed to get users created this week: %w", err)
	}
	stats["users_created_this_week"] = usersThisWeek

	// Users created this month
	var usersThisMonth int64
	monthStart := time.Date(time.Now().Year(), time.Now().Month(), 1, 0, 0, 0, 0, time.Now().Location())
	if err := s.db.Model(&models.User{}).Where("created_at >= ?", monthStart).Count(&usersThisMonth).Error; err != nil {
		return nil, fmt.Errorf("failed to get users created this month: %w", err)
	}
	stats["users_created_this_month"] = usersThisMonth

	return stats, nil
}

// Helper methods

func (s *UserService) usernameExists(username string) (bool, error) {
	var count int64
	err := s.db.Model(&models.User{}).Where("username = ?", username).Count(&count).Error
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func (s *UserService) emailExists(email string) (bool, error) {
	var count int64
	err := s.db.Model(&models.User{}).Where("email = ?", email).Count(&count).Error
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func (s *UserService) usernameExistsExcluding(username string, excludeUserID uuid.UUID) (bool, error) {
	var count int64
	err := s.db.Model(&models.User{}).Where("username = ? AND id != ?", username, excludeUserID).Count(&count).Error
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func (s *UserService) emailExistsExcluding(email string, excludeUserID uuid.UUID) (bool, error) {
	var count int64
	err := s.db.Model(&models.User{}).Where("email = ? AND id != ?", email, excludeUserID).Count(&count).Error
	if err != nil {
		return false, err
	}
	return count > 0, nil
}
