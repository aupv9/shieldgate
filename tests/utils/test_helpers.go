package utils

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"shield1/config"
	"shield1/internal/models"
)

// SetupTestDB creates a mock database for testing
// Note: This returns nil for now as we focus on unit testing business logic
func SetupTestDB(t *testing.T) *gorm.DB {
	// For now, return nil to focus on unit testing without database
	// In a real implementation, you would set up an in-memory database
	return nil
}

// CreateTestConfig returns a test configuration
func CreateTestConfig() *config.Config {
	return &config.Config{
		JWTSecret:                 "test-secret-key-for-testing-purposes",
		AccessTokenDuration:       time.Hour,
		RefreshTokenDuration:      24 * time.Hour,
		AuthorizationCodeDuration: 10 * time.Minute,
		BcryptCost:                4, // Lower cost for faster tests
		ServerURL:                 "http://localhost:8080",
	}
}

// CreateTestUser creates a test user
func CreateTestUser() *models.User {
	return &models.User{
		ID:           uuid.New(),
		Username:     "testuser",
		Email:        "test@example.com",
		PasswordHash: "$2a$04$test.hash.for.testing",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
}

// CreateTestUserWithPassword creates a test user with a specific password
func CreateTestUserWithPassword(password string) *models.User {
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return &models.User{
		ID:           uuid.New(),
		Username:     "testuser",
		Email:        "test@example.com",
		PasswordHash: string(hashedPassword),
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
}

// CreateTestClient creates a test OAuth client
func CreateTestClient() *models.Client {
	return &models.Client{
		ID:           uuid.New(),
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		Name:         "Test Client",
		RedirectURIs: models.StringArray{"http://localhost:3000/callback"},
		GrantTypes:   models.StringArray{"authorization_code", "refresh_token"},
		Scopes:       models.StringArray{"read", "write", "openid"},
		IsPublic:     false,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
}