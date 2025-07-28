package tests

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"shieldgate/internal/models"
	"shieldgate/internal/services"
	"shieldgate/tests/utils"
)

func TestUserService_CreateUser(t *testing.T) {
	db := utils.SetupTestDB(t)
	userService := services.NewUserService(db)

	tests := []struct {
		name        string
		request     *models.CreateUserRequest
		expectError bool
		errorMsg    string
	}{
		{
			name: "create valid user",
			request: &models.CreateUserRequest{
				Username: "testuser",
				Email:    "test@example.com",
				Password: "password123",
			},
			expectError: false,
		},
		{
			name: "create user with long password",
			request: &models.CreateUserRequest{
				Username: "testuser2",
				Email:    "test2@example.com",
				Password: "verylongpasswordwithspecialchars!@#$%^&*()",
			},
			expectError: false,
		},
		{
			name: "create user with minimum length username",
			request: &models.CreateUserRequest{
				Username: "abc",
				Email:    "abc@example.com",
				Password: "password123",
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user, err := userService.CreateUser(tt.request)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, user)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, user)
				assert.NotEmpty(t, user.ID)
				assert.Equal(t, tt.request.Username, user.Username)
				assert.Equal(t, tt.request.Email, user.Email)
				assert.NotEmpty(t, user.PasswordHash)
				assert.NotEqual(t, tt.request.Password, user.PasswordHash) // Should be hashed

				// Verify password hash is valid
				err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(tt.request.Password))
				assert.NoError(t, err)

				// Verify user is stored in database
				var dbUser models.User
				err = db.Where("id = ?", user.ID).First(&dbUser).Error
				assert.NoError(t, err)
				assert.Equal(t, user.Username, dbUser.Username)
			}
		})
	}
}

func TestUserService_CreateUser_DuplicateConstraints(t *testing.T) {
	db := utils.SetupTestDB(t)
	userService := services.NewUserService(db)

	// Create initial user
	initialUser := &models.CreateUserRequest{
		Username: "testuser",
		Email:    "test@example.com",
		Password: "password123",
	}
	_, err := userService.CreateUser(initialUser)
	require.NoError(t, err)

	tests := []struct {
		name        string
		request     *models.CreateUserRequest
		expectError bool
		errorMsg    string
	}{
		{
			name: "duplicate username",
			request: &models.CreateUserRequest{
				Username: "testuser", // Same username
				Email:    "different@example.com",
				Password: "password123",
			},
			expectError: true,
			errorMsg:    "username already exists",
		},
		{
			name: "duplicate email",
			request: &models.CreateUserRequest{
				Username: "differentuser",
				Email:    "test@example.com", // Same email
				Password: "password123",
			},
			expectError: true,
			errorMsg:    "email already exists",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user, err := userService.CreateUser(tt.request)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, user)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, user)
			}
		})
	}
}

func TestUserService_GetUser(t *testing.T) {
	db := utils.SetupTestDB(t)
	userService := services.NewUserService(db)

	// Create test user
	testUser := utils.CreateTestUser()
	require.NoError(t, db.Create(testUser).Error)

	tests := []struct {
		name        string
		userID      uuid.UUID
		expectError bool
		errorMsg    string
	}{
		{
			name:        "get existing user",
			userID:      testUser.ID,
			expectError: false,
		},
		{
			name:        "get non-existent user",
			userID:      uuid.New(),
			expectError: true,
			errorMsg:    "user not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user, err := userService.GetUser(tt.userID)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, user)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, user)
				assert.Equal(t, testUser.ID, user.ID)
				assert.Equal(t, testUser.Username, user.Username)
				assert.Equal(t, testUser.Email, user.Email)
			}
		})
	}
}

func TestUserService_GetUserByUsername(t *testing.T) {
	db := utils.SetupTestDB(t)
	userService := services.NewUserService(db)

	// Create test user
	testUser := utils.CreateTestUser()
	require.NoError(t, db.Create(testUser).Error)

	tests := []struct {
		name        string
		username    string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "get existing user by username",
			username:    testUser.Username,
			expectError: false,
		},
		{
			name:        "get non-existent user by username",
			username:    "nonexistentuser",
			expectError: true,
			errorMsg:    "user not found",
		},
		{
			name:        "get user with empty username",
			username:    "",
			expectError: true,
			errorMsg:    "user not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user, err := userService.GetUserByUsername(tt.username)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, user)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, user)
				assert.Equal(t, testUser.ID, user.ID)
				assert.Equal(t, testUser.Username, user.Username)
			}
		})
	}
}

func TestUserService_GetUserByEmail(t *testing.T) {
	db := utils.SetupTestDB(t)
	userService := services.NewUserService(db)

	// Create test user
	testUser := utils.CreateTestUser()
	require.NoError(t, db.Create(testUser).Error)

	tests := []struct {
		name        string
		email       string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "get existing user by email",
			email:       testUser.Email,
			expectError: false,
		},
		{
			name:        "get non-existent user by email",
			email:       "nonexistent@example.com",
			expectError: true,
			errorMsg:    "user not found",
		},
		{
			name:        "get user with empty email",
			email:       "",
			expectError: true,
			errorMsg:    "user not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user, err := userService.GetUserByEmail(tt.email)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, user)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, user)
				assert.Equal(t, testUser.ID, user.ID)
				assert.Equal(t, testUser.Email, user.Email)
			}
		})
	}
}

func TestUserService_UpdateUser(t *testing.T) {
	db := utils.SetupTestDB(t)
	userService := services.NewUserService(db)

	// Create test user
	testUser := utils.CreateTestUser()
	require.NoError(t, db.Create(testUser).Error)

	// Create another user for duplicate testing
	anotherUser := utils.CreateTestUser()
	anotherUser.Username = "anotheruser"
	anotherUser.Email = "another@example.com"
	require.NoError(t, db.Create(anotherUser).Error)

	tests := []struct {
		name        string
		userID      uuid.UUID
		request     *models.UpdateUserRequest
		expectError bool
		errorMsg    string
	}{
		{
			name:   "update username",
			userID: testUser.ID,
			request: &models.UpdateUserRequest{
				Username: "updateduser",
			},
			expectError: false,
		},
		{
			name:   "update email",
			userID: testUser.ID,
			request: &models.UpdateUserRequest{
				Email: "updated@example.com",
			},
			expectError: false,
		},
		{
			name:   "update password",
			userID: testUser.ID,
			request: &models.UpdateUserRequest{
				Password: "newpassword123",
			},
			expectError: false,
		},
		{
			name:   "update all fields",
			userID: testUser.ID,
			request: &models.UpdateUserRequest{
				Username: "completelyupdated",
				Email:    "completely@updated.com",
				Password: "newpassword456",
			},
			expectError: false,
		},
		{
			name:   "update with duplicate username",
			userID: testUser.ID,
			request: &models.UpdateUserRequest{
				Username: anotherUser.Username,
			},
			expectError: true,
			errorMsg:    "username already exists",
		},
		{
			name:   "update with duplicate email",
			userID: testUser.ID,
			request: &models.UpdateUserRequest{
				Email: anotherUser.Email,
			},
			expectError: true,
			errorMsg:    "email already exists",
		},
		{
			name:   "update non-existent user",
			userID: uuid.New(),
			request: &models.UpdateUserRequest{
				Username: "newusername",
			},
			expectError: true,
			errorMsg:    "user not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user, err := userService.UpdateUser(tt.userID, tt.request)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, user)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, user)

				if tt.request.Username != "" {
					assert.Equal(t, tt.request.Username, user.Username)
				}
				if tt.request.Email != "" {
					assert.Equal(t, tt.request.Email, user.Email)
				}
				if tt.request.Password != "" {
					// Verify password was hashed and updated
					err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(tt.request.Password))
					assert.NoError(t, err)
				}
			}
		})
	}
}

func TestUserService_DeleteUser(t *testing.T) {
	db := utils.SetupTestDB(t)
	userService := services.NewUserService(db)

	// Create test user
	testUser := utils.CreateTestUser()
	require.NoError(t, db.Create(testUser).Error)

	tests := []struct {
		name        string
		userID      uuid.UUID
		expectError bool
		errorMsg    string
	}{
		{
			name:        "delete existing user",
			userID:      testUser.ID,
			expectError: false,
		},
		{
			name:        "delete non-existent user",
			userID:      uuid.New(),
			expectError: true,
			errorMsg:    "user not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := userService.DeleteUser(tt.userID)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)

				// Verify user is deleted from database
				var dbUser models.User
				err = db.Where("id = ?", tt.userID).First(&dbUser).Error
				assert.Error(t, err) // Should not find the user
			}
		})
	}
}

func TestUserService_ListUsers(t *testing.T) {
	db := utils.SetupTestDB(t)
	userService := services.NewUserService(db)

	// Create multiple test users
	users := make([]*models.User, 5)
	for i := 0; i < 5; i++ {
		user := utils.CreateTestUser()
		user.Username = user.Username + string(rune('0'+i)) // Make unique
		user.Email = string(rune('a'+i)) + user.Email       // Make unique
		users[i] = user
		require.NoError(t, db.Create(user).Error)
	}

	tests := []struct {
		name          string
		limit         int
		offset        int
		expectedCount int
		expectedTotal int
	}{
		{
			name:          "list all users",
			limit:         10,
			offset:        0,
			expectedCount: 5,
			expectedTotal: 5,
		},
		{
			name:          "list with limit",
			limit:         3,
			offset:        0,
			expectedCount: 3,
			expectedTotal: 5,
		},
		{
			name:          "list with offset",
			limit:         10,
			offset:        2,
			expectedCount: 3,
			expectedTotal: 5,
		},
		{
			name:          "list with limit and offset",
			limit:         2,
			offset:        1,
			expectedCount: 2,
			expectedTotal: 5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userList, total, err := userService.ListUsers(tt.limit, tt.offset)

			assert.NoError(t, err)
			assert.Equal(t, tt.expectedCount, len(userList))
			assert.Equal(t, tt.expectedTotal, total)

			// Verify password hashes are not exposed
			for _, user := range userList {
				assert.Empty(t, user.PasswordHash)
			}
		})
	}
}

func TestUserService_AuthenticateUser(t *testing.T) {
	db := utils.SetupTestDB(t)
	userService := services.NewUserService(db)

	// Create test user with known password
	password := "testpassword123"
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	require.NoError(t, err)

	testUser := &models.User{
		ID:           uuid.New(),
		Username:     "testuser",
		Email:        "test@example.com",
		PasswordHash: string(hashedPassword),
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	require.NoError(t, db.Create(testUser).Error)

	tests := []struct {
		name            string
		usernameOrEmail string
		password        string
		expectError     bool
		errorMsg        string
	}{
		{
			name:            "authenticate with username",
			usernameOrEmail: testUser.Username,
			password:        password,
			expectError:     false,
		},
		{
			name:            "authenticate with email",
			usernameOrEmail: testUser.Email,
			password:        password,
			expectError:     false,
		},
		{
			name:            "authenticate with wrong password",
			usernameOrEmail: testUser.Username,
			password:        "wrongpassword",
			expectError:     true,
			errorMsg:        "invalid credentials",
		},
		{
			name:            "authenticate with non-existent username",
			usernameOrEmail: "nonexistentuser",
			password:        password,
			expectError:     true,
			errorMsg:        "invalid credentials",
		},
		{
			name:            "authenticate with non-existent email",
			usernameOrEmail: "nonexistent@example.com",
			password:        password,
			expectError:     true,
			errorMsg:        "invalid credentials",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user, err := userService.AuthenticateUser(tt.usernameOrEmail, tt.password)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, user)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, user)
				assert.Equal(t, testUser.ID, user.ID)
				assert.Equal(t, testUser.Username, user.Username)
				assert.Equal(t, testUser.Email, user.Email)
				assert.Empty(t, user.PasswordHash) // Should be cleared for security
			}
		})
	}
}

func TestUserService_ChangePassword(t *testing.T) {
	db := utils.SetupTestDB(t)
	userService := services.NewUserService(db)

	// Create test user with known password
	currentPassword := "currentpassword123"
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(currentPassword), bcrypt.DefaultCost)
	require.NoError(t, err)

	testUser := &models.User{
		ID:           uuid.New(),
		Username:     "testuser",
		Email:        "test@example.com",
		PasswordHash: string(hashedPassword),
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	require.NoError(t, db.Create(testUser).Error)

	tests := []struct {
		name            string
		userID          uuid.UUID
		currentPassword string
		newPassword     string
		expectError     bool
		errorMsg        string
	}{
		{
			name:            "change password successfully",
			userID:          testUser.ID,
			currentPassword: currentPassword,
			newPassword:     "newpassword456",
			expectError:     false,
		},
		{
			name:            "change password with wrong current password",
			userID:          testUser.ID,
			currentPassword: "wrongcurrentpassword",
			newPassword:     "newpassword789",
			expectError:     true,
			errorMsg:        "invalid current password",
		},
		{
			name:            "change password for non-existent user",
			userID:          uuid.New(),
			currentPassword: currentPassword,
			newPassword:     "newpassword123",
			expectError:     true,
			errorMsg:        "user not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := userService.ChangePassword(tt.userID, tt.currentPassword, tt.newPassword)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)

				// Verify password was changed in database
				var updatedUser models.User
				err = db.Where("id = ?", tt.userID).First(&updatedUser).Error
				require.NoError(t, err)

				// Verify new password works
				err = bcrypt.CompareHashAndPassword([]byte(updatedUser.PasswordHash), []byte(tt.newPassword))
				assert.NoError(t, err)

				// Verify old password no longer works
				err = bcrypt.CompareHashAndPassword([]byte(updatedUser.PasswordHash), []byte(currentPassword))
				assert.Error(t, err)
			}
		})
	}
}

func TestUserService_ValidateUser(t *testing.T) {
	db := utils.SetupTestDB(t)
	userService := services.NewUserService(db)

	// Create test user
	testUser := utils.CreateTestUser()
	require.NoError(t, db.Create(testUser).Error)

	tests := []struct {
		name        string
		userID      uuid.UUID
		expectError bool
		errorMsg    string
	}{
		{
			name:        "validate existing user",
			userID:      testUser.ID,
			expectError: false,
		},
		{
			name:        "validate non-existent user",
			userID:      uuid.New(),
			expectError: true,
			errorMsg:    "user not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user, err := userService.ValidateUser(tt.userID)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, user)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, user)
				assert.Equal(t, testUser.ID, user.ID)
			}
		})
	}
}

func TestUserService_GetUserStats(t *testing.T) {
	db := utils.SetupTestDB(t)
	userService := services.NewUserService(db)

	// Create test users with different creation times
	now := time.Now()

	// User created today
	userToday := utils.CreateTestUser()
	userToday.Username = "usertoday"
	userToday.Email = "today@example.com"
	userToday.CreatedAt = now
	require.NoError(t, db.Create(userToday).Error)

	// User created yesterday
	userYesterday := utils.CreateTestUser()
	userYesterday.Username = "useryesterday"
	userYesterday.Email = "yesterday@example.com"
	userYesterday.CreatedAt = now.AddDate(0, 0, -1)
	require.NoError(t, db.Create(userYesterday).Error)

	// User created last week
	userLastWeek := utils.CreateTestUser()
	userLastWeek.Username = "userlastweek"
	userLastWeek.Email = "lastweek@example.com"
	userLastWeek.CreatedAt = now.AddDate(0, 0, -8)
	require.NoError(t, db.Create(userLastWeek).Error)

	stats, err := userService.GetUserStats()
	require.NoError(t, err)
	require.NotNil(t, stats)

	// Verify stats structure
	assert.Contains(t, stats, "total_users")
	assert.Contains(t, stats, "users_created_today")
	assert.Contains(t, stats, "users_created_this_week")
	assert.Contains(t, stats, "users_created_this_month")

	// Verify total users count
	assert.Equal(t, int64(3), stats["total_users"])

	// Verify users created today (should be at least 1)
	assert.GreaterOrEqual(t, stats["users_created_today"].(int64), int64(1))

	// Verify users created this week (should be at least 2 - today and yesterday)
	assert.GreaterOrEqual(t, stats["users_created_this_week"].(int64), int64(2))

	// Verify users created this month (should be 3)
	assert.Equal(t, int64(3), stats["users_created_this_month"])
}
