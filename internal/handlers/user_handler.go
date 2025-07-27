package handlers

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"shield1/internal/models"
	"shield1/internal/services"
)

// UserHandler handles user management endpoints
type UserHandler struct {
	userService *services.UserService
}

// NewUserHandler creates a new UserHandler instance
func NewUserHandler(userService *services.UserService) *UserHandler {
	return &UserHandler{
		userService: userService,
	}
}

// CreateUser handles POST /users
func (h *UserHandler) CreateUser(c *gin.Context) {
	var req models.CreateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "Invalid request body",
			"details":           err.Error(),
		})
		return
	}

	// Validate request
	if err := h.validateCreateUserRequest(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": err.Error(),
		})
		return
	}

	// Create user
	user, err := h.userService.CreateUser(&req)
	if err != nil {
		if err.Error() == "username already exists" || err.Error() == "email already exists" {
			c.JSON(http.StatusConflict, gin.H{
				"error":             "conflict",
				"error_description": err.Error(),
			})
			return
		}
		logrus.Errorf("Failed to create user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "Failed to create user",
		})
		return
	}

	// Don't expose password hash
	user.PasswordHash = ""
	c.JSON(http.StatusCreated, user)
}

// GetUser handles GET /users/:user_id
func (h *UserHandler) GetUser(c *gin.Context) {
	userIDStr := c.Param("user_id")
	if userIDStr == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "user_id is required",
		})
		return
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "Invalid user_id format",
		})
		return
	}

	user, err := h.userService.GetUser(userID)
	if err != nil {
		if err.Error() == "user not found" {
			c.JSON(http.StatusNotFound, gin.H{
				"error":             "not_found",
				"error_description": "User not found",
			})
			return
		}
		logrus.Errorf("Failed to get user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "Failed to get user",
		})
		return
	}

	// Don't expose password hash
	user.PasswordHash = ""
	c.JSON(http.StatusOK, user)
}

// UpdateUser handles PUT /users/:user_id
func (h *UserHandler) UpdateUser(c *gin.Context) {
	userIDStr := c.Param("user_id")
	if userIDStr == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "user_id is required",
		})
		return
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "Invalid user_id format",
		})
		return
	}

	var req models.UpdateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "Invalid request body",
			"details":           err.Error(),
		})
		return
	}

	// Validate request
	if err := h.validateUpdateUserRequest(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": err.Error(),
		})
		return
	}

	// Update user
	user, err := h.userService.UpdateUser(userID, &req)
	if err != nil {
		if err.Error() == "user not found" {
			c.JSON(http.StatusNotFound, gin.H{
				"error":             "not_found",
				"error_description": "User not found",
			})
			return
		}
		if err.Error() == "username already exists" || err.Error() == "email already exists" {
			c.JSON(http.StatusConflict, gin.H{
				"error":             "conflict",
				"error_description": err.Error(),
			})
			return
		}
		logrus.Errorf("Failed to update user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "Failed to update user",
		})
		return
	}

	// Don't expose password hash
	user.PasswordHash = ""
	c.JSON(http.StatusOK, user)
}

// DeleteUser handles DELETE /users/:user_id
func (h *UserHandler) DeleteUser(c *gin.Context) {
	userIDStr := c.Param("user_id")
	if userIDStr == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "user_id is required",
		})
		return
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "Invalid user_id format",
		})
		return
	}

	err = h.userService.DeleteUser(userID)
	if err != nil {
		if err.Error() == "user not found" {
			c.JSON(http.StatusNotFound, gin.H{
				"error":             "not_found",
				"error_description": "User not found",
			})
			return
		}
		logrus.Errorf("Failed to delete user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "Failed to delete user",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "User deleted successfully",
	})
}

// ListUsers handles GET /users
func (h *UserHandler) ListUsers(c *gin.Context) {
	// Parse pagination parameters
	limitStr := c.DefaultQuery("limit", "20")
	offsetStr := c.DefaultQuery("offset", "0")

	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit < 1 || limit > 100 {
		limit = 20
	}

	offset, err := strconv.Atoi(offsetStr)
	if err != nil || offset < 0 {
		offset = 0
	}

	// Get users
	users, total, err := h.userService.ListUsers(limit, offset)
	if err != nil {
		logrus.Errorf("Failed to list users: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "Failed to list users",
		})
		return
	}

	// Calculate pagination info
	totalPages := (total + limit - 1) / limit
	currentPage := (offset / limit) + 1

	response := gin.H{
		"users": users,
		"pagination": gin.H{
			"total":        total,
			"limit":        limit,
			"offset":       offset,
			"current_page": currentPage,
			"total_pages":  totalPages,
			"has_next":     offset+limit < total,
			"has_prev":     offset > 0,
		},
	}

	c.JSON(http.StatusOK, response)
}

// GetUserStats handles GET /users/stats
func (h *UserHandler) GetUserStats(c *gin.Context) {
	stats, err := h.userService.GetUserStats()
	if err != nil {
		logrus.Errorf("Failed to get user stats: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "Failed to get user statistics",
		})
		return
	}

	c.JSON(http.StatusOK, stats)
}

// AuthenticateUser handles POST /users/authenticate
func (h *UserHandler) AuthenticateUser(c *gin.Context) {
	var req struct {
		UsernameOrEmail string `json:"username_or_email" binding:"required"`
		Password        string `json:"password" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "Invalid request body",
			"details":           err.Error(),
		})
		return
	}

	user, err := h.userService.AuthenticateUser(req.UsernameOrEmail, req.Password)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "invalid_credentials",
			"error_description": "Invalid username/email or password",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"authenticated": true,
		"user":          user,
	})
}

// ChangePassword handles POST /users/:user_id/change-password
func (h *UserHandler) ChangePassword(c *gin.Context) {
	userIDStr := c.Param("user_id")
	if userIDStr == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "user_id is required",
		})
		return
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "Invalid user_id format",
		})
		return
	}

	var req struct {
		CurrentPassword string `json:"current_password" binding:"required"`
		NewPassword     string `json:"new_password" binding:"required,min=8"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "Invalid request body",
			"details":           err.Error(),
		})
		return
	}

	err = h.userService.ChangePassword(userID, req.CurrentPassword, req.NewPassword)
	if err != nil {
		if err.Error() == "user not found" {
			c.JSON(http.StatusNotFound, gin.H{
				"error":             "not_found",
				"error_description": "User not found",
			})
			return
		}
		if err.Error() == "invalid current password" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":             "invalid_request",
				"error_description": "Current password is incorrect",
			})
			return
		}
		logrus.Errorf("Failed to change password: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "Failed to change password",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Password changed successfully",
	})
}

// GetUserByUsername handles GET /users/by-username/:username
func (h *UserHandler) GetUserByUsername(c *gin.Context) {
	username := c.Param("username")
	if username == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "username is required",
		})
		return
	}

	user, err := h.userService.GetUserByUsername(username)
	if err != nil {
		if err.Error() == "user not found" {
			c.JSON(http.StatusNotFound, gin.H{
				"error":             "not_found",
				"error_description": "User not found",
			})
			return
		}
		logrus.Errorf("Failed to get user by username: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "Failed to get user",
		})
		return
	}

	// Don't expose password hash
	user.PasswordHash = ""
	c.JSON(http.StatusOK, user)
}

// GetUserByEmail handles GET /users/by-email/:email
func (h *UserHandler) GetUserByEmail(c *gin.Context) {
	email := c.Param("email")
	if email == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "email is required",
		})
		return
	}

	user, err := h.userService.GetUserByEmail(email)
	if err != nil {
		if err.Error() == "user not found" {
			c.JSON(http.StatusNotFound, gin.H{
				"error":             "not_found",
				"error_description": "User not found",
			})
			return
		}
		logrus.Errorf("Failed to get user by email: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "Failed to get user",
		})
		return
	}

	// Don't expose password hash
	user.PasswordHash = ""
	c.JSON(http.StatusOK, user)
}

// Helper methods

func (h *UserHandler) validateCreateUserRequest(req *models.CreateUserRequest) error {
	if req.Username == "" {
		return fmt.Errorf("username is required")
	}

	if len(req.Username) < 3 {
		return fmt.Errorf("username must be at least 3 characters long")
	}

	if req.Email == "" {
		return fmt.Errorf("email is required")
	}

	if req.Password == "" {
		return fmt.Errorf("password is required")
	}

	if len(req.Password) < 8 {
		return fmt.Errorf("password must be at least 8 characters long")
	}

	// Additional validation can be added here
	// - Email format validation
	// - Password complexity requirements
	// - Username format validation

	return nil
}

func (h *UserHandler) validateUpdateUserRequest(req *models.UpdateUserRequest) error {
	if req.Username != "" && len(req.Username) < 3 {
		return fmt.Errorf("username must be at least 3 characters long")
	}

	if req.Password != "" && len(req.Password) < 8 {
		return fmt.Errorf("password must be at least 8 characters long")
	}

	// Additional validation can be added here
	// - Email format validation
	// - Password complexity requirements
	// - Username format validation

	return nil
}
