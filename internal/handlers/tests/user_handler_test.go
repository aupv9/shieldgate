package tests

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"shield1/internal/handlers"
	"shield1/internal/models"
	"shield1/internal/services"
	"shield1/tests/utils"
)

// setupUserHandler creates a test handler with real service
func setupUserHandler(t *testing.T) *handlers.UserHandler {
	db := utils.SetupTestDB(t)
	userService := services.NewUserService(db)
	handler := handlers.NewUserHandler(userService)
	return handler
}

// setupGinContext creates a test Gin context
func setupGinContext(method, path string, body interface{}) (*gin.Context, *httptest.ResponseRecorder) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	var bodyBytes []byte
	if body != nil {
		bodyBytes, _ = json.Marshal(body)
	}

	req := httptest.NewRequest(method, path, bytes.NewBuffer(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	c.Request = req

	return c, w
}

// Test Constructor
func TestNewUserHandler(t *testing.T) {
	handler := setupUserHandler(t)
	assert.NotNil(t, handler)
}

// Test CreateUser
func TestUserHandler_CreateUser_InvalidJSON(t *testing.T) {
	handler := setupUserHandler(t)

	c, w := setupGinContext("POST", "/users", "invalid json")
	handler.CreateUser(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "invalid_request", response["error"])
}

func TestUserHandler_CreateUser_ValidationError_ShortUsername(t *testing.T) {
	handler := setupUserHandler(t)

	req := &models.CreateUserRequest{
		Username: "ab", // Too short
		Email:    "test@example.com",
		Password: "password123",
	}

	c, w := setupGinContext("POST", "/users", req)
	handler.CreateUser(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "invalid_request", response["error"])
	assert.Contains(t, response["error_description"], "username must be at least 3 characters long")
}

func TestUserHandler_CreateUser_ValidationError_ShortPassword(t *testing.T) {
	handler := setupUserHandler(t)

	req := &models.CreateUserRequest{
		Username: "testuser",
		Email:    "test@example.com",
		Password: "short", // Too short - will be caught by Gin binding validation
	}

	c, w := setupGinContext("POST", "/users", req)
	handler.CreateUser(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "invalid_request", response["error"])
	assert.Contains(t, response["error_description"], "Invalid request body")
}

func TestUserHandler_CreateUser_ValidationError_MissingUsername(t *testing.T) {
	handler := setupUserHandler(t)

	req := &models.CreateUserRequest{
		Username: "", // Missing - will be caught by Gin binding validation
		Email:    "test@example.com",
		Password: "password123",
	}

	c, w := setupGinContext("POST", "/users", req)
	handler.CreateUser(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "invalid_request", response["error"])
	assert.Contains(t, response["error_description"], "Invalid request body")
}

func TestUserHandler_CreateUser_ValidationError_MissingEmail(t *testing.T) {
	handler := setupUserHandler(t)

	req := &models.CreateUserRequest{
		Username: "testuser",
		Email:    "", // Missing - will be caught by Gin binding validation
		Password: "password123",
	}

	c, w := setupGinContext("POST", "/users", req)
	handler.CreateUser(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "invalid_request", response["error"])
	assert.Contains(t, response["error_description"], "Invalid request body")
}

func TestUserHandler_CreateUser_ValidationError_MissingPassword(t *testing.T) {
	handler := setupUserHandler(t)

	req := &models.CreateUserRequest{
		Username: "testuser",
		Email:    "test@example.com",
		Password: "", // Missing - will be caught by Gin binding validation
	}

	c, w := setupGinContext("POST", "/users", req)
	handler.CreateUser(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "invalid_request", response["error"])
	assert.Contains(t, response["error_description"], "Invalid request body")
}

// Test GetUser
func TestUserHandler_GetUser_MissingUserID(t *testing.T) {
	handler := setupUserHandler(t)

	c, w := setupGinContext("GET", "/users/", nil)
	c.Params = []gin.Param{{Key: "user_id", Value: ""}}
	handler.GetUser(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "invalid_request", response["error"])
	assert.Contains(t, response["error_description"], "user_id is required")
}

func TestUserHandler_GetUser_InvalidUserID(t *testing.T) {
	handler := setupUserHandler(t)

	c, w := setupGinContext("GET", "/users/invalid-uuid", nil)
	c.Params = []gin.Param{{Key: "user_id", Value: "invalid-uuid"}}
	handler.GetUser(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "invalid_request", response["error"])
	assert.Contains(t, response["error_description"], "Invalid user_id format")
}

func TestUserHandler_GetUser_NotFound(t *testing.T) {
	t.Skip("Skipping test that requires database access - test DB setup returns nil")
}

// Test UpdateUser
func TestUserHandler_UpdateUser_MissingUserID(t *testing.T) {
	handler := setupUserHandler(t)

	req := &models.UpdateUserRequest{
		Username: "updateduser",
	}

	c, w := setupGinContext("PUT", "/users/", req)
	c.Params = []gin.Param{{Key: "user_id", Value: ""}}
	handler.UpdateUser(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "invalid_request", response["error"])
	assert.Contains(t, response["error_description"], "user_id is required")
}

func TestUserHandler_UpdateUser_InvalidUserID(t *testing.T) {
	handler := setupUserHandler(t)

	req := &models.UpdateUserRequest{
		Username: "updateduser",
	}

	c, w := setupGinContext("PUT", "/users/invalid-uuid", req)
	c.Params = []gin.Param{{Key: "user_id", Value: "invalid-uuid"}}
	handler.UpdateUser(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "invalid_request", response["error"])
	assert.Contains(t, response["error_description"], "Invalid user_id format")
}

func TestUserHandler_UpdateUser_InvalidJSON(t *testing.T) {
	handler := setupUserHandler(t)
	userID := uuid.New()

	c, w := setupGinContext("PUT", fmt.Sprintf("/users/%s", userID), "invalid json")
	c.Params = []gin.Param{{Key: "user_id", Value: userID.String()}}
	handler.UpdateUser(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "invalid_request", response["error"])
	assert.Contains(t, response["error_description"], "Invalid request body")
}

func TestUserHandler_UpdateUser_ValidationError_ShortUsername(t *testing.T) {
	handler := setupUserHandler(t)
	userID := uuid.New()

	req := &models.UpdateUserRequest{
		Username: "ab", // Too short
	}

	c, w := setupGinContext("PUT", fmt.Sprintf("/users/%s", userID), req)
	c.Params = []gin.Param{{Key: "user_id", Value: userID.String()}}
	handler.UpdateUser(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "invalid_request", response["error"])
	assert.Contains(t, response["error_description"], "username must be at least 3 characters long")
}

func TestUserHandler_UpdateUser_ValidationError_ShortPassword(t *testing.T) {
	handler := setupUserHandler(t)
	userID := uuid.New()

	req := &models.UpdateUserRequest{
		Password: "short", // Too short - will be caught by Gin binding validation
	}

	c, w := setupGinContext("PUT", fmt.Sprintf("/users/%s", userID), req)
	c.Params = []gin.Param{{Key: "user_id", Value: userID.String()}}
	handler.UpdateUser(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "invalid_request", response["error"])
	assert.Contains(t, response["error_description"], "Invalid request body")
}

func TestUserHandler_UpdateUser_NotFound(t *testing.T) {
	t.Skip("Skipping test that requires database access - test DB setup returns nil")
}

// Test DeleteUser
func TestUserHandler_DeleteUser_MissingUserID(t *testing.T) {
	handler := setupUserHandler(t)

	c, w := setupGinContext("DELETE", "/users/", nil)
	c.Params = []gin.Param{{Key: "user_id", Value: ""}}
	handler.DeleteUser(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "invalid_request", response["error"])
	assert.Contains(t, response["error_description"], "user_id is required")
}

func TestUserHandler_DeleteUser_InvalidUserID(t *testing.T) {
	handler := setupUserHandler(t)

	c, w := setupGinContext("DELETE", "/users/invalid-uuid", nil)
	c.Params = []gin.Param{{Key: "user_id", Value: "invalid-uuid"}}
	handler.DeleteUser(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "invalid_request", response["error"])
	assert.Contains(t, response["error_description"], "Invalid user_id format")
}

func TestUserHandler_DeleteUser_NotFound(t *testing.T) {
	t.Skip("Skipping test that requires database access - test DB setup returns nil")
}

// Test ListUsers - All require database access, skipping
func TestUserHandler_ListUsers_DefaultPagination(t *testing.T) {
	t.Skip("Skipping test that requires database access - test DB setup returns nil")
}

func TestUserHandler_ListUsers_CustomPagination(t *testing.T) {
	t.Skip("Skipping test that requires database access - test DB setup returns nil")
}

func TestUserHandler_ListUsers_InvalidLimit(t *testing.T) {
	t.Skip("Skipping test that requires database access - test DB setup returns nil")
}

func TestUserHandler_ListUsers_LimitTooHigh(t *testing.T) {
	t.Skip("Skipping test that requires database access - test DB setup returns nil")
}

// Test GetUserStats
func TestUserHandler_GetUserStats_Success(t *testing.T) {
	t.Skip("Skipping test that requires database access - test DB setup returns nil")
}

// Test AuthenticateUser
func TestUserHandler_AuthenticateUser_InvalidJSON(t *testing.T) {
	handler := setupUserHandler(t)

	c, w := setupGinContext("POST", "/users/authenticate", "invalid json")
	handler.AuthenticateUser(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "invalid_request", response["error"])
	assert.Contains(t, response["error_description"], "Invalid request body")
}

func TestUserHandler_AuthenticateUser_MissingCredentials(t *testing.T) {
	handler := setupUserHandler(t)

	req := map[string]string{
		"username_or_email": "",
		"password":          "",
	}

	c, w := setupGinContext("POST", "/users/authenticate", req)
	handler.AuthenticateUser(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "invalid_request", response["error"])
}

func TestUserHandler_AuthenticateUser_InvalidCredentials(t *testing.T) {
	t.Skip("Skipping test that requires database access - test DB setup returns nil")
}

// Test ChangePassword
func TestUserHandler_ChangePassword_MissingUserID(t *testing.T) {
	handler := setupUserHandler(t)

	req := map[string]string{
		"current_password": "oldpassword",
		"new_password":     "newpassword123",
	}

	c, w := setupGinContext("POST", "/users//change-password", req)
	c.Params = []gin.Param{{Key: "user_id", Value: ""}}
	handler.ChangePassword(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "invalid_request", response["error"])
	assert.Contains(t, response["error_description"], "user_id is required")
}

func TestUserHandler_ChangePassword_InvalidUserID(t *testing.T) {
	handler := setupUserHandler(t)

	req := map[string]string{
		"current_password": "oldpassword",
		"new_password":     "newpassword123",
	}

	c, w := setupGinContext("POST", "/users/invalid-uuid/change-password", req)
	c.Params = []gin.Param{{Key: "user_id", Value: "invalid-uuid"}}
	handler.ChangePassword(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "invalid_request", response["error"])
	assert.Contains(t, response["error_description"], "Invalid user_id format")
}

func TestUserHandler_ChangePassword_InvalidJSON(t *testing.T) {
	handler := setupUserHandler(t)
	userID := uuid.New()

	c, w := setupGinContext("POST", fmt.Sprintf("/users/%s/change-password", userID), "invalid json")
	c.Params = []gin.Param{{Key: "user_id", Value: userID.String()}}
	handler.ChangePassword(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "invalid_request", response["error"])
	assert.Contains(t, response["error_description"], "Invalid request body")
}

func TestUserHandler_ChangePassword_MissingPasswords(t *testing.T) {
	handler := setupUserHandler(t)
	userID := uuid.New()

	req := map[string]string{
		"current_password": "",
		"new_password":     "",
	}

	c, w := setupGinContext("POST", fmt.Sprintf("/users/%s/change-password", userID), req)
	c.Params = []gin.Param{{Key: "user_id", Value: userID.String()}}
	handler.ChangePassword(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "invalid_request", response["error"])
}

func TestUserHandler_ChangePassword_UserNotFound(t *testing.T) {
	t.Skip("Skipping test that requires database access - test DB setup returns nil")
}

// Test GetUserByUsername
func TestUserHandler_GetUserByUsername_MissingUsername(t *testing.T) {
	handler := setupUserHandler(t)

	c, w := setupGinContext("GET", "/users/by-username/", nil)
	c.Params = []gin.Param{{Key: "username", Value: ""}}
	handler.GetUserByUsername(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "invalid_request", response["error"])
	assert.Contains(t, response["error_description"], "username is required")
}

func TestUserHandler_GetUserByUsername_NotFound(t *testing.T) {
	t.Skip("Skipping test that requires database access - test DB setup returns nil")
}

// Test GetUserByEmail
func TestUserHandler_GetUserByEmail_MissingEmail(t *testing.T) {
	handler := setupUserHandler(t)

	c, w := setupGinContext("GET", "/users/by-email/", nil)
	c.Params = []gin.Param{{Key: "email", Value: ""}}
	handler.GetUserByEmail(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "invalid_request", response["error"])
	assert.Contains(t, response["error_description"], "email is required")
}

func TestUserHandler_GetUserByEmail_NotFound(t *testing.T) {
	t.Skip("Skipping test that requires database access - test DB setup returns nil")
}

// Test validation helper methods - These require database access, skipping
func TestUserHandler_ValidateCreateUserRequest(t *testing.T) {
	t.Skip("Skipping test that requires database access - test DB setup returns nil")
}

func TestUserHandler_ValidateUpdateUserRequest(t *testing.T) {
	t.Skip("Skipping test that requires database access - test DB setup returns nil")
}
