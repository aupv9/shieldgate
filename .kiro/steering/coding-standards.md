# ShieldGate Coding Standards

## Go Coding Guidelines

### Code Organization
- Tuân thủ Go project layout chuẩn
- Sử dụng package naming theo convention: `internal/handlers`, `internal/services`, etc.
- Mỗi package có một responsibility rõ ràng
- Tách biệt business logic (services) khỏi HTTP handling (handlers)

### Naming Conventions
- **Variables**: camelCase (`userID`, `clientSecret`)
- **Functions**: PascalCase cho exported, camelCase cho unexported
- **Constants**: UPPER_SNAKE_CASE hoặc PascalCase
- **Interfaces**: Thêm suffix `-er` (`TokenValidator`, `UserManager`)
- **Structs**: PascalCase (`AuthRequest`, `TokenResponse`)

### Error Handling
```go
// Luôn handle errors explicitly
if err != nil {
    log.WithError(err).Error("failed to process request")
    return nil, fmt.Errorf("processing failed: %w", err)
}

// Sử dụng custom error types cho business logic
type ValidationError struct {
    Field   string
    Message string
}

func (e ValidationError) Error() string {
    return fmt.Sprintf("validation failed for %s: %s", e.Field, e.Message)
}
```

### Logging Standards
```go
// Sử dụng structured logging với logrus
log.WithFields(logrus.Fields{
    "client_id": clientID,
    "user_id":   userID,
    "action":    "token_generation",
}).Info("access token generated successfully")

// Log levels:
// - Error: System errors, security violations
// - Warn: Business rule violations, deprecated usage
// - Info: Important business events (login, token generation)
// - Debug: Detailed flow information (development only)
```

### Security Practices
- **Input Validation**: Validate tất cả input từ client
- **SQL Injection Prevention**: Sử dụng parameterized queries với GORM
- **Password Handling**: Luôn hash passwords với bcrypt, không log passwords
- **Token Security**: JWT signing với strong secrets, validate token expiration
- **Rate Limiting**: Implement cho các sensitive endpoints

### Testing Standards
```go
// Test naming: TestFunctionName_Scenario_ExpectedResult
func TestGenerateAccessToken_ValidRequest_ReturnsToken(t *testing.T) {
    // Arrange
    service := NewAuthService(mockDB, mockRedis)
    request := &TokenRequest{
        ClientID: "test-client",
        UserID:   "test-user",
    }
    
    // Act
    token, err := service.GenerateAccessToken(request)
    
    // Assert
    assert.NoError(t, err)
    assert.NotEmpty(t, token.AccessToken)
    assert.Equal(t, 3600, token.ExpiresIn)
}
```

### Database Patterns
```go
// Sử dụng GORM với proper error handling
func (r *UserRepository) GetByID(id string) (*models.User, error) {
    var user models.User
    if err := r.db.Where("id = ?", id).First(&user).Error; err != nil {
        if errors.Is(err, gorm.ErrRecordNotFound) {
            return nil, ErrUserNotFound
        }
        return nil, fmt.Errorf("failed to get user: %w", err)
    }
    return &user, nil
}
```

### HTTP Handler Patterns
```go
// Consistent response structure
type APIResponse struct {
    Success bool        `json:"success"`
    Data    interface{} `json:"data,omitempty"`
    Error   string      `json:"error,omitempty"`
}

// Handler structure
func (h *AuthHandler) HandleTokenRequest(c *gin.Context) {
    var req TokenRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, APIResponse{
            Success: false,
            Error:   "invalid request format",
        })
        return
    }
    
    // Validate request
    if err := h.validator.ValidateTokenRequest(&req); err != nil {
        c.JSON(http.StatusBadRequest, APIResponse{
            Success: false,
            Error:   err.Error(),
        })
        return
    }
    
    // Process request
    token, err := h.authService.GenerateToken(&req)
    if err != nil {
        log.WithError(err).Error("token generation failed")
        c.JSON(http.StatusInternalServerError, APIResponse{
            Success: false,
            Error:   "internal server error",
        })
        return
    }
    
    c.JSON(http.StatusOK, APIResponse{
        Success: true,
        Data:    token,
    })
}
```