package tests

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"shieldgate/internal/handlers"
	"shieldgate/internal/models"
)

// Mock services for testing
type MockTenantService struct {
	mock.Mock
}

func (m *MockTenantService) Create(ctx context.Context, req *models.CreateTenantRequest) (*models.Tenant, error) {
	args := m.Called(ctx, req)
	return args.Get(0).(*models.Tenant), args.Error(1)
}

func (m *MockTenantService) GetByID(ctx context.Context, id uuid.UUID) (*models.Tenant, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Tenant), args.Error(1)
}

func (m *MockTenantService) GetByDomain(ctx context.Context, domain string) (*models.Tenant, error) {
	args := m.Called(ctx, domain)
	return args.Get(0).(*models.Tenant), args.Error(1)
}

func (m *MockTenantService) Update(ctx context.Context, id uuid.UUID, req *models.UpdateTenantRequest) (*models.Tenant, error) {
	args := m.Called(ctx, id, req)
	return args.Get(0).(*models.Tenant), args.Error(1)
}

func (m *MockTenantService) Delete(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockTenantService) List(ctx context.Context, limit, offset int) (*models.PaginatedResponse, error) {
	args := m.Called(ctx, limit, offset)
	return args.Get(0).(*models.PaginatedResponse), args.Error(1)
}

type MockUserService struct {
	mock.Mock
}

func (m *MockUserService) Create(ctx context.Context, tenantID uuid.UUID, req *models.CreateUserRequest) (*models.User, error) {
	args := m.Called(ctx, tenantID, req)
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserService) GetByID(ctx context.Context, tenantID, userID uuid.UUID) (*models.User, error) {
	args := m.Called(ctx, tenantID, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserService) GetByEmail(ctx context.Context, tenantID uuid.UUID, email string) (*models.User, error) {
	args := m.Called(ctx, tenantID, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserService) GetByUsername(ctx context.Context, tenantID uuid.UUID, username string) (*models.User, error) {
	args := m.Called(ctx, tenantID, username)
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserService) Update(ctx context.Context, tenantID, userID uuid.UUID, req *models.UpdateUserRequest) (*models.User, error) {
	args := m.Called(ctx, tenantID, userID, req)
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserService) Delete(ctx context.Context, tenantID, userID uuid.UUID) error {
	args := m.Called(ctx, tenantID, userID)
	return args.Error(0)
}

func (m *MockUserService) List(ctx context.Context, tenantID uuid.UUID, limit, offset int) (*models.PaginatedResponse, error) {
	args := m.Called(ctx, tenantID, limit, offset)
	return args.Get(0).(*models.PaginatedResponse), args.Error(1)
}

func (m *MockUserService) Authenticate(ctx context.Context, tenantID uuid.UUID, email, password string) (*models.User, error) {
	args := m.Called(ctx, tenantID, email, password)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserService) ChangePassword(ctx context.Context, tenantID, userID uuid.UUID, oldPassword, newPassword string) error {
	args := m.Called(ctx, tenantID, userID, oldPassword, newPassword)
	return args.Error(0)
}

type MockClientService struct {
	mock.Mock
}

func (m *MockClientService) Create(ctx context.Context, tenantID uuid.UUID, req *models.CreateClientRequest) (*models.Client, error) {
	args := m.Called(ctx, tenantID, req)
	return args.Get(0).(*models.Client), args.Error(1)
}

func (m *MockClientService) GetByID(ctx context.Context, tenantID, clientID uuid.UUID) (*models.Client, error) {
	args := m.Called(ctx, tenantID, clientID)
	return args.Get(0).(*models.Client), args.Error(1)
}

func (m *MockClientService) GetByClientID(ctx context.Context, tenantID uuid.UUID, clientID string) (*models.Client, error) {
	args := m.Called(ctx, tenantID, clientID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Client), args.Error(1)
}

func (m *MockClientService) Update(ctx context.Context, tenantID, clientID uuid.UUID, req *models.UpdateClientRequest) (*models.Client, error) {
	args := m.Called(ctx, tenantID, clientID, req)
	return args.Get(0).(*models.Client), args.Error(1)
}

func (m *MockClientService) Delete(ctx context.Context, tenantID, clientID uuid.UUID) error {
	args := m.Called(ctx, tenantID, clientID)
	return args.Error(0)
}

func (m *MockClientService) List(ctx context.Context, tenantID uuid.UUID, limit, offset int) (*models.PaginatedResponse, error) {
	args := m.Called(ctx, tenantID, limit, offset)
	return args.Get(0).(*models.PaginatedResponse), args.Error(1)
}

func (m *MockClientService) ValidateClient(ctx context.Context, tenantID uuid.UUID, clientID, clientSecret string) (*models.Client, error) {
	args := m.Called(ctx, tenantID, clientID, clientSecret)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Client), args.Error(1)
}

func (m *MockClientService) ValidateRedirectURI(ctx context.Context, client *models.Client, redirectURI string) error {
	args := m.Called(ctx, client, redirectURI)
	return args.Error(0)
}

type MockAuthService struct {
	mock.Mock
}

func (m *MockAuthService) GenerateAuthorizationCode(ctx context.Context, tenantID, clientID, userID uuid.UUID, redirectURI, scope, codeChallenge, codeChallengeMethod string) (*models.AuthorizationCode, error) {
	args := m.Called(ctx, tenantID, clientID, userID, redirectURI, scope, codeChallenge, codeChallengeMethod)
	return args.Get(0).(*models.AuthorizationCode), args.Error(1)
}

func (m *MockAuthService) ExchangeAuthorizationCode(ctx context.Context, tenantID uuid.UUID, code, clientID, clientSecret, redirectURI, codeVerifier string) (*models.TokenResponse, error) {
	args := m.Called(ctx, tenantID, code, clientID, clientSecret, redirectURI, codeVerifier)
	return args.Get(0).(*models.TokenResponse), args.Error(1)
}

func (m *MockAuthService) GenerateTokens(ctx context.Context, tenantID, clientID, userID uuid.UUID, scope string, includeIDToken bool) (*models.TokenResponse, error) {
	args := m.Called(ctx, tenantID, clientID, userID, scope, includeIDToken)
	return args.Get(0).(*models.TokenResponse), args.Error(1)
}

func (m *MockAuthService) RefreshTokens(ctx context.Context, tenantID uuid.UUID, refreshToken, clientID, clientSecret string) (*models.TokenResponse, error) {
	args := m.Called(ctx, tenantID, refreshToken, clientID, clientSecret)
	return args.Get(0).(*models.TokenResponse), args.Error(1)
}

func (m *MockAuthService) RevokeToken(ctx context.Context, tenantID uuid.UUID, token, tokenTypeHint string) error {
	args := m.Called(ctx, tenantID, token, tokenTypeHint)
	return args.Error(0)
}

func (m *MockAuthService) IntrospectToken(ctx context.Context, tenantID uuid.UUID, token string) (*models.IntrospectionResponse, error) {
	args := m.Called(ctx, tenantID, token)
	return args.Get(0).(*models.IntrospectionResponse), args.Error(1)
}

func (m *MockAuthService) ValidateAccessToken(ctx context.Context, tenantID uuid.UUID, tokenString string) (*models.JWTClaims, error) {
	args := m.Called(ctx, tenantID, tokenString)
	return args.Get(0).(*models.JWTClaims), args.Error(1)
}

func (m *MockAuthService) ValidatePKCE(codeVerifier, codeChallenge, method string) bool {
	args := m.Called(codeVerifier, codeChallenge, method)
	return args.Bool(0)
}

func (m *MockAuthService) GenerateIDToken(ctx context.Context, user *models.User, clientID string) (string, error) {
	args := m.Called(ctx, user, clientID)
	return args.String(0), args.Error(1)
}

func (m *MockAuthService) GetUserInfo(ctx context.Context, tenantID uuid.UUID, accessToken string) (*models.UserInfo, error) {
	args := m.Called(ctx, tenantID, accessToken)
	return args.Get(0).(*models.UserInfo), args.Error(1)
}

func (m *MockAuthService) GetDiscoveryDocument(ctx context.Context) (*models.OpenIDConfiguration, error) {
	args := m.Called(ctx)
	return args.Get(0).(*models.OpenIDConfiguration), args.Error(1)
}

func (m *MockAuthService) CleanupExpiredTokens(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func TestOAuthHandler_HandleAuthorize_Success(t *testing.T) {
	// Setup
	gin.SetMode(gin.TestMode)

	mockTenantService := new(MockTenantService)
	mockUserService := new(MockUserService)
	mockClientService := new(MockClientService)
	mockAuthService := new(MockAuthService)

	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel) // Reduce noise in tests

	handler := handlers.NewOAuthHandler(
		mockTenantService,
		mockUserService,
		mockClientService,
		mockAuthService,
		logger,
	)

	// Setup test data
	tenantID := uuid.New()
	clientID := "test-client-id"
	redirectURI := "http://localhost:3000/callback"

	client := &models.Client{
		ID:           uuid.New(),
		TenantID:     tenantID,
		ClientID:     clientID,
		Name:         "Test Client",
		RedirectURIs: models.StringArray{redirectURI},
		IsPublic:     true,
	}

	tenant := &models.Tenant{
		ID:   tenantID,
		Name: "Test Tenant",
	}

	// Setup mocks
	mockClientService.On("GetByClientID", mock.Anything, tenantID, clientID).Return(client, nil)
	mockClientService.On("ValidateRedirectURI", mock.Anything, client, redirectURI).Return(nil)
	mockTenantService.On("GetByID", mock.Anything, tenantID).Return(tenant, nil)

	// Setup router
	router := gin.New()
	router.LoadHTMLGlob("../../../templates/*")

	// Add tenant context middleware for testing
	router.Use(func(c *gin.Context) {
		c.Set("tenant_id", tenantID)
		c.Next()
	})

	handler.RegisterRoutes(router.Group(""))

	// Create request
	req := httptest.NewRequest("GET", "/oauth/authorize?response_type=code&client_id="+clientID+"&redirect_uri="+url.QueryEscape(redirectURI)+"&scope=read&state=xyz&code_challenge=test-challenge&code_challenge_method=S256", nil)
	w := httptest.NewRecorder()

	// Execute
	router.ServeHTTP(w, req)

	// Assert
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "Test Client") // Should render login page with client name

	// Verify mocks
	mockClientService.AssertExpectations(t)
	mockTenantService.AssertExpectations(t)
}

func TestOAuthHandler_HandleLogin_Success(t *testing.T) {
	// Setup
	gin.SetMode(gin.TestMode)

	mockTenantService := new(MockTenantService)
	mockUserService := new(MockUserService)
	mockClientService := new(MockClientService)
	mockAuthService := new(MockAuthService)

	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	handler := handlers.NewOAuthHandler(
		mockTenantService,
		mockUserService,
		mockClientService,
		mockAuthService,
		logger,
	)

	// Setup test data
	tenantID := uuid.New()
	userID := uuid.New()
	clientID := "test-client-id"
	redirectURI := "http://localhost:3000/callback"

	user := &models.User{
		ID:       userID,
		TenantID: tenantID,
		Email:    "test@example.com",
		Username: "testuser",
	}

	authCode := &models.AuthorizationCode{
		ID:       uuid.New(),
		TenantID: tenantID,
		Code:     "test-auth-code",
		ClientID: uuid.MustParse(clientID),
		UserID:   userID,
	}

	// Setup mocks
	mockUserService.On("GetByEmail", mock.Anything, tenantID, "test@example.com").Return(user, nil)
	mockAuthService.On("GenerateAuthorizationCode", mock.Anything, tenantID, mock.AnythingOfType("uuid.UUID"), userID, redirectURI, "read", "test-challenge", "S256").Return(authCode, nil)

	// Setup router
	router := gin.New()

	// Add tenant context middleware for testing
	router.Use(func(c *gin.Context) {
		c.Set("tenant_id", tenantID)
		c.Next()
	})

	handler.RegisterRoutes(router.Group(""))

	// Create form data
	formData := url.Values{}
	formData.Set("username", "test@example.com")
	formData.Set("password", "password123")
	formData.Set("client_id", clientID)
	formData.Set("redirect_uri", redirectURI)
	formData.Set("scope", "read")
	formData.Set("state", "xyz")
	formData.Set("code_challenge", "test-challenge")
	formData.Set("code_challenge_method", "S256")

	// Create request
	req := httptest.NewRequest("POST", "/oauth/login", strings.NewReader(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	// Execute
	router.ServeHTTP(w, req)

	// Assert
	assert.Equal(t, http.StatusFound, w.Code) // Should redirect
	location := w.Header().Get("Location")
	assert.Contains(t, location, redirectURI)
	assert.Contains(t, location, "code=test-auth-code")
	assert.Contains(t, location, "state=xyz")

	// Verify mocks
	mockUserService.AssertExpectations(t)
	mockAuthService.AssertExpectations(t)
}

func TestOAuthHandler_HandleToken_AuthorizationCodeGrant_Success(t *testing.T) {
	// Setup
	gin.SetMode(gin.TestMode)

	mockTenantService := new(MockTenantService)
	mockUserService := new(MockUserService)
	mockClientService := new(MockClientService)
	mockAuthService := new(MockAuthService)

	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	handler := handlers.NewOAuthHandler(
		mockTenantService,
		mockUserService,
		mockClientService,
		mockAuthService,
		logger,
	)

	// Setup test data
	tenantID := uuid.New()
	clientID := "test-client-id"
	clientSecret := "test-client-secret"

	client := &models.Client{
		ID:           uuid.New(),
		TenantID:     tenantID,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		IsPublic:     false,
	}

	tokenResponse := &models.TokenResponse{
		AccessToken:  "test-access-token",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		RefreshToken: "test-refresh-token",
		Scope:        "read",
	}

	// Setup mocks
	mockClientService.On("ValidateClient", mock.Anything, tenantID, clientID, clientSecret).Return(client, nil)
	mockAuthService.On("ExchangeAuthorizationCode", mock.Anything, tenantID, "test-code", clientID, clientSecret, "http://localhost:3000/callback", "test-verifier").Return(tokenResponse, nil)

	// Setup router
	router := gin.New()

	// Add tenant context middleware for testing
	router.Use(func(c *gin.Context) {
		c.Set("tenant_id", tenantID)
		c.Next()
	})

	handler.RegisterRoutes(router.Group(""))

	// Create form data
	formData := url.Values{}
	formData.Set("grant_type", "authorization_code")
	formData.Set("code", "test-code")
	formData.Set("client_id", clientID)
	formData.Set("client_secret", clientSecret)
	formData.Set("redirect_uri", "http://localhost:3000/callback")
	formData.Set("code_verifier", "test-verifier")

	// Create request
	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	// Execute
	router.ServeHTTP(w, req)

	// Assert
	assert.Equal(t, http.StatusOK, w.Code)

	var response models.TokenResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "test-access-token", response.AccessToken)
	assert.Equal(t, "Bearer", response.TokenType)
	assert.Equal(t, int64(3600), response.ExpiresIn)
	assert.Equal(t, "test-refresh-token", response.RefreshToken)

	// Verify mocks
	mockClientService.AssertExpectations(t)
	mockAuthService.AssertExpectations(t)
}
