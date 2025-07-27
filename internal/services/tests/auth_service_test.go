package tests

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"shield1/internal/models"
	"shield1/internal/services"
	"shield1/tests/utils"
)

func TestAuthService_GenerateAuthorizationCode(t *testing.T) {
	db := utils.SetupTestDB(t)
	cfg := utils.CreateTestConfig()
	authService := services.NewAuthService(db, nil, cfg)

	// Create test client and user
	client := utils.CreateTestClient()
	user := utils.CreateTestUser()
	require.NoError(t, db.Create(client).Error)
	require.NoError(t, db.Create(user).Error)

	tests := []struct {
		name                string
		clientID            uuid.UUID
		userID              uuid.UUID
		redirectURI         string
		scope               string
		codeChallenge       string
		codeChallengeMethod string
		expectError         bool
	}{
		{
			name:                "valid authorization code generation",
			clientID:            client.ID,
			userID:              user.ID,
			redirectURI:         "http://localhost:3000/callback",
			scope:               "read write",
			codeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
			codeChallengeMethod: "S256",
			expectError:         false,
		},
		{
			name:                "without PKCE",
			clientID:            client.ID,
			userID:              user.ID,
			redirectURI:         "http://localhost:3000/callback",
			scope:               "read",
			codeChallenge:       "",
			codeChallengeMethod: "",
			expectError:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authCode, err := authService.GenerateAuthorizationCode(
				tt.clientID, tt.userID, tt.redirectURI, tt.scope,
				tt.codeChallenge, tt.codeChallengeMethod,
			)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, authCode)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, authCode)
				assert.NotEmpty(t, authCode.Code)
				assert.Equal(t, tt.clientID, authCode.ClientID)
				assert.Equal(t, tt.userID, authCode.UserID)
				assert.Equal(t, tt.redirectURI, authCode.RedirectURI)
				assert.Equal(t, tt.scope, authCode.Scope)
				assert.Equal(t, tt.codeChallenge, authCode.CodeChallenge)
				assert.Equal(t, tt.codeChallengeMethod, authCode.CodeChallengeMethod)
				assert.True(t, authCode.ExpiresAt.After(time.Now()))
			}
		})
	}
}

func TestAuthService_ValidateAuthorizationCode(t *testing.T) {
	db := utils.SetupTestDB(t)
	cfg := utils.CreateTestConfig()
	authService := services.NewAuthService(db, nil, cfg)

	// Create test client and user
	client := utils.CreateTestClient()
	user := utils.CreateTestUser()
	require.NoError(t, db.Create(client).Error)
	require.NoError(t, db.Create(user).Error)

	// Generate a valid authorization code
	validCode, err := authService.GenerateAuthorizationCode(
		client.ID, user.ID, "http://localhost:3000/callback", "read write",
		"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "S256",
	)
	require.NoError(t, err)

	// Generate an expired code
	expiredCode := &models.AuthorizationCode{
		ID:                  uuid.New(),
		Code:                "expired-code",
		ClientID:            client.ID,
		UserID:              user.ID,
		RedirectURI:         "http://localhost:3000/callback",
		Scope:               "read",
		CodeChallenge:       "",
		CodeChallengeMethod: "",
		ExpiresAt:           time.Now().Add(-time.Hour),
		CreatedAt:           time.Now().Add(-time.Hour),
	}
	require.NoError(t, db.Create(expiredCode).Error)

	tests := []struct {
		name         string
		code         string
		clientID     string
		redirectURI  string
		codeVerifier string
		expectError  bool
		errorMsg     string
	}{
		{
			name:         "valid code with PKCE",
			code:         validCode.Code,
			clientID:     client.ID.String(),
			redirectURI:  "http://localhost:3000/callback",
			codeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
			expectError:  false,
		},
		{
			name:         "invalid code",
			code:         "invalid-code",
			clientID:     client.ID.String(),
			redirectURI:  "http://localhost:3000/callback",
			codeVerifier: "",
			expectError:  true,
			errorMsg:     "invalid authorization code",
		},
		{
			name:         "expired code",
			code:         expiredCode.Code,
			clientID:     client.ID.String(),
			redirectURI:  "http://localhost:3000/callback",
			codeVerifier: "",
			expectError:  true,
			errorMsg:     "authorization code expired",
		},
		{
			name:         "wrong redirect URI",
			code:         validCode.Code,
			clientID:     client.ID.String(),
			redirectURI:  "http://malicious.com/callback",
			codeVerifier: "",
			expectError:  true,
			errorMsg:     "invalid redirect URI",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Re-create the valid code for each test since it gets consumed
			if tt.name == "valid code with PKCE" {
				validCode, err = authService.GenerateAuthorizationCode(
					client.ID, user.ID, "http://localhost:3000/callback", "read write",
					"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "S256",
				)
				require.NoError(t, err)
				tt.code = validCode.Code
			}

			result, err := authService.ValidateAuthorizationCode(
				tt.code, tt.clientID, tt.redirectURI, tt.codeVerifier,
			)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, result)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
				assert.Equal(t, tt.code, result.Code)
			}
		})
	}
}

func TestAuthService_GenerateTokens(t *testing.T) {
	db := utils.SetupTestDB(t)
	cfg := utils.CreateTestConfig()
	authService := services.NewAuthService(db, nil, cfg)

	// Create test client and user
	client := utils.CreateTestClient()
	user := utils.CreateTestUser()
	require.NoError(t, db.Create(client).Error)
	require.NoError(t, db.Create(user).Error)

	tests := []struct {
		name           string
		clientID       uuid.UUID
		userID         uuid.UUID
		scope          string
		includeIDToken bool
		expectError    bool
		expectIDToken  bool
	}{
		{
			name:           "generate tokens without ID token",
			clientID:       client.ID,
			userID:         user.ID,
			scope:          "read write",
			includeIDToken: false,
			expectError:    false,
			expectIDToken:  false,
		},
		{
			name:           "generate tokens with ID token",
			clientID:       client.ID,
			userID:         user.ID,
			scope:          "read write openid",
			includeIDToken: true,
			expectError:    false,
			expectIDToken:  true,
		},
		{
			name:           "generate tokens with openid scope but no ID token flag",
			clientID:       client.ID,
			userID:         user.ID,
			scope:          "openid profile",
			includeIDToken: false,
			expectError:    false,
			expectIDToken:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenResponse, err := authService.GenerateTokens(
				tt.clientID, tt.userID, tt.scope, tt.includeIDToken,
			)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, tokenResponse)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, tokenResponse)
				assert.NotEmpty(t, tokenResponse.AccessToken)
				assert.NotEmpty(t, tokenResponse.RefreshToken)
				assert.Equal(t, "Bearer", tokenResponse.TokenType)
				assert.Equal(t, int64(cfg.AccessTokenDuration.Seconds()), tokenResponse.ExpiresIn)
				assert.Equal(t, tt.scope, tokenResponse.Scope)

				if tt.expectIDToken {
					assert.NotEmpty(t, tokenResponse.IDToken)
				} else {
					assert.Empty(t, tokenResponse.IDToken)
				}

				// Verify tokens are stored in database
				var accessToken models.AccessToken
				err = db.Where("token = ?", tokenResponse.AccessToken).First(&accessToken).Error
				assert.NoError(t, err)

				var refreshToken models.RefreshToken
				err = db.Where("token = ?", tokenResponse.RefreshToken).First(&refreshToken).Error
				assert.NoError(t, err)
			}
		})
	}
}

func TestAuthService_ValidateAccessToken(t *testing.T) {
	db := utils.SetupTestDB(t)
	cfg := utils.CreateTestConfig()
	authService := services.NewAuthService(db, nil, cfg)

	// Create test client and user
	client := utils.CreateTestClient()
	user := utils.CreateTestUser()
	require.NoError(t, db.Create(client).Error)
	require.NoError(t, db.Create(user).Error)

	// Generate valid tokens
	tokenResponse, err := authService.GenerateTokens(client.ID, user.ID, "read write", false)
	require.NoError(t, err)

	tests := []struct {
		name        string
		token       string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "valid token",
			token:       tokenResponse.AccessToken,
			expectError: false,
		},
		{
			name:        "invalid token",
			token:       "invalid.jwt.token",
			expectError: true,
			errorMsg:    "invalid token",
		},
		{
			name:        "empty token",
			token:       "",
			expectError: true,
			errorMsg:    "invalid token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims, err := authService.ValidateAccessToken(tt.token)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, claims)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, claims)
				assert.Equal(t, user.ID.String(), claims.Sub)
				assert.Equal(t, client.ID.String(), claims.Aud)
				assert.Equal(t, cfg.ServerURL, claims.Iss)
			}
		})
	}
}

func TestAuthService_RefreshAccessToken(t *testing.T) {
	db := utils.SetupTestDB(t)
	cfg := utils.CreateTestConfig()
	authService := services.NewAuthService(db, nil, cfg)

	// Create test client and user
	client := utils.CreateTestClient()
	user := utils.CreateTestUser()
	require.NoError(t, db.Create(client).Error)
	require.NoError(t, db.Create(user).Error)

	// Generate valid tokens
	tokenResponse, err := authService.GenerateTokens(client.ID, user.ID, "read write", false)
	require.NoError(t, err)

	// Create expired refresh token
	expiredRefreshToken := &models.RefreshToken{
		ID:        uuid.New(),
		Token:     "expired-refresh-token",
		ClientID:  client.ID,
		UserID:    user.ID,
		ExpiresAt: time.Now().Add(-time.Hour),
		CreatedAt: time.Now().Add(-time.Hour),
	}
	require.NoError(t, db.Create(expiredRefreshToken).Error)

	tests := []struct {
		name         string
		refreshToken string
		expectError  bool
		errorMsg     string
	}{
		{
			name:         "valid refresh token",
			refreshToken: tokenResponse.RefreshToken,
			expectError:  false,
		},
		{
			name:         "invalid refresh token",
			refreshToken: "invalid-refresh-token",
			expectError:  true,
			errorMsg:     "invalid refresh token",
		},
		{
			name:         "expired refresh token",
			refreshToken: expiredRefreshToken.Token,
			expectError:  true,
			errorMsg:     "refresh token expired",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			newTokenResponse, err := authService.RefreshAccessToken(tt.refreshToken)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, newTokenResponse)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, newTokenResponse)
				assert.NotEmpty(t, newTokenResponse.AccessToken)
				assert.NotEmpty(t, newTokenResponse.RefreshToken)
				assert.Equal(t, "Bearer", newTokenResponse.TokenType)

				// New tokens should be different from original
				assert.NotEqual(t, tokenResponse.AccessToken, newTokenResponse.AccessToken)
				assert.NotEqual(t, tokenResponse.RefreshToken, newTokenResponse.RefreshToken)
			}
		})
	}
}

func TestAuthService_RevokeToken(t *testing.T) {
	db := utils.SetupTestDB(t)
	cfg := utils.CreateTestConfig()
	authService := services.NewAuthService(db, nil, cfg)

	// Create test client and user
	client := utils.CreateTestClient()
	user := utils.CreateTestUser()
	require.NoError(t, db.Create(client).Error)
	require.NoError(t, db.Create(user).Error)

	// Generate valid tokens
	tokenResponse, err := authService.GenerateTokens(client.ID, user.ID, "read write", false)
	require.NoError(t, err)

	tests := []struct {
		name          string
		token         string
		tokenTypeHint string
		expectError   bool
	}{
		{
			name:          "revoke access token",
			token:         tokenResponse.AccessToken,
			tokenTypeHint: "access_token",
			expectError:   false,
		},
		{
			name:          "revoke refresh token",
			token:         tokenResponse.RefreshToken,
			tokenTypeHint: "refresh_token",
			expectError:   false,
		},
		{
			name:          "revoke non-existent token",
			token:         "non-existent-token",
			tokenTypeHint: "",
			expectError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := authService.RevokeToken(tt.token, tt.tokenTypeHint)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestAuthService_IntrospectToken(t *testing.T) {
	db := utils.SetupTestDB(t)
	cfg := utils.CreateTestConfig()
	authService := services.NewAuthService(db, nil, cfg)

	// Create test client and user
	client := utils.CreateTestClient()
	user := utils.CreateTestUser()
	require.NoError(t, db.Create(client).Error)
	require.NoError(t, db.Create(user).Error)

	// Generate valid tokens
	tokenResponse, err := authService.GenerateTokens(client.ID, user.ID, "read write", false)
	require.NoError(t, err)

	tests := []struct {
		name         string
		token        string
		expectError  bool
		expectActive bool
	}{
		{
			name:         "valid token",
			token:        tokenResponse.AccessToken,
			expectError:  false,
			expectActive: true,
		},
		{
			name:         "invalid token",
			token:        "invalid-token",
			expectError:  false,
			expectActive: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response, err := authService.IntrospectToken(tt.token)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, response)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, response)
				assert.Equal(t, tt.expectActive, response.Active)

				if tt.expectActive {
					assert.Equal(t, "read write", response.Scope)
					assert.Equal(t, client.ID.String(), response.ClientID)
					assert.Equal(t, user.ID.String(), response.UserID)
					assert.Greater(t, response.Exp, int64(0))
					assert.Greater(t, response.Iat, int64(0))
				}
			}
		})
	}
}

func TestAuthService_AuthenticateUser(t *testing.T) {
	db := utils.SetupTestDB(t)
	cfg := utils.CreateTestConfig()
	authService := services.NewAuthService(db, nil, cfg)

	// Create test user with hashed password
	password := "testpassword123"
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), cfg.BcryptCost)
	require.NoError(t, err)

	user := &models.User{
		ID:           uuid.New(),
		Username:     "testuser",
		Email:        "test@example.com",
		PasswordHash: string(hashedPassword),
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	require.NoError(t, db.Create(user).Error)

	tests := []struct {
		name            string
		usernameOrEmail string
		password        string
		expectError     bool
		errorMsg        string
	}{
		{
			name:            "valid username and password",
			usernameOrEmail: "testuser",
			password:        password,
			expectError:     false,
		},
		{
			name:            "valid email and password",
			usernameOrEmail: "test@example.com",
			password:        password,
			expectError:     false,
		},
		{
			name:            "invalid username",
			usernameOrEmail: "nonexistent",
			password:        password,
			expectError:     true,
			errorMsg:        "invalid credentials",
		},
		{
			name:            "invalid password",
			usernameOrEmail: "testuser",
			password:        "wrongpassword",
			expectError:     true,
			errorMsg:        "invalid credentials",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := authService.AuthenticateUser(tt.usernameOrEmail, tt.password)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, result)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
				assert.Equal(t, user.ID, result.ID)
				assert.Equal(t, user.Username, result.Username)
				assert.Equal(t, user.Email, result.Email)
			}
		})
	}
}

func TestAuthService_GetUserInfo(t *testing.T) {
	db := utils.SetupTestDB(t)
	cfg := utils.CreateTestConfig()
	authService := services.NewAuthService(db, nil, cfg)

	// Create test user
	user := utils.CreateTestUser()
	require.NoError(t, db.Create(user).Error)

	tests := []struct {
		name        string
		userID      uuid.UUID
		expectError bool
		errorMsg    string
	}{
		{
			name:        "valid user ID",
			userID:      user.ID,
			expectError: false,
		},
		{
			name:        "invalid user ID",
			userID:      uuid.New(),
			expectError: true,
			errorMsg:    "user not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userInfo, err := authService.GetUserInfo(tt.userID)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, userInfo)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, userInfo)
				assert.Equal(t, user.ID.String(), userInfo.Sub)
				assert.Equal(t, user.Username, userInfo.Name)
				assert.Equal(t, user.Email, userInfo.Email)
				assert.True(t, userInfo.EmailVerified)
			}
		})
	}
}
