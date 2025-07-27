package tests

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"shield1/config"
	"shield1/internal/models"
	"shield1/internal/services"
	"shield1/tests/utils"
)

func TestAuthService_AuthorizationCodeFlow_Complete(t *testing.T) {
	db := utils.SetupTestDB(t)
	cfg := &config.Config{
		JWTSecret:                 "test-secret-key-for-jwt-signing-minimum-32-chars",
		ServerURL:                 "http://localhost:8080",
		AccessTokenDuration:       time.Hour,
		RefreshTokenDuration:      24 * time.Hour,
		AuthorizationCodeDuration: 10 * time.Minute,
		BcryptCost:                4, // Lower cost for faster tests
	}
	authService := services.NewAuthService(db, nil, cfg)

	// Create test user and client
	testUser := utils.CreateTestUser()
	require.NoError(t, db.Create(testUser).Error)

	testClient := utils.CreateTestClient()
	testClient.GrantTypes = models.StringArray{"authorization_code", "refresh_token"}
	testClient.Scopes = models.StringArray{"read", "write", "openid", "profile", "email"}
	require.NoError(t, db.Create(testClient).Error)

	// Test complete Authorization Code Flow
	t.Run("complete authorization code flow", func(t *testing.T) {
		redirectURI := testClient.RedirectURIs[0]
		scope := "read write"
		codeChallenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
		codeChallengeMethod := "S256"
		codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

		// Step 1: Generate authorization code
		authCode, err := authService.GenerateAuthorizationCode(
			testClient.ID, testUser.ID, redirectURI, scope, codeChallenge, codeChallengeMethod,
		)
		require.NoError(t, err)
		require.NotNil(t, authCode)
		assert.NotEmpty(t, authCode.Code)
		assert.Equal(t, testClient.ID, authCode.ClientID)
		assert.Equal(t, testUser.ID, authCode.UserID)
		assert.Equal(t, redirectURI, authCode.RedirectURI)
		assert.Equal(t, scope, authCode.Scope)
		assert.Equal(t, codeChallenge, authCode.CodeChallenge)
		assert.Equal(t, codeChallengeMethod, authCode.CodeChallengeMethod)

		// Step 2: Validate authorization code and generate tokens
		validatedCode, err := authService.ValidateAuthorizationCode(
			authCode.Code, testClient.ID.String(), redirectURI, codeVerifier,
		)
		require.NoError(t, err)
		require.NotNil(t, validatedCode)
		assert.Equal(t, authCode.Code, validatedCode.Code)

		// Step 3: Generate tokens
		tokenResponse, err := authService.GenerateTokens(
			testClient.ID, testUser.ID, scope, false,
		)
		require.NoError(t, err)
		require.NotNil(t, tokenResponse)
		assert.NotEmpty(t, tokenResponse.AccessToken)
		assert.NotEmpty(t, tokenResponse.RefreshToken)
		assert.Equal(t, "Bearer", tokenResponse.TokenType)
		assert.Equal(t, int64(3600), tokenResponse.ExpiresIn)
		assert.Equal(t, scope, tokenResponse.Scope)

		// Step 4: Validate access token
		claims, err := authService.ValidateAccessToken(tokenResponse.AccessToken)
		require.NoError(t, err)
		require.NotNil(t, claims)
		assert.Equal(t, testUser.ID.String(), claims.UserID)
		assert.Equal(t, testClient.ID.String(), claims.ClientID)
		assert.Equal(t, scope, claims.Scope)

		// Step 5: Use refresh token to get new access token
		newTokenResponse, err := authService.RefreshAccessToken(tokenResponse.RefreshToken)
		require.NoError(t, err)
		require.NotNil(t, newTokenResponse)
		assert.NotEmpty(t, newTokenResponse.AccessToken)
		assert.NotEqual(t, tokenResponse.AccessToken, newTokenResponse.AccessToken) // Should be different

		// Step 6: Revoke tokens
		err = authService.RevokeToken(newTokenResponse.AccessToken, "access_token")
		assert.NoError(t, err)

		err = authService.RevokeToken(newTokenResponse.RefreshToken, "refresh_token")
		assert.NoError(t, err)
	})
}

func TestAuthService_AuthorizationCodeFlow_WithOpenIDConnect(t *testing.T) {
	db := utils.SetupTestDB(t)
	cfg := &config.Config{
		JWTSecret:                 "test-secret-key-for-jwt-signing-minimum-32-chars",
		ServerURL:                 "http://localhost:8080",
		AccessTokenDuration:       time.Hour,
		RefreshTokenDuration:      24 * time.Hour,
		AuthorizationCodeDuration: 10 * time.Minute,
		BcryptCost:                4,
	}
	authService := services.NewAuthService(db, nil, cfg)

	// Create test user and client
	testUser := utils.CreateTestUser()
	require.NoError(t, db.Create(testUser).Error)

	testClient := utils.CreateTestClient()
	testClient.GrantTypes = models.StringArray{"authorization_code", "refresh_token"}
	testClient.Scopes = models.StringArray{"openid", "profile", "email"}
	require.NoError(t, db.Create(testClient).Error)

	t.Run("authorization code flow with OpenID Connect", func(t *testing.T) {
		redirectURI := testClient.RedirectURIs[0]
		scope := "openid profile email"
		codeChallenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
		codeChallengeMethod := "S256"
		codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

		// Generate authorization code
		authCode, err := authService.GenerateAuthorizationCode(
			testClient.ID, testUser.ID, redirectURI, scope, codeChallenge, codeChallengeMethod,
		)
		require.NoError(t, err)

		// Validate authorization code
		_, err = authService.ValidateAuthorizationCode(
			authCode.Code, testClient.ID.String(), redirectURI, codeVerifier,
		)
		require.NoError(t, err)

		// Generate tokens with ID token
		tokenResponse, err := authService.GenerateTokens(
			testClient.ID, testUser.ID, scope, true,
		)
		require.NoError(t, err)
		require.NotNil(t, tokenResponse)
		assert.NotEmpty(t, tokenResponse.AccessToken)
		assert.NotEmpty(t, tokenResponse.RefreshToken)
		assert.NotEmpty(t, tokenResponse.IDToken) // Should have ID token
		assert.Equal(t, scope, tokenResponse.Scope)

		// Get user info using access token
		userInfo, err := authService.GetUserInfo(testUser.ID)
		require.NoError(t, err)
		require.NotNil(t, userInfo)
		assert.Equal(t, testUser.ID.String(), userInfo.Sub)
		assert.Equal(t, testUser.Username, userInfo.Name)
		assert.Equal(t, testUser.Email, userInfo.Email)
		assert.True(t, userInfo.EmailVerified)
	})
}

func TestAuthService_AuthorizationCodeFlow_PKCE_Validation(t *testing.T) {
	db := utils.SetupTestDB(t)
	cfg := &config.Config{
		JWTSecret:                 "test-secret-key-for-jwt-signing-minimum-32-chars",
		ServerURL:                 "http://localhost:8080",
		AccessTokenDuration:       time.Hour,
		RefreshTokenDuration:      24 * time.Hour,
		AuthorizationCodeDuration: 10 * time.Minute,
		BcryptCost:                4,
	}
	authService := services.NewAuthService(db, nil, cfg)

	// Create test user and client
	testUser := utils.CreateTestUser()
	require.NoError(t, db.Create(testUser).Error)

	testClient := utils.CreateTestClient()
	testClient.GrantTypes = models.StringArray{"authorization_code"}
	require.NoError(t, db.Create(testClient).Error)

	redirectURI := testClient.RedirectURIs[0]
	scope := "read"

	tests := []struct {
		name                string
		codeChallenge       string
		codeChallengeMethod string
		codeVerifier        string
		expectError         bool
		errorMsg            string
	}{
		{
			name:                "valid PKCE S256",
			codeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
			codeChallengeMethod: "S256",
			codeVerifier:        "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
			expectError:         false,
		},
		{
			name:                "valid PKCE plain",
			codeChallenge:       "test-code-verifier",
			codeChallengeMethod: "plain",
			codeVerifier:        "test-code-verifier",
			expectError:         false,
		},
		{
			name:                "invalid code verifier for S256",
			codeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
			codeChallengeMethod: "S256",
			codeVerifier:        "wrong-code-verifier",
			expectError:         true,
			errorMsg:            "invalid code verifier",
		},
		{
			name:                "invalid code verifier for plain",
			codeChallenge:       "test-code-verifier",
			codeChallengeMethod: "plain",
			codeVerifier:        "wrong-code-verifier",
			expectError:         true,
			errorMsg:            "invalid code verifier",
		},
		{
			name:                "missing code verifier",
			codeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
			codeChallengeMethod: "S256",
			codeVerifier:        "",
			expectError:         true,
			errorMsg:            "code verifier required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate authorization code with PKCE
			authCode, err := authService.GenerateAuthorizationCode(
				testClient.ID, testUser.ID, redirectURI, scope, tt.codeChallenge, tt.codeChallengeMethod,
			)
			require.NoError(t, err)

			// Validate authorization code with code verifier
			validatedCode, err := authService.ValidateAuthorizationCode(
				authCode.Code, testClient.ID.String(), redirectURI, tt.codeVerifier,
			)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, validatedCode)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, validatedCode)
			}
		})
	}
}

func TestAuthService_AuthorizationCodeFlow_ErrorCases(t *testing.T) {
	db := utils.SetupTestDB(t)
	cfg := &config.Config{
		JWTSecret:                 "test-secret-key-for-jwt-signing-minimum-32-chars",
		ServerURL:                 "http://localhost:8080",
		AccessTokenDuration:       time.Hour,
		RefreshTokenDuration:      24 * time.Hour,
		AuthorizationCodeDuration: 100 * time.Millisecond, // Very short for expiration test
		BcryptCost:                4,
	}
	authService := services.NewAuthService(db, nil, cfg)

	// Create test user and client
	testUser := utils.CreateTestUser()
	require.NoError(t, db.Create(testUser).Error)

	testClient := utils.CreateTestClient()
	require.NoError(t, db.Create(testClient).Error)

	redirectURI := testClient.RedirectURIs[0]
	scope := "read"

	t.Run("invalid authorization code", func(t *testing.T) {
		validatedCode, err := authService.ValidateAuthorizationCode(
			"invalid-code", testClient.ID.String(), redirectURI, "",
		)
		assert.Error(t, err)
		assert.Nil(t, validatedCode)
		assert.Contains(t, err.Error(), "invalid authorization code")
	})

	t.Run("wrong client ID", func(t *testing.T) {
		authCode, err := authService.GenerateAuthorizationCode(
			testClient.ID, testUser.ID, redirectURI, scope, "", "",
		)
		require.NoError(t, err)

		validatedCode, err := authService.ValidateAuthorizationCode(
			authCode.Code, uuid.New().String(), redirectURI, "",
		)
		assert.Error(t, err)
		assert.Nil(t, validatedCode)
		assert.Contains(t, err.Error(), "invalid authorization code")
	})

	t.Run("wrong redirect URI", func(t *testing.T) {
		authCode, err := authService.GenerateAuthorizationCode(
			testClient.ID, testUser.ID, redirectURI, scope, "", "",
		)
		require.NoError(t, err)

		validatedCode, err := authService.ValidateAuthorizationCode(
			authCode.Code, testClient.ID.String(), "https://wrong-redirect.com", "",
		)
		assert.Error(t, err)
		assert.Nil(t, validatedCode)
		assert.Contains(t, err.Error(), "invalid redirect URI")
	})

	t.Run("expired authorization code", func(t *testing.T) {
		authCode, err := authService.GenerateAuthorizationCode(
			testClient.ID, testUser.ID, redirectURI, scope, "", "",
		)
		require.NoError(t, err)

		// Wait for code to expire
		time.Sleep(200 * time.Millisecond)

		validatedCode, err := authService.ValidateAuthorizationCode(
			authCode.Code, testClient.ID.String(), redirectURI, "",
		)
		assert.Error(t, err)
		assert.Nil(t, validatedCode)
		assert.Contains(t, err.Error(), "authorization code expired")
	})

	t.Run("authorization code used twice", func(t *testing.T) {
		authCode, err := authService.GenerateAuthorizationCode(
			testClient.ID, testUser.ID, redirectURI, scope, "", "",
		)
		require.NoError(t, err)

		// Use code first time
		validatedCode, err := authService.ValidateAuthorizationCode(
			authCode.Code, testClient.ID.String(), redirectURI, "",
		)
		require.NoError(t, err)
		require.NotNil(t, validatedCode)

		// Try to use code second time
		validatedCode, err = authService.ValidateAuthorizationCode(
			authCode.Code, testClient.ID.String(), redirectURI, "",
		)
		assert.Error(t, err)
		assert.Nil(t, validatedCode)
		assert.Contains(t, err.Error(), "invalid authorization code")
	})
}

func TestAuthService_TokenIntrospection(t *testing.T) {
	db := utils.SetupTestDB(t)
	cfg := &config.Config{
		JWTSecret:                 "test-secret-key-for-jwt-signing-minimum-32-chars",
		ServerURL:                 "http://localhost:8080",
		AccessTokenDuration:       time.Hour,
		RefreshTokenDuration:      24 * time.Hour,
		AuthorizationCodeDuration: 10 * time.Minute,
		BcryptCost:                4,
	}
	authService := services.NewAuthService(db, nil, cfg)

	// Create test user and client
	testUser := utils.CreateTestUser()
	require.NoError(t, db.Create(testUser).Error)

	testClient := utils.CreateTestClient()
	require.NoError(t, db.Create(testClient).Error)

	// Generate tokens
	tokenResponse, err := authService.GenerateTokens(
		testClient.ID, testUser.ID, "read write", false,
	)
	require.NoError(t, err)

	t.Run("introspect valid access token", func(t *testing.T) {
		response, err := authService.IntrospectToken(tokenResponse.AccessToken)
		require.NoError(t, err)
		require.NotNil(t, response)
		assert.True(t, response.Active)
		assert.Equal(t, "read write", response.Scope)
		assert.Equal(t, testClient.ID.String(), response.ClientID)
		assert.Equal(t, testUser.ID.String(), response.UserID)
		assert.Greater(t, response.Exp, int64(0))
		assert.Greater(t, response.Iat, int64(0))
	})

	t.Run("introspect invalid token", func(t *testing.T) {
		response, err := authService.IntrospectToken("invalid-token")
		require.NoError(t, err)
		require.NotNil(t, response)
		assert.False(t, response.Active)
	})

	t.Run("introspect revoked token", func(t *testing.T) {
		// Revoke the token
		err := authService.RevokeToken(tokenResponse.AccessToken, "access_token")
		require.NoError(t, err)

		// Try to introspect revoked token
		response, err := authService.IntrospectToken(tokenResponse.AccessToken)
		require.NoError(t, err)
		require.NotNil(t, response)
		assert.False(t, response.Active)
	})
}

func TestAuthService_RefreshTokenFlow(t *testing.T) {
	db := utils.SetupTestDB(t)
	cfg := &config.Config{
		JWTSecret:                 "test-secret-key-for-jwt-signing-minimum-32-chars",
		ServerURL:                 "http://localhost:8080",
		AccessTokenDuration:       time.Hour,
		RefreshTokenDuration:      24 * time.Hour,
		AuthorizationCodeDuration: 10 * time.Minute,
		BcryptCost:                4,
	}
	authService := services.NewAuthService(db, nil, cfg)

	// Create test user and client
	testUser := utils.CreateTestUser()
	require.NoError(t, db.Create(testUser).Error)

	testClient := utils.CreateTestClient()
	testClient.GrantTypes = models.StringArray{"authorization_code", "refresh_token"}
	require.NoError(t, db.Create(testClient).Error)

	// Generate initial tokens
	tokenResponse, err := authService.GenerateTokens(
		testClient.ID, testUser.ID, "read write", false,
	)
	require.NoError(t, err)

	t.Run("refresh access token successfully", func(t *testing.T) {
		newTokenResponse, err := authService.RefreshAccessToken(tokenResponse.RefreshToken)
		require.NoError(t, err)
		require.NotNil(t, newTokenResponse)
		assert.NotEmpty(t, newTokenResponse.AccessToken)
		assert.NotEmpty(t, newTokenResponse.RefreshToken)
		assert.NotEqual(t, tokenResponse.AccessToken, newTokenResponse.AccessToken)
		assert.Equal(t, "read write", newTokenResponse.Scope)
	})

	t.Run("refresh with invalid refresh token", func(t *testing.T) {
		newTokenResponse, err := authService.RefreshAccessToken("invalid-refresh-token")
		assert.Error(t, err)
		assert.Nil(t, newTokenResponse)
		assert.Contains(t, err.Error(), "invalid refresh token")
	})

	t.Run("refresh with revoked refresh token", func(t *testing.T) {
		// Revoke the refresh token
		err := authService.RevokeToken(tokenResponse.RefreshToken, "refresh_token")
		require.NoError(t, err)

		// Try to use revoked refresh token
		newTokenResponse, err := authService.RefreshAccessToken(tokenResponse.RefreshToken)
		assert.Error(t, err)
		assert.Nil(t, newTokenResponse)
		assert.Contains(t, err.Error(), "invalid refresh token")
	})
}

func TestAuthService_TokenRevocation(t *testing.T) {
	db := utils.SetupTestDB(t)
	cfg := &config.Config{
		JWTSecret:                 "test-secret-key-for-jwt-signing-minimum-32-chars",
		ServerURL:                 "http://localhost:8080",
		AccessTokenDuration:       time.Hour,
		RefreshTokenDuration:      24 * time.Hour,
		AuthorizationCodeDuration: 10 * time.Minute,
		BcryptCost:                4,
	}
	authService := services.NewAuthService(db, nil, cfg)

	// Create test user and client
	testUser := utils.CreateTestUser()
	require.NoError(t, db.Create(testUser).Error)

	testClient := utils.CreateTestClient()
	require.NoError(t, db.Create(testClient).Error)

	// Generate tokens
	tokenResponse, err := authService.GenerateTokens(
		testClient.ID, testUser.ID, "read write", false,
	)
	require.NoError(t, err)

	t.Run("revoke access token", func(t *testing.T) {
		err := authService.RevokeToken(tokenResponse.AccessToken, "access_token")
		assert.NoError(t, err)

		// Verify token is revoked
		claims, err := authService.ValidateAccessToken(tokenResponse.AccessToken)
		assert.Error(t, err)
		assert.Nil(t, claims)
	})

	t.Run("revoke refresh token", func(t *testing.T) {
		err := authService.RevokeToken(tokenResponse.RefreshToken, "refresh_token")
		assert.NoError(t, err)

		// Verify refresh token is revoked
		newTokenResponse, err := authService.RefreshAccessToken(tokenResponse.RefreshToken)
		assert.Error(t, err)
		assert.Nil(t, newTokenResponse)
	})

	t.Run("revoke non-existent token", func(t *testing.T) {
		err := authService.RevokeToken("non-existent-token", "access_token")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "token not found")
	})

	t.Run("revoke token without hint", func(t *testing.T) {
		// Generate new tokens for this test
		newTokenResponse, err := authService.GenerateTokens(
			testClient.ID, testUser.ID, "read", false,
		)
		require.NoError(t, err)

		// Revoke without token type hint
		err = authService.RevokeToken(newTokenResponse.AccessToken, "")
		assert.NoError(t, err)
	})
}

func TestAuthService_ScopeHandling(t *testing.T) {
	db := utils.SetupTestDB(t)
	cfg := &config.Config{
		JWTSecret:                 "test-secret-key-for-jwt-signing-minimum-32-chars",
		ServerURL:                 "http://localhost:8080",
		AccessTokenDuration:       time.Hour,
		RefreshTokenDuration:      24 * time.Hour,
		AuthorizationCodeDuration: 10 * time.Minute,
		BcryptCost:                4,
	}
	authService := services.NewAuthService(db, nil, cfg)

	// Create test user and client
	testUser := utils.CreateTestUser()
	require.NoError(t, db.Create(testUser).Error)

	testClient := utils.CreateTestClient()
	testClient.Scopes = models.StringArray{"read", "write", "admin", "openid", "profile", "email"}
	require.NoError(t, db.Create(testClient).Error)

	tests := []struct {
		name           string
		requestedScope string
		includeIDToken bool
		expectIDToken  bool
	}{
		{
			name:           "basic scopes",
			requestedScope: "read write",
			includeIDToken: false,
			expectIDToken:  false,
		},
		{
			name:           "openid scope without ID token request",
			requestedScope: "openid read",
			includeIDToken: false,
			expectIDToken:  false,
		},
		{
			name:           "openid scope with ID token request",
			requestedScope: "openid profile email",
			includeIDToken: true,
			expectIDToken:  true,
		},
		{
			name:           "all scopes",
			requestedScope: "read write admin openid profile email",
			includeIDToken: true,
			expectIDToken:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenResponse, err := authService.GenerateTokens(
				testClient.ID, testUser.ID, tt.requestedScope, tt.includeIDToken,
			)
			require.NoError(t, err)
			require.NotNil(t, tokenResponse)

			assert.Equal(t, tt.requestedScope, tokenResponse.Scope)

			if tt.expectIDToken {
				assert.NotEmpty(t, tokenResponse.IDToken)
			} else {
				assert.Empty(t, tokenResponse.IDToken)
			}

			// Validate access token contains correct scope
			claims, err := authService.ValidateAccessToken(tokenResponse.AccessToken)
			require.NoError(t, err)
			assert.Equal(t, tt.requestedScope, claims.Scope)
		})
	}
}

func TestAuthService_UserAuthentication(t *testing.T) {
	db := utils.SetupTestDB(t)
	cfg := &config.Config{
		BcryptCost: 4, // Lower cost for faster tests
	}
	authService := services.NewAuthService(db, nil, cfg)

	// Create test user with known password
	password := "testpassword123"
	testUser := utils.CreateTestUserWithPassword(password)
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
			name:            "authenticate non-existent user",
			usernameOrEmail: "nonexistent@example.com",
			password:        password,
			expectError:     true,
			errorMsg:        "invalid credentials",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user, err := authService.AuthenticateUser(tt.usernameOrEmail, tt.password)

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
