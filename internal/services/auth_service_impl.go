package services

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"

	"shieldgate/config"
	"shieldgate/internal/models"
	"shieldgate/internal/repo"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type authServiceImpl struct {
	repos  *repo.Repositories
	config *config.Config
	logger *logrus.Logger
}

// NewAuthService creates a new auth service implementation
func NewAuthService(repos *repo.Repositories, config *config.Config, logger *logrus.Logger) AuthService {
	return &authServiceImpl{
		repos:  repos,
		config: config,
		logger: logger,
	}
}

func (s *authServiceImpl) GenerateAuthorizationCode(ctx context.Context, tenantID, clientID, userID uuid.UUID, redirectURI, scope, codeChallenge, codeChallengeMethod string) (*models.AuthorizationCode, error) {
	// Generate random code
	code, err := s.generateRandomString(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate authorization code: %w", err)
	}

	// Create authorization code
	authCode := &models.AuthorizationCode{
		ID:                  uuid.New(),
		TenantID:            tenantID,
		Code:                code,
		ClientID:            clientID,
		UserID:              userID,
		RedirectURI:         redirectURI,
		Scope:               scope,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		ExpiresAt:           time.Now().Add(s.config.AuthorizationCodeDuration),
	}

	if err := s.repos.AuthCode.Create(ctx, authCode); err != nil {
		return nil, fmt.Errorf("failed to store authorization code: %w", err)
	}

	s.logger.WithFields(logrus.Fields{
		"tenant_id": tenantID,
		"client_id": clientID,
		"user_id":   userID,
		"code":      code[:8] + "...", // Log only first 8 chars for security
	}).Info("authorization code generated")

	return authCode, nil
}

func (s *authServiceImpl) ExchangeAuthorizationCode(ctx context.Context, tenantID uuid.UUID, code, clientID, clientSecret, redirectURI, codeVerifier string) (*models.TokenResponse, error) {
	// Get authorization code
	authCode, err := s.repos.AuthCode.GetByCode(ctx, tenantID, code)
	if err != nil {
		return nil, models.ErrInvalidGrant
	}

	// Check if code is expired
	if authCode.IsExpired() {
		s.repos.AuthCode.Delete(ctx, tenantID, code) // Clean up expired code
		return nil, models.ErrInvalidGrant
	}

	// Validate client ID
	if authCode.ClientID.String() != clientID {
		return nil, models.ErrInvalidGrant
	}

	// Validate redirect URI
	if authCode.RedirectURI != redirectURI {
		return nil, models.ErrInvalidGrant
	}

	// Validate PKCE if present
	if authCode.CodeChallenge != "" {
		if !s.ValidatePKCE(codeVerifier, authCode.CodeChallenge, authCode.CodeChallengeMethod) {
			return nil, models.ErrInvalidGrant
		}
	}

	// Generate tokens
	tokenResponse, err := s.GenerateTokens(ctx, tenantID, authCode.ClientID, authCode.UserID, authCode.Scope, true)
	if err != nil {
		return nil, err
	}

	// Delete used authorization code
	s.repos.AuthCode.Delete(ctx, tenantID, code)

	s.logger.WithFields(logrus.Fields{
		"tenant_id": tenantID,
		"client_id": clientID,
		"user_id":   authCode.UserID,
	}).Info("authorization code exchanged for tokens")

	return tokenResponse, nil
}

func (s *authServiceImpl) GenerateTokens(ctx context.Context, tenantID, clientID, userID uuid.UUID, scope string, includeIDToken bool) (*models.TokenResponse, error) {
	// Generate access token
	accessToken, err := s.generateJWT(tenantID, clientID, userID, scope, s.config.AccessTokenDuration)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	// Generate refresh token
	refreshTokenStr, err := s.generateRandomString(64)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// Store refresh token
	refreshToken := &models.RefreshToken{
		ID:        uuid.New(),
		TenantID:  tenantID,
		Token:     refreshTokenStr,
		ClientID:  clientID,
		UserID:    userID,
		ExpiresAt: time.Now().Add(s.config.RefreshTokenDuration),
	}

	if err := s.repos.RefreshToken.Create(ctx, refreshToken); err != nil {
		return nil, fmt.Errorf("failed to store refresh token: %w", err)
	}

	// Store access token for introspection
	accessTokenRecord := &models.AccessToken{
		ID:        uuid.New(),
		TenantID:  tenantID,
		Token:     accessToken,
		ClientID:  clientID,
		UserID:    userID,
		Scope:     scope,
		ExpiresAt: time.Now().Add(s.config.AccessTokenDuration),
	}

	if err := s.repos.AccessToken.Create(ctx, accessTokenRecord); err != nil {
		return nil, fmt.Errorf("failed to store access token: %w", err)
	}

	response := &models.TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(s.config.AccessTokenDuration.Seconds()),
		RefreshToken: refreshTokenStr,
		Scope:        scope,
	}

	// Generate ID token if requested and scope includes openid
	if includeIDToken && contains(scope, "openid") {
		user, err := s.repos.User.GetByID(ctx, tenantID, userID)
		if err == nil {
			idToken, err := s.GenerateIDToken(ctx, user, clientID.String())
			if err == nil {
				response.IDToken = idToken
			}
		}
	}

	return response, nil
}

func (s *authServiceImpl) RefreshTokens(ctx context.Context, tenantID uuid.UUID, refreshToken, clientID, clientSecret string) (*models.TokenResponse, error) {
	// Get refresh token
	token, err := s.repos.RefreshToken.GetByToken(ctx, tenantID, refreshToken)
	if err != nil {
		return nil, models.ErrInvalidGrant
	}

	// Check if token is expired
	if token.IsExpired() {
		s.repos.RefreshToken.Delete(ctx, tenantID, refreshToken)
		return nil, models.ErrInvalidGrant
	}

	// Validate client
	if token.ClientID.String() != clientID {
		return nil, models.ErrInvalidGrant
	}

	// Generate new tokens
	tokenResponse, err := s.GenerateTokens(ctx, tenantID, token.ClientID, token.UserID, "", false)
	if err != nil {
		return nil, err
	}

	// Delete old refresh token
	s.repos.RefreshToken.Delete(ctx, tenantID, refreshToken)

	return tokenResponse, nil
}

func (s *authServiceImpl) RevokeToken(ctx context.Context, tenantID uuid.UUID, token, tokenTypeHint string) error {
	// Try to revoke as refresh token first
	if tokenTypeHint == "refresh_token" || tokenTypeHint == "" {
		if err := s.repos.RefreshToken.Delete(ctx, tenantID, token); err == nil {
			return nil
		}
	}

	// Try to revoke as access token
	if tokenTypeHint == "access_token" || tokenTypeHint == "" {
		if err := s.repos.AccessToken.Delete(ctx, tenantID, token); err == nil {
			return nil
		}
	}

	// Token not found, but that's OK per RFC
	return nil
}

func (s *authServiceImpl) IntrospectToken(ctx context.Context, tenantID uuid.UUID, token string) (*models.IntrospectionResponse, error) {
	// Try to find as access token
	accessToken, err := s.repos.AccessToken.GetByToken(ctx, tenantID, token)
	if err == nil {
		return &models.IntrospectionResponse{
			Active:   !accessToken.IsExpired(),
			Scope:    accessToken.Scope,
			ClientID: accessToken.ClientID.String(),
			UserID:   accessToken.UserID.String(),
			Exp:      accessToken.ExpiresAt.Unix(),
			Iat:      accessToken.CreatedAt.Unix(),
		}, nil
	}

	// Try to validate as JWT
	claims, err := s.ValidateAccessToken(ctx, tenantID, token)
	if err == nil {
		return &models.IntrospectionResponse{
			Active:   true,
			Scope:    "", // Would need to be stored in JWT claims
			ClientID: claims.ClientID,
			UserID:   claims.UserID,
			Exp:      claims.Exp,
			Iat:      claims.Iat,
		}, nil
	}

	return &models.IntrospectionResponse{Active: false}, nil
}

func (s *authServiceImpl) ValidateAccessToken(ctx context.Context, tenantID uuid.UUID, tokenString string) (*models.JWTClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &models.JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.config.JWTSecret), nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*models.JWTClaims); ok && token.Valid {
		// Validate tenant
		if claims.TenantID != tenantID.String() {
			return nil, models.ErrTenantMismatch
		}
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}

func (s *authServiceImpl) ValidatePKCE(codeVerifier, codeChallenge, method string) bool {
	if method != "S256" {
		return false
	}

	// SHA256 hash of code_verifier
	hash := sha256.Sum256([]byte(codeVerifier))
	// Base64URL encode
	computed := base64.RawURLEncoding.EncodeToString(hash[:])

	return computed == codeChallenge
}

func (s *authServiceImpl) GenerateIDToken(ctx context.Context, user *models.User, clientID string) (string, error) {
	claims := &models.JWTClaims{
		Sub:      user.ID.String(),
		Aud:      clientID,
		Iss:      s.config.ServerURL,
		Exp:      time.Now().Add(1 * time.Hour).Unix(),
		Iat:      time.Now().Unix(),
		TenantID: user.TenantID.String(),
		Email:    user.Email,
		Name:     user.Username,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.config.JWTSecret))
}

func (s *authServiceImpl) GetUserInfo(ctx context.Context, tenantID uuid.UUID, accessToken string) (*models.UserInfo, error) {
	// Validate access token
	claims, err := s.ValidateAccessToken(ctx, tenantID, accessToken)
	if err != nil {
		return nil, err
	}

	// Get user
	userID, err := uuid.Parse(claims.UserID)
	if err != nil {
		return nil, err
	}

	user, err := s.repos.User.GetByID(ctx, tenantID, userID)
	if err != nil {
		return nil, err
	}

	return &models.UserInfo{
		Sub:           user.ID.String(),
		Name:          user.Username,
		Email:         user.Email,
		EmailVerified: true, // Assume verified for now
	}, nil
}

func (s *authServiceImpl) GetDiscoveryDocument(ctx context.Context) (*models.OpenIDConfiguration, error) {
	return &models.OpenIDConfiguration{
		Issuer:                           s.config.ServerURL,
		AuthorizationEndpoint:            s.config.ServerURL + "/oauth/authorize",
		TokenEndpoint:                    s.config.ServerURL + "/oauth/token",
		UserInfoEndpoint:                 s.config.ServerURL + "/userinfo",
		JwksURI:                          s.config.ServerURL + "/.well-known/jwks.json",
		ResponseTypesSupported:           []string{"code"},
		SubjectTypesSupported:            []string{"public"},
		IDTokenSigningAlgValuesSupported: []string{"HS256"},
		ScopesSupported:                  []string{"openid", "profile", "email", "read", "write"},
		ClaimsSupported:                  []string{"sub", "name", "email", "email_verified"},
	}, nil
}

// Logout revokes the given access token and all associated refresh tokens for the
// user+client pair encoded in the JWT. This ensures that after logout, both the
// access token DB record and all refresh tokens are removed so that the
// RequireAuth DB-blacklist check will reject further use of the token.
func (s *authServiceImpl) Logout(ctx context.Context, tenantID uuid.UUID, tokenString string) error {
	// Delete the access token from the DB (this is the primary blacklist mechanism).
	if err := s.repos.AccessToken.Delete(ctx, tenantID, tokenString); err != nil {
		s.logger.WithError(err).WithField("tenant_id", tenantID).Warn("logout: failed to delete access token")
	}

	// Parse the JWT to retrieve user + client so we can clean up refresh tokens.
	claims, err := s.ValidateAccessToken(ctx, tenantID, tokenString)
	if err == nil {
		if userID, parseErr := uuid.Parse(claims.UserID); parseErr == nil && userID != uuid.Nil {
			if delErr := s.repos.RefreshToken.DeleteByUserID(ctx, tenantID, userID); delErr != nil {
				s.logger.WithError(delErr).WithField("user_id", userID).Warn("logout: failed to delete refresh tokens")
			}
		}
	}

	s.logger.WithField("tenant_id", tenantID).Info("user logged out, tokens revoked")
	return nil
}

func (s *authServiceImpl) CleanupExpiredTokens(ctx context.Context) error {
	if err := s.repos.AuthCode.DeleteExpired(ctx); err != nil {
		s.logger.WithError(err).Error("failed to cleanup expired authorization codes")
	}

	if err := s.repos.AccessToken.DeleteExpired(ctx); err != nil {
		s.logger.WithError(err).Error("failed to cleanup expired access tokens")
	}

	if err := s.repos.RefreshToken.DeleteExpired(ctx); err != nil {
		s.logger.WithError(err).Error("failed to cleanup expired refresh tokens")
	}

	return nil
}

// Helper methods

func (s *authServiceImpl) generateJWT(tenantID, clientID, userID uuid.UUID, scope string, duration time.Duration) (string, error) {
	claims := &models.JWTClaims{
		Sub:      userID.String(),
		Aud:      clientID.String(),
		Iss:      s.config.ServerURL,
		Exp:      time.Now().Add(duration).Unix(),
		Iat:      time.Now().Unix(),
		TenantID: tenantID.String(),
		Scope:    scope,
		ClientID: clientID.String(),
		UserID:   userID.String(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.config.JWTSecret))
}

func (s *authServiceImpl) generateRandomString(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

// Helper function
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr ||
		(len(s) > len(substr) && (s[:len(substr)+1] == substr+" " ||
			s[len(s)-len(substr)-1:] == " "+substr ||
			len(s) > len(substr)*2 && s[len(s)-len(substr):] == substr)))
}
