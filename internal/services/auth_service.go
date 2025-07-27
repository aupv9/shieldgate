package services

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"shield1/config"
	"shield1/internal/database"
	"shield1/internal/models"
)

// AuthService handles OAuth 2.0 authentication and authorization
type AuthService struct {
	db     *gorm.DB
	redis  *database.RedisClient
	config *config.Config
}

// NewAuthService creates a new AuthService instance
func NewAuthService(db *gorm.DB, redis *database.RedisClient, cfg *config.Config) *AuthService {
	return &AuthService{
		db:     db,
		redis:  redis,
		config: cfg,
	}
}

// GenerateAuthorizationCode generates a new authorization code
func (s *AuthService) GenerateAuthorizationCode(clientID, userID uuid.UUID, redirectURI, scope, codeChallenge, codeChallengeMethod string) (*models.AuthorizationCode, error) {
	// Generate random code
	code, err := s.generateRandomString(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate authorization code: %w", err)
	}

	authCode := &models.AuthorizationCode{
		ID:                  uuid.New(),
		Code:                code,
		ClientID:            clientID,
		UserID:              userID,
		RedirectURI:         redirectURI,
		Scope:               scope,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		ExpiresAt:           time.Now().Add(s.config.AuthorizationCodeDuration),
		CreatedAt:           time.Now(),
	}

	// Store in database using GORM
	if err := s.db.Create(authCode).Error; err != nil {
		return nil, fmt.Errorf("failed to store authorization code: %w", err)
	}

	return authCode, nil
}

// ValidateAuthorizationCode validates and consumes an authorization code
func (s *AuthService) ValidateAuthorizationCode(code, clientID, redirectURI, codeVerifier string) (*models.AuthorizationCode, error) {
	var authCode models.AuthorizationCode

	// Find authorization code using GORM
	err := s.db.Where("code = ? AND client_id = ?", code, clientID).First(&authCode).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("invalid authorization code")
		}
		return nil, fmt.Errorf("failed to validate authorization code: %w", err)
	}

	// Check if code is expired
	if authCode.IsExpired() {
		s.deleteAuthorizationCode(authCode.Code)
		return nil, fmt.Errorf("authorization code expired")
	}

	// Validate redirect URI
	if authCode.RedirectURI != redirectURI {
		return nil, fmt.Errorf("invalid redirect URI")
	}

	// Validate PKCE if present
	if authCode.CodeChallenge != "" {
		if codeVerifier == "" {
			return nil, fmt.Errorf("code verifier required")
		}

		if !s.validatePKCE(authCode.CodeChallenge, authCode.CodeChallengeMethod, codeVerifier) {
			return nil, fmt.Errorf("invalid code verifier")
		}
	}

	// Delete the authorization code (one-time use)
	s.deleteAuthorizationCode(authCode.Code)

	return &authCode, nil
}

// GenerateTokens generates access token, refresh token, and optionally ID token
func (s *AuthService) GenerateTokens(clientID, userID uuid.UUID, scope string, includeIDToken bool) (*models.TokenResponse, error) {
	// Generate access token
	accessToken, err := s.generateJWT(clientID, userID, scope, s.config.AccessTokenDuration)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	// Generate refresh token
	refreshTokenStr, err := s.generateRandomString(64)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// Store access token using GORM
	accessTokenModel := &models.AccessToken{
		ID:        uuid.New(),
		Token:     accessToken,
		ClientID:  clientID,
		UserID:    userID,
		Scope:     scope,
		ExpiresAt: time.Now().Add(s.config.AccessTokenDuration),
		CreatedAt: time.Now(),
	}

	if err := s.db.Create(accessTokenModel).Error; err != nil {
		return nil, fmt.Errorf("failed to store access token: %w", err)
	}

	// Store refresh token using GORM
	refreshTokenModel := &models.RefreshToken{
		ID:        uuid.New(),
		Token:     refreshTokenStr,
		ClientID:  clientID,
		UserID:    userID,
		ExpiresAt: time.Now().Add(s.config.RefreshTokenDuration),
		CreatedAt: time.Now(),
	}

	if err := s.db.Create(refreshTokenModel).Error; err != nil {
		return nil, fmt.Errorf("failed to store refresh token: %w", err)
	}

	response := &models.TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(s.config.AccessTokenDuration.Seconds()),
		RefreshToken: refreshTokenStr,
		Scope:        scope,
	}

	// Generate ID token if requested (OpenID Connect)
	if includeIDToken && strings.Contains(scope, "openid") {
		idToken, err := s.generateIDToken(clientID, userID, scope)
		if err != nil {
			logrus.Errorf("Failed to generate ID token: %v", err)
		} else {
			response.IDToken = idToken
		}
	}

	return response, nil
}

// ValidateAccessToken validates an access token
func (s *AuthService) ValidateAccessToken(tokenString string) (*models.JWTClaims, error) {
	// Parse and validate JWT
	token, err := jwt.ParseWithClaims(tokenString, &models.JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.config.JWTSecret), nil
	})

	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	claims, ok := token.Claims.(*models.JWTClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	// Check if token exists in database using GORM
	var accessToken models.AccessToken
	err = s.db.Where("token = ? AND expires_at > ?", tokenString, time.Now()).First(&accessToken).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("token not found or expired")
		}
		return nil, fmt.Errorf("failed to validate token: %w", err)
	}

	return claims, nil
}

// RefreshAccessToken refreshes an access token using a refresh token
func (s *AuthService) RefreshAccessToken(refreshTokenStr string) (*models.TokenResponse, error) {
	var refreshToken models.RefreshToken

	// Validate refresh token using GORM
	err := s.db.Where("token = ?", refreshTokenStr).First(&refreshToken).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("invalid refresh token")
		}
		return nil, fmt.Errorf("failed to validate refresh token: %w", err)
	}

	// Check if refresh token is expired
	if refreshToken.IsExpired() {
		s.deleteRefreshToken(refreshToken.Token)
		return nil, fmt.Errorf("refresh token expired")
	}

	// Get original scope from the most recent access token using GORM
	var accessToken models.AccessToken
	var scope string
	err = s.db.Where("client_id = ? AND user_id = ?", refreshToken.ClientID, refreshToken.UserID).
		Order("created_at DESC").First(&accessToken).Error
	if err != nil {
		scope = "" // Default to empty scope if not found
	} else {
		scope = accessToken.Scope
	}

	// Generate new tokens
	return s.GenerateTokens(refreshToken.ClientID, refreshToken.UserID, scope, strings.Contains(scope, "openid"))
}

// RevokeToken revokes an access or refresh token
func (s *AuthService) RevokeToken(tokenString, tokenTypeHint string) error {
	if tokenTypeHint == "refresh_token" || tokenTypeHint == "" {
		// Try to revoke as refresh token first using GORM
		result := s.db.Where("token = ?", tokenString).Delete(&models.RefreshToken{})
		if result.Error == nil && result.RowsAffected > 0 {
			return nil
		}
	}

	if tokenTypeHint == "access_token" || tokenTypeHint == "" {
		// Try to revoke as access token using GORM
		result := s.db.Where("token = ?", tokenString).Delete(&models.AccessToken{})
		if result.Error == nil && result.RowsAffected > 0 {
			return nil
		}
	}

	return fmt.Errorf("token not found")
}

// IntrospectToken returns information about a token
func (s *AuthService) IntrospectToken(tokenString string) (*models.IntrospectionResponse, error) {
	// Try to validate as JWT first
	claims, err := s.ValidateAccessToken(tokenString)
	if err == nil {
		return &models.IntrospectionResponse{
			Active:   true,
			Scope:    claims.Scope,
			ClientID: claims.ClientID,
			UserID:   claims.UserID,
			Exp:      claims.Exp,
			Iat:      claims.Iat,
		}, nil
	}

	// If JWT validation fails, check database using GORM
	var accessToken models.AccessToken
	err = s.db.Where("token = ?", tokenString).First(&accessToken).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return &models.IntrospectionResponse{Active: false}, nil
		}
		return nil, fmt.Errorf("failed to introspect token: %w", err)
	}

	// Check if token is expired
	if time.Now().After(accessToken.ExpiresAt) {
		return &models.IntrospectionResponse{Active: false}, nil
	}

	return &models.IntrospectionResponse{
		Active:   true,
		Scope:    accessToken.Scope,
		ClientID: accessToken.ClientID.String(),
		UserID:   accessToken.UserID.String(),
		Exp:      accessToken.ExpiresAt.Unix(),
		Iat:      accessToken.CreatedAt.Unix(),
	}, nil
}

// GetUserInfo returns user information for OpenID Connect
func (s *AuthService) GetUserInfo(userID uuid.UUID) (*models.UserInfo, error) {
	var user models.User
	err := s.db.Where("id = ?", userID).First(&user).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}

	return &models.UserInfo{
		Sub:           user.ID.String(),
		Name:          user.Username,
		Email:         user.Email,
		EmailVerified: true, // Assuming email is verified
	}, nil
}

// AuthenticateUser authenticates a user with username/email and password
func (s *AuthService) AuthenticateUser(usernameOrEmail, password string) (*models.User, error) {
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

	return &user, nil
}

// Helper methods

func (s *AuthService) generateJWT(clientID, userID uuid.UUID, scope string, duration time.Duration) (string, error) {
	now := time.Now()
	claims := &models.JWTClaims{
		Sub:      userID.String(),
		Aud:      clientID.String(),
		Iss:      s.config.ServerURL,
		Exp:      now.Add(duration).Unix(),
		Iat:      now.Unix(),
		Scope:    scope,
		ClientID: clientID.String(),
		UserID:   userID.String(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.config.JWTSecret))
}

func (s *AuthService) generateIDToken(clientID, userID uuid.UUID, scope string) (string, error) {
	// Get user info
	userInfo, err := s.GetUserInfo(userID)
	if err != nil {
		return "", err
	}

	now := time.Now()
	claims := &models.JWTClaims{
		Sub:   userInfo.Sub,
		Aud:   clientID.String(),
		Iss:   s.config.ServerURL,
		Exp:   now.Add(time.Hour).Unix(), // ID tokens typically have shorter expiration
		Iat:   now.Unix(),
		Email: userInfo.Email,
		Name:  userInfo.Name,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.config.JWTSecret))
}

func (s *AuthService) generateRandomString(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes)[:length], nil
}

func (s *AuthService) validatePKCE(codeChallenge, codeChallengeMethod, codeVerifier string) bool {
	switch codeChallengeMethod {
	case "S256":
		hash := sha256.Sum256([]byte(codeVerifier))
		expected := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(hash[:])
		return codeChallenge == expected
	case "plain":
		return codeChallenge == codeVerifier
	default:
		return false
	}
}

func (s *AuthService) deleteAuthorizationCode(code string) {
	if err := s.db.Where("code = ?", code).Delete(&models.AuthorizationCode{}).Error; err != nil {
		logrus.Errorf("Failed to delete authorization code: %v", err)
	}
}

func (s *AuthService) deleteRefreshToken(token string) {
	if err := s.db.Where("token = ?", token).Delete(&models.RefreshToken{}).Error; err != nil {
		logrus.Errorf("Failed to delete refresh token: %v", err)
	}
}
