package services

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"sync"
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

	// signing key cache (see signing_keys.go)
	keyMu      sync.RWMutex
	activeKey  *cachedSigningKey
	verifyKeys map[string]*rsa.PublicKey
}

// NewAuthService creates a new auth service implementation
func NewAuthService(repos *repo.Repositories, config *config.Config, logger *logrus.Logger) AuthService {
	return &authServiceImpl{
		repos:  repos,
		config: config,
		logger: logger,
	}
}

// hashToken returns the SHA-256 hash of a token, base64url-encoded. Only
// hashes are persisted so a database leak does not expose usable tokens.
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func (s *authServiceImpl) GenerateAuthorizationCode(ctx context.Context, tenantID, clientID, userID uuid.UUID, redirectURI, scope, codeChallenge, codeChallengeMethod, nonce string, authTime time.Time) (*models.AuthorizationCode, error) {
	// Generate random code
	code, err := s.generateRandomString(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate authorization code: %w", err)
	}

	// Create authorization code
	now := time.Now()
	if authTime.IsZero() {
		authTime = now
	}
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
		Nonce:               nonce,
		AuthTime:            &authTime,
		ExpiresAt:           now.Add(s.config.AuthorizationCodeDuration),
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
	// Atomically consume the code — a concurrent second exchange sees
	// ErrAuthCodeAlreadyUsed instead of racing on read-then-delete
	authCode, err := s.repos.AuthCode.Consume(ctx, tenantID, code)
	if err != nil {
		if err == models.ErrAuthCodeAlreadyUsed && authCode != nil {
			// RFC 6749 §4.1.2: replayed code SHOULD revoke all tokens issued on it
			s.revokeTokenFamily(ctx, tenantID, authCode.ID)
			s.logger.WithFields(logrus.Fields{
				"tenant_id": tenantID,
				"client_id": authCode.ClientID,
				"user_id":   authCode.UserID,
			}).Warn("authorization code reuse detected — token family revoked")
		}
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
		if codeVerifier == "" {
			return nil, models.ErrPKCEVerificationFailed
		}
		if !s.ValidatePKCE(codeVerifier, authCode.CodeChallenge, authCode.CodeChallengeMethod) {
			return nil, models.ErrPKCEVerificationFailed
		}
	}

	// Generate tokens; the family is keyed by the authorization code so a
	// later code replay can revoke everything issued from it
	authTime := authCode.CreatedAt
	if authCode.AuthTime != nil {
		authTime = *authCode.AuthTime
	}
	tokenResponse, err := s.issueTokensWithIDContext(ctx, tenantID, authCode.ClientID, authCode.UserID, authCode.Scope, authCode.ID, true, true, authCode.Nonce, authTime)
	if err != nil {
		return nil, err
	}

	s.logger.WithFields(logrus.Fields{
		"tenant_id": tenantID,
		"client_id": clientID,
		"user_id":   authCode.UserID,
	}).Info("authorization code exchanged for tokens")

	return tokenResponse, nil
}

func (s *authServiceImpl) GenerateTokens(ctx context.Context, tenantID, clientID, userID uuid.UUID, scope string, includeIDToken bool) (*models.TokenResponse, error) {
	return s.issueTokens(ctx, tenantID, clientID, userID, scope, uuid.New(), true, includeIDToken)
}

func (s *authServiceImpl) GenerateClientCredentialsTokens(ctx context.Context, tenantID uuid.UUID, client *models.Client, scope string) (*models.TokenResponse, error) {
	// RFC 6749 §4.4.3: no refresh token for the client credentials grant.
	// The subject of the token is the client itself.
	accessToken, err := s.generateJWTWithSubject(ctx, client.ID.String(), tenantID, client.ID, uuid.Nil, scope, s.config.AccessTokenDuration)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	accessTokenRecord := &models.AccessToken{
		ID:        uuid.New(),
		TenantID:  tenantID,
		Token:     hashToken(accessToken),
		ClientID:  client.ID,
		UserID:    uuid.Nil,
		FamilyID:  uuid.New(),
		Scope:     scope,
		ExpiresAt: time.Now().Add(s.config.AccessTokenDuration),
	}
	if err := s.repos.AccessToken.Create(ctx, accessTokenRecord); err != nil {
		return nil, fmt.Errorf("failed to store access token: %w", err)
	}

	return &models.TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int64(s.config.AccessTokenDuration.Seconds()),
		Scope:       scope,
	}, nil
}

// issueTokens creates an access token (and optionally a refresh token) within
// the given rotation family. Only token hashes are persisted.
func (s *authServiceImpl) issueTokens(ctx context.Context, tenantID, clientID, userID uuid.UUID, scope string, familyID uuid.UUID, includeRefreshToken, includeIDToken bool) (*models.TokenResponse, error) {
	return s.issueTokensWithIDContext(ctx, tenantID, clientID, userID, scope, familyID, includeRefreshToken, includeIDToken, "", time.Time{})
}

// issueTokensWithIDContext additionally threads the OIDC nonce and auth_time
// into the ID token when one is issued
func (s *authServiceImpl) issueTokensWithIDContext(ctx context.Context, tenantID, clientID, userID uuid.UUID, scope string, familyID uuid.UUID, includeRefreshToken, includeIDToken bool, nonce string, authTime time.Time) (*models.TokenResponse, error) {
	// Generate access token
	accessToken, err := s.generateJWT(ctx, tenantID, clientID, userID, scope, s.config.AccessTokenDuration)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	// Store access token (hashed) for introspection and revocation enforcement
	accessTokenRecord := &models.AccessToken{
		ID:        uuid.New(),
		TenantID:  tenantID,
		Token:     hashToken(accessToken),
		ClientID:  clientID,
		UserID:    userID,
		FamilyID:  familyID,
		Scope:     scope,
		ExpiresAt: time.Now().Add(s.config.AccessTokenDuration),
	}
	if err := s.repos.AccessToken.Create(ctx, accessTokenRecord); err != nil {
		return nil, fmt.Errorf("failed to store access token: %w", err)
	}

	response := &models.TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int64(s.config.AccessTokenDuration.Seconds()),
		Scope:       scope,
	}

	if includeRefreshToken {
		refreshTokenStr, err := s.generateRandomString(64)
		if err != nil {
			return nil, fmt.Errorf("failed to generate refresh token: %w", err)
		}

		refreshToken := &models.RefreshToken{
			ID:        uuid.New(),
			TenantID:  tenantID,
			Token:     hashToken(refreshTokenStr),
			ClientID:  clientID,
			UserID:    userID,
			FamilyID:  familyID,
			Scope:     scope,
			ExpiresAt: time.Now().Add(s.config.RefreshTokenDuration),
		}
		if err := s.repos.RefreshToken.Create(ctx, refreshToken); err != nil {
			return nil, fmt.Errorf("failed to store refresh token: %w", err)
		}
		response.RefreshToken = refreshTokenStr
	}

	// Generate ID token if requested and scope includes openid
	if includeIDToken && ScopeContains(scope, "openid") {
		user, err := s.repos.User.GetByID(ctx, tenantID, userID)
		if err == nil {
			idToken, err := s.GenerateIDToken(ctx, user, clientID.String(), nonce, accessToken, authTime)
			if err == nil {
				response.IDToken = idToken
			}
		}
	}

	return response, nil
}

func (s *authServiceImpl) RefreshTokens(ctx context.Context, tenantID uuid.UUID, refreshToken, clientID, requestedScope string) (*models.TokenResponse, error) {
	// Get refresh token by hash
	token, err := s.repos.RefreshToken.GetByToken(ctx, tenantID, hashToken(refreshToken))
	if err != nil {
		return nil, models.ErrInvalidGrant
	}

	// Reuse detection: a rotated (revoked) token being replayed means the
	// token may be compromised — revoke the whole family
	if token.IsRevoked() {
		s.revokeTokenFamily(ctx, tenantID, token.FamilyID)
		s.logger.WithFields(logrus.Fields{
			"tenant_id": tenantID,
			"client_id": token.ClientID,
			"user_id":   token.UserID,
			"family_id": token.FamilyID,
		}).Warn("refresh token reuse detected — token family revoked")
		return nil, models.ErrInvalidGrant
	}

	// Check if token is expired
	if token.IsExpired() {
		s.repos.RefreshToken.Delete(ctx, tenantID, hashToken(refreshToken))
		return nil, models.ErrInvalidGrant
	}

	// Validate client binding
	if token.ClientID.String() != clientID {
		return nil, models.ErrInvalidGrant
	}

	// Scope narrowing: the new grant keeps the original scope unless the
	// client requests a subset (RFC 6749 §6)
	scope := token.Scope
	if requestedScope != "" {
		if !ScopeIsSubset(requestedScope, token.Scope) {
			return nil, models.ErrInvalidScope
		}
		scope = requestedScope
	}

	// Issue new tokens in the same family, then mark the old token rotated
	tokenResponse, err := s.issueTokens(ctx, tenantID, token.ClientID, token.UserID, scope, token.FamilyID, true, true)
	if err != nil {
		return nil, err
	}

	if err := s.repos.RefreshToken.Revoke(ctx, tenantID, hashToken(refreshToken)); err != nil {
		s.logger.WithError(err).Error("failed to mark rotated refresh token as revoked")
	}

	return tokenResponse, nil
}

func (s *authServiceImpl) RevokeToken(ctx context.Context, tenantID uuid.UUID, token, tokenTypeHint string, requestingClientID uuid.UUID) error {
	tokenHash := hashToken(token)

	// Try to revoke as refresh token first
	if tokenTypeHint == "refresh_token" || tokenTypeHint == "" {
		if refreshToken, err := s.repos.RefreshToken.GetByToken(ctx, tenantID, tokenHash); err == nil {
			// RFC 7009 §2.1: only the client the token was issued to may revoke it;
			// mismatches are treated as invalid tokens (still HTTP 200)
			if refreshToken.ClientID != requestingClientID {
				return nil
			}
			// Revoking a refresh token also invalidates related access tokens
			s.revokeTokenFamily(ctx, tenantID, refreshToken.FamilyID)
			return nil
		}
	}

	// Try to revoke as access token
	if tokenTypeHint == "access_token" || tokenTypeHint == "" {
		if accessToken, err := s.repos.AccessToken.GetByToken(ctx, tenantID, tokenHash); err == nil {
			if accessToken.ClientID != requestingClientID {
				return nil
			}
			if err := s.repos.AccessToken.Delete(ctx, tenantID, tokenHash); err != nil {
				s.logger.WithError(err).Error("failed to delete access token on revocation")
			}
			return nil
		}
	}

	// Token not found, but that's OK per RFC 7009
	return nil
}

// revokeTokenFamily deletes every access and refresh token issued in a family
func (s *authServiceImpl) revokeTokenFamily(ctx context.Context, tenantID, familyID uuid.UUID) {
	if err := s.repos.RefreshToken.DeleteByFamilyID(ctx, tenantID, familyID); err != nil {
		s.logger.WithError(err).Error("failed to revoke refresh token family")
	}
	if err := s.repos.AccessToken.DeleteByFamilyID(ctx, tenantID, familyID); err != nil {
		s.logger.WithError(err).Error("failed to revoke access token family")
	}
}

func (s *authServiceImpl) IntrospectToken(ctx context.Context, tenantID uuid.UUID, token string) (*models.IntrospectionResponse, error) {
	// Look up the stored (hashed) access token record — this covers both
	// revocation state and opaque token metadata
	accessToken, err := s.repos.AccessToken.GetByToken(ctx, tenantID, hashToken(token))
	if err != nil {
		return &models.IntrospectionResponse{Active: false}, nil
	}

	response := &models.IntrospectionResponse{
		Active:   !accessToken.IsExpired(),
		Scope:    accessToken.Scope,
		ClientID: accessToken.ClientID.String(),
		Exp:      accessToken.ExpiresAt.Unix(),
		Iat:      accessToken.CreatedAt.Unix(),
	}
	if accessToken.UserID != uuid.Nil {
		response.UserID = accessToken.UserID.String()
	}
	return response, nil
}

func (s *authServiceImpl) ValidateAccessToken(ctx context.Context, tenantID uuid.UUID, tokenString string) (*models.JWTClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &models.JWTClaims{}, s.verificationKeyfunc(ctx))

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*models.JWTClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	// Validate tenant
	if claims.TenantID != tenantID.String() {
		return nil, models.ErrTenantMismatch
	}

	// Enforce revocation: the signed token must still have a live record.
	// (repos may be nil in pure-function unit tests)
	if s.repos != nil && s.repos.AccessToken != nil {
		if _, err := s.repos.AccessToken.GetByToken(ctx, tenantID, hashToken(tokenString)); err != nil {
			return nil, models.ErrRevokedToken
		}
	}

	return claims, nil
}

func (s *authServiceImpl) ValidatePKCE(codeVerifier, codeChallenge, method string) bool {
	if method != "S256" {
		return false
	}

	// SHA256 hash of code_verifier
	hash := sha256.Sum256([]byte(codeVerifier))
	// Base64URL encode
	computed := base64.RawURLEncoding.EncodeToString(hash[:])

	return subtle.ConstantTimeCompare([]byte(computed), []byte(codeChallenge)) == 1
}

// GenerateIDToken builds an OIDC ID token: nonce is echoed back for replay
// protection (OIDC Core §3.1.3.7), at_hash binds the ID token to its access
// token (§3.1.3.6), auth_time records when the user actually authenticated.
func (s *authServiceImpl) GenerateIDToken(ctx context.Context, user *models.User, clientID, nonce, accessToken string, authTime time.Time) (string, error) {
	duration := s.config.IDTokenDuration
	if duration <= 0 {
		duration = time.Hour
	}

	now := time.Now()
	claims := &models.JWTClaims{
		Sub:      user.ID.String(),
		Aud:      clientID,
		Iss:      s.config.ServerURL,
		Exp:      now.Add(duration).Unix(),
		Iat:      now.Unix(),
		TenantID: user.TenantID.String(),
		Email:    user.Email,
		Name:     user.GetFullName(),
		Nonce:    nonce,
	}
	if !authTime.IsZero() {
		claims.AuthTime = authTime.Unix()
	}
	if accessToken != "" {
		claims.AtHash = computeAtHash(accessToken)
	}

	return s.signToken(ctx, claims)
}

// computeAtHash implements the OIDC at_hash: base64url of the left half of
// the SHA-256 digest of the access token (for RS256/HS256-signed tokens)
func computeAtHash(accessToken string) string {
	sum := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(sum[:16])
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

	// Release claims according to the scopes granted to the access token
	// (OIDC Core §5.4)
	info := &models.UserInfo{Sub: user.ID.String()}
	if ScopeContains(claims.Scope, "profile") {
		info.Name = user.GetFullName()
		info.GivenName = user.FirstName
		info.FamilyName = user.LastName
		info.PreferredUsername = user.Username
		info.Locale = user.Locale
		info.Zoneinfo = user.Timezone
	}
	if ScopeContains(claims.Scope, "email") {
		info.Email = user.Email
		info.EmailVerified = user.EmailVerified
	}
	return info, nil
}

func (s *authServiceImpl) GetDiscoveryDocument(ctx context.Context) (*models.OpenIDConfiguration, error) {
	signingAlgs := []string{"HS256"}
	if s.signingKeysAvailable() {
		signingAlgs = []string{"RS256"}
	}

	return &models.OpenIDConfiguration{
		Issuer:                      s.config.ServerURL,
		AuthorizationEndpoint:       s.config.ServerURL + "/oauth/authorize",
		TokenEndpoint:               s.config.ServerURL + "/oauth/token",
		UserInfoEndpoint:            s.config.ServerURL + "/userinfo",
		JwksURI:                     s.config.ServerURL + "/.well-known/jwks.json",
		DeviceAuthorizationEndpoint: s.config.ServerURL + "/oauth/device_authorization",
		RevocationEndpoint:          s.config.ServerURL + "/oauth/revoke",
		IntrospectionEndpoint:       s.config.ServerURL + "/oauth/introspect",
		EndSessionEndpoint:          s.config.ServerURL + "/oauth/logout",
		ResponseTypesSupported:      []string{"code"},
		GrantTypesSupported: []string{
			"authorization_code",
			"refresh_token",
			"client_credentials",
			models.GrantTypeDeviceCode,
			models.GrantTypeTokenExchange,
		},
		SubjectTypesSupported:             []string{"public"},
		IDTokenSigningAlgValuesSupported:  signingAlgs,
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic", "client_secret_post"},
		CodeChallengeMethodsSupported:     []string{"S256"},
		ScopesSupported:                   []string{"openid", "profile", "email", "read", "write"},
		ClaimsSupported:                   []string{"sub", "name", "given_name", "family_name", "preferred_username", "locale", "zoneinfo", "email", "email_verified", "auth_time", "nonce"},
	}, nil
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

	if s.repos.DeviceCode != nil {
		if err := s.repos.DeviceCode.DeleteExpired(ctx); err != nil {
			s.logger.WithError(err).Error("failed to cleanup expired device codes")
		}
	}

	if s.repos.Session != nil {
		if err := s.repos.Session.DeleteExpired(ctx); err != nil {
			s.logger.WithError(err).Error("failed to cleanup expired sessions")
		}
	}

	return nil
}

// Helper methods

func (s *authServiceImpl) generateJWT(ctx context.Context, tenantID, clientID, userID uuid.UUID, scope string, duration time.Duration) (string, error) {
	return s.generateJWTWithSubject(ctx, userID.String(), tenantID, clientID, userID, scope, duration)
}

func (s *authServiceImpl) generateJWTWithSubject(ctx context.Context, subject string, tenantID, clientID, userID uuid.UUID, scope string, duration time.Duration) (string, error) {
	claims := &models.JWTClaims{
		Sub:      subject,
		Aud:      clientID.String(),
		Iss:      s.config.ServerURL,
		Exp:      time.Now().Add(duration).Unix(),
		Iat:      time.Now().Unix(),
		TenantID: tenantID.String(),
		Scope:    scope,
		ClientID: clientID.String(),
	}
	if userID != uuid.Nil {
		claims.UserID = userID.String()
	}

	return s.signToken(ctx, claims)
}

func (s *authServiceImpl) generateRandomString(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}
