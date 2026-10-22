package services

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"time"

	"shieldgate/config"
	"shieldgate/internal/jwtkeys"
	"shieldgate/internal/models"
	"shieldgate/internal/repo"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type authServiceImpl struct {
	repos  *repo.Repositories
	config *config.Config
	keys   *jwtkeys.KeySet
	logger *logrus.Logger
}

// NewAuthService creates a new auth service implementation. keys signs every
// issued JWT and verifies presented ones.
func NewAuthService(repos *repo.Repositories, config *config.Config, keys *jwtkeys.KeySet, logger *logrus.Logger) AuthService {
	return &authServiceImpl{
		repos:  repos,
		config: config,
		keys:   keys,
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
	auth := authContext{authTime: authCode.AuthTime, nonce: authCode.Nonce}
	tokenResponse, err := s.issueTokens(ctx, tenantID, authCode.ClientID, authCode.UserID, authCode.Scope, authCode.ID, true, true, auth)
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
	return s.issueTokens(ctx, tenantID, clientID, userID, scope, uuid.New(), true, includeIDToken, authContext{})
}

func (s *authServiceImpl) GenerateClientCredentialsTokens(ctx context.Context, tenantID uuid.UUID, client *models.Client, scope string) (*models.TokenResponse, error) {
	// RFC 6749 §4.4.3: no refresh token for the client credentials grant.
	// The subject of the token is the client itself.
	accessToken, err := s.generateJWTWithSubject(client.ID.String(), tenantID, client.ID, uuid.Nil, scope, s.config.AccessTokenDuration)
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
// the given rotation family, plus an ID token when requested and the scope
// includes openid. Only token hashes are persisted.
func (s *authServiceImpl) issueTokens(ctx context.Context, tenantID, clientID, userID uuid.UUID, scope string, familyID uuid.UUID, includeRefreshToken, includeIDToken bool, auth authContext) (*models.TokenResponse, error) {
	// Generate access token
	accessToken, err := s.generateJWT(tenantID, clientID, userID, scope, s.config.AccessTokenDuration)
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
			AuthTime:  auth.authTime,
			ExpiresAt: time.Now().Add(s.config.RefreshTokenDuration),
		}
		if err := s.repos.RefreshToken.Create(ctx, refreshToken); err != nil {
			return nil, fmt.Errorf("failed to store refresh token: %w", err)
		}
		response.RefreshToken = refreshTokenStr
	}

	// An openid request must yield an ID token (OIDC Core §3.1.3.3), so a
	// failure here fails the whole grant rather than silently dropping it
	if includeIDToken && ScopeContains(scope, ScopeOpenID) {
		user, err := s.repos.User.GetByID(ctx, tenantID, userID)
		if err != nil {
			return nil, fmt.Errorf("failed to load user for ID token: %w", err)
		}
		// The audience is the client's public client_id, which is what the
		// relying party compares aud against
		client, err := s.repos.Client.GetByID(ctx, tenantID, clientID)
		if err != nil {
			return nil, fmt.Errorf("failed to load client for ID token: %w", err)
		}
		idToken, err := s.GenerateIDToken(ctx, user, &models.IDTokenParams{
			ClientID:    client.ClientID,
			Scope:       scope,
			Nonce:       auth.nonce,
			AuthTime:    auth.authTime,
			AccessToken: accessToken,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to generate ID token: %w", err)
		}
		response.IDToken = idToken
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
	// No nonce on refresh; auth_time stays the original authentication time
	tokenResponse, err := s.issueTokens(ctx, tenantID, token.ClientID, token.UserID, scope, token.FamilyID, true, true, authContext{authTime: token.AuthTime})
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
	token, err := s.keys.Parse(tokenString, &models.JWTClaims{},
		jwt.WithIssuer(s.config.ServerURL), jwt.WithExpirationRequired())
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

func (s *authServiceImpl) GenerateIDToken(ctx context.Context, user *models.User, params *models.IDTokenParams) (string, error) {
	now := time.Now()
	claims := &models.IDTokenClaims{
		UserInfo: userClaimsForScope(user, params.Scope),
		Iss:      s.config.ServerURL,
		Aud:      params.ClientID,
		Exp:      now.Add(s.config.IDTokenDuration).Unix(),
		Iat:      now.Unix(),
		Nonce:    params.Nonce,
		TenantID: user.TenantID.String(),
	}
	if params.AuthTime != nil && !params.AuthTime.IsZero() {
		claims.AuthTime = params.AuthTime.Unix()
	}
	if params.AccessToken != "" {
		claims.AtHash = s.keys.TokenHash(params.AccessToken)
	}

	return s.keys.Sign(claims)
}

func (s *authServiceImpl) GetUserInfo(ctx context.Context, tenantID uuid.UUID, accessToken string) (*models.UserInfo, error) {
	claims, err := s.ValidateAccessToken(ctx, tenantID, accessToken)
	if err != nil {
		return nil, err
	}

	// UserInfo is an OIDC resource: the token must carry the openid scope
	// (OIDC Core §5.3), and claims are released per granted scope (§5.4)
	if !ScopeContains(claims.Scope, ScopeOpenID) {
		return nil, models.ErrInsufficientScope
	}

	userID, err := uuid.Parse(claims.UserID)
	if err != nil {
		return nil, models.ErrInvalidToken
	}

	user, err := s.repos.User.GetByID(ctx, tenantID, userID)
	if err != nil {
		return nil, err
	}

	info := userClaimsForScope(user, claims.Scope)
	return &info, nil
}

func (s *authServiceImpl) GetDiscoveryDocument(ctx context.Context) (*models.OpenIDConfiguration, error) {
	base := s.config.ServerURL
	clientAuthMethods := []string{"client_secret_basic", "client_secret_post"}

	return &models.OpenIDConfiguration{
		Issuer:                      base,
		AuthorizationEndpoint:       base + "/oauth/authorize",
		TokenEndpoint:               base + "/oauth/token",
		UserInfoEndpoint:            base + "/userinfo",
		JwksURI:                     base + "/.well-known/jwks.json",
		RevocationEndpoint:          base + "/oauth/revoke",
		IntrospectionEndpoint:       base + "/oauth/introspect",
		DeviceAuthorizationEndpoint: base + "/oauth/device_authorization",
		EndSessionEndpoint:          base + "/oauth/logout",
		ScopesSupported:             []string{ScopeOpenID, ScopeProfile, ScopeEmail, ScopePhone, "read", "write"},
		ResponseTypesSupported:      []string{"code"},
		ResponseModesSupported:      []string{"query"},
		GrantTypesSupported: []string{
			"authorization_code",
			"refresh_token",
			"client_credentials",
			models.GrantTypeDeviceCode,
			models.GrantTypeTokenExchange,
		},
		SubjectTypesSupported:            []string{"public"},
		IDTokenSigningAlgValuesSupported: []string{s.keys.Algorithm()},
		// "none" covers public clients, which authenticate with PKCE instead
		TokenEndpointAuthMethodsSupported:         append(append([]string{}, clientAuthMethods...), "none"),
		RevocationEndpointAuthMethodsSupported:    clientAuthMethods,
		IntrospectionEndpointAuthMethodsSupported: clientAuthMethods,
		CodeChallengeMethodsSupported:             []string{"S256"},
		PromptValuesSupported:                     []string{"none", "login", "consent", "select_account"},
		ClaimsSupported: []string{
			"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "at_hash", "tenant_id",
			"name", "given_name", "family_name", "preferred_username", "picture", "locale", "zoneinfo", "updated_at",
			"email", "email_verified",
			"phone_number", "phone_number_verified",
		},
		// request_uri_parameter_supported defaults to true when omitted
		// (OIDC Discovery §3), so every unsupported feature is stated
		ClaimsParameterSupported:                   false,
		RequestParameterSupported:                  false,
		RequestURIParameterSupported:               false,
		AuthorizationResponseIssParameterSupported: true,
	}, nil
}

func (s *authServiceImpl) ParseIDTokenHint(ctx context.Context, idToken string) (*models.IDTokenClaims, error) {
	// An id_token_hint may be expired (OIDC RP-Initiated Logout §2), so only
	// the signature and issuer are checked, not the time-based claims
	claims := &models.IDTokenClaims{}
	if _, err := s.keys.Parse(idToken, claims, jwt.WithoutClaimsValidation()); err != nil {
		return nil, models.ErrInvalidToken
	}
	if claims.Iss != s.config.ServerURL {
		return nil, models.ErrInvalidToken
	}
	return claims, nil
}

func (s *authServiceImpl) GetJWKS(ctx context.Context) (*jwtkeys.JWKSet, error) {
	set := s.keys.JWKS()
	return &set, nil
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

	if s.repos.EmailVerification != nil {
		if err := s.repos.EmailVerification.DeleteExpired(ctx); err != nil {
			s.logger.WithError(err).Error("failed to cleanup expired email verifications")
		}
	}

	if s.repos.PasswordReset != nil {
		if err := s.repos.PasswordReset.DeleteExpired(ctx); err != nil {
			s.logger.WithError(err).Error("failed to cleanup expired password resets")
		}
	}

	return nil
}

// Helper methods

func (s *authServiceImpl) generateJWT(tenantID, clientID, userID uuid.UUID, scope string, duration time.Duration) (string, error) {
	return s.generateJWTWithSubject(userID.String(), tenantID, clientID, userID, scope, duration)
}

func (s *authServiceImpl) generateJWTWithSubject(subject string, tenantID, clientID, userID uuid.UUID, scope string, duration time.Duration) (string, error) {
	claims := &models.JWTClaims{
		Jti:      uuid.NewString(),
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

	return s.keys.Sign(claims)
}

func (s *authServiceImpl) generateRandomString(length int) (string, error) {
	return randomToken(length)
}

// randomToken returns length bytes from crypto/rand, base64url-encoded
func randomToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}
