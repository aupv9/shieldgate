package services

// device_token_exchange.go implements the Device Authorization Grant
// (RFC 8628) and Token Exchange (RFC 8693) on top of authServiceImpl.

import (
	"context"
	"crypto/rand"
	"math/big"
	"strings"
	"time"

	"shieldgate/internal/models"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// userCodeCharset avoids vowels and ambiguous characters (0/O, 1/I, U/V)
// so codes are easy to read out and type (RFC 8628 §6.1)
const userCodeCharset = "BCDFGHJKLMNPQRSTVWXZ"

const userCodeLength = 8

// NormalizeUserCode canonicalizes a user-typed code: uppercase, separators removed
func NormalizeUserCode(code string) string {
	code = strings.ToUpper(strings.TrimSpace(code))
	code = strings.ReplaceAll(code, "-", "")
	return strings.ReplaceAll(code, " ", "")
}

// FormatUserCode renders a normalized user code for display (XXXX-XXXX)
func FormatUserCode(code string) string {
	if len(code) == userCodeLength {
		return code[:4] + "-" + code[4:]
	}
	return code
}

func generateUserCode() (string, error) {
	max := big.NewInt(int64(len(userCodeCharset)))
	b := make([]byte, userCodeLength)
	for i := range b {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		b[i] = userCodeCharset[n.Int64()]
	}
	return string(b), nil
}

func (s *authServiceImpl) CreateDeviceAuthorization(ctx context.Context, tenantID uuid.UUID, client *models.Client, scope string) (*models.DeviceAuthorizationResponse, error) {
	deviceCode, err := s.generateRandomString(48)
	if err != nil {
		return nil, err
	}
	userCode, err := generateUserCode()
	if err != nil {
		return nil, err
	}

	interval := s.config.DeviceCodePollInterval
	if interval <= 0 {
		interval = 5
	}
	duration := s.config.DeviceCodeDuration
	if duration <= 0 {
		duration = 10 * time.Minute
	}

	record := &models.DeviceCode{
		ID:         uuid.New(),
		TenantID:   tenantID,
		DeviceCode: hashToken(deviceCode),
		UserCode:   userCode,
		ClientID:   client.ID,
		Scope:      scope,
		Status:     models.DeviceCodePending,
		Interval:   interval,
		ExpiresAt:  time.Now().Add(duration),
	}
	if err := s.repos.DeviceCode.Create(ctx, record); err != nil {
		return nil, err
	}

	verificationURI := s.config.ServerURL + "/oauth/device"
	displayCode := FormatUserCode(userCode)

	s.logger.WithFields(logrus.Fields{
		"tenant_id": tenantID,
		"client_id": client.ClientID,
		"user_code": displayCode,
	}).Info("device authorization started")

	return &models.DeviceAuthorizationResponse{
		DeviceCode:              deviceCode,
		UserCode:                displayCode,
		VerificationURI:         verificationURI,
		VerificationURIComplete: verificationURI + "?user_code=" + displayCode,
		ExpiresIn:               int64(duration.Seconds()),
		Interval:                interval,
	}, nil
}

func (s *authServiceImpl) ApproveDeviceCode(ctx context.Context, tenantID uuid.UUID, userCode string, userID uuid.UUID) error {
	return s.resolveDeviceCode(ctx, tenantID, userCode, func(dc *models.DeviceCode) {
		dc.Status = models.DeviceCodeApproved
		dc.UserID = &userID
	})
}

func (s *authServiceImpl) DenyDeviceCode(ctx context.Context, tenantID uuid.UUID, userCode string) error {
	return s.resolveDeviceCode(ctx, tenantID, userCode, func(dc *models.DeviceCode) {
		dc.Status = models.DeviceCodeDenied
	})
}

// resolveDeviceCode applies a user decision to a pending device code
func (s *authServiceImpl) resolveDeviceCode(ctx context.Context, tenantID uuid.UUID, userCode string, decide func(*models.DeviceCode)) error {
	dc, err := s.repos.DeviceCode.GetByUserCode(ctx, tenantID, NormalizeUserCode(userCode))
	if err != nil {
		return models.ErrDeviceCodeNotFound
	}
	if dc.IsExpired() {
		return models.ErrExpiredDeviceCode
	}
	if dc.Status != models.DeviceCodePending {
		return models.ErrDeviceCodeNotFound
	}
	decide(dc)
	return s.repos.DeviceCode.Update(ctx, dc)
}

func (s *authServiceImpl) ExchangeDeviceCode(ctx context.Context, tenantID uuid.UUID, client *models.Client, deviceCode string) (*models.TokenResponse, error) {
	dc, err := s.repos.DeviceCode.GetByDeviceCode(ctx, tenantID, hashToken(deviceCode))
	if err != nil {
		return nil, models.ErrInvalidGrant
	}

	// The device code is bound to the client that requested it
	if dc.ClientID != client.ID {
		return nil, models.ErrInvalidGrant
	}

	if dc.IsExpired() {
		s.repos.DeviceCode.Delete(ctx, tenantID, dc.DeviceCode)
		return nil, models.ErrExpiredDeviceCode
	}

	// Enforce the polling interval (RFC 8628 §3.5 slow_down)
	now := time.Now()
	tooFast := dc.LastPolledAt != nil && now.Sub(*dc.LastPolledAt) < time.Duration(dc.Interval)*time.Second
	dc.LastPolledAt = &now
	if err := s.repos.DeviceCode.Update(ctx, dc); err != nil {
		s.logger.WithError(err).Error("failed to record device code poll")
	}
	if tooFast {
		return nil, models.ErrSlowDown
	}

	switch dc.Status {
	case models.DeviceCodePending:
		return nil, models.ErrAuthorizationPending
	case models.DeviceCodeDenied:
		s.repos.DeviceCode.Delete(ctx, tenantID, dc.DeviceCode)
		return nil, models.ErrDeviceAccessDenied
	case models.DeviceCodeApproved:
		if dc.UserID == nil {
			return nil, models.ErrInvalidGrant
		}
		// The device code is single-use: remove it before issuing tokens
		if err := s.repos.DeviceCode.Delete(ctx, tenantID, dc.DeviceCode); err != nil {
			return nil, models.ErrInvalidGrant
		}
		tokens, err := s.issueTokens(ctx, tenantID, dc.ClientID, *dc.UserID, dc.Scope, dc.ID, true, true)
		if err != nil {
			return nil, err
		}
		s.logger.WithFields(logrus.Fields{
			"tenant_id": tenantID,
			"client_id": client.ClientID,
			"user_id":   dc.UserID,
		}).Info("device code exchanged for tokens")
		return tokens, nil
	default:
		return nil, models.ErrInvalidGrant
	}
}

func (s *authServiceImpl) ExchangeToken(ctx context.Context, tenantID uuid.UUID, client *models.Client, subjectToken, subjectTokenType, requestedScope string) (*models.TokenExchangeResponse, error) {
	// Only access tokens are supported as subject tokens for now
	if subjectTokenType != models.TokenTypeAccessToken {
		return nil, models.ErrInvalidGrant
	}

	// The subject token must be a live (unrevoked) access token of this tenant
	subjectClaims, err := s.ValidateAccessToken(ctx, tenantID, subjectToken)
	if err != nil {
		return nil, models.ErrInvalidGrant
	}

	// The issued scope must stay within the subject token's scope AND the
	// requesting client's registration
	scope := subjectClaims.Scope
	if requestedScope != "" {
		if !ScopeIsSubset(requestedScope, subjectClaims.Scope) {
			return nil, models.ErrInvalidScope
		}
		scope = strings.Join(ParseScope(requestedScope), " ")
	}
	if _, err := ValidateScopeForClient(client, scope); err != nil {
		return nil, models.ErrInvalidScope
	}

	// Issue a delegation token: subject stays the original user, the acting
	// party is recorded in the act claim (RFC 8693 §4.1)
	now := time.Now()
	claims := &models.JWTClaims{
		Sub:      subjectClaims.Sub,
		Aud:      client.ID.String(),
		Iss:      s.config.ServerURL,
		Exp:      now.Add(s.config.AccessTokenDuration).Unix(),
		Iat:      now.Unix(),
		TenantID: tenantID.String(),
		Scope:    scope,
		ClientID: client.ID.String(),
		UserID:   subjectClaims.UserID,
		Act:      &models.ActorClaim{Sub: client.ID.String()},
	}
	accessToken, err := s.signToken(ctx, claims)
	if err != nil {
		return nil, err
	}

	userID := uuid.Nil
	if subjectClaims.UserID != "" {
		if parsed, err := uuid.Parse(subjectClaims.UserID); err == nil {
			userID = parsed
		}
	}
	record := &models.AccessToken{
		ID:        uuid.New(),
		TenantID:  tenantID,
		Token:     hashToken(accessToken),
		ClientID:  client.ID,
		UserID:    userID,
		FamilyID:  uuid.New(),
		Scope:     scope,
		ExpiresAt: now.Add(s.config.AccessTokenDuration),
	}
	if err := s.repos.AccessToken.Create(ctx, record); err != nil {
		return nil, err
	}

	s.logger.WithFields(logrus.Fields{
		"tenant_id": tenantID,
		"client_id": client.ClientID,
		"subject":   subjectClaims.Sub,
	}).Info("token exchanged")

	return &models.TokenExchangeResponse{
		AccessToken:     accessToken,
		IssuedTokenType: models.TokenTypeAccessToken,
		TokenType:       "Bearer",
		ExpiresIn:       int64(s.config.AccessTokenDuration.Seconds()),
		Scope:           scope,
	}, nil
}
