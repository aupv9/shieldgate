package tests

// device_token_exchange_test.go covers the Device Authorization Grant
// (RFC 8628) and Token Exchange (RFC 8693) service flows.

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"shieldgate/internal/models"
	"shieldgate/internal/services"
)

func deviceClient(tenantID uuid.UUID) *models.Client {
	return &models.Client{
		ID:         uuid.New(),
		TenantID:   tenantID,
		ClientID:   "tv-app",
		GrantTypes: models.StringArray{models.GrantTypeDeviceCode},
		Scopes:     models.StringArray{"openid", "read"},
		IsPublic:   true,
	}
}

// ---- User code helpers ----

func TestNormalizeAndFormatUserCode(t *testing.T) {
	assert.Equal(t, "BCDFGHJK", services.NormalizeUserCode(" bcdf-ghjk "))
	assert.Equal(t, "BCDFGHJK", services.NormalizeUserCode("BCDF GHJK"))
	assert.Equal(t, "BCDF-GHJK", services.FormatUserCode("BCDFGHJK"))
}

// ---- Device authorization flow ----

func TestDeviceFlow_HappyPath(t *testing.T) {
	svc, repos := newAuthServiceWithFakes()
	ctx := context.Background()
	tenantID := uuid.New()
	client := deviceClient(tenantID)
	user := seedUser(t, repos, tenantID)

	// Device requests authorization
	auth, err := svc.CreateDeviceAuthorization(ctx, tenantID, client, "openid read")
	require.NoError(t, err)
	assert.NotEmpty(t, auth.DeviceCode)
	assert.Len(t, services.NormalizeUserCode(auth.UserCode), 8)
	assert.Contains(t, auth.VerificationURI, "/oauth/device")
	assert.Contains(t, auth.VerificationURIComplete, auth.UserCode)
	assert.Equal(t, 5, auth.Interval)

	// User approves on the verification page
	require.NoError(t, svc.ApproveDeviceCode(ctx, tenantID, auth.UserCode, user.ID))

	// Device polls and receives tokens
	tokens, err := svc.ExchangeDeviceCode(ctx, tenantID, client, auth.DeviceCode)
	require.NoError(t, err)
	assert.NotEmpty(t, tokens.AccessToken)
	assert.NotEmpty(t, tokens.RefreshToken)
	assert.NotEmpty(t, tokens.IDToken, "openid scope must yield an ID token")
	assert.Equal(t, "openid read", tokens.Scope)

	claims, err := svc.ValidateAccessToken(ctx, tenantID, tokens.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, user.ID.String(), claims.UserID)

	// The device code is single-use
	_, err = svc.ExchangeDeviceCode(ctx, tenantID, client, auth.DeviceCode)
	assert.ErrorIs(t, err, models.ErrInvalidGrant)
}

func TestDeviceFlow_PendingUntilApproved(t *testing.T) {
	svc, _ := newAuthServiceWithFakes()
	ctx := context.Background()
	tenantID := uuid.New()
	client := deviceClient(tenantID)

	auth, err := svc.CreateDeviceAuthorization(ctx, tenantID, client, "read")
	require.NoError(t, err)

	_, err = svc.ExchangeDeviceCode(ctx, tenantID, client, auth.DeviceCode)
	assert.ErrorIs(t, err, models.ErrAuthorizationPending)
}

func TestDeviceFlow_SlowDownOnFastPolling(t *testing.T) {
	svc, _ := newAuthServiceWithFakes()
	ctx := context.Background()
	tenantID := uuid.New()
	client := deviceClient(tenantID)

	auth, err := svc.CreateDeviceAuthorization(ctx, tenantID, client, "read")
	require.NoError(t, err)

	_, err = svc.ExchangeDeviceCode(ctx, tenantID, client, auth.DeviceCode)
	assert.ErrorIs(t, err, models.ErrAuthorizationPending)

	// Immediate second poll violates the interval
	_, err = svc.ExchangeDeviceCode(ctx, tenantID, client, auth.DeviceCode)
	assert.ErrorIs(t, err, models.ErrSlowDown)
}

func TestDeviceFlow_DeniedByUser(t *testing.T) {
	svc, _ := newAuthServiceWithFakes()
	ctx := context.Background()
	tenantID := uuid.New()
	client := deviceClient(tenantID)

	auth, err := svc.CreateDeviceAuthorization(ctx, tenantID, client, "read")
	require.NoError(t, err)

	require.NoError(t, svc.DenyDeviceCode(ctx, tenantID, auth.UserCode))

	_, err = svc.ExchangeDeviceCode(ctx, tenantID, client, auth.DeviceCode)
	assert.ErrorIs(t, err, models.ErrDeviceAccessDenied)

	// Denied codes are removed — later polls see invalid_grant
	_, err = svc.ExchangeDeviceCode(ctx, tenantID, client, auth.DeviceCode)
	assert.ErrorIs(t, err, models.ErrInvalidGrant)
}

func TestDeviceFlow_WrongClient_Rejected(t *testing.T) {
	svc, _ := newAuthServiceWithFakes()
	ctx := context.Background()
	tenantID := uuid.New()
	client := deviceClient(tenantID)
	otherClient := deviceClient(tenantID)

	auth, err := svc.CreateDeviceAuthorization(ctx, tenantID, client, "read")
	require.NoError(t, err)

	_, err = svc.ExchangeDeviceCode(ctx, tenantID, otherClient, auth.DeviceCode)
	assert.ErrorIs(t, err, models.ErrInvalidGrant)
}

func TestDeviceFlow_ExpiredCode(t *testing.T) {
	svc, repos := newAuthServiceWithFakes()
	ctx := context.Background()
	tenantID := uuid.New()
	client := deviceClient(tenantID)

	auth, err := svc.CreateDeviceAuthorization(ctx, tenantID, client, "read")
	require.NoError(t, err)

	// Force expiry directly in the store
	dc, err := repos.DeviceCode.GetByUserCode(ctx, tenantID, services.NormalizeUserCode(auth.UserCode))
	require.NoError(t, err)
	dc.ExpiresAt = time.Now().Add(-time.Minute)
	require.NoError(t, repos.DeviceCode.Update(ctx, dc))

	_, err = svc.ExchangeDeviceCode(ctx, tenantID, client, auth.DeviceCode)
	assert.ErrorIs(t, err, models.ErrExpiredDeviceCode)

	// Approving an expired code also fails
	err = svc.ApproveDeviceCode(ctx, tenantID, auth.UserCode, uuid.New())
	assert.Error(t, err)
}

func TestApproveDeviceCode_UnknownCode(t *testing.T) {
	svc, _ := newAuthServiceWithFakes()
	err := svc.ApproveDeviceCode(context.Background(), uuid.New(), "XXXX-XXXX", uuid.New())
	assert.ErrorIs(t, err, models.ErrDeviceCodeNotFound)
}

// ---- Token exchange ----

func exchangeClient(tenantID uuid.UUID, scopes ...string) *models.Client {
	return &models.Client{
		ID:         uuid.New(),
		TenantID:   tenantID,
		ClientID:   "backend-svc",
		GrantTypes: models.StringArray{models.GrantTypeTokenExchange},
		Scopes:     models.StringArray(scopes),
		IsPublic:   false,
	}
}

func TestExchangeToken_HappyPath_DelegationWithActClaim(t *testing.T) {
	svc, _ := newAuthServiceWithFakes()
	ctx := context.Background()
	tenantID := uuid.New()
	userID := uuid.New()
	originClient := uuid.New()
	exchClient := exchangeClient(tenantID, "read", "write")

	subject, err := svc.GenerateTokens(ctx, tenantID, originClient, userID, "read write", false)
	require.NoError(t, err)

	result, err := svc.ExchangeToken(ctx, tenantID, exchClient, subject.AccessToken, models.TokenTypeAccessToken, "read")
	require.NoError(t, err)
	assert.Equal(t, models.TokenTypeAccessToken, result.IssuedTokenType)
	assert.Equal(t, "Bearer", result.TokenType)
	assert.Equal(t, "read", result.Scope)

	// The issued token keeps the original subject and records the actor
	// (signature already covered by ValidateAccessToken below)
	claims := &models.JWTClaims{}
	_, _, err = jwt.NewParser().ParseUnverified(result.AccessToken, claims)
	require.NoError(t, err)
	assert.Equal(t, userID.String(), claims.Sub, "subject must remain the original user")
	require.NotNil(t, claims.Act, "act claim must record the acting client")
	assert.Equal(t, exchClient.ID.String(), claims.Act.Sub)

	// The exchanged token is a live, validatable access token
	validated, err := svc.ValidateAccessToken(ctx, tenantID, result.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, "read", validated.Scope)
}

func TestExchangeToken_ScopeBeyondSubjectToken_Rejected(t *testing.T) {
	svc, _ := newAuthServiceWithFakes()
	ctx := context.Background()
	tenantID := uuid.New()
	exchClient := exchangeClient(tenantID, "read", "write", "admin")

	subject, err := svc.GenerateTokens(ctx, tenantID, uuid.New(), uuid.New(), "read", false)
	require.NoError(t, err)

	_, err = svc.ExchangeToken(ctx, tenantID, exchClient, subject.AccessToken, models.TokenTypeAccessToken, "read admin")
	assert.ErrorIs(t, err, models.ErrInvalidScope)
}

func TestExchangeToken_ScopeBeyondClientRegistration_Rejected(t *testing.T) {
	svc, _ := newAuthServiceWithFakes()
	ctx := context.Background()
	tenantID := uuid.New()
	exchClient := exchangeClient(tenantID, "read") // client may only hold "read"

	subject, err := svc.GenerateTokens(ctx, tenantID, uuid.New(), uuid.New(), "read write", false)
	require.NoError(t, err)

	// Default scope = subject scope "read write" — outside client registration
	_, err = svc.ExchangeToken(ctx, tenantID, exchClient, subject.AccessToken, models.TokenTypeAccessToken, "")
	assert.ErrorIs(t, err, models.ErrInvalidScope)

	// Narrowed to what the client is registered for, it succeeds
	result, err := svc.ExchangeToken(ctx, tenantID, exchClient, subject.AccessToken, models.TokenTypeAccessToken, "read")
	require.NoError(t, err)
	assert.Equal(t, "read", result.Scope)
}

func TestExchangeToken_InvalidSubjectToken_Rejected(t *testing.T) {
	svc, _ := newAuthServiceWithFakes()
	tenantID := uuid.New()
	exchClient := exchangeClient(tenantID, "read")

	_, err := svc.ExchangeToken(context.Background(), tenantID, exchClient, "not-a-token", models.TokenTypeAccessToken, "")
	assert.ErrorIs(t, err, models.ErrInvalidGrant)
}

func TestExchangeToken_RevokedSubjectToken_Rejected(t *testing.T) {
	svc, _ := newAuthServiceWithFakes()
	ctx := context.Background()
	tenantID := uuid.New()
	originClient := uuid.New()
	exchClient := exchangeClient(tenantID, "read")

	subject, err := svc.GenerateTokens(ctx, tenantID, originClient, uuid.New(), "read", false)
	require.NoError(t, err)
	require.NoError(t, svc.RevokeToken(ctx, tenantID, subject.AccessToken, "access_token", originClient))

	_, err = svc.ExchangeToken(ctx, tenantID, exchClient, subject.AccessToken, models.TokenTypeAccessToken, "")
	assert.ErrorIs(t, err, models.ErrInvalidGrant)
}

func TestExchangeToken_UnsupportedSubjectTokenType_Rejected(t *testing.T) {
	svc, _ := newAuthServiceWithFakes()
	tenantID := uuid.New()
	exchClient := exchangeClient(tenantID, "read")

	_, err := svc.ExchangeToken(context.Background(), tenantID, exchClient, "whatever", "urn:ietf:params:oauth:token-type:saml2", "")
	assert.ErrorIs(t, err, models.ErrInvalidGrant)
}
