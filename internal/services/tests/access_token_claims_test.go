package tests

// access_token_claims_test.go covers the JWT access token format (RFC 9068):
// the public client_id, ShieldGate as the audience and the at+jwt type, which
// keeps access tokens and ID tokens from being used in place of each other.

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"shieldgate/internal/jwtkeys"
	"shieldgate/internal/models"
	"shieldgate/internal/services"
	"shieldgate/tests/utils"
)

func TestCodeExchange_AccessToken_RFC9068Claims(t *testing.T) {
	// Arrange
	f := newOIDCFixture(t)
	cfg := utils.CreateTestConfig()

	// Act
	tokens := f.exchange(t, "openid read", "", time.Now())
	token, err := f.keys.Parse(tokens.AccessToken, jwt.MapClaims{})
	require.NoError(t, err)
	claims := token.Claims.(jwt.MapClaims)

	// Assert
	assert.Equal(t, "at+jwt", token.Header["typ"], "RFC 9068 §2.1")
	assert.Equal(t, "web-app", claims["client_id"], "the public client_id, not the internal UUID")
	assert.Equal(t, cfg.ServerURL, claims["aud"], "the resource server, not the client")
	assert.Equal(t, f.user.ID.String(), claims["sub"])
	assert.Equal(t, cfg.ServerURL, claims["iss"])
	assert.NotEmpty(t, claims["jti"])
	for name, value := range claims {
		assert.NotEqual(t, f.client.ID.String(), value, "claim %q exposes the client's internal ID", name)
	}
}

func TestValidateAccessToken_TypeAndAudience_Enforced(t *testing.T) {
	// No repositories: only the token itself is checked
	key, err := jwtkeys.Generate(jwtkeys.AlgRS256)
	require.NoError(t, err)
	keys, err := jwtkeys.NewKeySet(key)
	require.NoError(t, err)
	cfg := utils.CreateTestConfig()
	svc := services.NewAuthService(nil, cfg, keys, quietLogger())
	tenantID := uuid.New()
	claims := func(aud string) *models.JWTClaims {
		return &models.JWTClaims{Sub: uuid.NewString(), Aud: aud, Iss: cfg.ServerURL, TenantID: tenantID.String(),
			Exp: time.Now().Add(time.Hour).Unix(), Iat: time.Now().Unix(), ClientID: "web-app"}
	}
	sign := func(c *models.JWTClaims, typ string) string {
		signed, err := keys.SignTyped(c, typ)
		require.NoError(t, err)
		return signed
	}
	tests := []struct {
		name  string
		token string
		valid bool
	}{
		{"access token", sign(claims(cfg.ServerURL), jwtkeys.TypeAccessToken), true},
		{"typ JWT, as an ID token has", sign(claims(cfg.ServerURL), "JWT"), false},
		{"audience is a client", sign(claims("web-app"), jwtkeys.TypeAccessToken), false},
		{"pre-RFC 9068 token: client UUID audience, no at+jwt", sign(claims(uuid.NewString()), "JWT"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Act
			_, err := svc.ValidateAccessToken(context.Background(), tenantID, tt.token)

			// Assert
			if tt.valid {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestValidateAccessToken_IDToken_Rejected(t *testing.T) {
	// Arrange
	f := newOIDCFixture(t)
	tokens := f.exchange(t, "openid", "", time.Now())

	// Act
	_, err := f.svc.ValidateAccessToken(context.Background(), f.tenantID, tokens.IDToken)

	// Assert
	assert.Error(t, err)
}

func TestParseIDTokenHint_AccessToken_Rejected(t *testing.T) {
	// Arrange
	f := newOIDCFixture(t)
	tokens := f.exchange(t, "openid", "", time.Now())

	// Act
	_, accessErr := f.svc.ParseIDTokenHint(context.Background(), tokens.AccessToken)
	hint, idErr := f.svc.ParseIDTokenHint(context.Background(), tokens.IDToken)

	// Assert
	assert.ErrorIs(t, accessErr, models.ErrInvalidToken, "an access token is not an ID token")
	require.NoError(t, idErr)
	assert.Equal(t, "web-app", hint.Aud)
}

func TestRefreshTokens_ClientDeleted_InvalidGrantAndTokenKept(t *testing.T) {
	// Arrange
	svc, repos := newAuthServiceWithFakes()
	ctx := context.Background()
	tenantID := uuid.New()
	client := registerClient(t, repos, tenantID, uuid.New())
	tokens, err := svc.GenerateTokens(ctx, tenantID, client.ID, uuid.New(), "read", false)
	require.NoError(t, err)
	require.NoError(t, repos.Client.Delete(ctx, tenantID, client.ID))

	// Act
	_, err = svc.RefreshTokens(ctx, tenantID, tokens.RefreshToken, client.ID.String(), "")

	// Assert
	assert.ErrorIs(t, err, models.ErrInvalidGrant)
	stored, err := repos.RefreshToken.GetByToken(ctx, tenantID, storedHash(tokens.RefreshToken))
	require.NoError(t, err)
	assert.False(t, stored.IsRevoked(), "the token is not rotated when nothing is issued")
}

// storedHash is how the token store keys a token
func storedHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
