package tests

// jwt_signing_test.go checks that the auth service signs with the configured
// asymmetric key and that what it publishes is enough to verify its tokens.

import (
	"context"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"shieldgate/internal/jwtkeys"
	"shieldgate/internal/models"
	"shieldgate/internal/services"
	"shieldgate/tests/utils"
)

func newRS256AuthService(t *testing.T) (services.AuthService, *jwtkeys.KeySet) {
	t.Helper()
	key, err := jwtkeys.Generate(jwtkeys.AlgRS256)
	require.NoError(t, err)
	ks, err := jwtkeys.NewKeySet(key)
	require.NoError(t, err)
	return services.NewAuthService(nil, utils.CreateTestConfig(), ks, quietLogger()), ks
}

func TestGenerateIDToken_RS256_VerifiableWithPublishedJWKS(t *testing.T) {
	// Arrange
	svc, ks := newRS256AuthService(t)
	user := &models.User{ID: uuid.New(), TenantID: uuid.New(), Email: "a@example.com", Username: "alice"}
	ctx := context.Background()

	// Act
	idToken, err := svc.GenerateIDToken(ctx, user, &models.IDTokenParams{ClientID: "client-1", Scope: "openid"})
	require.NoError(t, err)
	jwks, err := svc.GetJWKS(ctx)
	require.NoError(t, err)

	// Assert: header names a kid the JWKS publishes, and the key set verifies it
	unverified, _, err := jwt.NewParser().ParseUnverified(idToken, &models.JWTClaims{})
	require.NoError(t, err)
	assert.Equal(t, "RS256", unverified.Header["alg"])
	require.Len(t, jwks.Keys, 1)
	assert.Equal(t, jwks.Keys[0].Kid, unverified.Header["kid"])

	verified, err := ks.Parse(idToken, &models.IDTokenClaims{})
	require.NoError(t, err)
	assert.Equal(t, user.ID.String(), verified.Claims.(*models.IDTokenClaims).Sub)
}

func TestValidateAccessToken_SignedByOtherKey_Rejected(t *testing.T) {
	// Arrange
	svc, _ := newRS256AuthService(t)
	_, otherKeys := newRS256AuthService(t)
	tenantID := uuid.New()
	forged, err := otherKeys.Sign(&models.JWTClaims{Sub: "x", TenantID: tenantID.String()})
	require.NoError(t, err)

	// Act
	_, err = svc.ValidateAccessToken(context.Background(), tenantID, forged)

	// Assert
	assert.Error(t, err)
}

func TestGetDiscoveryDocument_AdvertisesActiveSigningAlg(t *testing.T) {
	// Arrange
	svc, _ := newRS256AuthService(t)

	// Act
	doc, err := svc.GetDiscoveryDocument(context.Background())

	// Assert
	require.NoError(t, err)
	assert.Equal(t, []string{"RS256"}, doc.IDTokenSigningAlgValuesSupported)
}
