package tests

// oidc_compliance_test.go covers Phase 2: RS256 signing with kid, JWKS
// publication, key rotation, and OIDC ID-token claims (nonce, at_hash,
// auth_time) plus scope-based UserInfo claims.

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

	"shieldgate/internal/models"
)

// parseTokenHeader decodes a JWT without verification to inspect its header
func parseTokenHeader(t *testing.T, token string) map[string]interface{} {
	t.Helper()
	parsed, _, err := jwt.NewParser().ParseUnverified(token, jwt.MapClaims{})
	require.NoError(t, err)
	return parsed.Header
}

func parseClaimsUnverified(t *testing.T, token string) *models.JWTClaims {
	t.Helper()
	claims := &models.JWTClaims{}
	_, _, err := jwt.NewParser().ParseUnverified(token, claims)
	require.NoError(t, err)
	return claims
}

// ---- RS256 signing + JWKS ----

func TestAccessTokens_SignedWithRS256AndKid(t *testing.T) {
	svc, _ := newAuthServiceWithFakes()
	ctx := context.Background()
	tenantID := uuid.New()

	tokens, err := svc.GenerateTokens(ctx, tenantID, uuid.New(), uuid.New(), "read", false)
	require.NoError(t, err)

	header := parseTokenHeader(t, tokens.AccessToken)
	assert.Equal(t, "RS256", header["alg"])
	assert.NotEmpty(t, header["kid"])

	// The RS256 token round-trips through validation (kid lookup)
	claims, err := svc.ValidateAccessToken(ctx, tenantID, tokens.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, "read", claims.Scope)
}

func TestGetJWKS_PublishesActiveKey(t *testing.T) {
	svc, _ := newAuthServiceWithFakes()
	ctx := context.Background()

	jwks, err := svc.GetJWKS(ctx)
	require.NoError(t, err)
	require.Len(t, jwks.Keys, 1)

	key := jwks.Keys[0]
	assert.Equal(t, "RSA", key.Kty)
	assert.Equal(t, "sig", key.Use)
	assert.Equal(t, "RS256", key.Alg)
	assert.NotEmpty(t, key.Kid)
	assert.NotEmpty(t, key.N)
	assert.Equal(t, "AQAB", key.E, "standard RSA exponent 65537")
}

func TestRotateSigningKey_OldTokensStillVerify(t *testing.T) {
	svc, _ := newAuthServiceWithFakes()
	ctx := context.Background()
	tenantID := uuid.New()

	before, err := svc.GenerateTokens(ctx, tenantID, uuid.New(), uuid.New(), "read", false)
	require.NoError(t, err)
	oldKid := parseTokenHeader(t, before.AccessToken)["kid"]

	require.NoError(t, svc.RotateSigningKey(ctx))

	after, err := svc.GenerateTokens(ctx, tenantID, uuid.New(), uuid.New(), "read", false)
	require.NoError(t, err)
	newKid := parseTokenHeader(t, after.AccessToken)["kid"]
	assert.NotEqual(t, oldKid, newKid, "rotation must produce a new kid")

	// Both generations verify: the old key is still serving
	_, err = svc.ValidateAccessToken(ctx, tenantID, before.AccessToken)
	assert.NoError(t, err, "pre-rotation token must still verify")
	_, err = svc.ValidateAccessToken(ctx, tenantID, after.AccessToken)
	assert.NoError(t, err)

	// JWKS now serves both keys for a zero-downtime rollover
	jwks, err := svc.GetJWKS(ctx)
	require.NoError(t, err)
	assert.Len(t, jwks.Keys, 2)
}

// ---- ID token claims: nonce, at_hash, auth_time ----

func TestIDToken_CarriesNonceAtHashAuthTime(t *testing.T) {
	svc, repos := newAuthServiceWithFakes()
	ctx := context.Background()
	tenantID, clientUUID := uuid.New(), uuid.New()
	user := seedUser(t, repos, tenantID)

	authCode, err := svc.GenerateAuthorizationCode(ctx, tenantID, clientUUID, user.ID, "https://app/cb", "openid", "", "", "nonce-xyz", time.Time{})
	require.NoError(t, err)

	tokens, err := svc.ExchangeAuthorizationCode(ctx, tenantID, authCode.Code, clientUUID.String(), "", "https://app/cb", "")
	require.NoError(t, err)
	require.NotEmpty(t, tokens.IDToken)

	claims := parseClaimsUnverified(t, tokens.IDToken)
	assert.Equal(t, "nonce-xyz", claims.Nonce, "nonce must round-trip into the ID token (OIDC Core 3.1.3.7)")
	assert.NotZero(t, claims.AuthTime, "auth_time must be set")

	// at_hash = base64url(left 16 bytes of SHA-256(access_token))
	sum := sha256.Sum256([]byte(tokens.AccessToken))
	expected := base64.RawURLEncoding.EncodeToString(sum[:16])
	assert.Equal(t, expected, claims.AtHash, "at_hash must bind the ID token to the access token")

	// ID token signed RS256 with kid
	header := parseTokenHeader(t, tokens.IDToken)
	assert.Equal(t, "RS256", header["alg"])
	assert.NotEmpty(t, header["kid"])
}

// ---- UserInfo claims by scope ----

func TestGetUserInfo_ReleasesClaimsByScope(t *testing.T) {
	svc, repos := newAuthServiceWithFakes()
	ctx := context.Background()
	tenantID, clientUUID := uuid.New(), uuid.New()

	user := &models.User{
		ID: uuid.New(), TenantID: tenantID,
		Username: "alice", Email: "alice@example.com", EmailVerified: true,
		FirstName: "Alice", LastName: "Nguyen", Locale: "vi", Timezone: "Asia/Ho_Chi_Minh",
	}
	require.NoError(t, repos.User.Create(ctx, user))

	// openid only → just sub
	tokens, err := svc.GenerateTokens(ctx, tenantID, clientUUID, user.ID, "openid", false)
	require.NoError(t, err)
	info, err := svc.GetUserInfo(ctx, tenantID, tokens.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, user.ID.String(), info.Sub)
	assert.Empty(t, info.Email, "email must not leak without the email scope")
	assert.Empty(t, info.Name, "profile claims must not leak without the profile scope")

	// openid + profile + email → full claim set
	tokens, err = svc.GenerateTokens(ctx, tenantID, clientUUID, user.ID, "openid profile email", false)
	require.NoError(t, err)
	info, err = svc.GetUserInfo(ctx, tenantID, tokens.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, "Alice Nguyen", info.Name)
	assert.Equal(t, "Alice", info.GivenName)
	assert.Equal(t, "Nguyen", info.FamilyName)
	assert.Equal(t, "alice", info.PreferredUsername)
	assert.Equal(t, "vi", info.Locale)
	assert.Equal(t, "alice@example.com", info.Email)
	assert.True(t, info.EmailVerified)
}

// ---- Discovery completeness ----

func TestDiscovery_AdvertisesFullMetadata(t *testing.T) {
	svc, _ := newAuthServiceWithFakes()

	doc, err := svc.GetDiscoveryDocument(context.Background())
	require.NoError(t, err)

	assert.Equal(t, []string{"RS256"}, doc.IDTokenSigningAlgValuesSupported)
	assert.Contains(t, doc.TokenEndpointAuthMethodsSupported, "client_secret_basic")
	assert.Contains(t, doc.TokenEndpointAuthMethodsSupported, "client_secret_post")
	assert.Equal(t, []string{"S256"}, doc.CodeChallengeMethodsSupported)
	assert.NotEmpty(t, doc.RevocationEndpoint)
	assert.NotEmpty(t, doc.IntrospectionEndpoint)
	assert.NotEmpty(t, doc.DeviceAuthorizationEndpoint)
	assert.Len(t, doc.GrantTypesSupported, 5)
	assert.Contains(t, doc.ClaimsSupported, "auth_time")
	assert.Contains(t, doc.ClaimsSupported, "nonce")
}
