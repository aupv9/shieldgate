package tests

// oidc_compliance_test.go covers roadmap Phase 2.3–2.6: nonce end to end, ID
// token claims (auth_time, at_hash, aud, lifetime), scope-based UserInfo
// claims, issuer validation, and the discovery document.

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"shieldgate/internal/jwtkeys"
	"shieldgate/internal/models"
	"shieldgate/internal/repo"
	"shieldgate/internal/services"
	"shieldgate/tests/utils"
)

type oidcFixture struct {
	svc      services.AuthService
	repos    *repo.Repositories
	keys     *jwtkeys.KeySet
	tenantID uuid.UUID
	client   *models.Client
	user     *models.User
}

func newOIDCFixture(t *testing.T) *oidcFixture {
	t.Helper()
	key, err := jwtkeys.Generate(jwtkeys.AlgRS256)
	require.NoError(t, err)
	keys, err := jwtkeys.NewKeySet(key)
	require.NoError(t, err)

	repos := newFakeRepositories()
	f := &oidcFixture{
		svc:      services.NewAuthService(repos, utils.CreateTestConfig(), keys, quietLogger()),
		repos:    repos,
		keys:     keys,
		tenantID: uuid.New(),
	}
	f.client = &models.Client{ID: uuid.New(), TenantID: f.tenantID, ClientID: "web-app"}
	require.NoError(t, repos.Client.Create(context.Background(), f.client))
	f.user = &models.User{
		ID: uuid.New(), TenantID: f.tenantID, Username: "alice", Email: "alice@example.com",
		FirstName: "Alice", LastName: "Liddell", Locale: "en", Timezone: "UTC",
		EmailVerified: false, UpdatedAt: time.Unix(1700000000, 0),
	}
	require.NoError(t, repos.User.Create(context.Background(), f.user))
	return f
}

// exchange runs the authorization code flow and returns the token response
func (f *oidcFixture) exchange(t *testing.T, scope, nonce string, authTime time.Time) *models.TokenResponse {
	t.Helper()
	ctx := context.Background()
	code, err := f.svc.GenerateAuthorizationCode(ctx, f.tenantID, f.client.ID, f.user.ID, "https://app/cb", scope, "", "", nonce, authTime, nil)
	require.NoError(t, err)
	tokens, err := f.svc.ExchangeAuthorizationCode(ctx, f.tenantID, code.Code, f.client.ID.String(), "", "https://app/cb", "")
	require.NoError(t, err)
	return tokens
}

// idClaims verifies an ID token and returns its raw claim map, so tests see
// exactly what is serialized
func (f *oidcFixture) idClaims(t *testing.T, idToken string) map[string]interface{} {
	t.Helper()
	require.NotEmpty(t, idToken)
	_, err := f.keys.Parse(idToken, &models.IDTokenClaims{})
	require.NoError(t, err)
	parsed, _, err := jwt.NewParser().ParseUnverified(idToken, jwt.MapClaims{})
	require.NoError(t, err)
	return parsed.Claims.(jwt.MapClaims)
}

func atHash(accessToken string) string {
	sum := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(sum[:16])
}

func TestCodeExchange_OpenID_IDTokenCarriesNonceAuthTimeAtHashAndPublicAud(t *testing.T) {
	// Arrange
	f := newOIDCFixture(t)
	authTime := time.Now().Add(-2 * time.Minute).Truncate(time.Second)

	// Act
	tokens := f.exchange(t, "openid", "n-0S6_WzA2Mj", authTime)
	claims := f.idClaims(t, tokens.IDToken)

	// Assert
	assert.Equal(t, "n-0S6_WzA2Mj", claims["nonce"])
	assert.EqualValues(t, authTime.Unix(), claims["auth_time"])
	assert.Equal(t, atHash(tokens.AccessToken), claims["at_hash"])
	assert.Equal(t, "web-app", claims["aud"], "aud must be the public client_id, not the internal UUID")
	assert.Equal(t, utils.CreateTestConfig().ServerURL, claims["iss"])
	assert.Equal(t, f.user.ID.String(), claims["sub"])
	assert.EqualValues(t, time.Hour.Seconds(), claims["exp"].(float64)-claims["iat"].(float64))
}

func TestCodeExchange_NoNonceRequested_NonceOmitted(t *testing.T) {
	// Arrange
	f := newOIDCFixture(t)

	// Act
	claims := f.idClaims(t, f.exchange(t, "openid", "", time.Now()).IDToken)

	// Assert
	assert.NotContains(t, claims, "nonce")
}

func TestIDToken_UserClaims_FollowGrantedScopes(t *testing.T) {
	cases := []struct {
		scope   string
		present []string
		absent  []string
	}{
		{"openid", []string{"sub"}, []string{"name", "preferred_username", "email", "email_verified"}},
		{"openid profile", []string{"name", "given_name", "family_name", "preferred_username", "updated_at"}, []string{"email"}},
		{"openid email", []string{"email", "email_verified"}, []string{"name"}},
	}
	for _, tc := range cases {
		t.Run(tc.scope, func(t *testing.T) {
			// Arrange
			f := newOIDCFixture(t)

			// Act
			claims := f.idClaims(t, f.exchange(t, tc.scope, "", time.Now()).IDToken)

			// Assert
			for _, c := range tc.present {
				assert.Contains(t, claims, c)
			}
			for _, c := range tc.absent {
				assert.NotContains(t, claims, c)
			}
		})
	}
}

func TestIDToken_UnverifiedEmail_ReportedAsFalse(t *testing.T) {
	// Arrange: omitempty on a plain bool used to drop email_verified=false
	f := newOIDCFixture(t)

	// Act
	claims := f.idClaims(t, f.exchange(t, "openid email", "", time.Now()).IDToken)

	// Assert
	assert.Equal(t, false, claims["email_verified"])
}

func TestRefresh_IDToken_KeepsAuthTimeDropsNonceAndRehashesAccessToken(t *testing.T) {
	// Arrange
	f := newOIDCFixture(t)
	authTime := time.Now().Add(-10 * time.Minute).Truncate(time.Second)
	initial := f.exchange(t, "openid", "abc", authTime)

	// Act
	refreshed, err := f.svc.RefreshTokens(context.Background(), f.tenantID, initial.RefreshToken, f.client.ID.String(), "")
	require.NoError(t, err)
	claims := f.idClaims(t, refreshed.IDToken)

	// Assert (OIDC Core §12.2)
	assert.EqualValues(t, authTime.Unix(), claims["auth_time"], "auth_time is the original authentication")
	assert.NotContains(t, claims, "nonce")
	assert.Equal(t, atHash(refreshed.AccessToken), claims["at_hash"])
}

func TestDeviceFlow_IDToken_AuthTimeIsApprovalTime(t *testing.T) {
	// Arrange
	f := newOIDCFixture(t)
	ctx := context.Background()
	client := deviceClient(f.tenantID)
	require.NoError(t, f.repos.Client.Create(ctx, client))
	auth, err := f.svc.CreateDeviceAuthorization(ctx, f.tenantID, client, "openid")
	require.NoError(t, err)
	before := time.Now().Unix()
	require.NoError(t, f.svc.ApproveDeviceCode(ctx, f.tenantID, auth.UserCode, f.user.ID, nil))

	// Act
	tokens, err := f.svc.ExchangeDeviceCode(ctx, f.tenantID, client, auth.DeviceCode)
	require.NoError(t, err)
	claims := f.idClaims(t, tokens.IDToken)

	// Assert
	assert.GreaterOrEqual(t, int64(claims["auth_time"].(float64)), before)
	assert.Equal(t, client.ClientID, claims["aud"])
}

func TestCodeExchange_OpenIDButUserMissing_FailsInsteadOfDroppingIDToken(t *testing.T) {
	// Arrange
	f := newOIDCFixture(t)
	ctx := context.Background()
	code, err := f.svc.GenerateAuthorizationCode(ctx, f.tenantID, f.client.ID, uuid.New(), "https://app/cb", "openid", "", "", "", time.Now(), nil)
	require.NoError(t, err)

	// Act
	_, err = f.svc.ExchangeAuthorizationCode(ctx, f.tenantID, code.Code, f.client.ID.String(), "", "https://app/cb", "")

	// Assert
	assert.Error(t, err)
}

func TestGetUserInfo_ClaimsFollowTokenScope(t *testing.T) {
	// Arrange
	f := newOIDCFixture(t)
	ctx := context.Background()
	profileOnly := f.exchange(t, "openid profile", "", time.Now())
	emailOnly := f.exchange(t, "openid email", "", time.Now())

	// Act
	profile, err1 := f.svc.GetUserInfo(ctx, f.tenantID, profileOnly.AccessToken)
	email, err2 := f.svc.GetUserInfo(ctx, f.tenantID, emailOnly.AccessToken)

	// Assert
	require.NoError(t, err1)
	require.NoError(t, err2)
	assert.Equal(t, "Alice Liddell", profile.Name)
	assert.Equal(t, "alice", profile.PreferredUsername)
	assert.Empty(t, profile.Email)
	assert.Equal(t, "alice@example.com", email.Email)
	require.NotNil(t, email.EmailVerified)
	assert.False(t, *email.EmailVerified)
	assert.Empty(t, email.Name)
}

func TestGetUserInfo_TokenWithoutOpenIDScope_InsufficientScope(t *testing.T) {
	// Arrange
	f := newOIDCFixture(t)
	tokens, err := f.svc.GenerateTokens(context.Background(), f.tenantID, f.client.ID, f.user.ID, "read", false)
	require.NoError(t, err)

	// Act
	_, err = f.svc.GetUserInfo(context.Background(), f.tenantID, tokens.AccessToken)

	// Assert
	assert.ErrorIs(t, err, models.ErrInsufficientScope)
}

func TestValidateAccessToken_ForeignIssuerOrNoExpiry_Rejected(t *testing.T) {
	// Arrange: correctly signed by our key but with bad claims
	f := newOIDCFixture(t)
	cfg := utils.CreateTestConfig()
	foreignIss, err := f.keys.Sign(&models.JWTClaims{Iss: "https://evil.example", TenantID: f.tenantID.String(), Exp: time.Now().Add(time.Hour).Unix()})
	require.NoError(t, err)
	noExp, err := f.keys.Sign(&models.JWTClaims{Iss: cfg.ServerURL, TenantID: f.tenantID.String()})
	require.NoError(t, err)

	// Act
	_, errIss := f.svc.ValidateAccessToken(context.Background(), f.tenantID, foreignIss)
	_, errExp := f.svc.ValidateAccessToken(context.Background(), f.tenantID, noExp)

	// Assert
	assert.Error(t, errIss)
	assert.Error(t, errExp)
}

func TestGetDiscoveryDocument_PublishesRequiredAndRecommendedMetadata(t *testing.T) {
	// Arrange
	f := newOIDCFixture(t)
	base := utils.CreateTestConfig().ServerURL

	// Act
	doc, err := f.svc.GetDiscoveryDocument(context.Background())
	require.NoError(t, err)
	raw, err := json.Marshal(doc)
	require.NoError(t, err)
	var fields map[string]interface{}
	require.NoError(t, json.Unmarshal(raw, &fields))

	// Assert
	assert.Equal(t, base+"/oauth/revoke", doc.RevocationEndpoint)
	assert.Equal(t, base+"/oauth/introspect", doc.IntrospectionEndpoint)
	assert.Equal(t, []string{"S256"}, doc.CodeChallengeMethodsSupported)
	assert.ElementsMatch(t, []string{"client_secret_basic", "client_secret_post", "none"}, doc.TokenEndpointAuthMethodsSupported)
	assert.Contains(t, doc.ScopesSupported, "openid")
	assert.Contains(t, doc.ClaimsSupported, "nonce")
	assert.Contains(t, doc.ClaimsSupported, "at_hash")
	// request_uri_parameter_supported defaults to true if omitted, so it must
	// be serialized even though it is false
	assert.Equal(t, false, fields["request_uri_parameter_supported"])
	assert.Equal(t, true, fields["authorization_response_iss_parameter_supported"])
}

func TestGenerateTokens_SameClaimsSameSecond_ProduceDistinctTokens(t *testing.T) {
	// Arrange: identical sub/client/scope issued back to back used to yield
	// byte-identical JWTs, colliding on the unique token-hash index
	f := newOIDCFixture(t)
	ctx := context.Background()

	// Act
	first, err1 := f.svc.GenerateTokens(ctx, f.tenantID, f.client.ID, f.user.ID, "read", false)
	second, err2 := f.svc.GenerateTokens(ctx, f.tenantID, f.client.ID, f.user.ID, "read", false)

	// Assert
	require.NoError(t, err1)
	require.NoError(t, err2)
	assert.NotEqual(t, first.AccessToken, second.AccessToken)
}
