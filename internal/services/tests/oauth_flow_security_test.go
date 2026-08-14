package tests

// oauth_flow_security_test.go covers the Phase 1 security hardening:
// hashed client secrets, hashed tokens, authorization-code single use with
// reuse revocation, refresh token rotation with family reuse detection,
// scope validation, and revocation enforcement on JWT access tokens.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"shieldgate/internal/models"
	"shieldgate/internal/repo"
	"shieldgate/internal/services"
	"shieldgate/tests/utils"
)

func quietLogger() *logrus.Logger {
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)
	return logger
}

func newAuthServiceWithFakes() (services.AuthService, *repo.Repositories) {
	repos := newFakeRepositories()
	return services.NewAuthService(repos, utils.CreateTestConfig(), quietLogger()), repos
}

func newClientServiceWithFakes() (services.ClientService, *repo.Repositories) {
	repos := newFakeRepositories()
	return services.NewClientService(repos, quietLogger()), repos
}

// ---- Client secret hashing (1.1) ----

func TestClientService_Create_StoresBcryptHashAndReturnsPlaintextOnce(t *testing.T) {
	svc, repos := newClientServiceWithFakes()
	tenantID := uuid.New()

	client, err := svc.Create(context.Background(), tenantID, &models.CreateClientRequest{
		Name:         "Confidential App",
		RedirectURIs: []string{"https://app.example.com/callback"},
		GrantTypes:   []string{"authorization_code"},
		Scopes:       []string{"read"},
		IsPublic:     false,
	})
	require.NoError(t, err)

	// Plaintext returned once on create
	assert.NotEmpty(t, client.PlainClientSecret)
	// Stored value is a bcrypt hash, not the plaintext
	stored, err := repos.Client.GetByID(context.Background(), tenantID, client.ID)
	require.NoError(t, err)
	assert.NotEqual(t, client.PlainClientSecret, stored.ClientSecret)
	assert.True(t, strings.HasPrefix(stored.ClientSecret, "$2"))
	assert.NoError(t, bcrypt.CompareHashAndPassword([]byte(stored.ClientSecret), []byte(client.PlainClientSecret)))
}

func TestClientService_ValidateClient_BcryptSecret(t *testing.T) {
	svc, _ := newClientServiceWithFakes()
	tenantID := uuid.New()

	created, err := svc.Create(context.Background(), tenantID, &models.CreateClientRequest{
		Name:         "Confidential App",
		RedirectURIs: []string{"https://app.example.com/callback"},
		GrantTypes:   []string{"client_credentials"},
		Scopes:       []string{"read"},
	})
	require.NoError(t, err)

	// Correct secret validates
	validated, err := svc.ValidateClient(context.Background(), tenantID, created.ClientID, created.PlainClientSecret)
	require.NoError(t, err)
	assert.Equal(t, created.ID, validated.ID)

	// Wrong or empty secret is rejected
	_, err = svc.ValidateClient(context.Background(), tenantID, created.ClientID, "wrong-secret")
	assert.ErrorIs(t, err, models.ErrInvalidClient)
	_, err = svc.ValidateClient(context.Background(), tenantID, created.ClientID, "")
	assert.ErrorIs(t, err, models.ErrInvalidClient)
}

// ---- Token hashing (1.2) + code exchange ----

func seedUser(t *testing.T, repos *repo.Repositories, tenantID uuid.UUID) *models.User {
	t.Helper()
	user := &models.User{ID: uuid.New(), TenantID: tenantID, Username: "alice", Email: "alice@example.com", EmailVerified: true}
	require.NoError(t, repos.User.Create(context.Background(), user))
	return user
}

func TestExchangeAuthorizationCode_Success_StoresHashedTokens(t *testing.T) {
	svc, repos := newAuthServiceWithFakes()
	ctx := context.Background()
	tenantID, clientUUID := uuid.New(), uuid.New()
	user := seedUser(t, repos, tenantID)

	authCode, err := svc.GenerateAuthorizationCode(ctx, tenantID, clientUUID, user.ID, "https://app/cb", "openid read", "", "", "nonce-123", time.Time{})
	require.NoError(t, err)

	tokens, err := svc.ExchangeAuthorizationCode(ctx, tenantID, authCode.Code, clientUUID.String(), "", "https://app/cb", "")
	require.NoError(t, err)
	assert.NotEmpty(t, tokens.AccessToken)
	assert.NotEmpty(t, tokens.RefreshToken)
	assert.NotEmpty(t, tokens.IDToken, "openid scope must yield an ID token")
	assert.Equal(t, "openid read", tokens.Scope)

	// Raw token values must not appear in storage (only hashes)
	_, err = repos.AccessToken.GetByToken(ctx, tenantID, tokens.AccessToken)
	assert.Error(t, err, "raw access token must not be stored")
	_, err = repos.RefreshToken.GetByToken(ctx, tenantID, tokens.RefreshToken)
	assert.Error(t, err, "raw refresh token must not be stored")

	// But the token is still valid through the service (hash lookup)
	claims, err := svc.ValidateAccessToken(ctx, tenantID, tokens.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, user.ID.String(), claims.UserID)
}

// ---- Authorization code single use + reuse revocation (1.7) ----

func TestExchangeAuthorizationCode_Reuse_RevokesIssuedTokens(t *testing.T) {
	svc, _ := newAuthServiceWithFakes()
	ctx := context.Background()
	tenantID, clientUUID := uuid.New(), uuid.New()
	userID := uuid.New()

	authCode, err := svc.GenerateAuthorizationCode(ctx, tenantID, clientUUID, userID, "https://app/cb", "read", "", "", "", time.Time{})
	require.NoError(t, err)

	tokens, err := svc.ExchangeAuthorizationCode(ctx, tenantID, authCode.Code, clientUUID.String(), "", "https://app/cb", "")
	require.NoError(t, err)

	// Second exchange with the same code fails...
	_, err = svc.ExchangeAuthorizationCode(ctx, tenantID, authCode.Code, clientUUID.String(), "", "https://app/cb", "")
	assert.ErrorIs(t, err, models.ErrInvalidGrant)

	// ...and revokes the tokens issued by the first exchange (RFC 6749 §4.1.2)
	_, err = svc.ValidateAccessToken(ctx, tenantID, tokens.AccessToken)
	assert.Error(t, err, "access token from replayed code must be revoked")
	_, err = svc.RefreshTokens(ctx, tenantID, tokens.RefreshToken, clientUUID.String(), "")
	assert.ErrorIs(t, err, models.ErrInvalidGrant, "refresh token from replayed code must be revoked")
}

// ---- Refresh token rotation + reuse detection (1.6) ----

func TestRefreshTokens_RotationKeepsScopeAndDetectsReuse(t *testing.T) {
	svc, _ := newAuthServiceWithFakes()
	ctx := context.Background()
	tenantID, clientUUID := uuid.New(), uuid.New()
	userID := uuid.New()

	original, err := svc.GenerateTokens(ctx, tenantID, clientUUID, userID, "read write", false)
	require.NoError(t, err)

	// Rotation succeeds and keeps the original scope
	rotated, err := svc.RefreshTokens(ctx, tenantID, original.RefreshToken, clientUUID.String(), "")
	require.NoError(t, err)
	assert.Equal(t, "read write", rotated.Scope)
	assert.NotEqual(t, original.RefreshToken, rotated.RefreshToken)

	// Replaying the rotated-out token is reuse: the whole family dies
	_, err = svc.RefreshTokens(ctx, tenantID, original.RefreshToken, clientUUID.String(), "")
	assert.ErrorIs(t, err, models.ErrInvalidGrant)

	_, err = svc.RefreshTokens(ctx, tenantID, rotated.RefreshToken, clientUUID.String(), "")
	assert.ErrorIs(t, err, models.ErrInvalidGrant, "descendant token must be revoked after reuse detection")
	_, err = svc.ValidateAccessToken(ctx, tenantID, rotated.AccessToken)
	assert.Error(t, err, "descendant access token must be revoked after reuse detection")
}

func TestRefreshTokens_ScopeNarrowingAllowed_WideningRejected(t *testing.T) {
	svc, _ := newAuthServiceWithFakes()
	ctx := context.Background()
	tenantID, clientUUID := uuid.New(), uuid.New()

	original, err := svc.GenerateTokens(ctx, tenantID, clientUUID, uuid.New(), "read write", false)
	require.NoError(t, err)

	// Narrowing is allowed
	narrowed, err := svc.RefreshTokens(ctx, tenantID, original.RefreshToken, clientUUID.String(), "read")
	require.NoError(t, err)
	assert.Equal(t, "read", narrowed.Scope)

	// Widening beyond the original grant is rejected
	_, err = svc.RefreshTokens(ctx, tenantID, narrowed.RefreshToken, clientUUID.String(), "read write admin")
	assert.ErrorIs(t, err, models.ErrInvalidScope)
}

func TestRefreshTokens_WrongClient_Rejected(t *testing.T) {
	svc, _ := newAuthServiceWithFakes()
	ctx := context.Background()
	tenantID := uuid.New()

	original, err := svc.GenerateTokens(ctx, tenantID, uuid.New(), uuid.New(), "read", false)
	require.NoError(t, err)

	_, err = svc.RefreshTokens(ctx, tenantID, original.RefreshToken, uuid.New().String(), "")
	assert.ErrorIs(t, err, models.ErrInvalidGrant)
}

// ---- Client credentials grant (1.10) ----

func TestGenerateClientCredentialsTokens_NoRefreshToken_SubjectIsClient(t *testing.T) {
	svc, _ := newAuthServiceWithFakes()
	ctx := context.Background()
	tenantID := uuid.New()
	client := &models.Client{ID: uuid.New(), TenantID: tenantID, ClientID: "m2m-client"}

	tokens, err := svc.GenerateClientCredentialsTokens(ctx, tenantID, client, "read")
	require.NoError(t, err)

	assert.Empty(t, tokens.RefreshToken, "client_credentials must not issue a refresh token (RFC 6749 §4.4.3)")
	assert.NotEmpty(t, tokens.AccessToken)

	claims, err := svc.ValidateAccessToken(ctx, tenantID, tokens.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, client.ID.String(), claims.Sub, "subject must be the client, not a user")
	assert.Empty(t, claims.UserID)
}

// ---- Revocation (1.3, 1.8) ----

func TestRevokeToken_AccessToken_EnforcedOnValidation(t *testing.T) {
	svc, _ := newAuthServiceWithFakes()
	ctx := context.Background()
	tenantID, clientUUID := uuid.New(), uuid.New()

	tokens, err := svc.GenerateTokens(ctx, tenantID, clientUUID, uuid.New(), "read", false)
	require.NoError(t, err)

	// Valid before revocation
	_, err = svc.ValidateAccessToken(ctx, tenantID, tokens.AccessToken)
	require.NoError(t, err)

	// Revoked by the owning client → JWT signature alone is no longer enough
	require.NoError(t, svc.RevokeToken(ctx, tenantID, tokens.AccessToken, "access_token", clientUUID))
	_, err = svc.ValidateAccessToken(ctx, tenantID, tokens.AccessToken)
	assert.ErrorIs(t, err, models.ErrRevokedToken)
}

func TestRevokeToken_RefreshToken_RevokesFamily(t *testing.T) {
	svc, _ := newAuthServiceWithFakes()
	ctx := context.Background()
	tenantID, clientUUID := uuid.New(), uuid.New()

	tokens, err := svc.GenerateTokens(ctx, tenantID, clientUUID, uuid.New(), "read", false)
	require.NoError(t, err)

	require.NoError(t, svc.RevokeToken(ctx, tenantID, tokens.RefreshToken, "", clientUUID))

	// Both the refresh token and its sibling access token are dead
	_, err = svc.RefreshTokens(ctx, tenantID, tokens.RefreshToken, clientUUID.String(), "")
	assert.ErrorIs(t, err, models.ErrInvalidGrant)
	_, err = svc.ValidateAccessToken(ctx, tenantID, tokens.AccessToken)
	assert.Error(t, err)
}

func TestRevokeToken_OtherClientsToken_Ignored(t *testing.T) {
	svc, _ := newAuthServiceWithFakes()
	ctx := context.Background()
	tenantID, ownerClient, otherClient := uuid.New(), uuid.New(), uuid.New()

	tokens, err := svc.GenerateTokens(ctx, tenantID, ownerClient, uuid.New(), "read", false)
	require.NoError(t, err)

	// A different client revoking the token is a no-op (RFC 7009 §2.1)
	require.NoError(t, svc.RevokeToken(ctx, tenantID, tokens.AccessToken, "access_token", otherClient))
	_, err = svc.ValidateAccessToken(ctx, tenantID, tokens.AccessToken)
	assert.NoError(t, err, "token owned by another client must remain valid")
}

// ---- Introspection uses hashed lookup ----

func TestIntrospectToken_ActiveThenRevoked(t *testing.T) {
	svc, _ := newAuthServiceWithFakes()
	ctx := context.Background()
	tenantID, clientUUID := uuid.New(), uuid.New()

	tokens, err := svc.GenerateTokens(ctx, tenantID, clientUUID, uuid.New(), "read", false)
	require.NoError(t, err)

	result, err := svc.IntrospectToken(ctx, tenantID, tokens.AccessToken)
	require.NoError(t, err)
	assert.True(t, result.Active)
	assert.Equal(t, "read", result.Scope)
	assert.Equal(t, clientUUID.String(), result.ClientID)

	require.NoError(t, svc.RevokeToken(ctx, tenantID, tokens.AccessToken, "access_token", clientUUID))
	result, err = svc.IntrospectToken(ctx, tenantID, tokens.AccessToken)
	require.NoError(t, err)
	assert.False(t, result.Active)
}
