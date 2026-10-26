package tests

// registration_service_test.go covers roadmap 4.2: dynamic client
// registration (RFC 7591), client self-management (RFC 7592) and initial
// access tokens.

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"shieldgate/internal/models"
	"shieldgate/internal/repo"
	"shieldgate/internal/services"
)

// fakeIATRepo mirrors the repository's semantics in memory
type fakeIATRepo struct {
	mu     sync.Mutex
	tokens map[uuid.UUID]*models.InitialAccessToken
}

func (r *fakeIATRepo) Create(ctx context.Context, t *models.InitialAccessToken) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	stored := *t
	r.tokens[t.ID] = &stored
	return nil
}

func (r *fakeIATRepo) GetByHash(ctx context.Context, tenantID uuid.UUID, hash string) (*models.InitialAccessToken, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, t := range r.tokens {
		if t.TenantID == tenantID && t.TokenHash == hash {
			copied := *t
			return &copied, nil
		}
	}
	return nil, models.ErrInitialAccessTokenNotFound
}

func (r *fakeIATRepo) Consume(ctx context.Context, tenantID uuid.UUID, hash string) (*models.InitialAccessToken, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, t := range r.tokens {
		if t.TenantID == tenantID && t.TokenHash == hash && t.RevokedAt == nil && time.Now().Before(t.ExpiresAt) && t.Uses < t.MaxUses {
			t.Uses++
			copied := *t
			return &copied, nil
		}
	}
	return nil, models.ErrInitialAccessTokenNotFound
}

func (r *fakeIATRepo) List(ctx context.Context, tenantID uuid.UUID) ([]*models.InitialAccessToken, error) {
	return nil, nil
}

func (r *fakeIATRepo) Revoke(ctx context.Context, tenantID, id uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	t, ok := r.tokens[id]
	if !ok || t.TenantID != tenantID || t.RevokedAt != nil {
		return models.ErrInitialAccessTokenNotFound
	}
	now := time.Now()
	t.RevokedAt = &now
	return nil
}

type registrationFixture struct {
	ctx      context.Context
	tenantID uuid.UUID
	repos    *repo.Repositories
	iats     *fakeIATRepo
	svc      services.RegistrationService
	auth     services.AuthService
}

func newRegistrationFixture(t *testing.T) *registrationFixture {
	t.Helper()
	f := &registrationFixture{ctx: context.Background(), tenantID: uuid.New()}
	f.auth, f.repos = newAuthServiceWithFakes()
	f.iats = &fakeIATRepo{tokens: map[uuid.UUID]*models.InitialAccessToken{}}
	f.repos.InitialAccess = f.iats
	f.svc = services.NewRegistrationService(f.repos, services.NewClientService(f.repos, quietLogger()), "https://auth.example/", quietLogger())
	return f
}

// issue creates an initial access token allowing scopes
func (f *registrationFixture) issue(t *testing.T, maxUses int, scopes ...string) string {
	t.Helper()
	created, err := f.svc.CreateInitialAccessToken(f.ctx, f.tenantID, nil, &models.CreateInitialAccessTokenRequest{Scopes: scopes, MaxUses: maxUses})
	require.NoError(t, err)
	return created.Token
}

func webMetadata() *models.ClientMetadata {
	return &models.ClientMetadata{
		ClientName:   "Partner App",
		RedirectURIs: []string{"https://partner.example/cb"},
		GrantTypes:   []string{"authorization_code", "refresh_token"},
		Scope:        "openid profile",
	}
}

func registrationErrorCode(err error) string {
	var regErr *models.RegistrationError
	if errors.As(err, &regErr) {
		return regErr.Code
	}
	return ""
}

func TestRegister_ConfidentialClient_StoresHashesAndReturnsCredentialsOnce(t *testing.T) {
	// Arrange
	f := newRegistrationFixture(t)
	iat := f.issue(t, 1, "openid", "profile", "email")

	// Act
	resp, err := f.svc.Register(f.ctx, f.tenantID, iat, webMetadata())

	// Assert
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(resp.ClientID, "client_"))
	assert.NotEmpty(t, resp.ClientSecret)
	require.NotNil(t, resp.ClientSecretExpiresAt)
	assert.Zero(t, *resp.ClientSecretExpiresAt, "0 means the secret does not expire")
	assert.NotEmpty(t, resp.RegistrationAccessToken)
	assert.Equal(t, "https://auth.example/oauth/register/"+resp.ClientID, resp.RegistrationClientURI)
	assert.Equal(t, "client_secret_basic", resp.TokenEndpointAuthMethod, "RFC 7591 default")
	assert.Equal(t, []string{"code"}, resp.ResponseTypes)
	assert.Equal(t, "openid profile", resp.Scope)

	stored, err := f.repos.Client.GetByClientID(f.ctx, f.tenantID, resp.ClientID)
	require.NoError(t, err)
	assert.True(t, stored.DynamicallyRegistered)
	assert.False(t, stored.IsPublic)
	assert.NoError(t, bcrypt.CompareHashAndPassword([]byte(stored.ClientSecret), []byte(resp.ClientSecret)), "secret stored as bcrypt hash")
	assert.NotEqual(t, resp.RegistrationAccessToken, stored.RegistrationAccessToken, "registration token stored as hash")

	// The new client works at the token endpoint
	client, err := services.NewClientService(f.repos, quietLogger()).ValidateClient(f.ctx, f.tenantID, resp.ClientID, resp.ClientSecret)
	require.NoError(t, err)
	assert.Equal(t, stored.ID, client.ID)
}

func TestRegister_PublicNativeClient(t *testing.T) {
	// Arrange
	f := newRegistrationFixture(t)
	meta := &models.ClientMetadata{
		TokenEndpointAuthMethod: "none",
		RedirectURIs:            []string{"com.example.app:/oauth2redirect", "http://127.0.0.1:51004/cb"},
	}

	// Act
	resp, err := f.svc.Register(f.ctx, f.tenantID, f.issue(t, 1, "openid"), meta)

	// Assert
	require.NoError(t, err)
	assert.Empty(t, resp.ClientSecret)
	assert.Nil(t, resp.ClientSecretExpiresAt)
	assert.Equal(t, "openid", resp.Scope, "scope defaults to what the initial access token allows")
	assert.Equal(t, "Dynamically registered client", resp.ClientName)
	stored, _ := f.repos.Client.GetByClientID(f.ctx, f.tenantID, resp.ClientID)
	assert.True(t, stored.IsPublic)
}

func TestRegister_InvalidMetadata(t *testing.T) {
	tests := []struct {
		name     string
		mutate   func(m *models.ClientMetadata)
		wantCode string
	}{
		{"javascript redirect", func(m *models.ClientMetadata) { m.RedirectURIs = []string{"javascript:alert(1)"} }, "invalid_redirect_uri"},
		{"data redirect", func(m *models.ClientMetadata) { m.RedirectURIs = []string{"data:text/html,x"} }, "invalid_redirect_uri"},
		{"plain http", func(m *models.ClientMetadata) { m.RedirectURIs = []string{"http://partner.example/cb"} }, "invalid_redirect_uri"},
		{"fragment", func(m *models.ClientMetadata) { m.RedirectURIs = []string{"https://partner.example/cb#x"} }, "invalid_redirect_uri"},
		{"relative", func(m *models.ClientMetadata) { m.RedirectURIs = []string{"/cb"} }, "invalid_redirect_uri"},
		{"userinfo", func(m *models.ClientMetadata) { m.RedirectURIs = []string{"https://evil@partner.example/cb"} }, "invalid_redirect_uri"},
		{"no redirect for code", func(m *models.ClientMetadata) { m.RedirectURIs = nil }, "invalid_redirect_uri"},
		{"too many redirects", func(m *models.ClientMetadata) {
			m.RedirectURIs = nil
			for i := 0; i < 11; i++ {
				m.RedirectURIs = append(m.RedirectURIs, "https://partner.example/cb"+strings.Repeat("x", i))
			}
		}, "invalid_redirect_uri"},
		{"bad post-logout uri", func(m *models.ClientMetadata) { m.PostLogoutRedirectURIs = []string{"http://evil.example"} }, "invalid_redirect_uri"},
		{"token exchange grant", func(m *models.ClientMetadata) {
			m.GrantTypes = []string{"urn:ietf:params:oauth:grant-type:token-exchange"}
		}, "invalid_client_metadata"},
		{"password grant", func(m *models.ClientMetadata) { m.GrantTypes = []string{"password"} }, "invalid_client_metadata"},
		{"implicit response type", func(m *models.ClientMetadata) { m.ResponseTypes = []string{"token"} }, "invalid_client_metadata"},
		{"lone refresh_token", func(m *models.ClientMetadata) { m.GrantTypes = []string{"refresh_token"} }, "invalid_client_metadata"},
		{"public client_credentials", func(m *models.ClientMetadata) {
			m.GrantTypes, m.TokenEndpointAuthMethod = []string{"client_credentials"}, "none"
		}, "invalid_client_metadata"},
		{"unknown auth method", func(m *models.ClientMetadata) { m.TokenEndpointAuthMethod = "private_key_jwt" }, "invalid_client_metadata"},
		{"scope beyond token", func(m *models.ClientMetadata) { m.Scope = "openid admin" }, "invalid_client_metadata"},
		{"malformed scope", func(m *models.ClientMetadata) { m.Scope = `openid "x"` }, "invalid_client_metadata"},
		{"control characters in name", func(m *models.ClientMetadata) { m.ClientName = "App\nInjected" }, "invalid_client_metadata"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			f := newRegistrationFixture(t)
			iat := f.issue(t, 1, "openid", "profile")
			meta := webMetadata()
			tt.mutate(meta)

			// Act
			_, err := f.svc.Register(f.ctx, f.tenantID, iat, meta)

			// Assert
			assert.Equal(t, tt.wantCode, registrationErrorCode(err), "error: %v", err)
			_, retryErr := f.svc.Register(f.ctx, f.tenantID, iat, webMetadata())
			assert.NoError(t, retryErr, "a rejected request must not spend the token's single use")
		})
	}
}

func TestRegister_InitialAccessTokenRules(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(f *registrationFixture, t *testing.T) string
	}{
		{"missing", func(f *registrationFixture, t *testing.T) string { return "" }},
		{"unknown", func(f *registrationFixture, t *testing.T) string { return "not-a-token" }},
		{"used up", func(f *registrationFixture, t *testing.T) string {
			iat := f.issue(t, 1, "openid", "profile")
			_, err := f.svc.Register(f.ctx, f.tenantID, iat, webMetadata())
			require.NoError(t, err)
			return iat
		}},
		{"expired", func(f *registrationFixture, t *testing.T) string {
			iat := f.issue(t, 1, "openid", "profile")
			for _, tok := range f.iats.tokens {
				tok.ExpiresAt = time.Now().Add(-time.Second)
			}
			return iat
		}},
		{"revoked", func(f *registrationFixture, t *testing.T) string {
			iat := f.issue(t, 5, "openid", "profile")
			for id := range f.iats.tokens {
				require.NoError(t, f.svc.RevokeInitialAccessToken(f.ctx, f.tenantID, id))
			}
			return iat
		}},
		{"other tenant", func(f *registrationFixture, t *testing.T) string {
			other := f.tenantID
			f.tenantID = uuid.New()
			iat := f.issue(t, 1, "openid", "profile")
			f.tenantID = other
			return iat
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			f := newRegistrationFixture(t)
			iat := tt.prepare(f, t)

			// Act
			_, err := f.svc.Register(f.ctx, f.tenantID, iat, webMetadata())

			// Assert
			assert.ErrorIs(t, err, models.ErrInvalidToken)
		})
	}
}

func TestRegister_MultiUseToken_CountsUses(t *testing.T) {
	// Arrange
	f := newRegistrationFixture(t)
	iat := f.issue(t, 2, "openid", "profile")

	// Act
	_, err1 := f.svc.Register(f.ctx, f.tenantID, iat, webMetadata())
	_, err2 := f.svc.Register(f.ctx, f.tenantID, iat, webMetadata())
	_, err3 := f.svc.Register(f.ctx, f.tenantID, iat, webMetadata())

	// Assert
	assert.NoError(t, err1)
	assert.NoError(t, err2)
	assert.ErrorIs(t, err3, models.ErrInvalidToken)
}

func TestCreateInitialAccessToken_Validation(t *testing.T) {
	tests := []struct {
		name string
		req  models.CreateInitialAccessTokenRequest
	}{
		{"no scopes", models.CreateInitialAccessTokenRequest{}},
		{"bad scope", models.CreateInitialAccessTokenRequest{Scopes: []string{"a b"}}},
		{"too long", models.CreateInitialAccessTokenRequest{Scopes: []string{"openid"}, ExpiresIn: 31 * 24 * 3600}},
		{"negative uses", models.CreateInitialAccessTokenRequest{Scopes: []string{"openid"}, MaxUses: -1}},
		{"too many uses", models.CreateInitialAccessTokenRequest{Scopes: []string{"openid"}, MaxUses: 1001}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newRegistrationFixture(t)
			_, err := f.svc.CreateInitialAccessToken(f.ctx, f.tenantID, nil, &tt.req)
			assert.Equal(t, "invalid_client_metadata", registrationErrorCode(err))
		})
	}

	t.Run("defaults and hashing", func(t *testing.T) {
		f := newRegistrationFixture(t)
		created, err := f.svc.CreateInitialAccessToken(f.ctx, f.tenantID, nil, &models.CreateInitialAccessTokenRequest{Scopes: []string{"openid"}})
		require.NoError(t, err)
		assert.Equal(t, 1, created.MaxUses)
		assert.WithinDuration(t, time.Now().Add(24*time.Hour), created.ExpiresAt, time.Minute)
		assert.NotEqual(t, created.Token, created.TokenHash)
		assert.GreaterOrEqual(t, len(created.Token), 43)
	})
}

func TestClientConfiguration_ReadUpdateDelete(t *testing.T) {
	// Arrange
	f := newRegistrationFixture(t)
	reg, err := f.svc.Register(f.ctx, f.tenantID, f.issue(t, 1, "openid", "profile"), webMetadata())
	require.NoError(t, err)

	// Act: read
	read, readErr := f.svc.Read(f.ctx, f.tenantID, reg.ClientID, reg.RegistrationAccessToken)

	// Act: update narrows scope and replaces redirect URIs
	update := webMetadata()
	update.ClientID = reg.ClientID
	update.Scope = "openid"
	update.RedirectURIs = []string{"https://partner.example/new-cb"}
	updated, updateErr := f.svc.Update(f.ctx, f.tenantID, reg.ClientID, reg.RegistrationAccessToken, update)

	// Assert
	require.NoError(t, readErr)
	assert.Empty(t, read.ClientSecret, "the secret is never shown again")
	assert.Empty(t, read.RegistrationAccessToken)
	assert.Equal(t, reg.RedirectURIs, read.RedirectURIs)
	require.NoError(t, updateErr)
	assert.Equal(t, "openid", updated.Scope)
	assert.Equal(t, []string{"https://partner.example/new-cb"}, updated.RedirectURIs)
}

func TestClientConfiguration_UpdateRules(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(m *models.ClientMetadata, clientID string)
	}{
		{"widen scope", func(m *models.ClientMetadata, id string) { m.ClientID, m.Scope = id, "openid profile email" }},
		{"switch to public", func(m *models.ClientMetadata, id string) { m.ClientID, m.TokenEndpointAuthMethod = id, "none" }},
		{"client_id mismatch", func(m *models.ClientMetadata, id string) { m.ClientID = "client_other" }},
		{"client_id missing", func(m *models.ClientMetadata, id string) { m.ClientID = "" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			f := newRegistrationFixture(t)
			reg, err := f.svc.Register(f.ctx, f.tenantID, f.issue(t, 1, "openid", "profile", "email"), webMetadata())
			require.NoError(t, err)
			meta := webMetadata()
			tt.mutate(meta, reg.ClientID)

			// Act
			_, err = f.svc.Update(f.ctx, f.tenantID, reg.ClientID, reg.RegistrationAccessToken, meta)

			// Assert
			assert.Equal(t, "invalid_client_metadata", registrationErrorCode(err), "error: %v", err)
		})
	}
}

func TestClientConfiguration_RequiresTheClientsOwnToken(t *testing.T) {
	// Arrange
	f := newRegistrationFixture(t)
	a, err := f.svc.Register(f.ctx, f.tenantID, f.issue(t, 1, "openid"), &models.ClientMetadata{RedirectURIs: []string{"https://a.example/cb"}})
	require.NoError(t, err)
	b, err := f.svc.Register(f.ctx, f.tenantID, f.issue(t, 1, "openid"), &models.ClientMetadata{RedirectURIs: []string{"https://b.example/cb"}})
	require.NoError(t, err)
	admin, err := services.NewClientService(f.repos, quietLogger()).Create(f.ctx, f.tenantID, &models.CreateClientRequest{
		Name: "Admin app", RedirectURIs: []string{"https://admin.example/cb"}, GrantTypes: []string{"authorization_code"}, Scopes: []string{"openid"},
	})
	require.NoError(t, err)

	// Act
	_, crossErr := f.svc.Read(f.ctx, f.tenantID, a.ClientID, b.RegistrationAccessToken)
	_, missingErr := f.svc.Read(f.ctx, f.tenantID, a.ClientID, "")
	_, unknownErr := f.svc.Read(f.ctx, f.tenantID, "client_nope", a.RegistrationAccessToken)
	_, adminErr := f.svc.Read(f.ctx, f.tenantID, admin.ClientID, a.RegistrationAccessToken)
	deleteErr := f.svc.Delete(f.ctx, f.tenantID, a.ClientID, b.RegistrationAccessToken)

	// Assert
	for _, err := range []error{crossErr, missingErr, unknownErr, adminErr, deleteErr} {
		assert.ErrorIs(t, err, models.ErrInvalidToken, "all failures look alike")
	}
	_, stillThere := f.repos.Client.GetByClientID(f.ctx, f.tenantID, a.ClientID)
	assert.NoError(t, stillThere)
}

func TestClientConfiguration_DeleteRevokesTokens(t *testing.T) {
	// Arrange
	f := newRegistrationFixture(t)
	reg, err := f.svc.Register(f.ctx, f.tenantID, f.issue(t, 1, "read"),
		&models.ClientMetadata{GrantTypes: []string{"client_credentials"}, Scope: "read"})
	require.NoError(t, err)
	client, err := f.repos.Client.GetByClientID(f.ctx, f.tenantID, reg.ClientID)
	require.NoError(t, err)
	tokens, err := f.auth.GenerateClientCredentialsTokens(f.ctx, f.tenantID, client, "read")
	require.NoError(t, err)

	// Act
	err = f.svc.Delete(f.ctx, f.tenantID, reg.ClientID, reg.RegistrationAccessToken)

	// Assert
	require.NoError(t, err)
	_, getErr := f.repos.Client.GetByClientID(f.ctx, f.tenantID, reg.ClientID)
	assert.ErrorIs(t, getErr, models.ErrClientNotFound)
	_, validateErr := f.auth.ValidateAccessToken(f.ctx, f.tenantID, tokens.AccessToken)
	assert.Error(t, validateErr, "a deleted client's tokens stop working")
	_, readErr := f.svc.Read(f.ctx, f.tenantID, reg.ClientID, reg.RegistrationAccessToken)
	assert.ErrorIs(t, readErr, models.ErrInvalidToken)
}

func TestClientService_AdminDelete_RevokesTokens(t *testing.T) {
	// Arrange
	auth, repos := newAuthServiceWithFakes()
	ctx, tenantID := context.Background(), uuid.New()
	clients := services.NewClientService(repos, quietLogger())
	client, err := clients.Create(ctx, tenantID, &models.CreateClientRequest{
		Name: "svc", RedirectURIs: []string{"https://svc.example/cb"}, GrantTypes: []string{"client_credentials"}, Scopes: []string{"read"},
	})
	require.NoError(t, err)
	tokens, err := auth.GenerateClientCredentialsTokens(ctx, tenantID, client, "read")
	require.NoError(t, err)

	// Act
	require.NoError(t, clients.Delete(ctx, tenantID, client.ID))

	// Assert
	_, err = auth.ValidateAccessToken(ctx, tenantID, tokens.AccessToken)
	assert.Error(t, err)
}

func TestDiscovery_AdvertisesRegistrationEndpoint(t *testing.T) {
	// Arrange
	svc, _ := newAuthServiceWithFakes()

	// Act
	doc, err := svc.GetDiscoveryDocument(context.Background())

	// Assert
	require.NoError(t, err)
	assert.True(t, strings.HasSuffix(doc.RegistrationEndpoint, "/oauth/register"), doc.RegistrationEndpoint)
}
