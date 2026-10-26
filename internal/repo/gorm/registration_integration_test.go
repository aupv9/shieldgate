//go:build integration

package gorm_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"shieldgate/internal/models"
	gormrepo "shieldgate/internal/repo/gorm"
)

func TestIntegration_InitialAccessToken_ConsumeRespectsMaxUsesUnderConcurrency(t *testing.T) {
	// Arrange
	repo := gormrepo.NewInitialAccessTokenRepository(openTestDB(t))
	ctx := context.Background()
	token := &models.InitialAccessToken{ID: uuid.New(), TenantID: uuid.New(), TokenHash: uuid.NewString(),
		Scopes: models.StringArray{"openid"}, MaxUses: 2, ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now()}
	require.NoError(t, repo.Create(ctx, token))

	// Act
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := repo.Consume(ctx, token.TenantID, token.TokenHash)
			if err == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			} else {
				assert.ErrorIs(t, err, models.ErrInitialAccessTokenNotFound)
			}
		}()
	}
	wg.Wait()
	got, err := repo.GetByHash(ctx, token.TenantID, token.TokenHash)

	// Assert
	assert.Equal(t, 2, wins)
	require.NoError(t, err)
	assert.Equal(t, 2, got.Uses)
	assert.Equal(t, models.StringArray{"openid"}, got.Scopes)
}

func TestIntegration_InitialAccessToken_ExpiredOrRevokedNotConsumable(t *testing.T) {
	// Arrange
	repo := gormrepo.NewInitialAccessTokenRepository(openTestDB(t))
	ctx := context.Background()
	tenantID := uuid.New()
	expired := &models.InitialAccessToken{ID: uuid.New(), TenantID: tenantID, TokenHash: uuid.NewString(),
		Scopes: models.StringArray{"openid"}, MaxUses: 5, ExpiresAt: time.Now().Add(-time.Second), CreatedAt: time.Now()}
	revoked := &models.InitialAccessToken{ID: uuid.New(), TenantID: tenantID, TokenHash: uuid.NewString(),
		Scopes: models.StringArray{"openid"}, MaxUses: 5, ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now()}
	require.NoError(t, repo.Create(ctx, expired))
	require.NoError(t, repo.Create(ctx, revoked))
	require.NoError(t, repo.Revoke(ctx, tenantID, revoked.ID))

	// Act
	_, expiredErr := repo.Consume(ctx, tenantID, expired.TokenHash)
	_, revokedErr := repo.Consume(ctx, tenantID, revoked.TokenHash)
	revokeAgainErr := repo.Revoke(ctx, tenantID, revoked.ID)
	listed, listErr := repo.List(ctx, tenantID)

	// Assert
	assert.ErrorIs(t, expiredErr, models.ErrInitialAccessTokenNotFound)
	assert.ErrorIs(t, revokedErr, models.ErrInitialAccessTokenNotFound)
	assert.ErrorIs(t, revokeAgainErr, models.ErrInitialAccessTokenNotFound)
	require.NoError(t, listErr)
	assert.Len(t, listed, 2)
}

func TestIntegration_DynamicClient_RoundTripAndTokenRevocationByClient(t *testing.T) {
	// Arrange
	db := openTestDB(t)
	repos := gormrepo.NewRepositories(db)
	ctx := context.Background()
	tenantID := uuid.New()
	client := &models.Client{ID: uuid.New(), TenantID: tenantID, ClientID: "client_" + uuid.NewString()[:16], Name: "dyn",
		RedirectURIs: models.StringArray{"https://a.example/cb"}, PostLogoutRedirectURIs: models.StringArray{},
		GrantTypes: models.StringArray{"client_credentials"}, Scopes: models.StringArray{"read"},
		TokenEndpointAuthMethod: models.TokenEndpointAuthClientSecretPost, DynamicallyRegistered: true, RegistrationAccessToken: "hash-1"}
	require.NoError(t, repos.Client.Create(ctx, client))
	other := uuid.New()
	for _, owner := range []uuid.UUID{client.ID, other} {
		require.NoError(t, repos.AccessToken.Create(ctx, &models.AccessToken{ID: uuid.New(), TenantID: tenantID, Token: uuid.NewString(),
			ClientID: owner, FamilyID: uuid.New(), ExpiresAt: time.Now().Add(time.Hour)}))
	}

	// Act
	got, getErr := repos.Client.GetByClientID(ctx, tenantID, client.ClientID)
	deleteErr := repos.AccessToken.DeleteByClientID(ctx, tenantID, client.ID)
	var remaining int64
	db.Model(&models.AccessToken{}).Where("tenant_id = ?", tenantID).Count(&remaining)

	// Assert
	require.NoError(t, getErr)
	assert.Equal(t, models.TokenEndpointAuthClientSecretPost, got.TokenEndpointAuthMethod)
	assert.True(t, got.DynamicallyRegistered)
	assert.Equal(t, "hash-1", got.RegistrationAccessToken)
	require.NoError(t, deleteErr)
	assert.EqualValues(t, 1, remaining, "only the deleted client's tokens are removed")
}
