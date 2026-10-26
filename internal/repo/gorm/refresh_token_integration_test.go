//go:build integration

package gorm_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"shieldgate/internal/models"
	gormrepo "shieldgate/internal/repo/gorm"
)

func TestIntegration_RefreshTokenRevoke_ExactlyOneConcurrentWinner(t *testing.T) {
	// Arrange
	db := openTestDB(t)
	repos := gormrepo.NewRepositories(db)
	ctx := context.Background()
	token := &models.RefreshToken{
		ID: uuid.New(), TenantID: uuid.New(), Token: "it-" + uuid.NewString(), ClientID: uuid.New(), UserID: uuid.New(),
		FamilyID: uuid.New(), Scope: "read", ExpiresAt: time.Now().Add(time.Hour),
	}
	require.NoError(t, repos.RefreshToken.Create(ctx, token))
	const workers = 16
	var winners atomic.Int32
	start := make(chan struct{})
	var wg sync.WaitGroup

	// Act
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			revoked, err := repos.RefreshToken.Revoke(ctx, token.TenantID, token.Token)
			assert.NoError(t, err)
			if revoked {
				winners.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()

	// Assert
	assert.Equal(t, int32(1), winners.Load(), "exactly one rotation may claim the token")
	got, err := repos.RefreshToken.GetByToken(ctx, token.TenantID, token.Token)
	require.NoError(t, err)
	assert.True(t, got.IsRevoked())
	again, err := repos.RefreshToken.Revoke(ctx, token.TenantID, "it-missing-"+uuid.NewString())
	assert.NoError(t, err)
	assert.False(t, again, "an unknown token is never claimed")
}
