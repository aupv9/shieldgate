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

func newIdemRecord(tenantID uuid.UUID, key string) *models.IdempotencyKey {
	return &models.IdempotencyKey{
		ID: uuid.New(), TenantID: tenantID, Principal: "user:x", Key: key,
		Method: "POST", Path: "/v1/clients", RequestHash: "h", ExpiresAt: time.Now().Add(time.Hour),
	}
}

func TestIntegration_Idempotency_ConcurrentBeginOneWinner(t *testing.T) {
	// Arrange
	db := openTestDB(t)
	store := gormrepo.NewIdempotencyRepository(db)
	ctx := context.Background()
	tenantID := uuid.New()

	// Act
	var wg sync.WaitGroup
	var mu sync.Mutex
	winners, losers := 0, 0
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			stored, existing, err := store.Begin(ctx, newIdemRecord(tenantID, "k"), time.Now().Add(-time.Minute))
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				assert.ErrorIs(t, err, models.ErrResourceConflict)
				losers++
				return
			}
			if stored {
				winners++
			} else {
				assert.True(t, existing.InProgress())
				losers++
			}
		}()
	}
	wg.Wait()

	// Assert
	assert.Equal(t, 1, winners)
	assert.Equal(t, 9, losers)
}

func TestIntegration_Idempotency_CompleteThenBegin_ReturnsStoredResponse(t *testing.T) {
	// Arrange
	db := openTestDB(t)
	store := gormrepo.NewIdempotencyRepository(db)
	ctx := context.Background()
	tenantID := uuid.New()
	first := newIdemRecord(tenantID, "k")
	stored, _, err := store.Begin(ctx, first, time.Now().Add(-time.Minute))
	require.NoError(t, err)
	require.True(t, stored)
	require.NoError(t, store.Complete(ctx, first.ID, 201, "application/json", []byte(`{"id":"c-1"}`)))

	// Act
	stored, existing, err := store.Begin(ctx, newIdemRecord(tenantID, "k"), time.Now().Add(-time.Minute))

	// Assert
	require.NoError(t, err)
	assert.False(t, stored)
	assert.Equal(t, 201, existing.StatusCode)
	assert.Equal(t, "application/json", existing.ResponseContentType)
	assert.JSONEq(t, `{"id":"c-1"}`, string(existing.ResponseBody))
}

func TestIntegration_Idempotency_DeadRecordsAreTakenOver(t *testing.T) {
	tests := []struct {
		name string
		// expired makes the first record expire immediately
		expired bool
		// staleBefore is passed to the second Begin
		staleBefore time.Time
	}{
		{"expired", true, time.Now().Add(-time.Minute)},
		{"abandoned in progress", false, time.Now().Add(time.Minute)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			db := openTestDB(t)
			store := gormrepo.NewIdempotencyRepository(db)
			ctx := context.Background()
			tenantID := uuid.New()
			old := newIdemRecord(tenantID, "k")
			if tt.expired {
				old.ExpiresAt = time.Now().Add(-time.Second)
			}
			_, _, err := store.Begin(ctx, old, time.Now().Add(-time.Minute))
			require.NoError(t, err)
			if tt.expired {
				require.NoError(t, store.Complete(ctx, old.ID, 201, "application/json", []byte(`{}`)))
			}

			// Act
			stored, _, err := store.Begin(ctx, newIdemRecord(tenantID, "k"), tt.staleBefore)

			// Assert
			require.NoError(t, err)
			assert.True(t, stored)
		})
	}
}

func TestIntegration_Idempotency_LiveInProgressNotTakenOver(t *testing.T) {
	// Arrange
	db := openTestDB(t)
	store := gormrepo.NewIdempotencyRepository(db)
	ctx := context.Background()
	tenantID := uuid.New()
	_, _, err := store.Begin(ctx, newIdemRecord(tenantID, "k"), time.Now().Add(-time.Minute))
	require.NoError(t, err)

	// Act
	stored, existing, err := store.Begin(ctx, newIdemRecord(tenantID, "k"), time.Now().Add(-time.Minute))

	// Assert
	require.NoError(t, err)
	assert.False(t, stored)
	assert.True(t, existing.InProgress())
}
