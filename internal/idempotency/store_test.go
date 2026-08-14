package idempotency_test

import (
	"context"
	"testing"
	"time"

	"shieldgate/internal/idempotency"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ─── MemoryStore tests ───────────────────────────────────────────────────────

func TestMemoryStore_SetProcessing_NewKey_ReturnsTrue(t *testing.T) {
	store := idempotency.NewMemoryStore(time.Minute)
	claimed, err := store.SetProcessing(context.Background(), "key-1")
	require.NoError(t, err)
	assert.True(t, claimed, "first claim should succeed")
}

func TestMemoryStore_SetProcessing_DuplicateKey_ReturnsFalse(t *testing.T) {
	store := idempotency.NewMemoryStore(time.Minute)
	_, _ = store.SetProcessing(context.Background(), "key-dup")

	claimed, err := store.SetProcessing(context.Background(), "key-dup")
	require.NoError(t, err)
	assert.False(t, claimed, "second claim on same key should fail")
}

func TestMemoryStore_GetResponse_UnknownKey_ReturnsNil(t *testing.T) {
	store := idempotency.NewMemoryStore(time.Minute)
	rec, err := store.GetResponse(context.Background(), "does-not-exist")
	require.NoError(t, err)
	assert.Nil(t, rec)
}

func TestMemoryStore_GetResponse_ProcessingKey_ReturnsErrProcessing(t *testing.T) {
	store := idempotency.NewMemoryStore(time.Minute)
	_, _ = store.SetProcessing(context.Background(), "key-in-flight")

	rec, err := store.GetResponse(context.Background(), "key-in-flight")
	assert.Nil(t, rec)
	assert.ErrorIs(t, err, idempotency.ErrProcessing)
}

func TestMemoryStore_SaveResponse_ThenGetResponse_ReturnsRecord(t *testing.T) {
	store := idempotency.NewMemoryStore(time.Minute)
	ctx := context.Background()
	key := "key-done"

	_, _ = store.SetProcessing(ctx, key)

	want := &idempotency.Record{StatusCode: 201, Body: []byte(`{"id":"abc"}`)}
	require.NoError(t, store.SaveResponse(ctx, key, want))

	got, err := store.GetResponse(ctx, key)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, want.StatusCode, got.StatusCode)
	assert.Equal(t, want.Body, got.Body)
}

func TestMemoryStore_TTL_Expiry(t *testing.T) {
	store := idempotency.NewMemoryStore(10 * time.Millisecond)
	ctx := context.Background()
	key := "key-expires"

	_, _ = store.SetProcessing(ctx, key)
	require.NoError(t, store.SaveResponse(ctx, key, &idempotency.Record{StatusCode: 200}))

	time.Sleep(20 * time.Millisecond)

	rec, err := store.GetResponse(ctx, key)
	require.NoError(t, err)
	assert.Nil(t, rec, "record should have expired")
}

func TestMemoryStore_DifferentKeys_Independent(t *testing.T) {
	store := idempotency.NewMemoryStore(time.Minute)
	ctx := context.Background()

	claimed1, _ := store.SetProcessing(ctx, "key-A")
	claimed2, _ := store.SetProcessing(ctx, "key-B")

	assert.True(t, claimed1, "key-A should be claimable")
	assert.True(t, claimed2, "key-B should be claimable independently")
}
