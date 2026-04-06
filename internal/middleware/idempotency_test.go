package middleware_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"shieldgate/internal/idempotency"
	"shieldgate/internal/middleware"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// newTestRouter creates a minimal Gin router with idempotency middleware and a
// POST /test handler that returns 201 with a fixed JSON body.
func newTestRouter(store idempotency.Store) *gin.Engine {
	r := gin.New()
	r.Use(middleware.RequestID())
	r.Use(middleware.Idempotency(store))
	r.POST("/test", func(c *gin.Context) {
		c.JSON(http.StatusCreated, gin.H{"result": "created"})
	})
	return r
}

func doPost(r *gin.Engine, key string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewBufferString(`{}`))
	req.Header.Set("Content-Type", "application/json")
	if key != "" {
		req.Header.Set("Idempotency-Key", key)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// ─── Tests ────────────────────────────────────────────────────────────────────

func TestIdempotencyMiddleware_NoKey_PassesThrough(t *testing.T) {
	store := idempotency.NewMemoryStore(time.Minute)
	r := newTestRouter(store)

	w := doPost(r, "")
	assert.Equal(t, http.StatusCreated, w.Code)
	assert.Empty(t, w.Header().Get("Idempotency-Replayed"))
}

func TestIdempotencyMiddleware_FirstRequest_ExecutesAndStores(t *testing.T) {
	store := idempotency.NewMemoryStore(time.Minute)
	r := newTestRouter(store)

	w := doPost(r, "unique-key-1")
	assert.Equal(t, http.StatusCreated, w.Code)
	assert.Empty(t, w.Header().Get("Idempotency-Replayed"))

	// Verify it was saved in store.
	rec, err := store.GetResponse(context.Background(), "unique-key-1")
	require.NoError(t, err)
	require.NotNil(t, rec)
	assert.Equal(t, http.StatusCreated, rec.StatusCode)
}

func TestIdempotencyMiddleware_RepeatRequest_ReplaysResponse(t *testing.T) {
	store := idempotency.NewMemoryStore(time.Minute)
	r := newTestRouter(store)

	key := "replay-key"
	first := doPost(r, key)
	require.Equal(t, http.StatusCreated, first.Code)

	second := doPost(r, key)
	assert.Equal(t, http.StatusCreated, second.Code, "replayed response should keep original status code")
	assert.Equal(t, "true", second.Header().Get("Idempotency-Replayed"))
	assert.Equal(t, first.Body.String(), second.Body.String(), "replayed body must match original")
}

func TestIdempotencyMiddleware_ProcessingKey_Returns409(t *testing.T) {
	store := idempotency.NewMemoryStore(time.Minute)
	r := newTestRouter(store)

	key := "in-flight-key"
	// Pre-claim the key to simulate a concurrent in-flight request.
	claimed, err := store.SetProcessing(context.Background(), key)
	require.NoError(t, err)
	require.True(t, claimed)

	w := doPost(r, key)
	assert.Equal(t, http.StatusConflict, w.Code)
	assert.Contains(t, w.Body.String(), "IDEMPOTENCY_IN_PROGRESS")
}

func TestIdempotencyMiddleware_GetRequest_Skipped(t *testing.T) {
	store := idempotency.NewMemoryStore(time.Minute)
	r := gin.New()
	r.Use(middleware.Idempotency(store))
	r.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Idempotency-Key", "should-be-ignored")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	// GET with key must NOT be stored.
	rec, _ := store.GetResponse(context.Background(), "should-be-ignored")
	assert.Nil(t, rec)
}
