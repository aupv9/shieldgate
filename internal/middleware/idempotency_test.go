package middleware

// idempotency_test.go covers roadmap 4.4: Idempotency-Key handling for
// management API POSTs.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"shieldgate/internal/models"
)

// memIdempotencyStore mirrors the repository's semantics in memory
type memIdempotencyStore struct {
	mu      sync.Mutex
	records map[string]*models.IdempotencyKey
}

func newMemIdempotencyStore() *memIdempotencyStore {
	return &memIdempotencyStore{records: map[string]*models.IdempotencyKey{}}
}

func scopeOf(r *models.IdempotencyKey) string {
	return r.TenantID.String() + "|" + r.Principal + "|" + r.Key
}

func (s *memIdempotencyStore) Begin(ctx context.Context, record *models.IdempotencyKey, staleBefore time.Time) (bool, *models.IdempotencyKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record.CreatedAt = time.Now()
	if existing, ok := s.records[scopeOf(record)]; ok {
		dead := existing.ExpiresAt.Before(time.Now()) || (existing.InProgress() && existing.CreatedAt.Before(staleBefore))
		if !dead {
			copied := *existing
			return false, &copied, nil
		}
	}
	stored := *record
	s.records[scopeOf(record)] = &stored
	return true, nil, nil
}

func (s *memIdempotencyStore) Complete(ctx context.Context, id uuid.UUID, status int, contentType string, body []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.records {
		if r.ID == id {
			r.StatusCode, r.ResponseContentType, r.ResponseBody = status, contentType, body
		}
	}
	return nil
}

func (s *memIdempotencyStore) Delete(ctx context.Context, id uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, r := range s.records {
		if r.ID == id {
			delete(s.records, k)
		}
	}
	return nil
}

func (s *memIdempotencyStore) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.records)
}

type idempotencyFixture struct {
	store    *memIdempotencyStore
	router   *gin.Engine
	tenantID uuid.UUID
	calls    atomic.Int32
	// status and response are what the handler returns
	status   int
	response gin.H
	// release, when set, blocks the handler until closed
	release chan struct{}
}

func newIdempotencyFixture(t *testing.T) *idempotencyFixture {
	t.Helper()
	gin.SetMode(gin.TestMode)
	f := &idempotencyFixture{store: newMemIdempotencyStore(), tenantID: uuid.New(), status: http.StatusCreated}
	f.response = gin.H{"data": gin.H{"id": "c-1", "client_secret": "s3cret"}}
	f.router = gin.New()
	f.router.Use(func(c *gin.Context) {
		c.Set(TenantIDKey, f.tenantID)
		if user := c.GetHeader("X-Test-User"); user != "" {
			c.Set(UserIDKey, uuid.MustParse(user))
		}
		c.Next()
	})
	f.router.Use(Idempotency(f.store, time.Hour))
	handler := func(c *gin.Context) {
		f.calls.Add(1)
		if f.release != nil {
			<-f.release
		}
		if f.status == http.StatusTeapot {
			panic("boom")
		}
		_, _ = io.ReadAll(c.Request.Body)
		c.JSON(f.status, f.response)
	}
	f.router.POST("/v1/clients", handler)
	f.router.GET("/v1/clients", handler)
	return f
}

func (f *idempotencyFixture) send(method, key, body string, headers ...string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "/v1/clients", strings.NewReader(body))
	if key != "" {
		req.Header.Set(IdempotencyKeyHeader, key)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	w := httptest.NewRecorder()
	f.router.ServeHTTP(w, req)
	return w
}

func TestIdempotency_Retry_ReplaysWithoutRerunning(t *testing.T) {
	// Arrange
	f := newIdempotencyFixture(t)
	first := f.send(http.MethodPost, "key-1", `{"name":"app"}`)

	// Act
	retry := f.send(http.MethodPost, "key-1", `{"name":"app"}`)

	// Assert
	assert.Equal(t, int32(1), f.calls.Load(), "the side effect runs once")
	assert.Equal(t, http.StatusCreated, first.Code)
	assert.Equal(t, http.StatusCreated, retry.Code)
	assert.Equal(t, "true", retry.Header().Get(IdempotentReplayedHeader))
	assert.Empty(t, first.Header().Get(IdempotentReplayedHeader))
	assert.Contains(t, retry.Header().Get("Content-Type"), "application/json")
}

func TestIdempotency_ClientSecret_ReturnedOnceNeverStored(t *testing.T) {
	// Arrange
	f := newIdempotencyFixture(t)

	// Act
	first := f.send(http.MethodPost, "key-1", `{}`)
	retry := f.send(http.MethodPost, "key-1", `{}`)

	// Assert
	assert.Contains(t, first.Body.String(), "s3cret")
	assert.NotContains(t, retry.Body.String(), "s3cret")
	var replayed map[string]map[string]interface{}
	require.NoError(t, json.Unmarshal(retry.Body.Bytes(), &replayed))
	assert.Equal(t, "c-1", replayed["data"]["id"])
	for _, r := range f.store.records {
		assert.NotContains(t, string(r.ResponseBody), "s3cret")
	}
}

func TestIdempotency_SameKeyDifferentBody_Unprocessable(t *testing.T) {
	// Arrange
	f := newIdempotencyFixture(t)
	f.send(http.MethodPost, "key-1", `{"name":"app"}`)

	// Act
	w := f.send(http.MethodPost, "key-1", `{"name":"other"}`)

	// Assert
	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
	assert.Equal(t, int32(1), f.calls.Load())
}

func TestIdempotency_ConcurrentDuplicate_Conflict(t *testing.T) {
	// Arrange
	f := newIdempotencyFixture(t)
	f.release = make(chan struct{})
	done := make(chan *httptest.ResponseRecorder)
	go func() { done <- f.send(http.MethodPost, "key-1", `{}`) }()
	require.Eventually(t, func() bool { return f.calls.Load() == 1 }, time.Second, time.Millisecond)

	// Act
	dup := f.send(http.MethodPost, "key-1", `{}`)
	close(f.release)
	first := <-done

	// Assert
	assert.Equal(t, http.StatusConflict, dup.Code)
	assert.Equal(t, "1", dup.Header().Get("Retry-After"))
	assert.Equal(t, http.StatusCreated, first.Code)
	assert.Equal(t, int32(1), f.calls.Load())
}

func TestIdempotency_ServerError_NotStoredSoRetryRuns(t *testing.T) {
	// Arrange
	f := newIdempotencyFixture(t)
	f.status = http.StatusInternalServerError
	f.send(http.MethodPost, "key-1", `{}`)
	f.status = http.StatusCreated

	// Act
	retry := f.send(http.MethodPost, "key-1", `{}`)

	// Assert
	assert.Equal(t, http.StatusCreated, retry.Code)
	assert.Empty(t, retry.Header().Get(IdempotentReplayedHeader))
	assert.Equal(t, int32(2), f.calls.Load())
}

func TestIdempotency_ClientError_IsReplayed(t *testing.T) {
	// Arrange
	f := newIdempotencyFixture(t)
	f.status = http.StatusConflict
	f.send(http.MethodPost, "key-1", `{}`)

	// Act
	retry := f.send(http.MethodPost, "key-1", `{}`)

	// Assert
	assert.Equal(t, http.StatusConflict, retry.Code)
	assert.Equal(t, "true", retry.Header().Get(IdempotentReplayedHeader))
	assert.Equal(t, int32(1), f.calls.Load())
}

func TestIdempotency_HandlerPanic_ReleasesKey(t *testing.T) {
	// Arrange
	f := newIdempotencyFixture(t)
	f.status = http.StatusTeapot

	// Act
	assert.Panics(t, func() { f.send(http.MethodPost, "key-1", `{}`) })

	// Assert
	assert.Equal(t, 0, f.store.count(), "a crashed request must not block retries")
}

func TestIdempotency_KeysScopedPerPrincipal(t *testing.T) {
	// Arrange
	f := newIdempotencyFixture(t)
	alice, bob := uuid.NewString(), uuid.NewString()
	f.send(http.MethodPost, "key-1", `{}`, "X-Test-User", alice)

	// Act
	w := f.send(http.MethodPost, "key-1", `{}`, "X-Test-User", bob)

	// Assert
	assert.Empty(t, w.Header().Get(IdempotentReplayedHeader), "another principal never sees a replay")
	assert.Equal(t, int32(2), f.calls.Load())
}

func TestIdempotency_Passthrough(t *testing.T) {
	tests := []struct {
		name   string
		method string
		key    string
	}{
		{"POST without key", http.MethodPost, ""},
		{"GET with key", http.MethodGet, "key-1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			f := newIdempotencyFixture(t)

			// Act
			f.send(tt.method, tt.key, `{}`)
			f.send(tt.method, tt.key, `{}`)

			// Assert
			assert.Equal(t, int32(2), f.calls.Load())
			assert.Equal(t, 0, f.store.count())
		})
	}
}

func TestIdempotency_InvalidKey_BadRequest(t *testing.T) {
	tests := map[string]string{
		"too long":       strings.Repeat("k", 256),
		"contains space": "key 1",
		"non-ASCII":      "khóa",
	}
	for name, key := range tests {
		t.Run(name, func(t *testing.T) {
			// Arrange
			f := newIdempotencyFixture(t)

			// Act
			w := f.send(http.MethodPost, key, `{}`)

			// Assert
			assert.Equal(t, http.StatusBadRequest, w.Code)
			assert.Equal(t, int32(0), f.calls.Load())
		})
	}
}

func TestIdempotency_HandlerSeesOriginalBody(t *testing.T) {
	// Arrange
	gin.SetMode(gin.TestMode)
	store := newMemIdempotencyStore()
	router := gin.New()
	router.Use(func(c *gin.Context) { c.Set(TenantIDKey, uuid.New()); c.Next() })
	router.Use(Idempotency(store, time.Hour))
	var seen string
	router.POST("/x", func(c *gin.Context) {
		b, _ := io.ReadAll(c.Request.Body)
		seen = string(b)
		c.Status(http.StatusAccepted)
	})
	req := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(`{"a":1}`))
	req.Header.Set(IdempotencyKeyHeader, "k")

	// Act
	router.ServeHTTP(httptest.NewRecorder(), req)

	// Assert
	assert.Equal(t, `{"a":1}`, seen)
}
