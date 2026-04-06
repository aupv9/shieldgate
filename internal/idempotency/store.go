// Package idempotency provides safe-retry semantics for mutating HTTP endpoints.
//
// When a client supplies an "Idempotency-Key" header on a POST request, the
// server records the response for that key and replays it verbatim on any
// subsequent request carrying the same key, instead of executing the operation
// again.  This prevents duplicate tenant/user/client creation caused by network
// retries or client-side failures.
//
// Behaviour:
//   - First request with key K  → execute handler, store (status + body), return response
//   - Repeat request  with key K → return stored response immediately (HTTP 200 or original code)
//   - TTL: stored responses expire after 24 h by default
//
// Two backend implementations are provided:
//   - RedisStore  – production, distributed (uses RedisClient.SetNX for atomic check-and-set)
//   - MemoryStore – single-process fallback (safe for tests, not for multi-replica deployments)
package idempotency

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"shieldgate/internal/database"
)

const (
	// DefaultTTL is how long idempotency records are retained.
	DefaultTTL = 24 * time.Hour

	// keyPrefix scopes idempotency keys away from other Redis keys.
	keyPrefix = "idempotency:"

	// StatusProcessing is stored while the first request is still running so that
	// a concurrent duplicate can detect the in-flight state and return 409.
	StatusProcessing = "processing"
)

// Record is the payload stored for a completed request.
type Record struct {
	StatusCode int    `json:"status_code"`
	Body       []byte `json:"body"`
}

// Store is the backend-agnostic idempotency interface.
type Store interface {
	// SetProcessing atomically marks key as in-flight.
	// Returns (true, nil) when the key was newly reserved.
	// Returns (false, nil) when the key already exists (duplicate request).
	SetProcessing(ctx context.Context, key string) (bool, error)

	// SaveResponse persists the final response for key, replacing the
	// "processing" sentinel.
	SaveResponse(ctx context.Context, key string, rec *Record) error

	// GetResponse retrieves a previously stored response.
	// Returns (nil, nil) when the key does not exist.
	GetResponse(ctx context.Context, key string) (*Record, error)
}

// ─── Redis implementation ────────────────────────────────────────────────────

// RedisStore stores idempotency records in Redis.
type RedisStore struct {
	redis *database.RedisClient
	ttl   time.Duration
}

// NewRedisStore creates a Redis-backed Store with the given TTL.
func NewRedisStore(redis *database.RedisClient, ttl time.Duration) *RedisStore {
	return &RedisStore{redis: redis, ttl: ttl}
}

func (s *RedisStore) redisKey(key string) string {
	return keyPrefix + key
}

// SetProcessing uses SetNX to atomically claim the key.
func (s *RedisStore) SetProcessing(ctx context.Context, key string) (bool, error) {
	rk := s.redisKey(key)
	ok, err := s.redis.SetNX(ctx, rk, StatusProcessing, s.ttl)
	return ok, err
}

// SaveResponse serialises the record and overwrites the processing sentinel.
func (s *RedisStore) SaveResponse(ctx context.Context, key string, rec *Record) error {
	data, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("idempotency: failed to marshal record: %w", err)
	}
	return s.redis.Set(ctx, s.redisKey(key), data, s.ttl)
}

// GetResponse retrieves and deserialises a stored record.
// Returns (nil, nil) when the key is absent.
// Returns (nil, ErrProcessing) when the key is still in-flight.
func (s *RedisStore) GetResponse(ctx context.Context, key string) (*Record, error) {
	val, err := s.redis.Get(ctx, s.redisKey(key))
	if err != nil {
		return nil, fmt.Errorf("idempotency: redis get error: %w", err)
	}
	if val == "" {
		return nil, nil // key does not exist
	}
	if val == StatusProcessing {
		return nil, ErrProcessing
	}

	var rec Record
	if err := json.Unmarshal([]byte(val), &rec); err != nil {
		return nil, fmt.Errorf("idempotency: failed to unmarshal record: %w", err)
	}
	return &rec, nil
}

// ─── In-memory implementation ────────────────────────────────────────────────

type memEntry struct {
	value     string
	expiresAt time.Time
}

// MemoryStore is a non-distributed idempotency store backed by a sync.Map.
// Use for single-replica deployments or unit tests.
type MemoryStore struct {
	mu      sync.Mutex
	entries map[string]memEntry
	ttl     time.Duration
}

// NewMemoryStore creates an in-memory Store with the given TTL.
func NewMemoryStore(ttl time.Duration) *MemoryStore {
	return &MemoryStore{
		entries: make(map[string]memEntry),
		ttl:     ttl,
	}
}

func (s *MemoryStore) SetProcessing(ctx context.Context, key string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	if e, ok := s.entries[key]; ok && now.Before(e.expiresAt) {
		return false, nil // already exists
	}
	s.entries[key] = memEntry{value: StatusProcessing, expiresAt: now.Add(s.ttl)}
	return true, nil
}

func (s *MemoryStore) SaveResponse(ctx context.Context, key string, rec *Record) error {
	data, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("idempotency: failed to marshal record: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[key] = memEntry{value: string(data), expiresAt: time.Now().Add(s.ttl)}
	return nil
}

func (s *MemoryStore) GetResponse(ctx context.Context, key string) (*Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.entries[key]
	if !ok || time.Now().After(e.expiresAt) {
		return nil, nil
	}
	if e.value == StatusProcessing {
		return nil, ErrProcessing
	}

	var rec Record
	if err := json.Unmarshal([]byte(e.value), &rec); err != nil {
		return nil, fmt.Errorf("idempotency: failed to unmarshal record: %w", err)
	}
	return &rec, nil
}

// ─── Sentinel errors ─────────────────────────────────────────────────────────

// ErrProcessing is returned by GetResponse when a concurrent request is still
// executing the same idempotency key.
var ErrProcessing = fmt.Errorf("idempotency: request already in progress")
