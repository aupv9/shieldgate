// Package blocklist provides fast, distributed token revocation without a DB round-trip.
package blocklist

import (
	"context"
	"sync"
	"time"
)

// TokenBlocklist marks JWT tokens as revoked before their natural expiry.
type TokenBlocklist interface {
	// Block marks a token as revoked for the given TTL.
	Block(ctx context.Context, token string, ttl time.Duration) error
	// IsBlocked reports whether the token is currently blocked.
	IsBlocked(ctx context.Context, token string) (bool, error)
}

// MemoryBlocklist is a single-process, in-memory implementation of TokenBlocklist.
// Use RedisBlocklist for distributed / multi-node deployments.
type MemoryBlocklist struct {
	mu      sync.RWMutex
	entries map[string]time.Time
}

// NewMemoryBlocklist creates an empty in-memory blocklist.
func NewMemoryBlocklist() *MemoryBlocklist {
	return &MemoryBlocklist{entries: make(map[string]time.Time)}
}

func (m *MemoryBlocklist) Block(_ context.Context, token string, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries[token] = time.Now().Add(ttl)
	return nil
}

func (m *MemoryBlocklist) IsBlocked(_ context.Context, token string) (bool, error) {
	m.mu.RLock()
	exp, ok := m.entries[token]
	m.mu.RUnlock()
	if !ok {
		return false, nil
	}
	if time.Now().After(exp) {
		m.mu.Lock()
		delete(m.entries, token)
		m.mu.Unlock()
		return false, nil
	}
	return true, nil
}
