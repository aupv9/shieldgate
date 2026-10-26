package services

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"sync"
	"time"

	"github.com/google/uuid"
)

const (
	// clientSecretCacheTTL bounds how long a verified secret skips bcrypt
	clientSecretCacheTTL = 10 * time.Minute
	// maxCachedClientSecrets bounds the cache; one entry per client
	maxCachedClientSecrets = 10000
)

// clientSecretCache remembers client secrets that passed bcrypt, so a
// client authenticating on every request does not pay a full bcrypt
// comparison each time. bcrypt was the token endpoint's bottleneck under
// load (docs/LOAD_TEST.md).
//
// It is safe because client secrets are always server-generated 256-bit
// random values (generateClientSecret), for which bcrypt's slowness adds
// nothing over a keyed hash. Only successful verifications are cached:
// a wrong secret always goes through bcrypt, so guessing stays as slow as
// before. Entries are keyed by the stored bcrypt hash, so rotating a secret
// invalidates them; the client itself is still loaded on every request, so
// deleting it takes effect at once.
type clientSecretCache struct {
	key []byte
	ttl time.Duration
	now func() time.Time

	mu      sync.Mutex
	entries map[clientSecretCacheKey]clientSecretCacheEntry
}

type clientSecretCacheKey struct {
	clientID   uuid.UUID
	storedHash string
}

type clientSecretCacheEntry struct {
	mac     []byte
	expires time.Time
}

func newClientSecretCache(ttl time.Duration, now func() time.Time) *clientSecretCache {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		// Without a key the cache would be unsafe; run without it
		return nil
	}
	return &clientSecretCache{key: key, ttl: ttl, now: now, entries: make(map[clientSecretCacheKey]clientSecretCacheEntry)}
}

// verified reports whether secret was verified against storedHash recently
func (c *clientSecretCache) verified(clientID uuid.UUID, storedHash, secret string) bool {
	if c == nil {
		return false
	}
	k := clientSecretCacheKey{clientID, storedHash}
	c.mu.Lock()
	entry, ok := c.entries[k]
	c.mu.Unlock()
	if !ok || !c.now().Before(entry.expires) {
		return false
	}
	return hmac.Equal(entry.mac, c.mac(secret))
}

// remember records that secret matched storedHash
func (c *clientSecretCache) remember(clientID uuid.UUID, storedHash, secret string) {
	if c == nil {
		return
	}
	entry := clientSecretCacheEntry{mac: c.mac(secret), expires: c.now().Add(c.ttl)}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= maxCachedClientSecrets {
		c.entries = make(map[clientSecretCacheKey]clientSecretCacheEntry)
	}
	c.entries[clientSecretCacheKey{clientID, storedHash}] = entry
}

func (c *clientSecretCache) mac(secret string) []byte {
	m := hmac.New(sha256.New, c.key)
	m.Write([]byte(secret))
	return m.Sum(nil)
}
