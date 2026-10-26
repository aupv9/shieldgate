package services

// In-package test: the cache is unexported and its clock is injected

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClientSecretCache_Verified_MatchesOnlyRememberedSecret(t *testing.T) {
	// Arrange
	now := time.Now()
	c := newClientSecretCache(time.Minute, func() time.Time { return now })
	require.NotNil(t, c)
	id := uuid.New()
	c.remember(id, "hash-1", "secret")

	// Act & Assert
	assert.True(t, c.verified(id, "hash-1", "secret"))
	assert.False(t, c.verified(id, "hash-1", "secreT"), "other secret")
	assert.False(t, c.verified(id, "hash-2", "secret"), "stored hash changed")
	assert.False(t, c.verified(uuid.New(), "hash-1", "secret"), "other client")
}

func TestClientSecretCache_Verified_ExpiresAfterTTL(t *testing.T) {
	// Arrange
	now := time.Now()
	c := newClientSecretCache(time.Minute, func() time.Time { return now })
	id := uuid.New()
	c.remember(id, "hash", "secret")

	// Act
	now = now.Add(time.Minute)

	// Assert
	assert.False(t, c.verified(id, "hash", "secret"))
}

func TestClientSecretCache_Remember_BoundedSize(t *testing.T) {
	// Arrange
	c := newClientSecretCache(time.Minute, time.Now)

	// Act
	for i := 0; i < maxCachedClientSecrets+1; i++ {
		c.remember(uuid.New(), "hash", "secret")
	}

	// Assert
	assert.LessOrEqual(t, len(c.entries), maxCachedClientSecrets)
}

func TestClientSecretCache_StoresNoPlaintext(t *testing.T) {
	// Arrange
	c := newClientSecretCache(time.Minute, time.Now)
	id := uuid.New()

	// Act
	c.remember(id, "hash", "plain-secret")

	// Assert
	entry := c.entries[clientSecretCacheKey{id, "hash"}]
	assert.Len(t, entry.mac, 32)
	assert.NotContains(t, string(entry.mac), "plain-secret")
}

func TestClientSecretCache_Nil_NeverVerifies(t *testing.T) {
	// Arrange
	var c *clientSecretCache

	// Act
	c.remember(uuid.New(), "hash", "secret")

	// Assert
	assert.False(t, c.verified(uuid.New(), "hash", "secret"))
}
