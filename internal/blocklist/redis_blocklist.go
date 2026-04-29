package blocklist

import (
	"context"
	"time"

	"shieldgate/internal/database"
)

const blocklistKeyPrefix = "blocklist:"

// RedisBlocklist uses Redis SET-with-TTL for distributed, multi-node token revocation.
// Fail-open: if Redis is unavailable, tokens are treated as not blocked.
type RedisBlocklist struct {
	redis *database.RedisClient
}

// NewRedisBlocklist creates a Redis-backed blocklist.
func NewRedisBlocklist(redis *database.RedisClient) *RedisBlocklist {
	return &RedisBlocklist{redis: redis}
}

func (r *RedisBlocklist) Block(ctx context.Context, token string, ttl time.Duration) error {
	return r.redis.Set(ctx, blocklistKeyPrefix+token, "1", ttl)
}

func (r *RedisBlocklist) IsBlocked(ctx context.Context, token string) (bool, error) {
	val, err := r.redis.Get(ctx, blocklistKeyPrefix+token)
	if err != nil {
		return false, nil // fail-open: Redis unavailable → not blocked
	}
	return val != "", nil
}
