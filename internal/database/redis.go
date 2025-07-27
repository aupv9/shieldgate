package database

import (
	"context"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"
)

// RedisClient wraps the Redis client with additional functionality
type RedisClient struct {
	client *redis.Client
}

// InitializeRedis initializes the Redis connection
func InitializeRedis(redisURL string) (*RedisClient, error) {
	logrus.Info("Connecting to Redis...")

	opt, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Redis URL: %w", err)
	}

	client := redis.NewClient(opt)

	// Test the connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to ping Redis: %w", err)
	}

	logrus.Info("Redis connection established")
	return &RedisClient{client: client}, nil
}

// Close closes the Redis connection
func (r *RedisClient) Close() error {
	if r.client != nil {
		return r.client.Close()
	}
	return nil
}

// Set sets a key-value pair with expiration
func (r *RedisClient) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	return r.client.Set(ctx, key, value, expiration).Err()
}

// Get gets a value by key
func (r *RedisClient) Get(ctx context.Context, key string) (string, error) {
	result := r.client.Get(ctx, key)
	if result.Err() == redis.Nil {
		return "", nil // Key doesn't exist
	}
	return result.Result()
}

// Del deletes a key
func (r *RedisClient) Del(ctx context.Context, keys ...string) error {
	return r.client.Del(ctx, keys...).Err()
}

// Exists checks if a key exists
func (r *RedisClient) Exists(ctx context.Context, keys ...string) (int64, error) {
	return r.client.Exists(ctx, keys...).Result()
}

// SetNX sets a key-value pair only if the key doesn't exist
func (r *RedisClient) SetNX(ctx context.Context, key string, value interface{}, expiration time.Duration) (bool, error) {
	return r.client.SetNX(ctx, key, value, expiration).Result()
}

// Incr increments a key's value
func (r *RedisClient) Incr(ctx context.Context, key string) (int64, error) {
	return r.client.Incr(ctx, key).Result()
}

// Expire sets expiration for a key
func (r *RedisClient) Expire(ctx context.Context, key string, expiration time.Duration) error {
	return r.client.Expire(ctx, key, expiration).Err()
}

// TTL gets the time to live for a key
func (r *RedisClient) TTL(ctx context.Context, key string) (time.Duration, error) {
	return r.client.TTL(ctx, key).Result()
}

// HSet sets a hash field
func (r *RedisClient) HSet(ctx context.Context, key string, values ...interface{}) error {
	return r.client.HSet(ctx, key, values...).Err()
}

// HGet gets a hash field value
func (r *RedisClient) HGet(ctx context.Context, key, field string) (string, error) {
	result := r.client.HGet(ctx, key, field)
	if result.Err() == redis.Nil {
		return "", nil // Field doesn't exist
	}
	return result.Result()
}

// HGetAll gets all hash fields and values
func (r *RedisClient) HGetAll(ctx context.Context, key string) (map[string]string, error) {
	return r.client.HGetAll(ctx, key).Result()
}

// HDel deletes hash fields
func (r *RedisClient) HDel(ctx context.Context, key string, fields ...string) error {
	return r.client.HDel(ctx, key, fields...).Err()
}

// SAdd adds members to a set
func (r *RedisClient) SAdd(ctx context.Context, key string, members ...interface{}) error {
	return r.client.SAdd(ctx, key, members...).Err()
}

// SRem removes members from a set
func (r *RedisClient) SRem(ctx context.Context, key string, members ...interface{}) error {
	return r.client.SRem(ctx, key, members...).Err()
}

// SIsMember checks if a member exists in a set
func (r *RedisClient) SIsMember(ctx context.Context, key string, member interface{}) (bool, error) {
	return r.client.SIsMember(ctx, key, member).Result()
}

// SMembers gets all members of a set
func (r *RedisClient) SMembers(ctx context.Context, key string) ([]string, error) {
	return r.client.SMembers(ctx, key).Result()
}

// Pipeline creates a new pipeline
func (r *RedisClient) Pipeline() redis.Pipeliner {
	return r.client.Pipeline()
}

// TxPipeline creates a new transaction pipeline
func (r *RedisClient) TxPipeline() redis.Pipeliner {
	return r.client.TxPipeline()
}

// FlushDB flushes the current database (use with caution)
func (r *RedisClient) FlushDB(ctx context.Context) error {
	return r.client.FlushDB(ctx).Err()
}

// Keys returns all keys matching a pattern
func (r *RedisClient) Keys(ctx context.Context, pattern string) ([]string, error) {
	return r.client.Keys(ctx, pattern).Result()
}

// Scan scans keys matching a pattern
func (r *RedisClient) Scan(ctx context.Context, cursor uint64, match string, count int64) ([]string, uint64, error) {
	return r.client.Scan(ctx, cursor, match, count).Result()
}

// Helper methods for common OAuth operations

// SetToken stores a token with expiration
func (r *RedisClient) SetToken(ctx context.Context, tokenType, token string, data interface{}, expiration time.Duration) error {
	key := fmt.Sprintf("token:%s:%s", tokenType, token)
	return r.Set(ctx, key, data, expiration)
}

// GetToken retrieves token data
func (r *RedisClient) GetToken(ctx context.Context, tokenType, token string) (string, error) {
	key := fmt.Sprintf("token:%s:%s", tokenType, token)
	return r.Get(ctx, key)
}

// DeleteToken removes a token
func (r *RedisClient) DeleteToken(ctx context.Context, tokenType, token string) error {
	key := fmt.Sprintf("token:%s:%s", tokenType, token)
	return r.Del(ctx, key)
}

// SetUserSession stores user session data
func (r *RedisClient) SetUserSession(ctx context.Context, sessionID string, userID string, expiration time.Duration) error {
	key := fmt.Sprintf("session:%s", sessionID)
	return r.Set(ctx, key, userID, expiration)
}

// GetUserSession retrieves user session data
func (r *RedisClient) GetUserSession(ctx context.Context, sessionID string) (string, error) {
	key := fmt.Sprintf("session:%s", sessionID)
	return r.Get(ctx, key)
}

// DeleteUserSession removes user session
func (r *RedisClient) DeleteUserSession(ctx context.Context, sessionID string) error {
	key := fmt.Sprintf("session:%s", sessionID)
	return r.Del(ctx, key)
}

// SetRateLimit sets rate limiting data
func (r *RedisClient) SetRateLimit(ctx context.Context, identifier string, limit int64, window time.Duration) error {
	key := fmt.Sprintf("rate_limit:%s", identifier)
	pipe := r.Pipeline()
	pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, window)
	_, err := pipe.Exec(ctx)
	return err
}

// GetRateLimit gets current rate limit count
func (r *RedisClient) GetRateLimit(ctx context.Context, identifier string) (int64, error) {
	key := fmt.Sprintf("rate_limit:%s", identifier)
	result := r.client.Get(ctx, key)
	if result.Err() == redis.Nil {
		return 0, nil
	}
	return result.Int64()
}