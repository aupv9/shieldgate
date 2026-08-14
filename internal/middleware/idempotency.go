package middleware

// idempotency.go implements Idempotency-Key support for mutating management
// API calls: the first response for a key is stored in Redis and replayed for
// retries, so network-level retries cannot create duplicate resources.

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"

	"shieldgate/internal/database"
)

const (
	idempotencyHeader   = "Idempotency-Key"
	idempotencyTTL      = 24 * time.Hour
	idempotencyMaxKey   = 255
	idempotencyReplayed = "Idempotency-Replayed"
)

type storedResponse struct {
	Status      int    `json:"status"`
	ContentType string `json:"content_type"`
	Body        string `json:"body"`
}

// bodyCapturingWriter tees the response body so it can be stored for replay
type bodyCapturingWriter struct {
	gin.ResponseWriter
	body []byte
}

func (w *bodyCapturingWriter) Write(data []byte) (int, error) {
	w.body = append(w.body, data...)
	return w.ResponseWriter.Write(data)
}

// Idempotency replays stored responses for repeated POST/PUT/PATCH requests
// carrying the same Idempotency-Key. Requires Redis; without it the
// middleware is a no-op (requests pass through uncached).
func Idempotency() gin.HandlerFunc {
	return func(c *gin.Context) {
		method := c.Request.Method
		if method != http.MethodPost && method != http.MethodPut && method != http.MethodPatch {
			c.Next()
			return
		}

		key := c.GetHeader(idempotencyHeader)
		if key == "" || len(key) > idempotencyMaxKey {
			c.Next()
			return
		}

		redisValue, exists := c.Get("redis")
		if !exists {
			c.Next()
			return
		}
		redis, ok := redisValue.(*database.RedisClient)
		if !ok || redis == nil {
			c.Next()
			return
		}

		tenantScope := "global"
		if tenantID, err := GetTenantID(c); err == nil {
			tenantScope = tenantID.String()
		}
		storageKey := "idempotency:" + tenantScope + ":" + method + ":" + c.Request.URL.Path + ":" + key

		ctx, cancel := context.WithTimeout(c.Request.Context(), 3*time.Second)
		defer cancel()

		// Replay a stored response for this key if one exists
		if stored, err := redis.Get(ctx, storageKey); err == nil && stored != "" {
			var response storedResponse
			if err := json.Unmarshal([]byte(stored), &response); err == nil {
				c.Header(idempotencyReplayed, "true")
				c.Data(response.Status, response.ContentType, []byte(response.Body))
				c.Abort()
				return
			}
		}

		// First time: run the handler and store the outcome
		writer := &bodyCapturingWriter{ResponseWriter: c.Writer}
		c.Writer = writer
		c.Next()

		// Only cache definitive outcomes — 5xx should be retryable
		status := writer.Status()
		if status >= http.StatusInternalServerError {
			return
		}

		payload, err := json.Marshal(storedResponse{
			Status:      status,
			ContentType: writer.Header().Get("Content-Type"),
			Body:        string(writer.body),
		})
		if err != nil {
			return
		}
		storeCtx, storeCancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer storeCancel()
		if err := redis.Set(storeCtx, storageKey, string(payload), idempotencyTTL); err != nil {
			logrus.WithError(err).Warn("failed to store idempotent response")
		}
	}
}
