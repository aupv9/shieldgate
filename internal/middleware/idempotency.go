package middleware

import (
	"bytes"
	"net/http"

	"shieldgate/internal/idempotency"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

// Idempotency returns a Gin middleware that enforces idempotency for POST
// requests carrying an "Idempotency-Key" header.
//
// On the first request for a given key the handler executes normally and its
// response (status code + body) is persisted in store.  Any repeat request
// carrying the same key receives the cached response without re-executing the
// handler.
//
// If a concurrent duplicate arrives while the first request is still running,
// the middleware returns HTTP 409 Conflict with error code IDEMPOTENCY_IN_PROGRESS.
//
// Requests without an Idempotency-Key header pass through unchanged.
func Idempotency(store idempotency.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Only enforce on mutating methods.
		if c.Request.Method != http.MethodPost {
			c.Next()
			return
		}

		key := c.GetHeader("Idempotency-Key")
		if key == "" {
			c.Next()
			return
		}

		requestID := GetRequestID(c)
		log := logrus.WithFields(logrus.Fields{
			"request_id":      requestID,
			"idempotency_key": key,
			"path":            c.Request.URL.Path,
		})

		ctx := c.Request.Context()

		// Check if a response is already stored (or in progress).
		existing, err := store.GetResponse(ctx, key)
		if err != nil {
			if err == idempotency.ErrProcessing {
				log.Warn("idempotency: duplicate request received while in progress")
				c.JSON(http.StatusConflict, gin.H{
					"error":             "IDEMPOTENCY_IN_PROGRESS",
					"error_description": "A request with this Idempotency-Key is currently being processed. Please wait and retry.",
					"request_id":        requestID,
				})
				c.Abort()
				return
			}
			// Store error — log and fall through so the request still executes.
			log.WithError(err).Error("idempotency: failed to check store; proceeding without idempotency")
			c.Next()
			return
		}

		if existing != nil {
			// Replay the cached response.
			log.Info("idempotency: replaying cached response")
			c.Header("Idempotency-Replayed", "true")
			c.Data(existing.StatusCode, "application/json; charset=utf-8", existing.Body)
			c.Abort()
			return
		}

		// Mark key as in-flight.
		claimed, err := store.SetProcessing(ctx, key)
		if err != nil {
			log.WithError(err).Error("idempotency: failed to set processing; proceeding without idempotency")
			c.Next()
			return
		}
		if !claimed {
			// Another goroutine claimed the key between GetResponse and SetProcessing.
			log.Warn("idempotency: concurrent duplicate detected at SetProcessing")
			c.JSON(http.StatusConflict, gin.H{
				"error":             "IDEMPOTENCY_IN_PROGRESS",
				"error_description": "A request with this Idempotency-Key is currently being processed.",
				"request_id":        requestID,
			})
			c.Abort()
			return
		}

		// Intercept the response writer so we can capture status + body.
		rw := &responseWriter{ResponseWriter: c.Writer, body: &bytes.Buffer{}}
		c.Writer = rw

		c.Next()

		// Persist the response (even error responses) so retries are idempotent.
		rec := &idempotency.Record{
			StatusCode: rw.status,
			Body:       rw.body.Bytes(),
		}
		if saveErr := store.SaveResponse(ctx, key, rec); saveErr != nil {
			log.WithError(saveErr).Error("idempotency: failed to save response")
		}
	}
}

// responseWriter wraps gin.ResponseWriter to capture the written status code
// and body for idempotency storage.
type responseWriter struct {
	gin.ResponseWriter
	status int
	body   *bytes.Buffer
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	rw.body.Write(b)
	return rw.ResponseWriter.Write(b)
}

func (rw *responseWriter) WriteString(s string) (int, error) {
	rw.body.WriteString(s)
	return rw.ResponseWriter.WriteString(s)
}

func (rw *responseWriter) Status() int {
	if rw.status == 0 {
		return http.StatusOK
	}
	return rw.status
}
