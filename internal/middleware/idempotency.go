package middleware

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"shieldgate/internal/models"
)

const (
	// IdempotencyKeyHeader names the client-chosen key for a POST
	IdempotencyKeyHeader = "Idempotency-Key"
	// IdempotentReplayedHeader marks a response replayed from a stored one
	IdempotentReplayedHeader = "Idempotent-Replayed"

	maxIdempotencyKeyLength = 255
	// maxIdempotentBodyBytes bounds the request body read for hashing and
	// the response body stored for replay
	maxIdempotentBodyBytes = 1 << 20
	// idempotencyStaleAfter is how long a request may run before its key is
	// considered abandoned (well above the server's 15s write timeout)
	idempotencyStaleAfter = time.Minute
)

// redactedResponseFields are removed from a response before it is stored:
// they are shown exactly once, and storing them would undo their hashing
var redactedResponseFields = map[string]bool{"client_secret": true}

// IdempotencyStore persists Idempotency-Key records.
// repo.IdempotencyRepository satisfies it.
type IdempotencyStore interface {
	Begin(ctx context.Context, record *models.IdempotencyKey, staleBefore time.Time) (bool, *models.IdempotencyKey, error)
	Complete(ctx context.Context, id uuid.UUID, statusCode int, contentType string, body []byte) error
	Delete(ctx context.Context, id uuid.UUID) error
}

// Idempotency makes POST requests that carry an Idempotency-Key header safe
// to retry. Keys are scoped to the tenant and the authenticated principal
// and kept for ttl.
//
//   - First request: runs, and its response is stored (5xx responses are
//     not, so the client can retry).
//   - Same key, same request: the stored response is replayed with
//     Idempotent-Replayed: true. Fields in redactedResponseFields (such as a
//     newly issued client_secret) are not stored, so they are absent.
//   - Same key, different request: 422.
//   - Same key while the first request is still running: 409.
//
// It must run after RequireAuth.
func Idempotency(store IdempotencyStore, ttl time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		key := c.GetHeader(IdempotencyKeyHeader)
		if c.Request.Method != http.MethodPost || key == "" {
			c.Next()
			return
		}
		if !validIdempotencyKey(key) {
			RespondWithError(c, http.StatusBadRequest, models.ErrorCodeInvalidRequest,
				"Idempotency-Key must be 1-255 visible ASCII characters", nil)
			c.Abort()
			return
		}

		tenantID, err := GetTenantID(c)
		if err != nil {
			RespondWithError(c, http.StatusUnauthorized, models.ErrorCodeUnauthorized, "Invalid tenant context", nil)
			c.Abort()
			return
		}

		body, err := io.ReadAll(io.LimitReader(c.Request.Body, maxIdempotentBodyBytes+1))
		if err != nil {
			RespondWithError(c, http.StatusBadRequest, models.ErrorCodeInvalidRequest, "Failed to read request body", nil)
			c.Abort()
			return
		}
		if len(body) > maxIdempotentBodyBytes {
			RespondWithError(c, http.StatusRequestEntityTooLarge, models.ErrorCodeInvalidRequest, "Request body too large", nil)
			c.Abort()
			return
		}
		c.Request.Body = io.NopCloser(bytes.NewReader(body))

		record := &models.IdempotencyKey{
			ID:          uuid.New(),
			TenantID:    tenantID,
			Principal:   idempotencyPrincipal(c),
			Key:         key,
			Method:      c.Request.Method,
			Path:        c.Request.URL.RequestURI(),
			RequestHash: requestFingerprint(c.Request.Method, c.Request.URL.RequestURI(), body),
			ExpiresAt:   time.Now().Add(ttl),
		}
		ctx := c.Request.Context()
		stored, existing, err := store.Begin(ctx, record, time.Now().Add(-idempotencyStaleAfter))
		switch {
		case errors.Is(err, models.ErrResourceConflict):
			respondInProgress(c)
			return
		case err != nil:
			logrus.WithError(err).WithField("request_id", GetRequestID(c)).Error("idempotency key lookup failed")
			RespondWithError(c, http.StatusInternalServerError, models.ErrorCodeInternalError, "Internal server error", nil)
			c.Abort()
			return
		case !stored:
			replayOrReject(c, existing, record.RequestHash)
			return
		}

		capture := &capturingWriter{ResponseWriter: c.Writer}
		c.Writer = capture
		completed := false
		defer func() {
			// The handler panicked or the response could not be stored:
			// release the key so the client can retry
			if !completed {
				if err := store.Delete(context.WithoutCancel(ctx), record.ID); err != nil {
					logrus.WithError(err).Error("failed to release idempotency key")
				}
			}
		}()

		c.Next()

		status := capture.Status()
		if status >= http.StatusInternalServerError || capture.body.Len() > maxIdempotentBodyBytes {
			return
		}
		if err := store.Complete(context.WithoutCancel(ctx), record.ID, status,
			capture.Header().Get("Content-Type"), redactResponse(capture.body.Bytes())); err != nil {
			logrus.WithError(err).WithField("request_id", GetRequestID(c)).Error("failed to store idempotent response")
			return
		}
		completed = true
	}
}

func replayOrReject(c *gin.Context, existing *models.IdempotencyKey, requestHash string) {
	switch {
	case existing.RequestHash != requestHash:
		RespondWithError(c, http.StatusUnprocessableEntity, models.ErrorCodeInvalidRequest,
			"Idempotency-Key was already used with a different request", nil)
		c.Abort()
	case existing.InProgress():
		respondInProgress(c)
	default:
		c.Header(IdempotentReplayedHeader, "true")
		contentType := existing.ResponseContentType
		if contentType == "" {
			contentType = "application/octet-stream"
		}
		c.Data(existing.StatusCode, contentType, existing.ResponseBody)
		c.Abort()
	}
}

func respondInProgress(c *gin.Context) {
	c.Header("Retry-After", strconv.Itoa(1))
	RespondWithError(c, http.StatusConflict, models.ErrorCodeResourceConflict,
		"A request with this Idempotency-Key is still being processed", nil)
	c.Abort()
}

// idempotencyPrincipal identifies who sent the request, so two callers in
// one tenant cannot collide on (or read each other's responses through) a key
func idempotencyPrincipal(c *gin.Context) string {
	if userID, err := GetUserID(c); err == nil && userID != uuid.Nil {
		return "user:" + userID.String()
	}
	if clientID, err := GetClientID(c); err == nil && clientID != uuid.Nil {
		return "client:" + clientID.String()
	}
	return "anonymous"
}

func requestFingerprint(method, uri string, body []byte) string {
	h := sha256.New()
	h.Write([]byte(method))
	h.Write([]byte{0})
	h.Write([]byte(uri))
	h.Write([]byte{0})
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}

func validIdempotencyKey(key string) bool {
	if len(key) == 0 || len(key) > maxIdempotencyKeyLength {
		return false
	}
	for i := 0; i < len(key); i++ {
		if key[i] < 0x21 || key[i] > 0x7e {
			return false
		}
	}
	return true
}

// redactResponse removes redactedResponseFields from a JSON body at any
// depth; other bodies are returned unchanged
func redactResponse(body []byte) []byte {
	var doc interface{}
	if err := json.Unmarshal(body, &doc); err != nil {
		return body
	}
	if !redact(doc) {
		return body
	}
	out, err := json.Marshal(doc)
	if err != nil {
		return body
	}
	return out
}

// redact deletes redacted fields in place and reports whether any were found
func redact(v interface{}) bool {
	found := false
	switch node := v.(type) {
	case map[string]interface{}:
		for k, child := range node {
			if redactedResponseFields[k] {
				delete(node, k)
				found = true
				continue
			}
			found = redact(child) || found
		}
	case []interface{}:
		for _, child := range node {
			found = redact(child) || found
		}
	}
	return found
}

// capturingWriter copies the response body as it is written
type capturingWriter struct {
	gin.ResponseWriter
	body bytes.Buffer
}

func (w *capturingWriter) Write(b []byte) (int, error) {
	w.body.Write(b)
	return w.ResponseWriter.Write(b)
}

func (w *capturingWriter) WriteString(s string) (int, error) {
	w.body.WriteString(s)
	return w.ResponseWriter.WriteString(s)
}
