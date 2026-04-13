package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func init() { gin.SetMode(gin.TestMode) }

func newBruteForceRouter(cfg BruteForceConfig) *gin.Engine {
	r := gin.New()
	r.POST("/login", BruteForceProtection(cfg), func(c *gin.Context) {
		// simulate failure
		c.JSON(http.StatusUnauthorized, gin.H{"error": "bad credentials"})
	})
	return r
}

func TestBruteForce_AllowsUnderLimit(t *testing.T) {
	r := newBruteForceRouter(BruteForceConfig{MaxFailures: 3, Window: time.Minute})
	for i := 0; i < 3; i++ {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/login",
			strings.NewReader("email=test@example.com&password=wrong"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.ServeHTTP(w, req)
		assert.Equal(t, http.StatusUnauthorized, w.Code, "attempt %d should pass through", i+1)
	}
}

func TestBruteForce_BlocksAfterLimit(t *testing.T) {
	r := newBruteForceRouter(BruteForceConfig{MaxFailures: 3, Window: time.Minute})
	// Exhaust the limit
	for i := 0; i < 3; i++ {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/login",
			strings.NewReader("email=block@example.com&password=wrong"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.ServeHTTP(w, req)
	}
	// Next request must be blocked
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/login",
		strings.NewReader("email=block@example.com&password=wrong"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusTooManyRequests, w.Code)
	assert.NotEmpty(t, w.Header().Get("Retry-After"))
}

func TestBruteForce_DifferentIPsAreIndependent(t *testing.T) {
	r := newBruteForceRouter(BruteForceConfig{MaxFailures: 2, Window: time.Minute})

	postAs := func(ip string) int {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/login",
			strings.NewReader("email=shared@example.com&password=wrong"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("X-Forwarded-For", ip)
		r.ServeHTTP(w, req)
		return w.Code
	}

	// Block IP-A
	postAs("1.2.3.4")
	postAs("1.2.3.4")
	assert.Equal(t, http.StatusTooManyRequests, postAs("1.2.3.4"))
	// IP-B must still be allowed
	assert.Equal(t, http.StatusUnauthorized, postAs("9.9.9.9"))
}

func TestBruteForceKey(t *testing.T) {
	assert.Equal(t, "1.2.3.4|user@test.com", bruteForceKey("1.2.3.4", "user@test.com"))
}
