package middleware

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	DefaultMaxFailures = 5
	DefaultLockWindow  = 15 * time.Minute
)

// BruteForceConfig controls the brute-force protection parameters.
type BruteForceConfig struct {
	// MaxFailures is the number of failed attempts before blocking. Default: 5.
	MaxFailures int
	// Window is the sliding window for counting failures. Default: 15 min.
	Window time.Duration
}

type attempt struct {
	count     int
	windowEnd time.Time
}

// BruteForceProtection returns a Gin middleware that blocks repeated failed
// login attempts from the same IP+email combination.
//
// It uses an in-memory store, so it resets on restart. For multi-replica
// deployments, replace the store with a Redis-backed implementation.
func BruteForceProtection(cfg BruteForceConfig) gin.HandlerFunc {
	if cfg.MaxFailures <= 0 {
		cfg.MaxFailures = DefaultMaxFailures
	}
	if cfg.Window <= 0 {
		cfg.Window = DefaultLockWindow
	}

	var mu sync.Mutex
	store := make(map[string]*attempt)

	return func(c *gin.Context) {
		ip := getClientIP(c)
		email := c.PostForm("email")
		if email == "" {
			// Try JSON body via already-bound context key (set by login handler before calling Next)
			if v, ok := c.Get("login_email"); ok {
				email, _ = v.(string)
			}
		}

		key := bruteForceKey(ip, email)

		mu.Lock()
		acc, exists := store[key]
		if !exists || time.Now().After(acc.windowEnd) {
			// First attempt or window expired — reset
			acc = &attempt{count: 0, windowEnd: time.Now().Add(cfg.Window)}
			store[key] = acc
		}
		currentCount := acc.count
		mu.Unlock()

		if currentCount >= cfg.MaxFailures {
			c.Header("Retry-After", fmt.Sprintf("%.0f", time.Until(acc.windowEnd).Seconds()))
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":             "too_many_attempts",
				"error_description": "Account temporarily locked due to too many failed login attempts. Please try again later.",
			})
			c.Abort()
			return
		}

		c.Next()

		// Record failure if status is 401 or 403
		if status := c.Writer.Status(); status == http.StatusUnauthorized || status == http.StatusForbidden {
			mu.Lock()
			acc.count++
			mu.Unlock()
		}
	}
}

// RecordBruteForceSuccess resets the failure counter for an IP+email key.
// Call this from the login handler after a successful authentication.
func RecordBruteForceSuccess(store *sync.Map, ip, email string) {
	store.Delete(bruteForceKey(ip, email))
}

func bruteForceKey(ip, email string) string {
	return fmt.Sprintf("%s|%s", ip, email)
}
