package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"

	"shieldgate/config"
)

func TestRateLimit_WithoutRedis_PassesAndWarnsOnce(t *testing.T) {
	// Arrange
	gin.SetMode(gin.TestMode)
	hook := logtest.NewGlobal()
	defer hook.Reset()
	router := gin.New()
	router.Use(RateLimit(&config.Config{RateLimitRequestsPerMinute: 1}))
	router.GET("/", func(c *gin.Context) { c.Status(http.StatusNoContent) })

	// Act
	codes := make([]int, 0, 3)
	for i := 0; i < 3; i++ {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
		codes = append(codes, w.Code)
	}

	// Assert
	assert.Equal(t, []int{http.StatusNoContent, http.StatusNoContent, http.StatusNoContent}, codes)
	warnings := 0
	for _, e := range hook.AllEntries() {
		if e.Level == logrus.WarnLevel {
			warnings++
		}
	}
	assert.Equal(t, 1, warnings, "the missing Redis is reported once, not per request")
}
