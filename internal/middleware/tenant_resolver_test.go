package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"shieldgate/internal/jwtkeys"
	"shieldgate/internal/models"
)

type stubDomains struct {
	tenants map[string]*models.Tenant
	err     error
	calls   int
}

func (s *stubDomains) GetByDomain(ctx context.Context, domain string) (*models.Tenant, error) {
	s.calls++
	if s.err != nil {
		return nil, s.err
	}
	if t, ok := s.tenants[domain]; ok {
		return t, nil
	}
	return nil, models.ErrTenantNotFound
}

func TestDomainTenantResolver_NormalizesHostAndCaches(t *testing.T) {
	// Arrange
	acme := &models.Tenant{ID: uuid.New(), Domain: "login.acme.com", IsActive: true}
	lookup := &stubDomains{tenants: map[string]*models.Tenant{"login.acme.com": acme}}
	r := NewDomainTenantResolver(lookup, time.Minute)

	// Act
	id1, ok1 := r.Resolve(context.Background(), "LOGIN.Acme.com:8443")
	id2, ok2 := r.Resolve(context.Background(), "login.acme.com.")

	// Assert
	assert.True(t, ok1)
	assert.True(t, ok2)
	assert.Equal(t, acme.ID, id1)
	assert.Equal(t, acme.ID, id2)
	assert.Equal(t, 1, lookup.calls, "second lookup is served from cache")
}

func TestDomainTenantResolver_UnknownDomain_CachedMiss(t *testing.T) {
	// Arrange
	lookup := &stubDomains{tenants: map[string]*models.Tenant{}}
	r := NewDomainTenantResolver(lookup, time.Minute)

	// Act
	_, ok1 := r.Resolve(context.Background(), "unknown.example")
	_, ok2 := r.Resolve(context.Background(), "unknown.example")

	// Assert
	assert.False(t, ok1)
	assert.False(t, ok2)
	assert.Equal(t, 1, lookup.calls)
}

func TestDomainTenantResolver_InactiveTenant_NotResolved(t *testing.T) {
	// Arrange
	lookup := &stubDomains{tenants: map[string]*models.Tenant{
		"old.example": {ID: uuid.New(), Domain: "old.example", IsActive: false},
	}}

	// Act
	_, ok := NewDomainTenantResolver(lookup, time.Minute).Resolve(context.Background(), "old.example")

	// Assert
	assert.False(t, ok)
}

func TestDomainTenantResolver_LookupError_NotCached(t *testing.T) {
	// Arrange
	lookup := &stubDomains{err: errors.New("db down")}
	r := NewDomainTenantResolver(lookup, time.Minute)

	// Act
	r.Resolve(context.Background(), "login.acme.com")
	r.Resolve(context.Background(), "login.acme.com")

	// Assert
	assert.Equal(t, 2, lookup.calls, "transient failures are retried")
}

func TestTenantContext_BrowserRequestOnTenantDomain_SetsTenant(t *testing.T) {
	// Arrange
	acme := &models.Tenant{ID: uuid.New(), Domain: "login.acme.com", IsActive: true}
	resolver := NewDomainTenantResolver(&stubDomains{tenants: map[string]*models.Tenant{"login.acme.com": acme}}, time.Minute)
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(TenantContext(jwtkeys.NewHMAC(testConfig().JWTSecret), resolver))
	var got uuid.UUID
	r.GET("/oauth/authorize", func(c *gin.Context) {
		got, _ = GetTenantID(c)
		c.Status(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize", nil)
	req.Host = "login.acme.com"

	// Act
	r.ServeHTTP(httptest.NewRecorder(), req)

	// Assert
	assert.Equal(t, acme.ID, got)
}

func TestTenantContext_ExplicitHeaderWinsOverDomain(t *testing.T) {
	// Arrange
	acme := &models.Tenant{ID: uuid.New(), Domain: "login.acme.com", IsActive: true}
	resolver := NewDomainTenantResolver(&stubDomains{tenants: map[string]*models.Tenant{"login.acme.com": acme}}, time.Minute)
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(TenantContext(jwtkeys.NewHMAC(testConfig().JWTSecret), resolver))
	var got uuid.UUID
	r.GET("/oauth/token", func(c *gin.Context) {
		got, _ = GetTenantID(c)
		c.Status(http.StatusOK)
	})
	explicit := uuid.New()
	req := httptest.NewRequest(http.MethodGet, "/oauth/token", nil)
	req.Host = "login.acme.com"
	req.Header.Set("X-Tenant-ID", explicit.String())

	// Act
	r.ServeHTTP(httptest.NewRecorder(), req)

	// Assert
	assert.Equal(t, explicit, got)
}
