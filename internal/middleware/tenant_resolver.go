package middleware

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"shieldgate/internal/models"
)

// maxCachedDomains bounds the resolver cache; Host is client-controlled, so
// without a bound arbitrary hosts could grow it without limit
const maxCachedDomains = 10000

// TenantDomainLookup finds a tenant by its registered domain.
// repo.TenantRepository satisfies it.
type TenantDomainLookup interface {
	GetByDomain(ctx context.Context, domain string) (*models.Tenant, error)
}

// DomainTenantResolver maps a request's Host to the tenant registered for
// that domain, so browser flows (which cannot send X-Tenant-ID) reach the
// right tenant. Lookups, including misses, are cached for ttl.
type DomainTenantResolver struct {
	lookup TenantDomainLookup
	ttl    time.Duration

	mu      sync.Mutex
	entries map[string]domainEntry
}

type domainEntry struct {
	tenantID uuid.UUID
	found    bool
	expires  time.Time
}

// NewDomainTenantResolver creates a resolver backed by lookup
func NewDomainTenantResolver(lookup TenantDomainLookup, ttl time.Duration) *DomainTenantResolver {
	return &DomainTenantResolver{lookup: lookup, ttl: ttl, entries: make(map[string]domainEntry)}
}

// Resolve returns the active tenant registered for host, if any
func (r *DomainTenantResolver) Resolve(ctx context.Context, host string) (uuid.UUID, bool) {
	domain := normalizeHost(host)
	if domain == "" {
		return uuid.Nil, false
	}

	r.mu.Lock()
	entry, ok := r.entries[domain]
	r.mu.Unlock()
	if ok && time.Now().Before(entry.expires) {
		return entry.tenantID, entry.found
	}

	tenant, err := r.lookup.GetByDomain(ctx, domain)
	switch {
	case err == nil:
		entry = domainEntry{tenantID: tenant.ID, found: tenant.IsActive}
	case errors.Is(err, models.ErrTenantNotFound):
		entry = domainEntry{}
	default:
		// Transient failure: do not cache, so the next request retries
		logrus.WithError(err).WithField("domain", domain).Error("tenant domain lookup failed")
		return uuid.Nil, false
	}
	entry.expires = time.Now().Add(r.ttl)

	r.mu.Lock()
	if len(r.entries) >= maxCachedDomains {
		r.entries = make(map[string]domainEntry)
	}
	r.entries[domain] = entry
	r.mu.Unlock()

	return entry.tenantID, entry.found
}

// normalizeHost lowercases host and strips any port and trailing dot
func normalizeHost(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
}
