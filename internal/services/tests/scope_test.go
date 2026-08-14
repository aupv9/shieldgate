package tests

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"shieldgate/internal/models"
	"shieldgate/internal/services"
)

func TestParseScope(t *testing.T) {
	assert.Equal(t, []string{"read", "write"}, services.ParseScope("read write"))
	assert.Equal(t, []string{"read"}, services.ParseScope("  read  "))
	assert.Empty(t, services.ParseScope(""))
	assert.Empty(t, services.ParseScope("   "))
}

func TestScopeContains(t *testing.T) {
	assert.True(t, services.ScopeContains("openid profile email", "openid"))
	assert.True(t, services.ScopeContains("openid profile email", "email"))
	assert.False(t, services.ScopeContains("openid profile email", "admin"))
	// Substring of a scope value must NOT match (the old buggy contains() did)
	assert.False(t, services.ScopeContains("openid-connect", "openid"))
	assert.False(t, services.ScopeContains("readwrite", "read"))
	assert.False(t, services.ScopeContains("", "read"))
}

func TestScopeIsSubset(t *testing.T) {
	assert.True(t, services.ScopeIsSubset("read", "read write"))
	assert.True(t, services.ScopeIsSubset("", "read write"))
	assert.True(t, services.ScopeIsSubset("read write", "read write"))
	assert.False(t, services.ScopeIsSubset("read write admin", "read write"))
	assert.False(t, services.ScopeIsSubset("admin", ""))
}

func TestValidateScopeForClient(t *testing.T) {
	client := &models.Client{Scopes: models.StringArray{"read", "write", "openid"}}

	// Explicit subset is granted as requested
	granted, err := services.ValidateScopeForClient(client, "read openid")
	assert.NoError(t, err)
	assert.Equal(t, "read openid", granted)

	// Empty request defaults to the registered scopes (RFC 6749 §3.3)
	granted, err = services.ValidateScopeForClient(client, "")
	assert.NoError(t, err)
	assert.Equal(t, "read write openid", granted)

	// Out-of-registration scope is rejected
	_, err = services.ValidateScopeForClient(client, "read admin")
	assert.ErrorIs(t, err, models.ErrInvalidScope)
}
