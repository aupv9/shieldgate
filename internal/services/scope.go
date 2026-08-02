package services

import (
	"strings"

	"shieldgate/internal/models"
)

// ParseScope splits a space-delimited scope string into its individual scopes,
// dropping empty entries (RFC 6749 §3.3).
func ParseScope(scope string) []string {
	return strings.Fields(scope)
}

// ScopeContains reports whether the space-delimited scope string contains the
// given scope value.
func ScopeContains(scope, target string) bool {
	for _, s := range ParseScope(scope) {
		if s == target {
			return true
		}
	}
	return false
}

// ScopeIsSubset reports whether every scope in requested is present in allowed.
// An empty requested scope is trivially a subset.
func ScopeIsSubset(requested, allowed string) bool {
	allowedSet := make(map[string]struct{})
	for _, s := range ParseScope(allowed) {
		allowedSet[s] = struct{}{}
	}
	for _, s := range ParseScope(requested) {
		if _, ok := allowedSet[s]; !ok {
			return false
		}
	}
	return true
}

// ValidateScopeForClient checks the requested scope against the client's
// registered scopes and returns the scope to grant. An empty request defaults
// to the client's full registered scope set (RFC 6749 §3.3). Any requested
// scope outside the registered set yields models.ErrInvalidScope.
func ValidateScopeForClient(client *models.Client, requested string) (string, error) {
	registered := strings.Join(client.Scopes, " ")
	if strings.TrimSpace(requested) == "" {
		return registered, nil
	}
	if !ScopeIsSubset(requested, registered) {
		return "", models.ErrInvalidScope
	}
	return strings.Join(ParseScope(requested), " "), nil
}
