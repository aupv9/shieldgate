package services

import (
	"net"
	"net/url"
	"strings"
	"unicode"

	"shieldgate/internal/models"
)

const (
	maxRegisteredURIs     = 10
	maxRegisteredURILen   = 2000
	maxClientNameLength   = 255
	defaultDynamicClient  = "Dynamically registered client"
	responseTypeCode      = "code"
	maxRegisteredScopes   = 50
	maxRegisteredScopeLen = 128
)

// dynamicGrantTypes are the grants a client may register for itself.
// Token exchange is left to administrators: it lets a client act for users.
var dynamicGrantTypes = map[string]bool{
	models.GrantTypeAuthorizationCode: true,
	models.GrantTypeRefreshToken:      true,
	models.GrantTypeClientCredentials: true,
	models.GrantTypeDeviceCode:        true,
}

// registeredMetadata is client metadata after validation and defaults
type registeredMetadata struct {
	name                   string
	redirectURIs           []string
	postLogoutRedirectURIs []string
	grantTypes             []string
	authMethod             string
	scopes                 []string
}

func (m *registeredMetadata) isPublic() bool {
	return m.authMethod == models.TokenEndpointAuthNone
}

func invalidMetadata(description string) error {
	return &models.RegistrationError{Code: models.RegistrationErrorInvalidClientMetadata, Description: description}
}

func invalidRedirect(description string) error {
	return &models.RegistrationError{Code: models.RegistrationErrorInvalidRedirectURI, Description: description}
}

// validateClientMetadata checks registration metadata (RFC 7591 §2) and
// applies defaults. Scope is checked against a ceiling by the caller.
func validateClientMetadata(meta *models.ClientMetadata) (*registeredMetadata, error) {
	out := &registeredMetadata{}

	out.grantTypes = dedupe(meta.GrantTypes)
	if len(out.grantTypes) == 0 {
		out.grantTypes = []string{models.GrantTypeAuthorizationCode}
	}
	has := map[string]bool{}
	for _, g := range out.grantTypes {
		if !dynamicGrantTypes[g] {
			return nil, invalidMetadata("grant_type " + g + " cannot be registered")
		}
		has[g] = true
	}
	if has[models.GrantTypeRefreshToken] && !has[models.GrantTypeAuthorizationCode] && !has[models.GrantTypeDeviceCode] {
		return nil, invalidMetadata("refresh_token requires the authorization_code or device_code grant")
	}

	// response_types must match the grants (RFC 7591 §2.1)
	responseTypes := dedupe(meta.ResponseTypes)
	switch {
	case len(responseTypes) == 0:
	case has[models.GrantTypeAuthorizationCode] && len(responseTypes) == 1 && responseTypes[0] == responseTypeCode:
	case !has[models.GrantTypeAuthorizationCode]:
		return nil, invalidMetadata("response_types require the authorization_code grant")
	default:
		return nil, invalidMetadata("only the code response type is supported")
	}

	out.authMethod = meta.TokenEndpointAuthMethod
	switch out.authMethod {
	case "":
		out.authMethod = models.TokenEndpointAuthClientSecretBasic
	case models.TokenEndpointAuthNone, models.TokenEndpointAuthClientSecretBasic, models.TokenEndpointAuthClientSecretPost:
	default:
		return nil, invalidMetadata("unsupported token_endpoint_auth_method")
	}
	if out.isPublic() && has[models.GrantTypeClientCredentials] {
		return nil, invalidMetadata("client_credentials requires an authenticated client")
	}

	var err error
	if out.redirectURIs, err = validateRegisteredURIs(meta.RedirectURIs, "redirect_uris"); err != nil {
		return nil, err
	}
	if has[models.GrantTypeAuthorizationCode] && len(out.redirectURIs) == 0 {
		return nil, invalidRedirect("redirect_uris is required for the authorization_code grant")
	}
	if out.postLogoutRedirectURIs, err = validateRegisteredURIs(meta.PostLogoutRedirectURIs, "post_logout_redirect_uris"); err != nil {
		return nil, err
	}

	out.name = strings.TrimSpace(meta.ClientName)
	if out.name == "" {
		out.name = defaultDynamicClient
	}
	if len(out.name) > maxClientNameLength || strings.IndexFunc(out.name, unicode.IsControl) >= 0 {
		return nil, invalidMetadata("client_name is too long or contains control characters")
	}

	out.scopes = ParseScope(meta.Scope)
	if len(out.scopes) > maxRegisteredScopes {
		return nil, invalidMetadata("too many scopes")
	}
	for _, s := range out.scopes {
		if !validScopeToken(s) {
			return nil, invalidMetadata("invalid scope " + s)
		}
	}
	return out, nil
}

// validateRegisteredURIs checks redirect-style URIs: absolute, no
// fragment, and https — except http on loopback and private-use schemes
// for native apps (RFC 8252 §7)
func validateRegisteredURIs(uris []string, field string) ([]string, error) {
	uris = dedupe(uris)
	if len(uris) > maxRegisteredURIs {
		return nil, invalidRedirect("too many " + field)
	}
	for _, raw := range uris {
		if len(raw) > maxRegisteredURILen || strings.Contains(raw, "#") {
			return nil, invalidRedirect(field + " must not be too long or contain a fragment")
		}
		u, err := url.Parse(raw)
		if err != nil || !u.IsAbs() {
			return nil, invalidRedirect(field + " must be absolute URIs")
		}
		switch strings.ToLower(u.Scheme) {
		case "https":
			if u.Host == "" || u.User != nil {
				return nil, invalidRedirect(field + " must have a host and no user information")
			}
		case "http":
			if !isLoopback(u.Hostname()) || u.User != nil {
				return nil, invalidRedirect("http " + field + " are allowed only for loopback addresses")
			}
		default:
			// Private-use schemes must be reverse domain names, which also
			// rules out javascript:, data: and file:
			if !strings.Contains(u.Scheme, ".") {
				return nil, invalidRedirect(field + " must use https, loopback http or a reverse-domain scheme")
			}
		}
	}
	return uris, nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// validScopeToken reports whether s is a scope-token (RFC 6749 §3.3)
func validScopeToken(s string) bool {
	if s == "" || len(s) > maxRegisteredScopeLen {
		return false
	}
	for _, r := range s {
		if r < 0x21 || r > 0x7e || r == '"' || r == '\\' {
			return false
		}
	}
	return true
}

func dedupe(values []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, v := range values {
		if v = strings.TrimSpace(v); v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}
