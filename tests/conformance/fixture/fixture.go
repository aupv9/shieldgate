// Package fixture holds the test data that tests/conformance/seed creates
// and that the conformance tests, the OpenID Foundation suite configuration
// and the load tests rely on. It is for test databases only.
package fixture

import "github.com/google/uuid"

// Fixed identifiers, so test configuration can refer to them
var (
	TenantID = uuid.MustParse("c0f0c0f0-0000-4000-8000-000000000001")
	UserID   = uuid.MustParse("c0f0c0f0-0000-4000-8000-000000000002")
	User2ID  = uuid.MustParse("c0f0c0f0-0000-4000-8000-000000000003")
)

const (
	UserEmail  = "conformance@example.com"
	User2Email = "conformance2@example.com"
	// Password of both seeded users
	UserPassword = "Conformance-Passw0rd!"

	// ConfidentialClient authenticates with client_secret_basic
	ConfidentialClient = "conformance-rp"
	// ConfidentialClientPost authenticates with client_secret_post
	ConfidentialClientPost = "conformance-rp-2"
	// PublicClient authenticates with PKCE only
	PublicClient = "conformance-spa"
	// MachineClient may only use client_credentials
	MachineClient = "load-m2m"
	// ClientSecret is the secret of every confidential client
	ClientSecret = "conformance-client-secret-0123456789"

	// RedirectURI is where the conformance tests send the browser; they
	// never follow the redirect, so nothing has to listen there
	RedirectURI   = "https://rp.conformance.test/callback"
	PostLogoutURI = "https://rp.conformance.test/logged-out"
)

// OIDFRedirectURIs are the OpenID Foundation conformance suite callbacks for
// the test alias "shieldgate" on a locally run suite (scripts/conformance/oidf)
var OIDFRedirectURIs = []string{
	"https://localhost.emobix.co.uk:8443/test/a/shieldgate/callback",
	"https://localhost.emobix.co.uk:8443/test/a/shieldgate/callback?dummy1=lorem&dummy2=ipsum",
}

// OIDFPostLogoutRedirectURI is where the suite's RP-initiated logout tests
// expect to be sent after logout
const OIDFPostLogoutRedirectURI = "https://localhost.emobix.co.uk:8443/test/a/shieldgate/post_logout_redirect"
