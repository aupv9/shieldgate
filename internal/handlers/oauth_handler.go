package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"shieldgate/config"
	"shieldgate/internal/middleware"
	"shieldgate/internal/models"
	"shieldgate/internal/observability"
	"shieldgate/internal/services"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// OAuthHandler handles OAuth 2.0 authorization flows
type OAuthHandler struct {
	cfg            *config.Config
	tenantService  services.TenantService
	userService    services.UserService
	clientService  services.ClientService
	authService    services.AuthService
	sessionService services.SessionService
	// mfaService may be nil, in which case no second factor is asked
	mfaService services.MFAService
	// events may be nil, in which case nothing is audited or counted
	events *observability.Recorder
	logger *logrus.Logger
}

// WithRecorder makes the handler audit and count authentication events
func (h *OAuthHandler) WithRecorder(events *observability.Recorder) *OAuthHandler {
	h.events = events
	return h
}

// record audits and counts an authentication event of this request
func (h *OAuthHandler) record(c *gin.Context, ev observability.Event) {
	h.events.Record(c.Request.Context(), ev)
}

// NewOAuthHandler creates a new OAuth handler
func NewOAuthHandler(
	cfg *config.Config,
	tenantService services.TenantService,
	userService services.UserService,
	clientService services.ClientService,
	authService services.AuthService,
	sessionService services.SessionService,
	mfaService services.MFAService,
	logger *logrus.Logger,
) *OAuthHandler {
	return &OAuthHandler{
		cfg:            cfg,
		tenantService:  tenantService,
		userService:    userService,
		clientService:  clientService,
		authService:    authService,
		sessionService: sessionService,
		mfaService:     mfaService,
		logger:         logger,
	}
}

// RegisterRoutes registers OAuth routes
func (h *OAuthHandler) RegisterRoutes(router *gin.RouterGroup) {
	// OAuth 2.0 endpoints (no versioning per spec)
	oauth := router.Group("/oauth")
	{
		oauth.GET("/authorize", h.HandleAuthorize)
		oauth.POST("/authorize", h.HandleAuthorize)
		oauth.POST("/login", h.HandleLogin)
		oauth.POST("/login/mfa", h.HandleLoginMFA)
		oauth.POST("/consent", h.HandleConsent)
		oauth.GET("/logout", h.HandleLogout)
		oauth.POST("/logout", h.HandleLogout)
		// Responses carrying tokens or credentials must not be cached
		// (RFC 6749 §5.1, RFC 8628 §3.2, RFC 7662 §4)
		oauth.POST("/token", noStore, h.HandleToken)
		oauth.POST("/introspect", noStore, h.HandleIntrospect)
		oauth.POST("/revoke", h.HandleRevoke)
		oauth.POST("/device_authorization", noStore, h.HandleDeviceAuthorization)
		oauth.GET("/device", h.HandleDeviceVerificationPage)
		oauth.POST("/device", h.HandleDeviceVerification)
		oauth.POST("/device/mfa", h.HandleDeviceMFA)
	}

	// OpenID Connect endpoints
	oidc := router.Group("/.well-known")
	{
		oidc.GET("/openid-configuration", h.HandleDiscovery)
		// RFC 8414 authorization server metadata; same document
		oidc.GET("/oauth-authorization-server", h.HandleDiscovery)
		oidc.GET("/jwks.json", h.HandleJWKS)
	}

	// UserInfo endpoint; OIDC Core §5.3 requires both GET and POST
	router.GET("/userinfo", h.HandleUserInfo)
	router.POST("/userinfo", h.HandleUserInfo)
}

// HandleToken handles token exchange requests
func (h *OAuthHandler) HandleToken(c *gin.Context) {
	tenantID, err := middleware.GetTenantID(c)
	if err != nil {
		h.logger.WithError(err).Warn("missing tenant context on token endpoint")
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "Tenant context required — provide X-Tenant-ID header",
		})
		return
	}

	grantType := c.PostForm("grant_type")

	// Every grant branch writes its own response; capture it once here to
	// count the outcome by OAuth error code
	result := &tokenResultWriter{ResponseWriter: c.Writer}
	c.Writer = result
	defer func() { h.events.Metrics().TokenRequest(grantType, result.outcome()) }()

	switch grantType {
	case "authorization_code":
		h.handleAuthorizationCodeGrant(c, tenantID)
	case "refresh_token":
		h.handleRefreshTokenGrant(c, tenantID)
	case "client_credentials":
		h.handleClientCredentialsGrant(c, tenantID)
	case models.GrantTypeDeviceCode:
		h.handleDeviceCodeGrant(c, tenantID)
	case models.GrantTypeTokenExchange:
		h.handleTokenExchangeGrant(c, tenantID)
	default:
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "unsupported_grant_type",
			"error_description": "Grant type not supported",
		})
	}
}

// handleAuthorizationCodeGrant handles authorization code grant
func (h *OAuthHandler) handleAuthorizationCodeGrant(c *gin.Context, tenantID uuid.UUID) {
	code := c.PostForm("code")
	redirectURI := c.PostForm("redirect_uri")
	codeVerifier := c.PostForm("code_verifier")

	// Authenticate client (client_secret_basic or client_secret_post)
	client, ok := h.authenticateClient(c, tenantID)
	if !ok {
		return
	}
	clientID := client.ClientID

	if !client.HasGrantType("authorization_code") {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "unauthorized_client",
			"error_description": "Client is not authorized for the authorization_code grant",
		})
		return
	}

	// Exchange code for tokens. The code is bound to the client's internal
	// ID, not its public client_id.
	tokenResponse, err := h.authService.ExchangeAuthorizationCode(
		c.Request.Context(),
		tenantID,
		code,
		client.ID.String(),
		"", // client already authenticated above
		redirectURI,
		codeVerifier,
	)
	if err != nil {
		h.logger.WithError(err).Error("token exchange failed")
		if err == models.ErrPKCEVerificationFailed {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":             "invalid_grant",
				"error_description": "PKCE verification failed",
			})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_grant",
			"error_description": "Authorization code is invalid or expired",
		})
		return
	}

	h.logger.WithFields(logrus.Fields{
		"tenant_id": tenantID,
		"client_id": clientID,
	}).Info("tokens generated successfully")

	c.JSON(http.StatusOK, tokenResponse)
}

// handleRefreshTokenGrant handles refresh token grant
func (h *OAuthHandler) handleRefreshTokenGrant(c *gin.Context, tenantID uuid.UUID) {
	refreshToken := c.PostForm("refresh_token")
	requestedScope := c.PostForm("scope")

	// Authenticate client (client_secret_basic or client_secret_post)
	client, ok := h.authenticateClient(c, tenantID)
	if !ok {
		return
	}

	if !client.HasGrantType("refresh_token") {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "unauthorized_client",
			"error_description": "Client is not authorized for the refresh_token grant",
		})
		return
	}

	// Refresh tokens (rotation with reuse detection; scope may only narrow)
	// Refresh tokens are bound to the client's internal ID
	tokenResponse, err := h.authService.RefreshTokens(c.Request.Context(), tenantID, refreshToken, client.ID.String(), requestedScope)
	if err != nil {
		h.logger.WithError(err).WithField("client_id", client.ClientID).Warn("refresh token grant failed")
		if err == models.ErrInvalidScope {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":             "invalid_scope",
				"error_description": "Requested scope exceeds the originally granted scope",
			})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_grant",
			"error_description": "Refresh token is invalid or expired",
		})
		return
	}

	c.JSON(http.StatusOK, tokenResponse)
}

// handleClientCredentialsGrant handles client credentials grant
func (h *OAuthHandler) handleClientCredentialsGrant(c *gin.Context, tenantID uuid.UUID) {
	scope := c.PostForm("scope")

	// Authenticate client (client_secret_basic or client_secret_post)
	client, ok := h.authenticateClient(c, tenantID)
	if !ok {
		return
	}

	// Public clients cannot use the client credentials grant — there is
	// nothing to authenticate them with (RFC 6749 §4.4)
	if client.IsPublic {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "invalid_client",
			"error_description": "Public clients cannot use the client_credentials grant",
		})
		return
	}

	if !client.HasGrantType("client_credentials") {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "unauthorized_client",
			"error_description": "Client is not authorized for the client_credentials grant",
		})
		return
	}

	// Requested scopes must be within the client's registered scopes
	grantedScope, err := services.ValidateScopeForClient(client, scope)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_scope",
			"error_description": "Requested scope is not allowed for this client",
		})
		return
	}

	// Generate client credentials token (no refresh token per RFC 6749 §4.4.3)
	tokenResponse, err := h.authService.GenerateClientCredentialsTokens(c.Request.Context(), tenantID, client, grantedScope)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "Failed to generate tokens",
		})
		return
	}

	c.JSON(http.StatusOK, tokenResponse)
}

// authenticateClient extracts and validates client credentials from the
// request (Basic header or form body). On failure it writes the RFC-compliant
// 401 response and returns ok=false.
func (h *OAuthHandler) authenticateClient(c *gin.Context, tenantID uuid.UUID) (*models.Client, bool) {
	clientID, clientSecret, ok := clientCredentialsFromRequest(c)
	if !ok {
		c.Header("WWW-Authenticate", `Basic realm="oauth"`)
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "invalid_client",
			"error_description": "Client authentication required",
		})
		return nil, false
	}

	client, err := h.clientService.ValidateClient(c.Request.Context(), tenantID, clientID, clientSecret)
	if err != nil {
		h.logger.WithError(err).WithField("client_id", clientID).Warn("client authentication failed")
		c.Header("WWW-Authenticate", `Basic realm="oauth"`)
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "invalid_client",
			"error_description": "Client authentication failed",
		})
		return nil, false
	}

	return client, true
}

// HandleUserInfo returns claims about the authenticated user (OIDC Core §5.3).
// Errors follow RFC 6750 §3 with a WWW-Authenticate challenge.
func (h *OAuthHandler) HandleUserInfo(c *gin.Context) {
	// Tenant context comes from the bearer token via TenantContext
	tenantID, err := middleware.GetTenantID(c)
	if err != nil {
		h.bearerError(c, http.StatusUnauthorized, "invalid_token", "")
		return
	}

	authHeader := c.GetHeader("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		// No credentials: RFC 6750 §3.1 says to omit the error code
		c.Header("WWW-Authenticate", `Bearer realm="`+h.cfg.ServerURL+`"`)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_request"})
		return
	}
	token := strings.TrimPrefix(authHeader, "Bearer ")

	userInfo, err := h.authService.GetUserInfo(c.Request.Context(), tenantID, token)
	switch {
	case err == nil:
		c.JSON(http.StatusOK, userInfo)
	case errors.Is(err, models.ErrInsufficientScope):
		h.bearerError(c, http.StatusForbidden, "insufficient_scope", "openid")
	default:
		h.bearerError(c, http.StatusUnauthorized, "invalid_token", "")
	}
}

// bearerError writes an RFC 6750 §3 error with its WWW-Authenticate challenge
func (h *OAuthHandler) bearerError(c *gin.Context, status int, code, scope string) {
	challenge := `Bearer realm="` + h.cfg.ServerURL + `", error="` + code + `"`
	if scope != "" {
		challenge += `, scope="` + scope + `"`
	}
	c.Header("WWW-Authenticate", challenge)
	c.JSON(status, gin.H{"error": code})
}

// HandleDiscovery handles OpenID Connect discovery
func (h *OAuthHandler) HandleDiscovery(c *gin.Context) {
	discovery, err := h.authService.GetDiscoveryDocument(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	c.JSON(http.StatusOK, discovery)
}

// HandleJWKS publishes the public signing keys (RFC 7517) so relying parties
// can verify ID and access tokens. HS256 secrets are never published, so the
// set is empty when the server signs with HS256.
func (h *OAuthHandler) HandleJWKS(c *gin.Context) {
	jwks, err := h.authService.GetJWKS(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	// Short cache so a newly pre-published key is picked up well before it is
	// used for signing (see internal/jwtkeys for the rotation procedure)
	c.Header("Cache-Control", "public, max-age=900")
	c.JSON(http.StatusOK, jwks)
}

// HandleIntrospect handles token introspection (RFC 7662).
// The caller must authenticate as a confidential client (§2.1).
func (h *OAuthHandler) HandleIntrospect(c *gin.Context) {
	tenantID, err := middleware.GetTenantID(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "Tenant context required — provide X-Tenant-ID header",
		})
		return
	}

	client, ok := h.authenticateClient(c, tenantID)
	if !ok {
		return
	}
	// Introspection requires real authentication; a public client has no
	// credentials, so its "authentication" proves nothing
	if client.IsPublic {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "invalid_client",
			"error_description": "Introspection requires a confidential client",
		})
		return
	}

	token := c.PostForm("token")
	if token == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}

	introspection, err := h.authService.IntrospectToken(c.Request.Context(), tenantID, token)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"active": false})
		return
	}

	c.JSON(http.StatusOK, introspection)
}

// HandleRevoke handles token revocation (RFC 7009).
// The caller must authenticate; only its own tokens are revoked.
func (h *OAuthHandler) HandleRevoke(c *gin.Context) {
	tenantID, err := middleware.GetTenantID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client"})
		return
	}

	client, ok := h.authenticateClient(c, tenantID)
	if !ok {
		return
	}

	token := c.PostForm("token")
	tokenTypeHint := c.PostForm("token_type_hint")

	if token == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}

	err = h.authService.RevokeToken(c.Request.Context(), tenantID, token, tokenTypeHint, client.ID)
	if err != nil {
		h.logger.WithError(err).Error("token revocation failed")
	}

	// Always return 200 per RFC 7009
	c.Status(http.StatusOK)
}

// Helper methods

func (h *OAuthHandler) authenticateUser(ctx context.Context, tenantID uuid.UUID, username, password string) (*models.User, error) {
	return h.userService.Authenticate(ctx, tenantID, username, password)
}

// renderError shows an error page, or, when redirectURI is set, redirects
// the error to the client. Pass a redirectURI only after it has been
// validated against the client registration.
func (h *OAuthHandler) renderError(c *gin.Context, errorCode, errorDescription, redirectURI, state string) {
	if redirectURI != "" {
		// Redirect with error (RFC 6749 §4.1.2.1, RFC 9207)
		redirectURL, err := url.Parse(redirectURI)
		if err == nil {
			query := redirectURL.Query()
			query.Set("error", errorCode)
			query.Set("error_description", errorDescription)
			if state != "" {
				query.Set("state", state)
			}
			query.Set("iss", h.cfg.ServerURL)
			redirectURL.RawQuery = query.Encode()
			c.Redirect(http.StatusFound, redirectURL.String())
			return
		}
	}

	// Render error page
	c.HTML(http.StatusBadRequest, "error.html", gin.H{
		"error":             errorCode,
		"error_description": errorDescription,
	})
}

// maxTokenErrorBody bounds how much of an error response is kept to read
// its OAuth error code
const maxTokenErrorBody = 4096

// tokenResultWriter keeps the start of a token endpoint response so its
// outcome (success or OAuth error code) can be counted
type tokenResultWriter struct {
	gin.ResponseWriter
	body bytes.Buffer
}

func (w *tokenResultWriter) Write(b []byte) (int, error) {
	if room := maxTokenErrorBody - w.body.Len(); room > 0 && w.Status() >= http.StatusBadRequest {
		w.body.Write(b[:min(len(b), room)])
	}
	return w.ResponseWriter.Write(b)
}

func (w *tokenResultWriter) WriteString(s string) (int, error) {
	return w.Write([]byte(s))
}

// outcome returns "success" or the error code of an OAuth error response
func (w *tokenResultWriter) outcome() string {
	if w.Status() < http.StatusBadRequest {
		return "success"
	}
	var resp struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(w.body.Bytes(), &resp) != nil || resp.Error == "" {
		return "server_error"
	}
	return resp.Error
}
