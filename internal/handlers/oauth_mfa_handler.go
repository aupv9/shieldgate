package handlers

// oauth_mfa_handler.go implements the TOTP step of the browser login flow.
// The password step hands over a short-lived signed state token; this step
// verifies the authenticator code and then continues like a normal login.

import (
	"net/http"
	"strings"

	"shieldgate/internal/middleware"
	"shieldgate/internal/models"
	"shieldgate/internal/services"

	"github.com/gin-gonic/gin"
)

// HandleMFAVerify handles POST /oauth/mfa — second authentication factor
func (h *OAuthHandler) HandleMFAVerify(c *gin.Context) {
	tenantID, err := middleware.GetTenantID(c)
	if err != nil {
		h.renderError(c, "invalid_request", "Tenant context required — provide X-Tenant-ID header", "")
		return
	}

	// CSRF protection (same double-submit scheme as the login form)
	cookieToken, _ := c.Cookie(csrfCookieName)
	if !validateCSRFToken(h.cfg.JWTSecret, c.PostForm("csrf_token"), cookieToken) {
		h.logger.WithField("tenant_id", tenantID).Warn("CSRF validation failed on MFA endpoint")
		h.renderError(c, "invalid_request", "Invalid or missing CSRF token — please retry the authorization flow", "")
		return
	}

	// The state token proves the password step succeeded for this user
	userID, ok := validateMFAStateToken(h.cfg.JWTSecret, c.PostForm("mfa_token"))
	if !ok {
		h.renderError(c, "invalid_request", "Your login attempt has expired — please sign in again", "")
		return
	}

	clientID := c.PostForm("client_id")
	redirectURI := c.PostForm("redirect_uri")
	scope := c.PostForm("scope")
	state := c.PostForm("state")
	codeChallenge := c.PostForm("code_challenge")
	codeChallengeMethod := c.PostForm("code_challenge_method")
	nonce := c.PostForm("nonce")

	tenant, _ := h.tenantService.GetByID(c.Request.Context(), tenantID)

	// Verify the TOTP code
	if err := h.userService.VerifyMFA(c.Request.Context(), tenantID, userID, strings.TrimSpace(c.PostForm("code"))); err != nil {
		h.logger.WithField("tenant_id", tenantID).Warn("MFA verification failed")
		// Re-render with a fresh state token so the user can retry
		mfaToken, tokenErr := newMFAStateToken(h.cfg.JWTSecret, userID, mfaStateTokenTTL)
		if tokenErr != nil {
			h.renderError(c, "server_error", "Internal server error", "")
			return
		}
		h.renderMFAPage(c, tenant, mfaToken, clientID, redirectURI, scope, state, codeChallenge, codeChallengeMethod, nonce, "Invalid authentication code — try again")
		return
	}

	// Re-validate the client-controlled form parameters before issuing a code
	client, err := h.clientService.GetByClientID(c.Request.Context(), tenantID, clientID)
	if err != nil {
		h.renderError(c, "invalid_client", "Invalid client", "")
		return
	}
	if err := h.clientService.ValidateRedirectURI(c.Request.Context(), client, redirectURI); err != nil {
		h.renderError(c, "invalid_request", "Invalid redirect URI", "")
		return
	}
	if !client.HasGrantType("authorization_code") {
		h.renderError(c, "unauthorized_client", "Client is not authorized for the authorization_code grant", redirectURI)
		return
	}
	grantedScope, err := services.ValidateScopeForClient(client, scope)
	if err != nil {
		h.renderError(c, "invalid_scope", "Requested scope is not allowed for this client", redirectURI)
		return
	}

	h.finishBrowserLogin(c, tenantID, client, userID, redirectURI, grantedScope, state, codeChallenge, codeChallengeMethod, nonce)
}

func (h *OAuthHandler) renderMFAPage(c *gin.Context, tenant *models.Tenant, mfaToken, clientID, redirectURI, scope, state, codeChallenge, codeChallengeMethod, nonce, errorMsg string) {
	csrfToken, err := newCSRFToken(h.cfg.JWTSecret)
	if err != nil {
		h.logger.WithError(err).Error("failed to generate CSRF token")
		h.renderError(c, "server_error", "Internal server error", "")
		return
	}
	secure := strings.HasPrefix(h.cfg.ServerURL, "https://")
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(csrfCookieName, csrfToken, 600, "/oauth", "", secure, true)

	data := gin.H{
		"mfa_token":             mfaToken,
		"client_id":             clientID,
		"redirect_uri":          redirectURI,
		"scope":                 scope,
		"state":                 state,
		"code_challenge":        codeChallenge,
		"code_challenge_method": codeChallengeMethod,
		"nonce":                 nonce,
		"csrf_token":            csrfToken,
	}
	if tenant != nil {
		data["tenant_info"] = gin.H{"name": tenant.Name}
	}
	if errorMsg != "" {
		data["error"] = errorMsg
	}

	c.HTML(http.StatusOK, "mfa.html", data)
}
