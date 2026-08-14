package handlers

// oauth_session_handler.go implements the browser-session side of the
// authorization endpoint: SSO sessions, prompt/max_age handling, the consent
// screen, and RP-initiated logout (end_session_endpoint).

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"shieldgate/internal/middleware"
	"shieldgate/internal/models"
	"shieldgate/internal/services"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

const sessionCookieName = "sg_session"

// parsePrompt splits the OIDC prompt parameter into a set
func parsePrompt(prompt string) map[string]bool {
	set := make(map[string]bool)
	for _, p := range strings.Fields(prompt) {
		set[p] = true
	}
	return set
}

// currentSession resolves the SSO session cookie, returning nil when absent,
// expired or revoked
func (h *OAuthHandler) currentSession(c *gin.Context, tenantID uuid.UUID) *models.UserSession {
	token, err := c.Cookie(sessionCookieName)
	if err != nil || token == "" {
		return nil
	}
	session, err := h.authService.GetSession(c.Request.Context(), tenantID, token)
	if err != nil {
		return nil
	}
	return session
}

func (h *OAuthHandler) setSessionCookie(c *gin.Context, token string) {
	secure := strings.HasPrefix(h.cfg.ServerURL, "https://")
	maxAge := int(h.cfg.SessionDuration.Seconds())
	if maxAge <= 0 {
		maxAge = 86400
	}
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(sessionCookieName, token, maxAge, "/", "", secure, true)
}

func (h *OAuthHandler) clearSessionCookie(c *gin.Context) {
	secure := strings.HasPrefix(h.cfg.ServerURL, "https://")
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(sessionCookieName, "", -1, "/", "", secure, true)
}

// redirectAuthError sends an OAuth error back to the client's redirect URI
// (used for prompt=none failures and consent denials)
func (h *OAuthHandler) redirectAuthError(c *gin.Context, redirectURI, errorCode, description, state string) {
	parsed, err := url.Parse(redirectURI)
	if err != nil {
		h.renderError(c, errorCode, description, "")
		return
	}
	query := parsed.Query()
	query.Set("error", errorCode)
	query.Set("error_description", description)
	if state != "" {
		query.Set("state", state)
	}
	parsed.RawQuery = query.Encode()
	c.Redirect(http.StatusFound, parsed.String())
}

// completeAuthorization issues the authorization code and redirects back to
// the client. authTime is the moment the user actually authenticated.
func (h *OAuthHandler) completeAuthorization(c *gin.Context, tenantID uuid.UUID, client *models.Client, userID uuid.UUID, redirectURI, scope, state, codeChallenge, codeChallengeMethod, nonce string, authTime time.Time) {
	authCode, err := h.authService.GenerateAuthorizationCode(
		c.Request.Context(), tenantID, client.ID, userID,
		redirectURI, scope, codeChallenge, codeChallengeMethod, nonce, authTime,
	)
	if err != nil {
		h.logger.WithError(err).Error("failed to generate authorization code")
		h.renderError(c, "server_error", "Internal server error", redirectURI)
		return
	}

	redirectURL, err := url.Parse(redirectURI)
	if err != nil {
		h.renderError(c, "invalid_request", "Invalid redirect URI", "")
		return
	}
	query := redirectURL.Query()
	query.Set("code", authCode.Code)
	if state != "" {
		query.Set("state", state)
	}
	redirectURL.RawQuery = query.Encode()

	h.logger.WithFields(logrus.Fields{
		"tenant_id": tenantID,
		"user_id":   userID,
		"client_id": client.ClientID,
	}).Info("authorization code issued")

	c.Redirect(http.StatusFound, redirectURL.String())
}

// HandleConsent handles POST /oauth/consent — the user approves or denies the
// client's scope request from the consent screen
func (h *OAuthHandler) HandleConsent(c *gin.Context) {
	tenantID, err := middleware.GetTenantID(c)
	if err != nil {
		h.renderError(c, "invalid_request", "Tenant context required — provide X-Tenant-ID header", "")
		return
	}

	// CSRF protection
	cookieToken, _ := c.Cookie(csrfCookieName)
	if !validateCSRFToken(h.cfg.JWTSecret, c.PostForm("csrf_token"), cookieToken) {
		h.logger.WithField("tenant_id", tenantID).Warn("CSRF validation failed on consent endpoint")
		h.renderError(c, "invalid_request", "Invalid or missing CSRF token — please retry the authorization flow", "")
		return
	}

	// Consent decisions require a live session — never re-authenticate here
	session := h.currentSession(c, tenantID)
	if session == nil {
		h.renderError(c, "invalid_request", "Your session has expired — please restart the authorization flow", "")
		return
	}

	clientID := c.PostForm("client_id")
	redirectURI := c.PostForm("redirect_uri")
	scope := c.PostForm("scope")
	state := c.PostForm("state")

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

	if c.PostForm("action") == "deny" {
		h.redirectAuthError(c, redirectURI, "access_denied", "The user denied the authorization request", state)
		return
	}

	if err := h.authService.GrantConsent(c.Request.Context(), tenantID, session.UserID, client.ID, grantedScope); err != nil {
		h.logger.WithError(err).Error("failed to store consent")
		h.renderError(c, "server_error", "Internal server error", redirectURI)
		return
	}

	h.completeAuthorization(c, tenantID, client, session.UserID,
		redirectURI, grantedScope, state,
		c.PostForm("code_challenge"), c.PostForm("code_challenge_method"), c.PostForm("nonce"),
		session.AuthTime)
}

// HandleLogout implements RP-initiated logout (end_session_endpoint).
// The session cookie is revoked; post_logout_redirect_uri is honored only
// when it belongs to the identified client.
func (h *OAuthHandler) HandleLogout(c *gin.Context) {
	tenantID, tenantErr := middleware.GetTenantID(c)

	if tenantErr == nil {
		if token, err := c.Cookie(sessionCookieName); err == nil && token != "" {
			if err := h.authService.RevokeSession(c.Request.Context(), tenantID, token); err != nil {
				h.logger.WithError(err).Error("failed to revoke session on logout")
			}
		}
	}
	h.clearSessionCookie(c)

	// Optional redirect back to the relying party
	postLogoutURI := c.Query("post_logout_redirect_uri")
	if postLogoutURI == "" {
		postLogoutURI = c.PostForm("post_logout_redirect_uri")
	}
	clientID := c.Query("client_id")
	if clientID == "" {
		clientID = c.PostForm("client_id")
	}
	state := c.Query("state")
	if state == "" {
		state = c.PostForm("state")
	}

	if postLogoutURI != "" && clientID != "" && tenantErr == nil {
		client, err := h.clientService.GetByClientID(c.Request.Context(), tenantID, clientID)
		if err == nil && client.HasRedirectURI(postLogoutURI) {
			target, err := url.Parse(postLogoutURI)
			if err == nil {
				if state != "" {
					query := target.Query()
					query.Set("state", state)
					target.RawQuery = query.Encode()
				}
				c.Redirect(http.StatusFound, target.String())
				return
			}
		}
	}

	c.HTML(http.StatusOK, "logged_out.html", gin.H{})
}

// renderConsentPage shows the consent screen listing the requested scopes
func (h *OAuthHandler) renderConsentPage(c *gin.Context, req *models.AuthorizeRequest, client *models.Client, tenant *models.Tenant, grantedScope string) {
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
		"client_id":             req.ClientID,
		"client_name":           client.Name,
		"redirect_uri":          req.RedirectURI,
		"scope":                 grantedScope,
		"scopes":                services.ParseScope(grantedScope),
		"state":                 req.State,
		"code_challenge":        req.CodeChallenge,
		"code_challenge_method": req.CodeChallengeMethod,
		"nonce":                 req.Nonce,
		"csrf_token":            csrfToken,
	}
	if tenant != nil {
		data["tenant_info"] = gin.H{"name": tenant.Name}
	}

	c.HTML(http.StatusOK, "consent.html", data)
}

// maxAgeExceeded reports whether the session's authentication is older than
// the request's max_age parameter (OIDC Core §3.1.2.1)
func maxAgeExceeded(session *models.UserSession, maxAgeParam string) bool {
	if maxAgeParam == "" {
		return false
	}
	maxAge, err := strconv.Atoi(maxAgeParam)
	if err != nil || maxAge < 0 {
		return false
	}
	return time.Since(session.AuthTime) > time.Duration(maxAge)*time.Second
}
