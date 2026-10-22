package handlers

import (
	"net/http"
	"net/url"

	"shieldgate/internal/middleware"
	"shieldgate/internal/models"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

// HandleLogout implements OpenID Connect RP-Initiated Logout 1.0
// (end_session_endpoint) for GET and POST.
//
// Parameters: id_token_hint, client_id, post_logout_redirect_uri, state.
// The user is redirected to post_logout_redirect_uri only if the client is
// identified and registered that exact URI. Without an id_token_hint naming
// the signed-in user, the user is asked to confirm first, so a third-party
// site cannot sign users out (logout CSRF).
func (h *OAuthHandler) HandleLogout(c *gin.Context) {
	tenantID, err := middleware.GetTenantID(c)
	if err != nil {
		h.renderError(c, "invalid_request", "Tenant context required — use the tenant's domain or provide X-Tenant-ID", "", "")
		return
	}

	get := c.Query
	if c.Request.Method == http.MethodPost {
		if !h.validCSRF(c) {
			h.renderError(c, "invalid_request", "Invalid or missing CSRF token — please retry signing out", "", "")
			return
		}
		get = c.PostForm
	}

	var hint *models.IDTokenClaims
	if raw := get("id_token_hint"); raw != "" {
		claims, err := h.authService.ParseIDTokenHint(c.Request.Context(), raw)
		if err != nil || claims.TenantID != tenantID.String() {
			h.renderError(c, "invalid_request", "Invalid id_token_hint", "", "")
			return
		}
		hint = claims
	}

	clientID := get("client_id")
	if hint != nil {
		if clientID != "" && clientID != hint.Aud {
			h.renderError(c, "invalid_request", "client_id does not match id_token_hint", "", "")
			return
		}
		clientID = hint.Aud
	}

	redirectURI := get("post_logout_redirect_uri")
	if redirectURI != "" {
		if clientID == "" {
			h.renderError(c, "invalid_request", "post_logout_redirect_uri requires client_id or id_token_hint", "", "")
			return
		}
		client, err := h.clientService.GetByClientID(c.Request.Context(), tenantID, clientID)
		if err != nil {
			h.renderError(c, "invalid_request", "Unknown client", "", "")
			return
		}
		if !client.PostLogoutRedirectURIs.Contains(redirectURI) {
			h.logger.WithFields(logrus.Fields{
				"client_id":                clientID,
				"post_logout_redirect_uri": redirectURI,
			}).Warn("unregistered post_logout_redirect_uri")
			h.renderError(c, "invalid_request", "post_logout_redirect_uri is not registered for this client", "", "")
			return
		}
	}

	session := h.currentSession(c, tenantID)
	confirmed := c.Request.Method == http.MethodPost ||
		(hint != nil && (session == nil || hint.Sub == session.UserID.String()))
	if session != nil && !confirmed {
		data := gin.H{
			"confirm":                  true,
			"client_id":                clientID,
			"post_logout_redirect_uri": redirectURI,
			"state":                    get("state"),
		}
		if !h.addCSRFToken(c, data) {
			return
		}
		c.HTML(http.StatusOK, "logout.html", data)
		return
	}

	if session != nil {
		h.logger.WithFields(logrus.Fields{
			"tenant_id":  tenantID,
			"user_id":    session.UserID,
			"session_id": session.ID,
		}).Info("session ended by logout")
	}
	h.endBrowserSession(c, tenantID)

	if redirectURI != "" {
		target, err := url.Parse(redirectURI)
		if err == nil {
			if state := get("state"); state != "" {
				query := target.Query()
				query.Set("state", state)
				target.RawQuery = query.Encode()
			}
			c.Redirect(http.StatusFound, target.String())
			return
		}
	}

	c.HTML(http.StatusOK, "logout.html", gin.H{"confirm": false})
}
