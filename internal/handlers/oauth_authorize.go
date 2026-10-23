package handlers

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"shieldgate/internal/middleware"
	"shieldgate/internal/models"
	"shieldgate/internal/observability"
	"shieldgate/internal/services"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// sessionCookieName holds the SSO session token
const sessionCookieName = "sg_session"

// OIDC prompt values (OIDC Core §3.1.2.1)
const (
	promptNone          = "none"
	promptLogin         = "login"
	promptConsent       = "consent"
	promptSelectAccount = "select_account"
)

// authorizationRequest is a validated authorization request. It is rebuilt
// from the query string on /oauth/authorize and from hidden form fields on
// /oauth/login and /oauth/consent, and re-validated every time because form
// values are client-controlled.
type authorizationRequest struct {
	*models.AuthorizeRequest
	client *models.Client
	// scope is the requested scope after validation against the client
	scope  string
	prompt map[string]bool
	// maxAge is the max_age parameter; negative when not requested
	maxAge time.Duration
}

// acceptsSession reports whether an existing session satisfies the request,
// or whether the user must authenticate again (prompt=login, max_age)
func (r *authorizationRequest) acceptsSession(session *models.Session) bool {
	if r.prompt[promptLogin] || r.prompt[promptSelectAccount] {
		return false
	}
	return r.maxAge < 0 || time.Since(session.AuthTime) <= r.maxAge
}

func readAuthorizeRequest(get func(string) string) *models.AuthorizeRequest {
	return &models.AuthorizeRequest{
		ResponseType:        get("response_type"),
		ClientID:            get("client_id"),
		RedirectURI:         get("redirect_uri"),
		Scope:               get("scope"),
		State:               get("state"),
		CodeChallenge:       get("code_challenge"),
		CodeChallengeMethod: get("code_challenge_method"),
		Nonce:               get("nonce"),
		Prompt:              get("prompt"),
		MaxAge:              get("max_age"),
	}
}

// validateAuthorizationRequest checks an authorization request against the
// client registration. On failure it renders or redirects the error and
// returns false.
func (h *OAuthHandler) validateAuthorizationRequest(c *gin.Context, tenantID uuid.UUID, req *models.AuthorizeRequest) (*authorizationRequest, bool) {
	// Until the client and redirect URI are validated, errors must be shown
	// to the user rather than redirected (RFC 6749 §4.1.2.1) — otherwise the
	// endpoint becomes an open redirector
	client, err := h.clientService.GetByClientID(c.Request.Context(), tenantID, req.ClientID)
	if err != nil {
		h.logger.WithError(err).WithField("client_id", req.ClientID).Error("client validation failed")
		h.renderError(c, "invalid_client", "Invalid client", "", "")
		return nil, false
	}
	if err := h.clientService.ValidateRedirectURI(c.Request.Context(), client, req.RedirectURI); err != nil {
		h.logger.WithError(err).WithField("redirect_uri", req.RedirectURI).Error("invalid redirect URI")
		h.renderError(c, "invalid_request", "Invalid redirect URI", "", "")
		return nil, false
	}

	// From here on the redirect URI is trusted, so errors go back to the client
	fail := func(code, description string) (*authorizationRequest, bool) {
		h.renderError(c, code, description, req.RedirectURI, req.State)
		return nil, false
	}

	if err := req.Validate(); err != nil {
		return fail("unsupported_response_type", err.Error())
	}
	if len(req.Nonce) > maxNonceLength {
		return fail("invalid_request", "nonce is too long")
	}
	if !client.HasGrantType("authorization_code") {
		return fail("unauthorized_client", "Client is not authorized for the authorization_code grant")
	}
	scope, err := services.ValidateScopeForClient(client, req.Scope)
	if err != nil {
		return fail("invalid_scope", "Requested scope is not allowed for this client")
	}
	if client.IsPublic {
		if req.CodeChallenge == "" || req.CodeChallengeMethod == "" {
			return fail("invalid_request", "PKCE required for public clients")
		}
		if req.CodeChallengeMethod != "S256" {
			return fail("invalid_request", "Only S256 code challenge method supported")
		}
	}

	// Unknown prompt values are ignored (OIDC Core §3.1.2.1 allows either)
	prompt := make(map[string]bool)
	for _, p := range strings.Fields(req.Prompt) {
		prompt[p] = true
	}
	if prompt[promptNone] && len(prompt) > 1 {
		return fail("invalid_request", "prompt=none cannot be combined with other values")
	}

	maxAge := time.Duration(-1)
	if req.MaxAge != "" {
		seconds, err := strconv.Atoi(req.MaxAge)
		if err != nil || seconds < 0 {
			return fail("invalid_request", "max_age must be a non-negative integer")
		}
		maxAge = time.Duration(seconds) * time.Second
	}

	return &authorizationRequest{
		AuthorizeRequest: req,
		client:           client,
		scope:            scope,
		prompt:           prompt,
		maxAge:           maxAge,
	}, true
}

// HandleAuthorize handles OAuth authorization requests (GET). With a live
// session the user skips the login page; consent is asked only for scopes
// not granted before.
func (h *OAuthHandler) HandleAuthorize(c *gin.Context) {
	tenantID, err := middleware.GetTenantID(c)
	if err != nil {
		h.logger.WithError(err).Warn("missing tenant context on authorize endpoint")
		h.renderError(c, "invalid_request", "Tenant context required — use the tenant's domain or provide X-Tenant-ID", "", "")
		return
	}

	ar, ok := h.validateAuthorizationRequest(c, tenantID, readAuthorizeRequest(c.Query))
	if !ok {
		return
	}

	session := h.currentSession(c, tenantID)
	if session != nil && !ar.acceptsSession(session) {
		session = nil
	}
	if session == nil {
		if ar.prompt[promptNone] {
			h.renderError(c, "login_required", "End-user authentication is required", ar.RedirectURI, ar.State)
			return
		}
		h.renderLoginPage(c, tenantID, ar, "")
		return
	}

	h.continueAuthorization(c, tenantID, ar, session)
}

// HandleLogin handles login form submission: it authenticates the user,
// starts a new SSO session and continues the authorization request
func (h *OAuthHandler) HandleLogin(c *gin.Context) {
	tenantID, err := middleware.GetTenantID(c)
	if err != nil {
		h.logger.WithError(err).Warn("missing tenant context on login endpoint")
		h.renderError(c, "invalid_request", "Tenant context required — use the tenant's domain or provide X-Tenant-ID", "", "")
		return
	}

	if !h.validCSRF(c) {
		h.logger.WithField("tenant_id", tenantID).Warn("CSRF validation failed on login endpoint")
		h.renderError(c, "invalid_request", "Invalid or missing CSRF token — please retry the authorization flow", "", "")
		return
	}

	ar, ok := h.validateAuthorizationRequest(c, tenantID, readAuthorizeRequest(c.PostForm))
	if !ok {
		return
	}

	username := c.PostForm("username")
	user, err := h.authenticateUser(c.Request.Context(), tenantID, username, c.PostForm("password"))
	if err != nil {
		h.logger.WithError(err).WithFields(logrus.Fields{
			"tenant_id": tenantID,
			"username":  username,
		}).Warn("authentication failed")
		h.recordLoginFailure(c, tenantID, mfaPurposeLogin, username, err)
		h.renderLoginPage(c, tenantID, ar, "Invalid email or password")
		return
	}

	required, err := h.mfaRequired(c.Request.Context(), tenantID, user.ID)
	if err != nil {
		h.logger.WithError(err).Error("failed to check MFA enrollment")
		h.renderError(c, "server_error", "Internal server error", ar.RedirectURI, ar.State)
		return
	}
	if required {
		h.record(c, observability.Event{Name: "login", Result: "mfa_required"})
		h.startMFA(c, tenantID, user.ID, mfaPurposeLogin, "/oauth/login/mfa", authorizationFormData(ar))
		return
	}

	h.signIn(c, tenantID, ar, user.ID, []string{services.AMRPassword})
}

// signIn starts a new SSO session for a fully authenticated user and
// continues the authorization request
func (h *OAuthHandler) signIn(c *gin.Context, tenantID uuid.UUID, ar *authorizationRequest, userID uuid.UUID, amr []string) {
	// Always issue a fresh session token on login, discarding any previous
	// one, so a token planted before login cannot be reused (session fixation).
	// The new cookie overwrites the old one, so it is not cleared here.
	h.deleteBrowserSession(c, tenantID)
	token, session, err := h.sessionService.CreateSession(c.Request.Context(), tenantID, userID, amr, c.ClientIP(), c.Request.UserAgent())
	if err != nil {
		h.logger.WithError(err).Error("failed to create session")
		h.renderError(c, "server_error", "Internal server error", ar.RedirectURI, ar.State)
		return
	}
	h.setSessionCookie(c, token)
	h.record(c, observability.Event{
		Action: models.AuditActionUserLogin, TenantID: tenantID, UserID: &userID, ClientID: &ar.client.ID,
		Success: true, Metadata: map[string]interface{}{"amr": amr, "flow": mfaPurposeLogin},
		Name: "login", Result: "success",
	})

	h.continueAuthorization(c, tenantID, ar, session)
}

// recordLoginFailure audits a failed password check. The attempted
// username is kept so credential-stuffing patterns are visible.
func (h *OAuthHandler) recordLoginFailure(c *gin.Context, tenantID uuid.UUID, flow, username string, err error) {
	result := "invalid_credentials"
	if errors.Is(err, models.ErrUserLocked) {
		result = "locked"
	}
	h.record(c, observability.Event{
		Action: models.AuditActionUserLoginFailed, TenantID: tenantID, ErrorCode: result,
		Metadata: map[string]interface{}{"username": username, "flow": flow},
		Name:     "login", Result: result,
	})
}

// HandleConsent handles the consent form: on approval it remembers the
// granted scopes and issues the authorization code
func (h *OAuthHandler) HandleConsent(c *gin.Context) {
	tenantID, err := middleware.GetTenantID(c)
	if err != nil {
		h.renderError(c, "invalid_request", "Tenant context required — use the tenant's domain or provide X-Tenant-ID", "", "")
		return
	}

	if !h.validCSRF(c) {
		h.logger.WithField("tenant_id", tenantID).Warn("CSRF validation failed on consent endpoint")
		h.renderError(c, "invalid_request", "Invalid or missing CSRF token — please retry the authorization flow", "", "")
		return
	}

	ar, ok := h.validateAuthorizationRequest(c, tenantID, readAuthorizeRequest(c.PostForm))
	if !ok {
		return
	}

	// The session may have expired while the consent page was open
	session := h.currentSession(c, tenantID)
	if session == nil {
		h.renderLoginPage(c, tenantID, ar, "Your session has expired — please sign in again")
		return
	}

	if c.PostForm("decision") != "allow" {
		h.logger.WithFields(logrus.Fields{
			"tenant_id": tenantID,
			"user_id":   session.UserID,
			"client_id": ar.client.ClientID,
		}).Info("user denied consent")
		h.record(c, observability.Event{
			Action: models.AuditActionConsentDenied, TenantID: tenantID, UserID: &session.UserID, ClientID: &ar.client.ID,
			Metadata: map[string]interface{}{"scope": ar.scope}, Name: "consent", Result: "denied",
		})
		h.renderError(c, "access_denied", "The user denied the request", ar.RedirectURI, ar.State)
		return
	}

	if err := h.sessionService.GrantConsent(c.Request.Context(), tenantID, session.UserID, ar.client.ID, ar.scope); err != nil {
		h.logger.WithError(err).Error("failed to record consent")
		h.renderError(c, "server_error", "Internal server error", ar.RedirectURI, ar.State)
		return
	}
	h.record(c, observability.Event{
		Action: models.AuditActionConsentGranted, TenantID: tenantID, UserID: &session.UserID, ClientID: &ar.client.ID,
		Success: true, Metadata: map[string]interface{}{"scope": ar.scope}, Name: "consent", Result: "granted",
	})

	h.issueAuthorizationCode(c, tenantID, ar, session)
}

// continueAuthorization runs once the user has a session: it asks for consent
// when needed, otherwise issues the authorization code
func (h *OAuthHandler) continueAuthorization(c *gin.Context, tenantID uuid.UUID, ar *authorizationRequest, session *models.Session) {
	granted, err := h.sessionService.HasConsent(c.Request.Context(), tenantID, session.UserID, ar.client.ID, ar.scope)
	if err != nil {
		h.logger.WithError(err).Error("failed to check consent")
		h.renderError(c, "server_error", "Internal server error", ar.RedirectURI, ar.State)
		return
	}

	if !granted || ar.prompt[promptConsent] {
		if ar.prompt[promptNone] {
			h.renderError(c, "consent_required", "End-user consent is required", ar.RedirectURI, ar.State)
			return
		}
		h.renderConsentPage(c, tenantID, ar, session)
		return
	}

	h.issueAuthorizationCode(c, tenantID, ar, session)
}

// issueAuthorizationCode creates the code and redirects back to the client.
// auth_time is when the session's user last entered credentials.
func (h *OAuthHandler) issueAuthorizationCode(c *gin.Context, tenantID uuid.UUID, ar *authorizationRequest, session *models.Session) {
	authCode, err := h.authService.GenerateAuthorizationCode(
		c.Request.Context(),
		tenantID,
		ar.client.ID,
		session.UserID,
		ar.RedirectURI,
		ar.scope,
		ar.CodeChallenge,
		ar.CodeChallengeMethod,
		ar.Nonce,
		session.AuthTime,
		[]string(session.AMR),
	)
	if err != nil {
		h.logger.WithError(err).Error("failed to generate authorization code")
		h.renderError(c, "server_error", "Internal server error", ar.RedirectURI, ar.State)
		return
	}

	redirectURL, err := url.Parse(ar.RedirectURI)
	if err != nil {
		h.logger.WithError(err).Error("invalid redirect URI")
		h.renderError(c, "invalid_request", "Invalid redirect URI", "", "")
		return
	}
	query := redirectURL.Query()
	query.Set("code", authCode.Code)
	if ar.State != "" {
		query.Set("state", ar.State)
	}
	// RFC 9207: identify the issuer so clients can detect mix-up attacks
	query.Set("iss", h.cfg.ServerURL)
	redirectURL.RawQuery = query.Encode()

	h.logger.WithFields(logrus.Fields{
		"tenant_id": tenantID,
		"user_id":   session.UserID,
		"client_id": ar.client.ClientID,
	}).Info("authorization code generated successfully")

	c.Redirect(http.StatusFound, redirectURL.String())
}

// authorizationFormData holds the hidden fields that carry an authorization
// request through the login and consent forms
func authorizationFormData(ar *authorizationRequest) gin.H {
	return gin.H{
		"client_id":             ar.ClientID,
		"client_name":           ar.client.Name,
		"redirect_uri":          ar.RedirectURI,
		"scope":                 ar.scope,
		"state":                 ar.State,
		"code_challenge":        ar.CodeChallenge,
		"code_challenge_method": ar.CodeChallengeMethod,
		"nonce":                 ar.Nonce,
		"prompt":                ar.Prompt,
		"response_type":         "code",
	}
}

func (h *OAuthHandler) renderLoginPage(c *gin.Context, tenantID uuid.UUID, ar *authorizationRequest, errorMsg string) {
	data := authorizationFormData(ar)
	if !h.addCSRFToken(c, data) {
		return
	}
	if tenant, err := h.tenantService.GetByID(c.Request.Context(), tenantID); err == nil && tenant != nil {
		data["tenant_info"] = gin.H{"name": tenant.Name}
	}
	if errorMsg != "" {
		data["error"] = errorMsg
	}
	c.HTML(http.StatusOK, "login.html", data)
}

func (h *OAuthHandler) renderConsentPage(c *gin.Context, tenantID uuid.UUID, ar *authorizationRequest, session *models.Session) {
	data := authorizationFormData(ar)
	if !h.addCSRFToken(c, data) {
		return
	}
	if user, err := h.userService.GetByID(c.Request.Context(), tenantID, session.UserID); err == nil && user != nil {
		data["user_email"] = user.Email
	}
	c.HTML(http.StatusOK, "consent.html", data)
}

// addCSRFToken issues a CSRF token: signed value in a hidden form field,
// mirrored in an HttpOnly cookie (double-submit). Returns false after
// rendering an error if the token cannot be generated.
func (h *OAuthHandler) addCSRFToken(c *gin.Context, data gin.H) bool {
	csrfToken, err := newCSRFToken(h.cfg.JWTSecret)
	if err != nil {
		h.logger.WithError(err).Error("failed to generate CSRF token")
		h.renderError(c, "server_error", "Internal server error", "", "")
		return false
	}
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(csrfCookieName, csrfToken, 600, "/oauth", "", h.secureCookies(), true)
	data["csrf_token"] = csrfToken
	return true
}

func (h *OAuthHandler) validCSRF(c *gin.Context) bool {
	cookieToken, _ := c.Cookie(csrfCookieName)
	return validateCSRFToken(h.cfg.JWTSecret, c.PostForm("csrf_token"), cookieToken)
}

func (h *OAuthHandler) secureCookies() bool {
	return strings.HasPrefix(h.cfg.ServerURL, "https://")
}

// currentSession returns the browser's live session for the tenant, or nil
func (h *OAuthHandler) currentSession(c *gin.Context, tenantID uuid.UUID) *models.Session {
	token, err := c.Cookie(sessionCookieName)
	if err != nil || token == "" {
		return nil
	}
	session, err := h.sessionService.GetSession(c.Request.Context(), tenantID, token)
	if err != nil {
		if !errors.Is(err, models.ErrSessionNotFound) {
			h.logger.WithError(err).Error("failed to load session")
		}
		return nil
	}

	// Sessions are ended when an account is suspended or deleted; checking
	// here as well covers status changes made outside the user service
	user, err := h.userService.GetByID(c.Request.Context(), tenantID, session.UserID)
	if err != nil && !errors.Is(err, models.ErrUserNotFound) {
		h.logger.WithError(err).Error("failed to load session user")
		return nil
	}
	if err != nil || user.IsSuspended() {
		h.logger.WithFields(logrus.Fields{
			"tenant_id":  tenantID,
			"user_id":    session.UserID,
			"session_id": session.ID,
		}).Warn("ending session of unavailable user")
		if err := h.sessionService.EndSession(c.Request.Context(), tenantID, token); err != nil {
			h.logger.WithError(err).Error("failed to end session")
		}
		return nil
	}
	return session
}

// setSessionCookie stores the session token. SameSite=Lax keeps the cookie on
// the top-level redirect from a relying party to /oauth/authorize.
func (h *OAuthHandler) setSessionCookie(c *gin.Context, token string) {
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(sessionCookieName, token, int(h.cfg.SessionDuration.Seconds()), "/", "", h.secureCookies(), true)
}

// deleteBrowserSession deletes the session named by the browser's cookie, if any
func (h *OAuthHandler) deleteBrowserSession(c *gin.Context, tenantID uuid.UUID) {
	if token, err := c.Cookie(sessionCookieName); err == nil && token != "" {
		if err := h.sessionService.EndSession(c.Request.Context(), tenantID, token); err != nil {
			h.logger.WithError(err).Error("failed to end session")
		}
	}
}

// endBrowserSession deletes the browser's session and clears its cookie
func (h *OAuthHandler) endBrowserSession(c *gin.Context, tenantID uuid.UUID) {
	h.deleteBrowserSession(c, tenantID)
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(sessionCookieName, "", -1, "/", "", h.secureCookies(), true)
}
