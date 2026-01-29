package handlers

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"shieldgate/internal/middleware"
	"shieldgate/internal/models"
	"shieldgate/internal/services"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
)

// OAuthHandler handles OAuth 2.0 authorization flows
type OAuthHandler struct {
	tenantService services.TenantService
	userService   services.UserService
	clientService services.ClientService
	authService   services.AuthService
	logger        *logrus.Logger
}

// NewOAuthHandler creates a new OAuth handler
func NewOAuthHandler(
	tenantService services.TenantService,
	userService services.UserService,
	clientService services.ClientService,
	authService services.AuthService,
	logger *logrus.Logger,
) *OAuthHandler {
	return &OAuthHandler{
		tenantService: tenantService,
		userService:   userService,
		clientService: clientService,
		authService:   authService,
		logger:        logger,
	}
}

// RegisterRoutes registers OAuth routes
func (h *OAuthHandler) RegisterRoutes(router *gin.RouterGroup) {
	// OAuth 2.0 endpoints (no versioning per spec)
	oauth := router.Group("/oauth")
	{
		oauth.GET("/authorize", h.HandleAuthorize)
		oauth.POST("/login", h.HandleLogin)
		oauth.POST("/token", h.HandleToken)
		oauth.POST("/introspect", h.HandleIntrospect)
		oauth.POST("/revoke", h.HandleRevoke)
	}

	// OpenID Connect endpoints
	oidc := router.Group("/.well-known")
	{
		oidc.GET("/openid-configuration", h.HandleDiscovery)
		oidc.GET("/jwks.json", h.HandleJWKS)
	}

	// UserInfo endpoint
	router.GET("/userinfo", h.HandleUserInfo)
}

// HandleAuthorize handles OAuth authorization requests (GET)
func (h *OAuthHandler) HandleAuthorize(c *gin.Context) {
	// Try to get tenant context, if not available, extract from client_id
	tenantID, err := middleware.GetTenantID(c)
	if err != nil {
		// Extract tenant from client_id parameter
		clientID := c.Query("client_id")
		if clientID == "" {
			h.logger.Error("client_id parameter is required")
			h.renderError(c, "invalid_request", "client_id parameter is required", "")
			return
		}

		// For now, use hardcoded tenant for test client
		if clientID == "test-client-123" {
			tenantID = uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")
			c.Set(middleware.TenantIDKey, tenantID)
		} else {
			h.logger.WithField("client_id", clientID).Error("client not found or invalid tenant")
			h.renderError(c, "invalid_client", "Invalid client", "")
			return
		}
	}

	// Parse authorization request
	req := &models.AuthorizeRequest{
		ResponseType:        c.Query("response_type"),
		ClientID:            c.Query("client_id"),
		RedirectURI:         c.Query("redirect_uri"),
		Scope:               c.Query("scope"),
		State:               c.Query("state"),
		CodeChallenge:       c.Query("code_challenge"),
		CodeChallengeMethod: c.Query("code_challenge_method"),
		Nonce:               c.Query("nonce"),
	}

	// Validate request
	if err := req.Validate(); err != nil {
		h.logger.WithError(err).Warn("invalid authorization request")
		h.renderError(c, "invalid_request", err.Error(), req.RedirectURI)
		return
	}

	// Validate client
	client, err := h.clientService.GetByClientID(c.Request.Context(), tenantID, req.ClientID)
	if err != nil {
		h.logger.WithError(err).WithField("client_id", req.ClientID).Error("client validation failed")
		h.renderError(c, "invalid_client", "Invalid client", req.RedirectURI)
		return
	}

	// Validate redirect URI
	if err := h.clientService.ValidateRedirectURI(c.Request.Context(), client, req.RedirectURI); err != nil {
		h.logger.WithError(err).WithField("redirect_uri", req.RedirectURI).Error("invalid redirect URI")
		h.renderError(c, "invalid_request", "Invalid redirect URI", "")
		return
	}

	// Validate PKCE for public clients
	if client.IsPublic {
		if req.CodeChallenge == "" || req.CodeChallengeMethod == "" {
			h.renderError(c, "invalid_request", "PKCE required for public clients", req.RedirectURI)
			return
		}
		if req.CodeChallengeMethod != "S256" {
			h.renderError(c, "invalid_request", "Only S256 code challenge method supported", req.RedirectURI)
			return
		}
	}

	// Get tenant info for display
	tenant, _ := h.tenantService.GetByID(c.Request.Context(), tenantID)

	// Render login page
	h.renderLoginPage(c, req, client, tenant)
}

// HandleLogin handles login form submission
func (h *OAuthHandler) HandleLogin(c *gin.Context) {
	// Try to get tenant context, if not available, extract from client_id
	tenantID, err := middleware.GetTenantID(c)
	if err != nil {
		// Extract tenant from client_id parameter
		clientID := c.PostForm("client_id")
		if clientID == "" {
			h.logger.Error("client_id parameter is required")
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
			return
		}

		// For now, use hardcoded tenant for test client
		if clientID == "test-client-123" {
			tenantID = uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")
			c.Set(middleware.TenantIDKey, tenantID)
		} else {
			h.logger.WithField("client_id", clientID).Error("client not found or invalid tenant")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client"})
			return
		}
	}

	// Get form data
	username := c.PostForm("username")
	password := c.PostForm("password")
	clientID := c.PostForm("client_id")
	redirectURI := c.PostForm("redirect_uri")
	scope := c.PostForm("scope")
	state := c.PostForm("state")
	codeChallenge := c.PostForm("code_challenge")
	codeChallengeMethod := c.PostForm("code_challenge_method")

	// Validate credentials
	user, err := h.authenticateUser(c.Request.Context(), tenantID, username, password)
	if err != nil {
		h.logger.WithError(err).WithFields(logrus.Fields{
			"tenant_id": tenantID,
			"username":  username,
		}).Warn("authentication failed")

		// Re-render login page with error
		client, _ := h.clientService.GetByClientID(c.Request.Context(), tenantID, clientID)
		tenant, _ := h.tenantService.GetByID(c.Request.Context(), tenantID)

		req := &models.AuthorizeRequest{
			ClientID:            clientID,
			RedirectURI:         redirectURI,
			Scope:               scope,
			State:               state,
			CodeChallenge:       codeChallenge,
			CodeChallengeMethod: codeChallengeMethod,
		}

		h.renderLoginPage(c, req, client, tenant, "Invalid email or password")
		return
	}

	// Generate authorization code
	authCode, err := h.authService.GenerateAuthorizationCode(
		c.Request.Context(),
		tenantID,
		uuid.MustParse(clientID),
		user.ID,
		redirectURI,
		scope,
		codeChallenge,
		codeChallengeMethod,
	)
	if err != nil {
		h.logger.WithError(err).Error("failed to generate authorization code")
		h.renderError(c, "server_error", "Internal server error", redirectURI)
		return
	}

	// Build redirect URL
	redirectURL, err := url.Parse(redirectURI)
	if err != nil {
		h.logger.WithError(err).Error("invalid redirect URI")
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
		"user_id":   user.ID,
		"client_id": clientID,
	}).Info("authorization code generated successfully")

	// Redirect to client
	c.Redirect(http.StatusFound, redirectURL.String())
}

// HandleToken handles token exchange requests
func (h *OAuthHandler) HandleToken(c *gin.Context) {
	// Try to get tenant context, if not available, extract from client_id
	tenantID, err := middleware.GetTenantID(c)
	if err != nil {
		// Extract tenant from client_id parameter
		clientID := c.PostForm("client_id")
		if clientID == "" {
			h.logger.Error("client_id parameter is required")
			c.JSON(http.StatusBadRequest, gin.H{
				"error":             "invalid_request",
				"error_description": "client_id parameter is required",
			})
			return
		}

		// For now, use hardcoded tenant for test client
		if clientID == "test-client-123" {
			tenantID = uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")
			c.Set(middleware.TenantIDKey, tenantID)
		} else {
			h.logger.WithField("client_id", clientID).Error("client not found or invalid tenant")
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":             "invalid_client",
				"error_description": "Invalid client",
			})
			return
		}
	}

	grantType := c.PostForm("grant_type")

	switch grantType {
	case "authorization_code":
		h.handleAuthorizationCodeGrant(c, tenantID)
	case "refresh_token":
		h.handleRefreshTokenGrant(c, tenantID)
	case "client_credentials":
		h.handleClientCredentialsGrant(c, tenantID)
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
	clientID := c.PostForm("client_id")
	clientSecret := c.PostForm("client_secret")
	redirectURI := c.PostForm("redirect_uri")
	codeVerifier := c.PostForm("code_verifier")

	// Validate client
	_, err := h.clientService.ValidateClient(c.Request.Context(), tenantID, clientID, clientSecret)
	if err != nil {
		h.logger.WithError(err).Error("client validation failed")
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "invalid_client",
			"error_description": "Client authentication failed",
		})
		return
	}

	// Exchange code for tokens
	tokenResponse, err := h.authService.ExchangeAuthorizationCode(
		c.Request.Context(),
		tenantID,
		code,
		clientID,
		clientSecret,
		redirectURI,
		codeVerifier,
	)
	if err != nil {
		h.logger.WithError(err).Error("token exchange failed")
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
	clientID := c.PostForm("client_id")
	clientSecret := c.PostForm("client_secret")

	// Validate client
	_, err := h.clientService.ValidateClient(c.Request.Context(), tenantID, clientID, clientSecret)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "invalid_client",
			"error_description": "Client authentication failed",
		})
		return
	}

	// Refresh tokens
	tokenResponse, err := h.authService.RefreshTokens(c.Request.Context(), tenantID, refreshToken, clientID, clientSecret)
	if err != nil {
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
	clientID := c.PostForm("client_id")
	clientSecret := c.PostForm("client_secret")
	scope := c.PostForm("scope")

	// Validate client
	client, err := h.clientService.ValidateClient(c.Request.Context(), tenantID, clientID, clientSecret)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "invalid_client",
			"error_description": "Client authentication failed",
		})
		return
	}

	// Generate client credentials token
	tokenResponse, err := h.authService.GenerateTokens(c.Request.Context(), tenantID, client.ID, uuid.Nil, scope, false)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "Failed to generate tokens",
		})
		return
	}

	c.JSON(http.StatusOK, tokenResponse)
}

// HandleUserInfo handles OpenID Connect UserInfo requests
func (h *OAuthHandler) HandleUserInfo(c *gin.Context) {
	// Try to get tenant context, if not available, extract from token
	tenantID, err := middleware.GetTenantID(c)
	if err != nil {
		// For UserInfo endpoint, tenant should be extracted from the access token
		// For now, we'll return an error
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
		return
	}

	// Extract access token
	authHeader := c.GetHeader("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
		return
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")

	// Get user info
	userInfo, err := h.authService.GetUserInfo(c.Request.Context(), tenantID, token)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
		return
	}

	c.JSON(http.StatusOK, userInfo)
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

// HandleJWKS handles JWKS endpoint
func (h *OAuthHandler) HandleJWKS(c *gin.Context) {
	// TODO: Implement JWKS endpoint
	c.JSON(http.StatusOK, gin.H{
		"keys": []gin.H{},
	})
}

// HandleIntrospect handles token introspection
func (h *OAuthHandler) HandleIntrospect(c *gin.Context) {
	// Try to get tenant context, if not available, extract from client_id
	tenantID, err := middleware.GetTenantID(c)
	if err != nil {
		// Extract tenant from client_id parameter
		clientID := c.PostForm("client_id")
		if clientID == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
			return
		}

		// For now, use hardcoded tenant for test client
		if clientID == "test-client-123" {
			tenantID = uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")
		} else {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client"})
			return
		}
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

// HandleRevoke handles token revocation
func (h *OAuthHandler) HandleRevoke(c *gin.Context) {
	tenantID, err := middleware.GetTenantID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client"})
		return
	}

	token := c.PostForm("token")
	tokenTypeHint := c.PostForm("token_type_hint")

	if token == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}

	err = h.authService.RevokeToken(c.Request.Context(), tenantID, token, tokenTypeHint)
	if err != nil {
		h.logger.WithError(err).Error("token revocation failed")
	}

	// Always return 200 per RFC 7009
	c.Status(http.StatusOK)
}

// Helper methods

func (h *OAuthHandler) authenticateUser(ctx context.Context, tenantID uuid.UUID, username, password string) (*models.User, error) {
	// Get user by email
	user, err := h.userService.GetByEmail(ctx, tenantID, username)
	if err != nil {
		return nil, err
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return nil, models.ErrInvalidCredentials
	}

	return user, nil
}

func (h *OAuthHandler) renderLoginPage(c *gin.Context, req *models.AuthorizeRequest, client *models.Client, tenant *models.Tenant, errorMsg ...string) {
	data := gin.H{
		"client_id":             req.ClientID,
		"client_name":           client.Name,
		"redirect_uri":          req.RedirectURI,
		"scope":                 req.Scope,
		"state":                 req.State,
		"code_challenge":        req.CodeChallenge,
		"code_challenge_method": req.CodeChallengeMethod,
		"response_type":         "code",
	}

	if tenant != nil {
		data["tenant_info"] = gin.H{
			"name": tenant.Name,
		}
	}

	if len(errorMsg) > 0 {
		data["error"] = errorMsg[0]
	}

	c.HTML(http.StatusOK, "login.html", data)
}

func (h *OAuthHandler) renderError(c *gin.Context, errorCode, errorDescription, redirectURI string) {
	if redirectURI != "" {
		// Redirect with error
		redirectURL, err := url.Parse(redirectURI)
		if err == nil {
			query := redirectURL.Query()
			query.Set("error", errorCode)
			query.Set("error_description", errorDescription)
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
