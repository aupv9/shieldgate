package handlers

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"shield1/internal/models"
	"shield1/internal/services"
)

// AuthHandler handles OAuth 2.0 and OpenID Connect endpoints
type AuthHandler struct {
	authService   *services.AuthService
	clientService *services.ClientService
	userService   *services.UserService
}

// NewAuthHandler creates a new AuthHandler instance
func NewAuthHandler(authService *services.AuthService) *AuthHandler {
	return &AuthHandler{
		authService: authService,
	}
}

// SetServices sets additional services (used for dependency injection)
func (h *AuthHandler) SetServices(clientService *services.ClientService, userService *services.UserService) {
	h.clientService = clientService
	h.userService = userService
}

// Authorize handles the OAuth 2.0 authorization endpoint
func (h *AuthHandler) Authorize(c *gin.Context) {
	// Extract parameters
	responseType := c.Query("response_type")
	clientID := c.Query("client_id")
	redirectURI := c.Query("redirect_uri")
	scope := c.Query("scope")
	state := c.Query("state")
	codeChallenge := c.Query("code_challenge")
	codeChallengeMethod := c.Query("code_challenge_method")

	// Validate required parameters
	if responseType != "code" {
		h.redirectWithError(c, redirectURI, "unsupported_response_type", "Only 'code' response type is supported", state)
		return
	}

	if clientID == "" {
		h.redirectWithError(c, redirectURI, "invalid_request", "client_id is required", state)
		return
	}

	if redirectURI == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "redirect_uri is required",
		})
		return
	}

	// Validate client
	client, err := h.clientService.GetClient(clientID)
	if err != nil {
		h.redirectWithError(c, redirectURI, "invalid_client", "Invalid client", state)
		return
	}

	// Validate redirect URI
	if !client.HasRedirectURI(redirectURI) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "Invalid redirect_uri",
		})
		return
	}

	// Validate grant type
	if !client.HasGrantType("authorization_code") {
		h.redirectWithError(c, redirectURI, "unauthorized_client", "Client not authorized for authorization_code grant", state)
		return
	}

	// For PKCE validation (recommended for public clients)
	if client.IsPublic && codeChallenge == "" {
		h.redirectWithError(c, redirectURI, "invalid_request", "code_challenge is required for public clients", state)
		return
	}

	if codeChallenge != "" && codeChallengeMethod == "" {
		codeChallengeMethod = "plain" // Default method
	}

	if codeChallengeMethod != "" && codeChallengeMethod != "S256" && codeChallengeMethod != "plain" {
		h.redirectWithError(c, redirectURI, "invalid_request", "Invalid code_challenge_method", state)
		return
	}

	// Check if user is authenticated (simplified - in real implementation, check session)
	userID := h.getCurrentUserID(c)
	if userID == uuid.Nil {
		// Redirect to login page (simplified - return login form)
		c.HTML(http.StatusOK, "login.html", gin.H{
			"client_id":             clientID,
			"redirect_uri":          redirectURI,
			"scope":                 scope,
			"state":                 state,
			"code_challenge":        codeChallenge,
			"code_challenge_method": codeChallengeMethod,
			"client_name":           client.Name,
		})
		return
	}

	// Generate authorization code
	authCode, err := h.authService.GenerateAuthorizationCode(
		client.ID, userID, redirectURI, scope, codeChallenge, codeChallengeMethod,
	)
	if err != nil {
		logrus.Errorf("Failed to generate authorization code: %v", err)
		h.redirectWithError(c, redirectURI, "server_error", "Internal server error", state)
		return
	}

	// Redirect back to a client with authorization code
	redirectURL, _ := url.Parse(redirectURI)
	query := redirectURL.Query()
	query.Set("code", authCode.Code)
	if state != "" {
		query.Set("state", state)
	}
	redirectURL.RawQuery = query.Encode()

	c.Redirect(http.StatusFound, redirectURL.String())
}

// Token handles the OAuth 2.0 token endpoint
func (h *AuthHandler) Token(c *gin.Context) {
	grantType := c.PostForm("grant_type")

	switch grantType {
	case "authorization_code":
		h.handleAuthorizationCodeGrant(c)
	case "refresh_token":
		h.handleRefreshTokenGrant(c)
	case "client_credentials":
		h.handleClientCredentialsGrant(c)
	default:
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "unsupported_grant_type",
			"error_description": "Grant type not supported",
		})
	}
}

// Introspect handles the OAuth 2.0 token introspection endpoint
func (h *AuthHandler) Introspect(c *gin.Context) {
	token := c.PostForm("token")
	if token == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "token parameter is required",
		})
		return
	}

	// Validate client credentials (simplified)
	clientID := c.PostForm("client_id")
	clientSecret := c.PostForm("client_secret")

	if clientID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "invalid_client",
			"error_description": "Client authentication required",
		})
		return
	}

	// Validate client
	_, err := h.clientService.ValidateClient(clientID, clientSecret)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "invalid_client",
			"error_description": "Invalid client credentials",
		})
		return
	}

	// Introspect token
	response, err := h.authService.IntrospectToken(token)
	if err != nil {
		logrus.Errorf("Failed to introspect token: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "Internal server error",
		})
		return
	}

	c.JSON(http.StatusOK, response)
}

// Revoke handles the OAuth 2.0 token revocation endpoint
func (h *AuthHandler) Revoke(c *gin.Context) {
	token := c.PostForm("token")
	tokenTypeHint := c.PostForm("token_type_hint")

	if token == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "token parameter is required",
		})
		return
	}

	// Validate client credentials (simplified)
	clientID := c.PostForm("client_id")
	clientSecret := c.PostForm("client_secret")

	if clientID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "invalid_client",
			"error_description": "Client authentication required",
		})
		return
	}

	// Validate client
	_, err := h.clientService.ValidateClient(clientID, clientSecret)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "invalid_client",
			"error_description": "Invalid client credentials",
		})
		return
	}

	// Revoke token
	err = h.authService.RevokeToken(token, tokenTypeHint)
	if err != nil {
		logrus.Errorf("Failed to revoke token: %v", err)
		// OAuth 2.0 spec says to return 200 even if token doesn't exist
	}

	c.Status(http.StatusOK)
}

// Discovery handles the OpenID Connect discovery endpoint
func (h *AuthHandler) Discovery(c *gin.Context) {
	baseURL := c.Request.Header.Get("X-Forwarded-Proto")
	if baseURL == "" {
		if c.Request.TLS != nil {
			baseURL = "https"
		} else {
			baseURL = "http"
		}
	}
	baseURL += "://" + c.Request.Host

	config := &models.OpenIDConfiguration{
		Issuer:                           baseURL,
		AuthorizationEndpoint:            baseURL + "/oauth/authorize",
		TokenEndpoint:                    baseURL + "/oauth/token",
		UserInfoEndpoint:                 baseURL + "/userinfo",
		JwksURI:                          baseURL + "/.well-known/jwks.json",
		ResponseTypesSupported:           []string{"code"},
		SubjectTypesSupported:            []string{"public"},
		IDTokenSigningAlgValuesSupported: []string{"HS256"},
		ScopesSupported:                  []string{"openid", "profile", "email"},
		ClaimsSupported:                  []string{"sub", "name", "email", "iat", "exp"},
	}

	c.JSON(http.StatusOK, config)
}

// JWKS handles the JSON Web Key Set endpoint
func (h *AuthHandler) JWKS(c *gin.Context) {
	// In a real implementation, you would return the public keys used to verify JWTs
	// For HMAC (HS256), there are no public keys to expose
	jwks := gin.H{
		"keys": []gin.H{},
	}

	c.JSON(http.StatusOK, jwks)
}

// UserInfo handles the OpenID Connect UserInfo endpoint
func (h *AuthHandler) UserInfo(c *gin.Context) {
	// Get access token from Authorization header
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "invalid_token",
			"error_description": "Access token required",
		})
		return
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || parts[0] != "Bearer" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "invalid_token",
			"error_description": "Invalid token format",
		})
		return
	}

	token := parts[1]

	// Validate access token
	claims, err := h.authService.ValidateAccessToken(token)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "invalid_token",
			"error_description": "Invalid or expired token",
		})
		return
	}

	// Check if token has openid scope
	if !strings.Contains(claims.Scope, "openid") {
		c.JSON(http.StatusForbidden, gin.H{
			"error":             "insufficient_scope",
			"error_description": "Token does not have openid scope",
		})
		return
	}

	// Get user info
	userID, err := uuid.Parse(claims.UserID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "Invalid user ID in token",
		})
		return
	}

	userInfo, err := h.authService.GetUserInfo(userID)
	if err != nil {
		logrus.Errorf("Failed to get user info: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "Failed to get user information",
		})
		return
	}

	c.JSON(http.StatusOK, userInfo)
}

// Helper methods

func (h *AuthHandler) handleAuthorizationCodeGrant(c *gin.Context) {
	code := c.PostForm("code")
	redirectURI := c.PostForm("redirect_uri")
	clientID := c.PostForm("client_id")
	clientSecret := c.PostForm("client_secret")
	codeVerifier := c.PostForm("code_verifier")

	// Validate required parameters
	if code == "" || redirectURI == "" || clientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "Missing required parameters",
		})
		return
	}

	// Validate client
	client, err := h.clientService.ValidateClient(clientID, clientSecret)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "invalid_client",
			"error_description": "Invalid client credentials",
		})
		return
	}

	// Validate authorization code
	authCode, err := h.authService.ValidateAuthorizationCode(code, client.ID.String(), redirectURI, codeVerifier)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_grant",
			"error_description": "Invalid authorization code",
		})
		return
	}

	// Generate tokens
	includeIDToken := strings.Contains(authCode.Scope, "openid")
	tokenResponse, err := h.authService.GenerateTokens(authCode.ClientID, authCode.UserID, authCode.Scope, includeIDToken)
	if err != nil {
		logrus.Errorf("Failed to generate tokens: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "Failed to generate tokens",
		})
		return
	}

	c.JSON(http.StatusOK, tokenResponse)
}

func (h *AuthHandler) handleRefreshTokenGrant(c *gin.Context) {
	refreshToken := c.PostForm("refresh_token")
	clientID := c.PostForm("client_id")
	clientSecret := c.PostForm("client_secret")

	if refreshToken == "" || clientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "Missing required parameters",
		})
		return
	}

	// Validate client
	_, err := h.clientService.ValidateClient(clientID, clientSecret)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "invalid_client",
			"error_description": "Invalid client credentials",
		})
		return
	}

	// Refresh tokens
	tokenResponse, err := h.authService.RefreshAccessToken(refreshToken)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_grant",
			"error_description": "Invalid refresh token",
		})
		return
	}

	c.JSON(http.StatusOK, tokenResponse)
}

func (h *AuthHandler) handleClientCredentialsGrant(c *gin.Context) {
	clientID := c.PostForm("client_id")
	clientSecret := c.PostForm("client_secret")
	scope := c.PostForm("scope")

	if clientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "client_id is required",
		})
		return
	}

	// Validate client
	client, err := h.clientService.ValidateClient(clientID, clientSecret)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "invalid_client",
			"error_description": "Invalid client credentials",
		})
		return
	}

	// Check if client supports client_credentials grant
	if !client.HasGrantType("client_credentials") {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "unauthorized_client",
			"error_description": "Client not authorized for client_credentials grant",
		})
		return
	}

	// For client credentials, there's no user, so use client ID as user ID
	tokenResponse, err := h.authService.GenerateTokens(client.ID, client.ID, scope, false)
	if err != nil {
		logrus.Errorf("Failed to generate tokens: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "Failed to generate tokens",
		})
		return
	}

	// Client credentials flow doesn't return refresh token
	tokenResponse.RefreshToken = ""

	c.JSON(http.StatusOK, tokenResponse)
}

func (h *AuthHandler) redirectWithError(c *gin.Context, redirectURI, errorCode, errorDescription, state string) {
	if redirectURI == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             errorCode,
			"error_description": errorDescription,
		})
		return
	}

	redirectURL, err := url.Parse(redirectURI)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "Invalid redirect_uri",
		})
		return
	}

	query := redirectURL.Query()
	query.Set("error", errorCode)
	query.Set("error_description", errorDescription)
	if state != "" {
		query.Set("state", state)
	}
	redirectURL.RawQuery = query.Encode()

	c.Redirect(http.StatusFound, redirectURL.String())
}

func (h *AuthHandler) getCurrentUserID(c *gin.Context) uuid.UUID {
	// Simplified user authentication check
	// In a real implementation, you would check session, JWT, etc.

	// Check if there's a user_id in the session or context
	if userIDStr, exists := c.Get("user_id"); exists {
		if userID, err := uuid.Parse(userIDStr.(string)); err == nil {
			return userID
		}
	}

	// Check for basic authentication for testing purposes
	username, password, hasAuth := c.Request.BasicAuth()
	if hasAuth {
		user, err := h.userService.AuthenticateUser(username, password)
		if err == nil {
			c.Set("user_id", user.ID.String())
			return user.ID
		}
	}

	return uuid.Nil
}
