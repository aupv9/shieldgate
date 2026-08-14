package handlers

// oauth_device_handler.go implements the HTTP layer of the Device
// Authorization Grant (RFC 8628): the device_authorization endpoint the
// device calls, and the verification page where the user enters the code.

import (
	"net/http"
	"strings"

	"shieldgate/internal/middleware"
	"shieldgate/internal/models"
	"shieldgate/internal/services"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// HandleDeviceAuthorization handles POST /oauth/device_authorization
func (h *OAuthHandler) HandleDeviceAuthorization(c *gin.Context) {
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

	if !client.HasGrantType(models.GrantTypeDeviceCode) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "unauthorized_client",
			"error_description": "Client is not authorized for the device_code grant",
		})
		return
	}

	grantedScope, err := services.ValidateScopeForClient(client, c.PostForm("scope"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_scope",
			"error_description": "Requested scope is not allowed for this client",
		})
		return
	}

	response, err := h.authService.CreateDeviceAuthorization(c.Request.Context(), tenantID, client, grantedScope)
	if err != nil {
		h.logger.WithError(err).Error("failed to create device authorization")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "Failed to start device authorization",
		})
		return
	}

	c.JSON(http.StatusOK, response)
}

// handleDeviceCodeGrant handles grant_type=urn:ietf:params:oauth:grant-type:device_code
// on the token endpoint (device polling, RFC 8628 §3.4-3.5)
func (h *OAuthHandler) handleDeviceCodeGrant(c *gin.Context, tenantID uuid.UUID) {
	deviceCode := c.PostForm("device_code")
	if deviceCode == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "device_code is required",
		})
		return
	}

	client, ok := h.authenticateClient(c, tenantID)
	if !ok {
		return
	}

	if !client.HasGrantType(models.GrantTypeDeviceCode) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "unauthorized_client",
			"error_description": "Client is not authorized for the device_code grant",
		})
		return
	}

	tokenResponse, err := h.authService.ExchangeDeviceCode(c.Request.Context(), tenantID, client, deviceCode)
	if err != nil {
		// RFC 8628 §3.5 error codes — the device keys its polling loop off these
		switch err {
		case models.ErrAuthorizationPending:
			c.JSON(http.StatusBadRequest, gin.H{"error": "authorization_pending"})
		case models.ErrSlowDown:
			c.JSON(http.StatusBadRequest, gin.H{"error": "slow_down"})
		case models.ErrExpiredDeviceCode:
			c.JSON(http.StatusBadRequest, gin.H{"error": "expired_token"})
		case models.ErrDeviceAccessDenied:
			c.JSON(http.StatusBadRequest, gin.H{"error": "access_denied"})
		default:
			c.JSON(http.StatusBadRequest, gin.H{
				"error":             "invalid_grant",
				"error_description": "Device code is invalid",
			})
		}
		return
	}

	c.JSON(http.StatusOK, tokenResponse)
}

// handleTokenExchangeGrant handles grant_type=urn:ietf:params:oauth:grant-type:token-exchange
// (RFC 8693). Restricted to confidential clients.
func (h *OAuthHandler) handleTokenExchangeGrant(c *gin.Context, tenantID uuid.UUID) {
	client, ok := h.authenticateClient(c, tenantID)
	if !ok {
		return
	}

	// Delegation is sensitive: only clients that can actually authenticate
	// themselves may exchange tokens
	if client.IsPublic {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "invalid_client",
			"error_description": "Token exchange requires a confidential client",
		})
		return
	}

	if !client.HasGrantType(models.GrantTypeTokenExchange) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "unauthorized_client",
			"error_description": "Client is not authorized for the token-exchange grant",
		})
		return
	}

	subjectToken := c.PostForm("subject_token")
	subjectTokenType := c.PostForm("subject_token_type")
	requestedTokenType := c.PostForm("requested_token_type")
	requestedScope := c.PostForm("scope")

	if subjectToken == "" || subjectTokenType == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "subject_token and subject_token_type are required",
		})
		return
	}
	if requestedTokenType != "" && requestedTokenType != models.TokenTypeAccessToken {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "Only access tokens can be issued by this server",
		})
		return
	}

	response, err := h.authService.ExchangeToken(c.Request.Context(), tenantID, client, subjectToken, subjectTokenType, requestedScope)
	if err != nil {
		if err == models.ErrInvalidScope {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":             "invalid_scope",
				"error_description": "Requested scope exceeds the subject token or client registration",
			})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_grant",
			"error_description": "Subject token is invalid or expired",
		})
		return
	}

	c.JSON(http.StatusOK, response)
}

// HandleDeviceVerificationPage handles GET /oauth/device — the page where the
// user types the code shown on their device
func (h *OAuthHandler) HandleDeviceVerificationPage(c *gin.Context) {
	tenantID, err := middleware.GetTenantID(c)
	if err != nil {
		h.renderError(c, "invalid_request", "Tenant context required — provide X-Tenant-ID header", "")
		return
	}

	tenant, _ := h.tenantService.GetByID(c.Request.Context(), tenantID)
	h.renderDevicePage(c, tenant, c.Query("user_code"), "", "")
}

// HandleDeviceVerification handles POST /oauth/device — the user authenticates
// and approves or denies the device
func (h *OAuthHandler) HandleDeviceVerification(c *gin.Context) {
	tenantID, err := middleware.GetTenantID(c)
	if err != nil {
		h.renderError(c, "invalid_request", "Tenant context required — provide X-Tenant-ID header", "")
		return
	}

	tenant, _ := h.tenantService.GetByID(c.Request.Context(), tenantID)
	userCode := c.PostForm("user_code")

	// CSRF protection, same double-submit scheme as the login form
	cookieToken, _ := c.Cookie(csrfCookieName)
	if !validateCSRFToken(h.cfg.JWTSecret, c.PostForm("csrf_token"), cookieToken) {
		h.logger.WithField("tenant_id", tenantID).Warn("CSRF validation failed on device verification")
		h.renderDevicePage(c, tenant, userCode, "Invalid or missing CSRF token — please reload the page", "")
		return
	}

	if strings.TrimSpace(userCode) == "" {
		h.renderDevicePage(c, tenant, "", "Please enter the code shown on your device", "")
		return
	}

	// Authenticate the user
	user, err := h.userService.Authenticate(c.Request.Context(), tenantID, c.PostForm("username"), c.PostForm("password"))
	if err != nil {
		h.logger.WithError(err).WithField("tenant_id", tenantID).Warn("authentication failed on device verification")
		h.renderDevicePage(c, tenant, userCode, "Invalid email or password", "")
		return
	}

	// Apply the decision
	if c.PostForm("action") == "deny" {
		err = h.authService.DenyDeviceCode(c.Request.Context(), tenantID, userCode)
	} else {
		err = h.authService.ApproveDeviceCode(c.Request.Context(), tenantID, userCode, user.ID)
	}
	if err != nil {
		message := "Code not found — check the code and try again"
		if err == models.ErrExpiredDeviceCode {
			message = "This code has expired — request a new one on your device"
		}
		h.renderDevicePage(c, tenant, userCode, message, "")
		return
	}

	result := "Device approved — you can return to your device now"
	if c.PostForm("action") == "deny" {
		result = "Device denied — the sign-in request was rejected"
	}

	h.logger.WithFields(logrus.Fields{
		"tenant_id": tenantID,
		"user_id":   user.ID,
		"action":    c.PostForm("action"),
	}).Info("device verification completed")

	h.renderDevicePage(c, tenant, "", "", result)
}

func (h *OAuthHandler) renderDevicePage(c *gin.Context, tenant *models.Tenant, userCode, errorMsg, resultMsg string) {
	csrfToken, err := newCSRFToken(h.cfg.JWTSecret)
	if err != nil {
		h.logger.WithError(err).Error("failed to generate CSRF token")
		h.renderError(c, "server_error", "Internal server error", "")
		return
	}
	secureCookie := strings.HasPrefix(h.cfg.ServerURL, "https://")
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(csrfCookieName, csrfToken, 600, "/oauth", "", secureCookie, true)

	data := gin.H{
		"user_code":  userCode,
		"csrf_token": csrfToken,
	}
	if tenant != nil {
		data["tenant_info"] = gin.H{"name": tenant.Name}
	}
	if errorMsg != "" {
		data["error"] = errorMsg
	}
	if resultMsg != "" {
		data["result"] = resultMsg
	}

	c.HTML(http.StatusOK, "device.html", data)
}
