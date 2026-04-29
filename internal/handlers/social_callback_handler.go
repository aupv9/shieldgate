package handlers

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"shieldgate/config"
	"shieldgate/internal/models"
	"shieldgate/internal/services"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// providerMeta holds OAuth2 endpoint URLs for a known provider.
type providerMeta struct {
	tokenURL    string
	userInfoURL string
}

var knownProviders = map[string]providerMeta{
	"google": {
		tokenURL:    "https://oauth2.googleapis.com/token",
		userInfoURL: "https://openidconnect.googleapis.com/v1/userinfo",
	},
	"github": {
		tokenURL:    "https://github.com/login/oauth/access_token",
		userInfoURL: "https://api.github.com/user",
	},
	"facebook": {
		tokenURL:    "https://graph.facebook.com/v18.0/oauth/access_token",
		userInfoURL: "https://graph.facebook.com/me?fields=id,name,email,picture",
	},
}

// SocialCallbackHandler handles the OAuth2 authorize redirect and provider callback.
type SocialCallbackHandler struct {
	social  services.SocialLoginService
	session services.SessionService
	cfg     *config.Config
	logger  *logrus.Logger
}

// NewSocialCallbackHandler creates a new SocialCallbackHandler.
func NewSocialCallbackHandler(
	social services.SocialLoginService,
	session services.SessionService,
	cfg *config.Config,
	logger *logrus.Logger,
) *SocialCallbackHandler {
	return &SocialCallbackHandler{social: social, session: session, cfg: cfg, logger: logger}
}

// RegisterRoutes attaches social callback routes to the bare (unauthenticated) router.
func (h *SocialCallbackHandler) RegisterRoutes(rg *gin.RouterGroup) {
	rg.GET("/:provider/authorize", h.Authorize)
	rg.GET("/:provider/callback", h.Callback)
}

// Authorize redirects the user to the provider's OAuth2 authorization page.
// GET /oauth/social/:provider/authorize?tenant_id=...&return_url=...
func (h *SocialCallbackHandler) Authorize(c *gin.Context) {
	provider := strings.ToLower(c.Param("provider"))
	meta, ok := knownProviders[provider]
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported provider", "code": models.ErrorCodeInvalidRequest})
		return
	}
	_ = meta

	tenantID, err := uuid.Parse(c.Query("tenant_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant_id required", "code": models.ErrorCodeInvalidRequest})
		return
	}

	providerCfg, err := h.social.GetProvider(c.Request.Context(), tenantID, provider)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "provider not configured", "code": models.ErrorCodeResourceNotFound})
		return
	}

	csrfToken, err := generateToken(16)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error", "code": models.ErrorCodeInternalError})
		return
	}

	statePayload := fmt.Sprintf("%s|%s|%s", csrfToken, tenantID.String(), c.Query("return_url"))
	stateEncoded := url.QueryEscape(statePayload)

	callbackURL := fmt.Sprintf("%s/oauth/social/%s/callback", h.cfg.ServerURL, provider)
	scopes := strings.Join(providerCfg.Scopes, " ")

	authURL := buildAuthURL(provider, providerCfg.ClientID, callbackURL, scopes, stateEncoded)
	c.Redirect(http.StatusFound, authURL)
}

// Callback handles the OAuth2 provider redirect, exchanges the code, and issues a token.
// GET /oauth/social/:provider/callback?code=...&state=...
func (h *SocialCallbackHandler) Callback(c *gin.Context) {
	provider := strings.ToLower(c.Param("provider"))

	var req models.SocialCallbackRequest
	if err := c.ShouldBindQuery(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error(), "code": models.ErrorCodeInvalidRequest})
		return
	}

	if req.Error != "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             req.Error,
			"error_description": req.ErrorDescription,
			"code":              models.ErrorCodeUnauthorized,
		})
		return
	}

	if req.Code == "" || req.State == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "code and state required", "code": models.ErrorCodeInvalidRequest})
		return
	}

	// Parse state: csrfToken|tenantID|returnURL
	stateParts := strings.SplitN(req.State, "|", 3)
	if len(stateParts) < 2 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid state", "code": models.ErrorCodeInvalidRequest})
		return
	}
	tenantID, err := uuid.Parse(stateParts[1])
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid tenant in state", "code": models.ErrorCodeInvalidRequest})
		return
	}
	returnURL := ""
	if len(stateParts) == 3 {
		returnURL = stateParts[2]
	}

	providerCfg, err := h.social.GetProvider(c.Request.Context(), tenantID, provider)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "provider not configured", "code": models.ErrorCodeResourceNotFound})
		return
	}

	callbackURL := fmt.Sprintf("%s/oauth/social/%s/callback", h.cfg.ServerURL, provider)
	accessToken, err := exchangeCode(c.Request.Context(), provider, req.Code, providerCfg.ClientID, providerCfg.ClientSecret, callbackURL)
	if err != nil {
		h.logger.WithError(err).Error("social code exchange failed")
		c.JSON(http.StatusBadGateway, gin.H{"error": "failed to exchange code with provider", "code": models.ErrorCodeInternalError})
		return
	}

	socialUser, err := fetchUserInfo(c.Request.Context(), provider, accessToken)
	if err != nil {
		h.logger.WithError(err).Error("social user info fetch failed")
		c.JSON(http.StatusBadGateway, gin.H{"error": "failed to fetch user info from provider", "code": models.ErrorCodeInternalError})
		return
	}

	account := &models.SocialAccount{
		TenantID:    tenantID,
		Provider:    provider,
		ExternalID:  socialUser.ID,
		Email:       socialUser.Email,
		Name:        socialUser.Name,
		Avatar:      socialUser.Avatar,
		AccessToken: accessToken,
	}

	user, err := h.social.FindOrCreateUser(c.Request.Context(), tenantID, account)
	if err != nil {
		h.logger.WithError(err).Error("social find-or-create user failed")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to authenticate user", "code": models.ErrorCodeInternalError})
		return
	}

	sessionID := uuid.New().String()
	expiresAt := time.Now().Add(24 * time.Hour)
	_, _ = h.session.Create(c.Request.Context(), tenantID, user.ID, sessionID, c.ClientIP(), c.Request.UserAgent(), provider+" login", expiresAt)

	if returnURL != "" {
		redirectTarget := fmt.Sprintf("%s?session_id=%s&provider=%s", returnURL, sessionID, provider)
		c.Redirect(http.StatusFound, redirectTarget)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"session_id":  sessionID,
		"user_id":     user.ID,
		"tenant_id":   tenantID,
		"provider":    provider,
		"expires_at":  expiresAt,
	})
}

// ──────────────────────────────── helpers ────────────────────────────────────

func generateToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func buildAuthURL(provider, clientID, redirectURI, scope, state string) string {
	params := url.Values{}
	params.Set("client_id", clientID)
	params.Set("redirect_uri", redirectURI)
	params.Set("scope", scope)
	params.Set("state", state)
	params.Set("response_type", "code")

	switch provider {
	case "github":
		return "https://github.com/login/oauth/authorize?" + params.Encode()
	case "facebook":
		return "https://www.facebook.com/v18.0/dialog/oauth?" + params.Encode()
	default: // google and others
		params.Set("access_type", "offline")
		return "https://accounts.google.com/o/oauth2/v2/auth?" + params.Encode()
	}
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
}

func exchangeCode(ctx context.Context, provider, code, clientID, clientSecret, redirectURI string) (string, error) {
	meta, ok := knownProviders[provider]
	if !ok {
		return "", fmt.Errorf("unsupported provider: %s", provider)
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	form.Set("redirect_uri", redirectURI)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, meta.tokenURL, bytes.NewBufferString(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("provider returned %d: %s", resp.StatusCode, string(body))
	}

	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return "", fmt.Errorf("parse token response: %w", err)
	}
	return tr.AccessToken, nil
}

type externalUser struct {
	ID     string
	Email  string
	Name   string
	Avatar string
}

func fetchUserInfo(ctx context.Context, provider, accessToken string) (*externalUser, error) {
	meta, ok := knownProviders[provider]
	if !ok {
		return nil, fmt.Errorf("unsupported provider: %s", provider)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, meta.userInfoURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("provider returned %d: %s", resp.StatusCode, string(body))
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("parse userinfo: %w", err)
	}
	return parseProviderUser(provider, raw), nil
}

func parseProviderUser(provider string, raw map[string]interface{}) *externalUser {
	u := &externalUser{}
	getString := func(key string) string {
		if v, ok := raw[key]; ok {
			if s, ok := v.(string); ok {
				return s
			}
			return fmt.Sprintf("%v", v)
		}
		return ""
	}
	getFloat := func(key string) string {
		if v, ok := raw[key]; ok {
			return fmt.Sprintf("%.0f", v)
		}
		return ""
	}

	switch provider {
	case "github":
		if id := getFloat("id"); id != "" {
			u.ID = id
		} else {
			u.ID = getString("login")
		}
		u.Email = getString("email")
		u.Name = getString("name")
		u.Avatar = getString("avatar_url")
	case "facebook":
		u.ID = getString("id")
		u.Email = getString("email")
		u.Name = getString("name")
		if pic, ok := raw["picture"].(map[string]interface{}); ok {
			if data, ok := pic["data"].(map[string]interface{}); ok {
				u.Avatar = getString("url")
				_ = data
			}
		}
	default: // google / OIDC
		u.ID = getString("sub")
		u.Email = getString("email")
		u.Name = getString("name")
		u.Avatar = getString("picture")
	}
	return u
}

