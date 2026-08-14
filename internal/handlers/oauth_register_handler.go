package handlers

// oauth_register_handler.go implements Dynamic Client Registration (RFC 7591).
// The endpoint is protected: callers must present a valid management access
// token (the RFC's "initial access token").

import (
	"net/http"
	"strings"
	"time"

	"shieldgate/internal/middleware"
	"shieldgate/internal/models"

	"github.com/gin-gonic/gin"
)

// clientRegistrationRequest carries RFC 7591 client metadata
type clientRegistrationRequest struct {
	ClientName              string   `json:"client_name" binding:"required"`
	RedirectURIs            []string `json:"redirect_uris" binding:"required"`
	GrantTypes              []string `json:"grant_types"`
	Scope                   string   `json:"scope"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
}

// clientRegistrationResponse echoes the registered metadata (RFC 7591 §3.2.1)
type clientRegistrationResponse struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret,omitempty"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at"`
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	Scope                   string   `json:"scope"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
}

// HandleRegisterClient handles POST /oauth/register
func (h *OAuthHandler) HandleRegisterClient(c *gin.Context) {
	tenantID, err := middleware.GetTenantID(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "Tenant context required",
		})
		return
	}

	var req clientRegistrationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_client_metadata",
			"error_description": err.Error(),
		})
		return
	}

	grantTypes := req.GrantTypes
	if len(grantTypes) == 0 {
		grantTypes = []string{"authorization_code"} // RFC 7591 §2 default
	}

	// token_endpoint_auth_method: "none" registers a public client
	isPublic := req.TokenEndpointAuthMethod == "none"

	client, err := h.clientService.Create(c.Request.Context(), tenantID, &models.CreateClientRequest{
		Name:         req.ClientName,
		RedirectURIs: req.RedirectURIs,
		GrantTypes:   grantTypes,
		Scopes:       strings.Fields(req.Scope),
		IsPublic:     isPublic,
	})
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_client_metadata",
			"error_description": err.Error(),
		})
		return
	}

	authMethod := "client_secret_basic"
	if isPublic {
		authMethod = "none"
	}

	c.JSON(http.StatusCreated, clientRegistrationResponse{
		ClientID:                client.ClientID,
		ClientSecret:            client.PlainClientSecret,
		ClientIDIssuedAt:        time.Now().Unix(),
		ClientName:              client.Name,
		RedirectURIs:            client.RedirectURIs,
		GrantTypes:              client.GrantTypes,
		Scope:                   strings.Join(client.Scopes, " "),
		TokenEndpointAuthMethod: authMethod,
	})
}
