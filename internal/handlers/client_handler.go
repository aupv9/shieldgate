package handlers

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"

	"shield1/internal/models"
	"shield1/internal/services"
)

// ClientHandler handles client management endpoints
type ClientHandler struct {
	clientService *services.ClientService
}

// NewClientHandler creates a new ClientHandler instance
func NewClientHandler(clientService *services.ClientService) *ClientHandler {
	return &ClientHandler{
		clientService: clientService,
	}
}

// CreateClient handles POST /clients
func (h *ClientHandler) CreateClient(c *gin.Context) {
	var req models.CreateClientRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "Invalid request body",
			"details":           err.Error(),
		})
		return
	}

	// Validate request
	if err := h.validateCreateClientRequest(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": err.Error(),
		})
		return
	}

	// Create client
	client, err := h.clientService.CreateClient(&req)
	if err != nil {
		logrus.Errorf("Failed to create client: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "Failed to create client",
		})
		return
	}

	// Don't expose client secret in response for security
	response := *client
	if !req.IsPublic {
		// For confidential clients, show the secret only once during creation
		// In production, you might want to hash this or handle it differently
	}

	c.JSON(http.StatusCreated, response)
}

// GetClient handles GET /clients/:client_id
func (h *ClientHandler) GetClient(c *gin.Context) {
	clientID := c.Param("client_id")
	if clientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "client_id is required",
		})
		return
	}

	client, err := h.clientService.GetClient(clientID)
	if err != nil {
		if err.Error() == "client not found" {
			c.JSON(http.StatusNotFound, gin.H{
				"error":             "not_found",
				"error_description": "Client not found",
			})
			return
		}
		logrus.Errorf("Failed to get client: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "Failed to get client",
		})
		return
	}

	// Don't expose client secret
	client.ClientSecret = ""
	c.JSON(http.StatusOK, client)
}

// UpdateClient handles PUT /clients/:client_id
func (h *ClientHandler) UpdateClient(c *gin.Context) {
	clientID := c.Param("client_id")
	if clientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "client_id is required",
		})
		return
	}

	var req models.UpdateClientRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "Invalid request body",
			"details":           err.Error(),
		})
		return
	}

	// Validate request
	if err := h.validateUpdateClientRequest(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": err.Error(),
		})
		return
	}

	// Update client
	client, err := h.clientService.UpdateClient(clientID, &req)
	if err != nil {
		if err.Error() == "client not found" {
			c.JSON(http.StatusNotFound, gin.H{
				"error":             "not_found",
				"error_description": "Client not found",
			})
			return
		}
		logrus.Errorf("Failed to update client: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "Failed to update client",
		})
		return
	}

	// Don't expose client secret
	client.ClientSecret = ""
	c.JSON(http.StatusOK, client)
}

// DeleteClient handles DELETE /clients/:client_id
func (h *ClientHandler) DeleteClient(c *gin.Context) {
	clientID := c.Param("client_id")
	if clientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "client_id is required",
		})
		return
	}

	err := h.clientService.DeleteClient(clientID)
	if err != nil {
		if err.Error() == "client not found" {
			c.JSON(http.StatusNotFound, gin.H{
				"error":             "not_found",
				"error_description": "Client not found",
			})
			return
		}
		logrus.Errorf("Failed to delete client: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "Failed to delete client",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Client deleted successfully",
	})
}

// ListClients handles GET /clients
func (h *ClientHandler) ListClients(c *gin.Context) {
	// Parse pagination parameters
	limitStr := c.DefaultQuery("limit", "20")
	offsetStr := c.DefaultQuery("offset", "0")

	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit < 1 || limit > 100 {
		limit = 20
	}

	offset, err := strconv.Atoi(offsetStr)
	if err != nil || offset < 0 {
		offset = 0
	}

	// Get clients
	clients, total, err := h.clientService.ListClients(limit, offset)
	if err != nil {
		logrus.Errorf("Failed to list clients: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "Failed to list clients",
		})
		return
	}

	// Calculate pagination info
	totalPages := (total + limit - 1) / limit
	currentPage := (offset / limit) + 1

	response := gin.H{
		"clients": clients,
		"pagination": gin.H{
			"total":        total,
			"limit":        limit,
			"offset":       offset,
			"current_page": currentPage,
			"total_pages":  totalPages,
			"has_next":     offset+limit < total,
			"has_prev":     offset > 0,
		},
	}

	c.JSON(http.StatusOK, response)
}

// GetClientStats handles GET /clients/stats
func (h *ClientHandler) GetClientStats(c *gin.Context) {
	// This is a simple implementation - you can extend it based on your needs
	clients, total, err := h.clientService.ListClients(1000, 0) // Get all clients for stats
	if err != nil {
		logrus.Errorf("Failed to get client stats: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "Failed to get client statistics",
		})
		return
	}

	publicClients := 0
	confidentialClients := 0

	for _, client := range clients {
		if client.IsPublic {
			publicClients++
		} else {
			confidentialClients++
		}
	}

	stats := gin.H{
		"total_clients":        total,
		"public_clients":       publicClients,
		"confidential_clients": confidentialClients,
	}

	c.JSON(http.StatusOK, stats)
}

// ValidateClient handles POST /clients/validate
func (h *ClientHandler) ValidateClient(c *gin.Context) {
	var req struct {
		ClientID     string `json:"client_id" binding:"required"`
		ClientSecret string `json:"client_secret"`
		RedirectURI  string `json:"redirect_uri"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "Invalid request body",
			"details":           err.Error(),
		})
		return
	}

	// Validate client credentials
	client, err := h.clientService.ValidateClient(req.ClientID, req.ClientSecret)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "invalid_client",
			"error_description": "Invalid client credentials",
		})
		return
	}

	// Validate redirect URI if provided
	if req.RedirectURI != "" {
		if err := h.clientService.ValidateRedirectURI(req.ClientID, req.RedirectURI); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":             "invalid_request",
				"error_description": "Invalid redirect URI",
			})
			return
		}
	}

	// Return client info (without secret)
	client.ClientSecret = ""
	c.JSON(http.StatusOK, gin.H{
		"valid":  true,
		"client": client,
	})
}

// Helper methods

func (h *ClientHandler) validateCreateClientRequest(req *models.CreateClientRequest) error {
	if req.Name == "" {
		return fmt.Errorf("name is required")
	}

	if len(req.RedirectURIs) == 0 {
		return fmt.Errorf("at least one redirect URI is required")
	}

	if len(req.GrantTypes) == 0 {
		return fmt.Errorf("at least one grant type is required")
	}

	if len(req.Scopes) == 0 {
		return fmt.Errorf("at least one scope is required")
	}

	// Validate grant types
	validGrantTypes := map[string]bool{
		"authorization_code": true,
		"refresh_token":      true,
		"client_credentials": true,
	}

	for _, grantType := range req.GrantTypes {
		if !validGrantTypes[grantType] {
			return fmt.Errorf("invalid grant type: %s", grantType)
		}
	}

	// Validate redirect URIs
	for _, uri := range req.RedirectURIs {
		if uri == "" {
			return fmt.Errorf("redirect URI cannot be empty")
		}
		// Additional URI validation can be added here
	}

	return nil
}

func (h *ClientHandler) validateUpdateClientRequest(req *models.UpdateClientRequest) error {
	if req.Name != "" && len(req.Name) == 0 {
		return fmt.Errorf("name cannot be empty")
	}

	if req.RedirectURIs != nil && len(req.RedirectURIs) == 0 {
		return fmt.Errorf("at least one redirect URI is required")
	}

	if req.GrantTypes != nil && len(req.GrantTypes) == 0 {
		return fmt.Errorf("at least one grant type is required")
	}

	if req.Scopes != nil && len(req.Scopes) == 0 {
		return fmt.Errorf("at least one scope is required")
	}

	// Validate grant types if provided
	if req.GrantTypes != nil {
		validGrantTypes := map[string]bool{
			"authorization_code": true,
			"refresh_token":      true,
			"client_credentials": true,
		}

		for _, grantType := range req.GrantTypes {
			if !validGrantTypes[grantType] {
				return fmt.Errorf("invalid grant type: %s", grantType)
			}
		}
	}

	// Validate redirect URIs if provided
	if req.RedirectURIs != nil {
		for _, uri := range req.RedirectURIs {
			if uri == "" {
				return fmt.Errorf("redirect URI cannot be empty")
			}
			// Additional URI validation can be added here
		}
	}

	return nil
}
