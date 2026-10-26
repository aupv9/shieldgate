package handlers

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"shieldgate/internal/middleware"
	"shieldgate/internal/models"
	"shieldgate/internal/observability"
	"shieldgate/internal/services"
)

// maxRegistrationBody bounds a registration request body
const maxRegistrationBody = 64 << 10

// RegistrationHandler serves dynamic client registration (RFC 7591), client
// self-management (RFC 7592) and the management API for initial access
// tokens
type RegistrationHandler struct {
	registration services.RegistrationService
	events       *observability.Recorder
	logger       *logrus.Logger
}

// NewRegistrationHandler creates a new RegistrationHandler instance
func NewRegistrationHandler(registration services.RegistrationService, logger *logrus.Logger) *RegistrationHandler {
	return &RegistrationHandler{registration: registration, logger: logger}
}

// WithRecorder makes the handler audit registrations
func (h *RegistrationHandler) WithRecorder(events *observability.Recorder) *RegistrationHandler {
	h.events = events
	return h
}

// RegisterRoutes registers the registration endpoint and the client
// configuration endpoint. The tenant comes from the request's domain (or
// X-Tenant-ID) like the other OAuth endpoints.
func (h *RegistrationHandler) RegisterRoutes(router *gin.RouterGroup) {
	register := router.Group("/oauth/register", noStore)
	register.POST("", h.Register)
	register.GET("/:client_id", h.Read)
	register.PUT("/:client_id", h.Update)
	register.DELETE("/:client_id", h.Delete)
}

// RegisterManagementRoutes registers /v1/client-registration-tokens
func (h *RegistrationHandler) RegisterManagementRoutes(router *gin.RouterGroup, authz *middleware.Authorizer) {
	tokens := router.Group("/client-registration-tokens")
	tokens.POST("", authz.Require("client", "create"), h.CreateInitialAccessToken)
	tokens.GET("", authz.Require("client", "read"), h.ListInitialAccessTokens)
	tokens.DELETE("/:id", authz.Require("client", "delete"), h.RevokeInitialAccessToken)
}

// noStore keeps credentials in responses out of caches (RFC 6749 §5.1,
// RFC 7591 §3.2.1)
func noStore(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")
	c.Next()
}

// Register handles POST /oauth/register. The initial access token is sent
// as a bearer token.
func (h *RegistrationHandler) Register(c *gin.Context) {
	tenantID, ok := h.tenant(c)
	if !ok {
		return
	}
	meta, ok := h.bindMetadata(c)
	if !ok {
		return
	}

	resp, err := h.registration.Register(c.Request.Context(), tenantID, bearerToken(c), meta)
	if err != nil {
		h.fail(c, err)
		return
	}
	h.audit(c, models.AuditActionClientCreated, tenantID, resp.ClientID, map[string]interface{}{
		"registration": "dynamic",
		"grant_types":  resp.GrantTypes,
		"auth_method":  resp.TokenEndpointAuthMethod,
	})
	c.JSON(http.StatusCreated, resp)
}

// Read handles GET /oauth/register/:client_id
func (h *RegistrationHandler) Read(c *gin.Context) {
	tenantID, ok := h.tenant(c)
	if !ok {
		return
	}
	resp, err := h.registration.Read(c.Request.Context(), tenantID, c.Param("client_id"), bearerToken(c))
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, resp)
}

// Update handles PUT /oauth/register/:client_id: the request carries the
// client's complete metadata, which replaces what was registered
func (h *RegistrationHandler) Update(c *gin.Context) {
	tenantID, ok := h.tenant(c)
	if !ok {
		return
	}
	meta, ok := h.bindMetadata(c)
	if !ok {
		return
	}
	resp, err := h.registration.Update(c.Request.Context(), tenantID, c.Param("client_id"), bearerToken(c), meta)
	if err != nil {
		h.fail(c, err)
		return
	}
	h.audit(c, models.AuditActionClientUpdated, tenantID, resp.ClientID, map[string]interface{}{"registration": "dynamic"})
	c.JSON(http.StatusOK, resp)
}

// Delete handles DELETE /oauth/register/:client_id
func (h *RegistrationHandler) Delete(c *gin.Context) {
	tenantID, ok := h.tenant(c)
	if !ok {
		return
	}
	clientID := c.Param("client_id")
	if err := h.registration.Delete(c.Request.Context(), tenantID, clientID, bearerToken(c)); err != nil {
		h.fail(c, err)
		return
	}
	h.audit(c, models.AuditActionClientDeleted, tenantID, clientID, map[string]interface{}{"registration": "dynamic"})
	c.Status(http.StatusNoContent)
}

// CreateInitialAccessToken handles POST /v1/client-registration-tokens
func (h *RegistrationHandler) CreateInitialAccessToken(c *gin.Context) {
	tenantID, err := middleware.GetTenantID(c)
	if err != nil {
		middleware.RespondWithError(c, http.StatusUnauthorized, models.ErrorCodeUnauthorized, "Invalid tenant context", nil)
		return
	}
	var req models.CreateInitialAccessTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		middleware.RespondWithError(c, http.StatusBadRequest, models.ErrorCodeValidationFailed,
			"Request body must contain scopes", nil)
		return
	}
	var createdBy *uuid.UUID
	if userID, err := middleware.GetUserID(c); err == nil && userID != uuid.Nil {
		createdBy = &userID
	}

	token, err := h.registration.CreateInitialAccessToken(c.Request.Context(), tenantID, createdBy, &req)
	var regErr *models.RegistrationError
	switch {
	case errors.As(err, &regErr):
		middleware.RespondWithError(c, http.StatusBadRequest, models.ErrorCodeValidationFailed, regErr.Description, nil)
		return
	case err != nil:
		h.logger.WithError(err).Error("failed to create initial access token")
		middleware.RespondWithError(c, http.StatusInternalServerError, models.ErrorCodeInternalError, "Internal server error", nil)
		return
	}
	h.events.Record(c.Request.Context(), observability.Event{
		Action: models.AuditActionClientCreated, TenantID: tenantID, UserID: createdBy, Resource: "initial_access_token",
		Success: true, Metadata: map[string]interface{}{
			"initial_access_token_id": token.ID.String(), "scopes": token.Scopes, "max_uses": token.MaxUses,
		},
	})
	c.Header("Cache-Control", "no-store")
	middleware.RespondWithSuccess(c, http.StatusCreated, token)
}

// ListInitialAccessTokens handles GET /v1/client-registration-tokens
func (h *RegistrationHandler) ListInitialAccessTokens(c *gin.Context) {
	tenantID, err := middleware.GetTenantID(c)
	if err != nil {
		middleware.RespondWithError(c, http.StatusUnauthorized, models.ErrorCodeUnauthorized, "Invalid tenant context", nil)
		return
	}
	tokens, err := h.registration.ListInitialAccessTokens(c.Request.Context(), tenantID)
	if err != nil {
		h.logger.WithError(err).Error("failed to list initial access tokens")
		middleware.RespondWithError(c, http.StatusInternalServerError, models.ErrorCodeInternalError, "Internal server error", nil)
		return
	}
	middleware.RespondWithSuccess(c, http.StatusOK, tokens)
}

// RevokeInitialAccessToken handles DELETE /v1/client-registration-tokens/:id
func (h *RegistrationHandler) RevokeInitialAccessToken(c *gin.Context) {
	tenantID, err := middleware.GetTenantID(c)
	if err != nil {
		middleware.RespondWithError(c, http.StatusUnauthorized, models.ErrorCodeUnauthorized, "Invalid tenant context", nil)
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		middleware.RespondWithError(c, http.StatusBadRequest, models.ErrorCodeInvalidRequest, "Invalid token ID format", nil)
		return
	}
	switch err := h.registration.RevokeInitialAccessToken(c.Request.Context(), tenantID, id); {
	case errors.Is(err, models.ErrInitialAccessTokenNotFound):
		middleware.RespondWithError(c, http.StatusNotFound, models.ErrorCodeResourceNotFound, "Initial access token not found", nil)
	case err != nil:
		h.logger.WithError(err).Error("failed to revoke initial access token")
		middleware.RespondWithError(c, http.StatusInternalServerError, models.ErrorCodeInternalError, "Internal server error", nil)
	default:
		c.Status(http.StatusNoContent)
	}
}

func (h *RegistrationHandler) tenant(c *gin.Context) (uuid.UUID, bool) {
	tenantID, err := middleware.GetTenantID(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "Tenant context required — use the tenant's domain or provide X-Tenant-ID",
		})
		return uuid.Nil, false
	}
	return tenantID, true
}

func (h *RegistrationHandler) bindMetadata(c *gin.Context) (*models.ClientMetadata, bool) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxRegistrationBody)
	var meta models.ClientMetadata
	if err := c.ShouldBindJSON(&meta); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             models.RegistrationErrorInvalidClientMetadata,
			"error_description": "Request body must be a JSON object of client metadata",
		})
		return nil, false
	}
	return &meta, true
}

// fail maps service errors to RFC 7591 §3.2.2 / RFC 6750 §3 responses
func (h *RegistrationHandler) fail(c *gin.Context, err error) {
	var regErr *models.RegistrationError
	switch {
	case errors.As(err, &regErr):
		c.JSON(http.StatusBadRequest, gin.H{"error": regErr.Code, "error_description": regErr.Description})
	case errors.Is(err, models.ErrInvalidToken):
		c.Header("WWW-Authenticate", `Bearer error="invalid_token"`)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
	default:
		h.logger.WithError(err).WithField("request_id", middleware.GetRequestID(c)).Error("client registration failed")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
	}
}

func (h *RegistrationHandler) audit(c *gin.Context, action models.AuditAction, tenantID uuid.UUID, clientID string, metadata map[string]interface{}) {
	metadata["client_id"] = clientID
	h.events.Record(c.Request.Context(), observability.Event{
		Action: action, TenantID: tenantID, Resource: "client", Success: true, Metadata: metadata,
		Name: "client_registration", Result: strings.TrimPrefix(string(action), "client."),
	})
}

// bearerToken returns the bearer token of the Authorization header, or ""
func bearerToken(c *gin.Context) string {
	scheme, token, found := strings.Cut(c.GetHeader("Authorization"), " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return ""
	}
	return strings.TrimSpace(token)
}
