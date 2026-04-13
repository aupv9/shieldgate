package handlers

import (
	"net/http"
	"strconv"

	"shieldgate/internal/middleware"
	"shieldgate/internal/models"
	"shieldgate/internal/services"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// SessionHandler handles user session management endpoints.
type SessionHandler struct {
	sessions services.SessionService
	logger   *logrus.Logger
}

func NewSessionHandler(sessions services.SessionService, logger *logrus.Logger) *SessionHandler {
	return &SessionHandler{sessions: sessions, logger: logger}
}

// RegisterRoutes attaches session routes under the given group.
func (h *SessionHandler) RegisterRoutes(rg *gin.RouterGroup) {
	rg.GET("", h.List)
	rg.DELETE("", h.RevokeAll)
	rg.GET("/:id", h.Get)
	rg.DELETE("/:id", h.Revoke)
}

// List returns all active sessions for the current user.
// GET /v1/sessions
func (h *SessionHandler) List(c *gin.Context) {
	tenantID, _ := middleware.GetTenantID(c)
	userID, err := middleware.GetUserID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": models.ErrorCodeUnauthorized})
		return
	}

	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))

	resp, err := h.sessions.ListByUser(c.Request.Context(), tenantID, userID, limit, offset)
	if err != nil {
		h.logger.WithError(err).Error("list sessions failed")
		c.JSON(http.StatusInternalServerError, gin.H{"error": models.ErrorCodeInternalError})
		return
	}
	c.JSON(http.StatusOK, resp)
}

// Get returns a specific session.
// GET /v1/sessions/:id
func (h *SessionHandler) Get(c *gin.Context) {
	tenantID, _ := middleware.GetTenantID(c)

	sessionID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid session ID"})
		return
	}

	session, err := h.sessions.GetByID(c.Request.Context(), tenantID, sessionID)
	if err != nil {
		switch err {
		case models.ErrSessionNotFound:
			c.JSON(http.StatusNotFound, gin.H{"error": "session not found"})
		case models.ErrSessionRevoked:
			c.JSON(http.StatusGone, gin.H{"error": "session revoked"})
		case models.ErrSessionExpired:
			c.JSON(http.StatusGone, gin.H{"error": "session expired"})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": models.ErrorCodeInternalError})
		}
		return
	}
	c.JSON(http.StatusOK, session)
}

// Revoke revokes a specific session.
// DELETE /v1/sessions/:id
func (h *SessionHandler) Revoke(c *gin.Context) {
	tenantID, _ := middleware.GetTenantID(c)

	sessionID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid session ID"})
		return
	}

	if err := h.sessions.Revoke(c.Request.Context(), tenantID, sessionID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": models.ErrorCodeInternalError})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "session revoked"})
}

// RevokeAll revokes all sessions for the current user.
// DELETE /v1/sessions
func (h *SessionHandler) RevokeAll(c *gin.Context) {
	tenantID, _ := middleware.GetTenantID(c)
	userID, err := middleware.GetUserID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": models.ErrorCodeUnauthorized})
		return
	}

	if err := h.sessions.RevokeAll(c.Request.Context(), tenantID, userID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": models.ErrorCodeInternalError})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "all sessions revoked"})
}
