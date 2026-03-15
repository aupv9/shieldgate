package middleware

import (
	"github.com/gin-gonic/gin"
)

// APIResponse represents a standardized API response
type APIResponse struct {
	Success   bool        `json:"success"`
	Data      interface{} `json:"data,omitempty"`
	Error     *APIError   `json:"error,omitempty"`
	RequestID string      `json:"request_id"`
}

// APIError represents a standardized API error
type APIError struct {
	Code    string      `json:"code"`
	Message string      `json:"message"`
	Details interface{} `json:"details,omitempty"`
}

// RespondWithSuccess sends a 200 OK response with the given data.
func RespondWithSuccess(c *gin.Context, data interface{}) {
	response := APIResponse{
		Success:   true,
		Data:      data,
		RequestID: GetRequestID(c),
	}
	c.JSON(200, response)
}

// RespondWithError sends an error response
func RespondWithError(c *gin.Context, statusCode int, errorCode, message string, details interface{}) {
	response := APIResponse{
		Success: false,
		Error: &APIError{
			Code:    errorCode,
			Message: message,
			Details: details,
		},
		RequestID: GetRequestID(c),
	}
	c.JSON(statusCode, response)
}
