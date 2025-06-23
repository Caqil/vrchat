package utils

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// APIResponse represents the standard API response structure
type APIResponse struct {
	Success   bool        `json:"success"`
	Message   string      `json:"message,omitempty"`
	Data      interface{} `json:"data,omitempty"`
	Error     *APIError   `json:"error,omitempty"`
	Meta      *Meta       `json:"meta,omitempty"`
	Timestamp time.Time   `json:"timestamp"`
}

// APIError represents error details
type APIError struct {
	Code    string            `json:"code"`
	Message string            `json:"message"`
	Details map[string]string `json:"details,omitempty"`
}

// Meta represents metadata for responses
type Meta struct {
	Page       int `json:"page,omitempty"`
	Limit      int `json:"limit,omitempty"`
	Total      int `json:"total,omitempty"`
	TotalPages int `json:"total_pages,omitempty"`
}

// SuccessResponse sends a successful response
func SuccessResponse(c *gin.Context, data interface{}) {
	response := APIResponse{
		Success:   true,
		Data:      data,
		Timestamp: time.Now(),
	}
	c.JSON(http.StatusOK, response)
}

// SuccessResponseWithMessage sends a successful response with message
func SuccessResponseWithMessage(c *gin.Context, message string, data interface{}) {
	response := APIResponse{
		Success:   true,
		Message:   message,
		Data:      data,
		Timestamp: time.Now(),
	}
	c.JSON(http.StatusOK, response)
}

// SuccessResponseWithMeta sends a successful response with pagination metadata
func SuccessResponseWithMeta(c *gin.Context, data interface{}, meta *Meta) {
	response := APIResponse{
		Success:   true,
		Data:      data,
		Meta:      meta,
		Timestamp: time.Now(),
	}
	c.JSON(http.StatusOK, response)
}

// ErrorResponse sends an error response
func ErrorResponse(c *gin.Context, statusCode int, message string) {
	response := APIResponse{
		Success: false,
		Error: &APIError{
			Code:    getErrorCode(statusCode),
			Message: message,
		},
		Timestamp: time.Now(),
	}
	c.JSON(statusCode, response)
}

// ErrorResponseWithDetails sends an error response with details
func ErrorResponseWithDetails(c *gin.Context, statusCode int, message string, details map[string]string) {
	response := APIResponse{
		Success: false,
		Error: &APIError{
			Code:    getErrorCode(statusCode),
			Message: message,
			Details: details,
		},
		Timestamp: time.Now(),
	}
	c.JSON(statusCode, response)
}

// ValidationErrorResponse sends a validation error response
func ValidationErrorResponse(c *gin.Context, errors map[string]string) {
	response := APIResponse{
		Success: false,
		Error: &APIError{
			Code:    "VALIDATION_ERROR",
			Message: "Validation failed",
			Details: errors,
		},
		Timestamp: time.Now(),
	}
	c.JSON(http.StatusBadRequest, response)
}

// UnauthorizedResponse sends an unauthorized response
func UnauthorizedResponse(c *gin.Context, message string) {
	if message == "" {
		message = "Unauthorized access"
	}
	ErrorResponse(c, http.StatusUnauthorized, message)
}

// ForbiddenResponse sends a forbidden response
func ForbiddenResponse(c *gin.Context, message string) {
	if message == "" {
		message = "Access forbidden"
	}
	ErrorResponse(c, http.StatusForbidden, message)
}

// NotFoundResponse sends a not found response
func NotFoundResponse(c *gin.Context, message string) {
	if message == "" {
		message = "Resource not found"
	}
	ErrorResponse(c, http.StatusNotFound, message)
}

// InternalErrorResponse sends an internal server error response
func InternalErrorResponse(c *gin.Context, message string) {
	if message == "" {
		message = "Internal server error"
	}
	ErrorResponse(c, http.StatusInternalServerError, message)
}

// getErrorCode returns appropriate error code based on status
func getErrorCode(statusCode int) string {
	switch statusCode {
	case http.StatusBadRequest:
		return "BAD_REQUEST"
	case http.StatusUnauthorized:
		return "UNAUTHORIZED"
	case http.StatusForbidden:
		return "FORBIDDEN"
	case http.StatusNotFound:
		return "NOT_FOUND"
	case http.StatusTooManyRequests:
		return "RATE_LIMIT_EXCEEDED"
	case http.StatusInternalServerError:
		return "INTERNAL_ERROR"
	default:
		return "UNKNOWN_ERROR"
	}
}
