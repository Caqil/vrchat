package middleware

import (
	"net/http"
	"strings"
	"time"

	"vrchat/internal/config"
	"vrchat/internal/utils"
	"vrchat/pkg/logger"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
)

type Claims struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.StandardClaims
}

// SessionAuth middleware for user session validation
func SessionAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get session token from header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			// Check for session token in query params (for WebSocket)
			sessionToken := c.Query("session_token")
			if sessionToken == "" {
				utils.ErrorResponse(c, http.StatusUnauthorized, "Missing session token")
				c.Abort()
				return
			}
			authHeader = "Bearer " + sessionToken
		}

		// Extract token from Bearer format
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			utils.ErrorResponse(c, http.StatusUnauthorized, "Invalid token format")
			c.Abort()
			return
		}

		// Validate session token
		userID, err := utils.ValidateSessionToken(tokenString)
		if err != nil {
			utils.ErrorResponse(c, http.StatusUnauthorized, "Invalid session token")
			c.Abort()
			return
		}

		// Check if user is banned
		if utils.IsUserBanned(userID) {
			utils.ErrorResponse(c, http.StatusForbidden, "User is banned")
			c.Abort()
			return
		}

		// Set user ID in context
		c.Set("user_id", userID)
		c.Set("session_token", tokenString)

		// Update user last seen
		go utils.UpdateUserLastSeen(userID)

		c.Next()
	}
}

// OptionalAuth middleware for optional user authentication
func OptionalAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader != "" {
			tokenString := strings.TrimPrefix(authHeader, "Bearer ")
			if userID, err := utils.ValidateSessionToken(tokenString); err == nil {
				c.Set("user_id", userID)
				c.Set("authenticated", true)
			}
		}
		c.Next()
	}
}

// JWTAuth middleware for JWT token validation
func JWTAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			utils.ErrorResponse(c, http.StatusUnauthorized, "Missing authorization header")
			c.Abort()
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			utils.ErrorResponse(c, http.StatusUnauthorized, "Invalid token format")
			c.Abort()
			return
		}

		// Parse and validate JWT token
		token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
			return []byte(config.Load().Security.JWT.Secret), nil
		})

		if err != nil {
			logger.Error("JWT parsing error: " + err.Error())
			utils.ErrorResponse(c, http.StatusUnauthorized, "Invalid token")
			c.Abort()
			return
		}

		claims, ok := token.Claims.(*Claims)
		if !ok || !token.Valid {
			utils.ErrorResponse(c, http.StatusUnauthorized, "Invalid token claims")
			c.Abort()
			return
		}

		// Check token expiration
		if time.Unix(claims.ExpiresAt, 0).Before(time.Now()) {
			utils.ErrorResponse(c, http.StatusUnauthorized, "Token expired")
			c.Abort()
			return
		}

		// Set user info in context
		c.Set("user_id", claims.UserID)
		c.Set("username", claims.Username)
		c.Set("role", claims.Role)
		c.Set("token", tokenString)

		c.Next()
	}
}

// RefreshTokenAuth middleware for refresh token validation
func RefreshTokenAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			RefreshToken string `json:"refresh_token" binding:"required"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			utils.ErrorResponse(c, http.StatusBadRequest, "Missing refresh token")
			c.Abort()
			return
		}

		// Validate refresh token
		userID, err := utils.ValidateRefreshToken(req.RefreshToken)
		if err != nil {
			utils.ErrorResponse(c, http.StatusUnauthorized, "Invalid refresh token")
			c.Abort()
			return
		}

		c.Set("user_id", userID)
		c.Set("refresh_token", req.RefreshToken)

		c.Next()
	}
}

// ValidateUserAccess checks if user has access to specific resource
func ValidateUserAccess() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.GetString("user_id")
		resourceUserID := c.Param("user_id")

		// If no resource user ID in params, continue
		if resourceUserID == "" {
			c.Next()
			return
		}

		// Check if user is accessing their own resource or is admin
		if userID != resourceUserID && c.GetString("role") != "admin" {
			utils.ErrorResponse(c, http.StatusForbidden, "Access denied")
			c.Abort()
			return
		}

		c.Next()
	}
}
