package middleware

import (
	"net/http"
	"strings"

	"vrchat/internal/config"
	"vrchat/internal/utils"
	"vrchat/pkg/logger"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
)

type AdminClaims struct {
	AdminID     string   `json:"admin_id"`
	Username    string   `json:"username"`
	Role        string   `json:"role"`
	Permissions []string `json:"permissions"`
	jwt.Claims
}

// AdminAuth middleware for admin authentication
func AdminAuth() gin.HandlerFunc {
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

		// Parse admin JWT token
		token, err := jwt.ParseWithClaims(tokenString, &AdminClaims{}, func(token *jwt.Token) (interface{}, error) {
			// Use different secret for admin tokens
			return []byte(config.Load().Security.JWT.Secret + "_admin"), nil
		})

		if err != nil {
			logger.Error("Admin JWT parsing error: " + err.Error())
			utils.ErrorResponse(c, http.StatusUnauthorized, "Invalid admin token")
			c.Abort()
			return
		}

		claims, ok := token.Claims.(*AdminClaims)
		if !ok || !token.Valid {
			utils.ErrorResponse(c, http.StatusUnauthorized, "Invalid token claims")
			c.Abort()
			return
		}

		// Verify admin role
		if claims.Role != "admin" && claims.Role != "super_admin" {
			utils.ErrorResponse(c, http.StatusForbidden, "Admin access required")
			c.Abort()
			return
		}

		// Check if admin is active
		if !utils.IsAdminActive(claims.AdminID) {
			utils.ErrorResponse(c, http.StatusForbidden, "Admin account is inactive")
			c.Abort()
			return
		}

		// Set admin info in context
		c.Set("admin_id", claims.AdminID)
		c.Set("admin_username", claims.Username)
		c.Set("admin_role", claims.Role)
		c.Set("admin_permissions", claims.Permissions)
		c.Set("admin_token", tokenString)

		// Log admin access
		logger.Info("Admin access: " + claims.Username + " -> " + c.Request.Method + " " + c.Request.URL.Path)

		c.Next()
	}
}

// SuperAdminAuth middleware for super admin only access
func SuperAdminAuth() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		// First run admin auth
		AdminAuth()(c)

		if c.IsAborted() {
			return
		}

		// Check if super admin
		if c.GetString("admin_role") != "super_admin" {
			utils.ErrorResponse(c, http.StatusForbidden, "Super admin access required")
			c.Abort()
			return
		}

		c.Next()
	})
}

// PermissionCheck middleware for checking specific permissions
func PermissionCheck(requiredPermission string) gin.HandlerFunc {
	return func(c *gin.Context) {
		permissions, exists := c.Get("admin_permissions")
		if !exists {
			utils.ErrorResponse(c, http.StatusForbidden, "No permissions found")
			c.Abort()
			return
		}

		permList, ok := permissions.([]string)
		if !ok {
			utils.ErrorResponse(c, http.StatusInternalServerError, "Invalid permissions format")
			c.Abort()
			return
		}

		// Check if user has required permission or is super admin
		hasPermission := false
		for _, perm := range permList {
			if perm == requiredPermission || perm == "all" {
				hasPermission = true
				break
			}
		}

		if !hasPermission && c.GetString("admin_role") != "super_admin" {
			utils.ErrorResponse(c, http.StatusForbidden, "Insufficient permissions")
			c.Abort()
			return
		}

		c.Next()
	}
}

// AdminActivityLogger logs admin activities
func AdminActivityLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Skip logging for GET requests to reduce noise
		if c.Request.Method == "GET" {
			c.Next()
			return
		}

		adminID := c.GetString("admin_id")
		if adminID != "" {
			// Log admin activity asynchronously
			go func() {
				activity := map[string]interface{}{
					"admin_id":   adminID,
					"method":     c.Request.Method,
					"path":       c.Request.URL.Path,
					"ip":         c.ClientIP(),
					"user_agent": c.GetHeader("User-Agent"),
					"timestamp":  utils.GetCurrentTime(),
				}

				// Store activity log
				utils.LogAdminActivity(activity)
			}()
		}

		c.Next()
	}
}
