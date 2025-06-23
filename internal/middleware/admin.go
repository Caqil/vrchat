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
	jwt.StandardClaims
}

// AdminAuth middleware for admin authentication - UPDATED for full admin panel support
func AdminAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			utils.ErrorResponse(c, http.StatusUnauthorized, "Authorization header required")
			c.Abort()
			return
		}

		// Extract token from "Bearer <token>"
		tokenParts := strings.Split(authHeader, " ")
		if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
			utils.ErrorResponse(c, http.StatusUnauthorized, "Invalid authorization header format")
			c.Abort()
			return
		}

		tokenString := tokenParts[1]

		// Check if token is blacklisted
		if utils.IsTokenBlacklisted(tokenString) {
			utils.ErrorResponse(c, http.StatusUnauthorized, "Token has been invalidated")
			c.Abort()
			return
		}

		// Parse admin JWT token
		token, err := jwt.ParseWithClaims(tokenString, &AdminClaims{}, func(token *jwt.Token) (interface{}, error) {
			// Verify signing method
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, jwt.NewValidationError("unexpected signing method", jwt.ValidationErrorSignatureInvalid)
			}
			// Use different secret for admin tokens for added security
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
		if claims.Role != "admin" && claims.Role != "super_admin" && claims.Role != "moderator" {
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

// AdminPermission middleware to check specific permissions
func AdminPermission(permission string) gin.HandlerFunc {
	return func(c *gin.Context) {
		permissions, exists := c.Get("admin_permissions")
		if !exists {
			utils.ErrorResponse(c, http.StatusForbidden, "Admin permissions not found")
			c.Abort()
			return
		}

		permissionList, ok := permissions.([]string)
		if !ok {
			utils.ErrorResponse(c, http.StatusForbidden, "Invalid permissions format")
			c.Abort()
			return
		}

		// Check if admin has required permission or is super admin
		hasPermission := false
		for _, perm := range permissionList {
			if perm == permission || perm == "super_admin" || perm == "all" {
				hasPermission = true
				break
			}
		}

		if !hasPermission {
			utils.ErrorResponse(c, http.StatusForbidden, "Insufficient permissions: "+permission+" required")
			c.Abort()
			return
		}

		c.Next()
	}
}

// OptionalAdminAuth - allows both authenticated and unauthenticated access
func OptionalAdminAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader != "" {
			tokenParts := strings.Split(authHeader, " ")
			if len(tokenParts) == 2 && tokenParts[0] == "Bearer" {
				tokenString := tokenParts[1]

				// Try to validate admin token
				claims, err := utils.ValidateAdminJWT(tokenString)
				if err == nil && utils.IsAdminActive(claims.AdminID) {
					c.Set("admin_id", claims.AdminID)
					c.Set("admin_username", claims.Username)
					c.Set("admin_role", claims.Role)
					c.Set("admin_permissions", claims.Permissions)
					c.Set("is_admin", true)
				}
			}
		}
		c.Next()
	}
}

// PermissionCheck middleware for checking specific permissions - ENHANCED
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
			if perm == requiredPermission || perm == "super_admin" || perm == "all" {
				hasPermission = true
				break
			}
		}

		if !hasPermission && c.GetString("admin_role") != "super_admin" {
			utils.ErrorResponse(c, http.StatusForbidden, "Insufficient permissions: "+requiredPermission+" required")
			c.Abort()
			return
		}

		c.Next()
	}
}

// AdminActivityLogger logs admin activities - ENHANCED
func AdminActivityLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		adminID := c.GetString("admin_id")
		if adminID != "" {
			// Log admin activity asynchronously
			go func() {
				// Skip logging for GET requests to reduce noise, except for sensitive endpoints
				shouldLog := c.Request.Method != "GET" ||
					strings.Contains(c.Request.URL.Path, "/users/") ||
					strings.Contains(c.Request.URL.Path, "/chats/") ||
					strings.Contains(c.Request.URL.Path, "/reports/") ||
					strings.Contains(c.Request.URL.Path, "/system/")

				if shouldLog {
					activity := map[string]interface{}{
						"admin_id":   adminID,
						"username":   c.GetString("admin_username"),
						"method":     c.Request.Method,
						"path":       c.Request.URL.Path,
						"query":      c.Request.URL.RawQuery,
						"ip":         c.ClientIP(),
						"user_agent": c.GetHeader("User-Agent"),
						"timestamp":  utils.GetCurrentTime(),
						"action":     utils.GetActionFromPath(c.Request.Method, c.Request.URL.Path),
					}

					// Store activity log
					utils.LogAdminActivity(activity)
				}
			}()
		}

		c.Next()
	}
}

// AdminRateLimit - Rate limiting specifically for admin endpoints
func AdminRateLimit() gin.HandlerFunc {
	return func(c *gin.Context) {
		adminID := c.GetString("admin_id")
		if adminID != "" {
			// Check admin-specific rate limits
			if utils.IsAdminRateLimited(adminID, c.Request.URL.Path) {
				utils.ErrorResponse(c, http.StatusTooManyRequests, "Rate limit exceeded for admin user")
				c.Abort()
				return
			}
		}
		c.Next()
	}
}


// AdminSecurityHeaders - Add security headers for admin panel
func AdminSecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Security headers for admin panel
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Header("Permissions-Policy", "geolocation=(), microphone=(), camera=()")

		// HTTPS enforcement in production
		if config.Load().App.Environment == "production" {
			c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}

		c.Next()
	}
}
