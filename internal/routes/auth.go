package routes

import (
	"vrchat/internal/handlers"
	"vrchat/internal/middleware"

	"github.com/gin-gonic/gin"
)

func SetupAuthRoutes(router *gin.Engine, authHandler *handlers.AuthHandler) {
	// Main auth group
	auth := router.Group("/auth")
	{
		// Admin authentication endpoints - ENHANCED for admin panel
		adminAuth := auth.Group("/admin")
		{
			// Public admin auth endpoints
			adminAuth.POST("/login", authHandler.AdminLogin)
			adminAuth.POST("/refresh", authHandler.RefreshAdminToken)

			// Protected admin auth endpoints
			adminAuth.Use(middleware.AdminAuth())
			adminAuth.POST("/logout", authHandler.AdminLogout)
			adminAuth.GET("/verify", authHandler.VerifyAdminToken)
		}

		// Regular user authentication endpoints (existing functionality)
		userAuth := auth.Group("/user")
		{
			// Public user auth endpoints
			userAuth.POST("/register", authHandler.Register)
			userAuth.POST("/login", authHandler.Login)
			userAuth.POST("/verify-email", authHandler.VerifyEmail)
			userAuth.POST("/forgot-password", authHandler.ForgotPassword)
			userAuth.POST("/reset-password", authHandler.ResetPassword)

			// Protected user auth endpoints
			userAuth.Use(middleware.SessionAuth())
			userAuth.POST("/logout", authHandler.Logout)
		}

		// Social authentication endpoints (optional)
		social := auth.Group("/social")
		{
			// Google OAuth
			social.GET("/google", authHandler.GoogleAuth)
			social.GET("/google/callback", authHandler.GoogleCallback)

			// Facebook OAuth
			social.GET("/facebook", authHandler.FacebookAuth)
			social.GET("/facebook/callback", authHandler.FacebookCallback)
		}
	}

	// Legacy endpoints for backward compatibility (if needed)
	legacyAuth := router.Group("/api/v1/auth")
	{
		// Redirect to new admin endpoints
		legacyAuth.POST("/admin/login", authHandler.AdminLogin)
		legacyAuth.POST("/admin/logout", middleware.AdminAuth(), authHandler.AdminLogout)
		legacyAuth.GET("/admin/verify", middleware.AdminAuth(), authHandler.VerifyAdminToken)
		legacyAuth.POST("/admin/refresh", authHandler.RefreshAdminToken)

		// Regular auth endpoints
		legacyAuth.POST("/register", authHandler.Register)
		legacyAuth.POST("/login", authHandler.Login)
		legacyAuth.POST("/logout", middleware.SessionAuth(), authHandler.Logout)
	}
}
