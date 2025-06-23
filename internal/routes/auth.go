package routes

import (
	"vrchat/internal/handlers"
	"vrchat/internal/middleware"

	"github.com/gin-gonic/gin"
)

func SetupAuthRoutes(router *gin.Engine, authHandler *handlers.AuthHandler) {
	auth := router.Group("/auth")
	{
		// Admin authentication
		auth.POST("/admin/login", authHandler.AdminLogin)
		auth.POST("/admin/logout", authHandler.AdminLogout)
		auth.GET("/admin/verify", middleware.AdminAuth(), authHandler.VerifyAdminToken)
		auth.POST("/admin/refresh", authHandler.RefreshAdminToken)

		// Optional user registration (if you want registered users)
		auth.POST("/register", authHandler.Register)
		auth.POST("/login", authHandler.Login)
		auth.POST("/logout", authHandler.Logout)
		auth.POST("/verify-email", authHandler.VerifyEmail)
		auth.POST("/forgot-password", authHandler.ForgotPassword)
		auth.POST("/reset-password", authHandler.ResetPassword)

		// Social authentication (optional)
		auth.GET("/google", authHandler.GoogleAuth)
		auth.GET("/google/callback", authHandler.GoogleCallback)
		auth.GET("/facebook", authHandler.FacebookAuth)
		auth.GET("/facebook/callback", authHandler.FacebookCallback)
	}
}
