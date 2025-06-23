package routes

import (
	"vrchat/internal/handlers"
	"vrchat/internal/middleware"

	"github.com/gin-gonic/gin"
)

func SetupAdminRoutes(router *gin.Engine, adminHandler *handlers.AdminHandler, authHandler *handlers.AuthHandler) {
	// Admin panel static files
	router.Static("/admin/assets", "./web/admin/assets")
	router.LoadHTMLGlob("web/admin/*.html")

	// Admin panel dashboard (serves HTML)
	router.GET("/admin", func(c *gin.Context) {
		c.HTML(200, "index.html", gin.H{
			"title": "Admin Panel - Omegle Backend",
		})
	})

	// Admin API routes group
	adminAPI := router.Group("/admin/api")
	{
		// PUBLIC admin auth endpoints (NO middleware - these must be accessible without authentication)
		auth := adminAPI.Group("/auth")
		{
			auth.POST("/login", authHandler.AdminLogin)
			auth.POST("/refresh", authHandler.RefreshAdminToken)
		}

		// PROTECTED admin endpoints (require admin authentication)
		protected := adminAPI.Group("/")
		protected.Use(middleware.AdminAuth()) // Only protect these routes
		{
			// Auth verification and logout (protected)
			auth := protected.Group("/auth")
			{
				auth.POST("/logout", authHandler.AdminLogout)
				auth.GET("/verify", authHandler.VerifyAdminToken)
			}

			// Dashboard & Analytics
			dashboard := protected.Group("/dashboard")
			{
				dashboard.GET("/stats", adminHandler.GetDashboardStats)
				dashboard.GET("/realtime", adminHandler.GetRealtimeStats)
				dashboard.GET("/chart/users", adminHandler.GetUserChartData)
				dashboard.GET("/chart/chats", adminHandler.GetChatChartData)
				dashboard.GET("/chart/regions", adminHandler.GetRegionChartData)
			}

			// User Management
			users := protected.Group("/users")
			{
				users.GET("/", adminHandler.GetUsers)
				users.GET("/:id", adminHandler.GetUser)
				users.PUT("/:id", adminHandler.UpdateUser)
				users.DELETE("/:id", adminHandler.DeleteUser)
				users.POST("/:id/ban", adminHandler.BanUser)
				users.DELETE("/:id/ban", adminHandler.UnbanUser)
				users.GET("/:id/activity", adminHandler.GetUserActivity)
				users.GET("/:id/chats", adminHandler.GetUserChats)
				users.POST("/bulk-action", adminHandler.BulkUserAction)
				users.GET("/export", adminHandler.ExportUsers)
			}

			// Chat Management & Monitoring
			chats := protected.Group("/chats")
			{
				chats.GET("/", adminHandler.GetChats)
				chats.GET("/:id", adminHandler.GetChat)
				chats.DELETE("/:id", adminHandler.DeleteChat)
				chats.GET("/active", adminHandler.GetActiveChats)
				chats.POST("/:id/end", adminHandler.EndChat)
				chats.GET("/analytics", adminHandler.GetChatAnalytics)
			}

			// Reports & Moderation
			reports := protected.Group("/reports")
			{
				reports.GET("/", adminHandler.GetReports)
				reports.GET("/:id", adminHandler.GetReport)
				reports.POST("/:id/resolve", adminHandler.ResolveReport)
				reports.POST("/:id/dismiss", adminHandler.DismissReport)
			}

			// System Management
			system := protected.Group("/system")
			{
				system.GET("/coturn", adminHandler.GetCoturnServers)
				system.PUT("/coturn/:id", adminHandler.UpdateCoturnServer)
				system.DELETE("/coturn/:id", adminHandler.DeleteCoturnServer)
				system.POST("/coturn/:id/test", adminHandler.TestCoturnServer)
				system.GET("/health", adminHandler.GetSystemHealth)
				system.POST("/maintenance", adminHandler.ToggleMaintenanceMode)
				system.GET("/logs", adminHandler.GetSystemLogs)
				system.POST("/backup", adminHandler.CreateBackup)
				system.GET("/analytics/custom", adminHandler.GetCustomAnalytics)
			}

			// Content Management
			content := protected.Group("/content")
			{
				content.GET("/banned-words", adminHandler.GetBannedWords)
				content.POST("/banned-words", adminHandler.AddBannedWord)
				content.DELETE("/banned-words/:id", adminHandler.RemoveBannedWord)
				content.POST("/banned-words/bulk", adminHandler.BulkUpdateBannedWords)
				content.GET("/banned-countries", adminHandler.GetBannedCountries)
				content.POST("/banned-countries", adminHandler.AddBannedCountry)
				content.DELETE("/banned-countries/:code", adminHandler.RemoveBannedCountry)
			}

			// Email & Notifications
			notifications := protected.Group("/notifications")
			{
				notifications.GET("/templates", adminHandler.GetNotificationTemplates)
				notifications.PUT("/templates/:id", adminHandler.UpdateNotificationTemplate)
				notifications.POST("/send", adminHandler.SendNotification)
				notifications.GET("/history", adminHandler.GetNotificationHistory)
				notifications.GET("/settings", adminHandler.GetNotificationSettings)
				notifications.PUT("/settings", adminHandler.UpdateNotificationSettings)
			}

			// API Management
			api := protected.Group("/api")
			{
				api.GET("/keys", adminHandler.GetAPIKeys)
				api.POST("/keys", adminHandler.CreateAPIKey)
				api.DELETE("/keys/:id", adminHandler.RevokeAPIKey)
				api.GET("/usage", adminHandler.GetAPIUsage)
				api.GET("/rate-limits", adminHandler.GetRateLimits)
				api.PUT("/rate-limits", adminHandler.UpdateRateLimits)
			}

			// File Management
			files := protected.Group("/files")
			{
				files.POST("/upload", adminHandler.UploadFile)
				files.GET("/", adminHandler.GetFiles)
				files.DELETE("/:id", adminHandler.DeleteFile)
				files.GET("/storage-info", adminHandler.GetStorageInfo)
				files.POST("/cleanup", adminHandler.CleanupFiles)
			}
		}
	}
}
