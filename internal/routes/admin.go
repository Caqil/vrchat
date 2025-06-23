package routes

import (
	"vrchat/internal/handlers"
	"vrchat/internal/middleware"

	"github.com/gin-gonic/gin"
)

func SetupAdminRoutes(router *gin.Engine, adminHandler *handlers.AdminHandler) {
	// Admin panel static files
	router.Static("/admin/assets", "./web/admin/assets")
	router.LoadHTMLGlob("web/admin/*.html")

	// Admin panel dashboard (serves HTML)
	router.GET("/admin", func(c *gin.Context) {
		c.HTML(200, "index.html", gin.H{
			"title": "Admin Panel - Omegle Backend",
		})
	})

	// Admin API routes
	admin := router.Group("/admin/api")
	admin.Use(middleware.AdminAuth())
	{
		// Dashboard & Analytics
		dashboard := admin.Group("/dashboard")
		{
			dashboard.GET("/stats", adminHandler.GetDashboardStats)
			dashboard.GET("/realtime", adminHandler.GetRealtimeStats)
			dashboard.GET("/chart/users", adminHandler.GetUserChartData)
			dashboard.GET("/chart/chats", adminHandler.GetChatChartData)
			dashboard.GET("/chart/regions", adminHandler.GetRegionChartData)
		}

		// User Management
		users := admin.Group("/users")
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
		chats := admin.Group("/chats")
		{
			chats.GET("/", adminHandler.GetChats)
			chats.GET("/:id", adminHandler.GetChat)
			chats.DELETE("/:id", adminHandler.DeleteChat)
			chats.GET("/active", adminHandler.GetActiveChats)
			chats.POST("/:id/end", adminHandler.EndChat)
			chats.GET("/:id/messages", adminHandler.GetChatMessages)
			chats.POST("/bulk-action", adminHandler.BulkChatAction)
			chats.GET("/export", adminHandler.ExportChats)
		}

		// Reports & Moderation
		moderation := admin.Group("/moderation")
		{
			moderation.GET("/reports", adminHandler.GetReports)
			moderation.GET("/reports/:id", adminHandler.GetReport)
			moderation.POST("/reports/:id/resolve", adminHandler.ResolveReport)
			moderation.POST("/reports/:id/dismiss", adminHandler.DismissReport)
			moderation.GET("/queue", adminHandler.GetModerationQueue)
			moderation.POST("/content/:id/approve", adminHandler.ApproveContent)
			moderation.POST("/content/:id/reject", adminHandler.RejectContent)
			moderation.GET("/flagged-content", adminHandler.GetFlaggedContent)
			moderation.POST("/bulk-moderate", adminHandler.BulkModerate)
		}

		// App Settings Management
		settings := admin.Group("/settings")
		{
			settings.GET("/", adminHandler.GetSettings)
			settings.PUT("/", adminHandler.UpdateSettings)
			settings.GET("/backup", adminHandler.BackupSettings)
			settings.POST("/restore", adminHandler.RestoreSettings)
			settings.POST("/reset", adminHandler.ResetToDefaults)

			// Specific setting categories
			settings.GET("/general", adminHandler.GetGeneralSettings)
			settings.PUT("/general", adminHandler.UpdateGeneralSettings)
			settings.GET("/moderation", adminHandler.GetModerationSettings)
			settings.PUT("/moderation", adminHandler.UpdateModerationSettings)
			settings.GET("/matching", adminHandler.GetMatchingSettings)
			settings.PUT("/matching", adminHandler.UpdateMatchingSettings)
		}

		// COTURN/WebRTC Server Management
		coturn := admin.Group("/coturn")
		{
			coturn.GET("/servers", adminHandler.GetCoturnServers)
			coturn.POST("/servers", adminHandler.CreateCoturnServer)
			coturn.GET("/servers/:id", adminHandler.GetCoturnServer)
			coturn.PUT("/servers/:id", adminHandler.UpdateCoturnServer)
			coturn.DELETE("/servers/:id", adminHandler.DeleteCoturnServer)
			coturn.POST("/servers/:id/test", adminHandler.TestCoturnServer)
			coturn.POST("/servers/:id/toggle", adminHandler.ToggleCoturnServer)
			coturn.GET("/servers/:id/stats", adminHandler.GetCoturnServerStats)
			coturn.POST("/servers/bulk-test", adminHandler.BulkTestCoturnServers)
			coturn.GET("/regions", adminHandler.GetCoturnRegions)
		}

		// System Management
		system := admin.Group("/system")
		{
			system.GET("/info", adminHandler.GetSystemInfo)
			system.GET("/health", adminHandler.GetSystemHealth)
			system.GET("/logs", adminHandler.GetSystemLogs)
			system.POST("/maintenance", adminHandler.ToggleMaintenanceMode)
			system.POST("/clear-cache", adminHandler.ClearCache)
			system.GET("/database/stats", adminHandler.GetDatabaseStats)
			system.POST("/database/cleanup", adminHandler.CleanupDatabase)
			system.GET("/backup", adminHandler.CreateBackup)
			system.POST("/restore", adminHandler.RestoreBackup)
		}

		// Analytics & Reports
		analytics := admin.Group("/analytics")
		{
			analytics.GET("/overview", adminHandler.GetAnalyticsOverview)
			analytics.GET("/users", adminHandler.GetUserAnalytics)
			analytics.GET("/chats", adminHandler.GetChatAnalytics)
			analytics.GET("/regions", adminHandler.GetRegionAnalytics)
			analytics.GET("/performance", adminHandler.GetPerformanceAnalytics)
			analytics.GET("/revenue", adminHandler.GetRevenueAnalytics)
			analytics.GET("/export", adminHandler.ExportAnalytics)
			analytics.GET("/custom", adminHandler.GetCustomAnalytics)
		}

		// Content Management
		content := admin.Group("/content")
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
		notifications := admin.Group("/notifications")
		{
			notifications.GET("/templates", adminHandler.GetNotificationTemplates)
			notifications.PUT("/templates/:id", adminHandler.UpdateNotificationTemplate)
			notifications.POST("/send", adminHandler.SendNotification)
			notifications.GET("/history", adminHandler.GetNotificationHistory)
			notifications.GET("/settings", adminHandler.GetNotificationSettings)
			notifications.PUT("/settings", adminHandler.UpdateNotificationSettings)
		}

		// API Management
		api := admin.Group("/api")
		{
			api.GET("/keys", adminHandler.GetAPIKeys)
			api.POST("/keys", adminHandler.CreateAPIKey)
			api.DELETE("/keys/:id", adminHandler.RevokeAPIKey)
			api.GET("/usage", adminHandler.GetAPIUsage)
			api.GET("/rate-limits", adminHandler.GetRateLimits)
			api.PUT("/rate-limits", adminHandler.UpdateRateLimits)
		}

		// File Management
		files := admin.Group("/files")
		{
			files.POST("/upload", adminHandler.UploadFile)
			files.GET("/", adminHandler.GetFiles)
			files.DELETE("/:id", adminHandler.DeleteFile)
			files.GET("/storage-info", adminHandler.GetStorageInfo)
			files.POST("/cleanup", adminHandler.CleanupFiles)
		}
	}
}
