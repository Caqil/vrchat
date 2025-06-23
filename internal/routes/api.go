package routes

import (
	"vrchat/internal/handlers"
	"vrchat/internal/middleware"
	"vrchat/internal/services"
	"vrchat/internal/websocket"
	"vrchat/pkg/database"

	"github.com/gin-gonic/gin"
)

func SetupRoutes(router *gin.Engine, hub *websocket.Hub) {
	// Initialize database
	db := database.GetDB()

	// Initialize services
	userService := services.NewUserService(db)
	chatService := services.NewChatService(db)
	settingsService := services.NewSettingsService(db)
	coturnService := services.NewCoturnService(db)
	matchingService := services.NewMatchingService(db)
	authService := services.NewAuthService(db) // We'll need to create this

	// Initialize handlers with dependencies
	userHandler := handlers.NewUserHandler(userService)
	chatHandler := handlers.NewChatHandler(chatService, matchingService, hub)
	authHandler := handlers.NewAuthHandler(authService)
	adminHandler := handlers.NewAdminHandler(userService, chatService, settingsService, coturnService)
	settingsHandler := handlers.NewSettingsHandler(settingsService)
	coturnHandler := handlers.NewCoturnHandler(coturnService)

	// Global middleware
	router.Use(middleware.CORS())
	router.Use(middleware.RateLimit())
	router.Use(middleware.Logger())

	// Health check
	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status":  "ok",
			"message": "Server is running",
		})
	})

	// API v1 routes
	v1 := router.Group("/api/v1")
	{
		// Public routes (no auth required)
		public := v1.Group("/")
		{
			// App information
			public.GET("/info", handlers.GetAppInfo)
			public.GET("/regions", handlers.GetAvailableRegions)
			//public.GET("/languages", handlers.GetSupportedLanguages)

			// Guest user creation
			public.POST("/guest", userHandler.CreateGuest)
			public.GET("/guest/:id", userHandler.GetGuest)

			// WebSocket connection
			public.GET("/ws", chatHandler.HandleWebSocket)

			// COTURN/STUN servers for guest users
			public.GET("/ice-servers", coturnHandler.GetICEServers)

			// App settings (public ones)
			public.GET("/settings/public", settingsHandler.GetPublicSettings)
		}

		// Protected routes (require user session)
		protected := v1.Group("/")
		protected.Use(middleware.SessionAuth())
		{
			// User management
			user := protected.Group("/user")
			{
				user.GET("/profile", userHandler.GetProfile)
				user.PUT("/profile", userHandler.UpdateProfile)
				user.POST("/report", userHandler.ReportUser)
				user.GET("/history", userHandler.GetChatHistory)
				user.DELETE("/history", userHandler.ClearHistory)
				user.POST("/feedback", userHandler.SubmitFeedback)
			}

			// Chat management
			chat := protected.Group("/chat")
			{
				chat.POST("/start", chatHandler.StartChat)
				chat.POST("/join/:room_id", chatHandler.JoinChat)
				chat.POST("/leave/:room_id", chatHandler.LeaveChat)
				chat.GET("/active", chatHandler.GetActiveChats)
				chat.POST("/message", chatHandler.SendMessage)
				chat.GET("/:room_id/messages", chatHandler.GetMessages)
				chat.POST("/:room_id/typing", chatHandler.SendTyping)
				chat.POST("/:room_id/report", chatHandler.ReportChat)
			}

			// Matching system
			match := protected.Group("/match")
			{
				match.POST("/find", chatHandler.FindMatch)
				match.POST("/next", chatHandler.FindNextMatch)
				match.POST("/skip", chatHandler.SkipCurrentMatch)
				match.GET("/queue", chatHandler.GetQueueStatus)
				match.POST("/preferences", chatHandler.UpdateMatchPreferences)
			}

			// WebRTC signaling
			webrtc := protected.Group("/webrtc")
			{
				webrtc.POST("/offer", chatHandler.SendOffer)
				webrtc.POST("/answer", chatHandler.SendAnswer)
				webrtc.POST("/ice-candidate", chatHandler.SendICECandidate)
				webrtc.GET("/ice-servers/:region", coturnHandler.GetRegionalICEServers)
			}
		}
	}

	// Authentication routes
	SetupAuthRoutes(router, authHandler)

	// Admin routes
	SetupAdminRoutes(router, adminHandler)

	// Static files
	router.Static("/static", "./web/static")
	router.LoadHTMLGlob("web/templates/*")
}
