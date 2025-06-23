// cmd/server/main.go - CLEANED VERSION
package main

import (
	"log"
	"os"

	"vrchat/internal/config"
	"vrchat/internal/routes"
	"vrchat/internal/websocket"
	"vrchat/pkg/database"
	"vrchat/pkg/logger"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func main() {
	// Load environment variables
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found")
	}

	// Initialize logger
	logger.Init()

	// Load configuration
	cfg := config.Load()

	log.Println("🚀 Starting Omegle Clone Application...")

	// Initialize database connection
	log.Println("📡 Connecting to MongoDB...")
	if err := database.InitMongoDB(cfg.Database.MongoDB); err != nil {
		logger.Fatal("Failed to connect to MongoDB: " + err.Error())
	}

	// Initialize WebSocket hub
	log.Println("🔌 Initializing WebSocket hub...")
	hub := websocket.NewHub()
	go hub.Run()

	// Initialize Gin router
	if cfg.App.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.Default()

	// Setup routes
	routes.SetupRoutes(router, hub)

	// Start server
	port := os.Getenv("PORT")
	if port == "" {
		port = cfg.App.Port
	}

	logger.Info("🚀 Server starting on port: " + port)
	logger.Info("🌐 Environment: " + cfg.App.Environment)
	logger.Info("💡 Run 'make migrate' or 'go run scripts/migrate.go' to setup database")

	if err := router.Run(":" + port); err != nil {
		logger.Fatal("Failed to start server: " + err.Error())
	}
}
