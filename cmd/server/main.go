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

	// Initialize database
	database.InitMongoDB(cfg.MongoDB)

	// Initialize WebSocket hub
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

	logger.Info("Server starting on port: " + port)
	if err := router.Run(":" + port); err != nil {
		logger.Fatal("Failed to start server: " + err.Error())
	}
}
