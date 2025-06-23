package routes

import (
	"vrchat/internal/handlers"
	"vrchat/internal/middleware"
	"vrchat/internal/websocket"

	"github.com/gin-gonic/gin"
)

func SetupWebSocketRoutes(router *gin.Engine, hub *websocket.Hub) {
	wsHandler := handlers.NewWebSocketHandler(hub)

	// WebSocket endpoints
	ws := router.Group("/ws")
	{
		// Main chat WebSocket (with optional auth)
		ws.GET("/chat", middleware.OptionalAuth(), wsHandler.HandleChatWebSocket)

		// Admin WebSocket for real-time monitoring (requires admin auth)
		ws.GET("/admin", middleware.AdminAuth(), wsHandler.HandleAdminWebSocket)

		// WebRTC signaling WebSocket (requires session auth)
		ws.GET("/webrtc/:room_id", middleware.SessionAuth(), wsHandler.HandleWebRTCWebSocket)

		// General purpose WebSocket with room support (requires session auth)
		ws.GET("/room/:room_id", middleware.SessionAuth(), wsHandler.HandleRoomWebSocket)
	}
}
