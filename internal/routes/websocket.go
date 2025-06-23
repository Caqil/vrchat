package routes

import (
	"vrchat/internal/handlers"
	"vrchat/internal/websocket"

	"github.com/gin-gonic/gin"
)

func SetupWebSocketRoutes(router *gin.Engine, hub *websocket.Hub) {
	wsHandler := handlers.NewWebSocketHandler(hub)

	// WebSocket endpoints
	ws := router.Group("/ws")
	{
		// Main chat WebSocket
		ws.GET("/chat", wsHandler.HandleChatWebSocket)

		// Admin WebSocket for real-time monitoring
		ws.GET("/admin", wsHandler.HandleAdminWebSocket)

		// WebRTC signaling WebSocket
		ws.GET("/webrtc/:room_id", wsHandler.HandleWebRTCWebSocket)

		// General purpose WebSocket with room support
		ws.GET("/room/:room_id", wsHandler.HandleRoomWebSocket)
	}
}
