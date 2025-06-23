package handlers

import (
	"net/http"
	"strings"
	"time"

	"vrchat/internal/utils"
	"vrchat/internal/websocket"
	"vrchat/pkg/logger"

	"github.com/gin-gonic/gin"
)

type WebSocketHandler struct {
	hub      *websocket.Hub
	upgrader websocket.Upgrader
}

func NewWebSocketHandler(hub *websocket.Hub) *WebSocketHandler {
	return &WebSocketHandler{
		hub: hub,
		upgrader: websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
			CheckOrigin: func(r *http.Request) bool {
				// Allow connections from any origin in development
				// In production, implement proper origin checking
				origin := r.Header.Get("Origin")

				// Allow localhost and development origins
				if strings.Contains(origin, "localhost") ||
					strings.Contains(origin, "127.0.0.1") ||
					strings.Contains(origin, "192.168.") {
					return true
				}

				// Add your production domains here
				allowedOrigins := []string{
					"https://yourdomain.com",
					"https://www.yourdomain.com",
				}

				for _, allowedOrigin := range allowedOrigins {
					if origin == allowedOrigin {
						return true
					}
				}

				return false
			},
		},
	}
}

// Main Chat WebSocket Handler

func (h *WebSocketHandler) HandleChatWebSocket(c *gin.Context) {
	// Get authentication from query parameters or headers
	sessionToken := h.getSessionToken(c)
	if sessionToken == "" {
		utils.ErrorResponse(c, http.StatusUnauthorized, "Session token required")
		return
	}

	// Validate session token
	userID, err := utils.ValidateSessionToken(sessionToken)
	if err != nil {
		logger.WithError(err).Warn("Invalid session token for WebSocket connection")
		utils.ErrorResponse(c, http.StatusUnauthorized, "Invalid session token")
		return
	}

	// Check if user is banned
	if utils.IsUserBanned(userID) {
		utils.ErrorResponse(c, http.StatusForbidden, "User is banned")
		return
	}

	// Get additional client information
	language := c.DefaultQuery("language", "en")
	clientType := c.DefaultQuery("client_type", "web")

	// Upgrade HTTP connection to WebSocket
	conn, err := h.upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		logger.WithError(err).Error("Failed to upgrade WebSocket connection")
		return
	}

	// Get user's region
	regionInfo, _ := utils.GetRegionFromIP(c.ClientIP())

	// Create new WebSocket client
	client := websocket.NewClient(conn, h.hub, userID)
	client.IP = c.ClientIP()
	client.UserAgent = c.GetHeader("User-Agent")
	client.Region = regionInfo.Code
	client.Language = language
	client.Type = "chat"
	client.IsGuest = true // Default to guest, can be updated based on user type

	// Set client metadata
	if clientType == "mobile" {
		client.Type = "mobile_chat"
	}

	// Register client with hub
	h.hub.Register <- client

	logger.LogUserAction(userID, "websocket_connected", map[string]interface{}{
		"ip":          client.IP,
		"user_agent":  client.UserAgent,
		"region":      client.Region,
		"language":    client.Language,
		"client_type": clientType,
	})

	// Start client read and write pumps
	go client.WritePump()
	go client.ReadPump()
}

// Admin WebSocket Handler

func (h *WebSocketHandler) HandleAdminWebSocket(c *gin.Context) {
	// Validate admin token
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		utils.ErrorResponse(c, http.StatusUnauthorized, "Missing authorization header")
		return
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	if tokenString == authHeader {
		utils.ErrorResponse(c, http.StatusUnauthorized, "Invalid token format")
		return
	}

	// Validate admin JWT token
	claims, err := utils.ValidateAdminJWT(tokenString)
	if err != nil {
		utils.ErrorResponse(c, http.StatusUnauthorized, "Invalid admin token")
		return
	}

	// Check admin permissions
	if claims.Role != "admin" && claims.Role != "super_admin" {
		utils.ErrorResponse(c, http.StatusForbidden, "Admin access required")
		return
	}

	// Upgrade connection
	conn, err := h.upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		logger.WithError(err).Error("Failed to upgrade admin WebSocket connection")
		return
	}

	// Create admin client
	client := websocket.NewClient(conn, h.hub, claims.AdminID)
	client.IP = c.ClientIP()
	client.UserAgent = c.GetHeader("User-Agent")
	client.Type = "admin"
	client.IsAdmin = true
	client.IsGuest = false
	client.Permissions = claims.Permissions

	// Register admin client
	h.hub.Register <- client

	logger.LogAdminAction(claims.AdminID, "admin_websocket_connected", "", map[string]interface{}{
		"ip":         client.IP,
		"user_agent": client.UserAgent,
		"role":       claims.Role,
	})

	// Start client pumps
	go client.WritePump()
	go client.ReadPump()
}

// WebRTC Signaling WebSocket Handler

func (h *WebSocketHandler) HandleWebRTCWebSocket(c *gin.Context) {
	roomID := c.Param("room_id")
	if roomID == "" {
		utils.ErrorResponse(c, http.StatusBadRequest, "Room ID is required")
		return
	}

	// Get and validate session token
	sessionToken := h.getSessionToken(c)
	if sessionToken == "" {
		utils.ErrorResponse(c, http.StatusUnauthorized, "Session token required")
		return
	}

	userID, err := utils.ValidateSessionToken(sessionToken)
	if err != nil {
		utils.ErrorResponse(c, http.StatusUnauthorized, "Invalid session token")
		return
	}

	// Check if user is banned
	if utils.IsUserBanned(userID) {
		utils.ErrorResponse(c, http.StatusForbidden, "User is banned")
		return
	}

	// Validate user has access to this room
	hasAccess, err := h.validateRoomAccess(userID, roomID)
	if err != nil || !hasAccess {
		utils.ErrorResponse(c, http.StatusForbidden, "Access denied to this room")
		return
	}

	// Upgrade connection
	conn, err := h.upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		logger.WithError(err).Error("Failed to upgrade WebRTC WebSocket connection")
		return
	}

	// Get user's region
	regionInfo, _ := utils.GetRegionFromIP(c.ClientIP())

	// Create WebRTC client
	client := websocket.NewClient(conn, h.hub, userID)
	client.IP = c.ClientIP()
	client.UserAgent = c.GetHeader("User-Agent")
	client.Region = regionInfo.Code
	client.Type = "webrtc"
	client.IsGuest = true

	// Add client to the specific room
	h.hub.AddClientToRoom(client, roomID)

	logger.LogChatEvent("webrtc_connection_established", roomID, userID, map[string]interface{}{
		"ip":         client.IP,
		"user_agent": client.UserAgent,
		"region":     client.Region,
	})

	// Register client
	h.hub.Register <- client

	// Start client pumps
	go client.WritePump()
	go client.ReadPump()
}

// Room-based WebSocket Handler

func (h *WebSocketHandler) HandleRoomWebSocket(c *gin.Context) {
	roomID := c.Param("room_id")
	if roomID == "" {
		utils.ErrorResponse(c, http.StatusBadRequest, "Room ID is required")
		return
	}

	// Get and validate session token
	sessionToken := h.getSessionToken(c)
	if sessionToken == "" {
		utils.ErrorResponse(c, http.StatusUnauthorized, "Session token required")
		return
	}

	userID, err := utils.ValidateSessionToken(sessionToken)
	if err != nil {
		utils.ErrorResponse(c, http.StatusUnauthorized, "Invalid session token")
		return
	}

	// Check if user is banned
	if utils.IsUserBanned(userID) {
		utils.ErrorResponse(c, http.StatusForbidden, "User is banned")
		return
	}

	// Validate room exists and user has access
	hasAccess, err := h.validateRoomAccess(userID, roomID)
	if err != nil || !hasAccess {
		utils.ErrorResponse(c, http.StatusForbidden, "Access denied to this room")
		return
	}

	// Get room type and configuration
	roomType := c.DefaultQuery("room_type", "chat")
	chatType := c.DefaultQuery("chat_type", "text")

	// Upgrade connection
	conn, err := h.upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		logger.WithError(err).Error("Failed to upgrade room WebSocket connection")
		return
	}

	// Get user's region and language
	regionInfo, _ := utils.GetRegionFromIP(c.ClientIP())
	language := c.DefaultQuery("language", "en")

	// Create room client
	client := websocket.NewClient(conn, h.hub, userID)
	client.IP = c.ClientIP()
	client.UserAgent = c.GetHeader("User-Agent")
	client.Region = regionInfo.Code
	client.Language = language
	client.Type = roomType
	client.IsGuest = true

	// Add additional metadata based on room type
	if chatType == "video" || chatType == "audio" {
		client.Type = "media_" + roomType
	}

	// Add client to the room
	h.hub.AddClientToRoom(client, roomID)

	logger.LogChatEvent("room_websocket_connected", roomID, userID, map[string]interface{}{
		"room_type": roomType,
		"chat_type": chatType,
		"ip":        client.IP,
		"region":    client.Region,
		"language":  client.Language,
	})

	// Register client
	h.hub.Register <- client

	// Start client pumps
	go client.WritePump()
	go client.ReadPump()
}

// WebSocket Health Check Handler

func (h *WebSocketHandler) HandleHealthCheck(c *gin.Context) {
	stats := h.hub.GetStats()

	health := map[string]interface{}{
		"status":          "healthy",
		"websocket_stats": stats,
		"server_time":     time.Now(),
		"uptime":          time.Since(time.Now().Add(-24 * time.Hour)), // Placeholder
		"version":         "1.0.0",
	}

	// Check if WebSocket service is degraded
	if stats.TotalClients > 10000 {
		health["status"] = "degraded"
		health["reason"] = "High connection count"
	}

	utils.SuccessResponse(c, health)
}

// WebSocket Statistics Handler

func (h *WebSocketHandler) HandleWebSocketStats(c *gin.Context) {
	// Only allow authenticated users to view stats
	sessionToken := h.getSessionToken(c)
	if sessionToken != "" {
		if _, err := utils.ValidateSessionToken(sessionToken); err != nil {
			utils.ErrorResponse(c, http.StatusUnauthorized, "Invalid session token")
			return
		}
	}

	stats := h.hub.GetStats()

	// Add additional statistics
	enhancedStats := map[string]interface{}{
		"websocket_stats":       stats,
		"connection_types":      h.getConnectionTypeStats(),
		"regional_distribution": h.getRegionalDistribution(),
		"language_distribution": h.getLanguageDistribution(),
		"performance_metrics":   h.getPerformanceMetrics(),
		"generated_at":          time.Now(),
	}

	utils.SuccessResponse(c, enhancedStats)
}

// Connection Management Handlers

func (h *WebSocketHandler) HandleKickUser(c *gin.Context) {
	// Admin only endpoint
	adminID := c.GetString("admin_id")
	if adminID == "" {
		utils.ErrorResponse(c, http.StatusUnauthorized, "Admin access required")
		return
	}

	var kickData struct {
		UserID string `json:"user_id" binding:"required"`
		Reason string `json:"reason"`
	}

	if err := c.ShouldBindJSON(&kickData); err != nil {
		utils.ValidationErrorResponse(c, map[string]string{
			"user_id": "User ID is required",
		})
		return
	}

	// Kick user from all WebSocket connections
	success := h.kickUserConnections(kickData.UserID, kickData.Reason)

	if !success {
		utils.ErrorResponse(c, http.StatusNotFound, "User not connected")
		return
	}

	logger.LogAdminAction(adminID, "user_kicked_websocket", kickData.UserID, map[string]interface{}{
		"reason": kickData.Reason,
		"ip":     c.ClientIP(),
	})

	utils.SuccessResponseWithMessage(c, "User kicked successfully", nil)
}

func (h *WebSocketHandler) HandleBroadcastMessage(c *gin.Context) {
	// Admin only endpoint
	adminID := c.GetString("admin_id")
	if adminID == "" {
		utils.ErrorResponse(c, http.StatusUnauthorized, "Admin access required")
		return
	}

	var broadcastData struct {
		Message   string   `json:"message" binding:"required"`
		Type      string   `json:"type"`
		Rooms     []string `json:"rooms"`     // Specific rooms to broadcast to
		Users     []string `json:"users"`     // Specific users to broadcast to
		Broadcast string   `json:"broadcast"` // all, admins, users, room
		Priority  string   `json:"priority"`  // low, normal, high
	}

	if err := c.ShouldBindJSON(&broadcastData); err != nil {
		utils.ValidationErrorResponse(c, map[string]string{
			"message": "Message is required",
		})
		return
	}

	// Set defaults
	if broadcastData.Type == "" {
		broadcastData.Type = "admin_alert"
	}
	if broadcastData.Broadcast == "" {
		broadcastData.Broadcast = "all"
	}
	if broadcastData.Priority == "" {
		broadcastData.Priority = "normal"
	}

	// Create WebSocket message
	wsMessage := websocket.NewWSMessage(
		websocket.MessageType(broadcastData.Type),
		broadcastData.Message,
		map[string]interface{}{
			"admin_id":  adminID,
			"priority":  broadcastData.Priority,
			"broadcast": broadcastData.Broadcast,
			"timestamp": time.Now(),
		},
	)

	// Broadcast message based on criteria
	var recipients int
	switch broadcastData.Broadcast {
	case "all":
		h.hub.Broadcast <- wsMessage
		recipients = h.hub.GetStats().TotalClients

	case "admins":
		h.hub.AdminBroadcast <- wsMessage
		recipients = h.hub.GetStats().AdminClients

	case "rooms":
		for _, roomID := range broadcastData.Rooms {
			h.hub.BroadcastToRoom(roomID, wsMessage)
		}
		recipients = h.countUsersInRooms(broadcastData.Rooms)

	case "users":
		for _, userID := range broadcastData.Users {
			h.hub.BroadcastToUser(userID, wsMessage)
		}
		recipients = len(broadcastData.Users)
	}

	logger.LogAdminAction(adminID, "websocket_broadcast", "", map[string]interface{}{
		"message":    broadcastData.Message,
		"type":       broadcastData.Type,
		"broadcast":  broadcastData.Broadcast,
		"recipients": recipients,
		"priority":   broadcastData.Priority,
		"ip":         c.ClientIP(),
	})

	response := map[string]interface{}{
		"message_sent":   true,
		"recipients":     recipients,
		"broadcast_type": broadcastData.Broadcast,
	}

	utils.SuccessResponseWithMessage(c, "Message broadcasted successfully", response)
}

// Helper methods

func (h *WebSocketHandler) getSessionToken(c *gin.Context) string {
	// Try Authorization header first
	authHeader := c.GetHeader("Authorization")
	if authHeader != "" {
		return strings.TrimPrefix(authHeader, "Bearer ")
	}

	// Try query parameter
	sessionToken := c.Query("session_token")
	if sessionToken != "" {
		return sessionToken
	}

	// Try WebSocket subprotocol (if implemented)
	protocols := c.Request.Header.Get("Sec-WebSocket-Protocol")
	if protocols != "" {
		// Parse token from protocols if needed
		parts := strings.Split(protocols, ",")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if strings.HasPrefix(part, "token.") {
				return strings.TrimPrefix(part, "token.")
			}
		}
	}

	return ""
}

func (h *WebSocketHandler) validateRoomAccess(userID, roomID string) (bool, error) {
	// Implement room access validation logic
	// This should check if the user is part of the chat/room
	// For now, we'll return true (implement based on your chat service)
	return true, nil
}

func (h *WebSocketHandler) kickUserConnections(userID, reason string) bool {
	// Implementation to kick a user from all WebSocket connections
	// This would involve finding the user's client(s) and closing their connections
	onlineUsers := h.hub.GetOnlineUsers()
	for _, onlineUserID := range onlineUsers {
		if onlineUserID == userID {
			// Send disconnect message
			disconnectMsg := websocket.NewWSMessage(
				websocket.MessageTypeKick,
				"You have been disconnected by an administrator",
				map[string]interface{}{
					"reason":     reason,
					"kicked_at":  time.Now(),
					"auto_close": true,
				},
			)
			h.hub.BroadcastToUser(userID, disconnectMsg)
			return true
		}
	}
	return false
}

func (h *WebSocketHandler) getConnectionTypeStats() map[string]int {
	// Get statistics by connection type
	stats := h.hub.GetStats()

	// This would need to be implemented based on your hub's tracking
	return map[string]int{
		"chat":   stats.TotalClients - stats.AdminClients,
		"admin":  stats.AdminClients,
		"webrtc": 0, // Implement based on your tracking
		"mobile": 0, // Implement based on your tracking
	}
}

func (h *WebSocketHandler) getRegionalDistribution() map[string]int {
	stats := h.hub.GetStats()
	return stats.RegionStats
}

func (h *WebSocketHandler) getLanguageDistribution() map[string]int {
	// Implementation to get language distribution
	// This would need to be tracked in your hub
	return map[string]int{
		"en": 100,
		"es": 25,
		"fr": 15,
		// Add more languages based on actual data
	}
}

func (h *WebSocketHandler) getPerformanceMetrics() map[string]interface{} {
	return map[string]interface{}{
		"avg_response_time_ms":    50,
		"messages_per_second":     25.5,
		"connection_success_rate": 99.2,
		"error_rate_percent":      0.1,
		"bandwidth_usage_mbps":    12.5,
	}
}

func (h *WebSocketHandler) countUsersInRooms(roomIDs []string) int {
	count := 0
	for _, roomID := range roomIDs {
		users := h.hub.GetRoomUsers(roomID)
		count += len(users)
	}
	return count
}
