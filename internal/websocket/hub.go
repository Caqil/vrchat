package websocket

import (
	"context"
	"sync"
	"time"

	"vrchat/pkg/database"
	"vrchat/pkg/logger"

	"go.mongodb.org/mongo-driver/bson"
)

// Hub maintains the set of active clients and broadcasts messages
type Hub struct {
	// Registered clients
	clients map[*Client]bool

	// Clients organized by user ID
	userClients map[string]*Client

	// Clients organized by room ID
	roomClients map[string]map[*Client]bool

	// Admin clients for monitoring
	adminClients map[*Client]bool

	// Register requests from clients
	Register chan *Client

	// Unregister requests from clients
	Unregister chan *Client

	// Broadcast messages to all clients
	Broadcast chan *WSMessage

	// Broadcast messages to specific room
	RoomBroadcast chan *RoomMessage

	// Broadcast messages to specific user
	UserBroadcast chan *UserMessage

	// Admin broadcast for monitoring
	AdminBroadcast chan *WSMessage

	// Statistics
	stats *HubStats

	// Synchronization
	mu sync.RWMutex
}

// RoomMessage represents a message to be sent to a room
type RoomMessage struct {
	RoomID  string
	Message *WSMessage
	Exclude string // User ID to exclude from broadcast
}

// UserMessage represents a message to be sent to a user
type UserMessage struct {
	UserID  string
	Message *WSMessage
}

// HubStats contains hub statistics
type HubStats struct {
	TotalClients   int            `json:"total_clients"`
	OnlineUsers    int            `json:"online_users"`
	ActiveRooms    int            `json:"active_rooms"`
	AdminClients   int            `json:"admin_clients"`
	MessagesPerMin int            `json:"messages_per_minute"`
	RoomStats      map[string]int `json:"room_stats"`
	RegionStats    map[string]int `json:"region_stats"`
	LastUpdated    time.Time      `json:"last_updated"`
	mu             sync.RWMutex
}

// NewHub creates a new WebSocket hub
func NewHub() *Hub {
	return &Hub{
		clients:        make(map[*Client]bool),
		userClients:    make(map[string]*Client),
		roomClients:    make(map[string]map[*Client]bool),
		adminClients:   make(map[*Client]bool),
		Register:       make(chan *Client),
		Unregister:     make(chan *Client),
		Broadcast:      make(chan *WSMessage),
		RoomBroadcast:  make(chan *RoomMessage),
		UserBroadcast:  make(chan *UserMessage),
		AdminBroadcast: make(chan *WSMessage),
		stats: &HubStats{
			RoomStats:   make(map[string]int),
			RegionStats: make(map[string]int),
			LastUpdated: time.Now(),
		},
	}
}

// Run starts the hub and handles client registration/unregistration
func (h *Hub) Run() {
	// Start periodic tasks
	go h.startPeriodicTasks()

	for {
		select {
		case client := <-h.Register:
			h.registerClient(client)

		case client := <-h.Unregister:
			h.unregisterClient(client)

		case message := <-h.Broadcast:
			h.broadcastToAll(message)

		case roomMsg := <-h.RoomBroadcast:
			h.broadcastToRoom(roomMsg)

		case userMsg := <-h.UserBroadcast:
			h.broadcastToUser(userMsg)

		case adminMsg := <-h.AdminBroadcast:
			h.broadcastToAdmins(adminMsg)
		}
	}
}

// registerClient registers a new client
func (h *Hub) registerClient(client *Client) {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Add to main clients map
	h.clients[client] = true

	// Add to user clients map
	h.userClients[client.UserID] = client

	// Add to admin clients if admin
	if client.IsAdmin {
		h.adminClients[client] = true
	}

	// Update statistics
	h.updateStats()

	logger.WithFields(map[string]interface{}{
		"user_id":       client.UserID,
		"total_clients": len(h.clients),
		"client_type":   client.Type,
	}).Info("Client registered")

	// Send welcome message
	welcomeMsg := NewWSMessage(MessageTypeSuccess, "Connected successfully", map[string]interface{}{
		"user_id":      client.UserID,
		"server_time":  time.Now(),
		"online_users": len(h.userClients),
	})
	client.SendMessage(welcomeMsg)

	// Notify admins of new connection
	if !client.IsAdmin {
		h.notifyAdminsUserJoined(client)
	}
}

// unregisterClient unregisters a client
func (h *Hub) unregisterClient(client *Client) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if _, ok := h.clients[client]; ok {
		// Remove from main clients map
		delete(h.clients, client)

		// Remove from user clients map
		delete(h.userClients, client.UserID)

		// Remove from admin clients if admin
		if client.IsAdmin {
			delete(h.adminClients, client)
		}

		// Remove from room if in one
		if client.RoomID != "" {
			h.removeClientFromRoom(client)
		}

		// Close send channel
		close(client.Send)

		// Update statistics
		h.updateStats()

		logger.WithFields(map[string]interface{}{
			"user_id":       client.UserID,
			"total_clients": len(h.clients),
			"room_id":       client.RoomID,
		}).Info("Client unregistered")

		// Notify room if client was in one
		if client.RoomID != "" {
			h.notifyRoomUserLeft(client)
		}

		// Notify admins of disconnection
		if !client.IsAdmin {
			h.notifyAdminsUserLeft(client)
		}
	}
}

// addClientToRoom adds a client to a room
func (h *Hub) AddClientToRoom(client *Client, roomID string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Remove from previous room if in one
	if client.RoomID != "" {
		h.removeClientFromRoom(client)
	}

	// Add to new room
	if h.roomClients[roomID] == nil {
		h.roomClients[roomID] = make(map[*Client]bool)
	}
	h.roomClients[roomID][client] = true
	client.SetRoomID(roomID)

	// Update statistics
	h.updateStats()

	logger.LogChatEvent("user_joined_room", roomID, client.UserID, map[string]interface{}{
		"room_size": len(h.roomClients[roomID]),
	})

	// Notify room of new user
	h.notifyRoomUserJoined(client, roomID)
}

// removeClientFromRoom removes a client from their current room
func (h *Hub) removeClientFromRoom(client *Client) {
	if client.RoomID == "" {
		return
	}

	roomID := client.RoomID

	if roomClients, exists := h.roomClients[roomID]; exists {
		delete(roomClients, client)

		// Remove room if empty
		if len(roomClients) == 0 {
			delete(h.roomClients, roomID)
		}
	}

	client.SetRoomID("")

	logger.LogChatEvent("user_left_room", roomID, client.UserID, nil)
}

// broadcastToAll broadcasts a message to all connected clients
func (h *Hub) broadcastToAll(message *WSMessage) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	data, err := message.ToJSON()
	if err != nil {
		logger.WithError(err).Error("Failed to marshal broadcast message")
		return
	}

	for client := range h.clients {
		select {
		case client.Send <- data:
		default:
			// Client send buffer is full, remove client
			h.Unregister <- client
		}
	}
}

// broadcastToRoom broadcasts a message to all clients in a room
func (h *Hub) broadcastToRoom(roomMsg *RoomMessage) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	roomClients, exists := h.roomClients[roomMsg.RoomID]
	if !exists {
		return
	}

	data, err := roomMsg.Message.ToJSON()
	if err != nil {
		logger.WithError(err).Error("Failed to marshal room message")
		return
	}

	for client := range roomClients {
		// Skip excluded user
		if roomMsg.Exclude != "" && client.UserID == roomMsg.Exclude {
			continue
		}

		select {
		case client.Send <- data:
		default:
			h.Unregister <- client
		}
	}
}

// broadcastToUser broadcasts a message to a specific user
func (h *Hub) broadcastToUser(userMsg *UserMessage) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	client, exists := h.userClients[userMsg.UserID]
	if !exists {
		return
	}

	client.SendMessage(userMsg.Message)
}

// broadcastToAdmins broadcasts a message to all admin clients
func (h *Hub) broadcastToAdmins(message *WSMessage) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	data, err := message.ToJSON()
	if err != nil {
		logger.WithError(err).Error("Failed to marshal admin message")
		return
	}

	for client := range h.adminClients {
		select {
		case client.Send <- data:
		default:
			h.Unregister <- client
		}
	}
}

// Public methods for broadcasting

// BroadcastToRoom broadcasts a message to a room
func (h *Hub) BroadcastToRoom(roomID string, message *WSMessage) {
	h.RoomBroadcast <- &RoomMessage{
		RoomID:  roomID,
		Message: message,
	}
}

// BroadcastToRoomExcept broadcasts a message to a room except one user
func (h *Hub) BroadcastToRoomExcept(roomID, excludeUserID string, message *WSMessage) {
	h.RoomBroadcast <- &RoomMessage{
		RoomID:  roomID,
		Message: message,
		Exclude: excludeUserID,
	}
}

// BroadcastToUser broadcasts a message to a specific user
func (h *Hub) BroadcastToUser(userID string, message *WSMessage) {
	h.UserBroadcast <- &UserMessage{
		UserID:  userID,
		Message: message,
	}
}

// BroadcastTyping broadcasts typing indicator
func (h *Hub) BroadcastTyping(roomID, userID string, isTyping bool) {
	msgType := MessageTypeStopTyping
	if isTyping {
		msgType = MessageTypeTyping
	}

	message := NewWSMessage(msgType, "", map[string]interface{}{
		"user_id": userID,
	})

	h.BroadcastToRoomExcept(roomID, userID, message)
}

// BroadcastWebRTC broadcasts WebRTC signaling
func (h *Hub) BroadcastWebRTC(roomID, signalType, fromUserID string, data interface{}) {
	message := NewWSMessage(MessageType(signalType), "", map[string]interface{}{
		"from": fromUserID,
		"data": data,
	})
	message.SetRoomID(roomID)

	h.BroadcastToRoomExcept(roomID, fromUserID, message)
}

// Notification methods

func (h *Hub) notifyRoomUserJoined(client *Client, roomID string) {
	message := NewWSMessage(MessageTypeUserJoined, "", map[string]interface{}{
		"user_id":  client.UserID,
		"region":   client.Region,
		"is_guest": client.IsGuest,
	})
	message.SetRoomID(roomID)

	h.BroadcastToRoomExcept(roomID, client.UserID, message)
}

func (h *Hub) notifyRoomUserLeft(client *Client) {
	message := NewWSMessage(MessageTypeUserLeft, "", map[string]interface{}{
		"user_id": client.UserID,
	})
	message.SetRoomID(client.RoomID)

	h.BroadcastToRoomExcept(client.RoomID, client.UserID, message)
}

func (h *Hub) notifyAdminsUserJoined(client *Client) {
	message := NewWSMessage(MessageTypeUserJoined, "", map[string]interface{}{
		"user_id":    client.UserID,
		"ip":         client.IP,
		"region":     client.Region,
		"user_agent": client.UserAgent,
		"timestamp":  time.Now(),
	})

	h.AdminBroadcast <- message
}

func (h *Hub) notifyAdminsUserLeft(client *Client) {
	message := NewWSMessage(MessageTypeUserLeft, "", map[string]interface{}{
		"user_id":   client.UserID,
		"duration":  time.Since(client.ConnectedAt).Seconds(),
		"timestamp": time.Now(),
	})

	h.AdminBroadcast <- message
}

// Statistics and monitoring

func (h *Hub) updateStats() {
	h.stats.mu.Lock()
	defer h.stats.mu.Unlock()

	h.stats.TotalClients = len(h.clients)
	h.stats.OnlineUsers = len(h.userClients)
	h.stats.ActiveRooms = len(h.roomClients)
	h.stats.AdminClients = len(h.adminClients)
	h.stats.LastUpdated = time.Now()

	// Update room stats
	h.stats.RoomStats = make(map[string]int)
	for roomID, clients := range h.roomClients {
		h.stats.RoomStats[roomID] = len(clients)
	}

	// Update region stats
	h.stats.RegionStats = make(map[string]int)
	for client := range h.clients {
		if client.Region != "" {
			h.stats.RegionStats[client.Region]++
		}
	}
}

// GetStats returns current hub statistics
func (h *Hub) GetStats() *HubStats {
	h.stats.mu.RLock()
	defer h.stats.mu.RUnlock()

	// Create copy to avoid race conditions
	statsCopy := &HubStats{
		TotalClients:   h.stats.TotalClients,
		OnlineUsers:    h.stats.OnlineUsers,
		ActiveRooms:    h.stats.ActiveRooms,
		AdminClients:   h.stats.AdminClients,
		MessagesPerMin: h.stats.MessagesPerMin,
		LastUpdated:    h.stats.LastUpdated,
		RoomStats:      make(map[string]int),
		RegionStats:    make(map[string]int),
	}

	for k, v := range h.stats.RoomStats {
		statsCopy.RoomStats[k] = v
	}

	for k, v := range h.stats.RegionStats {
		statsCopy.RegionStats[k] = v
	}

	return statsCopy
}

// GetOnlineUsers returns list of online users
func (h *Hub) GetOnlineUsers() []string {
	h.mu.RLock()
	defer h.mu.RUnlock()

	users := make([]string, 0, len(h.userClients))
	for userID := range h.userClients {
		users = append(users, userID)
	}

	return users
}

// GetRoomUsers returns users in a specific room
func (h *Hub) GetRoomUsers(roomID string) []string {
	h.mu.RLock()
	defer h.mu.RUnlock()

	roomClients, exists := h.roomClients[roomID]
	if !exists {
		return []string{}
	}

	users := make([]string, 0, len(roomClients))
	for client := range roomClients {
		users = append(users, client.UserID)
	}

	return users
}

// IsUserOnline checks if a user is online
func (h *Hub) IsUserOnline(userID string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()

	_, exists := h.userClients[userID]
	return exists
}

// Periodic tasks

func (h *Hub) startPeriodicTasks() {
	// Update statistics every 30 seconds
	statsTimer := time.NewTicker(30 * time.Second)

	// Cleanup inactive connections every 5 minutes
	cleanupTimer := time.NewTicker(5 * time.Minute)

	// Store statistics every minute
	storeStatsTimer := time.NewTicker(1 * time.Minute)

	for {
		select {
		case <-statsTimer.C:
			h.updateStats()

		case <-cleanupTimer.C:
			h.cleanupInactiveConnections()

		case <-storeStatsTimer.C:
			h.storeStatistics()
		}
	}
}

// cleanupInactiveConnections removes inactive connections
func (h *Hub) cleanupInactiveConnections() {
	h.mu.RLock()
	inactiveClients := make([]*Client, 0)

	for client := range h.clients {
		// Check if client hasn't ponged in pongWait duration
		if time.Since(client.LastPong) > pongWait {
			inactiveClients = append(inactiveClients, client)
		}
	}
	h.mu.RUnlock()

	// Remove inactive clients
	for _, client := range inactiveClients {
		logger.WithFields(map[string]interface{}{
			"user_id":   client.UserID,
			"last_pong": client.LastPong,
		}).Info("Removing inactive client")

		h.Unregister <- client
	}
}

// storeStatistics stores current statistics in database
func (h *Hub) storeStatistics() {
	stats := h.GetStats()

	db := database.GetDB()
	collection := db.Collection("websocket_stats")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	doc := bson.M{
		"timestamp":     time.Now(),
		"total_clients": stats.TotalClients,
		"online_users":  stats.OnlineUsers,
		"active_rooms":  stats.ActiveRooms,
		"admin_clients": stats.AdminClients,
		"room_stats":    stats.RoomStats,
		"region_stats":  stats.RegionStats,
	}

	_, err := collection.InsertOne(ctx, doc)
	if err != nil {
		logger.WithError(err).Error("Failed to store WebSocket statistics")
	}
}
