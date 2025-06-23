package websocket

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"vrchat/internal/utils"
	"vrchat/pkg/database"
	"vrchat/pkg/logger"

	"github.com/gorilla/websocket"
)

const (
	// Time allowed to write a message to the peer
	writeWait = 10 * time.Second

	// Time allowed to read the next pong message from the peer
	pongWait = 60 * time.Second

	// Send pings to peer with this period. Must be less than pongWait
	pingPeriod = (pongWait * 9) / 10

	// Maximum message size allowed from peer
	maxMessageSize = 1024 * 1024 // 1MB

	// Buffer size for client send channel
	sendBufferSize = 256
)

var (
	newline = []byte{'\n'}
	space   = []byte{' '}
)

// Client represents a WebSocket client
type Client struct {
	// WebSocket connection
	Conn *websocket.Conn

	// Hub that manages this client
	Hub *Hub

	// Buffered channel of outbound messages
	Send chan []byte

	// Client information
	UserID    string
	SessionID string
	RoomID    string
	IP        string
	UserAgent string
	Region    string
	Language  string

	// Client type and permissions
	Type        string // chat, admin, webrtc
	IsAdmin     bool
	IsGuest     bool
	Permissions []string

	// Connection state
	IsConnected bool
	ConnectedAt time.Time
	LastPing    time.Time
	LastPong    time.Time

	// Rate limiting
	MessageCount    int
	LastMessage     time.Time
	MessageLimitHit bool

	// Synchronization
	mu sync.RWMutex
}

// NewClient creates a new WebSocket client
func NewClient(conn *websocket.Conn, hub *Hub, userID string) *Client {
	return &Client{
		Conn:        conn,
		Hub:         hub,
		Send:        make(chan []byte, sendBufferSize),
		UserID:      userID,
		IsConnected: true,
		ConnectedAt: time.Now(),
		LastPing:    time.Now(),
		LastPong:    time.Now(),
		Type:        "chat",
		IsGuest:     true,
	}
}

// ReadPump pumps messages from the WebSocket connection to the hub
func (c *Client) ReadPump() {
	defer func() {
		c.Hub.Unregister <- c
		c.Conn.Close()
		c.logDisconnection()
	}()

	// Set connection limits
	c.Conn.SetReadLimit(maxMessageSize)
	c.Conn.SetReadDeadline(time.Now().Add(pongWait))
	c.Conn.SetPongHandler(func(string) error {
		c.LastPong = time.Now()
		c.Conn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	c.logConnection()

	for {
		_, message, err := c.Conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				logger.WithFields(map[string]interface{}{
					"user_id": c.UserID,
					"error":   err.Error(),
				}).Error("WebSocket read error")
			}
			break
		}

		// Handle rate limiting
		if !c.checkRateLimit() {
			c.sendError("Rate limit exceeded")
			continue
		}

		// Parse and validate message
		wsMsg, err := c.parseMessage(message)
		if err != nil {
			c.sendError(fmt.Sprintf("Invalid message format: %v", err))
			continue
		}

		// Set message metadata
		wsMsg.SetFrom(c.UserID)
		if c.RoomID != "" {
			wsMsg.SetRoomID(c.RoomID)
		}

		// Validate message content
		if err := c.validateMessage(wsMsg); err != nil {
			c.sendError(fmt.Sprintf("Message validation failed: %v", err))
			continue
		}

		// Handle message based on type
		c.handleMessage(wsMsg)
	}
}

// WritePump pumps messages from the hub to the WebSocket connection
func (c *Client) WritePump() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		c.Conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.Send:
			c.Conn.SetWriteDeadline(time.Now().Add(writeWait))
			if !ok {
				c.Conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			w, err := c.Conn.NextWriter(websocket.TextMessage)
			if err != nil {
				return
			}
			w.Write(message)

			// Add queued messages to the current message
			n := len(c.Send)
			for i := 0; i < n; i++ {
				w.Write(newline)
				w.Write(<-c.Send)
			}

			if err := w.Close(); err != nil {
				return
			}

		case <-ticker.C:
			c.LastPing = time.Now()
			c.Conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.Conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// parseMessage parses incoming WebSocket message
func (c *Client) parseMessage(data []byte) (*WSMessage, error) {
	var wsMsg WSMessage
	if err := json.Unmarshal(data, &wsMsg); err != nil {
		return nil, err
	}

	// Set timestamp if not provided
	if wsMsg.Timestamp.IsZero() {
		wsMsg.Timestamp = time.Now()
	}

	return &wsMsg, nil
}

// validateMessage validates incoming message
func (c *Client) validateMessage(msg *WSMessage) error {
	// Basic validation
	if err := msg.Validate(); err != nil {
		return err
	}

	// Check if user can send this type of message
	if !c.canSendMessageType(msg.Type) {
		return fmt.Errorf("permission denied for message type: %s", msg.Type)
	}

	// Validate content for chat messages
	if msg.IsChatMessage() {
		if len(msg.Content) > 1000 {
			return fmt.Errorf("message content too long")
		}

		// Check for profanity
		if utils.ContainsProfanity(msg.Content) {
			return fmt.Errorf("message contains inappropriate content")
		}
	}

	return nil
}

// handleMessage processes different types of messages
func (c *Client) handleMessage(msg *WSMessage) {
	switch msg.Type {
	case MessageTypeText, MessageTypeImage, MessageTypeFile, MessageTypeEmoji:
		c.handleChatMessage(msg)
	case MessageTypeTyping, MessageTypeStopTyping:
		c.handleTypingIndicator(msg)
	case MessageTypeOffer, MessageTypeAnswer, MessageTypeICECandidate:
		c.handleWebRTCSignaling(msg)
	case MessageTypeHeartbeat:
		c.handleHeartbeat(msg)
	default:
		c.sendError(fmt.Sprintf("Unknown message type: %s", msg.Type))
	}
}

// handleChatMessage processes chat messages
func (c *Client) handleChatMessage(msg *WSMessage) {
	if c.RoomID == "" {
		c.sendError("Not in a chat room")
		return
	}

	// Store message in database
	chatMsg := NewChatMessage(c.RoomID, c.UserID, msg.Content, string(msg.Type), &MessageMetaData{
		UserAgent: c.UserAgent,
		IP:        c.IP,
		Region:    c.Region,
		Language:  c.Language,
	})

	if err := c.storeMessage(chatMsg); err != nil {
		logger.WithError(err).Error("Failed to store chat message")
	}

	// Broadcast to room
	c.Hub.BroadcastToRoom(c.RoomID, msg)

	// Log chat event
	logger.LogChatEvent("message_sent", c.RoomID, c.UserID, map[string]interface{}{
		"message_type":   msg.Type,
		"content_length": len(msg.Content),
	})
}

// handleTypingIndicator processes typing indicators
func (c *Client) handleTypingIndicator(msg *WSMessage) {
	if c.RoomID == "" {
		return
	}

	// Broadcast typing indicator to room (except sender)
	c.Hub.BroadcastToRoomExcept(c.RoomID, c.UserID, msg)
}

// handleWebRTCSignaling processes WebRTC signaling messages
func (c *Client) handleWebRTCSignaling(msg *WSMessage) {
	if c.RoomID == "" {
		c.sendError("Not in a chat room")
		return
	}

	// Broadcast WebRTC signal to room partner
	c.Hub.BroadcastToRoomExcept(c.RoomID, c.UserID, msg)

	logger.LogChatEvent("webrtc_signal", c.RoomID, c.UserID, map[string]interface{}{
		"signal_type": msg.Type,
	})
}

// handleHeartbeat processes heartbeat messages
func (c *Client) handleHeartbeat(msg *WSMessage) {
	// Respond with heartbeat
	response := NewWSMessage(MessageTypeHeartbeat, "", map[string]interface{}{
		"server_time": time.Now(),
		"uptime":      time.Since(c.ConnectedAt).Seconds(),
	})

	c.SendMessage(response)
}

// checkRateLimit checks if client is within rate limits
func (c *Client) checkRateLimit() bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()

	// Reset counter if minute has passed
	if now.Sub(c.LastMessage) > time.Minute {
		c.MessageCount = 0
		c.MessageLimitHit = false
	}

	c.LastMessage = now
	c.MessageCount++

	// Check limits based on client type
	var limit int
	if c.IsAdmin {
		limit = 200 // Higher limit for admins
	} else {
		limit = 60 // Regular users: 60 messages per minute
	}

	if c.MessageCount > limit {
		c.MessageLimitHit = true
		return false
	}

	return true
}

// canSendMessageType checks if client can send specific message type
func (c *Client) canSendMessageType(msgType MessageType) bool {
	// Admin can send any message type
	if c.IsAdmin {
		return true
	}

	// Regular users can send most message types
	allowedTypes := []MessageType{
		MessageTypeText, MessageTypeImage, MessageTypeFile, MessageTypeEmoji,
		MessageTypeTyping, MessageTypeStopTyping, MessageTypeOffer,
		MessageTypeAnswer, MessageTypeICECandidate, MessageTypeHeartbeat,
	}

	for _, allowed := range allowedTypes {
		if msgType == allowed {
			return true
		}
	}

	return false
}

// SendMessage sends a message to the client
func (c *Client) SendMessage(msg *WSMessage) error {
	data, err := msg.ToJSON()
	if err != nil {
		return err
	}

	select {
	case c.Send <- data:
		return nil
	default:
		// Channel is full, close connection
		close(c.Send)
		return fmt.Errorf("client send buffer full")
	}
}

// sendError sends an error message to the client
func (c *Client) sendError(message string) {
	errorMsg := NewWSMessage(MessageTypeError, message, nil)
	c.SendMessage(errorMsg)
}

// sendSuccess sends a success message to the client
func (c *Client) sendSuccess(message string, data map[string]interface{}) {
	successMsg := NewWSMessage(MessageTypeSuccess, message, data)
	c.SendMessage(successMsg)
}

// storeMessage stores chat message in database
func (c *Client) storeMessage(msg *ChatMessage) error {
	db := database.GetDatabase()
	collection := db.Collection("messages")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := collection.InsertOne(ctx, msg)
	return err
}

// SetRoomID sets the room ID for the client
func (c *Client) SetRoomID(roomID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.RoomID = roomID
}

// GetRoomID gets the room ID for the client
func (c *Client) GetRoomID() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.RoomID
}

// IsInRoom checks if client is in a specific room
func (c *Client) IsInRoom(roomID string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.RoomID == roomID
}

// UpdateLastActivity updates client's last activity time
func (c *Client) UpdateLastActivity() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.LastPong = time.Now()

	// Update user last seen in database
	go utils.UpdateUserLastSeen(c.UserID)
}

// GetConnectionInfo returns client connection information
func (c *Client) GetConnectionInfo() map[string]interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return map[string]interface{}{
		"user_id":       c.UserID,
		"room_id":       c.RoomID,
		"type":          c.Type,
		"is_admin":      c.IsAdmin,
		"is_guest":      c.IsGuest,
		"connected_at":  c.ConnectedAt,
		"last_ping":     c.LastPing,
		"last_pong":     c.LastPong,
		"message_count": c.MessageCount,
		"region":        c.Region,
		"language":      c.Language,
	}
}

// logConnection logs client connection
func (c *Client) logConnection() {
	logger.LogUserAction(c.UserID, "websocket_connected", map[string]interface{}{
		"ip":         c.IP,
		"user_agent": c.UserAgent,
		"region":     c.Region,
		"type":       c.Type,
	})
}

// logDisconnection logs client disconnection
func (c *Client) logDisconnection() {
	duration := time.Since(c.ConnectedAt)

	logger.LogUserAction(c.UserID, "websocket_disconnected", map[string]interface{}{
		"duration_seconds": duration.Seconds(),
		"message_count":    c.MessageCount,
		"room_id":          c.RoomID,
	})
}
