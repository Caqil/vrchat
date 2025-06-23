package websocket

import (
	"encoding/json"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// MessageType represents different types of WebSocket messages
type MessageType string

const (
	// Chat message types
	MessageTypeText       MessageType = "text"
	MessageTypeImage      MessageType = "image"
	MessageTypeFile       MessageType = "file"
	MessageTypeEmoji      MessageType = "emoji"
	MessageTypeTyping     MessageType = "typing"
	MessageTypeStopTyping MessageType = "stop_typing"

	// System message types
	MessageTypeUserJoined  MessageType = "user_joined"
	MessageTypeUserLeft    MessageType = "user_left"
	MessageTypeRoomCreated MessageType = "room_created"
	MessageTypeRoomClosed  MessageType = "room_closed"
	MessageTypeError       MessageType = "error"
	MessageTypeSuccess     MessageType = "success"
	MessageTypeHeartbeat   MessageType = "heartbeat"

	// WebRTC signaling types
	MessageTypeOffer        MessageType = "webrtc_offer"
	MessageTypeAnswer       MessageType = "webrtc_answer"
	MessageTypeICECandidate MessageType = "webrtc_ice_candidate"
	MessageTypeHangup       MessageType = "webrtc_hangup"

	// Matching system types
	MessageTypeMatchFound  MessageType = "match_found"
	MessageTypeMatchSkip   MessageType = "match_skip"
	MessageTypeQueueUpdate MessageType = "queue_update"

	// Admin message types
	MessageTypeAdminAlert MessageType = "admin_alert"
	MessageTypeModeration MessageType = "moderation"
	MessageTypeBan        MessageType = "ban"
	MessageTypeKick       MessageType = "kick"
)

// WSMessage represents a WebSocket message
type WSMessage struct {
	ID        string                 `json:"id"`
	Type      MessageType            `json:"type"`
	Content   string                 `json:"content,omitempty"`
	Data      map[string]interface{} `json:"data,omitempty"`
	From      string                 `json:"from,omitempty"`
	To        string                 `json:"to,omitempty"`
	RoomID    string                 `json:"room_id,omitempty"`
	Timestamp time.Time              `json:"timestamp"`
	MetaData  *MessageMetaData       `json:"metadata,omitempty"`
}

// MessageMetaData contains additional message information
type MessageMetaData struct {
	UserAgent   string `json:"user_agent,omitempty"`
	IP          string `json:"ip,omitempty"`
	Region      string `json:"region,omitempty"`
	Language    string `json:"language,omitempty"`
	ChatType    string `json:"chat_type,omitempty"`
	IsEncrypted bool   `json:"is_encrypted,omitempty"`
	FileSize    int64  `json:"file_size,omitempty"`
	FileName    string `json:"file_name,omitempty"`
	FileType    string `json:"file_type,omitempty"`
}

// ChatMessage represents a chat message stored in database
type ChatMessage struct {
	ID        primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	RoomID    string             `bson:"room_id" json:"room_id"`
	UserID    string             `bson:"user_id" json:"user_id"`
	Content   string             `bson:"content" json:"content"`
	Type      string             `bson:"type" json:"type"`
	Timestamp time.Time          `bson:"timestamp" json:"timestamp"`
	Flagged   bool               `bson:"flagged" json:"flagged"`
	Edited    bool               `bson:"edited" json:"edited"`
	EditedAt  *time.Time         `bson:"edited_at,omitempty" json:"edited_at,omitempty"`
	Deleted   bool               `bson:"deleted" json:"deleted"`
	DeletedAt *time.Time         `bson:"deleted_at,omitempty" json:"deleted_at,omitempty"`
	MetaData  *MessageMetaData   `bson:"metadata,omitempty" json:"metadata,omitempty"`
}

// WebRTCSignal represents WebRTC signaling data
type WebRTCSignal struct {
	Type      string      `json:"type"`
	SDP       string      `json:"sdp,omitempty"`
	Candidate interface{} `json:"candidate,omitempty"`
	RoomID    string      `json:"room_id"`
	From      string      `json:"from"`
	To        string      `json:"to"`
}

// MatchData represents matching system data
type MatchData struct {
	MatchID   string   `json:"match_id"`
	RoomID    string   `json:"room_id"`
	Partner   UserInfo `json:"partner"`
	ChatType  string   `json:"chat_type"`
	QueueTime int64    `json:"queue_time_ms"`
	Interests []string `json:"interests,omitempty"`
	Region    string   `json:"region,omitempty"`
}

// UserInfo represents basic user information
type UserInfo struct {
	ID        string   `json:"id"`
	Region    string   `json:"region"`
	Language  string   `json:"language"`
	Interests []string `json:"interests,omitempty"`
	IsGuest   bool     `json:"is_guest"`
}

// QueueStatus represents queue information
type QueueStatus struct {
	Position      int    `json:"position"`
	EstimatedWait int    `json:"estimated_wait_seconds"`
	QueueSize     int    `json:"queue_size"`
	ChatType      string `json:"chat_type"`
}

// AdminAlert represents admin alerts
type AdminAlert struct {
	Type           string                 `json:"type"`
	Severity       string                 `json:"severity"`
	Message        string                 `json:"message"`
	Data           map[string]interface{} `json:"data,omitempty"`
	Timestamp      time.Time              `json:"timestamp"`
	RequiresAction bool                   `json:"requires_action"`
}

// NewWSMessage creates a new WebSocket message
func NewWSMessage(msgType MessageType, content string, data map[string]interface{}) *WSMessage {
	return &WSMessage{
		ID:        generateMessageID(),
		Type:      msgType,
		Content:   content,
		Data:      data,
		Timestamp: time.Now(),
	}
}

// NewChatMessage creates a new chat message for database storage
func NewChatMessage(roomID, userID, content, msgType string, metadata *MessageMetaData) *ChatMessage {
	return &ChatMessage{
		ID:        primitive.NewObjectID(),
		RoomID:    roomID,
		UserID:    userID,
		Content:   content,
		Type:      msgType,
		Timestamp: time.Now(),
		Flagged:   false,
		Edited:    false,
		Deleted:   false,
		MetaData:  metadata,
	}
}

// ToJSON converts message to JSON bytes
func (msg *WSMessage) ToJSON() ([]byte, error) {
	return json.Marshal(msg)
}

// FromJSON creates message from JSON bytes
func FromJSON(data []byte) (*WSMessage, error) {
	var msg WSMessage
	err := json.Unmarshal(data, &msg)
	return &msg, err
}

// SetFrom sets the sender of the message
func (msg *WSMessage) SetFrom(userID string) {
	msg.From = userID
}

// SetTo sets the recipient of the message
func (msg *WSMessage) SetTo(userID string) {
	msg.To = userID
}

// SetRoomID sets the room ID for the message
func (msg *WSMessage) SetRoomID(roomID string) {
	msg.RoomID = roomID
}

// AddData adds data to the message
func (msg *WSMessage) AddData(key string, value interface{}) {
	if msg.Data == nil {
		msg.Data = make(map[string]interface{})
	}
	msg.Data[key] = value
}

// GetData retrieves data from the message
func (msg *WSMessage) GetData(key string) interface{} {
	if msg.Data == nil {
		return nil
	}
	return msg.Data[key]
}

// IsSystemMessage checks if message is a system message
func (msg *WSMessage) IsSystemMessage() bool {
	systemTypes := []MessageType{
		MessageTypeUserJoined, MessageTypeUserLeft, MessageTypeRoomCreated,
		MessageTypeRoomClosed, MessageTypeError, MessageTypeSuccess,
		MessageTypeMatchFound, MessageTypeQueueUpdate, MessageTypeAdminAlert,
		MessageTypeModeration, MessageTypeBan, MessageTypeKick,
	}

	for _, sysType := range systemTypes {
		if msg.Type == sysType {
			return true
		}
	}
	return false
}

// IsChatMessage checks if message is a chat message
func (msg *WSMessage) IsChatMessage() bool {
	chatTypes := []MessageType{
		MessageTypeText, MessageTypeImage, MessageTypeFile, MessageTypeEmoji,
	}

	for _, chatType := range chatTypes {
		if msg.Type == chatType {
			return true
		}
	}
	return false
}

// IsWebRTCMessage checks if message is WebRTC signaling
func (msg *WSMessage) IsWebRTCMessage() bool {
	webrtcTypes := []MessageType{
		MessageTypeOffer, MessageTypeAnswer, MessageTypeICECandidate, MessageTypeHangup,
	}

	for _, webrtcType := range webrtcTypes {
		if msg.Type == webrtcType {
			return true
		}
	}
	return false
}

// Validate validates the message structure
func (msg *WSMessage) Validate() error {
	if msg.Type == "" {
		return fmt.Errorf("message type is required")
	}

	if msg.IsChatMessage() && msg.Content == "" {
		return fmt.Errorf("content is required for chat messages")
	}

	if msg.IsWebRTCMessage() && msg.RoomID == "" {
		return fmt.Errorf("room_id is required for WebRTC messages")
	}

	return nil
}

// generateMessageID generates a unique message ID
func generateMessageID() string {
	return primitive.NewObjectID().Hex()
}
