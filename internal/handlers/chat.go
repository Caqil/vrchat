package handlers

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"vrchat/internal/services"
	"vrchat/internal/utils"
	"vrchat/internal/websocket"
	"vrchat/pkg/logger"

	"github.com/gin-gonic/gin"
	gorillaws "github.com/gorilla/websocket"
)

type ChatHandler struct {
	chatService     *services.ChatService
	matchingService *services.MatchingService
	hub             *websocket.Hub
	upgrader        gorillaws.Upgrader // Now use the aliased gorilla websocket
}

func NewChatHandler(chatService *services.ChatService, matchingService *services.MatchingService, hub *websocket.Hub) *ChatHandler {
	return &ChatHandler{
		chatService:     chatService,
		matchingService: matchingService,
		hub:             hub,
		upgrader: gorillaws.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
			CheckOrigin: func(r *http.Request) bool {
				// Allow connections from any origin in development
				// In production, you should check the origin properly
				return true
			},
		},
	}
}

// WebSocket Connection Handler

func (h *ChatHandler) HandleWebSocket(c *gin.Context) {
	// Get user session
	sessionToken := c.Query("session_token")
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

	// Upgrade HTTP connection to WebSocket
	conn, err := h.upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		logger.WithError(err).Error("Failed to upgrade WebSocket connection")
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to upgrade connection")
		return
	}

	// Get region information
	regionInfo, _ := utils.GetRegionFromIP(c.ClientIP())

	// Create new WebSocket client
	client := websocket.NewClient(conn, h.hub, userID)
	client.IP = c.ClientIP()
	client.UserAgent = c.GetHeader("User-Agent")
	client.Region = regionInfo.Code
	client.Language = c.DefaultQuery("language", "en")
	client.Type = "chat"

	// Set client as guest if no registered user
	client.IsGuest = true

	// Register client with hub
	h.hub.Register <- client

	// Start client read and write pumps
	go client.WritePump()
	go client.ReadPump()
}

// Chat Management

func (h *ChatHandler) StartChat(c *gin.Context) {
	userID := c.GetString("user_id")

	var chatData struct {
		ChatType  string   `json:"chat_type" binding:"required"` // text, video, audio
		Language  string   `json:"language"`
		Region    string   `json:"region"`
		Interests []string `json:"interests"`
	}

	if err := c.ShouldBindJSON(&chatData); err != nil {
		utils.ValidationErrorResponse(c, map[string]string{
			"chat_type": "Chat type is required (text, video, audio)",
		})
		return
	}

	// Validate chat type
	if !utils.ValidateChatType(chatData.ChatType) {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid chat type")
		return
	}

	// Get user region if not provided
	if chatData.Region == "" {
		regionInfo, _ := utils.GetRegionFromIP(c.ClientIP())
		chatData.Region = regionInfo.Code
	}

	// Create matching preferences
	preferences := &services.MatchingPreferences{
		UserID:    userID,
		ChatType:  chatData.ChatType,
		Language:  chatData.Language,
		Region:    chatData.Region,
		Interests: chatData.Interests,
	}

	// Find match
	match, err := h.matchingService.FindMatch(preferences)
	if err != nil {
		// Add to queue if no immediate match
		queuePosition, err := h.matchingService.AddToQueue(preferences)
		if err != nil {
			utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to add to matching queue")
			return
		}

		response := map[string]interface{}{
			"status":         "queued",
			"queue_position": queuePosition,
			"estimated_wait": h.matchingService.GetEstimatedWaitTime(chatData.ChatType),
			"message":        "Looking for a match...",
		}

		utils.SuccessResponse(c, response)
		return
	}

	// Create chat room
	roomID := h.generateRoomID()
	chat, err := h.chatService.CreateChat(roomID, userID, match.PartnerID, chatData.ChatType)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to create chat")
		return
	}

	// Notify both users via WebSocket
	h.notifyMatchFound(userID, match.PartnerID, roomID, chatData.ChatType, match)

	logger.LogChatEvent("chat_started", roomID, userID, map[string]interface{}{
		"partner_id": match.PartnerID,
		"chat_type":  chatData.ChatType,
		"queue_time": match.QueueTime,
	})

	response := map[string]interface{}{
		"status":     "matched",
		"chat_id":    chat.ID.Hex(),
		"room_id":    roomID,
		"partner":    match.Partner,
		"chat_type":  chatData.ChatType,
		"started_at": chat.StartedAt,
	}

	utils.SuccessResponseWithMessage(c, "Match found", response)
}

func (h *ChatHandler) JoinChat(c *gin.Context) {
	roomID := c.Param("room_id")
	userID := c.GetString("user_id")

	// Validate room exists and user has access
	chat, err := h.chatService.GetChatByRoomID(roomID)
	if err != nil {
		utils.ErrorResponse(c, http.StatusNotFound, "Chat room not found")
		return
	}

	// Check if user is part of this chat
	if chat.User1ID.Hex() != userID && chat.User2ID.Hex() != userID {
		utils.ErrorResponse(c, http.StatusForbidden, "Access denied to this chat room")
		return
	}

	// Check if chat is still active
	if chat.Status != "active" {
		utils.ErrorResponse(c, http.StatusBadRequest, "Chat is no longer active")
		return
	}

	// Add user to WebSocket room (this would be handled by WebSocket client)
	response := map[string]interface{}{
		"room_id":    roomID,
		"chat_type":  chat.ChatType,
		"partner_id": h.getPartnerID(chat, userID),
		"started_at": chat.StartedAt,
	}

	utils.SuccessResponse(c, response)
}

func (h *ChatHandler) LeaveChat(c *gin.Context) {
	roomID := c.Param("room_id")
	userID := c.GetString("user_id")

	// End the chat
	err := h.chatService.EndChat(roomID, userID, "user_left")
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to leave chat")
		return
	}

	// Notify partner via WebSocket
	h.notifyUserLeft(roomID, userID)

	logger.LogChatEvent("user_left_chat", roomID, userID, nil)

	utils.SuccessResponseWithMessage(c, "Left chat successfully", nil)
}

func (h *ChatHandler) GetActiveChats(c *gin.Context) {
	userID := c.GetString("user_id")

	chats, err := h.chatService.GetUserActiveChats(userID)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to get active chats")
		return
	}

	utils.SuccessResponse(c, chats)
}

func (h *ChatHandler) SendMessage(c *gin.Context) {
	userID := c.GetString("user_id")

	var messageData struct {
		RoomID   string                 `json:"room_id" binding:"required"`
		Content  string                 `json:"content" binding:"required"`
		Type     string                 `json:"type"` // text, image, file, emoji
		Metadata map[string]interface{} `json:"metadata"`
	}

	if err := c.ShouldBindJSON(&messageData); err != nil {
		utils.ValidationErrorResponse(c, map[string]string{
			"room_id": "Room ID is required",
			"content": "Message content is required",
		})
		return
	}

	// Validate message content
	if len(messageData.Content) > 1000 {
		utils.ErrorResponse(c, http.StatusBadRequest, "Message too long")
		return
	}

	if utils.ContainsProfanity(messageData.Content) {
		utils.ErrorResponse(c, http.StatusBadRequest, "Message contains inappropriate content")
		return
	}

	// Validate user has access to room
	chat, err := h.chatService.GetChatByRoomID(messageData.RoomID)
	if err != nil {
		utils.ErrorResponse(c, http.StatusNotFound, "Chat room not found")
		return
	}

	if chat.User1ID.Hex() != userID && chat.User2ID.Hex() != userID {
		utils.ErrorResponse(c, http.StatusForbidden, "Access denied to this chat room")
		return
	}

	// Set default message type
	if messageData.Type == "" {
		messageData.Type = "text"
	}

	// Create WebSocket message
	wsMessage := websocket.NewWSMessage(
		websocket.MessageType(messageData.Type),
		messageData.Content,
		messageData.Metadata,
	)
	wsMessage.SetFrom(userID)
	wsMessage.SetRoomID(messageData.RoomID)

	// Send via WebSocket
	h.hub.BroadcastToRoom(messageData.RoomID, wsMessage)

	utils.SuccessResponseWithMessage(c, "Message sent", nil)
}

func (h *ChatHandler) GetMessages(c *gin.Context) {
	roomID := c.Param("room_id")
	userID := c.GetString("user_id")

	// Validate user has access to room
	chat, err := h.chatService.GetChatByRoomID(roomID)
	if err != nil {
		utils.ErrorResponse(c, http.StatusNotFound, "Chat room not found")
		return
	}

	if chat.User1ID.Hex() != userID && chat.User2ID.Hex() != userID {
		utils.ErrorResponse(c, http.StatusForbidden, "Access denied to this chat room")
		return
	}

	// Get pagination parameters
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))

	messages, err := h.chatService.GetChatMessages(roomID, page, limit)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to get messages")
		return
	}

	utils.SuccessResponse(c, messages)
}

func (h *ChatHandler) SendTyping(c *gin.Context) {
	roomID := c.Param("room_id")
	userID := c.GetString("user_id")

	var typingData struct {
		IsTyping bool `json:"is_typing"`
	}

	if err := c.ShouldBindJSON(&typingData); err != nil {
		typingData.IsTyping = true // Default to typing indicator
	}

	// Validate user has access to room
	chat, err := h.chatService.GetChatByRoomID(roomID)
	if err != nil {
		utils.ErrorResponse(c, http.StatusNotFound, "Chat room not found")
		return
	}

	if chat.User1ID.Hex() != userID && chat.User2ID.Hex() != userID {
		utils.ErrorResponse(c, http.StatusForbidden, "Access denied to this chat room")
		return
	}

	// Send typing indicator via WebSocket
	h.hub.BroadcastTyping(roomID, userID, typingData.IsTyping)

	utils.SuccessResponse(c, nil)
}

func (h *ChatHandler) ReportChat(c *gin.Context) {
	roomID := c.Param("room_id")
	userID := c.GetString("user_id")

	var reportData struct {
		Reason      string   `json:"reason" binding:"required"`
		Description string   `json:"description"`
		Categories  []string `json:"categories"`
	}

	if err := c.ShouldBindJSON(&reportData); err != nil {
		utils.ValidationErrorResponse(c, map[string]string{
			"reason": "Report reason is required",
		})
		return
	}

	// Validate user has access to room
	chat, err := h.chatService.GetChatByRoomID(roomID)
	if err != nil {
		utils.ErrorResponse(c, http.StatusNotFound, "Chat room not found")
		return
	}

	if chat.User1ID.Hex() != userID && chat.User2ID.Hex() != userID {
		utils.ErrorResponse(c, http.StatusForbidden, "Access denied to this chat room")
		return
	}

	// Get partner ID
	partnerID := h.getPartnerID(chat, userID)

	// Create report
	report := map[string]interface{}{
		"reporter_id":      userID,
		"reported_user_id": partnerID,
		"chat_id":          chat.ID.Hex(),
		"room_id":          roomID,
		"reason":           reportData.Reason,
		"description":      reportData.Description,
		"categories":       reportData.Categories,
		"status":           "pending",
		"created_at":       time.Now(),
		"ip_address":       c.ClientIP(),
	}

	err = h.createReport(report)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to create report")
		return
	}

	logger.LogUserAction(userID, "chat_reported", map[string]interface{}{
		"room_id":    roomID,
		"partner_id": partnerID,
		"reason":     reportData.Reason,
		"categories": reportData.Categories,
	})

	utils.SuccessResponseWithMessage(c, "Report submitted successfully", nil)
}

// Matching System

func (h *ChatHandler) FindMatch(c *gin.Context) {
	userID := c.GetString("user_id")

	var matchData struct {
		ChatType  string   `json:"chat_type" binding:"required"`
		Language  string   `json:"language"`
		Region    string   `json:"region"`
		Interests []string `json:"interests"`
		AgeRange  struct {
			Min int `json:"min"`
			Max int `json:"max"`
		} `json:"age_range"`
	}

	if err := c.ShouldBindJSON(&matchData); err != nil {
		utils.ValidationErrorResponse(c, map[string]string{
			"chat_type": "Chat type is required",
		})
		return
	}

	// Get user region if not provided
	if matchData.Region == "" {
		regionInfo, _ := utils.GetRegionFromIP(c.ClientIP())
		matchData.Region = regionInfo.Code
	}

	// Create matching preferences
	preferences := &services.MatchingPreferences{
		UserID:    userID,
		ChatType:  matchData.ChatType,
		Language:  matchData.Language,
		Region:    matchData.Region,
		Interests: matchData.Interests,
		AgeRange: services.AgeRange{
			Min: matchData.AgeRange.Min,
			Max: matchData.AgeRange.Max,
		},
	}

	// Try to find immediate match
	match, err := h.matchingService.FindMatch(preferences)
	if err != nil {
		// Add to queue
		queuePosition, err := h.matchingService.AddToQueue(preferences)
		if err != nil {
			utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to join matching queue")
			return
		}

		response := map[string]interface{}{
			"status":         "queued",
			"queue_position": queuePosition,
			"estimated_wait": h.matchingService.GetEstimatedWaitTime(matchData.ChatType),
		}

		utils.SuccessResponse(c, response)
		return
	}

	// Create chat room
	roomID := h.generateRoomID()
	chat, err := h.chatService.CreateChat(roomID, userID, match.PartnerID, matchData.ChatType)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to create chat")
		return
	}

	response := map[string]interface{}{
		"status":     "matched",
		"chat_id":    chat.ID.Hex(),
		"room_id":    roomID,
		"partner":    match.Partner,
		"chat_type":  matchData.ChatType,
		"started_at": chat.StartedAt,
	}

	utils.SuccessResponseWithMessage(c, "Match found", response)
}

func (h *ChatHandler) FindNextMatch(c *gin.Context) {
	userID := c.GetString("user_id")

	// End current chat if any
	currentRoomID := c.Query("current_room_id")
	if currentRoomID != "" {
		h.chatService.EndChat(currentRoomID, userID, "next_match")
		h.notifyUserLeft(currentRoomID, userID)
	}

	// Find new match with same preferences
	lastPreferences, err := h.matchingService.GetLastPreferences(userID)
	if err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "No previous matching preferences found")
		return
	}

	// Try to find immediate match
	match, err := h.matchingService.FindMatch(lastPreferences)
	if err != nil {
		// Add to queue
		queuePosition, err := h.matchingService.AddToQueue(lastPreferences)
		if err != nil {
			utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to find next match")
			return
		}

		response := map[string]interface{}{
			"status":         "queued",
			"queue_position": queuePosition,
			"estimated_wait": h.matchingService.GetEstimatedWaitTime(lastPreferences.ChatType),
		}

		utils.SuccessResponse(c, response)
		return
	}

	// Create new chat room
	roomID := h.generateRoomID()
	chat, err := h.chatService.CreateChat(roomID, userID, match.PartnerID, lastPreferences.ChatType)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to create chat")
		return
	}

	response := map[string]interface{}{
		"status":     "matched",
		"chat_id":    chat.ID.Hex(),
		"room_id":    roomID,
		"partner":    match.Partner,
		"chat_type":  lastPreferences.ChatType,
		"started_at": chat.StartedAt,
	}

	utils.SuccessResponseWithMessage(c, "Next match found", response)
}

func (h *ChatHandler) SkipCurrentMatch(c *gin.Context) {
	userID := c.GetString("user_id")
	roomID := c.Query("room_id")

	if roomID == "" {
		utils.ErrorResponse(c, http.StatusBadRequest, "Room ID is required")
		return
	}

	// End current chat
	err := h.chatService.EndChat(roomID, userID, "skipped")
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to skip match")
		return
	}

	// Remove from queue and find new match
	h.matchingService.RemoveFromQueue(userID)

	// Notify partner
	h.notifyUserLeft(roomID, userID)

	logger.LogChatEvent("match_skipped", roomID, userID, nil)

	utils.SuccessResponseWithMessage(c, "Match skipped", nil)
}

func (h *ChatHandler) GetQueueStatus(c *gin.Context) {
	userID := c.GetString("user_id")

	status, err := h.matchingService.GetQueueStatus(userID)
	if err != nil {
		utils.ErrorResponse(c, http.StatusNotFound, "Not in queue")
		return
	}

	utils.SuccessResponse(c, status)
}

func (h *ChatHandler) UpdateMatchPreferences(c *gin.Context) {
	userID := c.GetString("user_id")

	var preferences services.MatchingPreferences
	if err := c.ShouldBindJSON(&preferences); err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid preferences data")
		return
	}

	preferences.UserID = userID

	err := h.matchingService.UpdatePreferences(&preferences)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to update preferences")
		return
	}

	utils.SuccessResponseWithMessage(c, "Preferences updated", preferences)
}

// WebRTC Signaling

func (h *ChatHandler) SendOffer(c *gin.Context) {
	userID := c.GetString("user_id")

	var offerData struct {
		RoomID string      `json:"room_id" binding:"required"`
		Offer  interface{} `json:"offer" binding:"required"`
	}

	if err := c.ShouldBindJSON(&offerData); err != nil {
		utils.ValidationErrorResponse(c, map[string]string{
			"room_id": "Room ID is required",
			"offer":   "WebRTC offer is required",
		})
		return
	}

	// Validate user has access to room
	if !h.validateRoomAccess(offerData.RoomID, userID) {
		utils.ErrorResponse(c, http.StatusForbidden, "Access denied to this chat room")
		return
	}

	// Send WebRTC offer via WebSocket
	h.hub.BroadcastWebRTC(offerData.RoomID, "webrtc_offer", userID, offerData.Offer)

	logger.LogChatEvent("webrtc_offer_sent", offerData.RoomID, userID, nil)

	utils.SuccessResponse(c, nil)
}

func (h *ChatHandler) SendAnswer(c *gin.Context) {
	userID := c.GetString("user_id")

	var answerData struct {
		RoomID string      `json:"room_id" binding:"required"`
		Answer interface{} `json:"answer" binding:"required"`
	}

	if err := c.ShouldBindJSON(&answerData); err != nil {
		utils.ValidationErrorResponse(c, map[string]string{
			"room_id": "Room ID is required",
			"answer":  "WebRTC answer is required",
		})
		return
	}

	// Validate user has access to room
	if !h.validateRoomAccess(answerData.RoomID, userID) {
		utils.ErrorResponse(c, http.StatusForbidden, "Access denied to this chat room")
		return
	}

	// Send WebRTC answer via WebSocket
	h.hub.BroadcastWebRTC(answerData.RoomID, "webrtc_answer", userID, answerData.Answer)

	logger.LogChatEvent("webrtc_answer_sent", answerData.RoomID, userID, nil)

	utils.SuccessResponse(c, nil)
}

func (h *ChatHandler) SendICECandidate(c *gin.Context) {
	userID := c.GetString("user_id")

	var candidateData struct {
		RoomID    string      `json:"room_id" binding:"required"`
		Candidate interface{} `json:"candidate" binding:"required"`
	}

	if err := c.ShouldBindJSON(&candidateData); err != nil {
		utils.ValidationErrorResponse(c, map[string]string{
			"room_id":   "Room ID is required",
			"candidate": "ICE candidate is required",
		})
		return
	}

	// Validate user has access to room
	if !h.validateRoomAccess(candidateData.RoomID, userID) {
		utils.ErrorResponse(c, http.StatusForbidden, "Access denied to this chat room")
		return
	}

	// Send ICE candidate via WebSocket
	h.hub.BroadcastWebRTC(candidateData.RoomID, "webrtc_ice_candidate", userID, candidateData.Candidate)

	utils.SuccessResponse(c, nil)
}

// Helper methods

func (h *ChatHandler) generateRoomID() string {
	return fmt.Sprintf("room_%d_%s", time.Now().Unix(), utils.HashSHA256(fmt.Sprintf("%d", time.Now().UnixNano()))[:8])
}

func (h *ChatHandler) getPartnerID(chat interface{}, userID string) string {
	// Type assertion to get chat fields
	if c, ok := chat.(*services.Chat); ok {
		if c.User1ID.Hex() == userID {
			return c.User2ID.Hex()
		}
		return c.User1ID.Hex()
	}
	return ""
}

func (h *ChatHandler) validateRoomAccess(roomID, userID string) bool {
	chat, err := h.chatService.GetChatByRoomID(roomID)
	if err != nil {
		return false
	}

	return chat.User1ID.Hex() == userID || chat.User2ID.Hex() == userID
}

func (h *ChatHandler) notifyMatchFound(user1ID, user2ID, roomID, chatType string, match *services.MatchResult) {
	// Notify first user
	message1 := websocket.NewWSMessage(websocket.MessageTypeMatchFound, "Match found!", map[string]interface{}{
		"room_id":    roomID,
		"partner":    match.Partner,
		"chat_type":  chatType,
		"queue_time": match.QueueTime,
	})
	h.hub.BroadcastToUser(user1ID, message1)

	// Notify second user
	message2 := websocket.NewWSMessage(websocket.MessageTypeMatchFound, "Match found!", map[string]interface{}{
		"room_id": roomID,
		"partner": map[string]interface{}{
			"id":        user1ID,
			"region":    match.Partner.Region,
			"language":  match.Partner.Language,
			"interests": match.Partner.Interests,
		},
		"chat_type":  chatType,
		"queue_time": match.QueueTime,
	})
	h.hub.BroadcastToUser(user2ID, message2)
}

func (h *ChatHandler) notifyUserLeft(roomID, userID string) {
	message := websocket.NewWSMessage(websocket.MessageTypeUserLeft, "Partner left the chat", map[string]interface{}{
		"user_id": userID,
		"reason":  "user_left",
	})
	message.SetRoomID(roomID)

	h.hub.BroadcastToRoomExcept(roomID, userID, message)
}

func (h *ChatHandler) createReport(report map[string]interface{}) error {
	// Implementation for creating a report in the database
	// This would typically involve inserting into a reports collection
	// For now, we'll just log it
	logger.Info("Report created", report)
	return nil
}

// Additional handlers for app info endpoints

func GetAppInfo(c *gin.Context) {
	info := map[string]interface{}{
		"name":        "Omegle Clone",
		"version":     "1.0.0",
		"description": "Anonymous chat application",
		"features": []string{
			"Random matching",
			"Text, video, and audio chat",
			"Interest-based matching",
			"Multi-region support",
			"Real-time messaging",
			"WebRTC video calls",
		},
		"regions":   utils.GetAvailableRegions(),
		"languages": GetSupportedLanguages(),
	}

	utils.SuccessResponse(c, info)
}

func GetAvailableRegions(c *gin.Context) {
	regions := utils.GetAvailableRegions()
	utils.SuccessResponse(c, regions)
}

func GetSupportedLanguages() []map[string]interface{} {
	return []map[string]interface{}{
		{"code": "en", "name": "English", "native_name": "English"},
		{"code": "es", "name": "Spanish", "native_name": "Español"},
		{"code": "fr", "name": "French", "native_name": "Français"},
		{"code": "de", "name": "German", "native_name": "Deutsch"},
		{"code": "it", "name": "Italian", "native_name": "Italiano"},
		{"code": "pt", "name": "Portuguese", "native_name": "Português"},
		{"code": "ru", "name": "Russian", "native_name": "Русский"},
		{"code": "zh", "name": "Chinese", "native_name": "中文"},
		{"code": "ja", "name": "Japanese", "native_name": "日本語"},
		{"code": "ko", "name": "Korean", "native_name": "한국어"},
		{"code": "ar", "name": "Arabic", "native_name": "العربية"},
		{"code": "hi", "name": "Hindi", "native_name": "हिन्दी"},
		{"code": "th", "name": "Thai", "native_name": "ไทย"},
		{"code": "vi", "name": "Vietnamese", "native_name": "Tiếng Việt"},
		{"code": "id", "name": "Indonesian", "native_name": "Bahasa Indonesia"},
		{"code": "ms", "name": "Malay", "native_name": "Bahasa Melayu"},
		{"code": "tr", "name": "Turkish", "native_name": "Türkçe"},
		{"code": "pl", "name": "Polish", "native_name": "Polski"},
		{"code": "nl", "name": "Dutch", "native_name": "Nederlands"},
		{"code": "sv", "name": "Swedish", "native_name": "Svenska"},
	}
}
