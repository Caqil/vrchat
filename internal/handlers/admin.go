package handlers

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"vrchat/internal/models"
	"vrchat/internal/services"
	"vrchat/internal/utils"
	"vrchat/pkg/logger"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type AdminHandler struct {
	userService     *services.UserService
	chatService     *services.ChatService
	settingsService *services.SettingsService
	coturnService   *services.CoturnService
}

func NewAdminHandler(userService *services.UserService, chatService *services.ChatService, settingsService *services.SettingsService, coturnService *services.CoturnService) *AdminHandler {
	return &AdminHandler{
		userService:     userService,
		chatService:     chatService,
		settingsService: settingsService,
		coturnService:   coturnService,
	}
}

// Dashboard & Analytics

func (h *AdminHandler) GetDashboardStats(c *gin.Context) {
	stats := map[string]interface{}{
		"total_users":   h.userService.GetTotalUsers(),
		"online_users":  h.userService.GetOnlineUsers(),
		"banned_users":  h.userService.GetBannedUsers(),
		"active_chats":  h.chatService.GetActiveChats(),
		"total_chats":   h.chatService.GetTotalChats(),
		"reports_count": h.getReportsCount(),
		"servers_count": h.coturnService.GetServersCount(),
		"today_signups": h.userService.GetTodaySignups(),
		"avg_chat_time": h.chatService.GetAverageChatDuration(),
		"server_uptime": h.getServerUptime(),
	}

	utils.SuccessResponse(c, stats)
}

func (h *AdminHandler) GetRealtimeStats(c *gin.Context) {
	stats := map[string]interface{}{
		"online_users":     h.userService.GetOnlineUsers(),
		"active_chats":     h.chatService.GetActiveChats(),
		"queue_size":       h.chatService.GetQueueSize(),
		"messages_per_min": h.chatService.GetMessagesPerMinute(),
		"new_users_today":  h.userService.GetTodaySignups(),
		"timestamp":        time.Now(),
	}

	utils.SuccessResponse(c, stats)
}

func (h *AdminHandler) GetUserChartData(c *gin.Context) {
	period := c.DefaultQuery("period", "7d")
	data := h.userService.GetUserChartData(period)
	utils.SuccessResponse(c, data)
}

func (h *AdminHandler) GetChatChartData(c *gin.Context) {
	period := c.DefaultQuery("period", "7d")
	data := h.chatService.GetChatChartData(period)
	utils.SuccessResponse(c, data)
}

func (h *AdminHandler) GetRegionChartData(c *gin.Context) {
	data := h.userService.GetRegionDistribution()
	utils.SuccessResponse(c, data)
}

// User Management

func (h *AdminHandler) GetUsers(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	search := c.Query("search")
	status := c.Query("status")
	region := c.Query("region")

	filter := bson.M{}
	if search != "" {
		filter["$or"] = []bson.M{
			{"session_id": bson.M{"$regex": search, "$options": "i"}},
			{"ip_address": bson.M{"$regex": search, "$options": "i"}},
		}
	}
	if status != "" {
		switch status {
		case "online":
			filter["is_online"] = true
		case "banned":
			filter["is_banned"] = true
		}
	}
	if region != "" {
		filter["region"] = region
	}

	users, total, err := h.userService.GetUsersWithPagination(filter, page, limit)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to fetch users")
		return
	}

	meta := &utils.Meta{
		Page:       page,
		Limit:      limit,
		Total:      int(total),
		TotalPages: int((total + int64(limit) - 1) / int64(limit)),
	}

	utils.SuccessResponseWithMeta(c, users, meta)
}

func (h *AdminHandler) GetUser(c *gin.Context) {
	userID := c.Param("id")
	objectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid user ID")
		return
	}

	user, err := h.userService.GetUserByID(objectID)
	if err != nil {
		utils.ErrorResponse(c, http.StatusNotFound, "User not found")
		return
	}

	// Get additional user data
	userData := map[string]interface{}{
		"user":          user,
		"chat_history":  h.chatService.GetUserChatHistory(objectID),
		"report_count":  h.getUserReportCount(objectID),
		"last_activity": h.userService.GetUserLastActivity(objectID),
	}

	utils.SuccessResponse(c, userData)
}

func (h *AdminHandler) UpdateUser(c *gin.Context) {
	userID := c.Param("id")
	objectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid user ID")
		return
	}

	var updateData map[string]interface{}
	if err := c.ShouldBindJSON(&updateData); err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid request data")
		return
	}

	err = h.userService.UpdateUser(objectID, updateData)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to update user")
		return
	}

	logger.LogAdminAction(c.GetString("admin_id"), "user_updated", userID, map[string]interface{}{
		"updated_fields": updateData,
	})

	utils.SuccessResponseWithMessage(c, "User updated successfully", nil)
}

func (h *AdminHandler) DeleteUser(c *gin.Context) {
	userID := c.Param("id")
	objectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid user ID")
		return
	}

	err = h.userService.DeleteUser(objectID)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to delete user")
		return
	}

	logger.LogAdminAction(c.GetString("admin_id"), "user_deleted", userID, nil)

	utils.SuccessResponseWithMessage(c, "User deleted successfully", nil)
}

func (h *AdminHandler) BanUser(c *gin.Context) {
	userID := c.Param("id")
	objectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid user ID")
		return
	}

	var banData struct {
		Reason   string `json:"reason" binding:"required"`
		Duration *int   `json:"duration"` // hours, nil for permanent
		BanType  string `json:"ban_type"` // user, ip
	}

	if err := c.ShouldBindJSON(&banData); err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid ban data")
		return
	}

	var expiry *time.Time
	if banData.Duration != nil {
		expiryTime := time.Now().Add(time.Duration(*banData.Duration) * time.Hour)
		expiry = &expiryTime
	}

	err = h.userService.BanUser(objectID, banData.Reason, expiry)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to ban user")
		return
	}

	logger.LogAdminAction(c.GetString("admin_id"), "user_banned", userID, map[string]interface{}{
		"reason":   banData.Reason,
		"duration": banData.Duration,
		"ban_type": banData.BanType,
	})

	utils.SuccessResponseWithMessage(c, "User banned successfully", nil)
}

func (h *AdminHandler) UnbanUser(c *gin.Context) {
	userID := c.Param("id")
	objectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid user ID")
		return
	}

	err = h.userService.UnbanUser(objectID)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to unban user")
		return
	}

	logger.LogAdminAction(c.GetString("admin_id"), "user_unbanned", userID, nil)

	utils.SuccessResponseWithMessage(c, "User unbanned successfully", nil)
}

func (h *AdminHandler) GetUserActivity(c *gin.Context) {
	userID := c.Param("id")
	objectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid user ID")
		return
	}

	activity := h.userService.GetUserActivity(objectID)
	utils.SuccessResponse(c, activity)
}

func (h *AdminHandler) GetUserChats(c *gin.Context) {
	userID := c.Param("id")
	objectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid user ID")
		return
	}

	chats := h.chatService.GetUserChats(objectID)
	utils.SuccessResponse(c, chats)
}

func (h *AdminHandler) BulkUserAction(c *gin.Context) {
	var bulkData struct {
		UserIDs []string               `json:"user_ids" binding:"required"`
		Action  string                 `json:"action" binding:"required"`
		Data    map[string]interface{} `json:"data"`
	}

	if err := c.ShouldBindJSON(&bulkData); err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid bulk action data")
		return
	}

	objectIDs := make([]primitive.ObjectID, len(bulkData.UserIDs))
	for i, id := range bulkData.UserIDs {
		objectID, err := primitive.ObjectIDFromHex(id)
		if err != nil {
			utils.ErrorResponse(c, http.StatusBadRequest, fmt.Sprintf("Invalid user ID: %s", id))
			return
		}
		objectIDs[i] = objectID
	}

	err := h.userService.BulkUserAction(objectIDs, bulkData.Action, bulkData.Data)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to perform bulk action")
		return
	}

	logger.LogAdminAction(c.GetString("admin_id"), "bulk_user_action", "", map[string]interface{}{
		"action":     bulkData.Action,
		"user_count": len(bulkData.UserIDs),
		"data":       bulkData.Data,
	})

	utils.SuccessResponseWithMessage(c, "Bulk action completed successfully", nil)
}

func (h *AdminHandler) ExportUsers(c *gin.Context) {
	format := c.DefaultQuery("format", "csv")
	filter := c.Query("filter")

	data, err := h.userService.ExportUsers(format, filter)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to export users")
		return
	}

	filename := fmt.Sprintf("users_export_%s.%s", time.Now().Format("20060102_150405"), format)
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))

	switch format {
	case "csv":
		c.Header("Content-Type", "text/csv")
	case "json":
		c.Header("Content-Type", "application/json")
	case "xlsx":
		c.Header("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
	}

	c.Data(http.StatusOK, c.GetHeader("Content-Type"), data)
}

// Chat Management

func (h *AdminHandler) GetChats(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	status := c.Query("status")
	chatType := c.Query("chat_type")

	filter := bson.M{}
	if status != "" {
		filter["status"] = status
	}
	if chatType != "" {
		filter["chat_type"] = chatType
	}

	chats, total, err := h.chatService.GetChatsWithPagination(filter, page, limit)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to fetch chats")
		return
	}

	meta := &utils.Meta{
		Page:       page,
		Limit:      limit,
		Total:      int(total),
		TotalPages: int((total + int64(limit) - 1) / int64(limit)),
	}

	utils.SuccessResponseWithMeta(c, chats, meta)
}

func (h *AdminHandler) GetChat(c *gin.Context) {
	chatID := c.Param("id")
	objectID, err := primitive.ObjectIDFromHex(chatID)
	if err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid chat ID")
		return
	}

	chat, err := h.chatService.GetChatByID(objectID)
	if err != nil {
		utils.ErrorResponse(c, http.StatusNotFound, "Chat not found")
		return
	}

	utils.SuccessResponse(c, chat)
}

func (h *AdminHandler) DeleteChat(c *gin.Context) {
	chatID := c.Param("id")
	objectID, err := primitive.ObjectIDFromHex(chatID)
	if err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid chat ID")
		return
	}

	err = h.chatService.DeleteChat(objectID)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to delete chat")
		return
	}

	logger.LogAdminAction(c.GetString("admin_id"), "chat_deleted", chatID, nil)

	utils.SuccessResponseWithMessage(c, "Chat deleted successfully", nil)
}

func (h *AdminHandler) GetActiveChats(c *gin.Context) {
	chats := h.chatService.GetActiveChatsWithDetails()
	utils.SuccessResponse(c, chats)
}

func (h *AdminHandler) EndChat(c *gin.Context) {
	chatID := c.Param("id")
	objectID, err := primitive.ObjectIDFromHex(chatID)
	if err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid chat ID")
		return
	}

	var endData struct {
		Reason string `json:"reason"`
	}
	c.ShouldBindJSON(&endData)

	err = h.chatService.EndChat(objectID, endData.Reason)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to end chat")
		return
	}

	logger.LogAdminAction(c.GetString("admin_id"), "chat_ended", chatID, map[string]interface{}{
		"reason": endData.Reason,
	})

	utils.SuccessResponseWithMessage(c, "Chat ended successfully", nil)
}

func (h *AdminHandler) GetChatMessages(c *gin.Context) {
	chatID := c.Param("id")
	objectID, err := primitive.ObjectIDFromHex(chatID)
	if err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid chat ID")
		return
	}

	messages := h.chatService.GetChatMessages(objectID)
	utils.SuccessResponse(c, messages)
}

func (h *AdminHandler) BulkChatAction(c *gin.Context) {
	var bulkData struct {
		ChatIDs []string               `json:"chat_ids" binding:"required"`
		Action  string                 `json:"action" binding:"required"`
		Data    map[string]interface{} `json:"data"`
	}

	if err := c.ShouldBindJSON(&bulkData); err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid bulk action data")
		return
	}

	objectIDs := make([]primitive.ObjectID, len(bulkData.ChatIDs))
	for i, id := range bulkData.ChatIDs {
		objectID, err := primitive.ObjectIDFromHex(id)
		if err != nil {
			utils.ErrorResponse(c, http.StatusBadRequest, fmt.Sprintf("Invalid chat ID: %s", id))
			return
		}
		objectIDs[i] = objectID
	}

	err := h.chatService.BulkChatAction(objectIDs, bulkData.Action, bulkData.Data)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to perform bulk action")
		return
	}

	logger.LogAdminAction(c.GetString("admin_id"), "bulk_chat_action", "", map[string]interface{}{
		"action":     bulkData.Action,
		"chat_count": len(bulkData.ChatIDs),
		"data":       bulkData.Data,
	})

	utils.SuccessResponseWithMessage(c, "Bulk action completed successfully", nil)
}

func (h *AdminHandler) ExportChats(c *gin.Context) {
	format := c.DefaultQuery("format", "csv")
	filter := c.Query("filter")

	data, err := h.chatService.ExportChats(format, filter)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to export chats")
		return
	}

	filename := fmt.Sprintf("chats_export_%s.%s", time.Now().Format("20060102_150405"), format)
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))

	switch format {
	case "csv":
		c.Header("Content-Type", "text/csv")
	case "json":
		c.Header("Content-Type", "application/json")
	case "xlsx":
		c.Header("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
	}

	c.Data(http.StatusOK, c.GetHeader("Content-Type"), data)
}

// Reports & Moderation

func (h *AdminHandler) GetReports(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	status := c.Query("status")
	reportType := c.Query("type")

	filter := bson.M{}
	if status != "" {
		filter["status"] = status
	}
	if reportType != "" {
		filter["type"] = reportType
	}

	reports, total, err := h.getReportsWithPagination(filter, page, limit)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to fetch reports")
		return
	}

	meta := &utils.Meta{
		Page:       page,
		Limit:      limit,
		Total:      int(total),
		TotalPages: int((total + int64(limit) - 1) / int64(limit)),
	}

	utils.SuccessResponseWithMeta(c, reports, meta)
}

func (h *AdminHandler) GetReport(c *gin.Context) {
	reportID := c.Param("id")
	objectID, err := primitive.ObjectIDFromHex(reportID)
	if err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid report ID")
		return
	}

	report, err := h.getReportByID(objectID)
	if err != nil {
		utils.ErrorResponse(c, http.StatusNotFound, "Report not found")
		return
	}

	utils.SuccessResponse(c, report)
}

func (h *AdminHandler) ResolveReport(c *gin.Context) {
	reportID := c.Param("id")
	objectID, err := primitive.ObjectIDFromHex(reportID)
	if err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid report ID")
		return
	}

	var resolveData struct {
		Action   string `json:"action" binding:"required"`
		Comments string `json:"comments"`
	}

	if err := c.ShouldBindJSON(&resolveData); err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid resolve data")
		return
	}

	err = h.resolveReport(objectID, resolveData.Action, resolveData.Comments, c.GetString("admin_id"))
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to resolve report")
		return
	}

	logger.LogAdminAction(c.GetString("admin_id"), "report_resolved", reportID, map[string]interface{}{
		"action":   resolveData.Action,
		"comments": resolveData.Comments,
	})

	utils.SuccessResponseWithMessage(c, "Report resolved successfully", nil)
}

func (h *AdminHandler) DismissReport(c *gin.Context) {
	reportID := c.Param("id")
	objectID, err := primitive.ObjectIDFromHex(reportID)
	if err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid report ID")
		return
	}

	var dismissData struct {
		Reason string `json:"reason"`
	}
	c.ShouldBindJSON(&dismissData)

	err = h.dismissReport(objectID, dismissData.Reason, c.GetString("admin_id"))
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to dismiss report")
		return
	}

	logger.LogAdminAction(c.GetString("admin_id"), "report_dismissed", reportID, map[string]interface{}{
		"reason": dismissData.Reason,
	})

	utils.SuccessResponseWithMessage(c, "Report dismissed successfully", nil)
}

func (h *AdminHandler) GetModerationQueue(c *gin.Context) {
	queue := h.getModerationQueue()
	utils.SuccessResponse(c, queue)
}

func (h *AdminHandler) ApproveContent(c *gin.Context) {
	contentID := c.Param("id")

	err := h.approveContent(contentID, c.GetString("admin_id"))
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to approve content")
		return
	}

	logger.LogAdminAction(c.GetString("admin_id"), "content_approved", contentID, nil)

	utils.SuccessResponseWithMessage(c, "Content approved successfully", nil)
}

func (h *AdminHandler) RejectContent(c *gin.Context) {
	contentID := c.Param("id")

	var rejectData struct {
		Reason string `json:"reason" binding:"required"`
	}

	if err := c.ShouldBindJSON(&rejectData); err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid reject data")
		return
	}

	err := h.rejectContent(contentID, rejectData.Reason, c.GetString("admin_id"))
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to reject content")
		return
	}

	logger.LogAdminAction(c.GetString("admin_id"), "content_rejected", contentID, map[string]interface{}{
		"reason": rejectData.Reason,
	})

	utils.SuccessResponseWithMessage(c, "Content rejected successfully", nil)
}

func (h *AdminHandler) GetFlaggedContent(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))

	content, total, err := h.getFlaggedContent(page, limit)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to fetch flagged content")
		return
	}

	meta := &utils.Meta{
		Page:       page,
		Limit:      limit,
		Total:      int(total),
		TotalPages: int((total + int64(limit) - 1) / int64(limit)),
	}

	utils.SuccessResponseWithMeta(c, content, meta)
}

func (h *AdminHandler) BulkModerate(c *gin.Context) {
	var bulkData struct {
		ContentIDs []string `json:"content_ids" binding:"required"`
		Action     string   `json:"action" binding:"required"`
		Reason     string   `json:"reason"`
	}

	if err := c.ShouldBindJSON(&bulkData); err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid bulk moderation data")
		return
	}

	err := h.bulkModerate(bulkData.ContentIDs, bulkData.Action, bulkData.Reason, c.GetString("admin_id"))
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to perform bulk moderation")
		return
	}

	logger.LogAdminAction(c.GetString("admin_id"), "bulk_moderation", "", map[string]interface{}{
		"action":        bulkData.Action,
		"content_count": len(bulkData.ContentIDs),
		"reason":        bulkData.Reason,
	})

	utils.SuccessResponseWithMessage(c, "Bulk moderation completed successfully", nil)
}

// Settings Management

func (h *AdminHandler) GetSettings(c *gin.Context) {
	settings, err := h.settingsService.GetSettings()
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to fetch settings")
		return
	}

	utils.SuccessResponse(c, settings)
}

func (h *AdminHandler) UpdateSettings(c *gin.Context) {
	var updateData map[string]interface{}
	if err := c.ShouldBindJSON(&updateData); err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid settings data")
		return
	}

	err := h.settingsService.UpdateSettings(updateData)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to update settings")
		return
	}

	logger.LogAdminAction(c.GetString("admin_id"), "settings_updated", "", map[string]interface{}{
		"updated_fields": updateData,
	})

	utils.SuccessResponseWithMessage(c, "Settings updated successfully", nil)
}

func (h *AdminHandler) BackupSettings(c *gin.Context) {
	backup, err := h.settingsService.BackupSettings()
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to backup settings")
		return
	}

	filename := fmt.Sprintf("settings_backup_%s.json", time.Now().Format("20060102_150405"))
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
	c.Header("Content-Type", "application/json")

	utils.SuccessResponse(c, backup)
}

func (h *AdminHandler) RestoreSettings(c *gin.Context) {
	var restoreData map[string]interface{}
	if err := c.ShouldBindJSON(&restoreData); err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid restore data")
		return
	}

	err := h.settingsService.RestoreSettings(restoreData)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to restore settings")
		return
	}

	logger.LogAdminAction(c.GetString("admin_id"), "settings_restored", "", nil)

	utils.SuccessResponseWithMessage(c, "Settings restored successfully", nil)
}

func (h *AdminHandler) ResetToDefaults(c *gin.Context) {
	err := h.settingsService.ResetToDefaults()
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to reset settings")
		return
	}

	logger.LogAdminAction(c.GetString("admin_id"), "settings_reset", "", nil)

	utils.SuccessResponseWithMessage(c, "Settings reset to defaults successfully", nil)
}

func (h *AdminHandler) GetGeneralSettings(c *gin.Context) {
	settings := h.settingsService.GetGeneralSettings()
	utils.SuccessResponse(c, settings)
}

func (h *AdminHandler) UpdateGeneralSettings(c *gin.Context) {
	var updateData map[string]interface{}
	if err := c.ShouldBindJSON(&updateData); err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid settings data")
		return
	}

	err := h.settingsService.UpdateGeneralSettings(updateData)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to update general settings")
		return
	}

	utils.SuccessResponseWithMessage(c, "General settings updated successfully", nil)
}

func (h *AdminHandler) GetModerationSettings(c *gin.Context) {
	settings := h.settingsService.GetModerationSettings()
	utils.SuccessResponse(c, settings)
}

func (h *AdminHandler) UpdateModerationSettings(c *gin.Context) {
	var updateData map[string]interface{}
	if err := c.ShouldBindJSON(&updateData); err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid settings data")
		return
	}

	err := h.settingsService.UpdateModerationSettings(updateData)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to update moderation settings")
		return
	}

	utils.SuccessResponseWithMessage(c, "Moderation settings updated successfully", nil)
}

func (h *AdminHandler) GetMatchingSettings(c *gin.Context) {
	settings := h.settingsService.GetMatchingSettings()
	utils.SuccessResponse(c, settings)
}

func (h *AdminHandler) UpdateMatchingSettings(c *gin.Context) {
	var updateData map[string]interface{}
	if err := c.ShouldBindJSON(&updateData); err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid settings data")
		return
	}

	err := h.settingsService.UpdateMatchingSettings(updateData)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to update matching settings")
		return
	}

	utils.SuccessResponseWithMessage(c, "Matching settings updated successfully", nil)
}

// COTURN Server Management

func (h *AdminHandler) GetCoturnServers(c *gin.Context) {
	servers, err := h.coturnService.GetAllServers()
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to fetch COTURN servers")
		return
	}

	utils.SuccessResponse(c, servers)
}

func (h *AdminHandler) CreateCoturnServer(c *gin.Context) {
	var server models.CoturnServer
	if err := c.ShouldBindJSON(&server); err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid server data")
		return
	}

	err := h.coturnService.CreateServer(&server)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to create COTURN server")
		return
	}

	logger.LogAdminAction(c.GetString("admin_id"), "coturn_server_created", server.ID.Hex(), map[string]interface{}{
		"name":   server.Name,
		"region": server.Region,
		"url":    server.URL,
	})

	utils.SuccessResponseWithMessage(c, "COTURN server created successfully", server)
}

func (h *AdminHandler) GetCoturnServer(c *gin.Context) {
	serverID := c.Param("id")
	objectID, err := primitive.ObjectIDFromHex(serverID)
	if err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid server ID")
		return
	}

	server, err := h.coturnService.GetServerByID(objectID)
	if err != nil {
		utils.ErrorResponse(c, http.StatusNotFound, "Server not found")
		return
	}

	utils.SuccessResponse(c, server)
}

func (h *AdminHandler) UpdateCoturnServer(c *gin.Context) {
	serverID := c.Param("id")
	objectID, err := primitive.ObjectIDFromHex(serverID)
	if err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid server ID")
		return
	}

	var updateData map[string]interface{}
	if err := c.ShouldBindJSON(&updateData); err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid update data")
		return
	}

	err = h.coturnService.UpdateServer(objectID, updateData)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to update server")
		return
	}

	logger.LogAdminAction(c.GetString("admin_id"), "coturn_server_updated", serverID, map[string]interface{}{
		"updated_fields": updateData,
	})

	utils.SuccessResponseWithMessage(c, "COTURN server updated successfully", nil)
}

func (h *AdminHandler) DeleteCoturnServer(c *gin.Context) {
	serverID := c.Param("id")
	objectID, err := primitive.ObjectIDFromHex(serverID)
	if err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid server ID")
		return
	}

	err = h.coturnService.DeleteServer(objectID)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to delete server")
		return
	}

	logger.LogAdminAction(c.GetString("admin_id"), "coturn_server_deleted", serverID, nil)

	utils.SuccessResponseWithMessage(c, "COTURN server deleted successfully", nil)
}

func (h *AdminHandler) TestCoturnServer(c *gin.Context) {
	serverID := c.Param("id")
	objectID, err := primitive.ObjectIDFromHex(serverID)
	if err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid server ID")
		return
	}

	result, err := h.coturnService.TestServer(objectID)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to test server")
		return
	}

	utils.SuccessResponse(c, result)
}

func (h *AdminHandler) ToggleCoturnServer(c *gin.Context) {
	serverID := c.Param("id")
	objectID, err := primitive.ObjectIDFromHex(serverID)
	if err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid server ID")
		return
	}

	err = h.coturnService.ToggleServerStatus(objectID)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to toggle server status")
		return
	}

	logger.LogAdminAction(c.GetString("admin_id"), "coturn_server_toggled", serverID, nil)

	utils.SuccessResponseWithMessage(c, "Server status toggled successfully", nil)
}

func (h *AdminHandler) GetCoturnServerStats(c *gin.Context) {
	serverID := c.Param("id")
	objectID, err := primitive.ObjectIDFromHex(serverID)
	if err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid server ID")
		return
	}

	stats, err := h.coturnService.GetServerStats(objectID)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to get server stats")
		return
	}

	utils.SuccessResponse(c, stats)
}

func (h *AdminHandler) BulkTestCoturnServers(c *gin.Context) {
	results, err := h.coturnService.BulkTestServers()
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to test servers")
		return
	}

	utils.SuccessResponse(c, results)
}

func (h *AdminHandler) GetCoturnRegions(c *gin.Context) {
	regions := h.coturnService.GetAvailableRegions()
	utils.SuccessResponse(c, regions)
}

// System Management

func (h *AdminHandler) GetSystemInfo(c *gin.Context) {
	info := h.getSystemInfo()
	utils.SuccessResponse(c, info)
}

func (h *AdminHandler) GetSystemHealth(c *gin.Context) {
	health := h.getSystemHealth()
	utils.SuccessResponse(c, health)
}

func (h *AdminHandler) GetSystemLogs(c *gin.Context) {
	level := c.DefaultQuery("level", "info")
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "100"))

	logs := h.getSystemLogs(level, limit)
	utils.SuccessResponse(c, logs)
}

func (h *AdminHandler) ToggleMaintenanceMode(c *gin.Context) {
	var maintenanceData struct {
		Enabled bool   `json:"enabled"`
		Message string `json:"message"`
	}

	if err := c.ShouldBindJSON(&maintenanceData); err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid maintenance data")
		return
	}

	err := h.settingsService.SetMaintenanceMode(maintenanceData.Enabled, maintenanceData.Message)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to toggle maintenance mode")
		return
	}

	logger.LogAdminAction(c.GetString("admin_id"), "maintenance_mode_toggled", "", map[string]interface{}{
		"enabled": maintenanceData.Enabled,
		"message": maintenanceData.Message,
	})

	utils.SuccessResponseWithMessage(c, "Maintenance mode updated successfully", nil)
}

func (h *AdminHandler) ClearCache(c *gin.Context) {
	cacheType := c.DefaultQuery("type", "all")

	err := h.clearCache(cacheType)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to clear cache")
		return
	}

	logger.LogAdminAction(c.GetString("admin_id"), "cache_cleared", "", map[string]interface{}{
		"cache_type": cacheType,
	})

	utils.SuccessResponseWithMessage(c, "Cache cleared successfully", nil)
}

func (h *AdminHandler) GetDatabaseStats(c *gin.Context) {
	stats := h.getDatabaseStats()
	utils.SuccessResponse(c, stats)
}

func (h *AdminHandler) CleanupDatabase(c *gin.Context) {
	err := h.cleanupDatabase()
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to cleanup database")
		return
	}

	logger.LogAdminAction(c.GetString("admin_id"), "database_cleanup", "", nil)

	utils.SuccessResponseWithMessage(c, "Database cleanup completed successfully", nil)
}

func (h *AdminHandler) CreateBackup(c *gin.Context) {
	backupType := c.DefaultQuery("type", "full")

	backup, err := h.createBackup(backupType)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to create backup")
		return
	}

	utils.SuccessResponse(c, backup)
}

func (h *AdminHandler) RestoreBackup(c *gin.Context) {
	var restoreData struct {
		BackupID string `json:"backup_id" binding:"required"`
	}

	if err := c.ShouldBindJSON(&restoreData); err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid restore data")
		return
	}

	err := h.restoreBackup(restoreData.BackupID)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to restore backup")
		return
	}

	logger.LogAdminAction(c.GetString("admin_id"), "backup_restored", restoreData.BackupID, nil)

	utils.SuccessResponseWithMessage(c, "Backup restored successfully", nil)
}

// Analytics & Reports

func (h *AdminHandler) GetAnalyticsOverview(c *gin.Context) {
	period := c.DefaultQuery("period", "7d")
	analytics := h.getAnalyticsOverview(period)
	utils.SuccessResponse(c, analytics)
}

func (h *AdminHandler) GetUserAnalytics(c *gin.Context) {
	period := c.DefaultQuery("period", "30d")
	analytics := h.userService.GetUserAnalytics(period)
	utils.SuccessResponse(c, analytics)
}

func (h *AdminHandler) GetChatAnalytics(c *gin.Context) {
	period := c.DefaultQuery("period", "30d")
	analytics := h.chatService.GetChatAnalytics(period)
	utils.SuccessResponse(c, analytics)
}

func (h *AdminHandler) GetRegionAnalytics(c *gin.Context) {
	analytics := h.getRegionAnalytics()
	utils.SuccessResponse(c, analytics)
}

func (h *AdminHandler) GetPerformanceAnalytics(c *gin.Context) {
	period := c.DefaultQuery("period", "24h")
	analytics := h.getPerformanceAnalytics(period)
	utils.SuccessResponse(c, analytics)
}

func (h *AdminHandler) GetRevenueAnalytics(c *gin.Context) {
	period := c.DefaultQuery("period", "30d")
	analytics := h.getRevenueAnalytics(period)
	utils.SuccessResponse(c, analytics)
}

func (h *AdminHandler) ExportAnalytics(c *gin.Context) {
	format := c.DefaultQuery("format", "csv")
	period := c.DefaultQuery("period", "30d")

	data, err := h.exportAnalytics(format, period)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to export analytics")
		return
	}

	filename := fmt.Sprintf("analytics_export_%s.%s", time.Now().Format("20060102_150405"), format)
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))

	switch format {
	case "csv":
		c.Header("Content-Type", "text/csv")
	case "json":
		c.Header("Content-Type", "application/json")
	case "xlsx":
		c.Header("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
	}

	c.Data(http.StatusOK, c.GetHeader("Content-Type"), data)
}

func (h *AdminHandler) GetCustomAnalytics(c *gin.Context) {
	var queryData struct {
		Metrics   []string               `json:"metrics" binding:"required"`
		Filters   map[string]interface{} `json:"filters"`
		GroupBy   string                 `json:"group_by"`
		Period    string                 `json:"period"`
		DateRange []string               `json:"date_range"`
	}

	if err := c.ShouldBindJSON(&queryData); err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid query data")
		return
	}

	analytics, err := h.getCustomAnalytics(queryData.Metrics, queryData.Filters, queryData.GroupBy, queryData.Period, queryData.DateRange)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to get custom analytics")
		return
	}

	utils.SuccessResponse(c, analytics)
}

// Content Management

func (h *AdminHandler) GetBannedWords(c *gin.Context) {
	words, err := h.settingsService.GetBannedWords()
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to fetch banned words")
		return
	}

	utils.SuccessResponse(c, words)
}

func (h *AdminHandler) AddBannedWord(c *gin.Context) {
	var wordData struct {
		Word string `json:"word" binding:"required"`
	}

	if err := c.ShouldBindJSON(&wordData); err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid word data")
		return
	}

	err := h.settingsService.AddBannedWord(wordData.Word)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to add banned word")
		return
	}

	logger.LogAdminAction(c.GetString("admin_id"), "banned_word_added", wordData.Word, nil)

	utils.SuccessResponseWithMessage(c, "Banned word added successfully", nil)
}

func (h *AdminHandler) RemoveBannedWord(c *gin.Context) {
	wordID := c.Param("id")

	err := h.settingsService.RemoveBannedWord(wordID)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to remove banned word")
		return
	}

	logger.LogAdminAction(c.GetString("admin_id"), "banned_word_removed", wordID, nil)

	utils.SuccessResponseWithMessage(c, "Banned word removed successfully", nil)
}

func (h *AdminHandler) BulkUpdateBannedWords(c *gin.Context) {
	var bulkData struct {
		Words  []string `json:"words" binding:"required"`
		Action string   `json:"action" binding:"required"` // add, remove, replace
	}

	if err := c.ShouldBindJSON(&bulkData); err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid bulk data")
		return
	}

	err := h.settingsService.BulkUpdateBannedWords(bulkData.Words, bulkData.Action)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to bulk update banned words")
		return
	}

	logger.LogAdminAction(c.GetString("admin_id"), "banned_words_bulk_updated", "", map[string]interface{}{
		"action":     bulkData.Action,
		"word_count": len(bulkData.Words),
	})

	utils.SuccessResponseWithMessage(c, "Banned words updated successfully", nil)
}

func (h *AdminHandler) GetBannedCountries(c *gin.Context) {
	countries, err := h.settingsService.GetBannedCountries()
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to fetch banned countries")
		return
	}

	utils.SuccessResponse(c, countries)
}

func (h *AdminHandler) AddBannedCountry(c *gin.Context) {
	var countryData struct {
		CountryCode string `json:"country_code" binding:"required"`
		CountryName string `json:"country_name" binding:"required"`
	}

	if err := c.ShouldBindJSON(&countryData); err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid country data")
		return
	}

	err := h.settingsService.AddBannedCountry(countryData.CountryCode, countryData.CountryName)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to add banned country")
		return
	}

	logger.LogAdminAction(c.GetString("admin_id"), "banned_country_added", countryData.CountryCode, map[string]interface{}{
		"country_name": countryData.CountryName,
	})

	utils.SuccessResponseWithMessage(c, "Banned country added successfully", nil)
}

func (h *AdminHandler) RemoveBannedCountry(c *gin.Context) {
	countryCode := c.Param("code")

	err := h.settingsService.RemoveBannedCountry(countryCode)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to remove banned country")
		return
	}

	logger.LogAdminAction(c.GetString("admin_id"), "banned_country_removed", countryCode, nil)

	utils.SuccessResponseWithMessage(c, "Banned country removed successfully", nil)
}

// Email & Notifications

func (h *AdminHandler) GetNotificationTemplates(c *gin.Context) {
	templates := h.getNotificationTemplates()
	utils.SuccessResponse(c, templates)
}

func (h *AdminHandler) UpdateNotificationTemplate(c *gin.Context) {
	templateID := c.Param("id")

	var templateData map[string]interface{}
	if err := c.ShouldBindJSON(&templateData); err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid template data")
		return
	}

	err := h.updateNotificationTemplate(templateID, templateData)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to update template")
		return
	}

	utils.SuccessResponseWithMessage(c, "Template updated successfully", nil)
}

func (h *AdminHandler) SendNotification(c *gin.Context) {
	var notificationData struct {
		Type       string                 `json:"type" binding:"required"`
		Recipients []string               `json:"recipients" binding:"required"`
		Subject    string                 `json:"subject" binding:"required"`
		Message    string                 `json:"message" binding:"required"`
		Data       map[string]interface{} `json:"data"`
	}

	if err := c.ShouldBindJSON(&notificationData); err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid notification data")
		return
	}

	err := h.sendNotification(notificationData.Type, notificationData.Recipients, notificationData.Subject, notificationData.Message, notificationData.Data)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to send notification")
		return
	}

	utils.SuccessResponseWithMessage(c, "Notification sent successfully", nil)
}

func (h *AdminHandler) GetNotificationHistory(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))

	history, total, err := h.getNotificationHistory(page, limit)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to fetch notification history")
		return
	}

	meta := &utils.Meta{
		Page:       page,
		Limit:      limit,
		Total:      int(total),
		TotalPages: int((total + int64(limit) - 1) / int64(limit)),
	}

	utils.SuccessResponseWithMeta(c, history, meta)
}

func (h *AdminHandler) GetNotificationSettings(c *gin.Context) {
	settings := h.getNotificationSettings()
	utils.SuccessResponse(c, settings)
}

func (h *AdminHandler) UpdateNotificationSettings(c *gin.Context) {
	var updateData map[string]interface{}
	if err := c.ShouldBindJSON(&updateData); err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid settings data")
		return
	}

	err := h.updateNotificationSettings(updateData)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to update notification settings")
		return
	}

	utils.SuccessResponseWithMessage(c, "Notification settings updated successfully", nil)
}

// API Management

func (h *AdminHandler) GetAPIKeys(c *gin.Context) {
	keys := h.getAPIKeys()
	utils.SuccessResponse(c, keys)
}

func (h *AdminHandler) CreateAPIKey(c *gin.Context) {
	var keyData struct {
		Name        string     `json:"name" binding:"required"`
		Permissions []string   `json:"permissions" binding:"required"`
		ExpiresAt   *time.Time `json:"expires_at"`
	}

	if err := c.ShouldBindJSON(&keyData); err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid API key data")
		return
	}

	apiKey, err := h.createAPIKey(keyData.Name, keyData.Permissions, keyData.ExpiresAt)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to create API key")
		return
	}

	logger.LogAdminAction(c.GetString("admin_id"), "api_key_created", apiKey.ID, map[string]interface{}{
		"name":        keyData.Name,
		"permissions": keyData.Permissions,
	})

	utils.SuccessResponseWithMessage(c, "API key created successfully", apiKey)
}

func (h *AdminHandler) RevokeAPIKey(c *gin.Context) {
	keyID := c.Param("id")

	err := h.revokeAPIKey(keyID)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to revoke API key")
		return
	}

	logger.LogAdminAction(c.GetString("admin_id"), "api_key_revoked", keyID, nil)

	utils.SuccessResponseWithMessage(c, "API key revoked successfully", nil)
}

func (h *AdminHandler) GetAPIUsage(c *gin.Context) {
	period := c.DefaultQuery("period", "7d")
	usage := h.getAPIUsage(period)
	utils.SuccessResponse(c, usage)
}

func (h *AdminHandler) GetRateLimits(c *gin.Context) {
	limits := h.getRateLimits()
	utils.SuccessResponse(c, limits)
}

func (h *AdminHandler) UpdateRateLimits(c *gin.Context) {
	var limitData map[string]interface{}
	if err := c.ShouldBindJSON(&limitData); err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid rate limit data")
		return
	}

	err := h.updateRateLimits(limitData)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to update rate limits")
		return
	}

	utils.SuccessResponseWithMessage(c, "Rate limits updated successfully", nil)
}

// File Management

func (h *AdminHandler) UploadFile(c *gin.Context) {
	file, header, err := c.Request.FormFile("file")
	if err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "No file uploaded")
		return
	}
	defer file.Close()

	uploadedFile, err := h.uploadFile(file, header, c.GetString("admin_id"))
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to upload file")
		return
	}

	utils.SuccessResponseWithMessage(c, "File uploaded successfully", uploadedFile)
}

func (h *AdminHandler) GetFiles(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	fileType := c.Query("type")

	files, total, err := h.getFiles(page, limit, fileType)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to fetch files")
		return
	}

	meta := &utils.Meta{
		Page:       page,
		Limit:      limit,
		Total:      int(total),
		TotalPages: int((total + int64(limit) - 1) / int64(limit)),
	}

	utils.SuccessResponseWithMeta(c, files, meta)
}

func (h *AdminHandler) DeleteFile(c *gin.Context) {
	fileID := c.Param("id")

	err := h.deleteFile(fileID)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to delete file")
		return
	}

	logger.LogAdminAction(c.GetString("admin_id"), "file_deleted", fileID, nil)

	utils.SuccessResponseWithMessage(c, "File deleted successfully", nil)
}

func (h *AdminHandler) GetStorageInfo(c *gin.Context) {
	info := h.getStorageInfo()
	utils.SuccessResponse(c, info)
}

func (h *AdminHandler) CleanupFiles(c *gin.Context) {
	var cleanupData struct {
		OlderThan int    `json:"older_than"` // days
		FileType  string `json:"file_type"`
	}

	if err := c.ShouldBindJSON(&cleanupData); err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid cleanup data")
		return
	}

	result, err := h.cleanupFiles(cleanupData.OlderThan, cleanupData.FileType)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to cleanup files")
		return
	}

	logger.LogAdminAction(c.GetString("admin_id"), "files_cleaned_up", "", map[string]interface{}{
		"older_than":    cleanupData.OlderThan,
		"file_type":     cleanupData.FileType,
		"deleted_count": result,
	})

	utils.SuccessResponseWithMessage(c, "File cleanup completed successfully", map[string]interface{}{
		"deleted_count": result,
	})
}

// Helper methods (implement these based on your specific needs)

func (h *AdminHandler) getReportsCount() int64 {
	// Implement report counting logic
	return 0
}

func (h *AdminHandler) getServerUptime() time.Duration {
	// Implement server uptime calculation
	return time.Hour * 24
}

func (h *AdminHandler) getUserReportCount(userID primitive.ObjectID) int64 {
	// Implement user report counting logic
	return 0
}

func (h *AdminHandler) getReportsWithPagination(filter bson.M, page, limit int) ([]models.Report, int64, error) {
	// Implement reports pagination logic
	return []models.Report{}, 0, nil
}

func (h *AdminHandler) getReportByID(reportID primitive.ObjectID) (*models.Report, error) {
	// Implement get report by ID logic
	return nil, nil
}

func (h *AdminHandler) resolveReport(reportID primitive.ObjectID, action, comments, adminID string) error {
	// Implement report resolution logic
	return nil
}

func (h *AdminHandler) dismissReport(reportID primitive.ObjectID, reason, adminID string) error {
	// Implement report dismissal logic
	return nil
}

func (h *AdminHandler) getModerationQueue() []interface{} {
	// Implement moderation queue logic
	return []interface{}{}
}

func (h *AdminHandler) approveContent(contentID, adminID string) error {
	// Implement content approval logic
	return nil
}

func (h *AdminHandler) rejectContent(contentID, reason, adminID string) error {
	// Implement content rejection logic
	return nil
}

func (h *AdminHandler) getFlaggedContent(page, limit int) ([]interface{}, int64, error) {
	// Implement flagged content logic
	return []interface{}{}, 0, nil
}

func (h *AdminHandler) bulkModerate(contentIDs []string, action, reason, adminID string) error {
	// Implement bulk moderation logic
	return nil
}

func (h *AdminHandler) getSystemInfo() map[string]interface{} {
	// Implement system info gathering
	return map[string]interface{}{
		"version":    "1.0.0",
		"go_version": "1.21",
		"uptime":     "24h",
	}
}

func (h *AdminHandler) getSystemHealth() map[string]interface{} {
	// Implement system health check
	return map[string]interface{}{
		"status":   "healthy",
		"database": "connected",
		"redis":    "connected",
		"memory":   "75%",
		"cpu":      "45%",
	}
}

func (h *AdminHandler) getSystemLogs(level string, limit int) []interface{} {
	// Implement system logs retrieval
	return []interface{}{}
}

func (h *AdminHandler) clearCache(cacheType string) error {
	// Implement cache clearing logic
	return nil
}

func (h *AdminHandler) getDatabaseStats() map[string]interface{} {
	// Implement database statistics
	return map[string]interface{}{
		"total_collections": 10,
		"total_documents":   50000,
		"database_size":     "125MB",
	}
}

func (h *AdminHandler) cleanupDatabase() error {
	// Implement database cleanup logic
	return nil
}

func (h *AdminHandler) createBackup(backupType string) (map[string]interface{}, error) {
	// Implement backup creation logic
	return map[string]interface{}{
		"backup_id":  "backup_" + time.Now().Format("20060102_150405"),
		"type":       backupType,
		"created_at": time.Now(),
	}, nil
}

func (h *AdminHandler) restoreBackup(backupID string) error {
	// Implement backup restoration logic
	return nil
}

func (h *AdminHandler) getAnalyticsOverview(period string) map[string]interface{} {
	// Implement analytics overview
	return map[string]interface{}{
		"total_users":  10000,
		"total_chats":  50000,
		"active_users": 2500,
		"avg_duration": "5m 30s",
	}
}

func (h *AdminHandler) getRegionAnalytics() map[string]interface{} {
	// Implement region analytics
	return map[string]interface{}{
		"us-east":      35.5,
		"eu-west":      28.2,
		"ap-southeast": 20.1,
		"ap-northeast": 10.8,
		"us-west":      5.4,
	}
}

func (h *AdminHandler) getPerformanceAnalytics(period string) map[string]interface{} {
	// Implement performance analytics
	return map[string]interface{}{
		"avg_response_time": "150ms",
		"throughput":        "1000 req/min",
		"error_rate":        "0.1%",
	}
}

func (h *AdminHandler) getRevenueAnalytics(period string) map[string]interface{} {
	// Implement revenue analytics (if applicable)
	return map[string]interface{}{
		"total_revenue": 0,
		"subscriptions": 0,
	}
}

func (h *AdminHandler) exportAnalytics(format, period string) ([]byte, error) {
	// Implement analytics export
	return []byte{}, nil
}

func (h *AdminHandler) getCustomAnalytics(metrics []string, filters map[string]interface{}, groupBy, period string, dateRange []string) (map[string]interface{}, error) {
	// Implement custom analytics query
	return map[string]interface{}{}, nil
}

func (h *AdminHandler) getNotificationTemplates() []interface{} {
	// Implement notification templates retrieval
	return []interface{}{}
}

func (h *AdminHandler) updateNotificationTemplate(templateID string, data map[string]interface{}) error {
	// Implement template update logic
	return nil
}

func (h *AdminHandler) sendNotification(notType string, recipients []string, subject, message string, data map[string]interface{}) error {
	// Implement notification sending logic
	return nil
}

func (h *AdminHandler) getNotificationHistory(page, limit int) ([]interface{}, int64, error) {
	// Implement notification history retrieval
	return []interface{}{}, 0, nil
}

func (h *AdminHandler) getNotificationSettings() map[string]interface{} {
	// Implement notification settings retrieval
	return map[string]interface{}{}
}

func (h *AdminHandler) updateNotificationSettings(data map[string]interface{}) error {
	// Implement notification settings update
	return nil
}

func (h *AdminHandler) getAPIKeys() []interface{} {
	// Implement API keys retrieval
	return []interface{}{}
}

func (h *AdminHandler) createAPIKey(name string, permissions []string, expiresAt *time.Time) (map[string]interface{}, error) {
	// Implement API key creation
	return map[string]interface{}{
		"id":   "api_" + time.Now().Format("20060102150405"),
		"key":  "ak_" + utils.HashSHA256(name + time.Now().String())[:32],
		"name": name,
	}, nil
}

func (h *AdminHandler) revokeAPIKey(keyID string) error {
	// Implement API key revocation
	return nil
}

func (h *AdminHandler) getAPIUsage(period string) map[string]interface{} {
	// Implement API usage statistics
	return map[string]interface{}{
		"total_requests": 10000,
		"successful":     9850,
		"errors":         150,
	}
}

func (h *AdminHandler) getRateLimits() map[string]interface{} {
	// Implement rate limits retrieval
	return map[string]interface{}{}
}

func (h *AdminHandler) updateRateLimits(data map[string]interface{}) error {
	// Implement rate limits update
	return nil
}

func (h *AdminHandler) uploadFile(file interface{}, header interface{}, adminID string) (map[string]interface{}, error) {
	// Implement file upload logic
	return map[string]interface{}{
		"id":          "file_" + time.Now().Format("20060102150405"),
		"filename":    "uploaded_file.txt",
		"size":        1024,
		"uploaded_by": adminID,
	}, nil
}

func (h *AdminHandler) getFiles(page, limit int, fileType string) ([]interface{}, int64, error) {
	// Implement files retrieval
	return []interface{}{}, 0, nil
}

func (h *AdminHandler) deleteFile(fileID string) error {
	// Implement file deletion
	return nil
}

func (h *AdminHandler) getStorageInfo() map[string]interface{} {
	// Implement storage info retrieval
	return map[string]interface{}{
		"total_size": "1.2GB",
		"used_size":  "890MB",
		"free_size":  "310MB",
	}
}

func (h *AdminHandler) cleanupFiles(olderThan int, fileType string) (int, error) {
	// Implement file cleanup logic
	return 25, nil
}
