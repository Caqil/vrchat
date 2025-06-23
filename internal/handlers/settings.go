package handlers

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"vrchat/internal/services"
	"vrchat/internal/utils"
	"vrchat/pkg/logger"

	"github.com/gin-gonic/gin"
)

type SettingsHandler struct {
	settingsService *services.SettingsService
}

func NewSettingsHandler(settingsService *services.SettingsService) *SettingsHandler {
	return &SettingsHandler{
		settingsService: settingsService,
	}
}

// ================================
// Public Settings (read-only, for general app info)
// ================================

func (h *SettingsHandler) GetPublicSettings(c *gin.Context) {
	settings, err := h.settingsService.GetPublicSettings()
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to get public settings")
		return
	}

	// Helper function to safely get values from map with default fallbacks
	getString := func(key, defaultValue string) string {
		if val, ok := settings[key].(string); ok {
			return val
		}
		return defaultValue
	}

	getInt := func(key string, defaultValue int) int {
		if val, ok := settings[key].(int); ok {
			return val
		}
		if val, ok := settings[key].(float64); ok {
			return int(val)
		}
		return defaultValue
	}

	getBool := func(key string, defaultValue bool) bool {
		if val, ok := settings[key].(bool); ok {
			return val
		}
		return defaultValue
	}

	// Filter out sensitive information for public consumption
	publicSettings := map[string]interface{}{
		"app_name":                getString("app_name", "Omegle Clone"),
		"app_description":         getString("app_description", "Random video chat application"),
		"max_users_per_room":      getInt("max_users_per_room", 2),
		"chat_timeout":            getInt("chat_timeout", 30),
		"enable_age_verification": getBool("enable_age_verification", false),
		"minimum_age":             getInt("minimum_age", 13),
		"maintenance_mode":        getBool("maintenance_mode", false),
		"maintenance_message":     getString("maintenance_message", "System maintenance in progress"),
		"supported_chat_types":    []string{"text", "video", "audio"},
		"supported_languages":     h.getSupportedLanguages(),
		"available_regions":       h.getAvailableRegions(),
		"features": map[string]bool{
			"interest_matching":  true,
			"region_matching":    true,
			"language_matching":  true,
			"profanity_filter":   getBool("enable_profanity_filter", true),
			"content_moderation": getBool("enable_moderation", true),
			"file_sharing":       true,
			"screen_sharing":     true,
			"voice_chat":         true,
			"video_chat":         true,
		},
		"limits": map[string]interface{}{
			"max_message_length":  1000,
			"max_file_size_mb":    10,
			"max_interests":       10,
			"session_timeout_min": getInt("chat_timeout", 30),
		},
	}

	utils.SuccessResponse(c, publicSettings)
}

// ================================
// Application Settings (Admin Only)
// ================================

func (h *SettingsHandler) GetSettings(c *gin.Context) {
	settings, err := h.settingsService.GetSettings()
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to get settings")
		return
	}

	utils.SuccessResponse(c, settings)
}

func (h *SettingsHandler) UpdateSettings(c *gin.Context) {
	var updateData map[string]interface{}

	if err := c.ShouldBindJSON(&updateData); err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid settings data")
		return
	}

	// Validate settings
	if err := h.validateAppSettings(updateData); err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, err.Error())
		return
	}

	err := h.settingsService.UpdateSettings(updateData)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to update settings")
		return
	}

	logger.LogSystemAction("app_settings_updated", map[string]interface{}{
		"updated_fields": updateData,
		"admin_id":       c.GetString("user_id"),
		"ip":             c.ClientIP(),
	})

	utils.SuccessResponseWithMessage(c, "Settings updated successfully", updateData)
}

// ================================
// User Settings
// ================================

func (h *SettingsHandler) GetUserSettings(c *gin.Context) {
	userID := c.GetString("user_id")

	settings, err := h.settingsService.GetUserSettings(userID)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to get user settings")
		return
	}

	utils.SuccessResponse(c, settings)
}

func (h *SettingsHandler) UpdateUserSettings(c *gin.Context) {
	userID := c.GetString("user_id")

	var updateData map[string]interface{}

	if err := c.ShouldBindJSON(&updateData); err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid user settings data")
		return
	}

	// Validate user settings
	if err := h.validateUserSettings(updateData); err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, err.Error())
		return
	}

	err := h.settingsService.UpdateUserSettings(userID, updateData)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to update user settings")
		return
	}

	logger.LogUserAction(userID, "user_settings_updated", map[string]interface{}{
		"updated_fields": updateData,
		"ip":             c.ClientIP(),
	})

	utils.SuccessResponseWithMessage(c, "User settings updated successfully", updateData)
}

func (h *SettingsHandler) ResetUserSettings(c *gin.Context) {
	userID := c.GetString("user_id")

	defaultSettings := h.getDefaultUserSettings()
	err := h.settingsService.UpdateUserSettings(userID, defaultSettings)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to reset user settings")
		return
	}

	logger.LogUserAction(userID, "user_settings_reset", map[string]interface{}{
		"ip": c.ClientIP(),
	})

	utils.SuccessResponseWithMessage(c, "User settings reset to defaults", defaultSettings)
}

// ================================
// Chat Preferences
// ================================

func (h *SettingsHandler) GetChatPreferences(c *gin.Context) {
	userID := c.GetString("user_id")

	preferences, err := h.settingsService.GetChatPreferences(userID)
	if err != nil {
		// Return default preferences if none exist
		preferences = h.settingsService.GetDefaultChatPreferences()
	}

	utils.SuccessResponse(c, preferences)
}

func (h *SettingsHandler) UpdateChatPreferences(c *gin.Context) {
	userID := c.GetString("user_id")

	var preferencesData struct {
		DefaultChatType        string   `json:"default_chat_type"`
		PreferredLanguages     []string `json:"preferred_languages"`
		PreferredRegions       []string `json:"preferred_regions"`
		AutoAcceptChats        bool     `json:"auto_accept_chats"`
		EnableTypingIndicator  bool     `json:"enable_typing_indicator"`
		EnableReadReceipts     bool     `json:"enable_read_receipts"`
		MessagePreview         bool     `json:"message_preview"`
		SaveChatHistory        bool     `json:"save_chat_history"`
		BlockAnonymous         bool     `json:"block_anonymous"`
		RequireAgeVerification bool     `json:"require_age_verification"`
		MaxChatDuration        int      `json:"max_chat_duration"`
		AutoEndInactiveChats   bool     `json:"auto_end_inactive_chats"`
	}

	if err := c.ShouldBindJSON(&preferencesData); err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid preferences data")
		return
	}

	// Validate preferences
	if err := h.validateChatPreferences(&preferencesData); err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, err.Error())
		return
	}

	// Convert to map for service layer processing
	preferences := map[string]interface{}{
		"default_chat_type":        preferencesData.DefaultChatType,
		"preferred_languages":      preferencesData.PreferredLanguages,
		"preferred_regions":        preferencesData.PreferredRegions,
		"auto_accept_chats":        preferencesData.AutoAcceptChats,
		"enable_typing_indicator":  preferencesData.EnableTypingIndicator,
		"enable_read_receipts":     preferencesData.EnableReadReceipts,
		"message_preview":          preferencesData.MessagePreview,
		"save_chat_history":        preferencesData.SaveChatHistory,
		"block_anonymous":          preferencesData.BlockAnonymous,
		"require_age_verification": preferencesData.RequireAgeVerification,
		"max_chat_duration":        preferencesData.MaxChatDuration,
		"auto_end_inactive_chats":  preferencesData.AutoEndInactiveChats,
		"updated_at":               time.Now(),
	}

	err := h.settingsService.UpdateChatPreferencesFromMap(userID, preferences)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to update chat preferences")
		return
	}

	logger.LogUserAction(userID, "chat_preferences_updated", map[string]interface{}{
		"preferences": preferences,
		"ip":          c.ClientIP(),
	})

	utils.SuccessResponseWithMessage(c, "Chat preferences updated successfully", preferences)
}

// ================================
// Privacy Settings
// ================================

func (h *SettingsHandler) GetPrivacySettings(c *gin.Context) {
	userID := c.GetString("user_id")

	privacy, err := h.settingsService.GetPrivacySettings(userID)
	if err != nil {
		// Return default privacy settings if none exist
		privacy = h.settingsService.GetDefaultPrivacySettings()
	}

	utils.SuccessResponse(c, privacy)
}

func (h *SettingsHandler) UpdatePrivacySettings(c *gin.Context) {
	userID := c.GetString("user_id")

	var privacyData struct {
		ShowOnlineStatus     bool `json:"show_online_status"`
		ShowTypingStatus     bool `json:"show_typing_status"`
		AllowScreenshots     bool `json:"allow_screenshots"`
		AllowRecording       bool `json:"allow_recording"`
		ShareLocation        bool `json:"share_location"`
		ShareInterests       bool `json:"share_interests"`
		AllowFriendRequests  bool `json:"allow_friend_requests"`
		ShowLastSeen         bool `json:"show_last_seen"`
		PublicProfile        bool `json:"public_profile"`
		SearchableProfile    bool `json:"searchable_profile"`
		BlockNewAccounts     bool `json:"block_new_accounts"`
		RequireVerifiedUsers bool `json:"require_verified_users"`
	}

	if err := c.ShouldBindJSON(&privacyData); err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid privacy settings data")
		return
	}

	privacy := map[string]interface{}{
		"show_online_status":     privacyData.ShowOnlineStatus,
		"show_typing_status":     privacyData.ShowTypingStatus,
		"allow_screenshots":      privacyData.AllowScreenshots,
		"allow_recording":        privacyData.AllowRecording,
		"share_location":         privacyData.ShareLocation,
		"share_interests":        privacyData.ShareInterests,
		"allow_friend_requests":  privacyData.AllowFriendRequests,
		"show_last_seen":         privacyData.ShowLastSeen,
		"public_profile":         privacyData.PublicProfile,
		"searchable_profile":     privacyData.SearchableProfile,
		"block_new_accounts":     privacyData.BlockNewAccounts,
		"require_verified_users": privacyData.RequireVerifiedUsers,
		"updated_at":             time.Now(),
	}

	err := h.settingsService.UpdatePrivacySettingsFromMap(userID, privacy)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to update privacy settings")
		return
	}

	logger.LogUserAction(userID, "privacy_settings_updated", map[string]interface{}{
		"privacy": privacy,
		"ip":      c.ClientIP(),
	})

	utils.SuccessResponseWithMessage(c, "Privacy settings updated successfully", privacy)
}

// ================================
// Notification Settings
// ================================

func (h *SettingsHandler) GetNotificationSettings(c *gin.Context) {
	userID := c.GetString("user_id")

	notifications, err := h.settingsService.GetNotificationSettings(userID)
	if err != nil {
		// Return default notification settings if none exist
		notifications = h.settingsService.GetDefaultNotificationSettings()
	}

	utils.SuccessResponse(c, notifications)
}

func (h *SettingsHandler) UpdateNotificationSettings(c *gin.Context) {
	userID := c.GetString("user_id")

	var notificationData struct {
		EnablePushNotifications  bool   `json:"enable_push_notifications"`
		EnableEmailNotifications bool   `json:"enable_email_notifications"`
		EnableSMSNotifications   bool   `json:"enable_sms_notifications"`
		NotifyNewMessage         bool   `json:"notify_new_message"`
		NotifyFriendRequest      bool   `json:"notify_friend_request"`
		NotifySystemUpdates      bool   `json:"notify_system_updates"`
		NotifyPromotions         bool   `json:"notify_promotions"`
		NotificationSound        bool   `json:"notification_sound"`
		VibrationEnabled         bool   `json:"vibration_enabled"`
		QuietHoursEnabled        bool   `json:"quiet_hours_enabled"`
		QuietHoursStart          string `json:"quiet_hours_start"`
		QuietHoursEnd            string `json:"quiet_hours_end"`
		EmailDigestFrequency     string `json:"email_digest_frequency"`
	}

	if err := c.ShouldBindJSON(&notificationData); err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid notification settings data")
		return
	}

	// Validate notification settings
	if err := h.validateNotificationSettings(&notificationData); err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, err.Error())
		return
	}

	notifications := map[string]interface{}{
		"enable_push_notifications":  notificationData.EnablePushNotifications,
		"enable_email_notifications": notificationData.EnableEmailNotifications,
		"enable_sms_notifications":   notificationData.EnableSMSNotifications,
		"notify_new_message":         notificationData.NotifyNewMessage,
		"notify_friend_request":      notificationData.NotifyFriendRequest,
		"notify_system_updates":      notificationData.NotifySystemUpdates,
		"notify_promotions":          notificationData.NotifyPromotions,
		"notification_sound":         notificationData.NotificationSound,
		"vibration_enabled":          notificationData.VibrationEnabled,
		"quiet_hours_enabled":        notificationData.QuietHoursEnabled,
		"quiet_hours_start":          notificationData.QuietHoursStart,
		"quiet_hours_end":            notificationData.QuietHoursEnd,
		"email_digest_frequency":     notificationData.EmailDigestFrequency,
		"updated_at":                 time.Now(),
	}

	err := h.settingsService.UpdateNotificationSettingsFromMap(userID, notifications)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to update notification settings")
		return
	}

	logger.LogUserAction(userID, "notification_settings_updated", map[string]interface{}{
		"notifications": notifications,
		"ip":            c.ClientIP(),
	})

	utils.SuccessResponseWithMessage(c, "Notification settings updated successfully", notifications)
}

// ================================
// Accessibility Settings
// ================================

func (h *SettingsHandler) GetAccessibilitySettings(c *gin.Context) {
	userID := c.GetString("user_id")

	accessibility, err := h.settingsService.GetAccessibilitySettings(userID)
	if err != nil {
		// Return default accessibility settings if none exist
		accessibility = h.settingsService.GetDefaultAccessibilitySettings()
	}

	utils.SuccessResponse(c, accessibility)
}

func (h *SettingsHandler) UpdateAccessibilitySettings(c *gin.Context) {
	userID := c.GetString("user_id")

	var accessibilityData struct {
		HighContrast     bool    `json:"high_contrast"`
		ScreenReader     bool    `json:"screen_reader"`
		ReducedMotion    bool    `json:"reduced_motion"`
		ColorBlindMode   string  `json:"color_blind_mode"`
		FontSize         float64 `json:"font_size"`
		VoiceCommands    bool    `json:"voice_commands"`
		KeyboardShortcut bool    `json:"keyboard_shortcut"`
	}

	if err := c.ShouldBindJSON(&accessibilityData); err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid accessibility settings data")
		return
	}

	// Validate accessibility settings
	if err := h.validateAccessibilitySettings(&accessibilityData); err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, err.Error())
		return
	}

	accessibility := map[string]interface{}{
		"high_contrast":     accessibilityData.HighContrast,
		"screen_reader":     accessibilityData.ScreenReader,
		"reduced_motion":    accessibilityData.ReducedMotion,
		"color_blind_mode":  accessibilityData.ColorBlindMode,
		"font_size":         accessibilityData.FontSize,
		"voice_commands":    accessibilityData.VoiceCommands,
		"keyboard_shortcut": accessibilityData.KeyboardShortcut,
		"updated_at":        time.Now(),
	}

	err := h.settingsService.UpdateAccessibilitySettingsFromMap(userID, accessibility)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to update accessibility settings")
		return
	}

	logger.LogUserAction(userID, "accessibility_settings_updated", map[string]interface{}{
		"accessibility": accessibility,
		"ip":            c.ClientIP(),
	})

	utils.SuccessResponseWithMessage(c, "Accessibility settings updated successfully", accessibility)
}

// ================================
// Block User Functionality
// ================================

func (h *SettingsHandler) BlockUser(c *gin.Context) {
	userID := c.GetString("user_id")

	var blockData struct {
		BlockedUserID string `json:"blocked_user_id" binding:"required"`
		Reason        string `json:"reason"`
	}

	if err := c.ShouldBindJSON(&blockData); err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid block request data")
		return
	}

	// Validate that user is not trying to block themselves
	if userID == blockData.BlockedUserID {
		utils.ErrorResponse(c, http.StatusBadRequest, "Cannot block yourself")
		return
	}

	err := h.settingsService.BlockUser(userID, blockData.BlockedUserID, blockData.Reason)
	if err != nil {
		if strings.Contains(err.Error(), "already blocked") {
			utils.ErrorResponse(c, http.StatusConflict, err.Error())
			return
		}
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to block user")
		return
	}

	logger.LogUserAction(userID, "user_blocked", map[string]interface{}{
		"blocked_user": blockData.BlockedUserID,
		"reason":       blockData.Reason,
		"ip":           c.ClientIP(),
	})

	utils.SuccessResponseWithMessage(c, "User blocked successfully", nil)
}

func (h *SettingsHandler) UnblockUser(c *gin.Context) {
	userID := c.GetString("user_id")

	var unblockData struct {
		BlockedUserID string `json:"blocked_user_id" binding:"required"`
	}

	if err := c.ShouldBindJSON(&unblockData); err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid unblock request data")
		return
	}

	err := h.settingsService.UnblockUser(userID, unblockData.BlockedUserID)
	if err != nil {
		if strings.Contains(err.Error(), "was not blocked") {
			utils.ErrorResponse(c, http.StatusNotFound, err.Error())
			return
		}
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to unblock user")
		return
	}

	logger.LogUserAction(userID, "user_unblocked", map[string]interface{}{
		"blocked_user": unblockData.BlockedUserID,
		"ip":           c.ClientIP(),
	})

	utils.SuccessResponseWithMessage(c, "User unblocked successfully", nil)
}

func (h *SettingsHandler) GetBlockedUsers(c *gin.Context) {
	userID := c.GetString("user_id")

	blockedUsers, err := h.settingsService.GetBlockedUsers(userID)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to get blocked users")
		return
	}

	utils.SuccessResponse(c, blockedUsers)
}

// ================================
// Export/Import Settings
// ================================

func (h *SettingsHandler) ExportSettings(c *gin.Context) {
	userID := c.GetString("user_id")

	exportData, err := h.settingsService.ExportUserSettings(userID)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to export user settings")
		return
	}

	// Set headers for file download
	filename := fmt.Sprintf("user_settings_export_%s_%s.json", userID, time.Now().Format("20060102_150405"))
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
	c.Header("Content-Type", "application/json")

	logger.LogUserAction(userID, "settings_exported", map[string]interface{}{
		"ip": c.ClientIP(),
	})

	utils.SuccessResponse(c, exportData)
}

func (h *SettingsHandler) ImportSettings(c *gin.Context) {
	userID := c.GetString("user_id")

	var importData struct {
		Settings  map[string]interface{} `json:"settings" binding:"required"`
		Overwrite bool                   `json:"overwrite"`
	}

	if err := c.ShouldBindJSON(&importData); err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid import data")
		return
	}

	// Validate imported settings
	if err := h.validateImportedSettings(importData.Settings); err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, err.Error())
		return
	}

	err := h.settingsService.ImportUserSettings(userID, importData.Settings, importData.Overwrite)
	if err != nil {
		if strings.Contains(err.Error(), "already exist") {
			utils.ErrorResponse(c, http.StatusConflict, err.Error())
			return
		}
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to import settings")
		return
	}

	logger.LogUserAction(userID, "settings_imported", map[string]interface{}{
		"overwrite": importData.Overwrite,
		"ip":        c.ClientIP(),
	})

	utils.SuccessResponseWithMessage(c, "Settings imported successfully", nil)
}

// ================================
// Admin-level Settings Management
// ================================

func (h *SettingsHandler) BackupSettings(c *gin.Context) {
	backup, err := h.settingsService.BackupSettings()
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to backup settings")
		return
	}

	filename := fmt.Sprintf("settings_backup_%s.json", time.Now().Format("20060102_150405"))
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
	c.Header("Content-Type", "application/json")

	logger.LogSystemAction("settings_backup_created", map[string]interface{}{
		"admin_id": c.GetString("user_id"),
		"ip":       c.ClientIP(),
	})

	utils.SuccessResponse(c, backup)
}

func (h *SettingsHandler) RestoreSettings(c *gin.Context) {
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

	logger.LogSystemAction("settings_restored", map[string]interface{}{
		"admin_id": c.GetString("user_id"),
		"ip":       c.ClientIP(),
	})

	utils.SuccessResponseWithMessage(c, "Settings restored successfully", nil)
}

func (h *SettingsHandler) ResetToDefaults(c *gin.Context) {
	err := h.settingsService.ResetToDefaults()
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to reset settings")
		return
	}

	logger.LogSystemAction("settings_reset_to_defaults", map[string]interface{}{
		"admin_id": c.GetString("user_id"),
		"ip":       c.ClientIP(),
	})

	utils.SuccessResponseWithMessage(c, "Settings reset to defaults successfully", nil)
}

func (h *SettingsHandler) GetGeneralSettings(c *gin.Context) {
	settings, err := h.settingsService.GetGeneralSettings()
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to fetch general settings")
		return
	}
	utils.SuccessResponse(c, settings)
}

func (h *SettingsHandler) UpdateGeneralSettings(c *gin.Context) {
	var updateData map[string]interface{}
	if err := c.ShouldBindJSON(&updateData); err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid settings data")
		return
	}

	// Validate general settings
	if err := h.validateAppSettings(updateData); err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, err.Error())
		return
	}

	err := h.settingsService.UpdateGeneralSettings(updateData)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to update general settings")
		return
	}

	logger.LogSystemAction("general_settings_updated", map[string]interface{}{
		"admin_id":       c.GetString("user_id"),
		"updated_fields": updateData,
		"ip":             c.ClientIP(),
	})

	utils.SuccessResponseWithMessage(c, "General settings updated successfully", nil)
}

func (h *SettingsHandler) GetModerationSettings(c *gin.Context) {
	settings, err := h.settingsService.GetModerationSettings()
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to fetch moderation settings")
		return
	}
	utils.SuccessResponse(c, settings)
}

func (h *SettingsHandler) UpdateModerationSettings(c *gin.Context) {
	var updateData map[string]interface{}
	if err := c.ShouldBindJSON(&updateData); err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid settings data")
		return
	}

	// Validate moderation settings
	if err := h.validateModerationSettings(updateData); err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, err.Error())
		return
	}

	err := h.settingsService.UpdateModerationSettings(updateData)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to update moderation settings")
		return
	}

	logger.LogSystemAction("moderation_settings_updated", map[string]interface{}{
		"admin_id":       c.GetString("user_id"),
		"updated_fields": updateData,
		"ip":             c.ClientIP(),
	})

	utils.SuccessResponseWithMessage(c, "Moderation settings updated successfully", nil)
}

func (h *SettingsHandler) SetMaintenanceMode(c *gin.Context) {
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
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to set maintenance mode")
		return
	}

	logger.LogSystemAction("maintenance_mode_updated", map[string]interface{}{
		"admin_id": c.GetString("user_id"),
		"enabled":  maintenanceData.Enabled,
		"message":  maintenanceData.Message,
		"ip":       c.ClientIP(),
	})

	utils.SuccessResponseWithMessage(c, "Maintenance mode updated successfully", nil)
}

func (h *SettingsHandler) GetMaintenanceMode(c *gin.Context) {
	enabled, message, err := h.settingsService.IsMaintenanceMode()
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to get maintenance mode status")
		return
	}

	response := map[string]interface{}{
		"enabled": enabled,
		"message": message,
	}

	utils.SuccessResponse(c, response)
}

// ================================
// Admin Data Management
// ================================

// func (h *SettingsHandler) GetAllUserSettings(c *gin.Context) {
// 	page := getPageFromQuery(c, 1)
// 	limit := getLimitFromQuery(c, 50)

// 	userSettings, total, err := h.settingsService.GetAllUserSettings(page, limit)
// 	if err != nil {
// 		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to get user settings")
// 		return
// 	}

// 	response := map[string]interface{}{
// 		"data":        userSettings,
// 		"total":       total,
// 		"page":        page,
// 		"limit":       limit,
// 		"total_pages": (total + int64(limit) - 1) / int64(limit),
// 	}

// 	utils.SuccessResponse(c, response)
// }

// func (h *SettingsHandler) DeleteUserSettings(c *gin.Context) {
// 	userID := c.Param("userId")
// 	if userID == "" {
// 		utils.ErrorResponse(c, http.StatusBadRequest, "User ID is required")
// 		return
// 	}

// 	err := h.settingsService.DeleteUserSettings(userID)
// 	if err != nil {
// 		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to delete user settings")
// 		return
// 	}

// 	logger.LogSystemAction("user_settings_deleted", map[string]interface{}{
// 		"admin_id":        c.GetString("user_id"),
// 		"deleted_user_id": userID,
// 		"ip":              c.ClientIP(),
// 	})

// 	utils.SuccessResponseWithMessage(c, "User settings deleted successfully", nil)
// }

// func (h *SettingsHandler) GetSettingsStats(c *gin.Context) {
// 	stats, err := h.settingsService.GetSettingsStats()
// 	if err != nil {
// 		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to get settings statistics")
// 		return
// 	}

// 	utils.SuccessResponse(c, stats)
// }

// func (h *SettingsHandler) ValidateSettingsIntegrity(c *gin.Context) {
// 	report, err := h.settingsService.ValidateSettingsIntegrity()
// 	if err != nil {
// 		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to validate settings integrity")
// 		return
// 	}

// 	utils.SuccessResponse(c, report)
// }

// func (h *SettingsHandler) CleanupOrphanedData(c *gin.Context) {
// 	err := h.settingsService.CleanupOrphanedData()
// 	if err != nil {
// 		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to cleanup orphaned data")
// 		return
// 	}

// 	logger.LogSystemAction("orphaned_data_cleanup", map[string]interface{}{
// 		"admin_id": c.GetString("user_id"),
// 		"ip":       c.ClientIP(),
// 	})

// 	utils.SuccessResponseWithMessage(c, "Orphaned data cleanup completed successfully", nil)
// }

// ================================
// Helper Methods
// ================================

func (h *SettingsHandler) getSupportedLanguages() []string {
	return []string{
		"en", "es", "fr", "de", "it", "pt", "ru", "zh", "ja", "ko",
		"ar", "hi", "th", "vi", "id", "ms", "tr", "pl", "nl", "sv",
	}
}

func (h *SettingsHandler) getAvailableRegions() []string {
	return []string{"us-east", "us-west", "eu-west", "ap-southeast", "ap-northeast"}
}

func (h *SettingsHandler) getDefaultUserSettings() map[string]interface{} {
	return map[string]interface{}{
		"theme":                   "auto",
		"language":                "en",
		"timezone":                "UTC",
		"date_format":             "DD/MM/YYYY",
		"time_format":             "24h",
		"enable_sound":            true,
		"enable_notifications":    true,
		"auto_save_preferences":   true,
		"remember_last_region":    true,
		"remember_last_interests": true,
		"created_at":              time.Now(),
		"updated_at":              time.Now(),
	}
}

// ================================
// Validation Methods
// ================================

func (h *SettingsHandler) validateAppSettings(settings map[string]interface{}) error {
	if chatTimeout, exists := settings["chat_timeout"]; exists {
		if timeout, ok := chatTimeout.(float64); ok {
			if timeout < 5 || timeout > 480 {
				return fmt.Errorf("chat timeout must be between 5 and 480 minutes")
			}
		}
	}

	if maxUsers, exists := settings["max_users_per_room"]; exists {
		if users, ok := maxUsers.(float64); ok {
			if users < 2 || users > 10 {
				return fmt.Errorf("max users per room must be between 2 and 10")
			}
		}
	}

	if minAge, exists := settings["minimum_age"]; exists {
		if age, ok := minAge.(float64); ok {
			if age < 13 || age > 99 {
				return fmt.Errorf("minimum age must be between 13 and 99")
			}
		}
	}

	return nil
}

func (h *SettingsHandler) validateUserSettings(settings map[string]interface{}) error {
	if theme, exists := settings["theme"]; exists {
		validThemes := []string{"light", "dark", "auto"}
		if !h.isValidTheme(theme.(string), validThemes) {
			return fmt.Errorf("invalid theme. Valid options: %v", validThemes)
		}
	}

	if language, exists := settings["language"]; exists {
		if !h.isValidLanguage(language.(string)) {
			return fmt.Errorf("invalid language code")
		}
	}

	if timezone, exists := settings["timezone"]; exists {
		if _, err := time.LoadLocation(timezone.(string)); err != nil {
			return fmt.Errorf("invalid timezone")
		}
	}

	return nil
}

func (h *SettingsHandler) validateChatPreferences(prefs interface{}) error {
	// Add validation logic for chat preferences
	type ChatPrefs struct {
		DefaultChatType    string   `json:"default_chat_type"`
		PreferredLanguages []string `json:"preferred_languages"`
		PreferredRegions   []string `json:"preferred_regions"`
		MaxChatDuration    int      `json:"max_chat_duration"`
	}

	// Type assertion to validate structure
	if p, ok := prefs.(*ChatPrefs); ok {
		validChatTypes := []string{"text", "video", "audio"}
		if !h.contains(validChatTypes, p.DefaultChatType) {
			return fmt.Errorf("invalid chat type. Valid options: %v", validChatTypes)
		}

		if p.MaxChatDuration < 1 || p.MaxChatDuration > 480 {
			return fmt.Errorf("max chat duration must be between 1 and 480 minutes")
		}

		for _, lang := range p.PreferredLanguages {
			if !h.isValidLanguage(lang) {
				return fmt.Errorf("invalid language code: %s", lang)
			}
		}

		availableRegions := h.getAvailableRegions()
		for _, region := range p.PreferredRegions {
			if !h.contains(availableRegions, region) {
				return fmt.Errorf("invalid region: %s", region)
			}
		}
	}

	return nil
}

func (h *SettingsHandler) validateNotificationSettings(notifications interface{}) error {
	type NotificationSettings struct {
		QuietHoursStart      string `json:"quiet_hours_start"`
		QuietHoursEnd        string `json:"quiet_hours_end"`
		EmailDigestFrequency string `json:"email_digest_frequency"`
	}

	if n, ok := notifications.(*NotificationSettings); ok {
		// Validate time format
		if n.QuietHoursStart != "" {
			if _, err := time.Parse("15:04", n.QuietHoursStart); err != nil {
				return fmt.Errorf("invalid quiet hours start time format. Use HH:MM")
			}
		}

		if n.QuietHoursEnd != "" {
			if _, err := time.Parse("15:04", n.QuietHoursEnd); err != nil {
				return fmt.Errorf("invalid quiet hours end time format. Use HH:MM")
			}
		}

		// Validate email digest frequency
		validFrequencies := []string{"immediate", "daily", "weekly", "never"}
		if !h.contains(validFrequencies, n.EmailDigestFrequency) {
			return fmt.Errorf("invalid email digest frequency. Valid options: %v", validFrequencies)
		}
	}

	return nil
}

func (h *SettingsHandler) validateAccessibilitySettings(accessibility interface{}) error {
	type AccessibilitySettings struct {
		ColorBlindMode string  `json:"color_blind_mode"`
		FontSize       float64 `json:"font_size"`
	}

	if a, ok := accessibility.(*AccessibilitySettings); ok {
		validColorBlindModes := []string{"none", "protanopia", "deuteranopia", "tritanopia"}
		if !h.contains(validColorBlindModes, a.ColorBlindMode) {
			return fmt.Errorf("invalid color blind mode. Valid options: %v", validColorBlindModes)
		}

		if a.FontSize < 0.5 || a.FontSize > 3.0 {
			return fmt.Errorf("font size must be between 0.5 and 3.0")
		}
	}

	return nil
}

func (h *SettingsHandler) validateModerationSettings(settings map[string]interface{}) error {
	if bannedWords, exists := settings["banned_words"]; exists {
		if words, ok := bannedWords.([]interface{}); ok {
			if len(words) > 1000 {
				return fmt.Errorf("too many banned words. Maximum allowed: 1000")
			}
		}
	}

	if bannedCountries, exists := settings["banned_countries"]; exists {
		if countries, ok := bannedCountries.([]interface{}); ok {
			if len(countries) > 250 {
				return fmt.Errorf("too many banned countries. Maximum allowed: 250")
			}
		}
	}

	if threshold, exists := settings["auto_ban_threshold"]; exists {
		if t, ok := threshold.(float64); ok {
			if t < 1 || t > 100 {
				return fmt.Errorf("auto ban threshold must be between 1 and 100")
			}
		}
	}

	if threshold, exists := settings["report_threshold"]; exists {
		if t, ok := threshold.(float64); ok {
			if t < 1 || t > 100 {
				return fmt.Errorf("report threshold must be between 1 and 100")
			}
		}
	}

	return nil
}

func (h *SettingsHandler) validateImportedSettings(settings map[string]interface{}) error {
	// Basic validation for imported settings structure
	if version, exists := settings["version"]; exists {
		if version != "1.0" {
			return fmt.Errorf("unsupported export version")
		}
	}

	if version, exists := settings["export_version"]; exists {
		if version != "1.0" {
			return fmt.Errorf("unsupported export version")
		}
	}

	return nil
}

// ================================
// Utility Methods
// ================================

func (h *SettingsHandler) isValidTheme(theme string, validThemes []string) bool {
	return h.contains(validThemes, theme)
}

func (h *SettingsHandler) isValidLanguage(language string) bool {
	supportedLanguages := h.getSupportedLanguages()
	return h.contains(supportedLanguages, language)
}

func (h *SettingsHandler) contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// ================================
// Additional Helper Methods
// ================================

func (h *SettingsHandler) getChatTypes() []string {
	return []string{"text", "video", "audio"}
}

func (h *SettingsHandler) getTimeFormats() []string {
	return []string{"12h", "24h"}
}

func (h *SettingsHandler) getDateFormats() []string {
	return []string{"DD/MM/YYYY", "MM/DD/YYYY", "YYYY-MM-DD", "DD-MM-YYYY", "MM-DD-YYYY"}
}

func (h *SettingsHandler) getThemes() []string {
	return []string{"light", "dark", "auto"}
}

func (h *SettingsHandler) getColorBlindModes() []string {
	return []string{"none", "protanopia", "deuteranopia", "tritanopia"}
}

func (h *SettingsHandler) getEmailDigestFrequencies() []string {
	return []string{"immediate", "daily", "weekly", "never"}
}

func (h *SettingsHandler) isValidTimeFormat(format string) bool {
	_, err := time.Parse("15:04", format)
	return err == nil
}

func (h *SettingsHandler) isValidEmail(email string) bool {
	// Basic email validation - you might want to use a more robust solution
	return strings.Contains(email, "@") && strings.Contains(email, ".")
}

func (h *SettingsHandler) sanitizeString(input string) string {
	// Basic string sanitization
	return strings.TrimSpace(input)
}

func (h *SettingsHandler) validateStringLength(input string, minLen, maxLen int) bool {
	length := len(input)
	return length >= minLen && length <= maxLen
}

// Utility functions that might be missing from utils package
func getPageFromQuery(c *gin.Context, defaultPage int) int {
	page := c.DefaultQuery("page", fmt.Sprintf("%d", defaultPage))
	if p, err := strconv.Atoi(page); err == nil && p > 0 {
		return p
	}
	return defaultPage
}

func getLimitFromQuery(c *gin.Context, defaultLimit int) int {
	limit := c.DefaultQuery("limit", fmt.Sprintf("%d", defaultLimit))
	if l, err := strconv.Atoi(limit); err == nil && l > 0 && l <= 100 {
		return l
	}
	return defaultLimit
}
