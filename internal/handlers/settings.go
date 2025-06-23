package handlers

import (
	"fmt"
	"net/http"
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

// Public Settings (read-only, for general app info)

func (h *SettingsHandler) GetPublicSettings(c *gin.Context) {
	settings, err := h.settingsService.GetPublicSettings()
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to get public settings")
		return
	}

	// Filter out sensitive information for public consumption
	publicSettings := map[string]interface{}{
		"app_name":                settings.AppName,
		"app_description":         settings.AppDescription,
		"max_users_per_room":      settings.MaxUsersPerRoom,
		"chat_timeout":            settings.ChatTimeout,
		"enable_age_verification": settings.EnableAgeVerification,
		"minimum_age":             settings.MinimumAge,
		"maintenance_mode":        settings.MaintenanceMode,
		"maintenance_message":     settings.MaintenanceMessage,
		"supported_chat_types":    []string{"text", "video", "audio"},
		"supported_languages":     h.getSupportedLanguages(),
		"available_regions":       h.getAvailableRegions(),
		"features": map[string]bool{
			"interest_matching":  true,
			"region_matching":    true,
			"language_matching":  true,
			"profanity_filter":   settings.EnableProfanityFilter,
			"content_moderation": settings.EnableModeration,
			"file_sharing":       true,
			"screen_sharing":     true,
			"voice_chat":         true,
			"video_chat":         true,
		},
		"limits": map[string]interface{}{
			"max_message_length":  1000,
			"max_file_size_mb":    10,
			"max_interests":       10,
			"session_timeout_min": settings.ChatTimeout,
		},
	}

	utils.SuccessResponse(c, publicSettings)
}

// Protected Settings (require authentication)

func (h *SettingsHandler) GetUserSettings(c *gin.Context) {
	userID := c.GetString("user_id")

	userSettings, err := h.settingsService.GetUserSettings(userID)
	if err != nil {
		// Return default settings if user settings don't exist
		userSettings = h.getDefaultUserSettings()
	}

	utils.SuccessResponse(c, userSettings)
}

func (h *SettingsHandler) UpdateUserSettings(c *gin.Context) {
	userID := c.GetString("user_id")

	var updateData map[string]interface{}
	if err := c.ShouldBindJSON(&updateData); err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid settings data")
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

// Chat Preferences

func (h *SettingsHandler) GetChatPreferences(c *gin.Context) {
	userID := c.GetString("user_id")

	preferences, err := h.settingsService.GetChatPreferences(userID)
	if err != nil {
		// Return default preferences if none exist
		preferences = h.getDefaultChatPreferences()
	}

	utils.SuccessResponse(c, preferences)
}

func (h *SettingsHandler) UpdateChatPreferences(c *gin.Context) {
	userID := c.GetString("user_id")

	var preferencesData struct {
		DefaultChatType     string   `json:"default_chat_type"`
		PreferredLanguages  []string `json:"preferred_languages"`
		PreferredRegions    []string `json:"preferred_regions"`
		Interests           []string `json:"interests"`
		AllowVideoChat      bool     `json:"allow_video_chat"`
		AllowAudioChat      bool     `json:"allow_audio_chat"`
		AutoMatchmaking     bool     `json:"auto_matchmaking"`
		MatchSameLanguage   bool     `json:"match_same_language"`
		MatchSameRegion     bool     `json:"match_same_region"`
		MatchSameInterests  bool     `json:"match_same_interests"`
		BlockAdultContent   bool     `json:"block_adult_content"`
		EnableNotifications bool     `json:"enable_notifications"`
		MaxWaitTime         int      `json:"max_wait_time"` // in seconds
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

	// Convert to map for storage
	preferences := map[string]interface{}{
		"default_chat_type":    preferencesData.DefaultChatType,
		"preferred_languages":  preferencesData.PreferredLanguages,
		"preferred_regions":    preferencesData.PreferredRegions,
		"interests":            preferencesData.Interests,
		"allow_video_chat":     preferencesData.AllowVideoChat,
		"allow_audio_chat":     preferencesData.AllowAudioChat,
		"auto_matchmaking":     preferencesData.AutoMatchmaking,
		"match_same_language":  preferencesData.MatchSameLanguage,
		"match_same_region":    preferencesData.MatchSameRegion,
		"match_same_interests": preferencesData.MatchSameInterests,
		"block_adult_content":  preferencesData.BlockAdultContent,
		"enable_notifications": preferencesData.EnableNotifications,
		"max_wait_time":        preferencesData.MaxWaitTime,
		"updated_at":           time.Now(),
	}

	err := h.settingsService.UpdateChatPreferences(userID, preferences)
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

// Privacy Settings

func (h *SettingsHandler) GetPrivacySettings(c *gin.Context) {
	userID := c.GetString("user_id")

	privacy, err := h.settingsService.GetPrivacySettings(userID)
	if err != nil {
		// Return default privacy settings
		privacy = h.getDefaultPrivacySettings()
	}

	utils.SuccessResponse(c, privacy)
}

func (h *SettingsHandler) UpdatePrivacySettings(c *gin.Context) {
	userID := c.GetString("user_id")

	var privacyData struct {
		ShowOnlineStatus     bool `json:"show_online_status"`
		AllowDirectMessages  bool `json:"allow_direct_messages"`
		ShareRegionInfo      bool `json:"share_region_info"`
		ShareLanguageInfo    bool `json:"share_language_info"`
		ShareInterests       bool `json:"share_interests"`
		StoreConversations   bool `json:"store_conversations"`
		AllowAnalytics       bool `json:"allow_analytics"`
		AllowCookies         bool `json:"allow_cookies"`
		BlockReportedUsers   bool `json:"block_reported_users"`
		RequireVerifiedUsers bool `json:"require_verified_users"`
	}

	if err := c.ShouldBindJSON(&privacyData); err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid privacy settings data")
		return
	}

	privacy := map[string]interface{}{
		"show_online_status":     privacyData.ShowOnlineStatus,
		"allow_direct_messages":  privacyData.AllowDirectMessages,
		"share_region_info":      privacyData.ShareRegionInfo,
		"share_language_info":    privacyData.ShareLanguageInfo,
		"share_interests":        privacyData.ShareInterests,
		"store_conversations":    privacyData.StoreConversations,
		"allow_analytics":        privacyData.AllowAnalytics,
		"allow_cookies":          privacyData.AllowCookies,
		"block_reported_users":   privacyData.BlockReportedUsers,
		"require_verified_users": privacyData.RequireVerifiedUsers,
		"updated_at":             time.Now(),
	}

	err := h.settingsService.UpdatePrivacySettings(userID, privacy)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to update privacy settings")
		return
	}

	logger.LogUserAction(userID, "privacy_settings_updated", map[string]interface{}{
		"settings": privacy,
		"ip":       c.ClientIP(),
	})

	utils.SuccessResponseWithMessage(c, "Privacy settings updated successfully", privacy)
}

// Notification Settings

func (h *SettingsHandler) GetNotificationSettings(c *gin.Context) {
	userID := c.GetString("user_id")

	notifications, err := h.settingsService.GetNotificationSettings(userID)
	if err != nil {
		// Return default notification settings
		notifications = h.getDefaultNotificationSettings()
	}

	utils.SuccessResponse(c, notifications)
}

func (h *SettingsHandler) UpdateNotificationSettings(c *gin.Context) {
	userID := c.GetString("user_id")

	var notificationData struct {
		EnablePushNotifications  bool   `json:"enable_push_notifications"`
		EnableEmailNotifications bool   `json:"enable_email_notifications"`
		EnableSoundNotifications bool   `json:"enable_sound_notifications"`
		NotifyOnNewMessage       bool   `json:"notify_on_new_message"`
		NotifyOnMatchFound       bool   `json:"notify_on_match_found"`
		NotifyOnUserJoined       bool   `json:"notify_on_user_joined"`
		NotifyOnUserLeft         bool   `json:"notify_on_user_left"`
		NotifyOnSystemUpdates    bool   `json:"notify_on_system_updates"`
		QuietHoursEnabled        bool   `json:"quiet_hours_enabled"`
		QuietHoursStart          string `json:"quiet_hours_start"`      // HH:MM format
		QuietHoursEnd            string `json:"quiet_hours_end"`        // HH:MM format
		NotificationFrequency    string `json:"notification_frequency"` // immediate, batched, daily
	}

	if err := c.ShouldBindJSON(&notificationData); err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid notification settings data")
		return
	}

	// Validate time formats
	if err := h.validateTimeFormat(notificationData.QuietHoursStart); err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid quiet hours start time format")
		return
	}

	if err := h.validateTimeFormat(notificationData.QuietHoursEnd); err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid quiet hours end time format")
		return
	}

	notifications := map[string]interface{}{
		"enable_push_notifications":  notificationData.EnablePushNotifications,
		"enable_email_notifications": notificationData.EnableEmailNotifications,
		"enable_sound_notifications": notificationData.EnableSoundNotifications,
		"notify_on_new_message":      notificationData.NotifyOnNewMessage,
		"notify_on_match_found":      notificationData.NotifyOnMatchFound,
		"notify_on_user_joined":      notificationData.NotifyOnUserJoined,
		"notify_on_user_left":        notificationData.NotifyOnUserLeft,
		"notify_on_system_updates":   notificationData.NotifyOnSystemUpdates,
		"quiet_hours_enabled":        notificationData.QuietHoursEnabled,
		"quiet_hours_start":          notificationData.QuietHoursStart,
		"quiet_hours_end":            notificationData.QuietHoursEnd,
		"notification_frequency":     notificationData.NotificationFrequency,
		"updated_at":                 time.Now(),
	}

	err := h.settingsService.UpdateNotificationSettings(userID, notifications)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to update notification settings")
		return
	}

	logger.LogUserAction(userID, "notification_settings_updated", map[string]interface{}{
		"settings": notifications,
		"ip":       c.ClientIP(),
	})

	utils.SuccessResponseWithMessage(c, "Notification settings updated successfully", notifications)
}

// Accessibility Settings

func (h *SettingsHandler) GetAccessibilitySettings(c *gin.Context) {
	userID := c.GetString("user_id")

	accessibility, err := h.settingsService.GetAccessibilitySettings(userID)
	if err != nil {
		// Return default accessibility settings
		accessibility = h.getDefaultAccessibilitySettings()
	}

	utils.SuccessResponse(c, accessibility)
}

func (h *SettingsHandler) UpdateAccessibilitySettings(c *gin.Context) {
	userID := c.GetString("user_id")

	var accessibilityData struct {
		HighContrastMode    bool    `json:"high_contrast_mode"`
		LargeFontSize       bool    `json:"large_font_size"`
		ScreenReaderSupport bool    `json:"screen_reader_support"`
		KeyboardNavigation  bool    `json:"keyboard_navigation"`
		ReducedMotion       bool    `json:"reduced_motion"`
		AudioDescriptions   bool    `json:"audio_descriptions"`
		ClosedCaptions      bool    `json:"closed_captions"`
		FontSizeMultiplier  float64 `json:"font_size_multiplier"`
		ColorScheme         string  `json:"color_scheme"` // light, dark, auto
		Language            string  `json:"language"`
		TextToSpeech        bool    `json:"text_to_speech"`
		SpeechToText        bool    `json:"speech_to_text"`
	}

	if err := c.ShouldBindJSON(&accessibilityData); err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid accessibility settings data")
		return
	}

	// Validate font size multiplier
	if accessibilityData.FontSizeMultiplier < 0.5 || accessibilityData.FontSizeMultiplier > 3.0 {
		utils.ErrorResponse(c, http.StatusBadRequest, "Font size multiplier must be between 0.5 and 3.0")
		return
	}

	// Validate color scheme
	validColorSchemes := []string{"light", "dark", "auto"}
	if !h.isValidColorScheme(accessibilityData.ColorScheme, validColorSchemes) {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid color scheme")
		return
	}

	accessibility := map[string]interface{}{
		"high_contrast_mode":    accessibilityData.HighContrastMode,
		"large_font_size":       accessibilityData.LargeFontSize,
		"screen_reader_support": accessibilityData.ScreenReaderSupport,
		"keyboard_navigation":   accessibilityData.KeyboardNavigation,
		"reduced_motion":        accessibilityData.ReducedMotion,
		"audio_descriptions":    accessibilityData.AudioDescriptions,
		"closed_captions":       accessibilityData.ClosedCaptions,
		"font_size_multiplier":  accessibilityData.FontSizeMultiplier,
		"color_scheme":          accessibilityData.ColorScheme,
		"language":              accessibilityData.Language,
		"text_to_speech":        accessibilityData.TextToSpeech,
		"speech_to_text":        accessibilityData.SpeechToText,
		"updated_at":            time.Now(),
	}

	err := h.settingsService.UpdateAccessibilitySettings(userID, accessibility)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to update accessibility settings")
		return
	}

	logger.LogUserAction(userID, "accessibility_settings_updated", map[string]interface{}{
		"settings": accessibility,
		"ip":       c.ClientIP(),
	})

	utils.SuccessResponseWithMessage(c, "Accessibility settings updated successfully", accessibility)
}

// Blocked Users Management

func (h *SettingsHandler) GetBlockedUsers(c *gin.Context) {
	userID := c.GetString("user_id")

	blockedUsers, err := h.settingsService.GetBlockedUsers(userID)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to get blocked users")
		return
	}

	utils.SuccessResponse(c, blockedUsers)
}

func (h *SettingsHandler) BlockUser(c *gin.Context) {
	userID := c.GetString("user_id")

	var blockData struct {
		BlockedUserID string `json:"blocked_user_id" binding:"required"`
		Reason        string `json:"reason"`
	}

	if err := c.ShouldBindJSON(&blockData); err != nil {
		utils.ValidationErrorResponse(c, map[string]string{
			"blocked_user_id": "User ID to block is required",
		})
		return
	}

	// Prevent users from blocking themselves
	if blockData.BlockedUserID == userID {
		utils.ErrorResponse(c, http.StatusBadRequest, "Cannot block yourself")
		return
	}

	err := h.settingsService.BlockUser(userID, blockData.BlockedUserID, blockData.Reason)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to block user")
		return
	}

	logger.LogUserAction(userID, "user_blocked", map[string]interface{}{
		"blocked_user_id": blockData.BlockedUserID,
		"reason":          blockData.Reason,
		"ip":              c.ClientIP(),
	})

	utils.SuccessResponseWithMessage(c, "User blocked successfully", nil)
}

func (h *SettingsHandler) UnblockUser(c *gin.Context) {
	userID := c.GetString("user_id")
	blockedUserID := c.Param("blocked_user_id")

	if blockedUserID == "" {
		utils.ErrorResponse(c, http.StatusBadRequest, "Blocked user ID is required")
		return
	}

	err := h.settingsService.UnblockUser(userID, blockedUserID)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to unblock user")
		return
	}

	logger.LogUserAction(userID, "user_unblocked", map[string]interface{}{
		"unblocked_user_id": blockedUserID,
		"ip":                c.ClientIP(),
	})

	utils.SuccessResponseWithMessage(c, "User unblocked successfully", nil)
}

// Export/Import Settings

func (h *SettingsHandler) ExportSettings(c *gin.Context) {
	userID := c.GetString("user_id")

	settings, err := h.settingsService.ExportUserSettings(userID)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to export settings")
		return
	}

	// Add metadata
	exportData := map[string]interface{}{
		"user_id":        userID,
		"exported_at":    time.Now(),
		"export_version": "1.0",
		"settings":       settings,
	}

	filename := fmt.Sprintf("user_settings_%s_%s.json", userID, time.Now().Format("20060102_150405"))
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
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to import settings")
		return
	}

	logger.LogUserAction(userID, "settings_imported", map[string]interface{}{
		"overwrite": importData.Overwrite,
		"ip":        c.ClientIP(),
	})

	utils.SuccessResponseWithMessage(c, "Settings imported successfully", nil)
}

// Helper methods

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

func (h *SettingsHandler) getDefaultChatPreferences() map[string]interface{} {
	return map[string]interface{}{
		"default_chat_type":    "text",
		"preferred_languages":  []string{"en"},
		"preferred_regions":    []string{},
		"interests":            []string{},
		"allow_video_chat":     true,
		"allow_audio_chat":     true,
		"auto_matchmaking":     true,
		"match_same_language":  false,
		"match_same_region":    false,
		"match_same_interests": false,
		"block_adult_content":  true,
		"enable_notifications": true,
		"max_wait_time":        300, // 5 minutes
		"created_at":           time.Now(),
		"updated_at":           time.Now(),
	}
}

func (h *SettingsHandler) getDefaultPrivacySettings() map[string]interface{} {
	return map[string]interface{}{
		"show_online_status":     true,
		"allow_direct_messages":  true,
		"share_region_info":      true,
		"share_language_info":    true,
		"share_interests":        true,
		"store_conversations":    false,
		"allow_analytics":        true,
		"allow_cookies":          true,
		"block_reported_users":   true,
		"require_verified_users": false,
		"created_at":             time.Now(),
		"updated_at":             time.Now(),
	}
}

func (h *SettingsHandler) getDefaultNotificationSettings() map[string]interface{} {
	return map[string]interface{}{
		"enable_push_notifications":  true,
		"enable_email_notifications": false,
		"enable_sound_notifications": true,
		"notify_on_new_message":      true,
		"notify_on_match_found":      true,
		"notify_on_user_joined":      true,
		"notify_on_user_left":        true,
		"notify_on_system_updates":   false,
		"quiet_hours_enabled":        false,
		"quiet_hours_start":          "22:00",
		"quiet_hours_end":            "08:00",
		"notification_frequency":     "immediate",
		"created_at":                 time.Now(),
		"updated_at":                 time.Now(),
	}
}

func (h *SettingsHandler) getDefaultAccessibilitySettings() map[string]interface{} {
	return map[string]interface{}{
		"high_contrast_mode":    false,
		"large_font_size":       false,
		"screen_reader_support": false,
		"keyboard_navigation":   false,
		"reduced_motion":        false,
		"audio_descriptions":    false,
		"closed_captions":       false,
		"font_size_multiplier":  1.0,
		"color_scheme":          "auto",
		"language":              "en",
		"text_to_speech":        false,
		"speech_to_text":        false,
		"created_at":            time.Now(),
		"updated_at":            time.Now(),
	}
}

func (h *SettingsHandler) validateUserSettings(settings map[string]interface{}) error {
	// Implement validation logic for user settings
	if theme, exists := settings["theme"]; exists {
		validThemes := []string{"light", "dark", "auto"}
		if !h.isValidTheme(theme.(string), validThemes) {
			return fmt.Errorf("invalid theme")
		}
	}

	if language, exists := settings["language"]; exists {
		if !h.isValidLanguage(language.(string)) {
			return fmt.Errorf("invalid language")
		}
	}

	return nil
}

func (h *SettingsHandler) validateChatPreferences(preferences interface{}) error {
	// Implement validation logic for chat preferences
	// This is a simplified version - add more validation as needed
	return nil
}

func (h *SettingsHandler) validateTimeFormat(timeStr string) error {
	if timeStr == "" {
		return nil
	}

	_, err := time.Parse("15:04", timeStr)
	return err
}

func (h *SettingsHandler) validateImportedSettings(settings map[string]interface{}) error {
	// Implement validation for imported settings
	// Check for required fields and valid values
	return nil
}

func (h *SettingsHandler) isValidColorScheme(scheme string, valid []string) bool {
	for _, v := range valid {
		if scheme == v {
			return true
		}
	}
	return false
}

func (h *SettingsHandler) isValidTheme(theme string, valid []string) bool {
	for _, v := range valid {
		if theme == v {
			return true
		}
	}
	return false
}

func (h *SettingsHandler) isValidLanguage(language string) bool {
	supportedLanguages := h.getSupportedLanguages()
	for _, lang := range supportedLanguages {
		if language == lang {
			return true
		}
	}
	return false
}
