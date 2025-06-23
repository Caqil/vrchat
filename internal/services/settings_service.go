package services

import (
	"context"
	"fmt"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"vrchat/internal/models"
	"vrchat/internal/utils"
	"vrchat/pkg/logger"
)

type SettingsService struct {
	db                     *mongo.Database
	appSettingsCollection  *mongo.Collection
	userSettingsCollection *mongo.Collection
	blockedUsersCollection *mongo.Collection
}

// ================================
// Struct Definitions
// ================================

// UserSettings represents user-specific settings
type UserSettings struct {
	ID                    primitive.ObjectID    `bson:"_id,omitempty" json:"id"`
	UserID                string                `bson:"user_id" json:"user_id"`
	Theme                 string                `bson:"theme" json:"theme"`                                     // light, dark, auto
	Language              string                `bson:"language" json:"language"`                               // user's preferred language
	Timezone              string                `bson:"timezone" json:"timezone"`                               // user's timezone
	DateFormat            string                `bson:"date_format" json:"date_format"`                         // DD/MM/YYYY, MM/DD/YYYY, etc.
	TimeFormat            string                `bson:"time_format" json:"time_format"`                         // 12h, 24h
	EnableSound           bool                  `bson:"enable_sound" json:"enable_sound"`                       // enable sound effects
	EnableNotifications   bool                  `bson:"enable_notifications" json:"enable_notifications"`       // enable notifications
	AutoSavePreferences   bool                  `bson:"auto_save_preferences" json:"auto_save_preferences"`     // auto-save preferences
	RememberLastRegion    bool                  `bson:"remember_last_region" json:"remember_last_region"`       // remember last selected region
	RememberLastInterests bool                  `bson:"remember_last_interests" json:"remember_last_interests"` // remember last interests
	ChatPreferences       ChatPreferences       `bson:"chat_preferences" json:"chat_preferences"`
	PrivacySettings       PrivacySettings       `bson:"privacy_settings" json:"privacy_settings"`
	NotificationSettings  NotificationSettings  `bson:"notification_settings" json:"notification_settings"`
	AccessibilitySettings AccessibilitySettings `bson:"accessibility_settings" json:"accessibility_settings"`
	CreatedAt             time.Time             `bson:"created_at" json:"created_at"`
	UpdatedAt             time.Time             `bson:"updated_at" json:"updated_at"`
}

// ChatPreferences represents chat-specific user preferences
type ChatPreferences struct {
	DefaultChatType        string   `bson:"default_chat_type" json:"default_chat_type"`               // text, video, audio
	PreferredLanguages     []string `bson:"preferred_languages" json:"preferred_languages"`           // list of preferred languages
	PreferredRegions       []string `bson:"preferred_regions" json:"preferred_regions"`               // list of preferred regions
	AutoAcceptChats        bool     `bson:"auto_accept_chats" json:"auto_accept_chats"`               // automatically accept chats
	EnableTypingIndicator  bool     `bson:"enable_typing_indicator" json:"enable_typing_indicator"`   // show typing indicator
	EnableReadReceipts     bool     `bson:"enable_read_receipts" json:"enable_read_receipts"`         // show read receipts
	MessagePreview         bool     `bson:"message_preview" json:"message_preview"`                   // show message preview
	SaveChatHistory        bool     `bson:"save_chat_history" json:"save_chat_history"`               // save chat history
	BlockAnonymous         bool     `bson:"block_anonymous" json:"block_anonymous"`                   // block anonymous users
	RequireAgeVerification bool     `bson:"require_age_verification" json:"require_age_verification"` // require age verification
	MaxChatDuration        int      `bson:"max_chat_duration" json:"max_chat_duration"`               // max chat duration in minutes
	AutoEndInactiveChats   bool     `bson:"auto_end_inactive_chats" json:"auto_end_inactive_chats"`   // auto end inactive chats
}

// PrivacySettings represents user privacy preferences
type PrivacySettings struct {
	ShowOnlineStatus     bool `bson:"show_online_status" json:"show_online_status"`         // show online status to others
	ShowTypingStatus     bool `bson:"show_typing_status" json:"show_typing_status"`         // show typing status
	AllowScreenshots     bool `bson:"allow_screenshots" json:"allow_screenshots"`           // allow screenshots during chat
	AllowRecording       bool `bson:"allow_recording" json:"allow_recording"`               // allow recording during chat
	ShareLocation        bool `bson:"share_location" json:"share_location"`                 // share location with chat partners
	ShareInterests       bool `bson:"share_interests" json:"share_interests"`               // share interests with chat partners
	AllowFriendRequests  bool `bson:"allow_friend_requests" json:"allow_friend_requests"`   // allow friend requests
	ShowLastSeen         bool `bson:"show_last_seen" json:"show_last_seen"`                 // show last seen timestamp
	PublicProfile        bool `bson:"public_profile" json:"public_profile"`                 // make profile publicly visible
	SearchableProfile    bool `bson:"searchable_profile" json:"searchable_profile"`         // allow profile to be searchable
	BlockNewAccounts     bool `bson:"block_new_accounts" json:"block_new_accounts"`         // block new accounts (spam protection)
	RequireVerifiedUsers bool `bson:"require_verified_users" json:"require_verified_users"` // only chat with verified users
}

// NotificationSettings represents user notification preferences
type NotificationSettings struct {
	EnablePushNotifications  bool   `bson:"enable_push_notifications" json:"enable_push_notifications"`   // enable push notifications
	EnableEmailNotifications bool   `bson:"enable_email_notifications" json:"enable_email_notifications"` // enable email notifications
	EnableSMSNotifications   bool   `bson:"enable_sms_notifications" json:"enable_sms_notifications"`     // enable SMS notifications
	NotifyNewMessage         bool   `bson:"notify_new_message" json:"notify_new_message"`                 // notify on new message
	NotifyFriendRequest      bool   `bson:"notify_friend_request" json:"notify_friend_request"`           // notify on friend request
	NotifySystemUpdates      bool   `bson:"notify_system_updates" json:"notify_system_updates"`           // notify on system updates
	NotifyPromotions         bool   `bson:"notify_promotions" json:"notify_promotions"`                   // notify on promotions
	NotificationSound        bool   `bson:"notification_sound" json:"notification_sound"`                 // play notification sound
	VibrationEnabled         bool   `bson:"vibration_enabled" json:"vibration_enabled"`                   // enable vibration
	QuietHoursEnabled        bool   `bson:"quiet_hours_enabled" json:"quiet_hours_enabled"`               // enable quiet hours
	QuietHoursStart          string `bson:"quiet_hours_start" json:"quiet_hours_start"`                   // quiet hours start time
	QuietHoursEnd            string `bson:"quiet_hours_end" json:"quiet_hours_end"`                       // quiet hours end time
	EmailDigestFrequency     string `bson:"email_digest_frequency" json:"email_digest_frequency"`         // daily, weekly, never
}

// AccessibilitySettings represents accessibility preferences
type AccessibilitySettings struct {
	HighContrast     bool    `bson:"high_contrast" json:"high_contrast"`         // high contrast mode
	ScreenReader     bool    `bson:"screen_reader" json:"screen_reader"`         // screen reader support
	ReducedMotion    bool    `bson:"reduced_motion" json:"reduced_motion"`       // reduce animations
	ColorBlindMode   string  `bson:"color_blind_mode" json:"color_blind_mode"`   // protanopia, deuteranopia, tritanopia
	FontSize         float64 `bson:"font_size" json:"font_size"`                 // font size multiplier
	VoiceCommands    bool    `bson:"voice_commands" json:"voice_commands"`       // voice command support
	KeyboardShortcut bool    `bson:"keyboard_shortcut" json:"keyboard_shortcut"` // keyboard navigation
}

// BlockedUser represents a blocked user relationship
type BlockedUser struct {
	ID            primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	UserID        string             `bson:"user_id" json:"user_id"`                           // user who blocked
	BlockedUserID string             `bson:"blocked_user_id" json:"blocked_user_id"`           // user who was blocked
	Reason        string             `bson:"reason" json:"reason"`                             // reason for blocking
	BlockedAt     time.Time          `bson:"blocked_at" json:"blocked_at"`                     // when the block was created
	ExpiresAt     *time.Time         `bson:"expires_at,omitempty" json:"expires_at,omitempty"` // temporary blocks
}

// NewSettingsService creates a new settings service instance
func NewSettingsService(db *mongo.Database) *SettingsService {
	return &SettingsService{
		db:                     db,
		appSettingsCollection:  db.Collection("app_settings"),
		userSettingsCollection: db.Collection("user_settings"),
		blockedUsersCollection: db.Collection("blocked_users"),
	}
}

// ================================
// App Settings Management
// ================================

// GetSettings retrieves all application settings
func (s *SettingsService) GetSettings() (*models.AppSettings, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var settings models.AppSettings
	err := s.appSettingsCollection.FindOne(ctx, bson.M{}).Decode(&settings)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			// Return default settings if none exist
			return s.createDefaultSettings()
		}
		logger.LogError(err, "Failed to get application settings", nil)
		return nil, fmt.Errorf("failed to get settings: %w", err)
	}

	return &settings, nil
}

// GetPublicSettings retrieves public application settings (safe for client consumption)
func (s *SettingsService) GetPublicSettings() (map[string]interface{}, error) {
	settings, err := s.GetSettings()
	if err != nil {
		return nil, err
	}

	publicSettings := map[string]interface{}{
		"app_name":                settings.AppName,
		"app_description":         settings.AppDescription,
		"max_users_per_room":      settings.MaxUsersPerRoom,
		"chat_timeout":            settings.ChatTimeout,
		"enable_age_verification": settings.EnableAgeVerification,
		"minimum_age":             settings.MinimumAge,
		"maintenance_mode":        settings.MaintenanceMode,
		"maintenance_message":     settings.MaintenanceMessage,
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
	}

	return publicSettings, nil
}

// UpdateSettings updates application settings
func (s *SettingsService) UpdateSettings(updateData map[string]interface{}) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Add updated timestamp
	updateData["updated_at"] = time.Now()

	// Validate critical settings
	if err := s.validateSettingsUpdate(updateData); err != nil {
		return fmt.Errorf("invalid settings data: %w", err)
	}

	update := bson.M{"$set": updateData}
	opts := options.Update().SetUpsert(true)

	result, err := s.appSettingsCollection.UpdateOne(ctx, bson.M{}, update, opts)
	if err != nil {
		logger.LogError(err, "Failed to update application settings", map[string]interface{}{
			"update_data": updateData,
		})
		return fmt.Errorf("failed to update settings: %w", err)
	}

	logger.LogSystemAction("settings_updated", map[string]interface{}{
		"modified_count": result.ModifiedCount,
		"upserted_count": result.UpsertedCount,
		"fields_updated": len(updateData),
	})

	return nil
}

// ================================
// User Settings Management
// ================================

// GetUserSettings retrieves user-specific settings
func (s *SettingsService) GetUserSettings(userID string) (*UserSettings, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var settings UserSettings
	err := s.userSettingsCollection.FindOne(ctx, bson.M{"user_id": userID}).Decode(&settings)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			// Return default user settings
			return s.createDefaultUserSettings(userID), nil
		}
		logger.LogError(err, "Failed to get user settings", map[string]interface{}{
			"user_id": userID,
		})
		return nil, fmt.Errorf("failed to get user settings: %w", err)
	}

	return &settings, nil
}

// UpdateUserSettings updates user-specific settings
func (s *SettingsService) UpdateUserSettings(userID string, updateData map[string]interface{}) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Add timestamps
	updateData["updated_at"] = time.Now()

	// Validate user settings update
	if err := s.validateUserSettingsUpdate(updateData); err != nil {
		return fmt.Errorf("invalid user settings data: %w", err)
	}

	update := bson.M{
		"$set":         updateData,
		"$setOnInsert": bson.M{"created_at": time.Now(), "user_id": userID},
	}
	opts := options.Update().SetUpsert(true)

	result, err := s.userSettingsCollection.UpdateOne(ctx, bson.M{"user_id": userID}, update, opts)
	if err != nil {
		logger.LogError(err, "Failed to update user settings", map[string]interface{}{
			"user_id":     userID,
			"update_data": updateData,
		})
		return fmt.Errorf("failed to update user settings: %w", err)
	}

	logger.LogUserAction(userID, "settings_updated", map[string]interface{}{
		"modified_count": result.ModifiedCount,
		"upserted_count": result.UpsertedCount,
		"fields_updated": len(updateData),
	})

	return nil
}

// ================================
// Chat Preferences
// ================================

// GetChatPreferences retrieves user chat preferences
func (s *SettingsService) GetChatPreferences(userID string) (*ChatPreferences, error) {
	userSettings, err := s.GetUserSettings(userID)
	if err != nil {
		// Return default chat preferences
		return s.getDefaultChatPreferences(), nil
	}

	return &userSettings.ChatPreferences, nil
}

// UpdateChatPreferences updates user chat preferences
func (s *SettingsService) UpdateChatPreferences(userID string, preferences *ChatPreferences) error {
	updateData := map[string]interface{}{
		"chat_preferences": preferences,
	}

	return s.UpdateUserSettings(userID, updateData)
}

// ================================
// Privacy Settings
// ================================

// GetPrivacySettings retrieves user privacy settings
func (s *SettingsService) GetPrivacySettings(userID string) (*PrivacySettings, error) {
	userSettings, err := s.GetUserSettings(userID)
	if err != nil {
		// Return default privacy settings
		return s.getDefaultPrivacySettings(), nil
	}

	return &userSettings.PrivacySettings, nil
}

// UpdatePrivacySettings updates user privacy settings
func (s *SettingsService) UpdatePrivacySettings(userID string, settings *PrivacySettings) error {
	updateData := map[string]interface{}{
		"privacy_settings": settings,
	}

	return s.UpdateUserSettings(userID, updateData)
}

// ================================
// Notification Settings
// ================================

// GetNotificationSettings retrieves user notification settings
func (s *SettingsService) GetNotificationSettings(userID string) (*NotificationSettings, error) {
	userSettings, err := s.GetUserSettings(userID)
	if err != nil {
		// Return default notification settings
		return s.getDefaultNotificationSettings(), nil
	}

	return &userSettings.NotificationSettings, nil
}

// UpdateNotificationSettings updates user notification settings
func (s *SettingsService) UpdateNotificationSettings(userID string, settings *NotificationSettings) error {
	updateData := map[string]interface{}{
		"notification_settings": settings,
	}

	return s.UpdateUserSettings(userID, updateData)
}

// ================================
// Banned Words Management
// ================================

// GetBannedWords returns the list of banned words
func (s *SettingsService) GetBannedWords() ([]string, error) {
	settings, err := s.GetSettings()
	if err != nil {
		return []string{}, err
	}

	if settings.BannedWords == nil {
		return []string{}, nil
	}

	return settings.BannedWords, nil
}

// AddBannedWord adds a new word to the banned words list
func (s *SettingsService) AddBannedWord(word string) error {
	if strings.TrimSpace(word) == "" {
		return fmt.Errorf("banned word cannot be empty")
	}

	word = strings.ToLower(strings.TrimSpace(word))

	// Get current banned words
	bannedWords, err := s.GetBannedWords()
	if err != nil {
		return err
	}

	// Check if word already exists
	for _, existingWord := range bannedWords {
		if strings.ToLower(existingWord) == word {
			return fmt.Errorf("word already exists in banned list")
		}
	}

	// Add new word
	bannedWords = append(bannedWords, word)

	// Update settings
	updateData := map[string]interface{}{
		"banned_words": bannedWords,
	}

	err = s.UpdateSettings(updateData)
	if err != nil {
		return fmt.Errorf("failed to add banned word: %w", err)
	}

	logger.LogSystemAction("banned_word_added", map[string]interface{}{
		"word": word,
	})

	return nil
}

// RemoveBannedWord removes a word from the banned words list
func (s *SettingsService) RemoveBannedWord(word string) error {
	if strings.TrimSpace(word) == "" {
		return fmt.Errorf("banned word cannot be empty")
	}

	word = strings.ToLower(strings.TrimSpace(word))

	// Get current banned words
	bannedWords, err := s.GetBannedWords()
	if err != nil {
		return err
	}

	// Find and remove the word
	var updatedWords []string
	found := false
	for _, existingWord := range bannedWords {
		if strings.ToLower(existingWord) != word {
			updatedWords = append(updatedWords, existingWord)
		} else {
			found = true
		}
	}

	if !found {
		return fmt.Errorf("word not found in banned list")
	}

	// Update settings
	updateData := map[string]interface{}{
		"banned_words": updatedWords,
	}

	err = s.UpdateSettings(updateData)
	if err != nil {
		return fmt.Errorf("failed to remove banned word: %w", err)
	}

	logger.LogSystemAction("banned_word_removed", map[string]interface{}{
		"word": word,
	})

	return nil
}

// BulkUpdateBannedWords performs bulk operations on banned words
func (s *SettingsService) BulkUpdateBannedWords(words []string, action string) error {
	if len(words) == 0 {
		return fmt.Errorf("no words provided for bulk update")
	}

	switch action {
	case "add":
		// Get current banned words
		bannedWords, err := s.GetBannedWords()
		if err != nil {
			return err
		}

		// Create a map for faster lookup
		existingWords := make(map[string]bool)
		for _, word := range bannedWords {
			existingWords[strings.ToLower(word)] = true
		}

		// Add new words (avoid duplicates)
		var newWords []string
		for _, word := range words {
			cleanWord := strings.ToLower(strings.TrimSpace(word))
			if cleanWord != "" && !existingWords[cleanWord] {
				bannedWords = append(bannedWords, cleanWord)
				newWords = append(newWords, cleanWord)
				existingWords[cleanWord] = true
			}
		}

		if len(newWords) == 0 {
			return fmt.Errorf("no new words to add (all words already exist or are empty)")
		}

		// Update settings
		updateData := map[string]interface{}{
			"banned_words": bannedWords,
		}

		err = s.UpdateSettings(updateData)
		if err != nil {
			return fmt.Errorf("failed to bulk add banned words: %w", err)
		}

		logger.LogSystemAction("banned_words_bulk_added", map[string]interface{}{
			"words_added": newWords,
			"count":       len(newWords),
		})

	case "remove":
		// Get current banned words
		bannedWords, err := s.GetBannedWords()
		if err != nil {
			return err
		}

		// Create a map of words to remove
		wordsToRemove := make(map[string]bool)
		for _, word := range words {
			wordsToRemove[strings.ToLower(strings.TrimSpace(word))] = true
		}

		// Filter out words to remove
		var updatedWords []string
		var removedWords []string
		for _, existingWord := range bannedWords {
			if !wordsToRemove[strings.ToLower(existingWord)] {
				updatedWords = append(updatedWords, existingWord)
			} else {
				removedWords = append(removedWords, existingWord)
			}
		}

		if len(removedWords) == 0 {
			return fmt.Errorf("no words were found to remove")
		}

		// Update settings
		updateData := map[string]interface{}{
			"banned_words": updatedWords,
		}

		err = s.UpdateSettings(updateData)
		if err != nil {
			return fmt.Errorf("failed to bulk remove banned words: %w", err)
		}

		logger.LogSystemAction("banned_words_bulk_removed", map[string]interface{}{
			"words_removed": removedWords,
			"count":         len(removedWords),
		})

	case "replace":
		// Replace entire banned words list
		var cleanWords []string
		for _, word := range words {
			cleanWord := strings.ToLower(strings.TrimSpace(word))
			if cleanWord != "" {
				cleanWords = append(cleanWords, cleanWord)
			}
		}

		// Update settings
		updateData := map[string]interface{}{
			"banned_words": cleanWords,
		}

		err := s.UpdateSettings(updateData)
		if err != nil {
			return fmt.Errorf("failed to replace banned words: %w", err)
		}

		logger.LogSystemAction("banned_words_replaced", map[string]interface{}{
			"new_words": cleanWords,
			"count":     len(cleanWords),
		})

	default:
		return fmt.Errorf("unknown bulk action: %s", action)
	}

	return nil
}

// ================================
// Banned Countries Management
// ================================

// GetBannedCountries returns the list of banned countries
func (s *SettingsService) GetBannedCountries() ([]string, error) {
	settings, err := s.GetSettings()
	if err != nil {
		return []string{}, err
	}

	if settings.BannedCountries == nil {
		return []string{}, nil
	}

	return settings.BannedCountries, nil
}

// AddBannedCountry adds a country to the banned countries list
func (s *SettingsService) AddBannedCountry(countryCode, countryName string) error {
	if strings.TrimSpace(countryCode) == "" {
		return fmt.Errorf("country code cannot be empty")
	}

	countryCode = strings.ToUpper(strings.TrimSpace(countryCode))

	// Validate country code format (should be 2 letters)
	if len(countryCode) != 2 {
		return fmt.Errorf("country code must be 2 letters")
	}

	// Get current banned countries
	bannedCountries, err := s.GetBannedCountries()
	if err != nil {
		return err
	}

	// Check if country already exists
	for _, existingCountry := range bannedCountries {
		if strings.ToUpper(existingCountry) == countryCode {
			return fmt.Errorf("country already exists in banned list")
		}
	}

	// Add new country
	bannedCountries = append(bannedCountries, countryCode)

	// Update settings
	updateData := map[string]interface{}{
		"banned_countries": bannedCountries,
	}

	err = s.UpdateSettings(updateData)
	if err != nil {
		return fmt.Errorf("failed to add banned country: %w", err)
	}

	logger.LogSystemAction("banned_country_added", map[string]interface{}{
		"country_code": countryCode,
		"country_name": countryName,
	})

	return nil
}

// RemoveBannedCountry removes a country from the banned countries list
func (s *SettingsService) RemoveBannedCountry(countryCode string) error {
	if strings.TrimSpace(countryCode) == "" {
		return fmt.Errorf("country code cannot be empty")
	}

	countryCode = strings.ToUpper(strings.TrimSpace(countryCode))

	// Get current banned countries
	bannedCountries, err := s.GetBannedCountries()
	if err != nil {
		return err
	}

	// Find and remove the country
	var updatedCountries []string
	found := false
	for _, existingCountry := range bannedCountries {
		if strings.ToUpper(existingCountry) != countryCode {
			updatedCountries = append(updatedCountries, existingCountry)
		} else {
			found = true
		}
	}

	if !found {
		return fmt.Errorf("country not found in banned list")
	}

	// Update settings
	updateData := map[string]interface{}{
		"banned_countries": updatedCountries,
	}

	err = s.UpdateSettings(updateData)
	if err != nil {
		return fmt.Errorf("failed to remove banned country: %w", err)
	}

	logger.LogSystemAction("banned_country_removed", map[string]interface{}{
		"country_code": countryCode,
	})

	return nil
}

// ================================
// Maintenance Mode
// ================================

// SetMaintenanceMode enables or disables maintenance mode
func (s *SettingsService) SetMaintenanceMode(enabled bool, message string) error {
	updateData := map[string]interface{}{
		"maintenance_mode": enabled,
	}

	// Set maintenance message if provided
	if message != "" {
		updateData["maintenance_message"] = message
	} else if enabled {
		// Set default message if enabling maintenance mode without a message
		updateData["maintenance_message"] = "The system is currently under maintenance. Please try again later."
	}

	err := s.UpdateSettings(updateData)
	if err != nil {
		return fmt.Errorf("failed to set maintenance mode: %w", err)
	}

	status := "disabled"
	if enabled {
		status = "enabled"
	}

	logger.LogSystemAction("maintenance_mode_updated", map[string]interface{}{
		"enabled": enabled,
		"message": message,
		"status":  status,
	})

	return nil
}

// IsMaintenanceMode checks if maintenance mode is currently enabled
func (s *SettingsService) IsMaintenanceMode() (bool, string, error) {
	settings, err := s.GetSettings()
	if err != nil {
		return false, "", err
	}

	return settings.MaintenanceMode, settings.MaintenanceMessage, nil
}

// ================================
// Settings Categories
// ================================

// GetGeneralSettings retrieves general application settings
func (s *SettingsService) GetGeneralSettings() (map[string]interface{}, error) {
	settings, err := s.GetSettings()
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"app_name":                settings.AppName,
		"app_description":         settings.AppDescription,
		"max_users_per_room":      settings.MaxUsersPerRoom,
		"chat_timeout":            settings.ChatTimeout,
		"enable_age_verification": settings.EnableAgeVerification,
		"minimum_age":             settings.MinimumAge,
		"maintenance_mode":        settings.MaintenanceMode,
		"maintenance_message":     settings.MaintenanceMessage,
	}, nil
}

// UpdateGeneralSettings updates general application settings
func (s *SettingsService) UpdateGeneralSettings(updateData map[string]interface{}) error {
	// Filter only general settings fields
	allowedFields := map[string]bool{
		"app_name":                true,
		"app_description":         true,
		"max_users_per_room":      true,
		"chat_timeout":            true,
		"enable_age_verification": true,
		"minimum_age":             true,
		"maintenance_mode":        true,
		"maintenance_message":     true,
	}

	filteredData := make(map[string]interface{})
	for key, value := range updateData {
		if allowedFields[key] {
			filteredData[key] = value
		}
	}

	return s.UpdateSettings(filteredData)
}

// GetModerationSettings retrieves moderation settings
func (s *SettingsService) GetModerationSettings() (map[string]interface{}, error) {
	settings, err := s.GetSettings()
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"enable_moderation":       settings.EnableModeration,
		"enable_profanity_filter": settings.EnableProfanityFilter,
		"banned_words":            settings.BannedWords,
		"banned_countries":        settings.BannedCountries,
	}, nil
}

// UpdateModerationSettings updates moderation settings
func (s *SettingsService) UpdateModerationSettings(updateData map[string]interface{}) error {
	allowedFields := map[string]bool{
		"enable_moderation":       true,
		"enable_profanity_filter": true,
		"banned_words":            true,
		"banned_countries":        true,
	}

	filteredData := make(map[string]interface{})
	for key, value := range updateData {
		if allowedFields[key] {
			filteredData[key] = value
		}
	}

	return s.UpdateSettings(filteredData)
}

// GetMatchingSettings retrieves matching algorithm settings
func (s *SettingsService) GetMatchingSettings() map[string]interface{} {
	return map[string]interface{}{
		"enable_interest_matching": true,
		"enable_region_matching":   true,
		"enable_language_matching": true,
		"max_queue_wait_time":      600, // 10 minutes
		"match_timeout":            30,  // 30 seconds
		"allow_cross_region":       true,
		"allow_cross_language":     false,
		"priority_boost_premium":   false,
	}
}

// UpdateMatchingSettings updates matching algorithm settings
func (s *SettingsService) UpdateMatchingSettings(updateData map[string]interface{}) error {
	// Since matching settings are not stored in the database yet,
	// this method can be implemented when matching settings are added to the database
	// For now, just log the attempt
	logger.LogSystemAction("matching_settings_update_attempted", map[string]interface{}{
		"update_data": updateData,
	})
	return nil
}

// ================================
// Blocked Users Management
// ================================

// BlockUser blocks a user for the current user
func (s *SettingsService) BlockUser(userID, blockedUserID, reason string, expiry *time.Time) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Check if user is already blocked
	isBlocked, err := s.IsUserBlocked(userID, blockedUserID)
	if err != nil {
		return err
	}

	if isBlocked {
		return fmt.Errorf("user is already blocked")
	}

	blockedUser := BlockedUser{
		UserID:        userID,
		BlockedUserID: blockedUserID,
		Reason:        reason,
		BlockedAt:     time.Now(),
		ExpiresAt:     expiry,
	}

	_, err = s.blockedUsersCollection.InsertOne(ctx, blockedUser)
	if err != nil {
		logger.LogError(err, "Failed to block user", map[string]interface{}{
			"user_id":         userID,
			"blocked_user_id": blockedUserID,
			"reason":          reason,
		})
		return fmt.Errorf("failed to block user: %w", err)
	}

	logger.LogUserAction(userID, "user_blocked", map[string]interface{}{
		"blocked_user_id": blockedUserID,
		"reason":          reason,
		"expires_at":      expiry,
	})

	return nil
}

// UnblockUser unblocks a user for the current user
func (s *SettingsService) UnblockUser(userID, blockedUserID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	filter := bson.M{
		"user_id":         userID,
		"blocked_user_id": blockedUserID,
	}

	result, err := s.blockedUsersCollection.DeleteMany(ctx, filter)
	if err != nil {
		logger.LogError(err, "Failed to unblock user", map[string]interface{}{
			"user_id":         userID,
			"blocked_user_id": blockedUserID,
		})
		return fmt.Errorf("failed to unblock user: %w", err)
	}

	if result.DeletedCount == 0 {
		return fmt.Errorf("user was not blocked or block has already expired")
	}

	logger.LogUserAction(userID, "user_unblocked", map[string]interface{}{
		"blocked_user_id": blockedUserID,
		"deleted_count":   result.DeletedCount,
	})

	return nil
}

// GetBlockedUsers retrieves all blocked users for a user
func (s *SettingsService) GetBlockedUsers(userID string) ([]BlockedUser, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	filter := bson.M{
		"user_id": userID,
		"$or": []bson.M{
			{"expires_at": bson.M{"$exists": false}},
			{"expires_at": bson.M{"$gt": time.Now()}},
		},
	}

	cursor, err := s.blockedUsersCollection.Find(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to get blocked users: %w", err)
	}
	defer cursor.Close(ctx)

	var blockedUsers []BlockedUser
	if err = cursor.All(ctx, &blockedUsers); err != nil {
		return nil, fmt.Errorf("failed to decode blocked users: %w", err)
	}

	return blockedUsers, nil
}

// IsUserBlocked checks if a user is blocked by another user
func (s *SettingsService) IsUserBlocked(userID, checkUserID string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	filter := bson.M{
		"user_id":         userID,
		"blocked_user_id": checkUserID,
		"$or": []bson.M{
			{"expires_at": bson.M{"$exists": false}},
			{"expires_at": bson.M{"$gt": time.Now()}},
		},
	}

	count, err := s.blockedUsersCollection.CountDocuments(ctx, filter)
	if err != nil {
		return false, fmt.Errorf("failed to check if user is blocked: %w", err)
	}

	return count > 0, nil
}

// ================================
// Backup & Restore
// ================================

// BackupSettings creates a complete backup of all settings
func (s *SettingsService) BackupSettings() (map[string]interface{}, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	backup := map[string]interface{}{
		"backup_version": "1.0",
		"created_at":     time.Now(),
	}

	// Backup app settings
	appSettings, err := s.GetSettings()
	if err == nil {
		backup["app_settings"] = appSettings
	}

	// Backup all user settings (for admin use)
	userSettingsCursor, err := s.userSettingsCollection.Find(ctx, bson.M{})
	if err == nil {
		var userSettings []UserSettings
		userSettingsCursor.All(ctx, &userSettings)
		backup["user_settings"] = userSettings
		userSettingsCursor.Close(ctx)
	}

	// Backup blocked users (for admin use)
	blockedUsersCursor, err := s.blockedUsersCollection.Find(ctx, bson.M{})
	if err == nil {
		var blockedUsers []BlockedUser
		blockedUsersCursor.All(ctx, &blockedUsers)
		backup["blocked_users"] = blockedUsers
		blockedUsersCursor.Close(ctx)
	}

	logger.LogSystemAction("settings_backup_created", map[string]interface{}{
		"backup_size": len(backup),
	})

	return backup, nil
}

// RestoreSettings restores settings from backup
func (s *SettingsService) RestoreSettings(backupData map[string]interface{}) error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Start transaction for atomic restore
	session, err := s.db.Client().StartSession()
	if err != nil {
		return fmt.Errorf("failed to start transaction: %w", err)
	}
	defer session.EndSession(ctx)

	_, err = session.WithTransaction(ctx, func(sc mongo.SessionContext) (interface{}, error) {
		// Restore app settings
		if appSettingsData, ok := backupData["app_settings"].(map[string]interface{}); ok {
			err := s.UpdateSettings(appSettingsData)
			if err != nil {
				return nil, fmt.Errorf("failed to restore app settings: %w", err)
			}
		}

		return nil, nil
	})

	if err != nil {
		logger.LogError(err, "Failed to restore settings", nil)
		return fmt.Errorf("failed to restore settings: %w", err)
	}

	logger.LogSystemAction("settings_restored", map[string]interface{}{
		"backup_version": backupData["backup_version"],
	})

	return nil
}

// ResetToDefaults resets all settings to default values
func (s *SettingsService) ResetToDefaults() error {
	defaultSettings, err := s.createDefaultSettings()
	if err != nil {
		return err
	}

	// Convert to map for update
	defaultData := map[string]interface{}{
		"app_name":                defaultSettings.AppName,
		"app_description":         defaultSettings.AppDescription,
		"max_users_per_room":      defaultSettings.MaxUsersPerRoom,
		"chat_timeout":            defaultSettings.ChatTimeout,
		"enable_moderation":       defaultSettings.EnableModeration,
		"enable_profanity_filter": defaultSettings.EnableProfanityFilter,
		"enable_age_verification": defaultSettings.EnableAgeVerification,
		"minimum_age":             defaultSettings.MinimumAge,
		"maintenance_mode":        defaultSettings.MaintenanceMode,
		"maintenance_message":     defaultSettings.MaintenanceMessage,
		"banned_words":            defaultSettings.BannedWords,
		"banned_countries":        defaultSettings.BannedCountries,
	}

	return s.UpdateSettings(defaultData)
}

// ================================
// User Settings Import/Export
// ================================

// ExportUserSettings exports all user settings for backup/transfer
func (s *SettingsService) ExportUserSettings(userID string) (map[string]interface{}, error) {
	settings, err := s.GetUserSettings(userID)
	if err != nil {
		return nil, err
	}

	blockedUsers, err := s.GetBlockedUsers(userID)
	if err != nil {
		// Continue even if blocked users can't be retrieved
		blockedUsers = []BlockedUser{}
	}

	exportData := map[string]interface{}{
		"user_id":       userID,
		"settings":      settings,
		"blocked_users": blockedUsers,
		"exported_at":   time.Now(),
		"version":       "1.0",
	}

	logger.LogUserAction(userID, "settings_exported", map[string]interface{}{
		"blocked_users_count": len(blockedUsers),
	})

	return exportData, nil
}

// ImportUserSettings imports user settings from backup
func (s *SettingsService) ImportUserSettings(userID string, importData map[string]interface{}, overwrite bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Start transaction for atomic import
	session, err := s.db.Client().StartSession()
	if err != nil {
		return fmt.Errorf("failed to start transaction: %w", err)
	}
	defer session.EndSession(ctx)

	_, err = session.WithTransaction(ctx, func(sc mongo.SessionContext) (interface{}, error) {
		// Import settings
		if settingsData, ok := importData["settings"].(map[string]interface{}); ok {
			if !overwrite {
				// Check if settings already exist
				existing, _ := s.GetUserSettings(userID)
				if existing != nil {
					return nil, fmt.Errorf("user settings already exist, use overwrite=true to replace")
				}
			}

			settingsData["user_id"] = userID
			settingsData["updated_at"] = time.Now()
			if settingsData["created_at"] == nil {
				settingsData["created_at"] = time.Now()
			}

			err := s.UpdateUserSettings(userID, settingsData)
			if err != nil {
				return nil, err
			}
		}

		return nil, nil
	})

	if err != nil {
		return err
	}

	logger.LogUserAction(userID, "settings_imported", map[string]interface{}{
		"overwrite": overwrite,
	})

	return nil
}

// ================================
// Helper Methods
// ================================

// createDefaultSettings creates default application settings
func (s *SettingsService) createDefaultSettings() (*models.AppSettings, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	defaultSettings := &models.AppSettings{
		AppName:               "Omegle Clone",
		AppDescription:        "Random video chat application",
		MaxUsersPerRoom:       2,
		ChatTimeout:           30, // 30 minutes
		EnableModeration:      true,
		EnableProfanityFilter: true,
		EnableAgeVerification: false,
		MinimumAge:            13,
		MaintenanceMode:       false,
		MaintenanceMessage:    "The system is currently under maintenance. Please try again later.",
		BannedWords:           []string{},
		BannedCountries:       []string{},
		CreatedAt:             time.Now(),
		UpdatedAt:             time.Now(),
	}

	// Save default settings to database
	_, err := s.appSettingsCollection.InsertOne(ctx, defaultSettings)
	if err != nil {
		logger.LogError(err, "Failed to create default settings", nil)
		return nil, fmt.Errorf("failed to create default settings: %w", err)
	}

	logger.LogSystemAction("default_settings_created", nil)

	return defaultSettings, nil
}

// createDefaultUserSettings creates default user settings
func (s *SettingsService) createDefaultUserSettings(userID string) *UserSettings {
	return &UserSettings{
		UserID:                userID,
		Theme:                 "auto",
		Language:              "en",
		Timezone:              "UTC",
		DateFormat:            "DD/MM/YYYY",
		TimeFormat:            "24h",
		EnableSound:           true,
		EnableNotifications:   true,
		AutoSavePreferences:   true,
		RememberLastRegion:    true,
		RememberLastInterests: true,
		ChatPreferences:       *s.getDefaultChatPreferences(),
		PrivacySettings:       *s.getDefaultPrivacySettings(),
		NotificationSettings:  *s.getDefaultNotificationSettings(),
		AccessibilitySettings: *s.getDefaultAccessibilitySettings(),
		CreatedAt:             time.Now(),
		UpdatedAt:             time.Now(),
	}
}

// getDefaultChatPreferences returns default chat preferences
func (s *SettingsService) getDefaultChatPreferences() *ChatPreferences {
	return &ChatPreferences{
		DefaultChatType:        "text",
		PreferredLanguages:     []string{"en"},
		PreferredRegions:       []string{"us-east"},
		AutoAcceptChats:        false,
		EnableTypingIndicator:  true,
		EnableReadReceipts:     true,
		MessagePreview:         true,
		SaveChatHistory:        true,
		BlockAnonymous:         false,
		RequireAgeVerification: false,
		MaxChatDuration:        30,
		AutoEndInactiveChats:   true,
	}
}

// getDefaultPrivacySettings returns default privacy settings
func (s *SettingsService) getDefaultPrivacySettings() *PrivacySettings {
	return &PrivacySettings{
		ShowOnlineStatus:     true,
		ShowTypingStatus:     true,
		AllowScreenshots:     true,
		AllowRecording:       false,
		ShareLocation:        false,
		ShareInterests:       true,
		AllowFriendRequests:  true,
		ShowLastSeen:         true,
		PublicProfile:        false,
		SearchableProfile:    false,
		BlockNewAccounts:     false,
		RequireVerifiedUsers: false,
	}
}

// getDefaultNotificationSettings returns default notification settings
func (s *SettingsService) getDefaultNotificationSettings() *NotificationSettings {
	return &NotificationSettings{
		EnablePushNotifications:  true,
		EnableEmailNotifications: true,
		EnableSMSNotifications:   false,
		NotifyNewMessage:         true,
		NotifyFriendRequest:      true,
		NotifySystemUpdates:      true,
		NotifyPromotions:         false,
		NotificationSound:        true,
		VibrationEnabled:         true,
		QuietHoursEnabled:        false,
		QuietHoursStart:          "22:00",
		QuietHoursEnd:            "08:00",
		EmailDigestFrequency:     "weekly",
	}
}

// getDefaultAccessibilitySettings returns default accessibility settings
func (s *SettingsService) getDefaultAccessibilitySettings() *AccessibilitySettings {
	return &AccessibilitySettings{
		HighContrast:     false,
		ScreenReader:     false,
		ReducedMotion:    false,
		ColorBlindMode:   "none",
		FontSize:         1.0,
		VoiceCommands:    false,
		KeyboardShortcut: true,
	}
}

// Validation methods
func (s *SettingsService) validateSettingsUpdate(updateData map[string]interface{}) error {
	// Add validation logic for application settings
	if chatTimeout, ok := updateData["chat_timeout"]; ok {
		if timeout, ok := chatTimeout.(int); ok {
			if timeout < 5 || timeout > 480 { // 5 minutes to 8 hours
				return fmt.Errorf("chat timeout must be between 5 and 480 minutes")
			}
		}
	}

	if maxUsers, ok := updateData["max_users_per_room"]; ok {
		if users, ok := maxUsers.(int); ok {
			if users < 2 || users > 10 {
				return fmt.Errorf("max users per room must be between 2 and 10")
			}
		}
	}

	return nil
}

func (s *SettingsService) validateUserSettingsUpdate(updateData map[string]interface{}) error {
	// Add validation logic for user settings
	if language, ok := updateData["language"]; ok {
		if lang, ok := language.(string); ok {
			if !utils.IsValidLanguageCode(lang) {
				return fmt.Errorf("invalid language code: %s", lang)
			}
		}
	}

	if timezone, ok := updateData["timezone"]; ok {
		if tz, ok := timezone.(string); ok {
			if _, err := time.LoadLocation(tz); err != nil {
				return fmt.Errorf("invalid timezone: %s", tz)
			}
		}
	}

	return nil
}

// GetAccessibilitySettings retrieves user accessibility settings
func (s *SettingsService) GetAccessibilitySettings(userID string) (*AccessibilitySettings, error) {
	userSettings, err := s.GetUserSettings(userID)
	if err != nil {
		// Return default accessibility settings
		return s.getDefaultAccessibilitySettings(), nil
	}

	return &userSettings.AccessibilitySettings, nil
}

// UpdateAccessibilitySettings updates user accessibility settings
func (s *SettingsService) UpdateAccessibilitySettings(userID string, settings *AccessibilitySettings) error {
	updateData := map[string]interface{}{
		"accessibility_settings": settings,
	}

	return s.UpdateUserSettings(userID, updateData)
}

// UpdateChatPreferencesFromMap updates chat preferences from a map
func (s *SettingsService) UpdateChatPreferencesFromMap(userID string, prefsMap map[string]interface{}) error {
	prefs := s.mapToChatPreferences(prefsMap)
	return s.UpdateChatPreferences(userID, prefs)
}

// UpdatePrivacySettingsFromMap updates privacy settings from a map
func (s *SettingsService) UpdatePrivacySettingsFromMap(userID string, settingsMap map[string]interface{}) error {
	settings := s.mapToPrivacySettings(settingsMap)
	return s.UpdatePrivacySettings(userID, settings)
}

// UpdateNotificationSettingsFromMap updates notification settings from a map
func (s *SettingsService) UpdateNotificationSettingsFromMap(userID string, settingsMap map[string]interface{}) error {
	settings := s.mapToNotificationSettings(settingsMap)
	return s.UpdateNotificationSettings(userID, settings)
}

// mapToChatPreferences converts map to ChatPreferences struct
func (s *SettingsService) mapToChatPreferences(data map[string]interface{}) *ChatPreferences {
	prefs := s.getDefaultChatPreferences()

	if val, ok := data["default_chat_type"].(string); ok {
		prefs.DefaultChatType = val
	}
	if val, ok := data["preferred_languages"].([]interface{}); ok {
		prefs.PreferredLanguages = interfaceSliceToStringSlice(val)
	}
	if val, ok := data["preferred_regions"].([]interface{}); ok {
		prefs.PreferredRegions = interfaceSliceToStringSlice(val)
	}
	if val, ok := data["auto_accept_chats"].(bool); ok {
		prefs.AutoAcceptChats = val
	}
	if val, ok := data["enable_typing_indicator"].(bool); ok {
		prefs.EnableTypingIndicator = val
	}
	if val, ok := data["enable_read_receipts"].(bool); ok {
		prefs.EnableReadReceipts = val
	}
	if val, ok := data["message_preview"].(bool); ok {
		prefs.MessagePreview = val
	}
	if val, ok := data["save_chat_history"].(bool); ok {
		prefs.SaveChatHistory = val
	}
	if val, ok := data["block_anonymous"].(bool); ok {
		prefs.BlockAnonymous = val
	}
	if val, ok := data["require_age_verification"].(bool); ok {
		prefs.RequireAgeVerification = val
	}
	if val, ok := data["max_chat_duration"].(float64); ok {
		prefs.MaxChatDuration = int(val)
	}
	if val, ok := data["auto_end_inactive_chats"].(bool); ok {
		prefs.AutoEndInactiveChats = val
	}

	return prefs
}

// mapToPrivacySettings converts map to PrivacySettings struct
func (s *SettingsService) mapToPrivacySettings(data map[string]interface{}) *PrivacySettings {
	settings := s.getDefaultPrivacySettings()

	if val, ok := data["show_online_status"].(bool); ok {
		settings.ShowOnlineStatus = val
	}
	if val, ok := data["show_typing_status"].(bool); ok {
		settings.ShowTypingStatus = val
	}
	if val, ok := data["allow_screenshots"].(bool); ok {
		settings.AllowScreenshots = val
	}
	if val, ok := data["allow_recording"].(bool); ok {
		settings.AllowRecording = val
	}
	if val, ok := data["share_location"].(bool); ok {
		settings.ShareLocation = val
	}
	if val, ok := data["share_interests"].(bool); ok {
		settings.ShareInterests = val
	}
	if val, ok := data["allow_friend_requests"].(bool); ok {
		settings.AllowFriendRequests = val
	}
	if val, ok := data["show_last_seen"].(bool); ok {
		settings.ShowLastSeen = val
	}
	if val, ok := data["public_profile"].(bool); ok {
		settings.PublicProfile = val
	}
	if val, ok := data["searchable_profile"].(bool); ok {
		settings.SearchableProfile = val
	}
	if val, ok := data["block_new_accounts"].(bool); ok {
		settings.BlockNewAccounts = val
	}
	if val, ok := data["require_verified_users"].(bool); ok {
		settings.RequireVerifiedUsers = val
	}

	return settings
}

// mapToNotificationSettings converts map to NotificationSettings struct
func (s *SettingsService) mapToNotificationSettings(data map[string]interface{}) *NotificationSettings {
	settings := s.getDefaultNotificationSettings()

	if val, ok := data["enable_push_notifications"].(bool); ok {
		settings.EnablePushNotifications = val
	}
	if val, ok := data["enable_email_notifications"].(bool); ok {
		settings.EnableEmailNotifications = val
	}
	if val, ok := data["enable_sms_notifications"].(bool); ok {
		settings.EnableSMSNotifications = val
	}
	if val, ok := data["notify_new_message"].(bool); ok {
		settings.NotifyNewMessage = val
	}
	if val, ok := data["notify_friend_request"].(bool); ok {
		settings.NotifyFriendRequest = val
	}
	if val, ok := data["notify_system_updates"].(bool); ok {
		settings.NotifySystemUpdates = val
	}
	if val, ok := data["notify_promotions"].(bool); ok {
		settings.NotifyPromotions = val
	}
	if val, ok := data["notification_sound"].(bool); ok {
		settings.NotificationSound = val
	}
	if val, ok := data["vibration_enabled"].(bool); ok {
		settings.VibrationEnabled = val
	}
	if val, ok := data["quiet_hours_enabled"].(bool); ok {
		settings.QuietHoursEnabled = val
	}
	if val, ok := data["quiet_hours_start"].(string); ok {
		settings.QuietHoursStart = val
	}
	if val, ok := data["quiet_hours_end"].(string); ok {
		settings.QuietHoursEnd = val
	}
	if val, ok := data["email_digest_frequency"].(string); ok {
		settings.EmailDigestFrequency = val
	}

	return settings
}

// mapToAccessibilitySettings converts map to AccessibilitySettings struct
func (s *SettingsService) mapToAccessibilitySettings(data map[string]interface{}) *AccessibilitySettings {
	settings := s.getDefaultAccessibilitySettings()

	if val, ok := data["high_contrast"].(bool); ok {
		settings.HighContrast = val
	}
	if val, ok := data["screen_reader"].(bool); ok {
		settings.ScreenReader = val
	}
	if val, ok := data["reduced_motion"].(bool); ok {
		settings.ReducedMotion = val
	}
	if val, ok := data["color_blind_mode"].(string); ok {
		settings.ColorBlindMode = val
	}
	if val, ok := data["font_size"].(float64); ok {
		settings.FontSize = val
	}
	if val, ok := data["voice_commands"].(bool); ok {
		settings.VoiceCommands = val
	}
	if val, ok := data["keyboard_shortcut"].(bool); ok {
		settings.KeyboardShortcut = val
	}

	return settings
}

// Helper function to convert []interface{} to []string
func interfaceSliceToStringSlice(input []interface{}) []string {
	result := make([]string, len(input))
	for i, v := range input {
		if str, ok := v.(string); ok {
			result[i] = str
		}
	}
	return result
}

// UpdateAccessibilitySettingsFromMap updates accessibility settings from a map
func (s *SettingsService) UpdateAccessibilitySettingsFromMap(userID string, settingsMap map[string]interface{}) error {
	settings := s.mapToAccessibilitySettings(settingsMap)
	return s.UpdateAccessibilitySettings(userID, settings)
}
