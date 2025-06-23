package services

import (
	"context"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"vrchat/internal/models"
	"vrchat/pkg/logger"
)

type SettingsService struct {
	db                     *mongo.Database
	appSettingsCollection  *mongo.Collection
	userSettingsCollection *mongo.Collection
	blockedUsersCollection *mongo.Collection
}

// UserSettings represents individual user preferences
type UserSettings struct {
	ID                    primitive.ObjectID    `bson:"_id,omitempty" json:"id"`
	UserID                string                `bson:"user_id" json:"user_id"`
	Theme                 string                `bson:"theme" json:"theme"`                                     // light, dark, auto
	Language              string                `bson:"language" json:"language"`                               // preferred language
	Timezone              string                `bson:"timezone" json:"timezone"`                               // user timezone
	DateFormat            string                `bson:"date_format" json:"date_format"`                         // DD/MM/YYYY, MM/DD/YYYY
	TimeFormat            string                `bson:"time_format" json:"time_format"`                         // 12h, 24h
	EnableSound           bool                  `bson:"enable_sound" json:"enable_sound"`                       // sound notifications
	EnableNotifications   bool                  `bson:"enable_notifications" json:"enable_notifications"`       // push notifications
	AutoSavePreferences   bool                  `bson:"auto_save_preferences" json:"auto_save_preferences"`     // auto-save settings
	RememberLastRegion    bool                  `bson:"remember_last_region" json:"remember_last_region"`       // remember region choice
	RememberLastInterests bool                  `bson:"remember_last_interests" json:"remember_last_interests"` // remember interests
	ChatPreferences       ChatPreferences       `bson:"chat_preferences" json:"chat_preferences"`
	PrivacySettings       PrivacySettings       `bson:"privacy_settings" json:"privacy_settings"`
	AccessibilitySettings AccessibilitySettings `bson:"accessibility_settings" json:"accessibility_settings"`
	CreatedAt             time.Time             `bson:"created_at" json:"created_at"`
	UpdatedAt             time.Time             `bson:"updated_at" json:"updated_at"`
}

type ChatPreferences struct {
	DefaultChatType     string   `bson:"default_chat_type" json:"default_chat_type"`         // text, video, audio
	PreferredLanguages  []string `bson:"preferred_languages" json:"preferred_languages"`     // language codes
	PreferredRegions    []string `bson:"preferred_regions" json:"preferred_regions"`         // region codes
	DefaultInterests    []string `bson:"default_interests" json:"default_interests"`         // default interests
	AutoJoinChat        bool     `bson:"auto_join_chat" json:"auto_join_chat"`               // auto-join after match
	ShowTypingIndicator bool     `bson:"show_typing_indicator" json:"show_typing_indicator"` // show typing status
	AllowFileSharing    bool     `bson:"allow_file_sharing" json:"allow_file_sharing"`       // allow file uploads
	AllowScreenSharing  bool     `bson:"allow_screen_sharing" json:"allow_screen_sharing"`   // allow screen share
	MessageHistory      bool     `bson:"message_history" json:"message_history"`             // save chat history
	AutoTranslate       bool     `bson:"auto_translate" json:"auto_translate"`               // auto-translate messages
}

type PrivacySettings struct {
	ShowOnlineStatus   bool `bson:"show_online_status" json:"show_online_status"`     // show online status
	AllowDirectMessage bool `bson:"allow_direct_message" json:"allow_direct_message"` // allow DMs
	ShareLocation      bool `bson:"share_location" json:"share_location"`             // share region info
	DataCollection     bool `bson:"data_collection" json:"data_collection"`           // allow analytics
	PersonalizedAds    bool `bson:"personalized_ads" json:"personalized_ads"`         // personalized content
}

type AccessibilitySettings struct {
	HighContrast     bool    `bson:"high_contrast" json:"high_contrast"`         // high contrast mode
	LargeText        bool    `bson:"large_text" json:"large_text"`               // large text mode
	ScreenReader     bool    `bson:"screen_reader" json:"screen_reader"`         // screen reader support
	ReducedMotion    bool    `bson:"reduced_motion" json:"reduced_motion"`       // reduce animations
	ColorBlindMode   string  `bson:"color_blind_mode" json:"color_blind_mode"`   // protanopia, deuteranopia, tritanopia
	FontSize         float64 `bson:"font_size" json:"font_size"`                 // font size multiplier
	VoiceCommands    bool    `bson:"voice_commands" json:"voice_commands"`       // voice command support
	KeyboardShortcut bool    `bson:"keyboard_shortcut" json:"keyboard_shortcut"` // keyboard navigation
}

type BlockedUser struct {
	ID            primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	UserID        string             `bson:"user_id" json:"user_id"`                 // user who blocked
	BlockedUserID string             `bson:"blocked_user_id" json:"blocked_user_id"` // user who was blocked
	Reason        string             `bson:"reason" json:"reason"`                   // reason for blocking
	BlockedAt     time.Time          `bson:"blocked_at" json:"blocked_at"`
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

		// Import blocked users
		if blockedUsersData, ok := importData["blocked_users"].([]interface{}); ok {
			for _, blockedData := range blockedUsersData {
				if blocked, ok := blockedData.(map[string]interface{}); ok {
					if blockedUserID, ok := blocked["blocked_user_id"].(string); ok {
						reason, _ := blocked["reason"].(string)
						err := s.BlockUser(userID, blockedUserID, reason)
						if err != nil {
							// Log error but continue with import
							logger.LogError(err, "Failed to import blocked user", map[string]interface{}{
								"user_id":         userID,
								"blocked_user_id": blockedUserID,
							})
						}
					}
				}
			}
		}

		return nil, nil
	})

	if err != nil {
		logger.LogError(err, "Failed to import user settings", map[string]interface{}{
			"user_id":   userID,
			"overwrite": overwrite,
		})
		return fmt.Errorf("failed to import settings: %w", err)
	}

	logger.LogUserAction(userID, "settings_imported", map[string]interface{}{
		"overwrite": overwrite,
	})

	return nil
}

// ================================
// Blocked Users Management
// ================================

// GetBlockedUsers retrieves all users blocked by a specific user
func (s *SettingsService) GetBlockedUsers(userID string) ([]BlockedUser, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	filter := bson.M{
		"user_id": userID,
		"$or": []bson.M{
			{"expires_at": bson.M{"$exists": false}},  // permanent blocks
			{"expires_at": bson.M{"$gt": time.Now()}}, // active temporary blocks
		},
	}

	opts := options.Find().SetSort(bson.D{{Key: "blocked_at", Value: -1}})
	cursor, err := s.blockedUsersCollection.Find(ctx, filter, opts)
	if err != nil {
		logger.LogError(err, "Failed to get blocked users", map[string]interface{}{
			"user_id": userID,
		})
		return nil, fmt.Errorf("failed to get blocked users: %w", err)
	}
	defer cursor.Close(ctx)

	var blockedUsers []BlockedUser
	if err = cursor.All(ctx, &blockedUsers); err != nil {
		return nil, fmt.Errorf("failed to decode blocked users: %w", err)
	}

	return blockedUsers, nil
}

// BlockUser blocks a user
func (s *SettingsService) BlockUser(userID, blockedUserID, reason string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Check if already blocked
	existing := s.blockedUsersCollection.FindOne(ctx, bson.M{
		"user_id":         userID,
		"blocked_user_id": blockedUserID,
		"$or": []bson.M{
			{"expires_at": bson.M{"$exists": false}},
			{"expires_at": bson.M{"$gt": time.Now()}},
		},
	})

	if existing.Err() == nil {
		return fmt.Errorf("user is already blocked")
	}

	blockEntry := BlockedUser{
		UserID:        userID,
		BlockedUserID: blockedUserID,
		Reason:        reason,
		BlockedAt:     time.Now(),
		// ExpiresAt is nil for permanent blocks
	}

	_, err := s.blockedUsersCollection.InsertOne(ctx, blockEntry)
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
	})

	return nil
}

// UnblockUser unblocks a user
func (s *SettingsService) UnblockUser(userID, blockedUserID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
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

	// Insert default settings if they don't exist
	opts := options.Update().SetUpsert(true)
	_, err := s.appSettingsCollection.UpdateOne(ctx, bson.M{}, bson.M{"$setOnInsert": defaultSettings}, opts)
	if err != nil {
		logger.LogError(err, "Failed to create default settings", nil)
		return nil, fmt.Errorf("failed to create default settings: %w", err)
	}

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
		ChatPreferences: ChatPreferences{
			DefaultChatType:     "text",
			PreferredLanguages:  []string{"en"},
			PreferredRegions:    []string{},
			DefaultInterests:    []string{},
			AutoJoinChat:        true,
			ShowTypingIndicator: true,
			AllowFileSharing:    true,
			AllowScreenSharing:  true,
			MessageHistory:      false,
			AutoTranslate:       false,
		},
		PrivacySettings: PrivacySettings{
			ShowOnlineStatus:   true,
			AllowDirectMessage: true,
			ShareLocation:      true,
			DataCollection:     true,
			PersonalizedAds:    false,
		},
		AccessibilitySettings: AccessibilitySettings{
			HighContrast:     false,
			LargeText:        false,
			ScreenReader:     false,
			ReducedMotion:    false,
			ColorBlindMode:   "none",
			FontSize:         1.0,
			VoiceCommands:    false,
			KeyboardShortcut: false,
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

// validateSettingsUpdate validates application settings update data
func (s *SettingsService) validateSettingsUpdate(updateData map[string]interface{}) error {
	// Validate max_users_per_room
	if maxUsers, ok := updateData["max_users_per_room"]; ok {
		if users, ok := maxUsers.(float64); ok {
			if users < 2 || users > 10 {
				return fmt.Errorf("max_users_per_room must be between 2 and 10")
			}
		}
	}

	// Validate chat_timeout
	if timeout, ok := updateData["chat_timeout"]; ok {
		if timeoutVal, ok := timeout.(float64); ok {
			if timeoutVal < 5 || timeoutVal > 120 {
				return fmt.Errorf("chat_timeout must be between 5 and 120 minutes")
			}
		}
	}

	// Validate minimum_age
	if minAge, ok := updateData["minimum_age"]; ok {
		if age, ok := minAge.(float64); ok {
			if age < 13 || age > 21 {
				return fmt.Errorf("minimum_age must be between 13 and 21")
			}
		}
	}

	return nil
}

// validateUserSettingsUpdate validates user settings update data
func (s *SettingsService) validateUserSettingsUpdate(updateData map[string]interface{}) error {
	// Validate theme
	if theme, ok := updateData["theme"]; ok {
		if themeStr, ok := theme.(string); ok {
			validThemes := map[string]bool{"light": true, "dark": true, "auto": true}
			if !validThemes[themeStr] {
				return fmt.Errorf("invalid theme: must be light, dark, or auto")
			}
		}
	}

	// Validate time_format
	if timeFormat, ok := updateData["time_format"]; ok {
		if format, ok := timeFormat.(string); ok {
			validFormats := map[string]bool{"12h": true, "24h": true}
			if !validFormats[format] {
				return fmt.Errorf("invalid time_format: must be 12h or 24h")
			}
		}
	}

	return nil
}
