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

type UserService struct {
	db                    *mongo.Database
	userCollection        *mongo.Collection
	profileCollection     *mongo.Collection
	reportCollection      *mongo.Collection
	feedbackCollection    *mongo.Collection
	activityCollection    *mongo.Collection
	chatHistoryCollection *mongo.Collection
}

// UserProfile represents extended user profile information
type UserProfile struct {
	ID           primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	UserID       primitive.ObjectID `bson:"user_id" json:"user_id"`
	Username     string             `bson:"username" json:"username"`
	DisplayName  string             `bson:"display_name" json:"display_name"`
	Email        string             `bson:"email,omitempty" json:"email,omitempty"`
	Bio          string             `bson:"bio" json:"bio"`
	Avatar       string             `bson:"avatar" json:"avatar"`
	DateOfBirth  *time.Time         `bson:"date_of_birth,omitempty" json:"date_of_birth,omitempty"`
	Gender       string             `bson:"gender" json:"gender"`
	Timezone     string             `bson:"timezone" json:"timezone"`
	Website      string             `bson:"website" json:"website"`
	SocialLinks  SocialLinks        `bson:"social_links" json:"social_links"`
	Preferences  UserPreferences    `bson:"preferences" json:"preferences"`
	Stats        UserProfileStats   `bson:"stats" json:"stats"`
	Verification UserVerification   `bson:"verification" json:"verification"`
	CreatedAt    time.Time          `bson:"created_at" json:"created_at"`
	UpdatedAt    time.Time          `bson:"updated_at" json:"updated_at"`
}

type SocialLinks struct {
	Twitter   string `bson:"twitter" json:"twitter"`
	Instagram string `bson:"instagram" json:"instagram"`
	LinkedIn  string `bson:"linkedin" json:"linkedin"`
	Discord   string `bson:"discord" json:"discord"`
	TikTok    string `bson:"tiktok" json:"tiktok"`
}

type UserPreferences struct {
	ShowEmail       bool `bson:"show_email" json:"show_email"`
	ShowAge         bool `bson:"show_age" json:"show_age"`
	ShowLocation    bool `bson:"show_location" json:"show_location"`
	AllowFriendReq  bool `bson:"allow_friend_requests" json:"allow_friend_requests"`
	NewsletterOptIn bool `bson:"newsletter_opt_in" json:"newsletter_opt_in"`
}

type UserProfileStats struct {
	TotalChats     int64     `bson:"total_chats" json:"total_chats"`
	TotalMinutes   int64     `bson:"total_minutes" json:"total_minutes"`
	FavoriteRegion string    `bson:"favorite_region" json:"favorite_region"`
	JoinedDate     time.Time `bson:"joined_date" json:"joined_date"`
	LastActive     time.Time `bson:"last_active" json:"last_active"`
}

type UserVerification struct {
	EmailVerified   bool       `bson:"email_verified" json:"email_verified"`
	PhoneVerified   bool       `bson:"phone_verified" json:"phone_verified"`
	IDVerified      bool       `bson:"id_verified" json:"id_verified"`
	VerifiedAt      *time.Time `bson:"verified_at,omitempty" json:"verified_at,omitempty"`
	VerificationDoc string     `bson:"verification_doc,omitempty" json:"verification_doc,omitempty"`
}

// UserReport represents a report made by one user against another
type UserReport struct {
	ID             primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	ReporterID     primitive.ObjectID `bson:"reporter_id" json:"reporter_id"`
	ReportedUserID primitive.ObjectID `bson:"reported_user_id" json:"reported_user_id"`
	ChatID         primitive.ObjectID `bson:"chat_id,omitempty" json:"chat_id,omitempty"`
	ReportType     string             `bson:"report_type" json:"report_type"` // spam, abuse, inappropriate, harassment, fake
	Category       string             `bson:"category" json:"category"`       // specific subcategory
	Description    string             `bson:"description" json:"description"`
	Evidence       []Evidence         `bson:"evidence" json:"evidence"`
	Status         string             `bson:"status" json:"status"`     // pending, reviewed, resolved, dismissed
	Priority       string             `bson:"priority" json:"priority"` // low, medium, high, critical
	AdminNotes     string             `bson:"admin_notes" json:"admin_notes"`
	ReviewedBy     primitive.ObjectID `bson:"reviewed_by,omitempty" json:"reviewed_by,omitempty"`
	ReviewedAt     *time.Time         `bson:"reviewed_at,omitempty" json:"reviewed_at,omitempty"`
	CreatedAt      time.Time          `bson:"created_at" json:"created_at"`
	UpdatedAt      time.Time          `bson:"updated_at" json:"updated_at"`
}

type Evidence struct {
	Type        string    `bson:"type" json:"type"`               // screenshot, video, text, url
	URL         string    `bson:"url" json:"url"`                 // file URL or link
	Description string    `bson:"description" json:"description"` // evidence description
	Timestamp   time.Time `bson:"timestamp" json:"timestamp"`
}

// UserFeedback represents user feedback/suggestions
type UserFeedback struct {
	ID          primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	UserID      primitive.ObjectID `bson:"user_id" json:"user_id"`
	Type        string             `bson:"type" json:"type"`         // bug, feature, improvement, other
	Category    string             `bson:"category" json:"category"` // ui, performance, feature, etc.
	Title       string             `bson:"title" json:"title"`
	Description string             `bson:"description" json:"description"`
	Priority    string             `bson:"priority" json:"priority"` // low, medium, high
	Status      string             `bson:"status" json:"status"`     // new, in_progress, resolved, closed
	Rating      int                `bson:"rating" json:"rating"`     // 1-5 stars
	UserAgent   string             `bson:"user_agent" json:"user_agent"`
	IPAddress   string             `bson:"ip_address" json:"ip_address"`
	Screenshots []string           `bson:"screenshots" json:"screenshots"` // screenshot URLs
	AdminNotes  string             `bson:"admin_notes" json:"admin_notes"`
	AssignedTo  primitive.ObjectID `bson:"assigned_to,omitempty" json:"assigned_to,omitempty"`
	CreatedAt   time.Time          `bson:"created_at" json:"created_at"`
	UpdatedAt   time.Time          `bson:"updated_at" json:"updated_at"`
}

// UserActivity represents user activity logs
type UserActivity struct {
	ID        primitive.ObjectID     `bson:"_id,omitempty" json:"id"`
	UserID    primitive.ObjectID     `bson:"user_id" json:"user_id"`
	Action    string                 `bson:"action" json:"action"`   // login, logout, chat_start, chat_end, etc.
	Details   map[string]interface{} `bson:"details" json:"details"` // additional action details
	IPAddress string                 `bson:"ip_address" json:"ip_address"`
	UserAgent string                 `bson:"user_agent" json:"user_agent"`
	Location  Location               `bson:"location" json:"location"`
	Timestamp time.Time              `bson:"timestamp" json:"timestamp"`
}

type Location struct {
	Country   string  `bson:"country" json:"country"`
	Region    string  `bson:"region" json:"region"`
	City      string  `bson:"city" json:"city"`
	Latitude  float64 `bson:"latitude" json:"latitude"`
	Longitude float64 `bson:"longitude" json:"longitude"`
}

// ChatHistory represents user's chat history entry
type ChatHistoryEntry struct {
	ID           primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	UserID       primitive.ObjectID `bson:"user_id" json:"user_id"`
	ChatID       primitive.ObjectID `bson:"chat_id" json:"chat_id"`
	PartnerID    primitive.ObjectID `bson:"partner_id,omitempty" json:"partner_id,omitempty"`
	ChatType     string             `bson:"chat_type" json:"chat_type"` // text, video, audio
	Duration     int64              `bson:"duration" json:"duration"`   // duration in seconds
	MessageCount int                `bson:"message_count" json:"message_count"`
	Rating       int                `bson:"rating" json:"rating"` // 1-5 stars rating of chat
	Notes        string             `bson:"notes" json:"notes"`   // user's private notes
	IsBookmarked bool               `bson:"is_bookmarked" json:"is_bookmarked"`
	StartedAt    time.Time          `bson:"started_at" json:"started_at"`
	EndedAt      time.Time          `bson:"ended_at" json:"ended_at"`
	CreatedAt    time.Time          `bson:"created_at" json:"created_at"`
}

// NewUserService creates a new user service instance
func NewUserService(db *mongo.Database) *UserService {
	return &UserService{
		db:                    db,
		userCollection:        db.Collection("users"),
		profileCollection:     db.Collection("user_profiles"),
		reportCollection:      db.Collection("user_reports"),
		feedbackCollection:    db.Collection("user_feedback"),
		activityCollection:    db.Collection("user_activity"),
		chatHistoryCollection: db.Collection("user_chat_history"),
	}
}

// ================================
// User Management
// ================================

// CreateGuestUser creates a new guest user
func (s *UserService) CreateGuestUser(ipAddress, userAgent, language string, interests []string, region string) (primitive.ObjectID, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Get location data from IP
	regionInfo, err := utils.GetRegionFromIP(ipAddress)
	if err != nil {
		logger.LogError(err, "Failed to get region from IP", map[string]interface{}{
			"ip_address": ipAddress,
		})
		// Continue with provided region
	} else if regionInfo != nil {
		region = regionInfo.Code
	}

	// Create guest user
	user := &models.User{
		SessionID: utils.GenerateSessionID(),
		IPAddress: ipAddress,
		UserAgent: userAgent,
		Language:  language,
		Interests: interests,
		Region:    region,
		IsOnline:  true,
		LastSeen:  time.Now(),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		IsBanned:  false,
	}

	// Add location details if available
	if regionInfo != nil {
		user.Country = regionInfo.Country
		user.City = regionInfo.City
	}

	result, err := s.userCollection.InsertOne(ctx, user)
	if err != nil {
		logger.LogError(err, "Failed to create guest user", map[string]interface{}{
			"ip_address": ipAddress,
			"region":     region,
			"language":   language,
		})
		return primitive.NilObjectID, fmt.Errorf("failed to create guest user: %w", err)
	}

	userID := result.InsertedID.(primitive.ObjectID)

	// Log user creation activity
	s.logUserActivity(userID, "user_created", map[string]interface{}{
		"user_type": "guest",
		"region":    region,
		"language":  language,
		"interests": interests,
	}, ipAddress, userAgent)

	return userID, nil
}

// GetUserByID retrieves a user by their ID
func (s *UserService) GetUserByID(userID primitive.ObjectID) (*models.User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var user models.User
	err := s.userCollection.FindOne(ctx, bson.M{"_id": userID}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, fmt.Errorf("user not found")
		}
		logger.LogError(err, "Failed to get user by ID", map[string]interface{}{
			"user_id": userID.Hex(),
		})
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return &user, nil
}

// GetUserBySessionID retrieves a user by their session ID
func (s *UserService) GetUserBySessionID(sessionID string) (*models.User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var user models.User
	err := s.userCollection.FindOne(ctx, bson.M{"session_id": sessionID}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, fmt.Errorf("user not found")
		}
		logger.LogError(err, "Failed to get user by session ID", map[string]interface{}{
			"session_id": sessionID,
		})
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return &user, nil
}

// UpdateUser updates user information
func (s *UserService) UpdateUser(userID primitive.ObjectID, updateData map[string]interface{}) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Add updated timestamp
	updateData["updated_at"] = time.Now()

	// Validate update data
	if err := s.validateUserUpdate(updateData); err != nil {
		return fmt.Errorf("invalid user data: %w", err)
	}

	update := bson.M{"$set": updateData}
	result, err := s.userCollection.UpdateOne(ctx, bson.M{"_id": userID}, update)
	if err != nil {
		logger.LogError(err, "Failed to update user", map[string]interface{}{
			"user_id":     userID.Hex(),
			"update_data": updateData,
		})
		return fmt.Errorf("failed to update user: %w", err)
	}

	if result.MatchedCount == 0 {
		return fmt.Errorf("user not found")
	}

	logger.LogUserAction(userID.Hex(), "user_updated", map[string]interface{}{
		"fields_updated": len(updateData),
		"modified_count": result.ModifiedCount,
	})

	return nil
}

// UpdateUserOnlineStatus updates user's online status
func (s *UserService) UpdateUserOnlineStatus(userID primitive.ObjectID, isOnline bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	update := bson.M{
		"$set": bson.M{
			"is_online":  isOnline,
			"last_seen":  time.Now(),
			"updated_at": time.Now(),
		},
	}

	_, err := s.userCollection.UpdateOne(ctx, bson.M{"_id": userID}, update)
	if err != nil {
		logger.LogError(err, "Failed to update user online status", map[string]interface{}{
			"user_id":   userID.Hex(),
			"is_online": isOnline,
		})
		return fmt.Errorf("failed to update online status: %w", err)
	}

	return nil
}

// DeleteUser soft deletes a user
func (s *UserService) DeleteUser(userID primitive.ObjectID) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Start transaction for comprehensive cleanup
	session, err := s.db.Client().StartSession()
	if err != nil {
		return fmt.Errorf("failed to start transaction: %w", err)
	}
	defer session.EndSession(ctx)

	_, err = session.WithTransaction(ctx, func(sc mongo.SessionContext) (interface{}, error) {
		// Mark user as deleted instead of hard delete
		update := bson.M{
			"$set": bson.M{
				"is_deleted": true,
				"deleted_at": time.Now(),
				"is_online":  false,
				"updated_at": time.Now(),
			},
		}

		result, err := s.userCollection.UpdateOne(sc, bson.M{"_id": userID}, update)
		if err != nil {
			return nil, err
		}

		if result.MatchedCount == 0 {
			return nil, fmt.Errorf("user not found")
		}

		// Log deletion activity
		s.logUserActivity(userID, "user_deleted", map[string]interface{}{
			"deletion_type": "soft_delete",
		}, "", "")

		return nil, nil
	})

	if err != nil {
		logger.LogError(err, "Failed to delete user", map[string]interface{}{
			"user_id": userID.Hex(),
		})
		return fmt.Errorf("failed to delete user: %w", err)
	}

	logger.LogUserAction(userID.Hex(), "user_deleted", map[string]interface{}{
		"deletion_type": "soft_delete",
	})

	return nil
}

// ================================
// User Profiles
// ================================

// GetUserProfile retrieves user profile information
func (s *UserService) GetUserProfile(userID primitive.ObjectID) (*UserProfile, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var profile UserProfile
	err := s.profileCollection.FindOne(ctx, bson.M{"user_id": userID}).Decode(&profile)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			// Create default profile if none exists
			return s.createDefaultProfile(userID)
		}
		logger.LogError(err, "Failed to get user profile", map[string]interface{}{
			"user_id": userID.Hex(),
		})
		return nil, fmt.Errorf("failed to get user profile: %w", err)
	}

	return &profile, nil
}

// UpdateUserProfile updates user profile information
func (s *UserService) UpdateUserProfile(userID primitive.ObjectID, updateData map[string]interface{}) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Add updated timestamp
	updateData["updated_at"] = time.Now()

	// Validate profile update data
	if err := s.validateProfileUpdate(updateData); err != nil {
		return fmt.Errorf("invalid profile data: %w", err)
	}

	update := bson.M{
		"$set":         updateData,
		"$setOnInsert": bson.M{"created_at": time.Now(), "user_id": userID},
	}
	opts := options.Update().SetUpsert(true)

	result, err := s.profileCollection.UpdateOne(ctx, bson.M{"user_id": userID}, update, opts)
	if err != nil {
		logger.LogError(err, "Failed to update user profile", map[string]interface{}{
			"user_id":     userID.Hex(),
			"update_data": updateData,
		})
		return fmt.Errorf("failed to update profile: %w", err)
	}

	logger.LogUserAction(userID.Hex(), "profile_updated", map[string]interface{}{
		"fields_updated": len(updateData),
		"modified_count": result.ModifiedCount,
		"upserted_count": result.UpsertedCount,
	})

	return nil
}

// ================================
// User Reports
// ================================

// CreateUserReport creates a new user report
func (s *UserService) CreateUserReport(reporterID, reportedUserID primitive.ObjectID, reportType, category, description string, evidence []Evidence, chatID *primitive.ObjectID) (primitive.ObjectID, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Check if user has already reported this user recently (prevent spam)
	existingReports, err := s.getRecentReports(reporterID, reportedUserID, 24*time.Hour)
	if err == nil && len(existingReports) >= 3 {
		return primitive.NilObjectID, fmt.Errorf("too many reports against this user in the last 24 hours")
	}

	// Determine priority based on report type
	priority := s.determinePriority(reportType, category)

	report := &UserReport{
		ReporterID:     reporterID,
		ReportedUserID: reportedUserID,
		ReportType:     reportType,
		Category:       category,
		Description:    description,
		Evidence:       evidence,
		Status:         "pending",
		Priority:       priority,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}

	if chatID != nil {
		report.ChatID = *chatID
	}

	result, err := s.reportCollection.InsertOne(ctx, report)
	if err != nil {
		logger.LogError(err, "Failed to create user report", map[string]interface{}{
			"reporter_id":      reporterID.Hex(),
			"reported_user_id": reportedUserID.Hex(),
			"report_type":      reportType,
		})
		return primitive.NilObjectID, fmt.Errorf("failed to create report: %w", err)
	}

	reportID := result.InsertedID.(primitive.ObjectID)

	// Log report creation
	s.logUserActivity(reporterID, "report_created", map[string]interface{}{
		"report_id":        reportID.Hex(),
		"reported_user_id": reportedUserID.Hex(),
		"report_type":      reportType,
		"priority":         priority,
	}, "", "")

	logger.LogUserAction(reporterID.Hex(), "user_reported", map[string]interface{}{
		"report_id":        reportID.Hex(),
		"reported_user_id": reportedUserID.Hex(),
		"report_type":      reportType,
		"priority":         priority,
	})

	return reportID, nil
}

// ================================
// User Feedback
// ================================

// CreateUserFeedback creates user feedback entry
func (s *UserService) CreateUserFeedback(userID primitive.ObjectID, feedbackType, category, title, description string, rating int, screenshots []string, ipAddress, userAgent string) (primitive.ObjectID, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Validate rating
	if rating < 1 || rating > 5 {
		return primitive.NilObjectID, fmt.Errorf("rating must be between 1 and 5")
	}

	// Determine priority based on type and rating
	priority := "low"
	if feedbackType == "bug" || rating <= 2 {
		priority = "high"
	} else if rating == 3 {
		priority = "medium"
	}

	feedback := &UserFeedback{
		UserID:      userID,
		Type:        feedbackType,
		Category:    category,
		Title:       title,
		Description: description,
		Priority:    priority,
		Status:      "new",
		Rating:      rating,
		UserAgent:   userAgent,
		IPAddress:   ipAddress,
		Screenshots: screenshots,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	result, err := s.feedbackCollection.InsertOne(ctx, feedback)
	if err != nil {
		logger.LogError(err, "Failed to create user feedback", map[string]interface{}{
			"user_id": userID.Hex(),
			"type":    feedbackType,
			"rating":  rating,
		})
		return primitive.NilObjectID, fmt.Errorf("failed to create feedback: %w", err)
	}

	feedbackID := result.InsertedID.(primitive.ObjectID)

	// Log feedback creation
	s.logUserActivity(userID, "feedback_submitted", map[string]interface{}{
		"feedback_id": feedbackID.Hex(),
		"type":        feedbackType,
		"rating":      rating,
		"priority":    priority,
	}, ipAddress, userAgent)

	logger.LogUserAction(userID.Hex(), "feedback_submitted", map[string]interface{}{
		"feedback_id": feedbackID.Hex(),
		"type":        feedbackType,
		"rating":      rating,
	})

	return feedbackID, nil
}

// ================================
// Chat History Management
// ================================

// AddChatToHistory adds a chat session to user's history
func (s *UserService) AddChatToHistory(userID, chatID primitive.ObjectID, partnerID *primitive.ObjectID, chatType string, duration int64, messageCount int, startedAt, endedAt time.Time) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	historyEntry := &ChatHistoryEntry{
		UserID:       userID,
		ChatID:       chatID,
		ChatType:     chatType,
		Duration:     duration,
		MessageCount: messageCount,
		StartedAt:    startedAt,
		EndedAt:      endedAt,
		CreatedAt:    time.Now(),
	}

	if partnerID != nil {
		historyEntry.PartnerID = *partnerID
	}

	_, err := s.chatHistoryCollection.InsertOne(ctx, historyEntry)
	if err != nil {
		logger.LogError(err, "Failed to add chat to history", map[string]interface{}{
			"user_id":       userID.Hex(),
			"chat_id":       chatID.Hex(),
			"chat_type":     chatType,
			"duration":      duration,
			"message_count": messageCount,
		})
		return fmt.Errorf("failed to add chat to history: %w", err)
	}

	// Update user profile stats
	s.updateUserProfileStats(userID, duration)

	return nil
}

// GetUserChatHistory retrieves user's chat history with pagination
func (s *UserService) GetUserChatHistory(userID string, page, limit int, chatType string, fromDate, toDate *time.Time) ([]ChatHistoryEntry, int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	userObjectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid user ID: %w", err)
	}

	// Build filter
	filter := bson.M{"user_id": userObjectID}

	if chatType != "" {
		filter["chat_type"] = chatType
	}

	if fromDate != nil || toDate != nil {
		dateFilter := bson.M{}
		if fromDate != nil {
			dateFilter["$gte"] = *fromDate
		}
		if toDate != nil {
			dateFilter["$lte"] = *toDate
		}
		filter["started_at"] = dateFilter
	}

	// Get total count
	total, err := s.chatHistoryCollection.CountDocuments(ctx, filter)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count chat history: %w", err)
	}

	// Get paginated results
	skip := (page - 1) * limit
	opts := options.Find().
		SetLimit(int64(limit)).
		SetSkip(int64(skip)).
		SetSort(bson.D{{Key: "started_at", Value: -1}})

	cursor, err := s.chatHistoryCollection.Find(ctx, filter, opts)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get chat history: %w", err)
	}
	defer cursor.Close(ctx)

	var history []ChatHistoryEntry
	if err = cursor.All(ctx, &history); err != nil {
		return nil, 0, fmt.Errorf("failed to decode chat history: %w", err)
	}

	return history, total, nil
}

// ClearChatHistory clears user's chat history based on criteria
func (s *UserService) ClearChatHistory(userID string, chatIDs []string, clearAll bool, olderThan *time.Time, chatType string) (int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	userObjectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		return 0, fmt.Errorf("invalid user ID: %w", err)
	}

	filter := bson.M{"user_id": userObjectID}

	if clearAll {
		// Clear all history for user
	} else if len(chatIDs) > 0 {
		// Clear specific chats
		objectIDs := make([]primitive.ObjectID, len(chatIDs))
		for i, id := range chatIDs {
			objectID, err := primitive.ObjectIDFromHex(id)
			if err != nil {
				return 0, fmt.Errorf("invalid chat ID %s: %w", id, err)
			}
			objectIDs[i] = objectID
		}
		filter["chat_id"] = bson.M{"$in": objectIDs}
	}

	// Add time filter
	if olderThan != nil {
		filter["started_at"] = bson.M{"$lt": *olderThan}
	}

	// Add chat type filter
	if chatType != "" {
		filter["chat_type"] = chatType
	}

	result, err := s.chatHistoryCollection.DeleteMany(ctx, filter)
	if err != nil {
		logger.LogError(err, "Failed to clear chat history", map[string]interface{}{
			"user_id":    userID,
			"clear_all":  clearAll,
			"chat_ids":   chatIDs,
			"older_than": olderThan,
			"chat_type":  chatType,
		})
		return 0, fmt.Errorf("failed to clear chat history: %w", err)
	}

	logger.LogUserAction(userID, "chat_history_cleared", map[string]interface{}{
		"deleted_count": result.DeletedCount,
		"clear_all":     clearAll,
		"older_than":    olderThan,
		"chat_type":     chatType,
	})

	return result.DeletedCount, nil
}

// ================================
// User Banning System
// ================================

// BanUser bans a user with optional expiry
func (s *UserService) BanUser(userID primitive.ObjectID, reason string, expiry *time.Time) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	update := bson.M{
		"$set": bson.M{
			"is_banned":  true,
			"ban_reason": reason,
			"banned_at":  time.Now(),
			"is_online":  false,
			"updated_at": time.Now(),
		},
	}

	if expiry != nil {
		update["$set"].(bson.M)["ban_expiry"] = *expiry
	}

	result, err := s.userCollection.UpdateOne(ctx, bson.M{"_id": userID}, update)
	if err != nil {
		logger.LogError(err, "Failed to ban user", map[string]interface{}{
			"user_id": userID.Hex(),
			"reason":  reason,
			"expiry":  expiry,
		})
		return fmt.Errorf("failed to ban user: %w", err)
	}

	if result.MatchedCount == 0 {
		return fmt.Errorf("user not found")
	}

	// Log ban activity
	s.logUserActivity(userID, "user_banned", map[string]interface{}{
		"reason":   reason,
		"expiry":   expiry,
		"ban_type": "manual",
	}, "", "")

	logger.LogUserAction(userID.Hex(), "user_banned", map[string]interface{}{
		"reason": reason,
		"expiry": expiry,
	})

	return nil
}

// UnbanUser removes a user's ban
func (s *UserService) UnbanUser(userID primitive.ObjectID) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	update := bson.M{
		"$set": bson.M{
			"is_banned":  false,
			"updated_at": time.Now(),
		},
		"$unset": bson.M{
			"ban_reason": "",
			"ban_expiry": "",
			"banned_at":  "",
		},
	}

	result, err := s.userCollection.UpdateOne(ctx, bson.M{"_id": userID}, update)
	if err != nil {
		logger.LogError(err, "Failed to unban user", map[string]interface{}{
			"user_id": userID.Hex(),
		})
		return fmt.Errorf("failed to unban user: %w", err)
	}

	if result.MatchedCount == 0 {
		return fmt.Errorf("user not found")
	}

	// Log unban activity
	s.logUserActivity(userID, "user_unbanned", map[string]interface{}{
		"unban_type": "manual",
	}, "", "")

	logger.LogUserAction(userID.Hex(), "user_unbanned", nil)

	return nil
}

// ================================
// Admin Functions
// ================================

// GetUsersWithPagination retrieves users with pagination for admin
func (s *UserService) GetUsersWithPagination(filter bson.M, page, limit int) ([]models.User, int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Get total count
	total, err := s.userCollection.CountDocuments(ctx, filter)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count users: %w", err)
	}

	// Get paginated results
	skip := (page - 1) * limit
	opts := options.Find().
		SetLimit(int64(limit)).
		SetSkip(int64(skip)).
		SetSort(bson.D{{Key: "created_at", Value: -1}})

	cursor, err := s.userCollection.Find(ctx, filter, opts)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get users: %w", err)
	}
	defer cursor.Close(ctx)

	var users []models.User
	if err = cursor.All(ctx, &users); err != nil {
		return nil, 0, fmt.Errorf("failed to decode users: %w", err)
	}

	return users, total, nil
}

// GetUserActivity retrieves user activity logs
func (s *UserService) GetUserActivity(userID primitive.ObjectID) []UserActivity {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	opts := options.Find().
		SetSort(bson.D{{Key: "timestamp", Value: -1}}).
		SetLimit(50)

	cursor, err := s.activityCollection.Find(ctx, bson.M{"user_id": userID}, opts)
	if err != nil {
		logger.LogError(err, "Failed to get user activity", map[string]interface{}{
			"user_id": userID.Hex(),
		})
		return []UserActivity{}
	}
	defer cursor.Close(ctx)

	var activities []UserActivity
	if err = cursor.All(ctx, &activities); err != nil {
		logger.LogError(err, "Failed to decode user activities", nil)
		return []UserActivity{}
	}

	return activities
}

// GetUserLastActivity gets user's last activity timestamp
func (s *UserService) GetUserLastActivity(userID primitive.ObjectID) *time.Time {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	opts := options.FindOne().SetSort(bson.D{{Key: "timestamp", Value: -1}})
	var activity UserActivity

	err := s.activityCollection.FindOne(ctx, bson.M{"user_id": userID}, opts).Decode(&activity)
	if err != nil {
		return nil
	}

	return &activity.Timestamp
}

// GetUserStats retrieves overall user statistics
func (s *UserService) GetUserStats() (*models.UserStats, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	stats := &models.UserStats{}

	// Total users
	total, err := s.userCollection.CountDocuments(ctx, bson.M{})
	if err == nil {
		stats.TotalUsers = total
	}

	// Online users
	online, err := s.userCollection.CountDocuments(ctx, bson.M{"is_online": true})
	if err == nil {
		stats.OnlineUsers = online
	}

	// Banned users
	banned, err := s.userCollection.CountDocuments(ctx, bson.M{"is_banned": true})
	if err == nil {
		stats.BannedUsers = banned
	}

	return stats, nil
}

// ================================
// Helper Methods
// ================================

// createDefaultProfile creates a default user profile
func (s *UserService) createDefaultProfile(userID primitive.ObjectID) (*UserProfile, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	profile := &UserProfile{
		UserID:      userID,
		DisplayName: "Anonymous User",
		Bio:         "",
		Avatar:      "",
		Timezone:    "UTC",
		SocialLinks: SocialLinks{},
		Preferences: UserPreferences{
			ShowEmail:       false,
			ShowAge:         false,
			ShowLocation:    true,
			AllowFriendReq:  true,
			NewsletterOptIn: false,
		},
		Stats: UserProfileStats{
			TotalChats:   0,
			TotalMinutes: 0,
			JoinedDate:   time.Now(),
			LastActive:   time.Now(),
		},
		Verification: UserVerification{
			EmailVerified: false,
			PhoneVerified: false,
			IDVerified:    false,
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	result, err := s.profileCollection.InsertOne(ctx, profile)
	if err != nil {
		logger.LogError(err, "Failed to create default profile", map[string]interface{}{
			"user_id": userID.Hex(),
		})
		return nil, fmt.Errorf("failed to create default profile: %w", err)
	}

	profile.ID = result.InsertedID.(primitive.ObjectID)
	return profile, nil
}

// logUserActivity logs user activity
func (s *UserService) logUserActivity(userID primitive.ObjectID, action string, details map[string]interface{}, ipAddress, userAgent string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	activity := &UserActivity{
		UserID:    userID,
		Action:    action,
		Details:   details,
		IPAddress: ipAddress,
		UserAgent: userAgent,
		Timestamp: time.Now(),
	}

	// Add location if IP is provided
	if ipAddress != "" {
		if regionInfo, err := utils.GetRegionFromIP(ipAddress); err == nil && regionInfo != nil {
			activity.Location = Location{
				Country: regionInfo.Country,
				Region:  regionInfo.Code,
				City:    regionInfo.City,
			}
		}
	}

	_, err := s.activityCollection.InsertOne(ctx, activity)
	if err != nil {
		// Log error but don't fail the main operation
		logger.LogError(err, "Failed to log user activity", map[string]interface{}{
			"user_id": userID.Hex(),
			"action":  action,
		})
	}
}

// getRecentReports gets recent reports by a user against another user
func (s *UserService) getRecentReports(reporterID, reportedUserID primitive.ObjectID, duration time.Duration) ([]UserReport, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	since := time.Now().Add(-duration)
	filter := bson.M{
		"reporter_id":      reporterID,
		"reported_user_id": reportedUserID,
		"created_at":       bson.M{"$gte": since},
	}

	cursor, err := s.reportCollection.Find(ctx, filter)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var reports []UserReport
	err = cursor.All(ctx, &reports)
	return reports, err
}

// determinePriority determines report priority based on type and category
func (s *UserService) determinePriority(reportType, category string) string {
	criticalTypes := map[string]bool{
		"harassment": true,
		"abuse":      true,
		"threats":    true,
	}

	if criticalTypes[reportType] || criticalTypes[category] {
		return "critical"
	}

	highTypes := map[string]bool{
		"inappropriate": true,
		"spam":          true,
		"fake":          true,
	}

	if highTypes[reportType] || highTypes[category] {
		return "high"
	}

	return "medium"
}

// updateUserProfileStats updates user profile statistics
func (s *UserService) updateUserProfileStats(userID primitive.ObjectID, chatDuration int64) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	update := bson.M{
		"$inc": bson.M{
			"stats.total_chats":   1,
			"stats.total_minutes": chatDuration / 60, // convert seconds to minutes
		},
		"$set": bson.M{
			"stats.last_active": time.Now(),
			"updated_at":        time.Now(),
		},
	}

	s.profileCollection.UpdateOne(ctx, bson.M{"user_id": userID}, update)
}

// validateUserUpdate validates user update data
func (s *UserService) validateUserUpdate(updateData map[string]interface{}) error {
	// Validate language
	if language, ok := updateData["language"]; ok {
		if lang, ok := language.(string); ok {
			if !utils.IsValidLanguageCode(lang) {
				return fmt.Errorf("invalid language code: %s", lang)
			}
		}
	}

	// Validate region
	if region, ok := updateData["region"]; ok {
		if reg, ok := region.(string); ok {
			if !utils.IsValidRegionCode(reg) {
				return fmt.Errorf("invalid region code: %s", reg)
			}
		}
	}

	// Validate interests
	if interests, ok := updateData["interests"]; ok {
		if interestSlice, ok := interests.([]interface{}); ok {
			if len(interestSlice) > 10 {
				return fmt.Errorf("maximum 10 interests allowed")
			}
			for _, interest := range interestSlice {
				if interestStr, ok := interest.(string); ok {
					if len(strings.TrimSpace(interestStr)) == 0 {
						return fmt.Errorf("interest cannot be empty")
					}
					if len(interestStr) > 50 {
						return fmt.Errorf("interest too long (max 50 characters)")
					}
				}
			}
		}
	}

	return nil
}

// validateProfileUpdate validates profile update data
func (s *UserService) validateProfileUpdate(updateData map[string]interface{}) error {
	// Validate username
	if username, ok := updateData["username"]; ok {
		if usernameStr, ok := username.(string); ok {
			if len(usernameStr) < 3 || len(usernameStr) > 30 {
				return fmt.Errorf("username must be between 3 and 30 characters")
			}
			if !utils.IsValidUsername(usernameStr) {
				return fmt.Errorf("username contains invalid characters")
			}
		}
	}

	// Validate email
	if email, ok := updateData["email"]; ok {
		if emailStr, ok := email.(string); ok {
			if !utils.IsValidEmail(emailStr) {
				return fmt.Errorf("invalid email format")
			}
		}
	}

	// Validate bio length
	if bio, ok := updateData["bio"]; ok {
		if bioStr, ok := bio.(string); ok {
			if len(bioStr) > 500 {
				return fmt.Errorf("bio too long (max 500 characters)")
			}
		}
	}

	return nil
}
