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
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type UserHandler struct {
	userService *services.UserService
}

func NewUserHandler(userService *services.UserService) *UserHandler {
	return &UserHandler{
		userService: userService,
	}
}

// Guest User Management

func (h *UserHandler) CreateGuest(c *gin.Context) {
	var guestData struct {
		Language  string   `json:"language"`
		Region    string   `json:"region"`
		Interests []string `json:"interests"`
		UserAgent string   `json:"user_agent"`
	}

	// Bind JSON data (optional for guests)
	c.ShouldBindJSON(&guestData)

	// Get client information
	ipAddress := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")
	if guestData.UserAgent != "" {
		userAgent = guestData.UserAgent
	}

	// Get region from IP if not provided
	var region string
	if guestData.Region != "" {
		region = guestData.Region
	} else {
		regionInfo, err := utils.GetRegionFromIP(ipAddress)
		if err != nil {
			region = "us-east" // Default region
		} else {
			region = regionInfo.Code
		}
	}

	// Set default language if not provided
	language := guestData.Language
	if language == "" {
		language = "en"
	}

	// Validate interests
	if len(guestData.Interests) > 10 {
		utils.ErrorResponse(c, http.StatusBadRequest, "Maximum 10 interests allowed")
		return
	}

	// Validate language
	if !utils.ValidateLanguageCode(language) {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid language code")
		return
	}

	// Validate interests
	if !utils.ValidateInterests(guestData.Interests) {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid interests format")
		return
	}

	// Create guest user
	guest := &models.User{
		IPAddress: ipAddress,
		UserAgent: userAgent,
		Region:    region,
		Language:  language,
		Interests: guestData.Interests,
		IsOnline:  true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		LastSeen:  time.Now(),
	}

	// Get location info
	regionInfo, _ := utils.GetRegionFromIP(ipAddress)
	if regionInfo != nil {
		guest.Country = regionInfo.Country
		guest.City = regionInfo.City
	}

	// Save guest user
	userID, err := h.userService.CreateGuestUser(guest)
	if err != nil {
		logger.LogError(err, "Failed to create guest user", map[string]interface{}{
			"ip_address": ipAddress,
			"region":     region,
		})
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to create guest user")
		return
	}

	// Generate session token
	sessionToken := utils.GenerateSessionToken(userID)

	logger.LogUserAction(userID, "guest_user_created", map[string]interface{}{
		"ip_address": ipAddress,
		"region":     region,
		"language":   language,
		"interests":  guestData.Interests,
	})

	response := map[string]interface{}{
		"user_id":       userID,
		"session_token": sessionToken,
		"region":        region,
		"language":      language,
		"interests":     guestData.Interests,
		"expires_at":    time.Now().Add(24 * time.Hour),
		"user_type":     "guest",
	}

	utils.SuccessResponseWithMessage(c, "Guest user created successfully", response)
}

func (h *UserHandler) GetGuest(c *gin.Context) {
	userID := c.Param("id")

	// Validate ObjectID format
	objectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid user ID format")
		return
	}

	// Get guest user
	user, err := h.userService.GetUserByID(objectID)
	if err != nil {
		utils.ErrorResponse(c, http.StatusNotFound, "Guest user not found")
		return
	}

	// Return public user information
	response := map[string]interface{}{
		"user_id":    user.ID.Hex(),
		"region":     user.Region,
		"language":   user.Language,
		"interests":  user.Interests,
		"is_online":  user.IsOnline,
		"created_at": user.CreatedAt,
		"user_type":  "guest",
	}

	utils.SuccessResponse(c, response)
}

// Registered User Profile Management

func (h *UserHandler) GetProfile(c *gin.Context) {
	userID := c.GetString("user_id")

	objectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid user ID")
		return
	}

	// Get user profile
	profile, err := h.userService.GetUserProfile(objectID)
	if err != nil {
		utils.ErrorResponse(c, http.StatusNotFound, "User profile not found")
		return
	}

	utils.SuccessResponse(c, profile)
}

func (h *UserHandler) UpdateProfile(c *gin.Context) {
	userID := c.GetString("user_id")

	var updateData struct {
		Username    string            `json:"username"`
		DisplayName string            `json:"display_name"`
		Bio         string            `json:"bio"`
		Language    string            `json:"language"`
		Region      string            `json:"region"`
		Interests   []string          `json:"interests"`
		DateOfBirth string            `json:"date_of_birth"` // YYYY-MM-DD format
		Gender      string            `json:"gender"`
		Country     string            `json:"country"`
		City        string            `json:"city"`
		Timezone    string            `json:"timezone"`
		Website     string            `json:"website"`
		SocialLinks map[string]string `json:"social_links"`
	}

	if err := c.ShouldBindJSON(&updateData); err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid profile data")
		return
	}

	objectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid user ID")
		return
	}

	// Validate input data
	if updateData.Username != "" && !utils.ValidateUsername(updateData.Username) {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid username format")
		return
	}

	if updateData.Language != "" && !utils.ValidateLanguageCode(updateData.Language) {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid language code")
		return
	}

	if len(updateData.Interests) > 0 && !utils.ValidateInterests(updateData.Interests) {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid interests")
		return
	}

	if updateData.Bio != "" && len(updateData.Bio) > 500 {
		utils.ErrorResponse(c, http.StatusBadRequest, "Bio must be less than 500 characters")
		return
	}

	// Check if username is already taken
	if updateData.Username != "" {
		exists, err := h.userService.CheckUsernameExists(updateData.Username, userID)
		if err != nil {
			utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to check username availability")
			return
		}
		if exists {
			utils.ErrorResponse(c, http.StatusConflict, "Username is already taken")
			return
		}
	}

	// Parse date of birth if provided
	var dateOfBirth *time.Time
	if updateData.DateOfBirth != "" {
		dob, err := time.Parse("2006-01-02", updateData.DateOfBirth)
		if err != nil {
			utils.ErrorResponse(c, http.StatusBadRequest, "Invalid date of birth format (use YYYY-MM-DD)")
			return
		}
		dateOfBirth = &dob
	}

	// Prepare update data
	profileUpdate := map[string]interface{}{
		"updated_at": time.Now(),
	}

	if updateData.Username != "" {
		profileUpdate["username"] = updateData.Username
	}
	if updateData.DisplayName != "" {
		profileUpdate["display_name"] = updateData.DisplayName
	}
	if updateData.Bio != "" {
		profileUpdate["bio"] = updateData.Bio
	}
	if updateData.Language != "" {
		profileUpdate["language"] = updateData.Language
	}
	if updateData.Region != "" {
		profileUpdate["region"] = updateData.Region
	}
	if len(updateData.Interests) > 0 {
		profileUpdate["interests"] = updateData.Interests
	}
	if dateOfBirth != nil {
		profileUpdate["date_of_birth"] = *dateOfBirth
	}
	if updateData.Gender != "" {
		profileUpdate["gender"] = updateData.Gender
	}
	if updateData.Country != "" {
		profileUpdate["country"] = updateData.Country
	}
	if updateData.City != "" {
		profileUpdate["city"] = updateData.City
	}
	if updateData.Timezone != "" {
		profileUpdate["timezone"] = updateData.Timezone
	}
	if updateData.Website != "" {
		profileUpdate["website"] = updateData.Website
	}
	if len(updateData.SocialLinks) > 0 {
		profileUpdate["social_links"] = updateData.SocialLinks
	}

	// Update profile
	err = h.userService.UpdateUserProfile(objectID, profileUpdate)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to update profile")
		return
	}

	logger.LogUserAction(userID, "profile_updated", map[string]interface{}{
		"updated_fields": profileUpdate,
		"ip":             c.ClientIP(),
	})

	utils.SuccessResponseWithMessage(c, "Profile updated successfully", profileUpdate)
}

// User Reporting

func (h *UserHandler) ReportUser(c *gin.Context) {
	reporterID := c.GetString("user_id")

	var reportData struct {
		ReportedUserID string   `json:"reported_user_id" binding:"required"`
		ChatID         string   `json:"chat_id"`
		RoomID         string   `json:"room_id"`
		Reason         string   `json:"reason" binding:"required"`
		Category       string   `json:"category" binding:"required"`
		Description    string   `json:"description"`
		Evidence       []string `json:"evidence"` // URLs or message IDs
		Severity       string   `json:"severity"` // low, medium, high, critical
	}

	if err := c.ShouldBindJSON(&reportData); err != nil {
		utils.ValidationErrorResponse(c, map[string]string{
			"reported_user_id": "Reported user ID is required",
			"reason":           "Report reason is required",
			"category":         "Report category is required",
		})
		return
	}

	// Validate reported user exists
	reportedObjectID, err := primitive.ObjectIDFromHex(reportData.ReportedUserID)
	if err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid reported user ID")
		return
	}

	exists, err := h.userService.UserExists(reportedObjectID)
	if err != nil || !exists {
		utils.ErrorResponse(c, http.StatusNotFound, "Reported user not found")
		return
	}

	// Prevent self-reporting
	if reportData.ReportedUserID == reporterID {
		utils.ErrorResponse(c, http.StatusBadRequest, "Cannot report yourself")
		return
	}

	// Validate category
	validCategories := []string{"harassment", "spam", "inappropriate_content", "fake_profile", "threats", "hate_speech", "underage", "other"}
	if !h.isValidCategory(reportData.Category, validCategories) {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid report category")
		return
	}

	// Set default severity if not provided
	if reportData.Severity == "" {
		reportData.Severity = "medium"
	}

	// Create report
	report := &models.Report{
		ReporterID:     reporterID,
		ReportedUserID: reportData.ReportedUserID,
		ChatID:         reportData.ChatID,
		RoomID:         reportData.RoomID,
		Reason:         reportData.Reason,
		Category:       reportData.Category,
		Description:    reportData.Description,
		Evidence:       reportData.Evidence,
		Severity:       reportData.Severity,
		Status:         "pending",
		IPAddress:      c.ClientIP(),
		UserAgent:      c.GetHeader("User-Agent"),
		CreatedAt:      time.Now(),
	}

	reportID, err := h.userService.CreateReport(report)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to create report")
		return
	}

	logger.LogUserAction(reporterID, "user_reported", map[string]interface{}{
		"report_id":        reportID,
		"reported_user_id": reportData.ReportedUserID,
		"category":         reportData.Category,
		"severity":         reportData.Severity,
		"chat_id":          reportData.ChatID,
		"room_id":          reportData.RoomID,
		"ip":               c.ClientIP(),
	})

	// Auto-escalate high severity reports
	if reportData.Severity == "critical" || reportData.Severity == "high" {
		h.escalateReport(reportID, reportData.Severity)
	}

	response := map[string]interface{}{
		"report_id": reportID,
		"status":    "submitted",
		"message":   "Report submitted successfully and is being reviewed",
	}

	utils.SuccessResponseWithMessage(c, "Report submitted successfully", response)
}

// Chat History

func (h *UserHandler) GetChatHistory(c *gin.Context) {
	userID := c.GetString("user_id")

	// Get pagination parameters
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
	chatType := c.Query("chat_type")
	dateFrom := c.Query("date_from")
	dateTo := c.Query("date_to")

	// Parse date filters
	var fromDate, toDate *time.Time
	if dateFrom != "" {
		from, err := time.Parse("2006-01-02", dateFrom)
		if err != nil {
			utils.ErrorResponse(c, http.StatusBadRequest, "Invalid date_from format (use YYYY-MM-DD)")
			return
		}
		fromDate = &from
	}

	if dateTo != "" {
		to, err := time.Parse("2006-01-02", dateTo)
		if err != nil {
			utils.ErrorResponse(c, http.StatusBadRequest, "Invalid date_to format (use YYYY-MM-DD)")
			return
		}
		toDate = &to
	}

	// Get chat history
	history, total, err := h.userService.GetUserChatHistory(userID, page, limit, chatType, fromDate, toDate)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to get chat history")
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

func (h *UserHandler) ClearHistory(c *gin.Context) {
	userID := c.GetString("user_id")

	var clearData struct {
		ChatIDs   []string `json:"chat_ids"`                   // Specific chats to clear
		ClearAll  bool     `json:"clear_all"`                  // Clear all history
		OlderThan string   `json:"older_than"`                 // Clear chats older than date (YYYY-MM-DD)
		ChatType  string   `json:"chat_type"`                  // Clear specific chat type
		Confirm   bool     `json:"confirm" binding:"required"` // Confirmation required
	}

	if err := c.ShouldBindJSON(&clearData); err != nil {
		utils.ValidationErrorResponse(c, map[string]string{
			"confirm": "Confirmation is required to clear chat history",
		})
		return
	}

	if !clearData.Confirm {
		utils.ErrorResponse(c, http.StatusBadRequest, "Confirmation is required to clear chat history")
		return
	}

	var olderThan *time.Time
	if clearData.OlderThan != "" {
		date, err := time.Parse("2006-01-02", clearData.OlderThan)
		if err != nil {
			utils.ErrorResponse(c, http.StatusBadRequest, "Invalid older_than date format (use YYYY-MM-DD)")
			return
		}
		olderThan = &date
	}

	// Clear chat history based on criteria
	deletedCount, err := h.userService.ClearChatHistory(userID, clearData.ChatIDs, clearData.ClearAll, olderThan, clearData.ChatType)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to clear chat history")
		return
	}

	logger.LogUserAction(userID, "chat_history_cleared", map[string]interface{}{
		"deleted_count": deletedCount,
		"clear_all":     clearData.ClearAll,
		"older_than":    clearData.OlderThan,
		"chat_type":     clearData.ChatType,
		"ip":            c.ClientIP(),
	})

	response := map[string]interface{}{
		"deleted_count": deletedCount,
		"message":       fmt.Sprintf("Successfully cleared %d chat records", deletedCount),
	}

	utils.SuccessResponseWithMessage(c, "Chat history cleared successfully", response)
}

// User Feedback

func (h *UserHandler) SubmitFeedback(c *gin.Context) {
	userID := c.GetString("user_id")

	var feedbackData struct {
		Type        string   `json:"type" binding:"required"` // bug, feature, improvement, complaint, compliment
		Category    string   `json:"category" binding:"required"`
		Subject     string   `json:"subject" binding:"required"`
		Description string   `json:"description" binding:"required"`
		Rating      int      `json:"rating"`      // 1-5 scale
		Screenshots []string `json:"screenshots"` // URLs to screenshots
		UserAgent   string   `json:"user_agent"`
		URL         string   `json:"url"`      // Page URL where feedback was submitted
		Priority    string   `json:"priority"` // low, normal, high
	}

	if err := c.ShouldBindJSON(&feedbackData); err != nil {
		utils.ValidationErrorResponse(c, map[string]string{
			"type":        "Feedback type is required",
			"category":    "Feedback category is required",
			"subject":     "Subject is required",
			"description": "Description is required",
		})
		return
	}

	// Validate feedback type
	validTypes := []string{"bug", "feature", "improvement", "complaint", "compliment", "question"}
	if !h.isValidFeedbackType(feedbackData.Type, validTypes) {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid feedback type")
		return
	}

	// Validate rating if provided
	if feedbackData.Rating < 0 || feedbackData.Rating > 5 {
		utils.ErrorResponse(c, http.StatusBadRequest, "Rating must be between 1 and 5")
		return
	}

	// Set default priority
	if feedbackData.Priority == "" {
		feedbackData.Priority = "normal"
	}

	// Create feedback record
	feedback := map[string]interface{}{
		"user_id":     userID,
		"type":        feedbackData.Type,
		"category":    feedbackData.Category,
		"subject":     feedbackData.Subject,
		"description": feedbackData.Description,
		"rating":      feedbackData.Rating,
		"screenshots": feedbackData.Screenshots,
		"user_agent":  c.GetHeader("User-Agent"),
		"url":         feedbackData.URL,
		"priority":    feedbackData.Priority,
		"ip_address":  c.ClientIP(),
		"status":      "submitted",
		"created_at":  time.Now(),
	}

	feedbackID, err := h.userService.CreateFeedback(feedback)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to submit feedback")
		return
	}

	logger.LogUserAction(userID, "feedback_submitted", map[string]interface{}{
		"feedback_id": feedbackID,
		"type":        feedbackData.Type,
		"category":    feedbackData.Category,
		"priority":    feedbackData.Priority,
		"rating":      feedbackData.Rating,
		"ip":          c.ClientIP(),
	})

	response := map[string]interface{}{
		"feedback_id": feedbackID,
		"status":      "submitted",
		"message":     "Thank you for your feedback! We'll review it and get back to you if needed.",
	}

	utils.SuccessResponseWithMessage(c, "Feedback submitted successfully", response)
}

// User Statistics

func (h *UserHandler) GetUserStats(c *gin.Context) {
	userID := c.GetString("user_id")

	stats, err := h.userService.GetUserStatistics(userID)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to get user statistics")
		return
	}

	utils.SuccessResponse(c, stats)
}

// Account Management

func (h *UserHandler) DeactivateAccount(c *gin.Context) {
	userID := c.GetString("user_id")

	var deactivateData struct {
		Reason   string `json:"reason" binding:"required"`
		Password string `json:"password"` // For registered users
		Confirm  bool   `json:"confirm" binding:"required"`
	}

	if err := c.ShouldBindJSON(&deactivateData); err != nil {
		utils.ValidationErrorResponse(c, map[string]string{
			"reason":  "Reason for deactivation is required",
			"confirm": "Confirmation is required",
		})
		return
	}

	if !deactivateData.Confirm {
		utils.ErrorResponse(c, http.StatusBadRequest, "Account deactivation must be confirmed")
		return
	}

	objectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid user ID")
		return
	}

	// For registered users, verify password
	if deactivateData.Password != "" {
		valid, err := h.userService.VerifyUserPassword(objectID, deactivateData.Password)
		if err != nil || !valid {
			utils.ErrorResponse(c, http.StatusUnauthorized, "Invalid password")
			return
		}
	}

	// Deactivate account
	err = h.userService.DeactivateAccount(objectID, deactivateData.Reason)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to deactivate account")
		return
	}

	// Invalidate all sessions
	h.invalidateUserSessions(userID)

	logger.LogUserAction(userID, "account_deactivated", map[string]interface{}{
		"reason": deactivateData.Reason,
		"ip":     c.ClientIP(),
	})

	utils.SuccessResponseWithMessage(c, "Account deactivated successfully", nil)
}

func (h *UserHandler) DeleteAccount(c *gin.Context) {
	userID := c.GetString("user_id")

	var deleteData struct {
		Password string `json:"password"` // For registered users
		Reason   string `json:"reason"`
		Confirm  bool   `json:"confirm" binding:"required"`
	}

	if err := c.ShouldBindJSON(&deleteData); err != nil {
		utils.ValidationErrorResponse(c, map[string]string{
			"confirm": "Confirmation is required to delete account",
		})
		return
	}

	if !deleteData.Confirm {
		utils.ErrorResponse(c, http.StatusBadRequest, "Account deletion must be confirmed")
		return
	}

	objectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid user ID")
		return
	}

	// For registered users, verify password
	if deleteData.Password != "" {
		valid, err := h.userService.VerifyUserPassword(objectID, deleteData.Password)
		if err != nil || !valid {
			utils.ErrorResponse(c, http.StatusUnauthorized, "Invalid password")
			return
		}
	}

	// Delete account and all associated data
	err = h.userService.DeleteAccount(objectID, deleteData.Reason)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to delete account")
		return
	}

	// Invalidate all sessions
	h.invalidateUserSessions(userID)

	logger.LogUserAction(userID, "account_deleted", map[string]interface{}{
		"reason": deleteData.Reason,
		"ip":     c.ClientIP(),
	})

	utils.SuccessResponseWithMessage(c, "Account deleted successfully", nil)
}

// Helper methods

func (h *UserHandler) isValidCategory(category string, validCategories []string) bool {
	for _, validCategory := range validCategories {
		if category == validCategory {
			return true
		}
	}
	return false
}

func (h *UserHandler) isValidFeedbackType(feedbackType string, validTypes []string) bool {
	for _, validType := range validTypes {
		if feedbackType == validType {
			return true
		}
	}
	return false
}

func (h *UserHandler) escalateReport(reportID, severity string) {
	// Implement report escalation logic
	// This could involve notifying administrators, auto-flagging content, etc.
	logger.Info("Report escalated", map[string]interface{}{
		"report_id": reportID,
		"severity":  severity,
	})
}

func (h *UserHandler) invalidateUserSessions(userID string) {
	// Invalidate all session tokens for this user
	utils.InvalidateToken("") // This would need to be updated to handle user-specific invalidation
}
