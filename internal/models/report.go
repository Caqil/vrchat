package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// Report represents a user report against another user or content
type Report struct {
	ID             primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	ReporterID     string             `bson:"reporter_id" json:"reporter_id"`                     // User making the report
	ReportedUserID string             `bson:"reported_user_id" json:"reported_user_id"`           // User being reported
	ChatID         string             `bson:"chat_id,omitempty" json:"chat_id,omitempty"`         // Associated chat ID
	RoomID         string             `bson:"room_id,omitempty" json:"room_id,omitempty"`         // Associated room ID
	Reason         string             `bson:"reason" json:"reason"`                               // Primary reason for report
	Category       string             `bson:"category" json:"category"`                           // Report category
	Description    string             `bson:"description" json:"description"`                     // Detailed description
	Evidence       []Evidence         `bson:"evidence" json:"evidence"`                           // Supporting evidence
	Severity       string             `bson:"severity" json:"severity"`                           // low, medium, high, critical
	Status         string             `bson:"status" json:"status"`                               // pending, under_review, resolved, dismissed
	Priority       int                `bson:"priority" json:"priority"`                           // 1-5 priority level
	IPAddress      string             `bson:"ip_address" json:"ip_address"`                       // Reporter's IP
	UserAgent      string             `bson:"user_agent" json:"user_agent"`                       // Reporter's user agent
	AdminNotes     string             `bson:"admin_notes" json:"admin_notes"`                     // Admin review notes
	Resolution     string             `bson:"resolution" json:"resolution"`                       // Resolution taken
	ReviewedBy     string             `bson:"reviewed_by,omitempty" json:"reviewed_by,omitempty"` // Admin who reviewed
	ReviewedAt     *time.Time         `bson:"reviewed_at,omitempty" json:"reviewed_at,omitempty"` // Review timestamp
	CreatedAt      time.Time          `bson:"created_at" json:"created_at"`
	UpdatedAt      time.Time          `bson:"updated_at" json:"updated_at"`
}

// Evidence represents supporting evidence for a report
type Evidence struct {
	ID          primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Type        string             `bson:"type" json:"type"`                                 // screenshot, video, audio, text, url, message
	URL         string             `bson:"url,omitempty" json:"url,omitempty"`               // File URL for media evidence
	Content     string             `bson:"content,omitempty" json:"content,omitempty"`       // Text content or message
	MessageID   string             `bson:"message_id,omitempty" json:"message_id,omitempty"` // Reference to specific message
	Description string             `bson:"description" json:"description"`                   // Description of evidence
	FileSize    int64              `bson:"file_size,omitempty" json:"file_size,omitempty"`   // File size in bytes
	MimeType    string             `bson:"mime_type,omitempty" json:"mime_type,omitempty"`   // MIME type for files
	Metadata    EvidenceMetadata   `bson:"metadata" json:"metadata"`                         // Additional metadata
	CreatedAt   time.Time          `bson:"created_at" json:"created_at"`
}

// EvidenceMetadata represents metadata for evidence files
type EvidenceMetadata struct {
	Filename   string                 `bson:"filename,omitempty" json:"filename,omitempty"`
	Duration   int64                  `bson:"duration,omitempty" json:"duration,omitempty"`     // For audio/video (seconds)
	Dimensions ImageDimensions        `bson:"dimensions,omitempty" json:"dimensions,omitempty"` // For images/videos
	Hash       string                 `bson:"hash,omitempty" json:"hash,omitempty"`             // File hash for verification
	Tags       []string               `bson:"tags,omitempty" json:"tags,omitempty"`             // Classification tags
	Location   *GeoLocation           `bson:"location,omitempty" json:"location,omitempty"`     // GPS coordinates if available
	Custom     map[string]interface{} `bson:"custom,omitempty" json:"custom,omitempty"`         // Custom metadata fields
}

// ImageDimensions represents image or video dimensions
type ImageDimensions struct {
	Width  int `bson:"width" json:"width"`
	Height int `bson:"height" json:"height"`
}

// GeoLocation represents geographical coordinates
type GeoLocation struct {
	Latitude  float64 `bson:"latitude" json:"latitude"`
	Longitude float64 `bson:"longitude" json:"longitude"`
	Accuracy  float64 `bson:"accuracy,omitempty" json:"accuracy,omitempty"` // Accuracy in meters
}

// Feedback represents user feedback about the application
type Feedback struct {
	ID          primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	UserID      string             `bson:"user_id" json:"user_id"`
	Type        string             `bson:"type" json:"type"`                                   // bug, feature, improvement, complaint, compliment, question
	Category    string             `bson:"category" json:"category"`                           // ui, performance, feature, security, etc.
	Subject     string             `bson:"subject" json:"subject"`                             // Brief title/subject
	Description string             `bson:"description" json:"description"`                     // Detailed description
	Rating      int                `bson:"rating" json:"rating"`                               // 1-5 star rating
	Priority    string             `bson:"priority" json:"priority"`                           // low, normal, high, urgent
	Status      string             `bson:"status" json:"status"`                               // new, acknowledged, in_progress, resolved, closed
	Screenshots []string           `bson:"screenshots" json:"screenshots"`                     // Screenshot URLs
	UserAgent   string             `bson:"user_agent" json:"user_agent"`                       // User's browser/device info
	IPAddress   string             `bson:"ip_address" json:"ip_address"`                       // User's IP address
	URL         string             `bson:"url" json:"url"`                                     // Page URL where feedback was submitted
	DeviceInfo  DeviceInfo         `bson:"device_info" json:"device_info"`                     // Device and browser information
	AdminNotes  string             `bson:"admin_notes" json:"admin_notes"`                     // Admin notes and responses
	Resolution  string             `bson:"resolution" json:"resolution"`                       // Resolution provided
	AssignedTo  string             `bson:"assigned_to,omitempty" json:"assigned_to,omitempty"` // Admin assigned to handle
	ResolvedBy  string             `bson:"resolved_by,omitempty" json:"resolved_by,omitempty"` // Admin who resolved
	ResolvedAt  *time.Time         `bson:"resolved_at,omitempty" json:"resolved_at,omitempty"` // Resolution timestamp
	CreatedAt   time.Time          `bson:"created_at" json:"created_at"`
	UpdatedAt   time.Time          `bson:"updated_at" json:"updated_at"`
}

// DeviceInfo represents device and browser information
type DeviceInfo struct {
	OS          string `bson:"os" json:"os"`                     // Operating system
	Browser     string `bson:"browser" json:"browser"`           // Browser name and version
	Device      string `bson:"device" json:"device"`             // Device type (desktop, mobile, tablet)
	ScreenSize  string `bson:"screen_size" json:"screen_size"`   // Screen resolution
	Language    string `bson:"language" json:"language"`         // Browser language
	Timezone    string `bson:"timezone" json:"timezone"`         // User timezone
	IsIncognito bool   `bson:"is_incognito" json:"is_incognito"` // Private/incognito mode
}

// ReportStats represents report statistics for admin dashboard
type ReportStats struct {
	TotalReports     int64             `json:"total_reports"`
	PendingReports   int64             `json:"pending_reports"`
	ResolvedReports  int64             `json:"resolved_reports"`
	DismissedReports int64             `json:"dismissed_reports"`
	CriticalReports  int64             `json:"critical_reports"`
	ByCategory       map[string]int64  `json:"by_category"`
	BySeverity       map[string]int64  `json:"by_severity"`
	ByStatus         map[string]int64  `json:"by_status"`
	TrendData        []ReportTrendData `json:"trend_data"`
	TopReporters     []UserReportCount `json:"top_reporters"`
	TopReported      []UserReportCount `json:"top_reported"`
}

// ReportTrendData represents report trends over time
type ReportTrendData struct {
	Date  time.Time `json:"date"`
	Count int64     `json:"count"`
}

// UserReportCount represents user report counts
type UserReportCount struct {
	UserID string `json:"user_id"`
	Count  int64  `json:"count"`
}

// FeedbackStats represents feedback statistics
type FeedbackStats struct {
	TotalFeedback      int64            `json:"total_feedback"`
	NewFeedback        int64            `json:"new_feedback"`
	ResolvedFeedback   int64            `json:"resolved_feedback"`
	AverageRating      float64          `json:"average_rating"`
	ByType             map[string]int64 `json:"by_type"`
	ByCategory         map[string]int64 `json:"by_category"`
	ByPriority         map[string]int64 `json:"by_priority"`
	RatingDistribution map[int]int64    `json:"rating_distribution"`
}

// ModerationAction represents an action taken by moderators
type ModerationAction struct {
	ID          primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	ReportID    primitive.ObjectID `bson:"report_id" json:"report_id"`
	ActionType  string             `bson:"action_type" json:"action_type"`                     // warn, suspend, ban, dismiss, escalate
	Duration    *time.Duration     `bson:"duration,omitempty" json:"duration,omitempty"`       // For temporary actions
	Reason      string             `bson:"reason" json:"reason"`                               // Reason for action
	Notes       string             `bson:"notes" json:"notes"`                                 // Additional notes
	PerformedBy string             `bson:"performed_by" json:"performed_by"`                   // Admin who performed action
	TargetUser  string             `bson:"target_user" json:"target_user"`                     // User who received the action
	IPBan       bool               `bson:"ip_ban" json:"ip_ban"`                               // Whether IP was also banned
	Reversed    bool               `bson:"reversed" json:"reversed"`                           // Whether action was reversed
	ReversedBy  string             `bson:"reversed_by,omitempty" json:"reversed_by,omitempty"` // Who reversed the action
	ReversedAt  *time.Time         `bson:"reversed_at,omitempty" json:"reversed_at,omitempty"` // When action was reversed
	CreatedAt   time.Time          `bson:"created_at" json:"created_at"`
}

// AutoModerationRule represents automated moderation rules
type AutoModerationRule struct {
	ID          primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Name        string             `bson:"name" json:"name"`
	Description string             `bson:"description" json:"description"`
	Enabled     bool               `bson:"enabled" json:"enabled"`
	Conditions  []RuleCondition    `bson:"conditions" json:"conditions"` // Conditions that trigger the rule
	Actions     []RuleAction       `bson:"actions" json:"actions"`       // Actions to take when triggered
	Severity    string             `bson:"severity" json:"severity"`     // Rule severity level
	CreatedBy   string             `bson:"created_by" json:"created_by"`
	CreatedAt   time.Time          `bson:"created_at" json:"created_at"`
	UpdatedAt   time.Time          `bson:"updated_at" json:"updated_at"`
}

// RuleCondition represents a condition for auto-moderation
type RuleCondition struct {
	Field         string      `bson:"field" json:"field"`                   // Field to check (e.g., "message_content", "report_count")
	Operator      string      `bson:"operator" json:"operator"`             // Comparison operator (e.g., "contains", "equals", "greater_than")
	Value         interface{} `bson:"value" json:"value"`                   // Value to compare against
	CaseSensitive bool        `bson:"case_sensitive" json:"case_sensitive"` // For string comparisons
}

// RuleAction represents an action for auto-moderation
type RuleAction struct {
	Type        string                 `bson:"type" json:"type"`                             // Action type (e.g., "flag", "hide", "ban")
	Duration    *time.Duration         `bson:"duration,omitempty" json:"duration,omitempty"` // For temporary actions
	Parameters  map[string]interface{} `bson:"parameters" json:"parameters"`                 // Additional action parameters
	NotifyAdmin bool                   `bson:"notify_admin" json:"notify_admin"`             // Whether to notify administrators
}

// ReportTemplate represents pre-defined report templates
type ReportTemplate struct {
	ID          primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Name        string             `bson:"name" json:"name"`
	Category    string             `bson:"category" json:"category"`
	Reason      string             `bson:"reason" json:"reason"`
	Description string             `bson:"description" json:"description"`
	Severity    string             `bson:"severity" json:"severity"`
	IsActive    bool               `bson:"is_active" json:"is_active"`
	UsageCount  int64              `bson:"usage_count" json:"usage_count"`
	CreatedBy   string             `bson:"created_by" json:"created_by"`
	CreatedAt   time.Time          `bson:"created_at" json:"created_at"`
	UpdatedAt   time.Time          `bson:"updated_at" json:"updated_at"`
}

// Predefined constants for report categories and types
const (
	// Report Categories
	ReportCategoryHarassment    = "harassment"
	ReportCategorySpam          = "spam"
	ReportCategoryInappropriate = "inappropriate_content"
	ReportCategoryFakeProfile   = "fake_profile"
	ReportCategoryThreats       = "threats"
	ReportCategoryHateSpeech    = "hate_speech"
	ReportCategoryUnderage      = "underage"
	ReportCategoryScam          = "scam"
	ReportCategoryViolence      = "violence"
	ReportCategoryOther         = "other"

	// Report Severities
	ReportSeverityLow      = "low"
	ReportSeverityMedium   = "medium"
	ReportSeverityHigh     = "high"
	ReportSeverityCritical = "critical"

	// Report Statuses
	ReportStatusPending     = "pending"
	ReportStatusUnderReview = "under_review"
	ReportStatusResolved    = "resolved"
	ReportStatusDismissed   = "dismissed"
	ReportStatusEscalated   = "escalated"

	// Evidence Types
	EvidenceTypeScreenshot = "screenshot"
	EvidenceTypeVideo      = "video"
	EvidenceTypeAudio      = "audio"
	EvidenceTypeText       = "text"
	EvidenceTypeURL        = "url"
	EvidenceTypeMessage    = "message"

	// Feedback Types
	FeedbackTypeBug         = "bug"
	FeedbackTypeFeature     = "feature"
	FeedbackTypeImprovement = "improvement"
	FeedbackTypeComplaint   = "complaint"
	FeedbackTypeCompliment  = "compliment"
	FeedbackTypeQuestion    = "question"

	// Feedback Priorities
	FeedbackPriorityLow    = "low"
	FeedbackPriorityNormal = "normal"
	FeedbackPriorityHigh   = "high"
	FeedbackPriorityUrgent = "urgent"

	// Feedback Statuses
	FeedbackStatusNew          = "new"
	FeedbackStatusAcknowledged = "acknowledged"
	FeedbackStatusInProgress   = "in_progress"
	FeedbackStatusResolved     = "resolved"
	FeedbackStatusClosed       = "closed"

	// Moderation Actions
	ModerationActionWarn     = "warn"
	ModerationActionSuspend  = "suspend"
	ModerationActionBan      = "ban"
	ModerationActionDismiss  = "dismiss"
	ModerationActionEscalate = "escalate"
	ModerationActionFlag     = "flag"
	ModerationActionHide     = "hide"
)

// Helper functions for validation

// IsValidReportCategory checks if a report category is valid
func IsValidReportCategory(category string) bool {
	validCategories := map[string]bool{
		ReportCategoryHarassment:    true,
		ReportCategorySpam:          true,
		ReportCategoryInappropriate: true,
		ReportCategoryFakeProfile:   true,
		ReportCategoryThreats:       true,
		ReportCategoryHateSpeech:    true,
		ReportCategoryUnderage:      true,
		ReportCategoryScam:          true,
		ReportCategoryViolence:      true,
		ReportCategoryOther:         true,
	}
	return validCategories[category]
}

// IsValidReportSeverity checks if a report severity is valid
func IsValidReportSeverity(severity string) bool {
	validSeverities := map[string]bool{
		ReportSeverityLow:      true,
		ReportSeverityMedium:   true,
		ReportSeverityHigh:     true,
		ReportSeverityCritical: true,
	}
	return validSeverities[severity]
}

// IsValidReportStatus checks if a report status is valid
func IsValidReportStatus(status string) bool {
	validStatuses := map[string]bool{
		ReportStatusPending:     true,
		ReportStatusUnderReview: true,
		ReportStatusResolved:    true,
		ReportStatusDismissed:   true,
		ReportStatusEscalated:   true,
	}
	return validStatuses[status]
}

// IsValidFeedbackType checks if a feedback type is valid
func IsValidFeedbackType(feedbackType string) bool {
	validTypes := map[string]bool{
		FeedbackTypeBug:         true,
		FeedbackTypeFeature:     true,
		FeedbackTypeImprovement: true,
		FeedbackTypeComplaint:   true,
		FeedbackTypeCompliment:  true,
		FeedbackTypeQuestion:    true,
	}
	return validTypes[feedbackType]
}

// IsValidFeedbackPriority checks if a feedback priority is valid
func IsValidFeedbackPriority(priority string) bool {
	validPriorities := map[string]bool{
		FeedbackPriorityLow:    true,
		FeedbackPriorityNormal: true,
		FeedbackPriorityHigh:   true,
		FeedbackPriorityUrgent: true,
	}
	return validPriorities[priority]
}

// GetReportPriority returns numeric priority based on severity
func GetReportPriority(severity string) int {
	switch severity {
	case ReportSeverityCritical:
		return 5
	case ReportSeverityHigh:
		return 4
	case ReportSeverityMedium:
		return 3
	case ReportSeverityLow:
		return 2
	default:
		return 1
	}
}

// GetSeverityFromPriority returns severity string from numeric priority
func GetSeverityFromPriority(priority int) string {
	switch priority {
	case 5:
		return ReportSeverityCritical
	case 4:
		return ReportSeverityHigh
	case 3:
		return ReportSeverityMedium
	case 2:
		return ReportSeverityLow
	default:
		return ReportSeverityLow
	}
}
