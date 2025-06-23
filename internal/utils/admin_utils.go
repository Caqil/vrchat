package utils

import (
	"context"
	"fmt"
	"strings"
	"time"

	"vrchat/pkg/database"
	"vrchat/pkg/logger"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// AdminActivity represents an admin activity log entry
type AdminActivity struct {
	ID        string                 `bson:"_id,omitempty" json:"id"`
	AdminID   string                 `bson:"admin_id" json:"admin_id"`
	Username  string                 `bson:"username" json:"username"`
	Action    string                 `bson:"action" json:"action"`
	Method    string                 `bson:"method" json:"method"`
	Path      string                 `bson:"path" json:"path"`
	Query     string                 `bson:"query,omitempty" json:"query,omitempty"`
	IP        string                 `bson:"ip" json:"ip"`
	UserAgent string                 `bson:"user_agent" json:"user_agent"`
	Details   map[string]interface{} `bson:"details,omitempty" json:"details,omitempty"`
	Timestamp time.Time              `bson:"timestamp" json:"timestamp"`
	Success   bool                   `bson:"success" json:"success"`
	ErrorMsg  string                 `bson:"error_msg,omitempty" json:"error_msg,omitempty"`
}

// RateLimitEntry represents rate limiting data
type RateLimitEntry struct {
	Key       string    `bson:"key" json:"key"`
	Count     int       `bson:"count" json:"count"`
	WindowEnd time.Time `bson:"window_end" json:"window_end"`
	CreatedAt time.Time `bson:"created_at" json:"created_at"`
}

// GetActionFromPath extracts action name from HTTP method and path
func GetActionFromPath(method, path string) string {
	method = strings.ToUpper(method)
	path = strings.ToLower(path)

	// Remove query parameters
	if idx := strings.Index(path, "?"); idx != -1 {
		path = path[:idx]
	}

	// Define action mappings
	actionMappings := map[string]string{
		"GET /admin/api/dashboard":               "view_dashboard",
		"GET /admin/api/users":                   "view_users",
		"POST /admin/api/users/.*/ban":           "ban_user",
		"DELETE /admin/api/users/.*/ban":         "unban_user",
		"DELETE /admin/api/users/":               "delete_user",
		"POST /admin/api/users/bulk-action":      "bulk_user_action",
		"GET /admin/api/chats":                   "view_chats",
		"DELETE /admin/api/chats/":               "delete_chat",
		"POST /admin/api/chats/.*/end":           "end_chat",
		"GET /admin/api/reports":                 "view_reports",
		"POST /admin/api/reports/.*/resolve":     "resolve_report",
		"POST /admin/api/reports/.*/dismiss":     "dismiss_report",
		"POST /admin/api/content/banned-words":   "add_banned_word",
		"DELETE /admin/api/content/banned-words": "remove_banned_word",
		"POST /admin/api/system/maintenance":     "maintenance_mode",
		"POST /admin/api/system/backup":          "create_backup",
		"POST /admin/api/system/cache/clear":     "clear_cache",
	}

	// Try to match specific patterns
	for pattern, action := range actionMappings {
		if matchesPattern(method+" "+path, pattern) {
			return action
		}
	}

	// Generic fallback
	if strings.Contains(path, "/users") {
		return method + "_users"
	} else if strings.Contains(path, "/chats") {
		return method + "_chats"
	} else if strings.Contains(path, "/reports") {
		return method + "_reports"
	} else if strings.Contains(path, "/system") {
		return method + "_system"
	}

	return method + "_" + strings.ReplaceAll(path, "/", "_")
}

// matchesPattern checks if a path matches a pattern (simple regex-like matching)
func matchesPattern(path, pattern string) bool {
	// Simple pattern matching - replace .* with actual path segments
	if strings.Contains(pattern, ".*") {
		parts := strings.Split(pattern, ".*")
		if len(parts) == 2 {
			return strings.HasPrefix(path, parts[0]) && strings.HasSuffix(path, parts[1])
		}
	}
	return path == pattern
}

// IsAdminRateLimited checks if admin user has exceeded rate limits
func IsAdminRateLimited(adminID, path string) bool {
	if adminID == "" {
		return false
	}

	// Get rate limit configuration
	limits := getAdminRateLimits(path)
	if limits.RequestsPerMinute == 0 {
		return false // No rate limiting configured
	}

	db := database.GetDatabase()
	collection := db.Collection("admin_rate_limits")

	key := fmt.Sprintf("admin:%s:%s", adminID, path)
	windowStart := time.Now().Truncate(time.Minute)

	// Check current rate limit entry
	var entry RateLimitEntry
	err := collection.FindOne(context.Background(), bson.M{
		"key":        key,
		"window_end": bson.M{"$gte": windowStart},
	}).Decode(&entry)

	if err == mongo.ErrNoDocuments {
		// Create new entry
		entry = RateLimitEntry{
			Key:       key,
			Count:     1,
			WindowEnd: windowStart.Add(time.Minute),
			CreatedAt: time.Now(),
		}
		collection.InsertOne(context.Background(), entry)
		return false
	}

	if err != nil {
		logger.Error("Failed to check admin rate limit: " + err.Error())
		return false
	}

	// Check if limit exceeded
	if entry.Count >= limits.RequestsPerMinute {
		return true
	}

	// Increment counter
	collection.UpdateOne(
		context.Background(),
		bson.M{"key": key},
		bson.M{"$inc": bson.M{"count": 1}},
	)

	return false
}

// AdminRateLimit configuration
type AdminRateLimit struct {
	RequestsPerMinute int
	BurstSize         int
}

// getAdminRateLimits returns rate limits for specific admin endpoints
func getAdminRateLimits(path string) AdminRateLimit {
	// Default limits
	defaultLimit := AdminRateLimit{
		RequestsPerMinute: 100,
		BurstSize:         20,
	}

	// Specific limits for sensitive endpoints
	sensitiveLimits := AdminRateLimit{
		RequestsPerMinute: 30,
		BurstSize:         10,
	}

	// Apply stricter limits to sensitive endpoints
	if strings.Contains(path, "/ban") ||
		strings.Contains(path, "/delete") ||
		strings.Contains(path, "/system") ||
		strings.Contains(path, "/bulk-action") {
		return sensitiveLimits
	}

	return defaultLimit
}


// CleanupAdminLogs removes old admin activity logs
func CleanupAdminLogs(retentionDays int) error {
	if retentionDays <= 0 {
		retentionDays = 90 // Default retention
	}

	db := database.GetDatabase()
	collection := db.Collection("admin_activity_logs")

	cutoffDate := time.Now().AddDate(0, 0, -retentionDays)

	result, err := collection.DeleteMany(context.Background(), bson.M{
		"timestamp": bson.M{"$lt": cutoffDate},
	})

	if err != nil {
		return err
	}

	logger.Info(fmt.Sprintf("Cleaned up %d old admin activity logs", result.DeletedCount))
	return nil
}

// GetAdminActivityLogs retrieves admin activity logs with pagination
func GetAdminActivityLogs(page, limit int, adminID string) ([]AdminActivity, int64, error) {
	db := database.GetDatabase()
	collection := db.Collection("admin_activity_logs")

	// Build filter
	filter := bson.M{}
	if adminID != "" {
		filter["admin_id"] = adminID
	}

	// Get total count
	total, err := collection.CountDocuments(context.Background(), filter)
	if err != nil {
		return nil, 0, err
	}

	// Calculate skip
	skip := (page - 1) * limit

	// Query with pagination
	cursor, err := collection.Find(
		context.Background(),
		filter,
		options.Find().
			SetSort(bson.M{"timestamp": -1}). // Most recent first
			SetSkip(int64(skip)).
			SetLimit(int64(limit)),
	)

	if err != nil {
		return nil, 0, err
	}
	defer cursor.Close(context.Background())

	var logs []AdminActivity
	if err = cursor.All(context.Background(), &logs); err != nil {
		return nil, 0, err
	}

	return logs, total, nil
}

// SecurityAlert represents a security alert
type SecurityAlert struct {
	ID          string                 `bson:"_id,omitempty" json:"id"`
	Type        string                 `bson:"type" json:"type"`
	Level       string                 `bson:"level" json:"level"` // info, warning, error, critical
	Title       string                 `bson:"title" json:"title"`
	Description string                 `bson:"description" json:"description"`
	Source      string                 `bson:"source" json:"source"`
	IP          string                 `bson:"ip,omitempty" json:"ip,omitempty"`
	UserID      string                 `bson:"user_id,omitempty" json:"user_id,omitempty"`
	AdminID     string                 `bson:"admin_id,omitempty" json:"admin_id,omitempty"`
	Details     map[string]interface{} `bson:"details,omitempty" json:"details,omitempty"`
	Resolved    bool                   `bson:"resolved" json:"resolved"`
	ResolvedBy  string                 `bson:"resolved_by,omitempty" json:"resolved_by,omitempty"`
	ResolvedAt  *time.Time             `bson:"resolved_at,omitempty" json:"resolved_at,omitempty"`
	CreatedAt   time.Time              `bson:"created_at" json:"created_at"`
}

// CreateSecurityAlert creates a new security alert
func CreateSecurityAlert(alertType, level, title, description, source, ip string, details map[string]interface{}) error {
	db := database.GetDatabase()
	collection := db.Collection("security_alerts")

	alert := SecurityAlert{
		Type:        alertType,
		Level:       level,
		Title:       title,
		Description: description,
		Source:      source,
		IP:          ip,
		Details:     details,
		Resolved:    false,
		CreatedAt:   time.Now(),
	}

	_, err := collection.InsertOne(context.Background(), alert)
	if err != nil {
		logger.Error("Failed to create security alert: " + err.Error())
		return err
	}

	// Log to system logger as well
	logger.LogSecurityEvent(alertType, "", ip, details)

	return nil
}

// GetUnresolvedSecurityAlerts retrieves unresolved security alerts
func GetUnresolvedSecurityAlerts(limit int) ([]SecurityAlert, error) {
	db := database.GetDatabase()
	collection := db.Collection("security_alerts")
	cursor, err := collection.Find(
		context.Background(),
		bson.M{"resolved": false},
		options.Find().SetSort(bson.M{"created_at": -1}).SetLimit(int64(limit)),
	)
	

	if err != nil {
		return nil, err
	}
	defer cursor.Close(context.Background())

	var alerts []SecurityAlert
	if err = cursor.All(context.Background(), &alerts); err != nil {
		return nil, err
	}

	return alerts, nil
}

// ResolveSecurityAlert marks a security alert as resolved
func ResolveSecurityAlert(alertID, resolvedBy string) error {
	db := database.GetDatabase()
	collection := db.Collection("security_alerts")

	now := time.Now()
	_, err := collection.UpdateOne(
		context.Background(),
		bson.M{"_id": alertID},
		bson.M{
			"$set": bson.M{
				"resolved":    true,
				"resolved_by": resolvedBy,
				"resolved_at": &now,
			},
		},
	)

	return err
}

// ValidateAdminPermissions checks if admin has required permissions
func ValidateAdminPermissions(adminPermissions []string, requiredPermissions ...string) bool {
	// Super admin has all permissions
	for _, perm := range adminPermissions {
		if perm == PermissionSuperAdmin || perm == "all" {
			return true
		}
	}

	// Check specific permissions
	for _, required := range requiredPermissions {
		hasPermission := false
		for _, perm := range adminPermissions {
			if perm == required {
				hasPermission = true
				break
			}
		}
		if !hasPermission {
			return false
		}
	}

	return true
}

// FormatAdminAction formats an admin action for logging
func FormatAdminAction(action, target string, details map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{
		"action":    action,
		"target":    target,
		"details":   details,
		"timestamp": GetCurrentTime(),
	}
}

// GetSystemHealthStatus returns basic system health information
func GetSystemHealthStatus() map[string]interface{} {
	health := map[string]interface{}{
		"timestamp": GetCurrentTime(),
		"status":    "healthy",
		"services":  map[string]string{},
	}

	// Check database connection
	db := database.GetDatabase()
	if err := db.Client().Ping(context.Background(), nil); err != nil {
		health["status"] = "unhealthy"
		health["services"].(map[string]string)["database"] = "error"
	} else {
		health["services"].(map[string]string)["database"] = "healthy"
	}

	// Add more health checks as needed
	return health
}
