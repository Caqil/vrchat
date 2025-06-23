package utils

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"regexp"
	"strings"
	"time"
	"unicode"
	"vrchat/pkg/database"

	"github.com/go-playground/validator/v10"
	"go.mongodb.org/mongo-driver/bson"
)

var validate *validator.Validate

func init() {
	validate = validator.New()

	// Register custom validators
	validate.RegisterValidation("username", validateUsername)
	validate.RegisterValidation("strong_password", validateStrongPassword)
	validate.RegisterValidation("language_code", validateLanguageCode)
	validate.RegisterValidation("region_code", validateRegionCode)
	validate.RegisterValidation("chat_type", validateChatType)
	validate.RegisterValidation("profanity", validateNoProfanity)
}

// ValidationError represents validation error details
type ValidationError struct {
	Field   string `json:"field"`
	Tag     string `json:"tag"`
	Value   string `json:"value"`
	Message string `json:"message"`
}

// ValidateStruct validates a struct and returns user-friendly error messages
func ValidateStruct(s interface{}) []ValidationError {
	var errors []ValidationError

	err := validate.Struct(s)
	if err != nil {
		for _, err := range err.(validator.ValidationErrors) {
			errors = append(errors, ValidationError{
				Field:   strings.ToLower(err.Field()),
				Tag:     err.Tag(),
				Value:   err.Param(),
				Message: getErrorMessage(err),
			})
		}
	}

	return errors
}

// ValidateEmail validates email format
func ValidateEmail(email string) bool {
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	return emailRegex.MatchString(email)
}

// ValidatePassword validates password strength
func ValidatePassword(password string) bool {
	return len(password) >= 8 &&
		containsUpper(password) &&
		containsLower(password) &&
		containsDigit(password) &&
		containsSpecial(password)
}

// ValidateUsername validates username format
func ValidateUsername(username string) bool {
	// Username: 3-20 characters, alphanumeric and underscore
	usernameRegex := regexp.MustCompile(`^[a-zA-Z0-9_]{3,20}$`)
	return usernameRegex.MatchString(username)
}

// ValidateInterests validates user interests
func ValidateInterests(interests []string) bool {
	if len(interests) > 10 {
		return false // Max 10 interests
	}

	for _, interest := range interests {
		if len(interest) < 2 || len(interest) > 30 {
			return false
		}
		if !regexp.MustCompile(`^[a-zA-Z0-9\s-]+$`).MatchString(interest) {
			return false
		}
	}

	return true
}

// ValidateLanguageCode validates language code format
func ValidateLanguageCode(languageCode string) bool {
	validLanguages := []string{
		"en", "es", "fr", "de", "it", "pt", "ru", "zh", "ja", "ko",
		"ar", "hi", "th", "vi", "id", "ms", "tr", "pl", "nl", "sv",
	}

	for _, lang := range validLanguages {
		if lang == languageCode {
			return true
		}
	}

	return false
}

// ValidateRegionCode validates region code
func ValidateRegionCode(regionCode string) bool {
	validRegions := []string{
		"us-east", "us-west", "eu-west", "ap-southeast", "ap-northeast",
	}

	for _, region := range validRegions {
		if region == regionCode {
			return true
		}
	}

	return false
}

// ValidateChatType validates chat type
func ValidateChatType(chatType string) bool {
	validTypes := []string{"text", "video", "audio"}

	for _, t := range validTypes {
		if t == chatType {
			return true
		}
	}

	return false
}

// ValidateIPAddress validates IP address format
func ValidateIPAddress(ip string) bool {
	ipRegex := regexp.MustCompile(`^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$`)
	return ipRegex.MatchString(ip)
}

// Custom validators for go-playground/validator

func validateUsername(fl validator.FieldLevel) bool {
	return ValidateUsername(fl.Field().String())
}

func validateStrongPassword(fl validator.FieldLevel) bool {
	return ValidatePassword(fl.Field().String())
}

func validateLanguageCode(fl validator.FieldLevel) bool {
	return ValidateLanguageCode(fl.Field().String())
}

func validateRegionCode(fl validator.FieldLevel) bool {
	return ValidateRegionCode(fl.Field().String())
}

func validateChatType(fl validator.FieldLevel) bool {
	return ValidateChatType(fl.Field().String())
}

func validateNoProfanity(fl validator.FieldLevel) bool {
	return !ContainsProfanity(fl.Field().String())
}

// Helper functions

func containsUpper(s string) bool {
	for _, r := range s {
		if unicode.IsUpper(r) {
			return true
		}
	}
	return false
}

func containsLower(s string) bool {
	for _, r := range s {
		if unicode.IsLower(r) {
			return true
		}
	}
	return false
}

func containsDigit(s string) bool {
	for _, r := range s {
		if unicode.IsDigit(r) {
			return true
		}
	}
	return false
}

func containsSpecial(s string) bool {
	specialChars := "!@#$%^&*()_+-=[]{}|;:,.<>?"
	for _, r := range s {
		if strings.ContainsRune(specialChars, r) {
			return true
		}
	}
	return false
}

// ContainsProfanity checks if text contains profanity
func ContainsProfanity(text string) bool {
	// Basic profanity filter - in production, use a comprehensive service
	profanityWords := []string{
		"badword1", "badword2", // Add actual profanity words
	}

	lowerText := strings.ToLower(text)
	for _, word := range profanityWords {
		if strings.Contains(lowerText, word) {
			return true
		}
	}

	return false
}

// getErrorMessage returns user-friendly error messages
func getErrorMessage(fe validator.FieldError) string {
	switch fe.Tag() {
	case "required":
		return "This field is required"
	case "email":
		return "Please enter a valid email address"
	case "min":
		return "This field must be at least " + fe.Param() + " characters long"
	case "max":
		return "This field must be no more than " + fe.Param() + " characters long"
	case "username":
		return "Username must be 3-20 characters long and contain only letters, numbers, and underscores"
	case "strong_password":
		return "Password must be at least 8 characters long and contain uppercase, lowercase, numbers, and special characters"
	case "language_code":
		return "Please select a valid language"
	case "region_code":
		return "Please select a valid region"
	case "chat_type":
		return "Chat type must be text, video, or audio"
	case "profanity":
		return "This content contains inappropriate language"
	default:
		return "This field is invalid"
	}
}

// GenerateSessionID generates a random session ID string.
func GenerateSessionID() string {
	bytes := make([]byte, 16)
	_, err := rand.Read(bytes)
	if err != nil {
		return ""
	}
	return hex.EncodeToString(bytes)
}

// IsUserBanned checks if user is banned
func IsUserBanned(userID string) bool {
	db := database.GetDB()
	collection := db.Collection("users")

	var user struct {
		IsBanned  bool       `bson:"is_banned"`
		BanExpiry *time.Time `bson:"ban_expiry"`
	}

	err := collection.FindOne(context.Background(), bson.M{"_id": userID}).Decode(&user)
	if err != nil {
		return false
	}

	if !user.IsBanned {
		return false
	}

	// Check if ban has expired
	if user.BanExpiry != nil && time.Now().After(*user.BanExpiry) {
		// Unban user automatically
		collection.UpdateOne(context.Background(),
			bson.M{"_id": userID},
			bson.M{"$set": bson.M{"is_banned": false, "ban_expiry": nil}})
		return false
	}

	return true
}

// UpdateUserLastSeen updates user's last seen timestamp
func UpdateUserLastSeen(userID string) {
	db := database.GetDB()
	collection := db.Collection("users")

	collection.UpdateOne(context.Background(),
		bson.M{"_id": userID},
		bson.M{"$set": bson.M{"last_seen": time.Now()}})
}

// IsAdminActive checks if admin account is active
func IsAdminActive(adminID string) bool {
	db := database.GetDB()
	collection := db.Collection("admins")

	var admin struct {
		IsActive bool `bson:"is_active"`
	}

	err := collection.FindOne(context.Background(), bson.M{"_id": adminID}).Decode(&admin)
	if err != nil {
		return false
	}

	return admin.IsActive
}

// LogAdminActivity logs admin activity
func LogAdminActivity(activity map[string]interface{}) {
	db := database.GetDB()
	collection := db.Collection("admin_activity_logs")

	collection.InsertOne(context.Background(), activity)
}

// GetCurrentTime returns current time
func GetCurrentTime() time.Time {
	return time.Now()
}
