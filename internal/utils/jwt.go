package utils

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"context"
	"vrchat/internal/config"
	"vrchat/pkg/database"

	"github.com/golang-jwt/jwt/v4"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

// UserClaims represents JWT claims for regular users
type UserClaims struct {
	UserID   string `json:"user_id"`
	Username string `json:"username,omitempty"`
	Role     string `json:"role"`
	jwt.StandardClaims
}

// AdminClaims represents JWT claims for admin users - ENHANCED
type AdminClaims struct {
	AdminID     string   `json:"admin_id"`
	Username    string   `json:"username"`
	Role        string   `json:"role"`
	Permissions []string `json:"permissions"`
	jwt.StandardClaims
}

// RefreshTokenClaims for refresh token
type RefreshTokenClaims struct {
	UserID    string `json:"user_id"`
	AdminID   string `json:"admin_id,omitempty"`
	TokenType string `json:"token_type"` // "user" or "admin"
	jwt.StandardClaims
}

// SessionToken represents a session token for guest users
type SessionToken struct {
	Token     string    `json:"token"`
	UserID    string    `json:"user_id"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	IsActive  bool      `json:"is_active"`
}

// TokenBlacklist represents blacklisted tokens
type TokenBlacklist struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

// JWT Configuration
var (
	tokenValidHours  = 8
	refreshValidDays = 30
)

// SetJWTConfig sets JWT configuration
func SetJWTConfig(tokenHours, refreshDays int) {
	tokenValidHours = tokenHours
	refreshValidDays = refreshDays
}

// GenerateUserJWT generates a JWT token for regular users
func GenerateUserJWT(userID, username, role string) (string, error) {
	cfg := config.Load()

	claims := UserClaims{
		UserID:   userID,
		Username: username,
		Role:     role,
		StandardClaims: jwt.StandardClaims{
			Issuer:    "omegle-backend",
			Subject:   userID,
			ExpiresAt: time.Now().Add(time.Hour * time.Duration(cfg.Security.JWT.ExpiryHour)).Unix(),
			NotBefore: time.Now().Unix(),
			IssuedAt:  time.Now().Unix(),
			Audience:  "omegle-app",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(cfg.Security.JWT.Secret))
}

// GenerateAdminJWT generates a JWT token for admin users - ENHANCED
func GenerateAdminJWT(adminID, username, role string, permissions []string) (string, error) {
	cfg := config.Load()

	claims := AdminClaims{
		AdminID:     adminID,
		Username:    username,
		Role:        role,
		Permissions: permissions,
		StandardClaims: jwt.StandardClaims{
			Issuer:    "omegle-backend-admin",
			Subject:   adminID,
			ExpiresAt: time.Now().Add(time.Hour * time.Duration(tokenValidHours)).Unix(),
			NotBefore: time.Now().Unix(),
			IssuedAt:  time.Now().Unix(),
			Audience:  "omegle-admin",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(cfg.Security.JWT.Secret + "_admin"))
}

// GenerateAdminRefreshToken generates a refresh token for admin - NEW
func GenerateAdminRefreshToken(adminID string) (string, error) {
	cfg := config.Load()

	claims := RefreshTokenClaims{
		AdminID:   adminID,
		TokenType: "admin",
		StandardClaims: jwt.StandardClaims{
			Issuer:    "omegle-backend-admin",
			Subject:   adminID,
			ExpiresAt: time.Now().Add(time.Hour * 24 * time.Duration(refreshValidDays)).Unix(),
			NotBefore: time.Now().Unix(),
			IssuedAt:  time.Now().Unix(),
			Audience:  "omegle-admin-refresh",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(cfg.Security.JWT.Secret + "_admin_refresh"))

	if err != nil {
		return "", err
	}

	// Store refresh token in database
	db := database.GetDatabase()
	collection := db.Collection("refresh_tokens")

	refreshToken := map[string]interface{}{
		"token":      tokenString,
		"admin_id":   adminID,
		"token_type": "admin",
		"created_at": time.Now(),
		"expires_at": time.Now().Add(time.Hour * 24 * time.Duration(refreshValidDays)),
		"is_active":  true,
	}

	_, err = collection.InsertOne(context.Background(), refreshToken)
	return tokenString, err
}

// ValidateUserJWT validates a user JWT token
func ValidateUserJWT(tokenString string) (*UserClaims, error) {
	cfg := config.Load()

	token, err := jwt.ParseWithClaims(tokenString, &UserClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(cfg.Security.JWT.Secret), nil
	})

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*UserClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return claims, nil
}

// ValidateAdminJWT validates an admin JWT token - ENHANCED
func ValidateAdminJWT(tokenString string) (*AdminClaims, error) {
	cfg := config.Load()

	token, err := jwt.ParseWithClaims(tokenString, &AdminClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(cfg.Security.JWT.Secret + "_admin"), nil
	})

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*AdminClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid admin token")
	}

	// Check if token is blacklisted
	if IsTokenBlacklisted(tokenString) {
		return nil, fmt.Errorf("token has been invalidated")
	}

	return claims, nil
}

// ValidateAdminRefreshToken validates an admin refresh token - NEW
func ValidateAdminRefreshToken(tokenString string) (string, error) {
	cfg := config.Load()

	token, err := jwt.ParseWithClaims(tokenString, &RefreshTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(cfg.Security.JWT.Secret + "_admin_refresh"), nil
	})

	if err != nil {
		return "", err
	}

	claims, ok := token.Claims.(*RefreshTokenClaims)
	if !ok || !token.Valid {
		return "", fmt.Errorf("invalid refresh token")
	}

	if claims.TokenType != "admin" {
		return "", fmt.Errorf("invalid token type")
	}

	// Verify token exists in database and is active
	db := database.GetDatabase()
	collection := db.Collection("refresh_tokens")

	var refreshToken map[string]interface{}
	err = collection.FindOne(context.Background(), bson.M{
		"token":      tokenString,
		"admin_id":   claims.AdminID,
		"token_type": "admin",
		"is_active":  true,
		"expires_at": bson.M{"$gt": time.Now()},
	}).Decode(&refreshToken)

	if err != nil {
		if err == mongo.ErrNoDocuments {
			return "", fmt.Errorf("refresh token not found or expired")
		}
		return "", err
	}

	return claims.AdminID, nil
}

// GenerateSessionToken generates a session token for guest users
func GenerateSessionToken(userID string) string {
	// Generate random token
	bytes := make([]byte, 32)
	rand.Read(bytes)
	token := hex.EncodeToString(bytes)

	// Store session token in database
	sessionToken := SessionToken{
		Token:     token,
		UserID:    userID,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour * 24), // 24 hours
		IsActive:  true,
	}

	// Store in MongoDB
	db := database.GetDatabase()
	collection := db.Collection("session_tokens")
	collection.InsertOne(context.Background(), sessionToken)

	return token
}

// ValidateSessionToken validates a session token
func ValidateSessionToken(token string) (string, error) {
	db := database.GetDatabase()
	collection := db.Collection("session_tokens")

	var sessionToken SessionToken
	err := collection.FindOne(context.Background(), bson.M{
		"token":      token,
		"is_active":  true,
		"expires_at": bson.M{"$gt": time.Now()},
	}).Decode(&sessionToken)

	if err != nil {
		if err == mongo.ErrNoDocuments {
			return "", fmt.Errorf("invalid session token")
		}
		return "", err
	}

	return sessionToken.UserID, nil
}

// GenerateRefreshToken generates a refresh token for regular users
func GenerateRefreshToken(userID string) (string, error) {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	token := hex.EncodeToString(bytes)

	// Store refresh token in database with longer expiry
	db := database.GetDatabase()
	collection := db.Collection("refresh_tokens")

	refreshToken := map[string]interface{}{
		"token":      token,
		"user_id":    userID,
		"token_type": "user",
		"created_at": time.Now(),
		"expires_at": time.Now().Add(time.Hour * 24 * 30), // 30 days
		"is_active":  true,
	}

	_, err := collection.InsertOne(context.Background(), refreshToken)
	return token, err
}

// ValidateRefreshToken validates a refresh token for regular users
func ValidateRefreshToken(token string) (string, error) {
	db := database.GetDatabase()
	collection := db.Collection("refresh_tokens")

	var refreshToken map[string]interface{}
	err := collection.FindOne(context.Background(), bson.M{
		"token":      token,
		"token_type": "user",
		"is_active":  true,
		"expires_at": bson.M{"$gt": time.Now()},
	}).Decode(&refreshToken)

	if err != nil {
		if err == mongo.ErrNoDocuments {
			return "", fmt.Errorf("invalid refresh token")
		}
		return "", err
	}

	userID, ok := refreshToken["user_id"].(string)
	if !ok {
		return "", fmt.Errorf("invalid user_id in refresh token")
	}

	return userID, nil
}

// InvalidateToken adds token to blacklist - ENHANCED
func InvalidateToken(tokenString string) error {
	// Get token expiration time
	expiration, err := GetTokenExpiration(tokenString)
	if err != nil {
		return err
	}

	// Add to blacklist
	db := database.GetDatabase()
	collection := db.Collection("token_blacklist")

	blacklistEntry := TokenBlacklist{
		Token:     tokenString,
		ExpiresAt: *expiration,
		CreatedAt: time.Now(),
	}

	_, err = collection.InsertOne(context.Background(), blacklistEntry)
	return err
}

// IsTokenBlacklisted checks if token is blacklisted - NEW
func IsTokenBlacklisted(tokenString string) bool {
	db := database.GetDatabase()
	collection := db.Collection("token_blacklist")

	var entry TokenBlacklist
	err := collection.FindOne(context.Background(), bson.M{
		"token":      tokenString,
		"expires_at": bson.M{"$gt": time.Now()},
	}).Decode(&entry)

	return err == nil
}

// GetTokenExpiration extracts expiration time from token - ENHANCED
func GetTokenExpiration(tokenString string) (*time.Time, error) {
	cfg := config.Load()

	// Try parsing as admin token first
	token, err := jwt.ParseWithClaims(tokenString, &AdminClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(cfg.Security.JWT.Secret + "_admin"), nil
	})

	if err == nil {
		if claims, ok := token.Claims.(*AdminClaims); ok {
			expTime := time.Unix(claims.ExpiresAt, 0)
			return &expTime, nil
		}
	}

	// Try parsing as user token
	token, err = jwt.ParseWithClaims(tokenString, &UserClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(cfg.Security.JWT.Secret), nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*UserClaims); ok {
		expTime := time.Unix(claims.ExpiresAt, 0)
		return &expTime, nil
	}

	return nil, errors.New("unable to extract expiration from token")
}

// RevokeRefreshToken revokes a refresh token - NEW
func RevokeRefreshToken(tokenString string) error {
	db := database.GetDatabase()
	collection := db.Collection("refresh_tokens")

	_, err := collection.UpdateOne(
		context.Background(),
		bson.M{"token": tokenString},
		bson.M{"$set": bson.M{"is_active": false}},
	)

	return err
}

// RevokeAllUserTokens revokes all tokens for a user - NEW
func RevokeAllUserTokens(userID string) error {
	db := database.GetDatabase()

	// Revoke refresh tokens
	refreshCollection := db.Collection("refresh_tokens")
	_, err := refreshCollection.UpdateMany(
		context.Background(),
		bson.M{"user_id": userID},
		bson.M{"$set": bson.M{"is_active": false}},
	)

	if err != nil {
		return err
	}

	// Revoke session tokens
	sessionCollection := db.Collection("session_tokens")
	_, err = sessionCollection.UpdateMany(
		context.Background(),
		bson.M{"user_id": userID},
		bson.M{"$set": bson.M{"is_active": false}},
	)

	return err
}

// RevokeAllAdminTokens revokes all tokens for an admin - NEW
func RevokeAllAdminTokens(adminID string) error {
	db := database.GetDatabase()
	collection := db.Collection("refresh_tokens")

	_, err := collection.UpdateMany(
		context.Background(),
		bson.M{"admin_id": adminID, "token_type": "admin"},
		bson.M{"$set": bson.M{"is_active": false}},
	)

	return err
}

// CleanupExpiredTokens removes expired tokens from database - NEW
func CleanupExpiredTokens() error {
	db := database.GetDatabase()
	ctx := context.Background()

	// Cleanup expired session tokens
	sessionCollection := db.Collection("session_tokens")
	_, err := sessionCollection.DeleteMany(ctx, bson.M{
		"expires_at": bson.M{"$lt": time.Now()},
	})
	if err != nil {
		return err
	}

	// Cleanup expired refresh tokens
	refreshCollection := db.Collection("refresh_tokens")
	_, err = refreshCollection.DeleteMany(ctx, bson.M{
		"expires_at": bson.M{"$lt": time.Now()},
	})
	if err != nil {
		return err
	}

	// Cleanup expired blacklisted tokens
	blacklistCollection := db.Collection("token_blacklist")
	_, err = blacklistCollection.DeleteMany(ctx, bson.M{
		"expires_at": bson.M{"$lt": time.Now()},
	})

	return err
}

// Admin Permission Constants - NEW
const (
	PermissionViewDashboard  = "view_dashboard"
	PermissionManageUsers    = "manage_users"
	PermissionMonitorChats   = "monitor_chats"
	PermissionManageReports  = "manage_reports"
	PermissionManageContent  = "manage_content"
	PermissionViewAnalytics  = "view_analytics"
	PermissionManageCOTURN   = "manage_coturn"
	PermissionManageSettings = "manage_settings"
	PermissionSystemAdmin    = "system_admin"
	PermissionSuperAdmin     = "super_admin"
)

// GetDefaultAdminPermissions returns default permissions for admin role - NEW
func GetDefaultAdminPermissions(role string) []string {
	switch role {
	case "super_admin":
		return []string{
			PermissionSuperAdmin,
			PermissionViewDashboard,
			PermissionManageUsers,
			PermissionMonitorChats,
			PermissionManageReports,
			PermissionManageContent,
			PermissionViewAnalytics,
			PermissionManageCOTURN,
			PermissionManageSettings,
			PermissionSystemAdmin,
		}
	case "admin":
		return []string{
			PermissionViewDashboard,
			PermissionManageUsers,
			PermissionMonitorChats,
			PermissionManageReports,
			PermissionManageContent,
			PermissionViewAnalytics,
		}
	case "moderator":
		return []string{
			PermissionViewDashboard,
			PermissionMonitorChats,
			PermissionManageReports,
			PermissionManageContent,
		}
	case "viewer":
		return []string{
			PermissionViewDashboard,
			PermissionViewAnalytics,
		}
	default:
		return []string{}
	}
}

// HasPermission checks if a list of permissions contains a specific permission - NEW
func HasPermission(permissions []string, permission string) bool {
	for _, perm := range permissions {
		if perm == permission || perm == PermissionSuperAdmin {
			return true
		}
	}
	return false
}
