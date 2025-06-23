package utils

import (
	"crypto/rand"
	"encoding/hex"
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

// AdminClaims represents JWT claims for admin users
type AdminClaims struct {
	AdminID     string   `json:"admin_id"`
	Username    string   `json:"username"`
	Role        string   `json:"role"`
	Permissions []string `json:"permissions"`
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
			ExpiresAt: time.Now().Add(time.Hour * time.Duration(cfg.JWT.ExpiryHour)).Unix(),
			NotBefore: time.Now().Unix(),
			IssuedAt:  time.Now().Unix(),
			Audience:  "omegle-app",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(cfg.JWT.Secret))
}

// GenerateAdminJWT generates a JWT token for admin users
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
			ExpiresAt: time.Now().Add(time.Hour * 8).Unix(),
			NotBefore: time.Now().Unix(),
			IssuedAt:  time.Now().Unix(),
			Audience:  "omegle-admin",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(cfg.JWT.Secret + "_admin"))
}

// ValidateUserJWT validates a user JWT token
func ValidateUserJWT(tokenString string) (*UserClaims, error) {
	cfg := config.Load()

	token, err := jwt.ParseWithClaims(tokenString, &UserClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(cfg.JWT.Secret), nil
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

// ValidateAdminJWT validates an admin JWT token
func ValidateAdminJWT(tokenString string) (*AdminClaims, error) {
	cfg := config.Load()

	token, err := jwt.ParseWithClaims(tokenString, &AdminClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(cfg.JWT.Secret + "_admin"), nil
	})

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*AdminClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return claims, nil
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
	db := database.GetDB()
	collection := db.Collection("session_tokens")
	collection.InsertOne(context.Background(), sessionToken)

	return token
}

// ValidateSessionToken validates a session token
func ValidateSessionToken(token string) (string, error) {
	db := database.GetDB()
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

// GenerateRefreshToken generates a refresh token
func GenerateRefreshToken(userID string) (string, error) {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	token := hex.EncodeToString(bytes)

	// Store refresh token in database with longer expiry
	db := database.GetDB()
	collection := db.Collection("refresh_tokens")

	refreshToken := map[string]interface{}{
		"token":      token,
		"user_id":    userID,
		"created_at": time.Now(),
		"expires_at": time.Now().Add(time.Hour * 24 * 30), // 30 days
		"is_active":  true,
	}

	_, err := collection.InsertOne(context.Background(), refreshToken)
	return token, err
}

// ValidateRefreshToken validates a refresh token
func ValidateRefreshToken(token string) (string, error) {
	db := database.GetDB()
	collection := db.Collection("refresh_tokens")

	var refreshToken map[string]interface{}
	err := collection.FindOne(context.Background(), bson.M{
		"token":      token,
		"is_active":  true,
		"expires_at": bson.M{"$gt": time.Now()},
	}).Decode(&refreshToken)

	if err != nil {
		if err == mongo.ErrNoDocuments {
			return "", fmt.Errorf("invalid refresh token")
		}
		return "", err
	}

	return refreshToken["user_id"].(string), nil
}

// InvalidateToken invalidates a token (logout)
func InvalidateToken(token string) error {
	db := database.GetDB()

	// Try to invalidate session token
	sessionCollection := db.Collection("session_tokens")
	sessionCollection.UpdateOne(context.Background(),
		bson.M{"token": token},
		bson.M{"$set": bson.M{"is_active": false}})

	// Try to invalidate refresh token
	refreshCollection := db.Collection("refresh_tokens")
	refreshCollection.UpdateOne(context.Background(),
		bson.M{"token": token},
		bson.M{"$set": bson.M{"is_active": false}})

	return nil
}

// CleanupExpiredTokens removes expired tokens from database
func CleanupExpiredTokens() error {
	db := database.GetDB()

	// Cleanup session tokens
	sessionCollection := db.Collection("session_tokens")
	sessionCollection.DeleteMany(context.Background(), bson.M{
		"expires_at": bson.M{"$lt": time.Now()},
	})

	// Cleanup refresh tokens
	refreshCollection := db.Collection("refresh_tokens")
	refreshCollection.DeleteMany(context.Background(), bson.M{
		"expires_at": bson.M{"$lt": time.Now()},
	})

	return nil
}
