package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type User struct {
	ID        primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	SessionID string             `bson:"session_id" json:"session_id"`
	IPAddress string             `bson:"ip_address" json:"ip_address"`
	UserAgent string             `bson:"user_agent" json:"user_agent"`
	Country   string             `bson:"country" json:"country"`
	Region    string             `bson:"region" json:"region"`
	City      string             `bson:"city" json:"city"`
	Language  string             `bson:"language" json:"language"`
	Interests []string           `bson:"interests" json:"interests"`
	IsOnline  bool               `bson:"is_online" json:"is_online"`
	LastSeen  time.Time          `bson:"last_seen" json:"last_seen"`
	CreatedAt time.Time          `bson:"created_at" json:"created_at"`
	UpdatedAt time.Time          `bson:"updated_at" json:"updated_at"`
	IsBanned  bool               `bson:"is_banned" json:"is_banned"`
	BanReason string             `bson:"ban_reason,omitempty" json:"ban_reason,omitempty"`
	BanExpiry *time.Time         `bson:"ban_expiry,omitempty" json:"ban_expiry,omitempty"`
}
type ExportUser struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	Username  string    `json:"username"`
	SessionID string    `json:"session_id"`
	UserType  string    `json:"user_type"` // "guest" or "registered"
	Region    string    `json:"region"`
	Language  string    `json:"language"`
	Country   string    `json:"country"`
	City      string    `json:"city"`
	IsOnline  bool      `json:"is_online"`
	IsBanned  bool      `json:"is_banned"`
	CreatedAt time.Time `json:"created_at"`
	LastSeen  time.Time `json:"last_seen"`
	Interests []string  `json:"interests"`
}

// RegisteredUser represents the structure of registered users
type RegisteredUser struct {
	ID         primitive.ObjectID `bson:"_id"`
	Email      string             `bson:"email"`
	Username   string             `bson:"username"`
	Language   string             `bson:"language"`
	Region     string             `bson:"region"`
	Interests  []string           `bson:"interests"`
	IsVerified bool               `bson:"is_verified"`
	IsActive   bool               `bson:"is_active"`
	IsBanned   bool               `bson:"is_banned"`
	LastLogin  *time.Time         `bson:"last_login"`
	CreatedAt  time.Time          `bson:"created_at"`
}
type UserStats struct {
	TotalUsers  int64 `json:"total_users"`
	OnlineUsers int64 `json:"online_users"`
	BannedUsers int64 `json:"banned_users"`
	ActiveChats int64 `json:"active_chats"`
}
