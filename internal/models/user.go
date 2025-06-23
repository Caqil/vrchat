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

type UserStats struct {
	TotalUsers  int64 `json:"total_users"`
	OnlineUsers int64 `json:"online_users"`
	BannedUsers int64 `json:"banned_users"`
	ActiveChats int64 `json:"active_chats"`
}
