package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Chat struct {
	ID        primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	RoomID    string             `bson:"room_id" json:"room_id"`
	User1ID   primitive.ObjectID `bson:"user1_id" json:"user1_id"`
	User2ID   primitive.ObjectID `bson:"user2_id" json:"user2_id"`
	Status    string             `bson:"status" json:"status"`       // waiting, active, ended
	ChatType  string             `bson:"chat_type" json:"chat_type"` // text, video, audio
	StartedAt time.Time          `bson:"started_at" json:"started_at"`
	EndedAt   *time.Time         `bson:"ended_at,omitempty" json:"ended_at,omitempty"`
	Duration  int64              `bson:"duration" json:"duration"` // in seconds
	Messages  []Message          `bson:"messages" json:"messages"`
	CreatedAt time.Time          `bson:"created_at" json:"created_at"`
}

type Message struct {
	ID        primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	UserID    primitive.ObjectID `bson:"user_id" json:"user_id"`
	Content   string             `bson:"content" json:"content"`
	Type      string             `bson:"type" json:"type"` // text, image, file, emoji
	Timestamp time.Time          `bson:"timestamp" json:"timestamp"`
	Flagged   bool               `bson:"flagged" json:"flagged"`
}
