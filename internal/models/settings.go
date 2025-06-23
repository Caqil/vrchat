package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type AppSettings struct {
	ID                    primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	AppName               string             `bson:"app_name" json:"app_name"`
	AppDescription        string             `bson:"app_description" json:"app_description"`
	MaxUsersPerRoom       int                `bson:"max_users_per_room" json:"max_users_per_room"`
	ChatTimeout           int                `bson:"chat_timeout" json:"chat_timeout"` // minutes
	EnableModeration      bool               `bson:"enable_moderation" json:"enable_moderation"`
	EnableProfanityFilter bool               `bson:"enable_profanity_filter" json:"enable_profanity_filter"`
	EnableAgeVerification bool               `bson:"enable_age_verification" json:"enable_age_verification"`
	MinimumAge            int                `bson:"minimum_age" json:"minimum_age"`
	MaintenanceMode       bool               `bson:"maintenance_mode" json:"maintenance_mode"`
	MaintenanceMessage    string             `bson:"maintenance_message" json:"maintenance_message"`
	BannedWords           []string           `bson:"banned_words" json:"banned_words"`
	BannedCountries       []string           `bson:"banned_countries" json:"banned_countries"`
	CreatedAt             time.Time          `bson:"created_at" json:"created_at"`
	UpdatedAt             time.Time          `bson:"updated_at" json:"updated_at"`
}
