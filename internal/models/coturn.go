package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type CoturnServer struct {
	ID           primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Name         string             `bson:"name" json:"name"`
	Region       string             `bson:"region" json:"region"`
	URL          string             `bson:"url" json:"url"`
	Username     string             `bson:"username" json:"username"`
	Password     string             `bson:"password" json:"password"`
	IsActive     bool               `bson:"is_active" json:"is_active"`
	Priority     int                `bson:"priority" json:"priority"`
	MaxUsers     int                `bson:"max_users" json:"max_users"`
	CurrentUsers int                `bson:"current_users" json:"current_users"`
	LastChecked  time.Time          `bson:"last_checked" json:"last_checked"`
	Status       string             `bson:"status" json:"status"` // online, offline, error
	CreatedAt    time.Time          `bson:"created_at" json:"created_at"`
	UpdatedAt    time.Time          `bson:"updated_at" json:"updated_at"`
}

type ICEServer struct {
	URLs       []string `json:"urls"`
	Username   string   `json:"username,omitempty"`
	Credential string   `json:"credential,omitempty"`
}
