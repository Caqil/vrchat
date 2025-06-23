// ==============================================
// pkg/database/mongodb.go
// ==============================================
package database

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"vrchat/internal/config"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
)

var (
	client   *mongo.Client
	database *mongo.Database
	once     sync.Once
)

// MongoConfig represents MongoDB configuration
type MongoConfig struct {
	URI                    string
	Database               string
	MaxPoolSize            uint64
	MinPoolSize            uint64
	MaxConnIdleTime        time.Duration
	ConnectTimeout         time.Duration
	ServerSelectionTimeout time.Duration
	HeartbeatInterval      time.Duration
}

// InitMongoDB initializes MongoDB connection
func InitMongoDB(cfg config.MongoConfig) error {
	var err error

	once.Do(func() {
		err = connectToMongoDB(cfg)
	})

	return err
}

// connectToMongoDB establishes connection to MongoDB
func connectToMongoDB(cfg config.MongoConfig) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// MongoDB client options
	clientOptions := options.Client().
		ApplyURI(cfg.URI).
		SetMaxPoolSize(100).                        // Max connections in pool
		SetMinPoolSize(5).                          // Min connections in pool
		SetMaxConnIdleTime(30 * time.Minute).       // Max idle time
		SetConnectTimeout(10 * time.Second).        // Connection timeout
		SetServerSelectionTimeout(5 * time.Second). // Server selection timeout
		SetHeartbeatInterval(10 * time.Second).     // Heartbeat interval
		SetRetryWrites(true).                       // Retry writes
		SetRetryReads(true)                         // Retry reads

	// Connect to MongoDB
	var err error
	client, err = mongo.Connect(ctx, clientOptions)
	if err != nil {
		return fmt.Errorf("failed to connect to MongoDB: %w", err)
	}

	// Ping the database to verify connection
	if err = client.Ping(ctx, readpref.Primary()); err != nil {
		return fmt.Errorf("failed to ping MongoDB: %w", err)
	}

	// Set the database
	database = client.Database(cfg.Database)

	log.Printf("✅ Connected to MongoDB database: %s", cfg.Database)

	// Create initial indexes
	go func() {
		if err := createIndexes(); err != nil {
			log.Printf("Warning: Failed to create indexes: %v", err)
		}
	}()

	// Start cleanup routine
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()

		for range ticker.C {
			if err := CleanupExpiredData(); err != nil {
				log.Printf("Cleanup error: %v", err)
			}
		}
	}()

	return nil
}

// GetDatabase returns the database instance
func GetDatabase() *mongo.Database {
	if database == nil {
		log.Fatal("Database not initialized. Call InitMongoDB first.")
	}
	return database
}

// GetClient returns the MongoDB client
func GetClient() *mongo.Client {
	if client == nil {
		log.Fatal("MongoDB client not initialized. Call InitMongoDB first.")
	}
	return client
}

// Disconnect closes MongoDB connection
func Disconnect() error {
	if client != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return client.Disconnect(ctx)
	}
	return nil
}

// Health check function
func HealthCheck() map[string]interface{} {
	if database == nil {
		return map[string]interface{}{
			"status": "disconnected",
			"error":  "database not initialized",
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Ping database
	if err := client.Ping(ctx, readpref.Primary()); err != nil {
		return map[string]interface{}{
			"status": "error",
			"error":  err.Error(),
		}
	}

	// Get connection stats
	stats := client.Database("admin").RunCommand(ctx, bson.D{{Key: "serverStatus", Value: 1}})
	var result bson.M
	stats.Decode(&result)

	connections := result["connections"].(bson.M)

	return map[string]interface{}{
		"status":                "connected",
		"database":              database.Name(),
		"current_connections":   connections["current"],
		"available_connections": connections["available"],
		"total_created":         connections["totalCreated"],
	}
}

// createIndexes creates necessary database indexes
func createIndexes() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	indexes := []struct {
		collection string
		indexes    []mongo.IndexModel
	}{
		{
			collection: "users",
			indexes: []mongo.IndexModel{
				{
					Keys:    bson.D{{Key: "session_id", Value: 1}},
					Options: options.Index().SetUnique(true).SetSparse(true),
				},
				{
					Keys: bson.D{{Key: "ip_address", Value: 1}},
				},
				{
					Keys: bson.D{{Key: "is_online", Value: 1}},
				},
				{
					Keys: bson.D{{Key: "region", Value: 1}},
				},
				{
					Keys: bson.D{{Key: "language", Value: 1}},
				},
				{
					Keys: bson.D{{Key: "interests", Value: 1}},
				},
				{
					Keys: bson.D{{Key: "created_at", Value: 1}},
				},
				{
					Keys: bson.D{{Key: "last_seen", Value: 1}},
				},
				{
					Keys: bson.D{{Key: "is_banned", Value: 1}},
				},
			},
		},
		{
			collection: "chats",
			indexes: []mongo.IndexModel{
				{
					Keys:    bson.D{{Key: "room_id", Value: 1}},
					Options: options.Index().SetUnique(true),
				},
				{
					Keys: bson.D{{Key: "user1_id", Value: 1}},
				},
				{
					Keys: bson.D{{Key: "user2_id", Value: 1}},
				},
				{
					Keys: bson.D{{Key: "status", Value: 1}},
				},
				{
					Keys: bson.D{{Key: "chat_type", Value: 1}},
				},
				{
					Keys: bson.D{{Key: "started_at", Value: 1}},
				},
				{
					Keys: bson.D{{Key: "ended_at", Value: 1}},
				},
				{
					Keys: bson.D{
						{Key: "user1_id", Value: 1},
						{Key: "user2_id", Value: 1},
					},
				},
			},
		},
		{
			collection: "session_tokens",
			indexes: []mongo.IndexModel{
				{
					Keys:    bson.D{{Key: "token", Value: 1}},
					Options: options.Index().SetUnique(true),
				},
				{
					Keys: bson.D{{Key: "user_id", Value: 1}},
				},
				{
					Keys: bson.D{{Key: "expires_at", Value: 1}},
				},
				{
					Keys: bson.D{{Key: "created_at", Value: 1}},
				},
			},
		},
		{
			collection: "refresh_tokens",
			indexes: []mongo.IndexModel{
				{
					Keys:    bson.D{{Key: "token", Value: 1}},
					Options: options.Index().SetUnique(true),
				},
				{
					Keys: bson.D{{Key: "user_id", Value: 1}},
				},
				{
					Keys: bson.D{{Key: "expires_at", Value: 1}},
				},
			},
		},
		{
			collection: "reports",
			indexes: []mongo.IndexModel{
				{
					Keys: bson.D{{Key: "reported_user_id", Value: 1}},
				},
				{
					Keys: bson.D{{Key: "reporter_id", Value: 1}},
				},
				{
					Keys: bson.D{{Key: "status", Value: 1}},
				},
				{
					Keys: bson.D{{Key: "category", Value: 1}},
				},
				{
					Keys: bson.D{{Key: "created_at", Value: 1}},
				},
			},
		},
		{
			collection: "bans",
			indexes: []mongo.IndexModel{
				{
					Keys: bson.D{{Key: "user_id", Value: 1}},
				},
				{
					Keys: bson.D{{Key: "ip_address", Value: 1}},
				},
				{
					Keys: bson.D{{Key: "ban_type", Value: 1}},
				},
				{
					Keys: bson.D{{Key: "is_active", Value: 1}},
				},
				{
					Keys: bson.D{{Key: "expires_at", Value: 1}},
				},
			},
		},
		{
			collection: "messages",
			indexes: []mongo.IndexModel{
				{
					Keys: bson.D{{Key: "chat_id", Value: 1}},
				},
				{
					Keys: bson.D{{Key: "sender_id", Value: 1}},
				},
				{
					Keys: bson.D{{Key: "timestamp", Value: 1}},
				},
				{
					Keys: bson.D{{Key: "message_type", Value: 1}},
				},
			},
		},
		{
			collection: "coturn_servers",
			indexes: []mongo.IndexModel{
				{
					Keys: bson.D{{Key: "region", Value: 1}},
				},
				{
					Keys: bson.D{{Key: "is_active", Value: 1}},
				},
				{
					Keys: bson.D{{Key: "priority", Value: 1}},
				},
			},
		},
		{
			collection: "admins",
			indexes: []mongo.IndexModel{
				{
					Keys:    bson.D{{Key: "username", Value: 1}},
					Options: options.Index().SetUnique(true),
				},
				{
					Keys:    bson.D{{Key: "email", Value: 1}},
					Options: options.Index().SetUnique(true),
				},
				{
					Keys: bson.D{{Key: "role", Value: 1}},
				},
				{
					Keys: bson.D{{Key: "is_active", Value: 1}},
				},
			},
		},
		{
			collection: "interests",
			indexes: []mongo.IndexModel{
				{
					Keys:    bson.D{{Key: "name", Value: 1}},
					Options: options.Index().SetUnique(true),
				},
				{
					Keys: bson.D{{Key: "is_active", Value: 1}},
				},
				{
					Keys: bson.D{{Key: "category", Value: 1}},
				},
			},
		},
		{
			collection: "regions",
			indexes: []mongo.IndexModel{
				{
					Keys:    bson.D{{Key: "code", Value: 1}},
					Options: options.Index().SetUnique(true),
				},
				{
					Keys: bson.D{{Key: "country", Value: 1}},
				},
				{
					Keys: bson.D{{Key: "is_active", Value: 1}},
				},
			},
		},
		{
			collection: "languages",
			indexes: []mongo.IndexModel{
				{
					Keys:    bson.D{{Key: "code", Value: 1}},
					Options: options.Index().SetUnique(true),
				},
				{
					Keys: bson.D{{Key: "is_active", Value: 1}},
				},
			},
		},
		{
			collection: "admin_activity_logs",
			indexes: []mongo.IndexModel{
				{
					Keys: bson.D{{Key: "admin_id", Value: 1}},
				},
				{
					Keys: bson.D{{Key: "action", Value: 1}},
				},
				{
					Keys: bson.D{{Key: "timestamp", Value: 1}},
				},
			},
		},
		{
			collection: "ip_cache",
			indexes: []mongo.IndexModel{
				{
					Keys:    bson.D{{Key: "ip_address", Value: 1}},
					Options: options.Index().SetUnique(true),
				},
				{
					Keys: bson.D{{Key: "created_at", Value: 1}},
				},
			},
		},
		{
			collection: "app_settings",
			indexes: []mongo.IndexModel{
				{
					Keys: bson.D{{Key: "updated_at", Value: 1}},
				},
			},
		},
	}

	// Create indexes for each collection
	for _, indexGroup := range indexes {
		collection := database.Collection(indexGroup.collection)

		if len(indexGroup.indexes) > 0 {
			_, err := collection.Indexes().CreateMany(ctx, indexGroup.indexes)
			if err != nil {
				log.Printf("Failed to create indexes for collection %s: %v", indexGroup.collection, err)
				continue
			}
			log.Printf("Created %d indexes for collection: %s", len(indexGroup.indexes), indexGroup.collection)
		}
	}

	return nil
}

// Transaction helper functions
type TransactionFunc func(ctx mongo.SessionContext) (interface{}, error)

// WithTransaction executes a function within a MongoDB transaction
func WithTransaction(fn TransactionFunc) (interface{}, error) {
	session, err := client.StartSession()
	if err != nil {
		return nil, err
	}
	defer session.EndSession(context.Background())

	return session.WithTransaction(context.Background(), fn)
}

// Collection helper functions

// GetCollection returns a collection with error handling
func GetCollection(name string) *mongo.Collection {
	if database == nil {
		log.Fatal("Database not initialized")
	}
	return database.Collection(name)
}

// EnsureCollection creates collection if it doesn't exist
func EnsureCollection(name string) error {
	if database == nil {
		return fmt.Errorf("database not initialized")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	collections, err := database.ListCollectionNames(ctx, bson.M{"name": name})
	if err != nil {
		return err
	}

	if len(collections) == 0 {
		return database.CreateCollection(ctx, name)
	}

	return nil
}

// CleanupExpiredData removes expired data from collections
func CleanupExpiredData() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Cleanup expired session tokens
	sessionTokens := database.Collection("session_tokens")
	_, err := sessionTokens.DeleteMany(ctx, bson.M{
		"expires_at": bson.M{"$lt": time.Now()},
	})
	if err != nil {
		log.Printf("Failed to cleanup session tokens: %v", err)
	}

	// Cleanup expired refresh tokens
	refreshTokens := database.Collection("refresh_tokens")
	_, err = refreshTokens.DeleteMany(ctx, bson.M{
		"expires_at": bson.M{"$lt": time.Now()},
	})
	if err != nil {
		log.Printf("Failed to cleanup refresh tokens: %v", err)
	}

	// Cleanup old IP cache entries (older than 7 days)
	ipCache := database.Collection("ip_cache")
	_, err = ipCache.DeleteMany(ctx, bson.M{
		"created_at": bson.M{"$lt": time.Now().Add(-7 * 24 * time.Hour)},
	})
	if err != nil {
		log.Printf("Failed to cleanup IP cache: %v", err)
	}

	// Cleanup old admin activity logs (older than 90 days)
	adminLogs := database.Collection("admin_activity_logs")
	_, err = adminLogs.DeleteMany(ctx, bson.M{
		"timestamp": bson.M{"$lt": time.Now().Add(-90 * 24 * time.Hour)},
	})
	if err != nil {
		log.Printf("Failed to cleanup admin logs: %v", err)
	}

	log.Println("Database cleanup completed successfully")
	return nil
}

// Backup creates a backup of specific collections
func BackupCollections(collections []string) error {
	// Implementation would depend on your backup strategy
	// This is a placeholder for backup functionality
	log.Printf("Backup requested for collections: %v", collections)
	return nil
}

// Migration functions

// MigrateData performs data migrations
func MigrateData() error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Example migration: Add default values to existing documents
	users := database.Collection("users")
	_, err := users.UpdateMany(ctx,
		bson.M{"is_online": bson.M{"$exists": false}},
		bson.M{"$set": bson.M{"is_online": false}},
	)
	if err != nil {
		log.Printf("Migration error: %v", err)
	}

	log.Println("Data migration completed")
	return nil
}
