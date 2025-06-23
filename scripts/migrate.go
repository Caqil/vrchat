package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

type Config struct {
	MongoURI      string
	DatabaseName  string
	AdminUsername string
	AdminPassword string
}

type CollectionSetup struct {
	Name     string
	Indexes  []mongo.IndexModel
	SeedData interface{}
}

func main() {
	log.Println("🚀 Starting Omegle Clone Database Migration...")

	// Load environment variables
	if err := godotenv.Load(); err != nil {
		log.Println("Warning: No .env file found, using environment variables")
	}

	config := loadConfig()

	// Connect to MongoDB
	client, database, err := connectMongoDB(config)
	if err != nil {
		log.Fatalf("❌ Failed to connect to MongoDB: %v", err)
	}
	defer client.Disconnect(context.Background())

	// Run migration steps
	if err := runMigration(database, config); err != nil {
		log.Fatalf("❌ Migration failed: %v", err)
	}

	log.Println("✅ Migration completed successfully!")
}

func loadConfig() Config {
	return Config{
		MongoURI:      getEnv("MONGODB_URI", "mongodb://localhost:27017"),
		DatabaseName:  getEnv("MONGODB_DATABASE", "omegle_app"),
		AdminUsername: getEnv("ADMIN_USERNAME", "admin"),
		AdminPassword: getEnv("ADMIN_PASSWORD", "admin123"),
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func connectMongoDB(config Config) (*mongo.Client, *mongo.Database, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	clientOptions := options.Client().
		ApplyURI(config.MongoURI).
		SetMaxPoolSize(100).
		SetMinPoolSize(5).
		SetMaxConnIdleTime(30 * time.Minute).
		SetConnectTimeout(10 * time.Second).
		SetServerSelectionTimeout(5 * time.Second).
		SetRetryWrites(true).
		SetRetryReads(true)

	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		return nil, nil, err
	}

	if err = client.Ping(ctx, nil); err != nil {
		return nil, nil, err
	}

	database := client.Database(config.DatabaseName)
	log.Printf("✅ Connected to MongoDB database: %s", config.DatabaseName)

	return client, database, nil
}

func runMigration(database *mongo.Database, config Config) error {
	collections := getCollectionSetups()

	// Step 1: Create collections and indexes
	log.Println("📋 Creating collections and indexes...")
	for _, collection := range collections {
		if err := createCollectionWithIndexes(database, collection); err != nil {
			return fmt.Errorf("failed to create collection %s: %w", collection.Name, err)
		}
	}

	// Step 2: Seed initial data
	log.Println("🌱 Seeding initial data...")
	if err := seedInitialData(database, config); err != nil {
		return fmt.Errorf("failed to seed initial data: %w", err)
	}

	// Step 3: Create admin user
	log.Println("👑 Creating admin user...")
	if err := createAdminUser(database, config); err != nil {
		return fmt.Errorf("failed to create admin user: %w", err)
	}

	// Step 4: Setup initial COTURN servers
	log.Println("🌐 Setting up COTURN servers...")
	if err := setupCOTURNServers(database); err != nil {
		return fmt.Errorf("failed to setup COTURN servers: %w", err)
	}

	// Step 5: Create application settings
	log.Println("⚙️  Creating application settings...")
	if err := createAppSettings(database); err != nil {
		return fmt.Errorf("failed to create app settings: %w", err)
	}

	// Step 6: Setup region and language data
	log.Println("🗺️  Setting up regions and languages...")
	if err := setupRegionsAndLanguages(database); err != nil {
		return fmt.Errorf("failed to setup regions and languages: %w", err)
	}

	// Step 7: Create interest categories
	log.Println("🎯 Setting up interest categories...")
	if err := setupInterestCategories(database); err != nil {
		return fmt.Errorf("failed to setup interest categories: %w", err)
	}

	return nil
}

func getCollectionSetups() []CollectionSetup {
	return []CollectionSetup{
		{
			Name: "users",
			Indexes: []mongo.IndexModel{
				{Keys: bson.D{{Key: "session_id", Value: 1}}, Options: options.Index().SetUnique(true).SetSparse(true)},
				{Keys: bson.D{{Key: "ip_address", Value: 1}}},
				{Keys: bson.D{{Key: "is_online", Value: 1}}},
				{Keys: bson.D{{Key: "region", Value: 1}}},
				{Keys: bson.D{{Key: "language", Value: 1}}},
				{Keys: bson.D{{Key: "interests", Value: 1}}},
				{Keys: bson.D{{Key: "created_at", Value: 1}}},
				{Keys: bson.D{{Key: "last_seen", Value: 1}}},
				{Keys: bson.D{{Key: "is_banned", Value: 1}}},
				{Keys: bson.D{{Key: "ban_expiry", Value: 1}}, Options: options.Index().SetExpireAfterSeconds(0).SetSparse(true)},
			},
		},
		{
			Name: "registered_users",
			Indexes: []mongo.IndexModel{
				{Keys: bson.D{{Key: "email", Value: 1}}, Options: options.Index().SetUnique(true)},
				{Keys: bson.D{{Key: "username", Value: 1}}, Options: options.Index().SetUnique(true)},
				{Keys: bson.D{{Key: "is_verified", Value: 1}}},
				{Keys: bson.D{{Key: "is_active", Value: 1}}},
				{Keys: bson.D{{Key: "is_banned", Value: 1}}},
				{Keys: bson.D{{Key: "region", Value: 1}}},
				{Keys: bson.D{{Key: "language", Value: 1}}},
				{Keys: bson.D{{Key: "interests", Value: 1}}},
				{Keys: bson.D{{Key: "created_at", Value: 1}}},
				{Keys: bson.D{{Key: "last_login", Value: 1}}},
			},
		},
		{
			Name: "chats",
			Indexes: []mongo.IndexModel{
				{Keys: bson.D{{Key: "room_id", Value: 1}}, Options: options.Index().SetUnique(true)},
				{Keys: bson.D{{Key: "user1_id", Value: 1}}},
				{Keys: bson.D{{Key: "user2_id", Value: 1}}},
				{Keys: bson.D{{Key: "status", Value: 1}}},
				{Keys: bson.D{{Key: "chat_type", Value: 1}}},
				{Keys: bson.D{{Key: "started_at", Value: 1}}},
				{Keys: bson.D{{Key: "ended_at", Value: 1}}},
				{Keys: bson.D{{Key: "region", Value: 1}}},
				{Keys: bson.D{{Key: "language", Value: 1}}},
				{Keys: bson.D{{Key: "interests", Value: 1}}},
				{Keys: bson.D{{Key: "user1_id", Value: 1}, {Key: "user2_id", Value: 1}}},
			},
		},
		{
			Name: "messages",
			Indexes: []mongo.IndexModel{
				{Keys: bson.D{{Key: "room_id", Value: 1}}},
				{Keys: bson.D{{Key: "user_id", Value: 1}}},
				{Keys: bson.D{{Key: "timestamp", Value: 1}}},
				{Keys: bson.D{{Key: "type", Value: 1}}},
				{Keys: bson.D{{Key: "flagged", Value: 1}}},
				{Keys: bson.D{{Key: "deleted", Value: 1}}},
				{Keys: bson.D{{Key: "room_id", Value: 1}, {Key: "timestamp", Value: 1}}},
			},
		},
		{
			Name: "session_tokens",
			Indexes: []mongo.IndexModel{
				{Keys: bson.D{{Key: "token", Value: 1}}, Options: options.Index().SetUnique(true)},
				{Keys: bson.D{{Key: "user_id", Value: 1}}},
				{Keys: bson.D{{Key: "expires_at", Value: 1}}, Options: options.Index().SetExpireAfterSeconds(0)},
				{Keys: bson.D{{Key: "is_active", Value: 1}}},
			},
		},
		{
			Name: "refresh_tokens",
			Indexes: []mongo.IndexModel{
				{Keys: bson.D{{Key: "token", Value: 1}}, Options: options.Index().SetUnique(true)},
				{Keys: bson.D{{Key: "user_id", Value: 1}}},
				{Keys: bson.D{{Key: "expires_at", Value: 1}}, Options: options.Index().SetExpireAfterSeconds(0)},
			},
		},
		{
			Name: "coturn_servers",
			Indexes: []mongo.IndexModel{
				{Keys: bson.D{{Key: "region", Value: 1}}},
				{Keys: bson.D{{Key: "is_active", Value: 1}}},
				{Keys: bson.D{{Key: "status", Value: 1}}},
				{Keys: bson.D{{Key: "priority", Value: 1}}},
				{Keys: bson.D{{Key: "current_users", Value: 1}}},
			},
		},
		{
			Name: "reports",
			Indexes: []mongo.IndexModel{
				{Keys: bson.D{{Key: "reporter_id", Value: 1}}},
				{Keys: bson.D{{Key: "reported_user_id", Value: 1}}},
				{Keys: bson.D{{Key: "chat_id", Value: 1}}},
				{Keys: bson.D{{Key: "room_id", Value: 1}}},
				{Keys: bson.D{{Key: "status", Value: 1}}},
				{Keys: bson.D{{Key: "severity", Value: 1}}},
				{Keys: bson.D{{Key: "category", Value: 1}}},
				{Keys: bson.D{{Key: "created_at", Value: 1}}},
				{Keys: bson.D{{Key: "resolved_at", Value: 1}}},
			},
		},
		{
			Name: "ip_cache",
			Indexes: []mongo.IndexModel{
				{Keys: bson.D{{Key: "ip", Value: 1}}, Options: options.Index().SetUnique(true)},
				{Keys: bson.D{{Key: "created_at", Value: 1}}, Options: options.Index().SetExpireAfterSeconds(86400)}, // 24 hours TTL
			},
		},
		{
			Name: "admin_activity_logs",
			Indexes: []mongo.IndexModel{
				{Keys: bson.D{{Key: "admin_id", Value: 1}}},
				{Keys: bson.D{{Key: "timestamp", Value: 1}}},
				{Keys: bson.D{{Key: "action", Value: 1}}},
				{Keys: bson.D{{Key: "method", Value: 1}}},
				{Keys: bson.D{{Key: "path", Value: 1}}},
			},
		},
		{
			Name: "app_settings",
			Indexes: []mongo.IndexModel{
				{Keys: bson.D{{Key: "updated_at", Value: 1}}},
				{Keys: bson.D{{Key: "setting_key", Value: 1}}, Options: options.Index().SetUnique(true).SetSparse(true)},
			},
		},
		{
			Name: "user_settings",
			Indexes: []mongo.IndexModel{
				{Keys: bson.D{{Key: "user_id", Value: 1}}, Options: options.Index().SetUnique(true)},
				{Keys: bson.D{{Key: "updated_at", Value: 1}}},
			},
		},
		{
			Name: "blocked_users",
			Indexes: []mongo.IndexModel{
				{Keys: bson.D{{Key: "user_id", Value: 1}}},
				{Keys: bson.D{{Key: "blocked_user_id", Value: 1}}},
				{Keys: bson.D{{Key: "blocked_at", Value: 1}}},
				{Keys: bson.D{{Key: "expires_at", Value: 1}}, Options: options.Index().SetExpireAfterSeconds(0).SetSparse(true)},
				{Keys: bson.D{{Key: "user_id", Value: 1}, {Key: "blocked_user_id", Value: 1}}, Options: options.Index().SetUnique(true)},
			},
		},
		{
			Name: "analytics_events",
			Indexes: []mongo.IndexModel{
				{Keys: bson.D{{Key: "event_type", Value: 1}}},
				{Keys: bson.D{{Key: "user_id", Value: 1}}},
				{Keys: bson.D{{Key: "timestamp", Value: 1}}},
				{Keys: bson.D{{Key: "region", Value: 1}}},
				{Keys: bson.D{{Key: "event_type", Value: 1}, {Key: "timestamp", Value: 1}}},
			},
		},
		{
			Name: "match_queue",
			Indexes: []mongo.IndexModel{
				{Keys: bson.D{{Key: "user_id", Value: 1}}, Options: options.Index().SetUnique(true)},
				{Keys: bson.D{{Key: "chat_type", Value: 1}}},
				{Keys: bson.D{{Key: "region", Value: 1}}},
				{Keys: bson.D{{Key: "language", Value: 1}}},
				{Keys: bson.D{{Key: "interests", Value: 1}}},
				{Keys: bson.D{{Key: "created_at", Value: 1}}},
				{Keys: bson.D{{Key: "status", Value: 1}}},
			},
		},
		{
			Name: "regions",
			Indexes: []mongo.IndexModel{
				{Keys: bson.D{{Key: "code", Value: 1}}, Options: options.Index().SetUnique(true)},
				{Keys: bson.D{{Key: "is_active", Value: 1}}},
			},
		},
		{
			Name: "languages",
			Indexes: []mongo.IndexModel{
				{Keys: bson.D{{Key: "code", Value: 1}}, Options: options.Index().SetUnique(true)},
				{Keys: bson.D{{Key: "is_active", Value: 1}}},
			},
		},
		{
			Name: "interest_categories",
			Indexes: []mongo.IndexModel{
				{Keys: bson.D{{Key: "name", Value: 1}}, Options: options.Index().SetUnique(true)},
				{Keys: bson.D{{Key: "is_active", Value: 1}}},
				{Keys: bson.D{{Key: "category", Value: 1}}},
			},
		},
		{
			Name: "banned_content",
			Indexes: []mongo.IndexModel{
				{Keys: bson.D{{Key: "type", Value: 1}}},
				{Keys: bson.D{{Key: "content", Value: 1}}},
				{Keys: bson.D{{Key: "is_active", Value: 1}}},
			},
		},
		{
			Name: "moderation_queue",
			Indexes: []mongo.IndexModel{
				{Keys: bson.D{{Key: "status", Value: 1}}},
				{Keys: bson.D{{Key: "priority", Value: 1}}},
				{Keys: bson.D{{Key: "created_at", Value: 1}}},
				{Keys: bson.D{{Key: "assigned_to", Value: 1}}},
			},
		},
	}
}

func createCollectionWithIndexes(database *mongo.Database, setup CollectionSetup) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Check if collection exists
	collections, err := database.ListCollectionNames(ctx, bson.M{"name": setup.Name})
	if err != nil {
		return err
	}

	// Create collection if it doesn't exist
	if len(collections) == 0 {
		if err := database.CreateCollection(ctx, setup.Name); err != nil {
			return err
		}
		log.Printf("  📁 Created collection: %s", setup.Name)
	} else {
		log.Printf("  📁 Collection already exists: %s", setup.Name)
	}

	// Create indexes
	collection := database.Collection(setup.Name)
	if len(setup.Indexes) > 0 {
		_, err := collection.Indexes().CreateMany(ctx, setup.Indexes)
		if err != nil {
			log.Printf("  ⚠️  Warning: Failed to create indexes for %s: %v", setup.Name, err)
		} else {
			log.Printf("  📊 Created %d indexes for: %s", len(setup.Indexes), setup.Name)
		}
	}

	return nil
}

func seedInitialData(database *mongo.Database, config Config) error {
	// This function coordinates all the seeding
	// Individual seed functions are called from main migration flow
	return nil
}

func createAdminUser(database *mongo.Database, config Config) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	collection := database.Collection("admins")

	// Check if admin user already exists
	count, err := collection.CountDocuments(ctx, bson.M{"username": config.AdminUsername})
	if err != nil {
		return err
	}

	if count > 0 {
		log.Printf("  👑 Admin user already exists: %s", config.AdminUsername)
		return nil
	}

	// Hash admin password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(config.AdminPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	admin := bson.M{
		"username":    config.AdminUsername,
		"password":    string(hashedPassword),
		"email":       "admin@omegle-clone.com",
		"role":        "super_admin",
		"permissions": []string{"all"},
		"is_active":   true,
		"created_at":  time.Now(),
		"updated_at":  time.Now(),
	}

	_, err = collection.InsertOne(ctx, admin)
	if err != nil {
		return err
	}

	log.Printf("  ✅ Created admin user: %s", config.AdminUsername)
	return nil
}

func setupCOTURNServers(database *mongo.Database) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	collection := database.Collection("coturn_servers")

	// Check if servers already exist
	count, err := collection.CountDocuments(ctx, bson.M{})
	if err != nil {
		return err
	}

	if count > 0 {
		log.Printf("  🌐 COTURN servers already exist")
		return nil
	}

	servers := []bson.M{
		{
			"name":          "US East COTURN",
			"region":        "us-east-1",
			"url":           "turn:turn1.example.com:3478",
			"username":      "turn_user",
			"credential":    "turn_secret",
			"priority":      1,
			"max_users":     1000,
			"current_users": 0,
			"is_active":     true,
			"status":        "offline",
			"created_at":    time.Now(),
			"updated_at":    time.Now(),
			"last_checked":  time.Now(),
		},
		{
			"name":          "US West COTURN",
			"region":        "us-west-1",
			"url":           "turn:turn2.example.com:3478",
			"username":      "turn_user",
			"credential":    "turn_secret",
			"priority":      1,
			"max_users":     1000,
			"current_users": 0,
			"is_active":     true,
			"status":        "offline",
			"created_at":    time.Now(),
			"updated_at":    time.Now(),
			"last_checked":  time.Now(),
		},
		{
			"name":          "EU West COTURN",
			"region":        "eu-west-1",
			"url":           "turn:turn3.example.com:3478",
			"username":      "turn_user",
			"credential":    "turn_secret",
			"priority":      1,
			"max_users":     1000,
			"current_users": 0,
			"is_active":     true,
			"status":        "offline",
			"created_at":    time.Now(),
			"updated_at":    time.Now(),
			"last_checked":  time.Now(),
		},
		{
			"name":          "AP Southeast COTURN",
			"region":        "ap-southeast-1",
			"url":           "turn:turn4.example.com:3478",
			"username":      "turn_user",
			"credential":    "turn_secret",
			"priority":      1,
			"max_users":     1000,
			"current_users": 0,
			"is_active":     true,
			"status":        "offline",
			"created_at":    time.Now(),
			"updated_at":    time.Now(),
			"last_checked":  time.Now(),
		},
		{
			"name":          "AP Northeast COTURN",
			"region":        "ap-northeast-1",
			"url":           "turn:turn5.example.com:3478",
			"username":      "turn_user",
			"credential":    "turn_secret",
			"priority":      1,
			"max_users":     1000,
			"current_users": 0,
			"is_active":     true,
			"status":        "offline",
			"created_at":    time.Now(),
			"updated_at":    time.Now(),
			"last_checked":  time.Now(),
		},
	}

	// Convert []bson.M to []interface{}
	serverInterfaces := make([]interface{}, len(servers))
	for i, v := range servers {
		serverInterfaces[i] = v
	}
	_, err = collection.InsertMany(ctx, serverInterfaces)
	if err != nil {
		return err
	}

	log.Printf("  ✅ Created %d COTURN servers", len(servers))
	return nil
}

func createAppSettings(database *mongo.Database) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	collection := database.Collection("app_settings")

	// Check if settings already exist
	count, err := collection.CountDocuments(ctx, bson.M{})
	if err != nil {
		return err
	}

	if count > 0 {
		log.Printf("  ⚙️  App settings already exist")
		return nil
	}

	defaultSettings := bson.M{
		"app_name":                "Omegle Clone",
		"app_description":         "Random video chat application",
		"max_users_per_room":      2,
		"chat_timeout":            30, // 30 minutes
		"enable_moderation":       true,
		"enable_profanity_filter": true,
		"enable_age_verification": false,
		"minimum_age":             13,
		"maintenance_mode":        false,
		"maintenance_message":     "The system is currently under maintenance. Please try again later.",
		"banned_words":            []string{"spam", "scam", "phishing"},
		"banned_countries":        []string{},
		"max_file_size":           10485760, // 10MB
		"allowed_file_types":      []string{"image/jpeg", "image/png", "image/gif", "image/webp"},
		"rate_limit_messages":     50, // messages per minute
		"rate_limit_connections":  5,  // connections per minute
		"enable_screenshots":      false,
		"enable_file_sharing":     true,
		"enable_typing_indicator": true,
		"auto_moderate_threshold": 3, // reports before auto-moderation
		"created_at":              time.Now(),
		"updated_at":              time.Now(),
	}

	_, err = collection.InsertOne(ctx, defaultSettings)
	if err != nil {
		return err
	}

	log.Printf("  ✅ Created default app settings")
	return nil
}

func setupRegionsAndLanguages(database *mongo.Database) error {
	if err := setupRegions(database); err != nil {
		return err
	}
	return setupLanguages(database)
}

func setupRegions(database *mongo.Database) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	collection := database.Collection("regions")

	// Check if regions already exist
	count, err := collection.CountDocuments(ctx, bson.M{})
	if err != nil {
		return err
	}

	if count > 0 {
		log.Printf("  🗺️  Regions already exist")
		return nil
	}

	regions := []bson.M{
		{"code": "us-east-1", "name": "US East (Virginia)", "country": "US", "is_active": true, "created_at": time.Now()},
		{"code": "us-west-1", "name": "US West (California)", "country": "US", "is_active": true, "created_at": time.Now()},
		{"code": "eu-west-1", "name": "EU West (Ireland)", "country": "IE", "is_active": true, "created_at": time.Now()},
		{"code": "eu-central-1", "name": "EU Central (Germany)", "country": "DE", "is_active": true, "created_at": time.Now()},
		{"code": "ap-southeast-1", "name": "Asia Pacific (Singapore)", "country": "SG", "is_active": true, "created_at": time.Now()},
		{"code": "ap-northeast-1", "name": "Asia Pacific (Tokyo)", "country": "JP", "is_active": true, "created_at": time.Now()},
		{"code": "ap-south-1", "name": "Asia Pacific (Mumbai)", "country": "IN", "is_active": true, "created_at": time.Now()},
		{"code": "ca-central-1", "name": "Canada Central", "country": "CA", "is_active": true, "created_at": time.Now()},
		{"code": "sa-east-1", "name": "South America (São Paulo)", "country": "BR", "is_active": true, "created_at": time.Now()},
		{"code": "af-south-1", "name": "Africa (Cape Town)", "country": "ZA", "is_active": true, "created_at": time.Now()},
	}

	regionInterfaces := make([]interface{}, len(regions))
	for i, v := range regions {
		regionInterfaces[i] = v
	}
	_, err = collection.InsertMany(ctx, regionInterfaces)
	if err != nil {
		return err
	}

	log.Printf("  ✅ Created %d regions", len(regions))
	return nil
}

func setupLanguages(database *mongo.Database) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	collection := database.Collection("languages")

	// Check if languages already exist
	count, err := collection.CountDocuments(ctx, bson.M{})
	if err != nil {
		return err
	}

	if count > 0 {
		log.Printf("  🌐 Languages already exist")
		return nil
	}

	languages := []bson.M{
		{"code": "en", "name": "English", "native_name": "English", "is_active": true, "created_at": time.Now()},
		{"code": "es", "name": "Spanish", "native_name": "Español", "is_active": true, "created_at": time.Now()},
		{"code": "fr", "name": "French", "native_name": "Français", "is_active": true, "created_at": time.Now()},
		{"code": "de", "name": "German", "native_name": "Deutsch", "is_active": true, "created_at": time.Now()},
		{"code": "it", "name": "Italian", "native_name": "Italiano", "is_active": true, "created_at": time.Now()},
		{"code": "pt", "name": "Portuguese", "native_name": "Português", "is_active": true, "created_at": time.Now()},
		{"code": "ru", "name": "Russian", "native_name": "Русский", "is_active": true, "created_at": time.Now()},
		{"code": "ja", "name": "Japanese", "native_name": "日本語", "is_active": true, "created_at": time.Now()},
		{"code": "ko", "name": "Korean", "native_name": "한국어", "is_active": true, "created_at": time.Now()},
		{"code": "zh", "name": "Chinese", "native_name": "中文", "is_active": true, "created_at": time.Now()},
		{"code": "ar", "name": "Arabic", "native_name": "العربية", "is_active": true, "created_at": time.Now()},
		{"code": "hi", "name": "Hindi", "native_name": "हिन्दी", "is_active": true, "created_at": time.Now()},
		{"code": "tr", "name": "Turkish", "native_name": "Türkçe", "is_active": true, "created_at": time.Now()},
		{"code": "nl", "name": "Dutch", "native_name": "Nederlands", "is_active": true, "created_at": time.Now()},
		{"code": "sv", "name": "Swedish", "native_name": "Svenska", "is_active": true, "created_at": time.Now()},
	}

	languageInterfaces := make([]interface{}, len(languages))
	for i, v := range languages {
		languageInterfaces[i] = v
	}
	_, err = collection.InsertMany(ctx, languageInterfaces)
	if err != nil {
		return err
	}

	log.Printf("  ✅ Created %d languages", len(languages))
	return nil
}

func setupInterestCategories(database *mongo.Database) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	collection := database.Collection("interest_categories")

	// Check if interests already exist
	count, err := collection.CountDocuments(ctx, bson.M{})
	if err != nil {
		return err
	}

	if count > 0 {
		log.Printf("  🎯 Interest categories already exist")
		return nil
	}

	interests := []bson.M{
		// Technology
		{"name": "Programming", "category": "technology", "description": "Software development and coding", "is_active": true, "created_at": time.Now()},
		{"name": "Gaming", "category": "technology", "description": "Video games and gaming culture", "is_active": true, "created_at": time.Now()},
		{"name": "Tech News", "category": "technology", "description": "Latest technology trends and news", "is_active": true, "created_at": time.Now()},
		{"name": "Crypto", "category": "technology", "description": "Cryptocurrency and blockchain", "is_active": true, "created_at": time.Now()},
		{"name": "AI/ML", "category": "technology", "description": "Artificial Intelligence and Machine Learning", "is_active": true, "created_at": time.Now()},

		// Entertainment
		{"name": "Movies", "category": "entertainment", "description": "Films and cinema", "is_active": true, "created_at": time.Now()},
		{"name": "TV Shows", "category": "entertainment", "description": "Television series and shows", "is_active": true, "created_at": time.Now()},
		{"name": "Music", "category": "entertainment", "description": "Music and artists", "is_active": true, "created_at": time.Now()},
		{"name": "Anime", "category": "entertainment", "description": "Japanese animation", "is_active": true, "created_at": time.Now()},
		{"name": "Books", "category": "entertainment", "description": "Literature and reading", "is_active": true, "created_at": time.Now()},

		// Sports & Fitness
		{"name": "Football", "category": "sports", "description": "American football", "is_active": true, "created_at": time.Now()},
		{"name": "Soccer", "category": "sports", "description": "Association football", "is_active": true, "created_at": time.Now()},
		{"name": "Basketball", "category": "sports", "description": "Basketball sports", "is_active": true, "created_at": time.Now()},
		{"name": "Fitness", "category": "sports", "description": "Exercise and fitness", "is_active": true, "created_at": time.Now()},
		{"name": "Yoga", "category": "sports", "description": "Yoga and meditation", "is_active": true, "created_at": time.Now()},

		// Hobbies & Arts
		{"name": "Photography", "category": "hobbies", "description": "Photography and visual arts", "is_active": true, "created_at": time.Now()},
		{"name": "Cooking", "category": "hobbies", "description": "Culinary arts and recipes", "is_active": true, "created_at": time.Now()},
		{"name": "Travel", "category": "hobbies", "description": "Travel and exploration", "is_active": true, "created_at": time.Now()},
		{"name": "Art", "category": "hobbies", "description": "Visual and creative arts", "is_active": true, "created_at": time.Now()},
		{"name": "Music Production", "category": "hobbies", "description": "Creating and producing music", "is_active": true, "created_at": time.Now()},

		// Education & Learning
		{"name": "Science", "category": "education", "description": "Scientific discussions", "is_active": true, "created_at": time.Now()},
		{"name": "History", "category": "education", "description": "Historical topics", "is_active": true, "created_at": time.Now()},
		{"name": "Language Learning", "category": "education", "description": "Learning new languages", "is_active": true, "created_at": time.Now()},
		{"name": "Philosophy", "category": "education", "description": "Philosophical discussions", "is_active": true, "created_at": time.Now()},
		{"name": "Current Events", "category": "education", "description": "News and current affairs", "is_active": true, "created_at": time.Now()},

		// Lifestyle
		{"name": "Fashion", "category": "lifestyle", "description": "Fashion and style", "is_active": true, "created_at": time.Now()},
		{"name": "Health", "category": "lifestyle", "description": "Health and wellness", "is_active": true, "created_at": time.Now()},
		{"name": "Relationships", "category": "lifestyle", "description": "Dating and relationships", "is_active": true, "created_at": time.Now()},
		{"name": "Career", "category": "lifestyle", "description": "Career and professional development", "is_active": true, "created_at": time.Now()},
		{"name": "Mental Health", "category": "lifestyle", "description": "Mental health and wellbeing", "is_active": true, "created_at": time.Now()},
	}

	interestInterfaces := make([]interface{}, len(interests))
	for i, v := range interests {
		interestInterfaces[i] = v
	}
	_, err = collection.InsertMany(ctx, interestInterfaces)
	if err != nil {
		return err
	}

	log.Printf("  ✅ Created %d interest categories", len(interests))
	return nil
}
