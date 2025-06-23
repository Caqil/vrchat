package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"vrchat/internal/config"
	"vrchat/internal/routes"
	"vrchat/internal/websocket"
	"vrchat/pkg/database"
	"vrchat/pkg/logger"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

func main() {
	// Load environment variables
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found")
	}

	// Initialize logger
	logger.Init()

	// Load configuration
	cfg := config.Load()

	log.Println("🚀 Starting Omegle Clone Application...")

	// Initialize database connection
	log.Println("📡 Connecting to MongoDB...")
	if err := database.InitMongoDB(cfg.Database.MongoDB); err != nil {
		logger.Fatal("Failed to connect to MongoDB: " + err.Error())
	}

	// Run database migration automatically
	log.Println("🔧 Running database migration...")
	if err := runDatabaseMigration(cfg); err != nil {
		logger.Fatal("Database migration failed: " + err.Error())
	}
	log.Println("✅ Database migration completed successfully!")

	// Initialize WebSocket hub
	log.Println("🔌 Initializing WebSocket hub...")
	hub := websocket.NewHub()
	go hub.Run()

	// Initialize Gin router
	if cfg.App.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.Default()

	// Setup routes
	routes.SetupRoutes(router, hub)

	// Start server
	port := os.Getenv("PORT")
	if port == "" {
		port = cfg.App.Port
	}

	logger.Info("🚀 Server starting on port: " + port)
	logger.Info("🌐 Environment: " + cfg.App.Environment)
	if err := router.Run(":" + port); err != nil {
		logger.Fatal("Failed to start server: " + err.Error())
	}
}

// Migration Configuration
type MigrationConfig struct {
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

// runDatabaseMigration runs the complete database migration process
func runDatabaseMigration(cfg *config.Config) error {
	migrationConfig := MigrationConfig{
		MongoURI:      cfg.Database.MongoDB.URI,
		DatabaseName:  cfg.Database.MongoDB.Database,
		AdminUsername: getEnv("ADMIN_USERNAME", "admin"),
		AdminPassword: getEnv("ADMIN_PASSWORD", "admin123"),
	}

	// Get database connection
	db := database.GetDatabase()
	if db == nil {
		return fmt.Errorf("database connection not available")
	}

	// Run migration steps
	return runMigrationSteps(db, migrationConfig)
}

// getEnv gets environment variable with default value
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// runMigrationSteps executes all migration steps
func runMigrationSteps(database *mongo.Database, config MigrationConfig) error {
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
	log.Println("⚙️ Creating application settings...")
	if err := createAppSettings(database); err != nil {
		return fmt.Errorf("failed to create app settings: %w", err)
	}

	// Step 6: Setup region and language data
	log.Println("🗺️ Setting up regions and languages...")
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

// getCollectionSetups returns all collection configurations
func getCollectionSetups() []CollectionSetup {
	return []CollectionSetup{
		{
			Name: "users",
			Indexes: []mongo.IndexModel{
				{Keys: bson.D{{Key: "session_id", Value: 1}}, Options: options.Index().SetUnique(true)},
				{Keys: bson.D{{Key: "ip_address", Value: 1}}},
				{Keys: bson.D{{Key: "is_online", Value: 1}}},
				{Keys: bson.D{{Key: "region", Value: 1}}},
				{Keys: bson.D{{Key: "language", Value: 1}}},
				{Keys: bson.D{{Key: "interests", Value: 1}}},
				{Keys: bson.D{{Key: "created_at", Value: 1}}},
				{Keys: bson.D{{Key: "last_seen", Value: 1}}},
				{Keys: bson.D{{Key: "is_banned", Value: 1}}},
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
				{Keys: bson.D{{Key: "user1_id", Value: 1}, {Key: "user2_id", Value: 1}}},
			},
		},
		{
			Name: "messages",
			Indexes: []mongo.IndexModel{
				{Keys: bson.D{{Key: "chat_id", Value: 1}}},
				{Keys: bson.D{{Key: "sender_id", Value: 1}}},
				{Keys: bson.D{{Key: "timestamp", Value: 1}}},
				{Keys: bson.D{{Key: "message_type", Value: 1}}},
				{Keys: bson.D{{Key: "is_flagged", Value: 1}}},
			},
		},
		{
			Name: "reports",
			Indexes: []mongo.IndexModel{
				{Keys: bson.D{{Key: "reported_user_id", Value: 1}}},
				{Keys: bson.D{{Key: "reporter_id", Value: 1}}},
				{Keys: bson.D{{Key: "status", Value: 1}}},
				{Keys: bson.D{{Key: "category", Value: 1}}},
				{Keys: bson.D{{Key: "created_at", Value: 1}}},
				{Keys: bson.D{{Key: "priority", Value: 1}}},
			},
		},
		{
			Name: "bans",
			Indexes: []mongo.IndexModel{
				{Keys: bson.D{{Key: "user_id", Value: 1}}},
				{Keys: bson.D{{Key: "ip_address", Value: 1}}},
				{Keys: bson.D{{Key: "ban_type", Value: 1}}},
				{Keys: bson.D{{Key: "is_active", Value: 1}}},
				{Keys: bson.D{{Key: "expires_at", Value: 1}}},
				{Keys: bson.D{{Key: "created_at", Value: 1}}},
			},
		},
		{
			Name: "coturn_servers",
			Indexes: []mongo.IndexModel{
				{Keys: bson.D{{Key: "region", Value: 1}}},
				{Keys: bson.D{{Key: "is_active", Value: 1}}},
				{Keys: bson.D{{Key: "priority", Value: 1}}},
				{Keys: bson.D{{Key: "health_status", Value: 1}}},
			},
		},
		{
			Name: "admins",
			Indexes: []mongo.IndexModel{
				{Keys: bson.D{{Key: "username", Value: 1}}, Options: options.Index().SetUnique(true)},
				{Keys: bson.D{{Key: "email", Value: 1}}, Options: options.Index().SetUnique(true)},
				{Keys: bson.D{{Key: "role", Value: 1}}},
				{Keys: bson.D{{Key: "is_active", Value: 1}}},
			},
		},
		{
			Name: "session_tokens",
			Indexes: []mongo.IndexModel{
				{Keys: bson.D{{Key: "token", Value: 1}}, Options: options.Index().SetUnique(true)},
				{Keys: bson.D{{Key: "user_id", Value: 1}}},
				{Keys: bson.D{{Key: "expires_at", Value: 1}}},
				{Keys: bson.D{{Key: "created_at", Value: 1}}},
			},
		},
		{
			Name: "refresh_tokens",
			Indexes: []mongo.IndexModel{
				{Keys: bson.D{{Key: "token", Value: 1}}, Options: options.Index().SetUnique(true)},
				{Keys: bson.D{{Key: "user_id", Value: 1}}},
				{Keys: bson.D{{Key: "expires_at", Value: 1}}},
			},
		},
		{
			Name: "interests",
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
		{
			Name: "regions",
			Indexes: []mongo.IndexModel{
				{Keys: bson.D{{Key: "code", Value: 1}}, Options: options.Index().SetUnique(true)},
				{Keys: bson.D{{Key: "country", Value: 1}}},
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
			Name: "app_settings",
			Indexes: []mongo.IndexModel{
				{Keys: bson.D{{Key: "updated_at", Value: 1}}},
			},
		},
		{
			Name: "admin_activity_logs",
			Indexes: []mongo.IndexModel{
				{Keys: bson.D{{Key: "admin_id", Value: 1}}},
				{Keys: bson.D{{Key: "action", Value: 1}}},
				{Keys: bson.D{{Key: "timestamp", Value: 1}}},
			},
		},
		{
			Name: "ip_cache",
			Indexes: []mongo.IndexModel{
				{Keys: bson.D{{Key: "ip_address", Value: 1}}, Options: options.Index().SetUnique(true)},
				{Keys: bson.D{{Key: "created_at", Value: 1}}},
			},
		},
	}
}

// createCollectionWithIndexes creates a collection and its indexes
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
			log.Printf("  ⚠️ Warning: Failed to create indexes for %s: %v", setup.Name, err)
		} else {
			log.Printf("  📊 Created %d indexes for: %s", len(setup.Indexes), setup.Name)
		}
	}

	return nil
}

// seedInitialData coordinates all seeding operations
func seedInitialData(database *mongo.Database, config MigrationConfig) error {
	// This function coordinates all the seeding
	// Individual seed functions are called from main migration flow
	return nil
}

// createAdminUser creates the default admin user
func createAdminUser(database *mongo.Database, config MigrationConfig) error {
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

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(config.AdminPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	// Create admin user
	admin := bson.M{
		"username":   config.AdminUsername,
		"email":      "admin@omegle.com",
		"password":   string(hashedPassword),
		"role":       "super_admin",
		"is_active":  true,
		"created_at": time.Now(),
		"updated_at": time.Now(),
		"last_login": nil,
		"permissions": []string{
			"users.view", "users.edit", "users.delete", "users.ban",
			"chats.view", "chats.monitor", "chats.end",
			"reports.view", "reports.moderate", "reports.resolve",
			"settings.view", "settings.edit",
			"system.view", "system.manage",
			"analytics.view",
			"coturn.manage",
		},
	}

	_, err = collection.InsertOne(ctx, admin)
	if err != nil {
		return err
	}

	log.Printf("  ✅ Created admin user: %s", config.AdminUsername)
	return nil
}

// setupCOTURNServers creates initial COTURN server configurations
func setupCOTURNServers(database *mongo.Database) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	collection := database.Collection("coturn_servers")

	// Check if COTURN servers already exist
	count, err := collection.CountDocuments(ctx, bson.M{})
	if err != nil {
		return err
	}

	if count > 0 {
		log.Printf("  🌐 COTURN servers already exist")
		return nil
	}

	// Create default COTURN servers
	servers := []bson.M{
		{
			"name":          "US East TURN Server",
			"url":           "turn:turn-us-east.omegle.com:3478",
			"username":      "omegle",
			"credential":    "secretkey123",
			"region":        "us-east-1",
			"priority":      1,
			"is_active":     true,
			"health_status": "healthy",
			"created_at":    time.Now(),
			"updated_at":    time.Now(),
		},
		{
			"name":          "EU West TURN Server",
			"url":           "turn:turn-eu-west.omegle.com:3478",
			"username":      "omegle",
			"credential":    "secretkey123",
			"region":        "eu-west-1",
			"priority":      1,
			"is_active":     true,
			"health_status": "healthy",
			"created_at":    time.Now(),
			"updated_at":    time.Now(),
		},
		{
			"name":          "AP Southeast TURN Server",
			"url":           "turn:turn-ap-southeast.omegle.com:3478",
			"username":      "omegle",
			"credential":    "secretkey123",
			"region":        "ap-southeast-1",
			"priority":      1,
			"is_active":     true,
			"health_status": "healthy",
			"created_at":    time.Now(),
			"updated_at":    time.Now(),
		},
	}

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

// createAppSettings creates default application settings
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
		log.Printf("  ⚙️ App settings already exist")
		return nil
	}

	// Create default settings
	defaultSettings := bson.M{
		"app_name":                "Omegle Clone",
		"app_description":         "Random chat application",
		"max_users_per_room":      2,
		"chat_timeout":            1800, // 30 minutes
		"enable_age_verification": false,
		"minimum_age":             13,
		"enable_profanity_filter": true,
		"enable_auto_moderation":  true,
		"maintenance_mode":        false,
		"maintenance_message":     "System is under maintenance. Please try again later.",
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

// setupRegionsAndLanguages sets up region and language data
func setupRegionsAndLanguages(database *mongo.Database) error {
	if err := setupRegions(database); err != nil {
		return err
	}
	return setupLanguages(database)
}

// setupRegions creates default regions
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
		log.Printf("  🗺️ Regions already exist")
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

// setupLanguages creates default languages
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
		{"code": "pl", "name": "Polish", "native_name": "Polski", "is_active": true, "created_at": time.Now()},
		{"code": "nl", "name": "Dutch", "native_name": "Nederlands", "is_active": true, "created_at": time.Now()},
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

// setupInterestCategories creates default interest categories
func setupInterestCategories(database *mongo.Database) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	collection := database.Collection("interests")

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
		{"name": "Gaming", "category": "Entertainment", "is_active": true, "created_at": time.Now()},
		{"name": "Music", "category": "Entertainment", "is_active": true, "created_at": time.Now()},
		{"name": "Movies", "category": "Entertainment", "is_active": true, "created_at": time.Now()},
		{"name": "Sports", "category": "Recreation", "is_active": true, "created_at": time.Now()},
		{"name": "Technology", "category": "Education", "is_active": true, "created_at": time.Now()},
		{"name": "Programming", "category": "Education", "is_active": true, "created_at": time.Now()},
		{"name": "Art", "category": "Creative", "is_active": true, "created_at": time.Now()},
		{"name": "Photography", "category": "Creative", "is_active": true, "created_at": time.Now()},
		{"name": "Travel", "category": "Lifestyle", "is_active": true, "created_at": time.Now()},
		{"name": "Food", "category": "Lifestyle", "is_active": true, "created_at": time.Now()},
		{"name": "Books", "category": "Education", "is_active": true, "created_at": time.Now()},
		{"name": "Fitness", "category": "Health", "is_active": true, "created_at": time.Now()},
		{"name": "Science", "category": "Education", "is_active": true, "created_at": time.Now()},
		{"name": "Fashion", "category": "Lifestyle", "is_active": true, "created_at": time.Now()},
		{"name": "Anime", "category": "Entertainment", "is_active": true, "created_at": time.Now()},
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
