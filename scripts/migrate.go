package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

type Config struct {
	MongoURI      string
	DatabaseName  string
	AdminUsername string
	AdminPassword string
	AdminEmail    string
	Environment   string
}

type CollectionSetup struct {
	Name     string
	Indexes  []mongo.IndexModel
	SeedData interface{}
}

// AdminUser represents the admin user structure
type AdminUser struct {
	ID          string        `bson:"_id"`
	Username    string        `bson:"username"`
	Email       string        `bson:"email"`
	Password    string        `bson:"password"`
	Role        string        `bson:"role"`
	Permissions []string      `bson:"permissions"`
	IsActive    bool          `bson:"is_active"`
	Profile     AdminProfile  `bson:"profile"`
	Security    AdminSecurity `bson:"security"`
	CreatedAt   time.Time     `bson:"created_at"`
	UpdatedAt   time.Time     `bson:"updated_at"`
	LastLogin   *time.Time    `bson:"last_login,omitempty"`
}

type AdminProfile struct {
	FirstName   string `bson:"first_name"`
	LastName    string `bson:"last_name"`
	DisplayName string `bson:"display_name"`
	Avatar      string `bson:"avatar,omitempty"`
	Phone       string `bson:"phone,omitempty"`
	Timezone    string `bson:"timezone"`
}

type AdminSecurity struct {
	LastIP            string     `bson:"last_ip,omitempty"`
	FailedAttempts    int        `bson:"failed_attempts"`
	LockedUntil       *time.Time `bson:"locked_until,omitempty"`
	TwoFactorEnabled  bool       `bson:"two_factor_enabled"`
	TwoFactorSecret   string     `bson:"two_factor_secret,omitempty"`
	PasswordChangedAt time.Time  `bson:"password_changed_at"`
	LastActivity      time.Time  `bson:"last_activity"`
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
	log.Println("")
	log.Println("🎉 Admin Panel Setup Complete!")
	log.Println("📊 Access your admin panel at: http://localhost:8080/admin")
	log.Println("")
	log.Printf("👤 Default Admin Credentials:")
	log.Printf("   Username: %s", config.AdminUsername)
	log.Printf("   Password: %s", config.AdminPassword)
	log.Printf("   Email: %s", config.AdminEmail)
	log.Println("")
	log.Println("⚠️  IMPORTANT: Change the default password after first login!")
}

func loadConfig() Config {
	return Config{
		MongoURI:      getEnv("MONGODB_URI", "mongodb://localhost:27017"),
		DatabaseName:  getEnv("MONGODB_DATABASE", "omegle_app"),
		AdminUsername: getEnv("ADMIN_USERNAME", "admin"),
		AdminPassword: getEnv("ADMIN_PASSWORD", "admin123"),
		AdminEmail:    getEnv("ADMIN_EMAIL", "admin@omegle-clone.local"),
		Environment:   getEnv("APP_ENV", "development"),
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

	// Step 3: Create admin users - ENHANCED
	log.Println("👑 Creating admin users...")
	if err := createAdminUsers(database, config); err != nil {
		return fmt.Errorf("failed to create admin users: %w", err)
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

	// Step 8: Create admin-specific initial data - NEW
	log.Println("🔧 Setting up admin-specific data...")
	if err := setupAdminData(database, config); err != nil {
		return fmt.Errorf("failed to setup admin data: %w", err)
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
				{Keys: bson.D{{Key: "region", Value: 1}, {Key: "language", Value: 1}, {Key: "is_online", Value: 1}}},
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
				{Keys: bson.D{{Key: "room_id", Value: 1}}},
				{Keys: bson.D{{Key: "user_id", Value: 1}}},
				{Keys: bson.D{{Key: "timestamp", Value: 1}}},
				{Keys: bson.D{{Key: "flagged", Value: 1}}},
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
				{Keys: bson.D{{Key: "admin_id", Value: 1}}},
				{Keys: bson.D{{Key: "token_type", Value: 1}}},
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
		// Admin-specific collections - ENHANCED
		{
			Name: "admins",
			Indexes: []mongo.IndexModel{
				{Keys: bson.D{{Key: "username", Value: 1}}, Options: options.Index().SetUnique(true)},
				{Keys: bson.D{{Key: "email", Value: 1}}, Options: options.Index().SetUnique(true)},
				{Keys: bson.D{{Key: "role", Value: 1}}},
				{Keys: bson.D{{Key: "is_active", Value: 1}}},
				{Keys: bson.D{{Key: "created_at", Value: 1}}},
				{Keys: bson.D{{Key: "last_login", Value: 1}}},
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
				{Keys: bson.D{{Key: "success", Value: 1}}},
			},
		},
		{
			Name: "security_alerts",
			Indexes: []mongo.IndexModel{
				{Keys: bson.D{{Key: "type", Value: 1}}},
				{Keys: bson.D{{Key: "level", Value: 1}}},
				{Keys: bson.D{{Key: "resolved", Value: 1}}},
				{Keys: bson.D{{Key: "created_at", Value: 1}}},
				{Keys: bson.D{{Key: "source", Value: 1}}},
			},
		},
		{
			Name: "admin_rate_limits",
			Indexes: []mongo.IndexModel{
				{Keys: bson.D{{Key: "key", Value: 1}}, Options: options.Index().SetUnique(true)},
				{Keys: bson.D{{Key: "window_end", Value: 1}}},
				{Keys: bson.D{{Key: "created_at", Value: 1}}, Options: options.Index().SetExpireAfterSeconds(3600)}, // 1 hour TTL
			},
		},
		{
			Name: "token_blacklist",
			Indexes: []mongo.IndexModel{
				{Keys: bson.D{{Key: "token", Value: 1}}, Options: options.Index().SetUnique(true)},
				{Keys: bson.D{{Key: "expires_at", Value: 1}}, Options: options.Index().SetExpireAfterSeconds(0)},
				{Keys: bson.D{{Key: "created_at", Value: 1}}},
			},
		},
		{
			Name: "banned_words",
			Indexes: []mongo.IndexModel{
				{Keys: bson.D{{Key: "word", Value: 1}}, Options: options.Index().SetUnique(true)},
				{Keys: bson.D{{Key: "is_active", Value: 1}}},
				{Keys: bson.D{{Key: "category", Value: 1}}},
			},
		},
		{
			Name: "banned_countries",
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

// createAdminUsers creates comprehensive admin users - ENHANCED
func createAdminUsers(database *mongo.Database, config Config) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	collection := database.Collection("admins")

	// Check if any admin users already exist
	count, err := collection.CountDocuments(ctx, bson.M{})
	if err != nil {
		return err
	}

	if count > 0 {
		log.Printf("  👑 Admin users already exist (%d found)", count)
		return nil
	}

	// Define admin users to create
	adminUsers := []AdminUser{
		{
			ID:       primitive.NewObjectID().Hex(),
			Username: config.AdminUsername,
			Email:    config.AdminEmail,
			Role:     "super_admin",
			Permissions: []string{
				"super_admin",
				"view_dashboard",
				"manage_users",
				"monitor_chats",
				"manage_reports",
				"manage_content",
				"view_analytics",
				"manage_coturn",
				"manage_settings",
				"system_admin",
			},
			IsActive: true,
			Profile: AdminProfile{
				FirstName:   "Super",
				LastName:    "Admin",
				DisplayName: "Super Administrator",
				Timezone:    "UTC",
			},
			Security: AdminSecurity{
				FailedAttempts:    0,
				TwoFactorEnabled:  false,
				PasswordChangedAt: time.Now(),
				LastActivity:      time.Now(),
			},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
	}

	// Add additional admin users for different environments
	if config.Environment == "development" {
		// Add demo admin users for development
		adminUsers = append(adminUsers, []AdminUser{
			{
				ID:       primitive.NewObjectID().Hex(),
				Username: "demo-admin",
				Email:    "demo@omegle-clone.local",
				Role:     "admin",
				Permissions: []string{
					"view_dashboard",
					"manage_users",
					"monitor_chats",
					"manage_reports",
					"manage_content",
					"view_analytics",
				},
				IsActive: true,
				Profile: AdminProfile{
					FirstName:   "Demo",
					LastName:    "Admin",
					DisplayName: "Demo Administrator",
					Timezone:    "UTC",
				},
				Security: AdminSecurity{
					FailedAttempts:    0,
					TwoFactorEnabled:  false,
					PasswordChangedAt: time.Now(),
					LastActivity:      time.Now(),
				},
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			},
			{
				ID:       primitive.NewObjectID().Hex(),
				Username: "moderator",
				Email:    "moderator@omegle-clone.local",
				Role:     "moderator",
				Permissions: []string{
					"view_dashboard",
					"monitor_chats",
					"manage_reports",
					"manage_content",
				},
				IsActive: true,
				Profile: AdminProfile{
					FirstName:   "Demo",
					LastName:    "Moderator",
					DisplayName: "Content Moderator",
					Timezone:    "UTC",
				},
				Security: AdminSecurity{
					FailedAttempts:    0,
					TwoFactorEnabled:  false,
					PasswordChangedAt: time.Now(),
					LastActivity:      time.Now(),
				},
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			},
		}...)
	}

	// Hash passwords and insert admin users
	for i, admin := range adminUsers {
		// Use same password for all demo users in development
		password := config.AdminPassword
		if admin.Username == "demo-admin" {
			password = "demo123"
		} else if admin.Username == "moderator" {
			password = "mod123"
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			return err
		}

		adminUsers[i].Password = string(hashedPassword)

		_, err = collection.InsertOne(ctx, adminUsers[i])
		if err != nil {
			return err
		}

		log.Printf("  ✅ Created admin user: %s (%s)", admin.Username, admin.Role)
		if config.Environment == "development" && admin.Username != config.AdminUsername {
			log.Printf("     Password: %s", password)
		}
	}

	return nil
}

// setupAdminData creates admin-specific initial data - NEW
func setupAdminData(database *mongo.Database, config Config) error {
	// Setup banned words
	if err := setupBannedWords(database); err != nil {
		return err
	}

	// Setup initial admin settings
	if err := setupAdminSettings(database); err != nil {
		return err
	}

	return nil
}

func setupBannedWords(database *mongo.Database) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	collection := database.Collection("banned_words")

	// Check if banned words already exist
	count, err := collection.CountDocuments(ctx, bson.M{})
	if err != nil {
		return err
	}

	if count > 0 {
		log.Printf("  🚫 Banned words already exist")
		return nil
	}

	// Default banned words
	bannedWords := []bson.M{
		{"word": "spam", "category": "general", "is_active": true, "created_at": time.Now()},
		{"word": "scam", "category": "general", "is_active": true, "created_at": time.Now()},
		{"word": "phishing", "category": "security", "is_active": true, "created_at": time.Now()},
		{"word": "fraud", "category": "security", "is_active": true, "created_at": time.Now()},
		{"word": "hack", "category": "security", "is_active": true, "created_at": time.Now()},
	}

	for _, word := range bannedWords {
		_, err = collection.InsertOne(ctx, word)
		if err != nil {
			log.Printf("  ⚠️  Warning: Failed to insert banned word: %v", err)
		}
	}

	log.Printf("  ✅ Created %d banned words", len(bannedWords))
	return nil
}

func setupAdminSettings(database *mongo.Database) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	collection := database.Collection("admin_settings")

	// Check if admin settings already exist
	count, err := collection.CountDocuments(ctx, bson.M{})
	if err != nil {
		return err
	}

	if count > 0 {
		log.Printf("  ⚙️  Admin settings already exist")
		return nil
	}

	adminSettings := bson.M{
		"panel_title":             "Omegle Admin Panel",
		"items_per_page":          50,
		"session_timeout_hours":   8,
		"auto_refresh_enabled":    true,
		"auto_refresh_interval":   30,
		"activity_logging":        true,
		"security_alerts":         true,
		"two_factor_required":     false,
		"ip_whitelist_enabled":    false,
		"allowed_ips":             []string{},
		"maintenance_mode":        false,
		"maintenance_message":     "System is under maintenance. Please check back later.",
		"backup_enabled":          true,
		"backup_retention_days":   30,
		"log_retention_days":      90,
		"rate_limit_enabled":      true,
		"max_failed_logins":       5,
		"account_lockout_minutes": 30,
		"created_at":              time.Now(),
		"updated_at":              time.Now(),
	}

	_, err = collection.InsertOne(ctx, adminSettings)
	if err != nil {
		return err
	}

	log.Printf("  ✅ Created admin settings")
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
	}

	for _, server := range servers {
		_, err = collection.InsertOne(ctx, server)
		if err != nil {
			return err
		}
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
		"app_version":             "1.0.0",
		"maintenance_mode":        false,
		"maintenance_message":     "We're currently performing maintenance. Please try again later.",
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
	}

	for _, region := range regions {
		_, err = collection.InsertOne(ctx, region)
		if err != nil {
			return err
		}
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
	}

	for _, language := range languages {
		_, err = collection.InsertOne(ctx, language)
		if err != nil {
			return err
		}
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
		{"name": "Gaming", "description": "Video games and gaming", "is_active": true, "created_at": time.Now()},
		{"name": "Music", "description": "Music and musical instruments", "is_active": true, "created_at": time.Now()},
		{"name": "Movies", "description": "Films and television", "is_active": true, "created_at": time.Now()},
		{"name": "Sports", "description": "Sports and fitness", "is_active": true, "created_at": time.Now()},
		{"name": "Technology", "description": "Technology and programming", "is_active": true, "created_at": time.Now()},
		{"name": "Art", "description": "Visual arts and creativity", "is_active": true, "created_at": time.Now()},
		{"name": "Travel", "description": "Travel and exploration", "is_active": true, "created_at": time.Now()},
		{"name": "Books", "description": "Literature and reading", "is_active": true, "created_at": time.Now()},
		{"name": "Food", "description": "Cooking and cuisine", "is_active": true, "created_at": time.Now()},
		{"name": "Science", "description": "Science and research", "is_active": true, "created_at": time.Now()},
	}

	for _, interest := range interests {
		_, err = collection.InsertOne(ctx, interest)
		if err != nil {
			return err
		}
	}

	log.Printf("  ✅ Created %d interest categories", len(interests))
	return nil
}
