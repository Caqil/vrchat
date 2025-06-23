package config

import (
	"os"
	"strconv"
)

type Config struct {
	App     AppConfig
	MongoDB MongoConfig
	JWT     JWTConfig
	Coturn  CoturnConfig
	WebRTC  WebRTCConfig
}

type AppConfig struct {
	Name        string
	Version     string
	Environment string
	Port        string
	Domain      string
}

type MongoConfig struct {
	URI      string
	Database string
}

type JWTConfig struct {
	Secret     string
	ExpiryHour int
}

type CoturnConfig struct {
	Servers []CoturnServer
}

type CoturnServer struct {
	Region   string
	URL      string
	Username string
	Password string
	Active   bool
}

type WebRTCConfig struct {
	STUNServers []string
	TURNServers []string
}

func Load() *Config {
	return &Config{
		App: AppConfig{
			Name:        getEnv("APP_NAME", "Omegle Backend"),
			Version:     getEnv("APP_VERSION", "1.0.0"),
			Environment: getEnv("APP_ENV", "development"),
			Port:        getEnv("PORT", "8080"),
			Domain:      getEnv("APP_DOMAIN", "localhost"),
		},
		MongoDB: MongoConfig{
			URI:      getEnv("MONGODB_URI", "mongodb://localhost:27017"),
			Database: getEnv("MONGODB_DATABASE", "omegle_app"),
		},
		JWT: JWTConfig{
			Secret:     getEnv("JWT_SECRET", "your-secret-key"),
			ExpiryHour: getEnvAsInt("JWT_EXPIRY_HOUR", 24),
		},
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvAsInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}
