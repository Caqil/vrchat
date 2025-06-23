// ==============================================
// Enhanced Configuration System for Omegle Clone
// Complete Go-based configuration without YAML
// ==============================================

package config

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// ==============================================
// Main Configuration Structure
// ==============================================

type Config struct {
	App      AppConfig
	Server   ServerConfig
	Database DatabaseConfig
	WebRTC   WebRTCConfig
	Chat     ChatConfig
	Users    UsersConfig
	Security SecurityConfig
	Features FeatureConfig
	Regional RegionalConfig
	Admin    AdminConfig
}

// ==============================================
// Application Configuration
// ==============================================

type AppConfig struct {
	Name               string
	Version            string
	Environment        string
	Domain             string
	Port               string
	Debug              bool
	MaintenanceMode    bool
	MaintenanceMessage string
}

// ==============================================
// Server Configuration
// ==============================================

type ServerConfig struct {
	HTTP      HTTPConfig
	WebSocket WebSocketConfig
	CORS      CORSConfig
	TLS       TLSConfig
}

type HTTPConfig struct {
	Port           string
	Host           string
	ReadTimeout    time.Duration
	WriteTimeout   time.Duration
	IdleTimeout    time.Duration
	MaxHeaderBytes int
}

type WebSocketConfig struct {
	ReadBufferSize  int
	WriteBufferSize int
	CheckOrigin     bool
	Compression     bool
	PingPeriod      time.Duration
	PongWait        time.Duration
	WriteWait       time.Duration
	MaxMessageSize  int64
}

type CORSConfig struct {
	AllowedOrigins   []string
	AllowedMethods   []string
	AllowedHeaders   []string
	AllowCredentials bool
	MaxAge           time.Duration
}

type TLSConfig struct {
	Enabled  bool
	Port     string
	CertFile string
	KeyFile  string
	AutoCert bool
}

// ==============================================
// Database Configuration
// ==============================================

type DatabaseConfig struct {
	MongoDB MongoConfig
	Redis   RedisConfig
}

type MongoConfig struct {
	URI                    string
	Database               string
	AuthSource             string
	Username               string
	Password               string
	MaxPoolSize            uint64
	MinPoolSize            uint64
	MaxConnIdleTime        time.Duration
	ConnectTimeout         time.Duration
	ServerSelectionTimeout time.Duration
	HeartbeatInterval      time.Duration
	SSLEnabled             bool
	SSLCertFile            string
	SSLKeyFile             string
	SSLCAFile              string
	SSLInsecureSkipVerify  bool
}

type RedisConfig struct {
	URL      string
	Password string
	DB       int
	PoolSize int
}

// ==============================================
// WebRTC/COTURN Configuration
// ==============================================

type WebRTCConfig struct {
	COTURN      COTURNConfig
	Fallback    FallbackConfig
	Credentials CredentialsConfig
}

type COTURNConfig struct {
	Secret       string
	Realm        string
	Regions      map[string]RegionServers
	DefaultPorts PortConfig
}

type RegionServers struct {
	Name        string
	Description string
	CountryCode string
	Coordinates Coordinates
	Servers     []ServerInfo
	Settings    RegionSettings
}

type Coordinates struct {
	Latitude  float64
	Longitude float64
}

type ServerInfo struct {
	Name       string
	URL        string
	ExternalIP string
	Username   string
	Password   string
	Priority   int
	MaxUsers   int
	IsActive   bool
	SSLCert    string
	SSLKey     string
}

type RegionSettings struct {
	BandwidthLimit      string
	ConcurrentSessions  int
	HealthCheckInterval time.Duration
	FailoverThreshold   int
	LoadBalancing       string
}

type PortConfig struct {
	Listening    int
	TLS          int
	AltListening int
	AltTLS       int
	MinRelay     int
	MaxRelay     int
}

type FallbackConfig struct {
	STUNServers []string
}

type CredentialsConfig struct {
	TTL              time.Duration
	Algorithm        string
	UsernameFormat   string
	RotationEnabled  bool
	RotationInterval time.Duration
}

// ==============================================
// Chat Configuration
// ==============================================

type ChatConfig struct {
	Matching      MatchingConfig
	Communication CommunicationConfig
	Management    ChatManagementConfig
}

type MatchingConfig struct {
	Algorithm         string
	FallbackAlgorithm string
	QueueTimeout      time.Duration
	MaxQueueSize      int
	SmartMatching     SmartMatchingConfig
	InterestMatching  InterestMatchingConfig
	RegionMatching    RegionMatchingConfig
	LanguageMatching  LanguageMatchingConfig
}

type SmartMatchingConfig struct {
	AvoidRecentConnections bool
	RecentConnectionWindow time.Duration
	PreferenceWeight       float64
	RegionWeight           float64
	LanguageWeight         float64
	InterestWeight         float64
}

type InterestMatchingConfig struct {
	Enabled             bool
	MaxInterests        int
	MinCommonInterests  int
	InterestBoostFactor float64
	PopularInterests    []string
}

type RegionMatchingConfig struct {
	Enabled          bool
	PreferSameRegion bool
	SameRegionBoost  float64
	MaxDistanceKM    float64
}

type LanguageMatchingConfig struct {
	Enabled            bool
	PreferSameLanguage bool
	SameLanguageBoost  float64
}

type CommunicationConfig struct {
	TextChat    TextChatConfig
	VideoChat   VideoChatConfig
	AudioChat   AudioChatConfig
	ScreenShare ScreenShareConfig
	FileSharing FileSharingConfig
}

type TextChatConfig struct {
	Enabled          bool
	MaxMessageLength int
	TypingIndicators bool
	EmojiSupport     bool
	MessageHistory   bool
	HistoryLimit     int
}

type VideoChatConfig struct {
	Enabled         bool
	MaxResolution   string
	AdaptiveQuality bool
	QualityLevels   []QualityLevel
}

type QualityLevel struct {
	Name       string
	Resolution string
	Bitrate    string
}

type AudioChatConfig struct {
	Enabled          bool
	Bitrate          string
	EchoCancellation bool
	NoiseSuppression bool
}

type ScreenShareConfig struct {
	Enabled       bool
	MaxResolution string
	MaxFramerate  int
}

type FileSharingConfig struct {
	Enabled       bool
	MaxFileSize   string
	AllowedTypes  []string
	VirusScanning bool
}

type ChatManagementConfig struct {
	MaxUsersPerRoom         int
	ChatTimeout             time.Duration
	IdleTimeout             time.Duration
	SkipCooldown            time.Duration
	ReconnectionTimeout     time.Duration
	MaxReconnectionAttempts int
}

// ==============================================
// Users Configuration
// ==============================================

type UsersConfig struct {
	Guest           GuestConfig
	Registration    RegistrationConfig
	SocialLogin     SocialLoginConfig
	Preferences     UserPreferencesConfig
	AgeVerification AgeVerificationConfig
}

type GuestConfig struct {
	Enabled         bool
	AnonymousAccess bool
	SessionDuration time.Duration
	AutoCleanup     bool
}

type RegistrationConfig struct {
	Enabled              bool
	EmailRequired        bool
	EmailVerification    bool
	PasswordRequirements PasswordRequirements
}

type PasswordRequirements struct {
	MinLength           int
	RequireUppercase    bool
	RequireLowercase    bool
	RequireNumbers      bool
	RequireSpecialChars bool
}

type SocialLoginConfig struct {
	Google   SocialProvider
	Facebook SocialProvider
}

type SocialProvider struct {
	Enabled      bool
	ClientID     string
	ClientSecret string
}

type UserPreferencesConfig struct {
	DefaultLanguage     string
	DefaultRegion       string
	DefaultTheme        string
	AllowLanguageChange bool
	AllowRegionChange   bool
}

type AgeVerificationConfig struct {
	Enabled    bool
	MinimumAge int
	Strict     bool
}

// ==============================================
// Security Configuration
// ==============================================

type SecurityConfig struct {
	JWT         JWTConfig
	RateLimit   RateLimitConfig
	Moderation  ModerationConfig
	Encryption  EncryptionConfig
	IPFiltering IPFilteringConfig
}

type JWTConfig struct {
	Secret          string
	ExpiryHour      int
	AdminSecret     string
	AdminExpiryHour int
	RefreshTokenTTL time.Duration
}

type RateLimitConfig struct {
	Enabled     bool
	Requests    int
	Window      time.Duration
	IPWhitelist []string
	Exemptions  []string
}

type ModerationConfig struct {
	AutoModeration  bool
	ProfanityFilter bool
	ContentScanning bool
	AIModeration    bool
	BannedWords     []string
	BannedCountries []string
	ReportThreshold int
	AutoBanEnabled  bool
}

type EncryptionConfig struct {
	Enabled   bool
	Algorithm string
	KeySize   int
}

type IPFilteringConfig struct {
	Enabled     bool
	Whitelist   []string
	Blacklist   []string
	GeoBlocking GeoBlockingConfig
}

type GeoBlockingConfig struct {
	Enabled          bool
	AllowedCountries []string
	BlockedCountries []string
}

// ==============================================
// Feature Configuration
// ==============================================

type FeatureConfig struct {
	InterestMatching bool
	RegionMatching   bool
	LanguageMatching bool
	VideoChat        bool
	AudioChat        bool
	ScreenSharing    bool
	FileSharing      bool
	MessageHistory   bool
	UserReports      bool
	AdminPanel       bool
	Analytics        bool
	APIAccess        bool
}

// ==============================================
// Regional Configuration
// ==============================================

type RegionalConfig struct {
	DefaultRegion string
	AutoDetection bool
	Regions       map[string]RegionInfo
}

type RegionInfo struct {
	Code        string
	Name        string
	Countries   []string
	Flag        string
	Description string
}

// ==============================================
// Admin Configuration
// ==============================================

type AdminConfig struct {
	Username     string
	Password     string
	Secret       string
	PanelEnabled bool
	LogLevel     string
	LogFormat    string
	LogOutput    string
}

// ==============================================
// Configuration Loading Functions
// ==============================================

func Load() *Config {
	return &Config{
		App:      loadAppConfig(),
		Server:   loadServerConfig(),
		Database: loadDatabaseConfig(),
		WebRTC:   loadWebRTCConfig(),
		Chat:     loadChatConfig(),
		Users:    loadUsersConfig(),
		Security: loadSecurityConfig(),
		Features: loadFeatureConfig(),
		Regional: loadRegionalConfig(),
		Admin:    loadAdminConfig(),
	}
}

func loadAppConfig() AppConfig {
	return AppConfig{
		Name:               getEnv("APP_NAME", "Omegle Clone"),
		Version:            getEnv("APP_VERSION", "1.0.0"),
		Environment:        getEnv("APP_ENV", "development"),
		Domain:             getEnv("APP_DOMAIN", "localhost"),
		Port:               getEnv("PORT", "8080"),
		Debug:              getEnvAsBool("DEBUG", false),
		MaintenanceMode:    getEnvAsBool("MAINTENANCE_MODE", false),
		MaintenanceMessage: getEnv("MAINTENANCE_MESSAGE", "Service temporarily unavailable"),
	}
}

func loadServerConfig() ServerConfig {
	return ServerConfig{
		HTTP: HTTPConfig{
			Port:           getEnv("HTTP_PORT", "8080"),
			Host:           getEnv("HTTP_HOST", "0.0.0.0"),
			ReadTimeout:    getEnvAsDuration("HTTP_READ_TIMEOUT", "30s"),
			WriteTimeout:   getEnvAsDuration("HTTP_WRITE_TIMEOUT", "30s"),
			IdleTimeout:    getEnvAsDuration("HTTP_IDLE_TIMEOUT", "60s"),
			MaxHeaderBytes: getEnvAsInt("HTTP_MAX_HEADER_BYTES", 1048576),
		},
		WebSocket: WebSocketConfig{
			ReadBufferSize:  getEnvAsInt("WS_READ_BUFFER", 1024),
			WriteBufferSize: getEnvAsInt("WS_WRITE_BUFFER", 1024),
			CheckOrigin:     getEnvAsBool("WS_CHECK_ORIGIN", true),
			Compression:     getEnvAsBool("WS_COMPRESSION", true),
			PingPeriod:      getEnvAsDuration("WS_PING_PERIOD", "54s"),
			PongWait:        getEnvAsDuration("WS_PONG_WAIT", "60s"),
			WriteWait:       getEnvAsDuration("WS_WRITE_WAIT", "10s"),
			MaxMessageSize:  getEnvAsInt64("WS_MAX_MESSAGE_SIZE", 512),
		},
		CORS: CORSConfig{
			AllowedOrigins:   getEnvAsSlice("CORS_ORIGINS", "http://localhost:3000"),
			AllowedMethods:   getEnvAsSlice("CORS_METHODS", "GET,POST,PUT,DELETE,OPTIONS"),
			AllowedHeaders:   getEnvAsSlice("CORS_HEADERS", "Origin,Content-Type,Accept,Authorization,X-Requested-With"),
			AllowCredentials: getEnvAsBool("CORS_CREDENTIALS", true),
			MaxAge:           getEnvAsDuration("CORS_MAX_AGE", "12h"),
		},
		TLS: TLSConfig{
			Enabled:  getEnvAsBool("TLS_ENABLED", false),
			Port:     getEnv("TLS_PORT", "8443"),
			CertFile: getEnv("TLS_CERT_FILE", ""),
			KeyFile:  getEnv("TLS_KEY_FILE", ""),
			AutoCert: getEnvAsBool("TLS_AUTO_CERT", false),
		},
	}
}

func loadDatabaseConfig() DatabaseConfig {
	return DatabaseConfig{
		MongoDB: MongoConfig{
			URI:                    getEnv("MONGODB_URI", "mongodb://localhost:27017"),
			Database:               getEnv("MONGODB_DATABASE", "omegle_app"),
			AuthSource:             getEnv("MONGODB_AUTH_SOURCE", "admin"),
			Username:               getEnv("MONGODB_USERNAME", ""),
			Password:               getEnv("MONGODB_PASSWORD", ""),
			MaxPoolSize:            getEnvAsUint64("MONGODB_MAX_POOL_SIZE", 100),
			MinPoolSize:            getEnvAsUint64("MONGODB_MIN_POOL_SIZE", 5),
			MaxConnIdleTime:        getEnvAsDuration("MONGODB_MAX_IDLE_TIME", "30m"),
			ConnectTimeout:         getEnvAsDuration("MONGODB_CONNECT_TIMEOUT", "10s"),
			ServerSelectionTimeout: getEnvAsDuration("MONGODB_SERVER_SELECTION_TIMEOUT", "5s"),
			HeartbeatInterval:      getEnvAsDuration("MONGODB_HEARTBEAT_INTERVAL", "10s"),
			SSLEnabled:             getEnvAsBool("MONGODB_SSL_ENABLED", false),
			SSLCertFile:            getEnv("MONGODB_SSL_CERT_FILE", ""),
			SSLKeyFile:             getEnv("MONGODB_SSL_KEY_FILE", ""),
			SSLCAFile:              getEnv("MONGODB_SSL_CA_FILE", ""),
			SSLInsecureSkipVerify:  getEnvAsBool("MONGODB_SSL_SKIP_VERIFY", false),
		},
		Redis: RedisConfig{
			URL:      getEnv("REDIS_URL", "redis://localhost:6379"),
			Password: getEnv("REDIS_PASSWORD", ""),
			DB:       getEnvAsInt("REDIS_DB", 0),
			PoolSize: getEnvAsInt("REDIS_POOL_SIZE", 10),
		},
	}
}

func loadWebRTCConfig() WebRTCConfig {
	return WebRTCConfig{
		COTURN: COTURNConfig{
			Secret: getEnv("COTURN_SECRET", "your-coturn-secret"),
			Realm:  getEnv("COTURN_REALM", "omegle.example.com"),
			Regions: map[string]RegionServers{
				"us-east": {
					Name:        "US East",
					Description: "United States East Coast",
					CountryCode: "US",
					Coordinates: Coordinates{39.0458, -76.6413},
					Servers: []ServerInfo{
						{
							Name:       "us-east-primary",
							URL:        getEnv("COTURN_US_EAST_PRIMARY_URL", "turn.us-east-1.omegle.com"),
							ExternalIP: getEnv("COTURN_US_EAST_PRIMARY_IP", ""),
							Username:   getEnv("COTURN_US_EAST_PRIMARY_USER", "turnuser"),
							Password:   getEnv("COTURN_US_EAST_PRIMARY_PASS", "turnpass"),
							Priority:   1,
							MaxUsers:   1000,
							IsActive:   true,
							SSLCert:    getEnv("COTURN_US_EAST_PRIMARY_CERT", "/etc/ssl/certs/turn.pem"),
							SSLKey:     getEnv("COTURN_US_EAST_PRIMARY_KEY", "/etc/ssl/private/turn.key"),
						},
					},
					Settings: RegionSettings{
						BandwidthLimit:      "10Gbps",
						ConcurrentSessions:  2000,
						HealthCheckInterval: 30 * time.Second,
						FailoverThreshold:   3,
						LoadBalancing:       "round_robin",
					},
				},
				"eu-west": {
					Name:        "Europe West",
					Description: "Western Europe",
					CountryCode: "GB",
					Coordinates: Coordinates{51.5074, -0.1278},
					Servers: []ServerInfo{
						{
							Name:       "eu-west-primary",
							URL:        getEnv("COTURN_EU_WEST_PRIMARY_URL", "turn.eu-west-1.omegle.com"),
							ExternalIP: getEnv("COTURN_EU_WEST_PRIMARY_IP", ""),
							Username:   getEnv("COTURN_EU_WEST_PRIMARY_USER", "turnuser"),
							Password:   getEnv("COTURN_EU_WEST_PRIMARY_PASS", "turnpass"),
							Priority:   1,
							MaxUsers:   1200,
							IsActive:   true,
							SSLCert:    getEnv("COTURN_EU_WEST_PRIMARY_CERT", "/etc/ssl/certs/turn.pem"),
							SSLKey:     getEnv("COTURN_EU_WEST_PRIMARY_KEY", "/etc/ssl/private/turn.key"),
						},
					},
					Settings: RegionSettings{
						BandwidthLimit:      "12Gbps",
						ConcurrentSessions:  2500,
						HealthCheckInterval: 30 * time.Second,
						FailoverThreshold:   3,
						LoadBalancing:       "weighted",
					},
				},
				"ap-southeast": {
					Name:        "Asia Pacific Southeast",
					Description: "Southeast Asia and Oceania",
					CountryCode: "SG",
					Coordinates: Coordinates{1.3521, 103.8198},
					Servers: []ServerInfo{
						{
							Name:       "ap-southeast-primary",
							URL:        getEnv("COTURN_AP_SE_PRIMARY_URL", "turn.ap-southeast-1.omegle.com"),
							ExternalIP: getEnv("COTURN_AP_SE_PRIMARY_IP", ""),
							Username:   getEnv("COTURN_AP_SE_PRIMARY_USER", "turnuser"),
							Password:   getEnv("COTURN_AP_SE_PRIMARY_PASS", "turnpass"),
							Priority:   1,
							MaxUsers:   1000,
							IsActive:   true,
							SSLCert:    getEnv("COTURN_AP_SE_PRIMARY_CERT", "/etc/ssl/certs/turn.pem"),
							SSLKey:     getEnv("COTURN_AP_SE_PRIMARY_KEY", "/etc/ssl/private/turn.key"),
						},
					},
					Settings: RegionSettings{
						BandwidthLimit:      "8Gbps",
						ConcurrentSessions:  1800,
						HealthCheckInterval: 30 * time.Second,
						FailoverThreshold:   3,
						LoadBalancing:       "round_robin",
					},
				},
			},
			DefaultPorts: PortConfig{
				Listening:    3478,
				TLS:          5349,
				AltListening: 3479,
				AltTLS:       5350,
				MinRelay:     49152,
				MaxRelay:     65535,
			},
		},
		Fallback: FallbackConfig{
			STUNServers: []string{
				"stun:stun.l.google.com:19302",
				"stun:stun1.l.google.com:19302",
				"stun:stun2.l.google.com:19302",
				"stun:stun.cloudflare.com:3478",
			},
		},
		Credentials: CredentialsConfig{
			TTL:              getEnvAsDuration("COTURN_CREDENTIAL_TTL", "1h"),
			Algorithm:        getEnv("COTURN_CREDENTIAL_ALGORITHM", "hmac-sha1"),
			UsernameFormat:   getEnv("COTURN_USERNAME_FORMAT", "timestamp:random"),
			RotationEnabled:  getEnvAsBool("COTURN_ROTATION_ENABLED", true),
			RotationInterval: getEnvAsDuration("COTURN_ROTATION_INTERVAL", "24h"),
		},
	}
}

func loadChatConfig() ChatConfig {
	return ChatConfig{
		Matching: MatchingConfig{
			Algorithm:         getEnv("MATCHING_ALGORITHM", "smart_random"),
			FallbackAlgorithm: getEnv("MATCHING_FALLBACK", "pure_random"),
			QueueTimeout:      getEnvAsDuration("QUEUE_TIMEOUT", "5m"),
			MaxQueueSize:      getEnvAsInt("MAX_QUEUE_SIZE", 10000),
			SmartMatching: SmartMatchingConfig{
				AvoidRecentConnections: getEnvAsBool("AVOID_RECENT_CONNECTIONS", true),
				RecentConnectionWindow: getEnvAsDuration("RECENT_CONNECTION_WINDOW", "1h"),
				PreferenceWeight:       getEnvAsFloat64("PREFERENCE_WEIGHT", 0.7),
				RegionWeight:           getEnvAsFloat64("REGION_WEIGHT", 0.3),
				LanguageWeight:         getEnvAsFloat64("LANGUAGE_WEIGHT", 0.5),
				InterestWeight:         getEnvAsFloat64("INTEREST_WEIGHT", 0.4),
			},
			InterestMatching: InterestMatchingConfig{
				Enabled:             getEnvAsBool("INTEREST_MATCHING_ENABLED", true),
				MaxInterests:        getEnvAsInt("MAX_INTERESTS", 10),
				MinCommonInterests:  getEnvAsInt("MIN_COMMON_INTERESTS", 1),
				InterestBoostFactor: getEnvAsFloat64("INTEREST_BOOST_FACTOR", 2.0),
				PopularInterests: []string{
					"gaming", "music", "movies", "sports", "technology",
					"art", "travel", "food", "books", "anime",
				},
			},
			RegionMatching: RegionMatchingConfig{
				Enabled:          getEnvAsBool("REGION_MATCHING_ENABLED", true),
				PreferSameRegion: getEnvAsBool("PREFER_SAME_REGION", true),
				SameRegionBoost:  getEnvAsFloat64("SAME_REGION_BOOST", 1.5),
				MaxDistanceKM:    getEnvAsFloat64("MAX_DISTANCE_KM", 10000),
			},
			LanguageMatching: LanguageMatchingConfig{
				Enabled:            getEnvAsBool("LANGUAGE_MATCHING_ENABLED", true),
				PreferSameLanguage: getEnvAsBool("PREFER_SAME_LANGUAGE", true),
				SameLanguageBoost:  getEnvAsFloat64("SAME_LANGUAGE_BOOST", 2.0),
			},
		},
		Communication: CommunicationConfig{
			TextChat: TextChatConfig{
				Enabled:          getEnvAsBool("TEXT_CHAT_ENABLED", true),
				MaxMessageLength: getEnvAsInt("MAX_MESSAGE_LENGTH", 1000),
				TypingIndicators: getEnvAsBool("TYPING_INDICATORS", true),
				EmojiSupport:     getEnvAsBool("EMOJI_SUPPORT", true),
				MessageHistory:   getEnvAsBool("MESSAGE_HISTORY", true),
				HistoryLimit:     getEnvAsInt("HISTORY_LIMIT", 100),
			},
			VideoChat: VideoChatConfig{
				Enabled:         getEnvAsBool("VIDEO_CHAT_ENABLED", true),
				MaxResolution:   getEnv("VIDEO_MAX_RESOLUTION", "1280x720"),
				AdaptiveQuality: getEnvAsBool("VIDEO_ADAPTIVE_QUALITY", true),
				QualityLevels: []QualityLevel{
					{Name: "low", Resolution: "320x240", Bitrate: "100kbps"},
					{Name: "medium", Resolution: "640x480", Bitrate: "500kbps"},
					{Name: "high", Resolution: "1280x720", Bitrate: "1500kbps"},
				},
			},
			AudioChat: AudioChatConfig{
				Enabled:          getEnvAsBool("AUDIO_CHAT_ENABLED", true),
				Bitrate:          getEnv("AUDIO_BITRATE", "64kbps"),
				EchoCancellation: getEnvAsBool("AUDIO_ECHO_CANCELLATION", true),
				NoiseSuppression: getEnvAsBool("AUDIO_NOISE_SUPPRESSION", true),
			},
			ScreenShare: ScreenShareConfig{
				Enabled:       getEnvAsBool("SCREEN_SHARE_ENABLED", true),
				MaxResolution: getEnv("SCREEN_SHARE_MAX_RESOLUTION", "1920x1080"),
				MaxFramerate:  getEnvAsInt("SCREEN_SHARE_MAX_FRAMERATE", 15),
			},
			FileSharing: FileSharingConfig{
				Enabled:     getEnvAsBool("FILE_SHARING_ENABLED", true),
				MaxFileSize: getEnv("FILE_SHARING_MAX_SIZE", "10MB"),
				AllowedTypes: getEnvAsSlice("FILE_SHARING_ALLOWED_TYPES",
					"image/jpeg,image/png,image/gif,image/webp,application/pdf,text/plain"),
				VirusScanning: getEnvAsBool("FILE_SHARING_VIRUS_SCAN", false),
			},
		},
		Management: ChatManagementConfig{
			MaxUsersPerRoom:         getEnvAsInt("MAX_USERS_PER_ROOM", 2),
			ChatTimeout:             getEnvAsDuration("CHAT_TIMEOUT", "30m"),
			IdleTimeout:             getEnvAsDuration("IDLE_TIMEOUT", "5m"),
			SkipCooldown:            getEnvAsDuration("SKIP_COOLDOWN", "3s"),
			ReconnectionTimeout:     getEnvAsDuration("RECONNECTION_TIMEOUT", "30s"),
			MaxReconnectionAttempts: getEnvAsInt("MAX_RECONNECTION_ATTEMPTS", 3),
		},
	}
}

func loadUsersConfig() UsersConfig {
	return UsersConfig{
		Guest: GuestConfig{
			Enabled:         getEnvAsBool("GUEST_USERS_ENABLED", true),
			AnonymousAccess: getEnvAsBool("ANONYMOUS_ACCESS", true),
			SessionDuration: getEnvAsDuration("GUEST_SESSION_DURATION", "24h"),
			AutoCleanup:     getEnvAsBool("GUEST_AUTO_CLEANUP", true),
		},
		Registration: RegistrationConfig{
			Enabled:           getEnvAsBool("REGISTRATION_ENABLED", true),
			EmailRequired:     getEnvAsBool("EMAIL_REQUIRED", true),
			EmailVerification: getEnvAsBool("EMAIL_VERIFICATION", true),
			PasswordRequirements: PasswordRequirements{
				MinLength:           getEnvAsInt("PASSWORD_MIN_LENGTH", 8),
				RequireUppercase:    getEnvAsBool("PASSWORD_REQUIRE_UPPERCASE", true),
				RequireLowercase:    getEnvAsBool("PASSWORD_REQUIRE_LOWERCASE", true),
				RequireNumbers:      getEnvAsBool("PASSWORD_REQUIRE_NUMBERS", true),
				RequireSpecialChars: getEnvAsBool("PASSWORD_REQUIRE_SPECIAL", true),
			},
		},
		SocialLogin: SocialLoginConfig{
			Google: SocialProvider{
				Enabled:      getEnvAsBool("GOOGLE_LOGIN_ENABLED", false),
				ClientID:     getEnv("GOOGLE_CLIENT_ID", ""),
				ClientSecret: getEnv("GOOGLE_CLIENT_SECRET", ""),
			},
			Facebook: SocialProvider{
				Enabled:      getEnvAsBool("FACEBOOK_LOGIN_ENABLED", false),
				ClientID:     getEnv("FACEBOOK_APP_ID", ""),
				ClientSecret: getEnv("FACEBOOK_APP_SECRET", ""),
			},
		},
		Preferences: UserPreferencesConfig{
			DefaultLanguage:     getEnv("DEFAULT_LANGUAGE", "en"),
			DefaultRegion:       getEnv("DEFAULT_REGION", "auto"),
			DefaultTheme:        getEnv("DEFAULT_THEME", "light"),
			AllowLanguageChange: getEnvAsBool("ALLOW_LANGUAGE_CHANGE", true),
			AllowRegionChange:   getEnvAsBool("ALLOW_REGION_CHANGE", true),
		},
		AgeVerification: AgeVerificationConfig{
			Enabled:    getEnvAsBool("AGE_VERIFICATION_ENABLED", true),
			MinimumAge: getEnvAsInt("MINIMUM_AGE", 13),
			Strict:     getEnvAsBool("AGE_VERIFICATION_STRICT", false),
		},
	}
}

func loadSecurityConfig() SecurityConfig {
	return SecurityConfig{
		JWT: JWTConfig{
			Secret:          getEnv("JWT_SECRET", "your-secret-key"),
			ExpiryHour:      getEnvAsInt("JWT_EXPIRY_HOUR", 24),
			AdminSecret:     getEnv("ADMIN_JWT_SECRET", "admin-secret-key"),
			AdminExpiryHour: getEnvAsInt("ADMIN_JWT_EXPIRY_HOUR", 8),
			RefreshTokenTTL: getEnvAsDuration("REFRESH_TOKEN_TTL", "168h"), // 7 days
		},
		RateLimit: RateLimitConfig{
			Enabled:     getEnvAsBool("RATE_LIMIT_ENABLED", true),
			Requests:    getEnvAsInt("RATE_LIMIT_REQUESTS", 100),
			Window:      getEnvAsDuration("RATE_LIMIT_WINDOW", "1h"),
			IPWhitelist: getEnvAsSlice("RATE_LIMIT_WHITELIST", ""),
			Exemptions:  getEnvAsSlice("RATE_LIMIT_EXEMPTIONS", ""),
		},
		Moderation: ModerationConfig{
			AutoModeration:  getEnvAsBool("AUTO_MODERATION", true),
			ProfanityFilter: getEnvAsBool("PROFANITY_FILTER", true),
			ContentScanning: getEnvAsBool("CONTENT_SCANNING", true),
			AIModeration:    getEnvAsBool("AI_MODERATION", false),
			BannedWords:     getEnvAsSlice("BANNED_WORDS", ""),
			BannedCountries: getEnvAsSlice("BANNED_COUNTRIES", ""),
			ReportThreshold: getEnvAsInt("REPORT_THRESHOLD", 3),
			AutoBanEnabled:  getEnvAsBool("AUTO_BAN_ENABLED", true),
		},
		Encryption: EncryptionConfig{
			Enabled:   getEnvAsBool("ENCRYPTION_ENABLED", true),
			Algorithm: getEnv("ENCRYPTION_ALGORITHM", "AES-256-GCM"),
			KeySize:   getEnvAsInt("ENCRYPTION_KEY_SIZE", 256),
		},
		IPFiltering: IPFilteringConfig{
			Enabled:   getEnvAsBool("IP_FILTERING_ENABLED", false),
			Whitelist: getEnvAsSlice("IP_WHITELIST", ""),
			Blacklist: getEnvAsSlice("IP_BLACKLIST", ""),
			GeoBlocking: GeoBlockingConfig{
				Enabled:          getEnvAsBool("GEO_BLOCKING_ENABLED", false),
				AllowedCountries: getEnvAsSlice("ALLOWED_COUNTRIES", ""),
				BlockedCountries: getEnvAsSlice("BLOCKED_COUNTRIES", ""),
			},
		},
	}
}

func loadFeatureConfig() FeatureConfig {
	return FeatureConfig{
		InterestMatching: getEnvAsBool("FEATURE_INTEREST_MATCHING", true),
		RegionMatching:   getEnvAsBool("FEATURE_REGION_MATCHING", true),
		LanguageMatching: getEnvAsBool("FEATURE_LANGUAGE_MATCHING", true),
		VideoChat:        getEnvAsBool("FEATURE_VIDEO_CHAT", true),
		AudioChat:        getEnvAsBool("FEATURE_AUDIO_CHAT", true),
		ScreenSharing:    getEnvAsBool("FEATURE_SCREEN_SHARING", true),
		FileSharing:      getEnvAsBool("FEATURE_FILE_SHARING", true),
		MessageHistory:   getEnvAsBool("FEATURE_MESSAGE_HISTORY", true),
		UserReports:      getEnvAsBool("FEATURE_USER_REPORTS", true),
		AdminPanel:       getEnvAsBool("FEATURE_ADMIN_PANEL", true),
		Analytics:        getEnvAsBool("FEATURE_ANALYTICS", true),
		APIAccess:        getEnvAsBool("FEATURE_API_ACCESS", true),
	}
}

func loadRegionalConfig() RegionalConfig {
	return RegionalConfig{
		DefaultRegion: getEnv("DEFAULT_REGION", "us-east"),
		AutoDetection: getEnvAsBool("AUTO_REGION_DETECTION", true),
		Regions: map[string]RegionInfo{
			"us-east": {
				Code:        "us-east",
				Name:        "US East",
				Countries:   []string{"US", "CA", "BR", "AR", "CL", "CO"},
				Flag:        "🇺🇸",
				Description: "United States East Coast",
			},
			"us-west": {
				Code:        "us-west",
				Name:        "US West",
				Countries:   []string{"MX"},
				Flag:        "🇺🇸",
				Description: "United States West Coast",
			},
			"eu-west": {
				Code:        "eu-west",
				Name:        "Europe West",
				Countries:   []string{"GB", "DE", "FR", "IT", "ES", "NL", "SE", "NO", "FI", "DK", "IE", "CH", "AT", "BE", "LU", "PT", "RU", "UA", "PL", "CZ", "HU", "ZA", "EG", "NG", "KE"},
				Flag:        "🇪🇺",
				Description: "Western Europe",
			},
			"ap-southeast": {
				Code:        "ap-southeast",
				Name:        "Asia Pacific Southeast",
				Countries:   []string{"SG", "MY", "TH", "ID", "PH", "VN", "AU", "NZ", "IN"},
				Flag:        "🌏",
				Description: "Southeast Asia and Oceania",
			},
			"ap-northeast": {
				Code:        "ap-northeast",
				Name:        "Asia Pacific Northeast",
				Countries:   []string{"CN", "JP", "KR", "TW", "HK", "MO"},
				Flag:        "🌏",
				Description: "Northeast Asia",
			},
		},
	}
}

func loadAdminConfig() AdminConfig {
	return AdminConfig{
		Username:     getEnv("ADMIN_USERNAME", "admin"),
		Password:     getEnv("ADMIN_PASSWORD", "admin123"),
		Secret:       getEnv("ADMIN_JWT_SECRET", "admin-secret-key"),
		PanelEnabled: getEnvAsBool("ADMIN_PANEL_ENABLED", true),
		LogLevel:     getEnv("LOG_LEVEL", "info"),
		LogFormat:    getEnv("LOG_FORMAT", "json"),
		LogOutput:    getEnv("LOG_OUTPUT", "stdout"),
	}
}

// ==============================================
// Helper Functions
// ==============================================

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

func getEnvAsInt64(key string, defaultValue int64) int64 {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.ParseInt(value, 10, 64); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getEnvAsUint64(key string, defaultValue uint64) uint64 {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.ParseUint(value, 10, 64); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getEnvAsFloat64(key string, defaultValue float64) float64 {
	if value := os.Getenv(key); value != "" {
		if floatValue, err := strconv.ParseFloat(value, 64); err == nil {
			return floatValue
		}
	}
	return defaultValue
}

func getEnvAsBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
	}
	return defaultValue
}

func getEnvAsDuration(key string, defaultValue string) time.Duration {
	if value := os.Getenv(key); value != "" {
		if duration, err := time.ParseDuration(value); err == nil {
			return duration
		}
	}
	duration, _ := time.ParseDuration(defaultValue)
	return duration
}

func getEnvAsSlice(key string, defaultValue string) []string {
	value := getEnv(key, defaultValue)
	if value == "" {
		return []string{}
	}
	return strings.Split(value, ",")
}

// ==============================================
// Configuration Validation
// ==============================================

func (c *Config) Validate() error {
	// Add validation logic here
	// Check required fields, validate ranges, etc.
	return nil
}

// ==============================================
// Environment-specific Configuration
// ==============================================

func (c *Config) ApplyEnvironmentOverrides() {
	switch c.App.Environment {
	case "development":
		c.applyDevelopmentOverrides()
	case "staging":
		c.applyStagingOverrides()
	case "production":
		c.applyProductionOverrides()
	}
}

func (c *Config) applyDevelopmentOverrides() {
	c.App.Debug = true
	c.Database.MongoDB.Database = "omegle_dev"
	c.Server.CORS.AllowedOrigins = append(c.Server.CORS.AllowedOrigins, "http://localhost:3000", "http://localhost:3001")
}

func (c *Config) applyStagingOverrides() {
	c.Database.MongoDB.Database = "omegle_staging"
	c.Security.RateLimit.Requests = 200
}

func (c *Config) applyProductionOverrides() {
	c.App.Debug = false
	c.Database.MongoDB.Database = "omegle_production"
	c.Database.MongoDB.SSLEnabled = true
	c.Security.RateLimit.Requests = 50
	c.Server.TLS.Enabled = true
}
