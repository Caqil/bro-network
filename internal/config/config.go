package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/spf13/viper"
)

// Config represents the main application configuration
type Config struct {
	App      *AppConfig      `mapstructure:"app"`
	Database *DatabaseConfig `mapstructure:"database"`
	Redis    *RedisConfig    `mapstructure:"redis"`
	AWS      *AWSConfig      `mapstructure:"aws"`
	SMTP     *SMTPConfig     `mapstructure:"smtp"`
	Auth     *AuthConfig     `mapstructure:"auth"`
	Upload   *UploadConfig   `mapstructure:"upload"`
	Social   *SocialConfig   `mapstructure:"social"`
	Payment  *PaymentConfig  `mapstructure:"payment"`
	Push     *PushConfig     `mapstructure:"push"`
	Search   *SearchConfig   `mapstructure:"search"`
	Cache    *CacheConfig    `mapstructure:"cache"`
	Queue    *QueueConfig    `mapstructure:"queue"`
	Storage  *StorageConfig  `mapstructure:"storage"`
}

// AuthConfig represents authentication configuration
type AuthConfig struct {
	JWTSecret             string `mapstructure:"jwt_secret"`
	JWTExpiryHours        int    `mapstructure:"jwt_expiry_hours"`
	RefreshTokenExpiry    int    `mapstructure:"refresh_token_expiry_days"`
	PasswordMinLength     int    `mapstructure:"password_min_length"`
	MaxLoginAttempts      int    `mapstructure:"max_login_attempts"`
	LockoutDuration       int    `mapstructure:"lockout_duration_minutes"`
	SessionTimeout        int    `mapstructure:"session_timeout_minutes"`
	EnableTwoFactor       bool   `mapstructure:"enable_two_factor"`
	TwoFactorIssuer       string `mapstructure:"two_factor_issuer"`
	EnableSocialLogin     bool   `mapstructure:"enable_social_login"`
	GoogleClientID        string `mapstructure:"google_client_id"`
	GoogleClientSecret    string `mapstructure:"google_client_secret"`
	FacebookAppID         string `mapstructure:"facebook_app_id"`
	FacebookAppSecret     string `mapstructure:"facebook_app_secret"`
	TwitterConsumerKey    string `mapstructure:"twitter_consumer_key"`
	TwitterConsumerSecret string `mapstructure:"twitter_consumer_secret"`
	GithubClientID        string `mapstructure:"github_client_id"`
	GithubClientSecret    string `mapstructure:"github_client_secret"`
	LinkedInClientID      string `mapstructure:"linkedin_client_id"`
	LinkedInClientSecret  string `mapstructure:"linkedin_client_secret"`
}

// UploadConfig represents file upload configuration
type UploadConfig struct {
	MaxFileSize       int64    `mapstructure:"max_file_size"`
	AllowedExtensions []string `mapstructure:"allowed_extensions"`
	AllowedMimeTypes  []string `mapstructure:"allowed_mime_types"`
	UploadPath        string   `mapstructure:"upload_path"`
	TempPath          string   `mapstructure:"temp_path"`
	EnableS3          bool     `mapstructure:"enable_s3"`
	EnableResize      bool     `mapstructure:"enable_resize"`
	ImageQuality      int      `mapstructure:"image_quality"`
	ThumbnailSize     int      `mapstructure:"thumbnail_size"`
	MaxImageWidth     int      `mapstructure:"max_image_width"`
	MaxImageHeight    int      `mapstructure:"max_image_height"`
	EnableWatermark   bool     `mapstructure:"enable_watermark"`
	WatermarkPath     string   `mapstructure:"watermark_path"`
	WatermarkOpacity  float64  `mapstructure:"watermark_opacity"`
}

// SocialConfig represents social media integration configuration
type SocialConfig struct {
	EnableSharing     bool   `mapstructure:"enable_sharing"`
	ShareAPIKey       string `mapstructure:"share_api_key"`
	FacebookAppID     string `mapstructure:"facebook_app_id"`
	TwitterAPIKey     string `mapstructure:"twitter_api_key"`
	TwitterAPISecret  string `mapstructure:"twitter_api_secret"`
	LinkedInAPIKey    string `mapstructure:"linkedin_api_key"`
	LinkedInAPISecret string `mapstructure:"linkedin_api_secret"`
	InstagramClientID string `mapstructure:"instagram_client_id"`
	TikTokClientID    string `mapstructure:"tiktok_client_id"`
	SnapchatClientID  string `mapstructure:"snapchat_client_id"`
	PinterestAppID    string `mapstructure:"pinterest_app_id"`
	RedditClientID    string `mapstructure:"reddit_client_id"`
	TumblrConsumerKey string `mapstructure:"tumblr_consumer_key"`
}

// PaymentConfig represents payment processing configuration
type PaymentConfig struct {
	EnablePayments       bool   `mapstructure:"enable_payments"`
	Provider             string `mapstructure:"provider"` // stripe, paypal, square
	StripePublishableKey string `mapstructure:"stripe_publishable_key"`
	StripeSecretKey      string `mapstructure:"stripe_secret_key"`
	StripeWebhookSecret  string `mapstructure:"stripe_webhook_secret"`
	PayPalClientID       string `mapstructure:"paypal_client_id"`
	PayPalClientSecret   string `mapstructure:"paypal_client_secret"`
	PayPalMode           string `mapstructure:"paypal_mode"` // sandbox, live
	Currency             string `mapstructure:"currency"`
	EnableSubscriptions  bool   `mapstructure:"enable_subscriptions"`
	TrialPeriodDays      int    `mapstructure:"trial_period_days"`
}

// PushConfig represents push notification configuration
type PushConfig struct {
	EnablePush          bool   `mapstructure:"enable_push"`
	FCMServerKey        string `mapstructure:"fcm_server_key"`
	FCMSenderID         string `mapstructure:"fcm_sender_id"`
	APNSCertFile        string `mapstructure:"apns_cert_file"`
	APNSKeyFile         string `mapstructure:"apns_key_file"`
	APNSKeyID           string `mapstructure:"apns_key_id"`
	APNSTeamID          string `mapstructure:"apns_team_id"`
	APNSBundleID        string `mapstructure:"apns_bundle_id"`
	APNSProduction      bool   `mapstructure:"apns_production"`
	WebPushVAPIDPublic  string `mapstructure:"web_push_vapid_public"`
	WebPushVAPIDPrivate string `mapstructure:"web_push_vapid_private"`
	WebPushContact      string `mapstructure:"web_push_contact"`
}

// SearchConfig represents search engine configuration
type SearchConfig struct {
	Provider        string `mapstructure:"provider"` // elasticsearch, mongodb, algolia
	ElasticURL      string `mapstructure:"elastic_url"`
	ElasticUsername string `mapstructure:"elastic_username"`
	ElasticPassword string `mapstructure:"elastic_password"`
	ElasticIndex    string `mapstructure:"elastic_index"`
	AlgoliaAppID    string `mapstructure:"algolia_app_id"`
	AlgoliaAPIKey   string `mapstructure:"algolia_api_key"`
	AlgoliaIndex    string `mapstructure:"algolia_index"`
	MaxResults      int    `mapstructure:"max_results"`
	EnableFuzzy     bool   `mapstructure:"enable_fuzzy"`
	FuzzyDistance   int    `mapstructure:"fuzzy_distance"`
}

// CacheConfig represents caching configuration
type CacheConfig struct {
	Provider      string `mapstructure:"provider"` // redis, memory, memcached
	DefaultTTL    int    `mapstructure:"default_ttl_seconds"`
	MaxKeys       int    `mapstructure:"max_keys"`
	EnableMetrics bool   `mapstructure:"enable_metrics"`
	Prefix        string `mapstructure:"prefix"`
}

// QueueConfig represents queue system configuration
type QueueConfig struct {
	Provider      string `mapstructure:"provider"` // redis, rabbitmq, sqs
	Workers       int    `mapstructure:"workers"`
	MaxRetries    int    `mapstructure:"max_retries"`
	RetryDelay    int    `mapstructure:"retry_delay_seconds"`
	QueuePrefix   string `mapstructure:"queue_prefix"`
	EnableDLQ     bool   `mapstructure:"enable_dlq"`
	DLQName       string `mapstructure:"dlq_name"`
	RabbitMQURL   string `mapstructure:"rabbitmq_url"`
	RabbitMQVHost string `mapstructure:"rabbitmq_vhost"`
}

// StorageConfig represents storage configuration
type StorageConfig struct {
	Provider        string `mapstructure:"provider"` // local, s3, gcs, azure
	LocalPath       string `mapstructure:"local_path"`
	PublicURL       string `mapstructure:"public_url"`
	EnableCDN       bool   `mapstructure:"enable_cdn"`
	CDNBaseURL      string `mapstructure:"cdn_base_url"`
	EnableSignedURL bool   `mapstructure:"enable_signed_url"`
	SignedURLExpiry int    `mapstructure:"signed_url_expiry_hours"`
}

var (
	instance *Config
	once     sync.Once
)

// LoadConfig loads configuration from environment variables and config files
func LoadConfig() (*Config, error) {
	var err error
	once.Do(func() {
		instance, err = loadConfig()
	})
	return instance, err
}

// GetConfig returns the singleton configuration instance
func GetConfig() *Config {
	if instance == nil {
		config, err := LoadConfig()
		if err != nil {
			panic(fmt.Sprintf("Failed to load configuration: %v", err))
		}
		return config
	}
	return instance
}

// loadConfig performs the actual configuration loading
func loadConfig() (*Config, error) {
	// Initialize Viper
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")

	// Add config paths
	viper.AddConfigPath("./config")
	viper.AddConfigPath("./configs")
	viper.AddConfigPath(".")
	viper.AddConfigPath("/etc/bro-network/")

	// Set environment variable prefix
	viper.SetEnvPrefix("BRO")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	// Set defaults
	setDefaults()

	// Try to read config file (optional)
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("error reading config file: %w", err)
		}
		// Config file not found, use environment variables and defaults
	}

	// Load configuration from environment variables
	config := &Config{
		App:      LoadAppConfig(),
		Database: LoadDatabaseConfig(),
		Redis:    LoadRedisConfig(),
		AWS:      LoadAWSConfig(),
		SMTP:     LoadSMTPConfig(),
		Auth:     LoadAuthConfig(),
		Upload:   LoadUploadConfig(),
		Social:   LoadSocialConfig(),
		Payment:  LoadPaymentConfig(),
		Push:     LoadPushConfig(),
		Search:   LoadSearchConfig(),
		Cache:    LoadCacheConfig(),
		Queue:    LoadQueueConfig(),
		Storage:  LoadStorageConfig(),
	}

	// Validate configuration
	if err := validateConfig(config); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	return config, nil
}

// setDefaults sets default configuration values
func setDefaults() {
	// App defaults
	viper.SetDefault("app.name", "Bro Network")
	viper.SetDefault("app.version", "1.0.0")
	viper.SetDefault("app.environment", "development")
	viper.SetDefault("app.port", "8080")
	viper.SetDefault("app.host", "0.0.0.0")
	viper.SetDefault("app.debug", false)

	// Database defaults
	viper.SetDefault("database.host", "localhost")
	viper.SetDefault("database.port", 27017)
	viper.SetDefault("database.name", "bro_network")
	viper.SetDefault("database.timeout", 30)
	viper.SetDefault("database.max_pool_size", 100)
	viper.SetDefault("database.min_pool_size", 10)

	// Redis defaults
	viper.SetDefault("redis.host", "localhost")
	viper.SetDefault("redis.port", 6379)
	viper.SetDefault("redis.db", 0)
	viper.SetDefault("redis.max_retries", 3)
	viper.SetDefault("redis.pool_size", 10)

	// Auth defaults
	viper.SetDefault("auth.jwt_expiry_hours", 24)
	viper.SetDefault("auth.refresh_token_expiry_days", 30)
	viper.SetDefault("auth.password_min_length", 8)
	viper.SetDefault("auth.max_login_attempts", 5)
	viper.SetDefault("auth.lockout_duration_minutes", 15)
	viper.SetDefault("auth.session_timeout_minutes", 60)

	// Upload defaults
	viper.SetDefault("upload.max_file_size", 10*1024*1024) // 10MB
	viper.SetDefault("upload.upload_path", "./uploads")
	viper.SetDefault("upload.temp_path", "./temp")
	viper.SetDefault("upload.image_quality", 85)
	viper.SetDefault("upload.thumbnail_size", 200)
	viper.SetDefault("upload.max_image_width", 2048)
	viper.SetDefault("upload.max_image_height", 2048)
}

// LoadAuthConfig loads authentication configuration
func LoadAuthConfig() *AuthConfig {
	return &AuthConfig{
		JWTSecret:             getEnvString("JWT_SECRET", "your-super-secret-jwt-key-change-this"),
		JWTExpiryHours:        getEnvInt("JWT_EXPIRY_HOURS", 24),
		RefreshTokenExpiry:    getEnvInt("REFRESH_TOKEN_EXPIRY_DAYS", 30),
		PasswordMinLength:     getEnvInt("PASSWORD_MIN_LENGTH", 8),
		MaxLoginAttempts:      getEnvInt("MAX_LOGIN_ATTEMPTS", 5),
		LockoutDuration:       getEnvInt("LOCKOUT_DURATION_MINUTES", 15),
		SessionTimeout:        getEnvInt("SESSION_TIMEOUT_MINUTES", 60),
		EnableTwoFactor:       getEnvBool("ENABLE_TWO_FACTOR", false),
		TwoFactorIssuer:       getEnvString("TWO_FACTOR_ISSUER", "Bro Network"),
		EnableSocialLogin:     getEnvBool("ENABLE_SOCIAL_LOGIN", false),
		GoogleClientID:        getEnvString("GOOGLE_CLIENT_ID", ""),
		GoogleClientSecret:    getEnvString("GOOGLE_CLIENT_SECRET", ""),
		FacebookAppID:         getEnvString("FACEBOOK_APP_ID", ""),
		FacebookAppSecret:     getEnvString("FACEBOOK_APP_SECRET", ""),
		TwitterConsumerKey:    getEnvString("TWITTER_CONSUMER_KEY", ""),
		TwitterConsumerSecret: getEnvString("TWITTER_CONSUMER_SECRET", ""),
		GithubClientID:        getEnvString("GITHUB_CLIENT_ID", ""),
		GithubClientSecret:    getEnvString("GITHUB_CLIENT_SECRET", ""),
		LinkedInClientID:      getEnvString("LINKEDIN_CLIENT_ID", ""),
		LinkedInClientSecret:  getEnvString("LINKEDIN_CLIENT_SECRET", ""),
	}
}

// LoadUploadConfig loads upload configuration
func LoadUploadConfig() *UploadConfig {
	return &UploadConfig{
		MaxFileSize:       getEnvInt64("UPLOAD_MAX_FILE_SIZE", 10*1024*1024), // 10MB
		AllowedExtensions: getEnvStringSlice("UPLOAD_ALLOWED_EXTENSIONS", []string{".jpg", ".jpeg", ".png", ".gif", ".pdf", ".txt"}),
		AllowedMimeTypes:  getEnvStringSlice("UPLOAD_ALLOWED_MIME_TYPES", []string{"image/jpeg", "image/png", "image/gif", "application/pdf", "text/plain"}),
		UploadPath:        getEnvString("UPLOAD_PATH", "./uploads"),
		TempPath:          getEnvString("UPLOAD_TEMP_PATH", "./temp"),
		EnableS3:          getEnvBool("UPLOAD_ENABLE_S3", false),
		EnableResize:      getEnvBool("UPLOAD_ENABLE_RESIZE", true),
		ImageQuality:      getEnvInt("UPLOAD_IMAGE_QUALITY", 85),
		ThumbnailSize:     getEnvInt("UPLOAD_THUMBNAIL_SIZE", 200),
		MaxImageWidth:     getEnvInt("UPLOAD_MAX_IMAGE_WIDTH", 2048),
		MaxImageHeight:    getEnvInt("UPLOAD_MAX_IMAGE_HEIGHT", 2048),
		EnableWatermark:   getEnvBool("UPLOAD_ENABLE_WATERMARK", false),
		WatermarkPath:     getEnvString("UPLOAD_WATERMARK_PATH", ""),
		WatermarkOpacity:  getEnvFloat64("UPLOAD_WATERMARK_OPACITY", 0.5),
	}
}

// LoadSocialConfig loads social media integration configuration
func LoadSocialConfig() *SocialConfig {
	return &SocialConfig{
		EnableSharing:     getEnvBool("SOCIAL_ENABLE_SHARING", true),
		ShareAPIKey:       getEnvString("SOCIAL_SHARE_API_KEY", ""),
		FacebookAppID:     getEnvString("SOCIAL_FACEBOOK_APP_ID", ""),
		TwitterAPIKey:     getEnvString("SOCIAL_TWITTER_API_KEY", ""),
		TwitterAPISecret:  getEnvString("SOCIAL_TWITTER_API_SECRET", ""),
		LinkedInAPIKey:    getEnvString("SOCIAL_LINKEDIN_API_KEY", ""),
		LinkedInAPISecret: getEnvString("SOCIAL_LINKEDIN_API_SECRET", ""),
		InstagramClientID: getEnvString("SOCIAL_INSTAGRAM_CLIENT_ID", ""),
		TikTokClientID:    getEnvString("SOCIAL_TIKTOK_CLIENT_ID", ""),
		SnapchatClientID:  getEnvString("SOCIAL_SNAPCHAT_CLIENT_ID", ""),
		PinterestAppID:    getEnvString("SOCIAL_PINTEREST_APP_ID", ""),
		RedditClientID:    getEnvString("SOCIAL_REDDIT_CLIENT_ID", ""),
		TumblrConsumerKey: getEnvString("SOCIAL_TUMBLR_CONSUMER_KEY", ""),
	}
}

// LoadPaymentConfig loads payment processing configuration
func LoadPaymentConfig() *PaymentConfig {
	return &PaymentConfig{
		EnablePayments:       getEnvBool("PAYMENT_ENABLE_PAYMENTS", false),
		Provider:             getEnvString("PAYMENT_PROVIDER", "stripe"),
		StripePublishableKey: getEnvString("STRIPE_PUBLISHABLE_KEY", ""),
		StripeSecretKey:      getEnvString("STRIPE_SECRET_KEY", ""),
		StripeWebhookSecret:  getEnvString("STRIPE_WEBHOOK_SECRET", ""),
		PayPalClientID:       getEnvString("PAYPAL_CLIENT_ID", ""),
		PayPalClientSecret:   getEnvString("PAYPAL_CLIENT_SECRET", ""),
		PayPalMode:           getEnvString("PAYPAL_MODE", "sandbox"),
		Currency:             getEnvString("PAYMENT_CURRENCY", "USD"),
		EnableSubscriptions:  getEnvBool("PAYMENT_ENABLE_SUBSCRIPTIONS", false),
		TrialPeriodDays:      getEnvInt("PAYMENT_TRIAL_PERIOD_DAYS", 7),
	}
}

// LoadPushConfig loads push notification configuration
func LoadPushConfig() *PushConfig {
	return &PushConfig{
		EnablePush:          getEnvBool("PUSH_ENABLE_PUSH", false),
		FCMServerKey:        getEnvString("FCM_SERVER_KEY", ""),
		FCMSenderID:         getEnvString("FCM_SENDER_ID", ""),
		APNSCertFile:        getEnvString("APNS_CERT_FILE", ""),
		APNSKeyFile:         getEnvString("APNS_KEY_FILE", ""),
		APNSKeyID:           getEnvString("APNS_KEY_ID", ""),
		APNSTeamID:          getEnvString("APNS_TEAM_ID", ""),
		APNSBundleID:        getEnvString("APNS_BUNDLE_ID", ""),
		APNSProduction:      getEnvBool("APNS_PRODUCTION", false),
		WebPushVAPIDPublic:  getEnvString("WEB_PUSH_VAPID_PUBLIC", ""),
		WebPushVAPIDPrivate: getEnvString("WEB_PUSH_VAPID_PRIVATE", ""),
		WebPushContact:      getEnvString("WEB_PUSH_CONTACT", ""),
	}
}

// LoadSearchConfig loads search engine configuration
func LoadSearchConfig() *SearchConfig {
	return &SearchConfig{
		Provider:        getEnvString("SEARCH_PROVIDER", "mongodb"),
		ElasticURL:      getEnvString("ELASTICSEARCH_URL", "http://localhost:9200"),
		ElasticUsername: getEnvString("ELASTICSEARCH_USERNAME", ""),
		ElasticPassword: getEnvString("ELASTICSEARCH_PASSWORD", ""),
		ElasticIndex:    getEnvString("ELASTICSEARCH_INDEX", "bro_network"),
		AlgoliaAppID:    getEnvString("ALGOLIA_APP_ID", ""),
		AlgoliaAPIKey:   getEnvString("ALGOLIA_API_KEY", ""),
		AlgoliaIndex:    getEnvString("ALGOLIA_INDEX", "bro_network"),
		MaxResults:      getEnvInt("SEARCH_MAX_RESULTS", 50),
		EnableFuzzy:     getEnvBool("SEARCH_ENABLE_FUZZY", true),
		FuzzyDistance:   getEnvInt("SEARCH_FUZZY_DISTANCE", 2),
	}
}

// LoadCacheConfig loads caching configuration
func LoadCacheConfig() *CacheConfig {
	return &CacheConfig{
		Provider:      getEnvString("CACHE_PROVIDER", "redis"),
		DefaultTTL:    getEnvInt("CACHE_DEFAULT_TTL_SECONDS", 3600),
		MaxKeys:       getEnvInt("CACHE_MAX_KEYS", 10000),
		EnableMetrics: getEnvBool("CACHE_ENABLE_METRICS", true),
		Prefix:        getEnvString("CACHE_PREFIX", "bro_network:"),
	}
}

// LoadQueueConfig loads queue system configuration
func LoadQueueConfig() *QueueConfig {
	return &QueueConfig{
		Provider:      getEnvString("QUEUE_PROVIDER", "redis"),
		Workers:       getEnvInt("QUEUE_WORKERS", 5),
		MaxRetries:    getEnvInt("QUEUE_MAX_RETRIES", 3),
		RetryDelay:    getEnvInt("QUEUE_RETRY_DELAY_SECONDS", 60),
		QueuePrefix:   getEnvString("QUEUE_PREFIX", "bro_network:queue:"),
		EnableDLQ:     getEnvBool("QUEUE_ENABLE_DLQ", true),
		DLQName:       getEnvString("QUEUE_DLQ_NAME", "dead_letter_queue"),
		RabbitMQURL:   getEnvString("RABBITMQ_URL", "amqp://guest:guest@localhost:5672/"),
		RabbitMQVHost: getEnvString("RABBITMQ_VHOST", "/"),
	}
}

// LoadStorageConfig loads storage configuration
func LoadStorageConfig() *StorageConfig {
	return &StorageConfig{
		Provider:        getEnvString("STORAGE_PROVIDER", "local"),
		LocalPath:       getEnvString("STORAGE_LOCAL_PATH", "./storage"),
		PublicURL:       getEnvString("STORAGE_PUBLIC_URL", "http://localhost:8080/files"),
		EnableCDN:       getEnvBool("STORAGE_ENABLE_CDN", false),
		CDNBaseURL:      getEnvString("STORAGE_CDN_BASE_URL", ""),
		EnableSignedURL: getEnvBool("STORAGE_ENABLE_SIGNED_URL", false),
		SignedURLExpiry: getEnvInt("STORAGE_SIGNED_URL_EXPIRY_HOURS", 24),
	}
}

// validateConfig validates the loaded configuration
func validateConfig(config *Config) error {
	// Validate required fields
	if config.App.Port == "" {
		return fmt.Errorf("app port is required")
	}

	if config.Database.Host == "" {
		return fmt.Errorf("database host is required")
	}

	if config.Auth.JWTSecret == "" || config.Auth.JWTSecret == "your-super-secret-jwt-key-change-this" {
		return fmt.Errorf("JWT secret must be set and changed from default")
	}

	// Validate database configuration
	if err := config.Database.ValidateDatabaseConfig(); err != nil {
		return fmt.Errorf("database config validation failed: %w", err)
	}

	// Validate AWS configuration if S3 is enabled
	if config.Upload.EnableS3 {
		if err := config.AWS.ValidateAWSConfig(); err != nil {
			return fmt.Errorf("AWS config validation failed: %w", err)
		}
	}

	// Validate SMTP configuration if email features are enabled
	if config.App.Features.EnableEmailVerify || config.App.Features.EnablePasswordReset {
		if err := config.SMTP.ValidateSMTPConfig(); err != nil {
			return fmt.Errorf("SMTP config validation failed: %w", err)
		}
	}

	// Validate upload paths
	if err := validateUploadPaths(config.Upload); err != nil {
		return fmt.Errorf("upload config validation failed: %w", err)
	}

	return nil
}

// validateUploadPaths validates upload directory paths
func validateUploadPaths(uploadConfig *UploadConfig) error {
	// Ensure upload directories exist
	paths := []string{uploadConfig.UploadPath, uploadConfig.TempPath}

	for _, path := range paths {
		if path != "" {
			// Create directory if it doesn't exist
			if err := os.MkdirAll(path, 0755); err != nil {
				return fmt.Errorf("failed to create directory %s: %w", path, err)
			}

			// Check if directory is writable
			testFile := filepath.Join(path, ".write_test")
			if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
				return fmt.Errorf("directory %s is not writable: %w", path, err)
			}
			os.Remove(testFile)
		}
	}

	return nil
}

// GetConfigFromViper gets configuration value from viper
func GetConfigFromViper(key string) interface{} {
	return viper.Get(key)
}

// GetStringFromViper gets string configuration value from viper
func GetStringFromViper(key string) string {
	return viper.GetString(key)
}

// GetIntFromViper gets integer configuration value from viper
func GetIntFromViper(key string) int {
	return viper.GetInt(key)
}

// GetBoolFromViper gets boolean configuration value from viper
func GetBoolFromViper(key string) bool {
	return viper.GetBool(key)
}

// GetStringSliceFromViper gets string slice configuration value from viper
func GetStringSliceFromViper(key string) []string {
	return viper.GetStringSlice(key)
}

// ReloadConfig reloads configuration from file and environment
func ReloadConfig() (*Config, error) {
	// Reset the singleton
	once = sync.Once{}
	instance = nil

	// Reload configuration
	return LoadConfig()
}

// PrintConfig prints the current configuration (without sensitive data)
func PrintConfig(config *Config) {
	fmt.Println("=== Application Configuration ===")
	fmt.Printf("App Name: %s\n", config.App.Name)
	fmt.Printf("Version: %s\n", config.App.Version)
	fmt.Printf("Environment: %s\n", config.App.Environment)
	fmt.Printf("Port: %s\n", config.App.Port)
	fmt.Printf("Debug: %v\n", config.App.Debug)

	fmt.Println("\n=== Database Configuration ===")
	fmt.Printf("Host: %s\n", config.Database.Host)
	fmt.Printf("Port: %d\n", config.Database.Port)
	fmt.Printf("Database: %s\n", config.Database.Name)
	fmt.Printf("SSL: %v\n", config.Database.SSL)

	fmt.Println("\n=== Redis Configuration ===")
	fmt.Printf("Host: %s\n", config.Redis.Host)
	fmt.Printf("Port: %d\n", config.Redis.Port)
	fmt.Printf("Database: %d\n", config.Redis.DB)

	fmt.Println("\n=== Features Configuration ===")
	fmt.Printf("Registration: %v\n", config.App.Features.EnableRegistration)
	fmt.Printf("Email Verification: %v\n", config.App.Features.EnableEmailVerify)
	fmt.Printf("Social Login: %v\n", config.App.Features.EnableSocialLogin)
	fmt.Printf("File Upload: %v\n", config.App.Features.EnableFileUpload)
	fmt.Printf("Notifications: %v\n", config.App.Features.EnableNotifications)

	fmt.Println("\n=== Storage Configuration ===")
	fmt.Printf("Provider: %s\n", config.Storage.Provider)
	fmt.Printf("Upload Path: %s\n", config.Upload.UploadPath)
	fmt.Printf("Max File Size: %d bytes\n", config.Upload.MaxFileSize)

	// Don't print sensitive information like secrets, passwords, etc.
}
