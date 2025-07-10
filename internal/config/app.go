package config

import (
	"os"
	"strconv"
	"strings"
	"time"

	"bro-network/pkg/constants"
)

// AppConfig represents application configuration
type AppConfig struct {
	Name        string `mapstructure:"name"`
	Version     string `mapstructure:"version"`
	Description string `mapstructure:"description"`
	Environment string `mapstructure:"environment"`
	Debug       bool   `mapstructure:"debug"`
	Port        string `mapstructure:"port"`
	Host        string `mapstructure:"host"`
	BaseURL     string `mapstructure:"base_url"`

	// API Configuration
	API APIConfig `mapstructure:"api"`

	// Server Configuration
	Server ServerConfig `mapstructure:"server"`

	// Logging Configuration
	Logging LoggingConfig `mapstructure:"logging"`

	// Security Configuration
	Security SecurityConfig `mapstructure:"security"`

	// Feature Flags
	Features FeatureConfig `mapstructure:"features"`

	// Performance Configuration
	Performance PerformanceConfig `mapstructure:"performance"`

	// Monitoring Configuration
	Monitoring MonitoringConfig `mapstructure:"monitoring"`
}

// APIConfig represents API configuration
type APIConfig struct {
	Version         string        `mapstructure:"version"`
	Prefix          string        `mapstructure:"prefix"`
	AdminPrefix     string        `mapstructure:"admin_prefix"`
	Timeout         time.Duration `mapstructure:"timeout"`
	MaxRequestSize  int64         `mapstructure:"max_request_size"`
	EnableDocs      bool          `mapstructure:"enable_docs"`
	EnableCORS      bool          `mapstructure:"enable_cors"`
	EnableMetrics   bool          `mapstructure:"enable_metrics"`
	EnableProfiling bool          `mapstructure:"enable_profiling"`
}

// ServerConfig represents server configuration
type ServerConfig struct {
	ReadTimeout       time.Duration `mapstructure:"read_timeout"`
	WriteTimeout      time.Duration `mapstructure:"write_timeout"`
	IdleTimeout       time.Duration `mapstructure:"idle_timeout"`
	ShutdownTimeout   time.Duration `mapstructure:"shutdown_timeout"`
	MaxHeaderBytes    int           `mapstructure:"max_header_bytes"`
	EnableKeepAlive   bool          `mapstructure:"enable_keep_alive"`
	EnableCompression bool          `mapstructure:"enable_compression"`
	TrustedProxies    []string      `mapstructure:"trusted_proxies"`
}

// LoggingConfig represents logging configuration
type LoggingConfig struct {
	Level      string `mapstructure:"level"`
	Format     string `mapstructure:"format"`
	Output     string `mapstructure:"output"`
	File       string `mapstructure:"file"`
	MaxSize    int    `mapstructure:"max_size"`
	MaxAge     int    `mapstructure:"max_age"`
	MaxBackups int    `mapstructure:"max_backups"`
	Compress   bool   `mapstructure:"compress"`
	EnableJSON bool   `mapstructure:"enable_json"`
}

// SecurityConfig represents security configuration
type SecurityConfig struct {
	EnableHTTPS        bool     `mapstructure:"enable_https"`
	TLSCertFile        string   `mapstructure:"tls_cert_file"`
	TLSKeyFile         string   `mapstructure:"tls_key_file"`
	SecretKey          string   `mapstructure:"secret_key"`
	EncryptionKey      string   `mapstructure:"encryption_key"`
	AllowedHosts       []string `mapstructure:"allowed_hosts"`
	TrustedDomains     []string `mapstructure:"trusted_domains"`
	EnableSecHeaders   bool     `mapstructure:"enable_security_headers"`
	EnableCSRF         bool     `mapstructure:"enable_csrf"`
	EnableHSTS         bool     `mapstructure:"enable_hsts"`
	ContentSecPolicy   string   `mapstructure:"content_security_policy"`
	FrameOptions       string   `mapstructure:"frame_options"`
	ContentTypeNoSniff bool     `mapstructure:"content_type_no_sniff"`
}

// FeatureConfig represents feature flags configuration
type FeatureConfig struct {
	EnableRegistration    bool `mapstructure:"enable_registration"`
	EnablePasswordReset   bool `mapstructure:"enable_password_reset"`
	EnableEmailVerify     bool `mapstructure:"enable_email_verification"`
	EnableSocialLogin     bool `mapstructure:"enable_social_login"`
	EnableTwoFactor       bool `mapstructure:"enable_two_factor"`
	EnableFileUpload      bool `mapstructure:"enable_file_upload"`
	EnableNotifications   bool `mapstructure:"enable_notifications"`
	EnableWebsockets      bool `mapstructure:"enable_websockets"`
	EnableAnalytics       bool `mapstructure:"enable_analytics"`
	EnableAdvancedSearch  bool `mapstructure:"enable_advanced_search"`
	EnableVideoProcessing bool `mapstructure:"enable_video_processing"`
	EnableRealtimeChat    bool `mapstructure:"enable_realtime_chat"`
	EnableAIModeration    bool `mapstructure:"enable_ai_moderation"`
	EnableStories         bool `mapstructure:"enable_stories"`
	EnableLiveStreaming   bool `mapstructure:"enable_live_streaming"`
	EnableBetaFeatures    bool `mapstructure:"enable_beta_features"`
	MaintenanceMode       bool `mapstructure:"maintenance_mode"`
}

// PerformanceConfig represents performance configuration
type PerformanceConfig struct {
	MaxConcurrency     int           `mapstructure:"max_concurrency"`
	DatabaseMaxConns   int           `mapstructure:"database_max_connections"`
	DatabaseMaxIdle    int           `mapstructure:"database_max_idle"`
	DatabaseTimeout    time.Duration `mapstructure:"database_timeout"`
	CacheEnabled       bool          `mapstructure:"cache_enabled"`
	CacheTimeout       time.Duration `mapstructure:"cache_timeout"`
	CacheMaxItems      int           `mapstructure:"cache_max_items"`
	EnableGZip         bool          `mapstructure:"enable_gzip"`
	EnableETag         bool          `mapstructure:"enable_etag"`
	EnableLastModified bool          `mapstructure:"enable_last_modified"`
}

// MonitoringConfig represents monitoring configuration
type MonitoringConfig struct {
	EnableMetrics      bool   `mapstructure:"enable_metrics"`
	EnableHealthChecks bool   `mapstructure:"enable_health_checks"`
	EnableProfiling    bool   `mapstructure:"enable_profiling"`
	EnableTracing      bool   `mapstructure:"enable_tracing"`
	MetricsPath        string `mapstructure:"metrics_path"`
	HealthPath         string `mapstructure:"health_path"`
	ProfilePath        string `mapstructure:"profile_path"`
	TracingEndpoint    string `mapstructure:"tracing_endpoint"`
	SentryDSN          string `mapstructure:"sentry_dsn"`
}

// LoadAppConfig loads application configuration from environment variables
func LoadAppConfig() *AppConfig {
	return &AppConfig{
		Name:        getEnvString(constants.EnvEnvironment, constants.AppName),
		Version:     constants.AppVersion,
		Description: constants.AppDescription,
		Environment: getEnvString(constants.EnvEnvironment, constants.EnvDevelopment),
		Debug:       getEnvBool("DEBUG", false),
		Port:        getEnvString(constants.EnvPort, "8080"),
		Host:        getEnvString("HOST", "0.0.0.0"),
		BaseURL:     getEnvString("BASE_URL", "http://localhost:8080"),

		API: APIConfig{
			Version:         constants.APIVersion,
			Prefix:          constants.APIPrefix,
			AdminPrefix:     constants.AdminPrefix,
			Timeout:         getEnvDuration("API_TIMEOUT", 30*time.Second),
			MaxRequestSize:  getEnvInt64("API_MAX_REQUEST_SIZE", 32<<20), // 32MB
			EnableDocs:      getEnvBool("API_ENABLE_DOCS", true),
			EnableCORS:      getEnvBool("API_ENABLE_CORS", true),
			EnableMetrics:   getEnvBool("API_ENABLE_METRICS", true),
			EnableProfiling: getEnvBool("API_ENABLE_PROFILING", false),
		},

		Server: ServerConfig{
			ReadTimeout:       getEnvDuration("SERVER_READ_TIMEOUT", 10*time.Second),
			WriteTimeout:      getEnvDuration("SERVER_WRITE_TIMEOUT", 10*time.Second),
			IdleTimeout:       getEnvDuration("SERVER_IDLE_TIMEOUT", 60*time.Second),
			ShutdownTimeout:   getEnvDuration("SERVER_SHUTDOWN_TIMEOUT", 30*time.Second),
			MaxHeaderBytes:    getEnvInt("SERVER_MAX_HEADER_BYTES", 1<<20), // 1MB
			EnableKeepAlive:   getEnvBool("SERVER_ENABLE_KEEP_ALIVE", true),
			EnableCompression: getEnvBool("SERVER_ENABLE_COMPRESSION", true),
			TrustedProxies:    getEnvStringSlice("SERVER_TRUSTED_PROXIES", []string{}),
		},

		Logging: LoggingConfig{
			Level:      getEnvString(constants.EnvLogLevel, "info"),
			Format:     getEnvString("LOG_FORMAT", "json"),
			Output:     getEnvString("LOG_OUTPUT", "stdout"),
			File:       getEnvString("LOG_FILE", ""),
			MaxSize:    getEnvInt("LOG_MAX_SIZE", 100),
			MaxAge:     getEnvInt("LOG_MAX_AGE", 28),
			MaxBackups: getEnvInt("LOG_MAX_BACKUPS", 3),
			Compress:   getEnvBool("LOG_COMPRESS", true),
			EnableJSON: getEnvBool("LOG_ENABLE_JSON", true),
		},

		Security: SecurityConfig{
			EnableHTTPS:        getEnvBool("SECURITY_ENABLE_HTTPS", false),
			TLSCertFile:        getEnvString("TLS_CERT_FILE", ""),
			TLSKeyFile:         getEnvString("TLS_KEY_FILE", ""),
			SecretKey:          getEnvString("SECRET_KEY", "your-secret-key-change-this"),
			EncryptionKey:      getEnvString(constants.EnvEncryptionKey, "your-encryption-key-change-this"),
			AllowedHosts:       getEnvStringSlice("SECURITY_ALLOWED_HOSTS", []string{}),
			TrustedDomains:     getEnvStringSlice("SECURITY_TRUSTED_DOMAINS", []string{}),
			EnableSecHeaders:   getEnvBool("SECURITY_ENABLE_HEADERS", true),
			EnableCSRF:         getEnvBool("SECURITY_ENABLE_CSRF", true),
			EnableHSTS:         getEnvBool("SECURITY_ENABLE_HSTS", false),
			ContentSecPolicy:   getEnvString("SECURITY_CSP", "default-src 'self'"),
			FrameOptions:       getEnvString("SECURITY_FRAME_OPTIONS", "DENY"),
			ContentTypeNoSniff: getEnvBool("SECURITY_CONTENT_TYPE_NO_SNIFF", true),
		},

		Features: FeatureConfig{
			EnableRegistration:    getEnvBool("FEATURE_REGISTRATION", true),
			EnablePasswordReset:   getEnvBool("FEATURE_PASSWORD_RESET", true),
			EnableEmailVerify:     getEnvBool("FEATURE_EMAIL_VERIFICATION", true),
			EnableSocialLogin:     getEnvBool("FEATURE_SOCIAL_LOGIN", false),
			EnableTwoFactor:       getEnvBool("FEATURE_TWO_FACTOR", false),
			EnableFileUpload:      getEnvBool("FEATURE_FILE_UPLOAD", true),
			EnableNotifications:   getEnvBool("FEATURE_NOTIFICATIONS", true),
			EnableWebsockets:      getEnvBool("FEATURE_WEBSOCKETS", true),
			EnableAnalytics:       getEnvBool("FEATURE_ANALYTICS", true),
			EnableAdvancedSearch:  getEnvBool("FEATURE_ADVANCED_SEARCH", true),
			EnableVideoProcessing: getEnvBool("FEATURE_VIDEO_PROCESSING", false),
			EnableRealtimeChat:    getEnvBool("FEATURE_REALTIME_CHAT", true),
			EnableAIModeration:    getEnvBool("FEATURE_AI_MODERATION", false),
			EnableStories:         getEnvBool("FEATURE_STORIES", false),
			EnableLiveStreaming:   getEnvBool("FEATURE_LIVE_STREAMING", false),
			EnableBetaFeatures:    getEnvBool("FEATURE_BETA_FEATURES", false),
			MaintenanceMode:       getEnvBool("MAINTENANCE_MODE", false),
		},

		Performance: PerformanceConfig{
			MaxConcurrency:     getEnvInt("PERFORMANCE_MAX_CONCURRENCY", 1000),
			DatabaseMaxConns:   getEnvInt("DB_MAX_CONNECTIONS", 100),
			DatabaseMaxIdle:    getEnvInt("DB_MAX_IDLE", 10),
			DatabaseTimeout:    getEnvDuration("DB_TIMEOUT", 30*time.Second),
			CacheEnabled:       getEnvBool("CACHE_ENABLED", true),
			CacheTimeout:       getEnvDuration("CACHE_TIMEOUT", 24*time.Hour),
			CacheMaxItems:      getEnvInt("CACHE_MAX_ITEMS", 1000),
			EnableGZip:         getEnvBool("PERFORMANCE_ENABLE_GZIP", true),
			EnableETag:         getEnvBool("PERFORMANCE_ENABLE_ETAG", true),
			EnableLastModified: getEnvBool("PERFORMANCE_ENABLE_LAST_MODIFIED", true),
		},

		Monitoring: MonitoringConfig{
			EnableMetrics:      getEnvBool("MONITORING_ENABLE_METRICS", true),
			EnableHealthChecks: getEnvBool("MONITORING_ENABLE_HEALTH_CHECKS", true),
			EnableProfiling:    getEnvBool("MONITORING_ENABLE_PROFILING", false),
			EnableTracing:      getEnvBool("MONITORING_ENABLE_TRACING", false),
			MetricsPath:        getEnvString("MONITORING_METRICS_PATH", "/metrics"),
			HealthPath:         getEnvString("MONITORING_HEALTH_PATH", "/health"),
			ProfilePath:        getEnvString("MONITORING_PROFILE_PATH", "/debug/pprof"),
			TracingEndpoint:    getEnvString("MONITORING_TRACING_ENDPOINT", ""),
			SentryDSN:          getEnvString("SENTRY_DSN", ""),
		},
	}
}

// IsProduction returns true if the application is running in production environment
func (c *AppConfig) IsProduction() bool {
	return c.Environment == constants.EnvProduction
}

// IsDevelopment returns true if the application is running in development environment
func (c *AppConfig) IsDevelopment() bool {
	return c.Environment == constants.EnvDevelopment
}

// IsStaging returns true if the application is running in staging environment
func (c *AppConfig) IsStaging() bool {
	return c.Environment == constants.EnvStaging
}

// IsTesting returns true if the application is running in testing environment
func (c *AppConfig) IsTesting() bool {
	return c.Environment == constants.EnvTesting
}

// GetAddress returns the server address (host:port)
func (c *AppConfig) GetAddress() string {
	return c.Host + ":" + c.Port
}

// Helper functions for environment variable parsing

func getEnvString(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil {
			return parsed
		}
	}
	return defaultValue
}

func getEnvInt64(key string, defaultValue int64) int64 {
	if value := os.Getenv(key); value != "" {
		if parsed, err := strconv.ParseInt(value, 10, 64); err == nil {
			return parsed
		}
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if parsed, err := strconv.ParseBool(value); err == nil {
			return parsed
		}
	}
	return defaultValue
}

func getEnvDuration(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if parsed, err := time.ParseDuration(value); err == nil {
			return parsed
		}
	}
	return defaultValue
}

func getEnvStringSlice(key string, defaultValue []string) []string {
	if value := os.Getenv(key); value != "" {
		return strings.Split(value, ",")
	}
	return defaultValue
}
