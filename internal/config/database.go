package config

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"bro-network/pkg/constants"
)

// DatabaseConfig represents database configuration
type DatabaseConfig struct {
	// Connection settings
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
	Name     string `mapstructure:"name"`
	URI      string `mapstructure:"uri"`

	// SSL/TLS settings
	SSL                bool   `mapstructure:"ssl"`
	SSLMode            string `mapstructure:"ssl_mode"`
	SSLCert            string `mapstructure:"ssl_cert"`
	SSLKey             string `mapstructure:"ssl_key"`
	SSLRootCert        string `mapstructure:"ssl_root_cert"`
	InsecureSkipVerify bool   `mapstructure:"insecure_skip_verify"`

	// Connection pool settings
	MaxPoolSize            int           `mapstructure:"max_pool_size"`
	MinPoolSize            int           `mapstructure:"min_pool_size"`
	MaxConnIdleTime        time.Duration `mapstructure:"max_conn_idle_time"`
	MaxConnLifetime        time.Duration `mapstructure:"max_conn_lifetime"`
	ConnectTimeout         time.Duration `mapstructure:"connect_timeout"`
	SocketTimeout          time.Duration `mapstructure:"socket_timeout"`
	ServerSelectionTimeout time.Duration `mapstructure:"server_selection_timeout"`

	// Retry settings
	RetryWrites   bool          `mapstructure:"retry_writes"`
	RetryReads    bool          `mapstructure:"retry_reads"`
	MaxRetries    int           `mapstructure:"max_retries"`
	RetryInterval time.Duration `mapstructure:"retry_interval"`

	// Read/Write preferences
	ReadPreference     string   `mapstructure:"read_preference"`
	ReadConcern        string   `mapstructure:"read_concern"`
	WriteConcern       string   `mapstructure:"write_concern"`
	ReadPreferenceTags []string `mapstructure:"read_preference_tags"`

	// Advanced settings
	AppName       string   `mapstructure:"app_name"`
	ReplicaSet    string   `mapstructure:"replica_set"`
	AuthSource    string   `mapstructure:"auth_source"`
	AuthMechanism string   `mapstructure:"auth_mechanism"`
	Compressors   []string `mapstructure:"compressors"`
	ZlibLevel     int      `mapstructure:"zlib_level"`
	ZstdLevel     int      `mapstructure:"zstd_level"`

	// Monitoring and logging
	EnableMonitoring   bool          `mapstructure:"enable_monitoring"`
	EnableSlowQueries  bool          `mapstructure:"enable_slow_queries"`
	SlowQueryThreshold time.Duration `mapstructure:"slow_query_threshold"`
	LogLevel           string        `mapstructure:"log_level"`

	// Database-specific settings
	Journal          bool          `mapstructure:"journal"`
	ReadOnly         bool          `mapstructure:"read_only"`
	DirectConnection bool          `mapstructure:"direct_connection"`
	LocalThreshold   time.Duration `mapstructure:"local_threshold"`

	// Migration settings
	MigrationsPath   string `mapstructure:"migrations_path"`
	MigrationsTable  string `mapstructure:"migrations_table"`
	EnableMigrations bool   `mapstructure:"enable_migrations"`

	// Backup settings
	BackupEnabled   bool   `mapstructure:"backup_enabled"`
	BackupPath      string `mapstructure:"backup_path"`
	BackupSchedule  string `mapstructure:"backup_schedule"`
	BackupRetention int    `mapstructure:"backup_retention_days"`

	// Performance settings
	EnableIndexHints  bool  `mapstructure:"enable_index_hints"`
	DefaultBatchSize  int   `mapstructure:"default_batch_size"`
	MaxDocumentSize   int64 `mapstructure:"max_document_size"`
	EnableOplogReplay bool  `mapstructure:"enable_oplog_replay"`

	// Security settings
	EnableAuditLog             bool   `mapstructure:"enable_audit_log"`
	AuditLogPath               string `mapstructure:"audit_log_path"`
	EncryptionKeyFile          string `mapstructure:"encryption_key_file"`
	EnableFieldLevelEncryption bool   `mapstructure:"enable_field_level_encryption"`
}

// RedisConfig represents Redis configuration
type RedisConfig struct {
	// Connection settings
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	Password string `mapstructure:"password"`
	DB       int    `mapstructure:"db"`
	URI      string `mapstructure:"uri"`

	// SSL/TLS settings
	TLSEnabled         bool   `mapstructure:"tls_enabled"`
	TLSCert            string `mapstructure:"tls_cert"`
	TLSKey             string `mapstructure:"tls_key"`
	TLSCACert          string `mapstructure:"tls_ca_cert"`
	InsecureSkipVerify bool   `mapstructure:"insecure_skip_verify"`

	// Connection pool settings
	PoolSize           int           `mapstructure:"pool_size"`
	MinIdleConns       int           `mapstructure:"min_idle_conns"`
	MaxConnAge         time.Duration `mapstructure:"max_conn_age"`
	PoolTimeout        time.Duration `mapstructure:"pool_timeout"`
	IdleTimeout        time.Duration `mapstructure:"idle_timeout"`
	IdleCheckFrequency time.Duration `mapstructure:"idle_check_frequency"`

	// Timeouts
	DialTimeout  time.Duration `mapstructure:"dial_timeout"`
	ReadTimeout  time.Duration `mapstructure:"read_timeout"`
	WriteTimeout time.Duration `mapstructure:"write_timeout"`

	// Retry settings
	MaxRetries      int           `mapstructure:"max_retries"`
	MinRetryBackoff time.Duration `mapstructure:"min_retry_backoff"`
	MaxRetryBackoff time.Duration `mapstructure:"max_retry_backoff"`

	// Cluster settings
	EnableCluster  bool     `mapstructure:"enable_cluster"`
	ClusterNodes   []string `mapstructure:"cluster_nodes"`
	ClusterSlots   bool     `mapstructure:"cluster_slots"`
	ReadOnly       bool     `mapstructure:"read_only"`
	RouteByLatency bool     `mapstructure:"route_by_latency"`
	RouteRandomly  bool     `mapstructure:"route_randomly"`

	// Sentinel settings
	EnableSentinel     bool     `mapstructure:"enable_sentinel"`
	SentinelAddrs      []string `mapstructure:"sentinel_addrs"`
	SentinelMasterName string   `mapstructure:"sentinel_master_name"`
	SentinelPassword   string   `mapstructure:"sentinel_password"`

	// Performance settings
	MaxRedirects   int  `mapstructure:"max_redirects"`
	ReadOnlyMode   bool `mapstructure:"read_only_mode"`
	EnablePipeline bool `mapstructure:"enable_pipeline"`

	// Monitoring settings
	EnableMonitoring bool   `mapstructure:"enable_monitoring"`
	EnableMetrics    bool   `mapstructure:"enable_metrics"`
	LogLevel         string `mapstructure:"log_level"`

	// Cache settings
	DefaultExpiration time.Duration `mapstructure:"default_expiration"`
	CleanupInterval   time.Duration `mapstructure:"cleanup_interval"`
	KeyPrefix         string        `mapstructure:"key_prefix"`

	// Persistence settings
	EnablePersistence    bool   `mapstructure:"enable_persistence"`
	PersistenceMode      string `mapstructure:"persistence_mode"` // RDB, AOF, or BOTH
	RDBSaveSeconds       int    `mapstructure:"rdb_save_seconds"`
	RDBSaveChanges       int    `mapstructure:"rdb_save_changes"`
	AOFSyncMode          string `mapstructure:"aof_sync_mode"` // always, everysec, no
	EnableAOFRewrite     bool   `mapstructure:"enable_aof_rewrite"`
	AOFRewritePercentage int    `mapstructure:"aof_rewrite_percentage"`
	AOFRewriteMinSize    string `mapstructure:"aof_rewrite_min_size"`
}

// LoadDatabaseConfig loads database configuration from environment variables
func LoadDatabaseConfig() *DatabaseConfig {
	// Try to get URI first
	uri := getEnvString(constants.EnvDatabaseURL, "")

	config := &DatabaseConfig{
		// Connection settings
		Host:     getEnvString("DB_HOST", "localhost"),
		Port:     getEnvInt("DB_PORT", 27017),
		Username: getEnvString("DB_USERNAME", ""),
		Password: getEnvString("DB_PASSWORD", ""),
		Name:     getEnvString("DB_NAME", "bro_network"),
		URI:      uri,

		// SSL/TLS settings
		SSL:                getEnvBool("DB_SSL", false),
		SSLMode:            getEnvString("DB_SSL_MODE", "disable"),
		SSLCert:            getEnvString("DB_SSL_CERT", ""),
		SSLKey:             getEnvString("DB_SSL_KEY", ""),
		SSLRootCert:        getEnvString("DB_SSL_ROOT_CERT", ""),
		InsecureSkipVerify: getEnvBool("DB_INSECURE_SKIP_VERIFY", false),

		// Connection pool settings
		MaxPoolSize:            getEnvInt("DB_MAX_POOL_SIZE", 100),
		MinPoolSize:            getEnvInt("DB_MIN_POOL_SIZE", 10),
		MaxConnIdleTime:        getEnvDuration("DB_MAX_CONN_IDLE_TIME", 30*time.Minute),
		MaxConnLifetime:        getEnvDuration("DB_MAX_CONN_LIFETIME", 1*time.Hour),
		ConnectTimeout:         getEnvDuration("DB_CONNECT_TIMEOUT", 30*time.Second),
		SocketTimeout:          getEnvDuration("DB_SOCKET_TIMEOUT", 30*time.Second),
		ServerSelectionTimeout: getEnvDuration("DB_SERVER_SELECTION_TIMEOUT", 30*time.Second),

		// Retry settings
		RetryWrites:   getEnvBool("DB_RETRY_WRITES", true),
		RetryReads:    getEnvBool("DB_RETRY_READS", true),
		MaxRetries:    getEnvInt("DB_MAX_RETRIES", 3),
		RetryInterval: getEnvDuration("DB_RETRY_INTERVAL", 1*time.Second),

		// Read/Write preferences
		ReadPreference:     getEnvString("DB_READ_PREFERENCE", "primary"),
		ReadConcern:        getEnvString("DB_READ_CONCERN", "majority"),
		WriteConcern:       getEnvString("DB_WRITE_CONCERN", "majority"),
		ReadPreferenceTags: getEnvStringSlice("DB_READ_PREFERENCE_TAGS", []string{}),

		// Advanced settings
		AppName:       getEnvString("DB_APP_NAME", "bro-network"),
		ReplicaSet:    getEnvString("DB_REPLICA_SET", ""),
		AuthSource:    getEnvString("DB_AUTH_SOURCE", "admin"),
		AuthMechanism: getEnvString("DB_AUTH_MECHANISM", "SCRAM-SHA-256"),
		Compressors:   getEnvStringSlice("DB_COMPRESSORS", []string{"snappy", "zlib", "zstd"}),
		ZlibLevel:     getEnvInt("DB_ZLIB_LEVEL", 6),
		ZstdLevel:     getEnvInt("DB_ZSTD_LEVEL", 6),

		// Monitoring and logging
		EnableMonitoring:   getEnvBool("DB_ENABLE_MONITORING", true),
		EnableSlowQueries:  getEnvBool("DB_ENABLE_SLOW_QUERIES", true),
		SlowQueryThreshold: getEnvDuration("DB_SLOW_QUERY_THRESHOLD", 100*time.Millisecond),
		LogLevel:           getEnvString("DB_LOG_LEVEL", "info"),

		// Database-specific settings
		Journal:          getEnvBool("DB_JOURNAL", true),
		ReadOnly:         getEnvBool("DB_READ_ONLY", false),
		DirectConnection: getEnvBool("DB_DIRECT_CONNECTION", false),
		LocalThreshold:   getEnvDuration("DB_LOCAL_THRESHOLD", 15*time.Millisecond),

		// Migration settings
		MigrationsPath:   getEnvString("DB_MIGRATIONS_PATH", "./migrations"),
		MigrationsTable:  getEnvString("DB_MIGRATIONS_TABLE", "schema_migrations"),
		EnableMigrations: getEnvBool("DB_ENABLE_MIGRATIONS", true),

		// Backup settings
		BackupEnabled:   getEnvBool("DB_BACKUP_ENABLED", false),
		BackupPath:      getEnvString("DB_BACKUP_PATH", "./backups"),
		BackupSchedule:  getEnvString("DB_BACKUP_SCHEDULE", "0 2 * * *"), // Daily at 2 AM
		BackupRetention: getEnvInt("DB_BACKUP_RETENTION_DAYS", 30),

		// Performance settings
		EnableIndexHints:  getEnvBool("DB_ENABLE_INDEX_HINTS", true),
		DefaultBatchSize:  getEnvInt("DB_DEFAULT_BATCH_SIZE", 1000),
		MaxDocumentSize:   getEnvInt64("DB_MAX_DOCUMENT_SIZE", 16*1024*1024), // 16MB
		EnableOplogReplay: getEnvBool("DB_ENABLE_OPLOG_REPLAY", false),

		// Security settings
		EnableAuditLog:             getEnvBool("DB_ENABLE_AUDIT_LOG", false),
		AuditLogPath:               getEnvString("DB_AUDIT_LOG_PATH", "./logs/audit.log"),
		EncryptionKeyFile:          getEnvString("DB_ENCRYPTION_KEY_FILE", ""),
		EnableFieldLevelEncryption: getEnvBool("DB_ENABLE_FIELD_LEVEL_ENCRYPTION", false),
	}

	// If URI is provided, parse it to extract connection details
	if uri != "" {
		parseURIToConfig(config, uri)
	}

	return config
}

// LoadRedisConfig loads Redis configuration from environment variables
func LoadRedisConfig() *RedisConfig {
	// Try to get URI first
	uri := getEnvString(constants.EnvRedisURL, "")

	config := &RedisConfig{
		// Connection settings
		Host:     getEnvString("REDIS_HOST", "localhost"),
		Port:     getEnvInt("REDIS_PORT", 6379),
		Password: getEnvString("REDIS_PASSWORD", ""),
		DB:       getEnvInt("REDIS_DB", 0),
		URI:      uri,

		// SSL/TLS settings
		TLSEnabled:         getEnvBool("REDIS_TLS_ENABLED", false),
		TLSCert:            getEnvString("REDIS_TLS_CERT", ""),
		TLSKey:             getEnvString("REDIS_TLS_KEY", ""),
		TLSCACert:          getEnvString("REDIS_TLS_CA_CERT", ""),
		InsecureSkipVerify: getEnvBool("REDIS_INSECURE_SKIP_VERIFY", false),

		// Connection pool settings
		PoolSize:           getEnvInt("REDIS_POOL_SIZE", 10),
		MinIdleConns:       getEnvInt("REDIS_MIN_IDLE_CONNS", 5),
		MaxConnAge:         getEnvDuration("REDIS_MAX_CONN_AGE", 30*time.Minute),
		PoolTimeout:        getEnvDuration("REDIS_POOL_TIMEOUT", 5*time.Second),
		IdleTimeout:        getEnvDuration("REDIS_IDLE_TIMEOUT", 5*time.Minute),
		IdleCheckFrequency: getEnvDuration("REDIS_IDLE_CHECK_FREQUENCY", 1*time.Minute),

		// Timeouts
		DialTimeout:  getEnvDuration("REDIS_DIAL_TIMEOUT", 5*time.Second),
		ReadTimeout:  getEnvDuration("REDIS_READ_TIMEOUT", 3*time.Second),
		WriteTimeout: getEnvDuration("REDIS_WRITE_TIMEOUT", 3*time.Second),

		// Retry settings
		MaxRetries:      getEnvInt("REDIS_MAX_RETRIES", 3),
		MinRetryBackoff: getEnvDuration("REDIS_MIN_RETRY_BACKOFF", 8*time.Millisecond),
		MaxRetryBackoff: getEnvDuration("REDIS_MAX_RETRY_BACKOFF", 512*time.Millisecond),

		// Cluster settings
		EnableCluster:  getEnvBool("REDIS_ENABLE_CLUSTER", false),
		ClusterNodes:   getEnvStringSlice("REDIS_CLUSTER_NODES", []string{}),
		ClusterSlots:   getEnvBool("REDIS_CLUSTER_SLOTS", true),
		ReadOnly:       getEnvBool("REDIS_READ_ONLY", false),
		RouteByLatency: getEnvBool("REDIS_ROUTE_BY_LATENCY", false),
		RouteRandomly:  getEnvBool("REDIS_ROUTE_RANDOMLY", false),

		// Sentinel settings
		EnableSentinel:     getEnvBool("REDIS_ENABLE_SENTINEL", false),
		SentinelAddrs:      getEnvStringSlice("REDIS_SENTINEL_ADDRS", []string{}),
		SentinelMasterName: getEnvString("REDIS_SENTINEL_MASTER_NAME", "mymaster"),
		SentinelPassword:   getEnvString("REDIS_SENTINEL_PASSWORD", ""),

		// Performance settings
		MaxRedirects:   getEnvInt("REDIS_MAX_REDIRECTS", 8),
		ReadOnlyMode:   getEnvBool("REDIS_READ_ONLY_MODE", false),
		EnablePipeline: getEnvBool("REDIS_ENABLE_PIPELINE", true),

		// Monitoring settings
		EnableMonitoring: getEnvBool("REDIS_ENABLE_MONITORING", true),
		EnableMetrics:    getEnvBool("REDIS_ENABLE_METRICS", true),
		LogLevel:         getEnvString("REDIS_LOG_LEVEL", "info"),

		// Cache settings
		DefaultExpiration: getEnvDuration("REDIS_DEFAULT_EXPIRATION", 24*time.Hour),
		CleanupInterval:   getEnvDuration("REDIS_CLEANUP_INTERVAL", 10*time.Minute),
		KeyPrefix:         getEnvString("REDIS_KEY_PREFIX", "bro_network:"),

		// Persistence settings
		EnablePersistence:    getEnvBool("REDIS_ENABLE_PERSISTENCE", true),
		PersistenceMode:      getEnvString("REDIS_PERSISTENCE_MODE", "RDB"),
		RDBSaveSeconds:       getEnvInt("REDIS_RDB_SAVE_SECONDS", 900),
		RDBSaveChanges:       getEnvInt("REDIS_RDB_SAVE_CHANGES", 1),
		AOFSyncMode:          getEnvString("REDIS_AOF_SYNC_MODE", "everysec"),
		EnableAOFRewrite:     getEnvBool("REDIS_ENABLE_AOF_REWRITE", true),
		AOFRewritePercentage: getEnvInt("REDIS_AOF_REWRITE_PERCENTAGE", 100),
		AOFRewriteMinSize:    getEnvString("REDIS_AOF_REWRITE_MIN_SIZE", "64mb"),
	}

	// If URI is provided, parse it to extract connection details
	if uri != "" {
		parseRedisURIToConfig(config, uri)
	}

	return config
}

// ValidateDatabaseConfig validates database configuration
func (c *DatabaseConfig) ValidateDatabaseConfig() error {
	if c.URI == "" {
		if c.Host == "" {
			return fmt.Errorf("database host is required when URI is not provided")
		}
		if c.Port <= 0 || c.Port > 65535 {
			return fmt.Errorf("database port must be between 1 and 65535")
		}
		if c.Name == "" {
			return fmt.Errorf("database name is required")
		}
	}

	if c.MaxPoolSize <= 0 {
		return fmt.Errorf("max pool size must be greater than 0")
	}

	if c.MinPoolSize < 0 {
		return fmt.Errorf("min pool size must be greater than or equal to 0")
	}

	if c.MinPoolSize > c.MaxPoolSize {
		return fmt.Errorf("min pool size cannot be greater than max pool size")
	}

	return nil
}

// ValidateRedisConfig validates Redis configuration
func (c *RedisConfig) ValidateRedisConfig() error {
	if c.URI == "" {
		if c.Host == "" {
			return fmt.Errorf("Redis host is required when URI is not provided")
		}
		if c.Port <= 0 || c.Port > 65535 {
			return fmt.Errorf("Redis port must be between 1 and 65535")
		}
	}

	if c.DB < 0 || c.DB > 15 {
		return fmt.Errorf("Redis database number must be between 0 and 15")
	}

	if c.PoolSize <= 0 {
		return fmt.Errorf("Redis pool size must be greater than 0")
	}

	if c.MinIdleConns < 0 {
		return fmt.Errorf("Redis min idle connections must be greater than or equal to 0")
	}

	if c.MinIdleConns > c.PoolSize {
		return fmt.Errorf("Redis min idle connections cannot be greater than pool size")
	}

	return nil
}

// GetMongoURI builds MongoDB connection URI
func (c *DatabaseConfig) GetMongoURI() string {
	if c.URI != "" {
		return c.URI
	}

	var uri strings.Builder
	uri.WriteString("mongodb://")

	// Add authentication if provided
	if c.Username != "" {
		uri.WriteString(url.QueryEscape(c.Username))
		if c.Password != "" {
			uri.WriteString(":")
			uri.WriteString(url.QueryEscape(c.Password))
		}
		uri.WriteString("@")
	}

	// Add host and port
	uri.WriteString(c.Host)
	if c.Port != 27017 {
		uri.WriteString(":")
		uri.WriteString(strconv.Itoa(c.Port))
	}

	// Add database name
	uri.WriteString("/")
	uri.WriteString(c.Name)

	// Add query parameters
	var params []string

	if c.AuthSource != "" && c.AuthSource != "admin" {
		params = append(params, "authSource="+c.AuthSource)
	}

	if c.AuthMechanism != "" && c.AuthMechanism != "SCRAM-SHA-256" {
		params = append(params, "authMechanism="+c.AuthMechanism)
	}

	if c.ReplicaSet != "" {
		params = append(params, "replicaSet="+c.ReplicaSet)
	}

	if c.SSL {
		params = append(params, "ssl=true")
		if c.SSLMode != "" {
			params = append(params, "sslMode="+c.SSLMode)
		}
	}

	if c.RetryWrites {
		params = append(params, "retryWrites=true")
	}

	if c.RetryReads {
		params = append(params, "retryReads=true")
	}

	if c.ReadPreference != "" && c.ReadPreference != "primary" {
		params = append(params, "readPreference="+c.ReadPreference)
	}

	if c.ReadConcern != "" && c.ReadConcern != "majority" {
		params = append(params, "readConcernLevel="+c.ReadConcern)
	}

	if c.WriteConcern != "" && c.WriteConcern != "majority" {
		params = append(params, "w="+c.WriteConcern)
	}

	if c.AppName != "" {
		params = append(params, "appName="+url.QueryEscape(c.AppName))
	}

	if len(c.Compressors) > 0 {
		params = append(params, "compressors="+strings.Join(c.Compressors, ","))
	}

	if c.MaxPoolSize != 100 {
		params = append(params, "maxPoolSize="+strconv.Itoa(c.MaxPoolSize))
	}

	if c.MinPoolSize != 0 {
		params = append(params, "minPoolSize="+strconv.Itoa(c.MinPoolSize))
	}

	if c.ConnectTimeout != 30*time.Second {
		params = append(params, "connectTimeoutMS="+strconv.FormatInt(c.ConnectTimeout.Milliseconds(), 10))
	}

	if c.SocketTimeout != 30*time.Second {
		params = append(params, "socketTimeoutMS="+strconv.FormatInt(c.SocketTimeout.Milliseconds(), 10))
	}

	if c.ServerSelectionTimeout != 30*time.Second {
		params = append(params, "serverSelectionTimeoutMS="+strconv.FormatInt(c.ServerSelectionTimeout.Milliseconds(), 10))
	}

	if c.MaxConnIdleTime != 30*time.Minute {
		params = append(params, "maxIdleTimeMS="+strconv.FormatInt(c.MaxConnIdleTime.Milliseconds(), 10))
	}

	if c.MaxConnLifetime != 1*time.Hour {
		params = append(params, "maxLifeTimeMS="+strconv.FormatInt(c.MaxConnLifetime.Milliseconds(), 10))
	}

	if c.DirectConnection {
		params = append(params, "directConnection=true")
	}

	if c.LocalThreshold != 15*time.Millisecond {
		params = append(params, "localThresholdMS="+strconv.FormatInt(c.LocalThreshold.Milliseconds(), 10))
	}

	if len(params) > 0 {
		uri.WriteString("?")
		uri.WriteString(strings.Join(params, "&"))
	}

	return uri.String()
}

// GetRedisAddr returns Redis address in host:port format
func (c *RedisConfig) GetRedisAddr() string {
	if c.URI != "" {
		// Parse URI to extract host and port
		if parsedURI, err := url.Parse(c.URI); err == nil && parsedURI.Host != "" {
			return parsedURI.Host
		}
	}

	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}

// parseURIToConfig parses MongoDB URI and updates config
func parseURIToConfig(config *DatabaseConfig, uri string) {
	if parsedURI, err := url.Parse(uri); err == nil {
		if parsedURI.Host != "" {
			hostPort := strings.Split(parsedURI.Host, ":")
			config.Host = hostPort[0]
			if len(hostPort) > 1 {
				if port, err := strconv.Atoi(hostPort[1]); err == nil {
					config.Port = port
				}
			}
		}

		if parsedURI.User != nil {
			config.Username = parsedURI.User.Username()
			if password, ok := parsedURI.User.Password(); ok {
				config.Password = password
			}
		}

		if parsedURI.Path != "" && parsedURI.Path != "/" {
			config.Name = strings.TrimPrefix(parsedURI.Path, "/")
		}

		// Parse query parameters
		query := parsedURI.Query()
		if authSource := query.Get("authSource"); authSource != "" {
			config.AuthSource = authSource
		}
		if authMechanism := query.Get("authMechanism"); authMechanism != "" {
			config.AuthMechanism = authMechanism
		}
		if replicaSet := query.Get("replicaSet"); replicaSet != "" {
			config.ReplicaSet = replicaSet
		}
		if ssl := query.Get("ssl"); ssl == "true" {
			config.SSL = true
		}
		if sslMode := query.Get("sslMode"); sslMode != "" {
			config.SSLMode = sslMode
		}
	}
}

// parseRedisURIToConfig parses Redis URI and updates config
func parseRedisURIToConfig(config *RedisConfig, uri string) {
	if parsedURI, err := url.Parse(uri); err == nil {
		if parsedURI.Host != "" {
			hostPort := strings.Split(parsedURI.Host, ":")
			config.Host = hostPort[0]
			if len(hostPort) > 1 {
				if port, err := strconv.Atoi(hostPort[1]); err == nil {
					config.Port = port
				}
			}
		}

		if parsedURI.User != nil {
			if password, ok := parsedURI.User.Password(); ok {
				config.Password = password
			}
		}

		if parsedURI.Path != "" && parsedURI.Path != "/" {
			dbStr := strings.TrimPrefix(parsedURI.Path, "/")
			if db, err := strconv.Atoi(dbStr); err == nil {
				config.DB = db
			}
		}

		// Check for TLS
		if parsedURI.Scheme == "rediss" {
			config.TLSEnabled = true
		}
	}
}
