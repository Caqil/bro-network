package config

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"bro-network/pkg/constants"
)

// AWSConfig represents AWS configuration
type AWSConfig struct {
	AccessKeyID     string           `mapstructure:"access_key_id"`
	SecretAccessKey string           `mapstructure:"secret_access_key"`
	Region          string           `mapstructure:"region"`
	SessionToken    string           `mapstructure:"session_token"`
	Profile         string           `mapstructure:"profile"`
	Endpoint        string           `mapstructure:"endpoint"`
	S3              S3Config         `mapstructure:"s3"`
	SES             SESConfig        `mapstructure:"ses"`
	SNS             SNSConfig        `mapstructure:"sns"`
	SQS             SQSConfig        `mapstructure:"sqs"`
	Lambda          LambdaConfig     `mapstructure:"lambda"`
	CloudWatch      CloudWatchConfig `mapstructure:"cloudwatch"`
}

// S3Config represents AWS S3 configuration
type S3Config struct {
	Bucket              string        `mapstructure:"bucket"`
	Region              string        `mapstructure:"region"`
	Endpoint            string        `mapstructure:"endpoint"`
	ForcePathStyle      bool          `mapstructure:"force_path_style"`
	UseSSL              bool          `mapstructure:"use_ssl"`
	DisableSSL          bool          `mapstructure:"disable_ssl"`
	AccelerateEndpoint  bool          `mapstructure:"accelerate_endpoint"`
	UseAccelerate       bool          `mapstructure:"use_accelerate"`
	UseAccelerateConfig bool          `mapstructure:"use_accelerate_config"`
	PresignExpiry       time.Duration `mapstructure:"presign_expiry"`
	MaxRetries          int           `mapstructure:"max_retries"`
	Timeout             time.Duration `mapstructure:"timeout"`

	// Upload Configuration
	UploadPartSize    int64         `mapstructure:"upload_part_size"`
	UploadConcurrency int           `mapstructure:"upload_concurrency"`
	UploadTimeout     time.Duration `mapstructure:"upload_timeout"`
	LeavePartsOnError bool          `mapstructure:"leave_parts_on_error"`

	// Storage Classes
	DefaultStorageClass string `mapstructure:"default_storage_class"`
	IntelligentTiering  bool   `mapstructure:"intelligent_tiering"`

	// Lifecycle Configuration
	EnableLifecycle     bool `mapstructure:"enable_lifecycle"`
	TransitionToIA      int  `mapstructure:"transition_to_ia_days"`
	TransitionToGlacier int  `mapstructure:"transition_to_glacier_days"`
	ExpirationDays      int  `mapstructure:"expiration_days"`

	// Security Configuration
	EnableEncryption  bool   `mapstructure:"enable_encryption"`
	KMSKeyID          string `mapstructure:"kms_key_id"`
	ServerSideEncrypt string `mapstructure:"server_side_encryption"`

	// CORS Configuration
	EnableCORS     bool     `mapstructure:"enable_cors"`
	AllowedOrigins []string `mapstructure:"allowed_origins"`
	AllowedMethods []string `mapstructure:"allowed_methods"`
	AllowedHeaders []string `mapstructure:"allowed_headers"`
	ExposedHeaders []string `mapstructure:"exposed_headers"`
	MaxAgeSeconds  int      `mapstructure:"max_age_seconds"`

	// Public Access Configuration
	BlockPublicACLs       bool `mapstructure:"block_public_acls"`
	IgnorePublicACLs      bool `mapstructure:"ignore_public_acls"`
	BlockPublicPolicy     bool `mapstructure:"block_public_policy"`
	RestrictPublicBuckets bool `mapstructure:"restrict_public_buckets"`
}

// SESConfig represents AWS SES configuration
type SESConfig struct {
	Region           string        `mapstructure:"region"`
	FromEmail        string        `mapstructure:"from_email"`
	FromName         string        `mapstructure:"from_name"`
	ReplyToEmail     string        `mapstructure:"reply_to_email"`
	ReturnPath       string        `mapstructure:"return_path"`
	ConfigurationSet string        `mapstructure:"configuration_set"`
	MaxSendRate      float64       `mapstructure:"max_send_rate"`
	MaxRetries       int           `mapstructure:"max_retries"`
	RetryDelay       time.Duration `mapstructure:"retry_delay"`
	Timeout          time.Duration `mapstructure:"timeout"`

	// Template Configuration
	EnableTemplates bool              `mapstructure:"enable_templates"`
	DefaultTemplate string            `mapstructure:"default_template"`
	TemplateData    map[string]string `mapstructure:"template_data"`

	// Bounce and Complaint Handling
	EnableBounceHandling    bool   `mapstructure:"enable_bounce_handling"`
	EnableComplaintHandling bool   `mapstructure:"enable_complaint_handling"`
	BounceTopicARN          string `mapstructure:"bounce_topic_arn"`
	ComplaintTopicARN       string `mapstructure:"complaint_topic_arn"`

	// Sending Quota Management
	EnableQuotaManagement bool    `mapstructure:"enable_quota_management"`
	DailyQuotaThreshold   float64 `mapstructure:"daily_quota_threshold"`
	RateLimitThreshold    float64 `mapstructure:"rate_limit_threshold"`
}

// SNSConfig represents AWS SNS configuration
type SNSConfig struct {
	Region            string            `mapstructure:"region"`
	TopicARN          string            `mapstructure:"topic_arn"`
	MaxRetries        int               `mapstructure:"max_retries"`
	RetryDelay        time.Duration     `mapstructure:"retry_delay"`
	Timeout           time.Duration     `mapstructure:"timeout"`
	MessageAttributes map[string]string `mapstructure:"message_attributes"`

	// Platform Application Configuration
	PlatformApps map[string]string `mapstructure:"platform_apps"`

	// SMS Configuration
	SMSType            string `mapstructure:"sms_type"` // Promotional or Transactional
	SMSSenderID        string `mapstructure:"sms_sender_id"`
	SMSMaxPrice        string `mapstructure:"sms_max_price"`
	DefaultCountryCode string `mapstructure:"default_country_code"`

	// Push Notification Configuration
	APNSEnvironment string `mapstructure:"apns_environment"` // development or production
	APNSCertificate string `mapstructure:"apns_certificate"`
	APNSPrivateKey  string `mapstructure:"apns_private_key"`
	FCMServerKey    string `mapstructure:"fcm_server_key"`
	FCMSenderID     string `mapstructure:"fcm_sender_id"`
}

// SQSConfig represents AWS SQS configuration
type SQSConfig struct {
	Region                 string        `mapstructure:"region"`
	QueueURL               string        `mapstructure:"queue_url"`
	QueueName              string        `mapstructure:"queue_name"`
	MaxRetries             int           `mapstructure:"max_retries"`
	RetryDelay             time.Duration `mapstructure:"retry_delay"`
	Timeout                time.Duration `mapstructure:"timeout"`
	VisibilityTimeout      int           `mapstructure:"visibility_timeout"`
	MaxReceiveCount        int           `mapstructure:"max_receive_count"`
	MessageRetentionPeriod int           `mapstructure:"message_retention_period"`
	DelaySeconds           int           `mapstructure:"delay_seconds"`
	ReceiveMessageWaitTime int           `mapstructure:"receive_message_wait_time"`

	// Dead Letter Queue Configuration
	EnableDLQ          bool   `mapstructure:"enable_dlq"`
	DLQName            string `mapstructure:"dlq_name"`
	DLQMaxReceiveCount int    `mapstructure:"dlq_max_receive_count"`

	// Batch Configuration
	MaxBatchSize       int           `mapstructure:"max_batch_size"`
	BatchFlushInterval time.Duration `mapstructure:"batch_flush_interval"`

	// Polling Configuration
	EnableLongPolling bool          `mapstructure:"enable_long_polling"`
	PollTimeout       time.Duration `mapstructure:"poll_timeout"`
	MaxMessages       int           `mapstructure:"max_messages"`
	WaitTimeSeconds   int           `mapstructure:"wait_time_seconds"`
}

// LambdaConfig represents AWS Lambda configuration
type LambdaConfig struct {
	Region     string        `mapstructure:"region"`
	MaxRetries int           `mapstructure:"max_retries"`
	RetryDelay time.Duration `mapstructure:"retry_delay"`
	Timeout    time.Duration `mapstructure:"timeout"`

	// Function Configuration
	Functions map[string]LambdaFunction `mapstructure:"functions"`

	// Invocation Configuration
	DefaultInvocationType string `mapstructure:"default_invocation_type"` // RequestResponse, Event, DryRun
	EnablePayloadLogging  bool   `mapstructure:"enable_payload_logging"`
	MaxPayloadSize        int64  `mapstructure:"max_payload_size"`
}

// LambdaFunction represents individual Lambda function configuration
type LambdaFunction struct {
	FunctionName   string `mapstructure:"function_name"`
	FunctionARN    string `mapstructure:"function_arn"`
	InvocationType string `mapstructure:"invocation_type"`
	Qualifier      string `mapstructure:"qualifier"`
}

// CloudWatchConfig represents AWS CloudWatch configuration
type CloudWatchConfig struct {
	Region        string        `mapstructure:"region"`
	LogGroup      string        `mapstructure:"log_group"`
	LogStream     string        `mapstructure:"log_stream"`
	RetentionDays int           `mapstructure:"retention_days"`
	MaxRetries    int           `mapstructure:"max_retries"`
	RetryDelay    time.Duration `mapstructure:"retry_delay"`
	Timeout       time.Duration `mapstructure:"timeout"`

	// Metrics Configuration
	EnableMetrics     bool              `mapstructure:"enable_metrics"`
	MetricNamespace   string            `mapstructure:"metric_namespace"`
	DefaultDimensions map[string]string `mapstructure:"default_dimensions"`

	// Alarms Configuration
	EnableAlarms       bool   `mapstructure:"enable_alarms"`
	AlarmPrefix        string `mapstructure:"alarm_prefix"`
	DefaultSNSTopicARN string `mapstructure:"default_sns_topic_arn"`

	// Dashboard Configuration
	EnableDashboard bool   `mapstructure:"enable_dashboard"`
	DashboardName   string `mapstructure:"dashboard_name"`
}

// LoadAWSConfig loads AWS configuration from environment variables
func LoadAWSConfig() *AWSConfig {
	return &AWSConfig{
		AccessKeyID:     getEnvString(constants.EnvAWSAccessKey, ""),
		SecretAccessKey: getEnvString(constants.EnvAWSSecretKey, ""),
		Region:          getEnvString(constants.EnvAWSRegion, "us-east-1"),
		SessionToken:    getEnvString("AWS_SESSION_TOKEN", ""),
		Profile:         getEnvString("AWS_PROFILE", "default"),
		Endpoint:        getEnvString("AWS_ENDPOINT", ""),

		S3: S3Config{
			Bucket:              getEnvString(constants.EnvAWSBucket, "bro-network-uploads"),
			Region:              getEnvString("AWS_S3_REGION", getEnvString(constants.EnvAWSRegion, "us-east-1")),
			Endpoint:            getEnvString("AWS_S3_ENDPOINT", ""),
			ForcePathStyle:      getEnvBool("AWS_S3_FORCE_PATH_STYLE", false),
			UseSSL:              getEnvBool("AWS_S3_USE_SSL", true),
			DisableSSL:          getEnvBool("AWS_S3_DISABLE_SSL", false),
			AccelerateEndpoint:  getEnvBool("AWS_S3_ACCELERATE_ENDPOINT", false),
			UseAccelerate:       getEnvBool("AWS_S3_USE_ACCELERATE", false),
			UseAccelerateConfig: getEnvBool("AWS_S3_USE_ACCELERATE_CONFIG", false),
			PresignExpiry:       getEnvDuration("AWS_S3_PRESIGN_EXPIRY", 15*time.Minute),
			MaxRetries:          getEnvInt("AWS_S3_MAX_RETRIES", 3),
			Timeout:             getEnvDuration("AWS_S3_TIMEOUT", 30*time.Second),

			UploadPartSize:    getEnvInt64("AWS_S3_UPLOAD_PART_SIZE", 5*1024*1024), // 5MB
			UploadConcurrency: getEnvInt("AWS_S3_UPLOAD_CONCURRENCY", 5),
			UploadTimeout:     getEnvDuration("AWS_S3_UPLOAD_TIMEOUT", 5*time.Minute),
			LeavePartsOnError: getEnvBool("AWS_S3_LEAVE_PARTS_ON_ERROR", false),

			DefaultStorageClass: getEnvString("AWS_S3_DEFAULT_STORAGE_CLASS", "STANDARD"),
			IntelligentTiering:  getEnvBool("AWS_S3_INTELLIGENT_TIERING", false),

			EnableLifecycle:     getEnvBool("AWS_S3_ENABLE_LIFECYCLE", false),
			TransitionToIA:      getEnvInt("AWS_S3_TRANSITION_TO_IA_DAYS", 30),
			TransitionToGlacier: getEnvInt("AWS_S3_TRANSITION_TO_GLACIER_DAYS", 90),
			ExpirationDays:      getEnvInt("AWS_S3_EXPIRATION_DAYS", 365),

			EnableEncryption:  getEnvBool("AWS_S3_ENABLE_ENCRYPTION", true),
			KMSKeyID:          getEnvString("AWS_S3_KMS_KEY_ID", ""),
			ServerSideEncrypt: getEnvString("AWS_S3_SERVER_SIDE_ENCRYPTION", "AES256"),

			EnableCORS:     getEnvBool("AWS_S3_ENABLE_CORS", true),
			AllowedOrigins: getEnvStringSlice("AWS_S3_ALLOWED_ORIGINS", []string{"*"}),
			AllowedMethods: getEnvStringSlice("AWS_S3_ALLOWED_METHODS", []string{"GET", "POST", "PUT", "DELETE", "HEAD"}),
			AllowedHeaders: getEnvStringSlice("AWS_S3_ALLOWED_HEADERS", []string{"*"}),
			ExposedHeaders: getEnvStringSlice("AWS_S3_EXPOSED_HEADERS", []string{"ETag"}),
			MaxAgeSeconds:  getEnvInt("AWS_S3_MAX_AGE_SECONDS", 3600),

			BlockPublicACLs:       getEnvBool("AWS_S3_BLOCK_PUBLIC_ACLS", true),
			IgnorePublicACLs:      getEnvBool("AWS_S3_IGNORE_PUBLIC_ACLS", true),
			BlockPublicPolicy:     getEnvBool("AWS_S3_BLOCK_PUBLIC_POLICY", true),
			RestrictPublicBuckets: getEnvBool("AWS_S3_RESTRICT_PUBLIC_BUCKETS", true),
		},

		SES: SESConfig{
			Region:           getEnvString("AWS_SES_REGION", getEnvString(constants.EnvAWSRegion, "us-east-1")),
			FromEmail:        getEnvString("AWS_SES_FROM_EMAIL", "noreply@bro-network.com"),
			FromName:         getEnvString("AWS_SES_FROM_NAME", "Bro Network"),
			ReplyToEmail:     getEnvString("AWS_SES_REPLY_TO_EMAIL", ""),
			ReturnPath:       getEnvString("AWS_SES_RETURN_PATH", ""),
			ConfigurationSet: getEnvString("AWS_SES_CONFIGURATION_SET", ""),
			MaxSendRate:      getEnvFloat64("AWS_SES_MAX_SEND_RATE", 14.0),
			MaxRetries:       getEnvInt("AWS_SES_MAX_RETRIES", 3),
			RetryDelay:       getEnvDuration("AWS_SES_RETRY_DELAY", 1*time.Second),
			Timeout:          getEnvDuration("AWS_SES_TIMEOUT", 30*time.Second),

			EnableTemplates: getEnvBool("AWS_SES_ENABLE_TEMPLATES", true),
			DefaultTemplate: getEnvString("AWS_SES_DEFAULT_TEMPLATE", ""),

			EnableBounceHandling:    getEnvBool("AWS_SES_ENABLE_BOUNCE_HANDLING", true),
			EnableComplaintHandling: getEnvBool("AWS_SES_ENABLE_COMPLAINT_HANDLING", true),
			BounceTopicARN:          getEnvString("AWS_SES_BOUNCE_TOPIC_ARN", ""),
			ComplaintTopicARN:       getEnvString("AWS_SES_COMPLAINT_TOPIC_ARN", ""),

			EnableQuotaManagement: getEnvBool("AWS_SES_ENABLE_QUOTA_MANAGEMENT", true),
			DailyQuotaThreshold:   getEnvFloat64("AWS_SES_DAILY_QUOTA_THRESHOLD", 0.8),
			RateLimitThreshold:    getEnvFloat64("AWS_SES_RATE_LIMIT_THRESHOLD", 0.8),
		},

		SNS: SNSConfig{
			Region:     getEnvString("AWS_SNS_REGION", getEnvString(constants.EnvAWSRegion, "us-east-1")),
			TopicARN:   getEnvString("AWS_SNS_TOPIC_ARN", ""),
			MaxRetries: getEnvInt("AWS_SNS_MAX_RETRIES", 3),
			RetryDelay: getEnvDuration("AWS_SNS_RETRY_DELAY", 1*time.Second),
			Timeout:    getEnvDuration("AWS_SNS_TIMEOUT", 30*time.Second),

			SMSType:            getEnvString("AWS_SNS_SMS_TYPE", "Transactional"),
			SMSSenderID:        getEnvString("AWS_SNS_SMS_SENDER_ID", "BroNetwork"),
			SMSMaxPrice:        getEnvString("AWS_SNS_SMS_MAX_PRICE", "0.50"),
			DefaultCountryCode: getEnvString("AWS_SNS_DEFAULT_COUNTRY_CODE", "US"),

			APNSEnvironment: getEnvString("AWS_SNS_APNS_ENVIRONMENT", "production"),
			APNSCertificate: getEnvString("AWS_SNS_APNS_CERTIFICATE", ""),
			APNSPrivateKey:  getEnvString("AWS_SNS_APNS_PRIVATE_KEY", ""),
			FCMServerKey:    getEnvString("AWS_SNS_FCM_SERVER_KEY", ""),
			FCMSenderID:     getEnvString("AWS_SNS_FCM_SENDER_ID", ""),
		},

		SQS: SQSConfig{
			Region:                 getEnvString("AWS_SQS_REGION", getEnvString(constants.EnvAWSRegion, "us-east-1")),
			QueueURL:               getEnvString("AWS_SQS_QUEUE_URL", ""),
			QueueName:              getEnvString("AWS_SQS_QUEUE_NAME", "bro-network-queue"),
			MaxRetries:             getEnvInt("AWS_SQS_MAX_RETRIES", 3),
			RetryDelay:             getEnvDuration("AWS_SQS_RETRY_DELAY", 1*time.Second),
			Timeout:                getEnvDuration("AWS_SQS_TIMEOUT", 30*time.Second),
			VisibilityTimeout:      getEnvInt("AWS_SQS_VISIBILITY_TIMEOUT", 30),
			MaxReceiveCount:        getEnvInt("AWS_SQS_MAX_RECEIVE_COUNT", 3),
			MessageRetentionPeriod: getEnvInt("AWS_SQS_MESSAGE_RETENTION_PERIOD", 1209600), // 14 days
			DelaySeconds:           getEnvInt("AWS_SQS_DELAY_SECONDS", 0),
			ReceiveMessageWaitTime: getEnvInt("AWS_SQS_RECEIVE_MESSAGE_WAIT_TIME", 20),

			EnableDLQ:          getEnvBool("AWS_SQS_ENABLE_DLQ", true),
			DLQName:            getEnvString("AWS_SQS_DLQ_NAME", "bro-network-dlq"),
			DLQMaxReceiveCount: getEnvInt("AWS_SQS_DLQ_MAX_RECEIVE_COUNT", 3),

			MaxBatchSize:       getEnvInt("AWS_SQS_MAX_BATCH_SIZE", 10),
			BatchFlushInterval: getEnvDuration("AWS_SQS_BATCH_FLUSH_INTERVAL", 5*time.Second),

			EnableLongPolling: getEnvBool("AWS_SQS_ENABLE_LONG_POLLING", true),
			PollTimeout:       getEnvDuration("AWS_SQS_POLL_TIMEOUT", 20*time.Second),
			MaxMessages:       getEnvInt("AWS_SQS_MAX_MESSAGES", 10),
			WaitTimeSeconds:   getEnvInt("AWS_SQS_WAIT_TIME_SECONDS", 20),
		},

		Lambda: LambdaConfig{
			Region:     getEnvString("AWS_LAMBDA_REGION", getEnvString(constants.EnvAWSRegion, "us-east-1")),
			MaxRetries: getEnvInt("AWS_LAMBDA_MAX_RETRIES", 3),
			RetryDelay: getEnvDuration("AWS_LAMBDA_RETRY_DELAY", 1*time.Second),
			Timeout:    getEnvDuration("AWS_LAMBDA_TIMEOUT", 30*time.Second),

			DefaultInvocationType: getEnvString("AWS_LAMBDA_DEFAULT_INVOCATION_TYPE", "RequestResponse"),
			EnablePayloadLogging:  getEnvBool("AWS_LAMBDA_ENABLE_PAYLOAD_LOGGING", false),
			MaxPayloadSize:        getEnvInt64("AWS_LAMBDA_MAX_PAYLOAD_SIZE", 6*1024*1024), // 6MB
		},

		CloudWatch: CloudWatchConfig{
			Region:        getEnvString("AWS_CLOUDWATCH_REGION", getEnvString(constants.EnvAWSRegion, "us-east-1")),
			LogGroup:      getEnvString("AWS_CLOUDWATCH_LOG_GROUP", "/aws/lambda/bro-network"),
			LogStream:     getEnvString("AWS_CLOUDWATCH_LOG_STREAM", ""),
			RetentionDays: getEnvInt("AWS_CLOUDWATCH_RETENTION_DAYS", 30),
			MaxRetries:    getEnvInt("AWS_CLOUDWATCH_MAX_RETRIES", 3),
			RetryDelay:    getEnvDuration("AWS_CLOUDWATCH_RETRY_DELAY", 1*time.Second),
			Timeout:       getEnvDuration("AWS_CLOUDWATCH_TIMEOUT", 30*time.Second),

			EnableMetrics:   getEnvBool("AWS_CLOUDWATCH_ENABLE_METRICS", true),
			MetricNamespace: getEnvString("AWS_CLOUDWATCH_METRIC_NAMESPACE", "BroNetwork"),

			EnableAlarms:       getEnvBool("AWS_CLOUDWATCH_ENABLE_ALARMS", true),
			AlarmPrefix:        getEnvString("AWS_CLOUDWATCH_ALARM_PREFIX", "BroNetwork"),
			DefaultSNSTopicARN: getEnvString("AWS_CLOUDWATCH_DEFAULT_SNS_TOPIC_ARN", ""),

			EnableDashboard: getEnvBool("AWS_CLOUDWATCH_ENABLE_DASHBOARD", true),
			DashboardName:   getEnvString("AWS_CLOUDWATCH_DASHBOARD_NAME", "BroNetwork"),
		},
	}
}

// ValidateAWSConfig validates AWS configuration
func (c *AWSConfig) ValidateAWSConfig() error {
	if c.AccessKeyID == "" || c.SecretAccessKey == "" {
		return nil // Allow for IAM role-based authentication
	}

	if c.Region == "" {
		return fmt.Errorf("AWS region is required")
	}

	return nil
}

// GetS3URL returns the S3 URL for a given key
func (c *AWSConfig) GetS3URL(key string) string {
	if c.S3.Endpoint != "" {
		return fmt.Sprintf("%s/%s/%s", c.S3.Endpoint, c.S3.Bucket, key)
	}
	return fmt.Sprintf("https://%s.s3.%s.amazonaws.com/%s", c.S3.Bucket, c.S3.Region, key)
}

// GetS3BucketURL returns the S3 bucket URL
func (c *AWSConfig) GetS3BucketURL() string {
	if c.S3.Endpoint != "" {
		return fmt.Sprintf("%s/%s", c.S3.Endpoint, c.S3.Bucket)
	}
	return fmt.Sprintf("https://%s.s3.%s.amazonaws.com", c.S3.Bucket, c.S3.Region)
}

// Helper function to get float64 from environment
func getEnvFloat64(key string, defaultValue float64) float64 {
	if value := os.Getenv(key); value != "" {
		if parsed, err := strconv.ParseFloat(value, 64); err == nil {
			return parsed
		}
	}
	return defaultValue
}
