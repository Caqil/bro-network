package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"bro-network/pkg/constants"
)

// SMTPConfig represents SMTP configuration for email sending
type SMTPConfig struct {
	// Basic SMTP settings
	Host     string `mapstructure:"host"`
	Port     string `mapstructure:"port"`
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`

	// Email settings
	FromEmail string `mapstructure:"from_email"`
	FromName  string `mapstructure:"from_name"`
	ReplyTo   string `mapstructure:"reply_to"`

	// Security settings
	UseTLS        bool `mapstructure:"use_tls"`
	UseSSL        bool `mapstructure:"use_ssl"`
	SkipTLSVerify bool `mapstructure:"skip_tls_verify"`

	// Connection settings
	ConnectionTimeout time.Duration `mapstructure:"connection_timeout"`
	SendTimeout       time.Duration `mapstructure:"send_timeout"`
	KeepAlive         time.Duration `mapstructure:"keep_alive"`
	MaxIdleConns      int           `mapstructure:"max_idle_conns"`
	MaxConnsPerHost   int           `mapstructure:"max_conns_per_host"`

	// Retry settings
	MaxRetries             int           `mapstructure:"max_retries"`
	RetryDelay             time.Duration `mapstructure:"retry_delay"`
	RetryBackoffMultiplier float64       `mapstructure:"retry_backoff_multiplier"`
	MaxRetryDelay          time.Duration `mapstructure:"max_retry_delay"`

	// Rate limiting
	RateLimitEnabled bool          `mapstructure:"rate_limit_enabled"`
	EmailsPerSecond  float64       `mapstructure:"emails_per_second"`
	EmailsPerMinute  int           `mapstructure:"emails_per_minute"`
	EmailsPerHour    int           `mapstructure:"emails_per_hour"`
	EmailsPerDay     int           `mapstructure:"emails_per_day"`
	BurstSize        int           `mapstructure:"burst_size"`
	RateLimitWindow  time.Duration `mapstructure:"rate_limit_window"`

	// Queue settings
	EnableQueue     bool `mapstructure:"enable_queue"`
	QueueSize       int  `mapstructure:"queue_size"`
	QueueWorkers    int  `mapstructure:"queue_workers"`
	QueueRetryLimit int  `mapstructure:"queue_retry_limit"`
	EnablePriority  bool `mapstructure:"enable_priority"`

	// Template settings
	TemplateDir      string            `mapstructure:"template_dir"`
	DefaultLanguage  string            `mapstructure:"default_language"`
	EnableTemplating bool              `mapstructure:"enable_templating"`
	TemplateVars     map[string]string `mapstructure:"template_vars"`

	// Bounce and complaint handling
	EnableBounceHandling    bool   `mapstructure:"enable_bounce_handling"`
	EnableComplaintHandling bool   `mapstructure:"enable_complaint_handling"`
	BounceWebhookURL        string `mapstructure:"bounce_webhook_url"`
	ComplaintWebhookURL     string `mapstructure:"complaint_webhook_url"`

	// Tracking settings
	EnableOpenTracking  bool   `mapstructure:"enable_open_tracking"`
	EnableClickTracking bool   `mapstructure:"enable_click_tracking"`
	TrackingDomain      string `mapstructure:"tracking_domain"`
	TrackingPixelURL    string `mapstructure:"tracking_pixel_url"`

	// Content settings
	MaxEmailSize       int64  `mapstructure:"max_email_size"`
	EnableHTMLEmail    bool   `mapstructure:"enable_html_email"`
	EnablePlainText    bool   `mapstructure:"enable_plain_text"`
	DefaultCharset     string `mapstructure:"default_charset"`
	DefaultContentType string `mapstructure:"default_content_type"`

	// Attachment settings
	EnableAttachments   bool     `mapstructure:"enable_attachments"`
	MaxAttachmentSize   int64    `mapstructure:"max_attachment_size"`
	AllowedAttachTypes  []string `mapstructure:"allowed_attachment_types"`
	AttachmentScanVirus bool     `mapstructure:"attachment_scan_virus"`

	// Email validation
	EnableValidation      bool `mapstructure:"enable_validation"`
	ValidateEmailFormat   bool `mapstructure:"validate_email_format"`
	ValidateDomain        bool `mapstructure:"validate_domain"`
	ValidateMX            bool `mapstructure:"validate_mx"`
	EnableDisposableCheck bool `mapstructure:"enable_disposable_check"`

	// Logging and monitoring
	EnableLogging   bool          `mapstructure:"enable_logging"`
	LogLevel        string        `mapstructure:"log_level"`
	LogFile         string        `mapstructure:"log_file"`
	EnableMetrics   bool          `mapstructure:"enable_metrics"`
	MetricsInterval time.Duration `mapstructure:"metrics_interval"`

	// Webhook settings
	EnableWebhooks bool              `mapstructure:"enable_webhooks"`
	WebhookURL     string            `mapstructure:"webhook_url"`
	WebhookSecret  string            `mapstructure:"webhook_secret"`
	WebhookTimeout time.Duration     `mapstructure:"webhook_timeout"`
	WebhookRetries int               `mapstructure:"webhook_retries"`
	WebhookEvents  []string          `mapstructure:"webhook_events"`
	WebhookHeaders map[string]string `mapstructure:"webhook_headers"`

	// Backup SMTP settings
	EnableBackupSMTP bool   `mapstructure:"enable_backup_smtp"`
	BackupHost       string `mapstructure:"backup_host"`
	BackupPort       string `mapstructure:"backup_port"`
	BackupUsername   string `mapstructure:"backup_username"`
	BackupPassword   string `mapstructure:"backup_password"`
	BackupUseTLS     bool   `mapstructure:"backup_use_tls"`
	BackupUseSSL     bool   `mapstructure:"backup_use_ssl"`

	// Provider-specific settings
	Provider string `mapstructure:"provider"` // smtp, ses, sendgrid, mailgun, postmark

	// SendGrid settings
	SendGridAPIKey      string `mapstructure:"sendgrid_api_key"`
	SendGridAPIEndpoint string `mapstructure:"sendgrid_api_endpoint"`

	// Mailgun settings
	MailgunAPIKey  string `mapstructure:"mailgun_api_key"`
	MailgunDomain  string `mapstructure:"mailgun_domain"`
	MailgunAPIBase string `mapstructure:"mailgun_api_base"`
	MailgunRegion  string `mapstructure:"mailgun_region"`

	// Postmark settings
	PostmarkAPIKey      string `mapstructure:"postmark_api_key"`
	PostmarkAPIEndpoint string `mapstructure:"postmark_api_endpoint"`

	// Custom headers
	DefaultHeaders map[string]string `mapstructure:"default_headers"`

	// Testing settings
	TestMode           bool   `mapstructure:"test_mode"`
	TestEmailRecipient string `mapstructure:"test_email_recipient"`
	CatchAllEmail      string `mapstructure:"catch_all_email"`

	// Delivery settings
	DeliveryMode  string        `mapstructure:"delivery_mode"` // immediate, queue, batch
	BatchSize     int           `mapstructure:"batch_size"`
	BatchInterval time.Duration `mapstructure:"batch_interval"`

	// Unsubscribe settings
	EnableUnsubscribe  bool   `mapstructure:"enable_unsubscribe"`
	UnsubscribeURL     string `mapstructure:"unsubscribe_url"`
	ListUnsubscribeURL string `mapstructure:"list_unsubscribe_url"`

	// DKIM settings
	EnableDKIM     bool   `mapstructure:"enable_dkim"`
	DKIMPrivateKey string `mapstructure:"dkim_private_key"`
	DKIMSelector   string `mapstructure:"dkim_selector"`
	DKIMDomain     string `mapstructure:"dkim_domain"`

	// SPF and DMARC settings
	EnableSPF   bool   `mapstructure:"enable_spf"`
	SPFRecord   string `mapstructure:"spf_record"`
	EnableDMARC bool   `mapstructure:"enable_dmarc"`
	DMARCPolicy string `mapstructure:"dmarc_policy"`
}

// LoadSMTPConfig loads SMTP configuration from environment variables
func LoadSMTPConfig() *SMTPConfig {
	return &SMTPConfig{
		// Basic SMTP settings
		Host:     getEnvString(constants.EnvSMTPHost, "localhost"),
		Port:     getEnvString(constants.EnvSMTPPort, "587"),
		Username: getEnvString(constants.EnvSMTPUsername, ""),
		Password: getEnvString(constants.EnvSMTPPassword, ""),

		// Email settings
		FromEmail: getEnvString("SMTP_FROM_EMAIL", "noreply@bro-network.com"),
		FromName:  getEnvString("SMTP_FROM_NAME", "Bro Network"),
		ReplyTo:   getEnvString("SMTP_REPLY_TO", ""),

		// Security settings
		UseTLS:        getEnvBool("SMTP_USE_TLS", true),
		UseSSL:        getEnvBool("SMTP_USE_SSL", false),
		SkipTLSVerify: getEnvBool("SMTP_SKIP_TLS_VERIFY", false),

		// Connection settings
		ConnectionTimeout: getEnvDuration("SMTP_CONNECTION_TIMEOUT", 30*time.Second),
		SendTimeout:       getEnvDuration("SMTP_SEND_TIMEOUT", 30*time.Second),
		KeepAlive:         getEnvDuration("SMTP_KEEP_ALIVE", 30*time.Second),
		MaxIdleConns:      getEnvInt("SMTP_MAX_IDLE_CONNS", 10),
		MaxConnsPerHost:   getEnvInt("SMTP_MAX_CONNS_PER_HOST", 10),

		// Retry settings
		MaxRetries:             getEnvInt("SMTP_MAX_RETRIES", 3),
		RetryDelay:             getEnvDuration("SMTP_RETRY_DELAY", 1*time.Second),
		RetryBackoffMultiplier: getEnvFloat64("SMTP_RETRY_BACKOFF_MULTIPLIER", 2.0),
		MaxRetryDelay:          getEnvDuration("SMTP_MAX_RETRY_DELAY", 30*time.Second),

		// Rate limiting
		RateLimitEnabled: getEnvBool("SMTP_RATE_LIMIT_ENABLED", true),
		EmailsPerSecond:  getEnvFloat64("SMTP_EMAILS_PER_SECOND", 5.0),
		EmailsPerMinute:  getEnvInt("SMTP_EMAILS_PER_MINUTE", 300),
		EmailsPerHour:    getEnvInt("SMTP_EMAILS_PER_HOUR", 1000),
		EmailsPerDay:     getEnvInt("SMTP_EMAILS_PER_DAY", 10000),
		BurstSize:        getEnvInt("SMTP_BURST_SIZE", 10),
		RateLimitWindow:  getEnvDuration("SMTP_RATE_LIMIT_WINDOW", 1*time.Minute),

		// Queue settings
		EnableQueue:     getEnvBool("SMTP_ENABLE_QUEUE", true),
		QueueSize:       getEnvInt("SMTP_QUEUE_SIZE", 1000),
		QueueWorkers:    getEnvInt("SMTP_QUEUE_WORKERS", 5),
		QueueRetryLimit: getEnvInt("SMTP_QUEUE_RETRY_LIMIT", 3),
		EnablePriority:  getEnvBool("SMTP_ENABLE_PRIORITY", true),

		// Template settings
		TemplateDir:      getEnvString("SMTP_TEMPLATE_DIR", "./templates/email"),
		DefaultLanguage:  getEnvString("SMTP_DEFAULT_LANGUAGE", "en"),
		EnableTemplating: getEnvBool("SMTP_ENABLE_TEMPLATING", true),

		// Bounce and complaint handling
		EnableBounceHandling:    getEnvBool("SMTP_ENABLE_BOUNCE_HANDLING", true),
		EnableComplaintHandling: getEnvBool("SMTP_ENABLE_COMPLAINT_HANDLING", true),
		BounceWebhookURL:        getEnvString("SMTP_BOUNCE_WEBHOOK_URL", ""),
		ComplaintWebhookURL:     getEnvString("SMTP_COMPLAINT_WEBHOOK_URL", ""),

		// Tracking settings
		EnableOpenTracking:  getEnvBool("SMTP_ENABLE_OPEN_TRACKING", false),
		EnableClickTracking: getEnvBool("SMTP_ENABLE_CLICK_TRACKING", false),
		TrackingDomain:      getEnvString("SMTP_TRACKING_DOMAIN", ""),
		TrackingPixelURL:    getEnvString("SMTP_TRACKING_PIXEL_URL", ""),

		// Content settings
		MaxEmailSize:       getEnvInt64("SMTP_MAX_EMAIL_SIZE", 10*1024*1024), // 10MB
		EnableHTMLEmail:    getEnvBool("SMTP_ENABLE_HTML_EMAIL", true),
		EnablePlainText:    getEnvBool("SMTP_ENABLE_PLAIN_TEXT", true),
		DefaultCharset:     getEnvString("SMTP_DEFAULT_CHARSET", "UTF-8"),
		DefaultContentType: getEnvString("SMTP_DEFAULT_CONTENT_TYPE", "text/html"),

		// Attachment settings
		EnableAttachments:   getEnvBool("SMTP_ENABLE_ATTACHMENTS", true),
		MaxAttachmentSize:   getEnvInt64("SMTP_MAX_ATTACHMENT_SIZE", 5*1024*1024), // 5MB
		AllowedAttachTypes:  getEnvStringSlice("SMTP_ALLOWED_ATTACHMENT_TYPES", []string{"pdf", "doc", "docx", "txt", "jpg", "png"}),
		AttachmentScanVirus: getEnvBool("SMTP_ATTACHMENT_SCAN_VIRUS", false),

		// Email validation
		EnableValidation:      getEnvBool("SMTP_ENABLE_VALIDATION", true),
		ValidateEmailFormat:   getEnvBool("SMTP_VALIDATE_EMAIL_FORMAT", true),
		ValidateDomain:        getEnvBool("SMTP_VALIDATE_DOMAIN", true),
		ValidateMX:            getEnvBool("SMTP_VALIDATE_MX", false),
		EnableDisposableCheck: getEnvBool("SMTP_ENABLE_DISPOSABLE_CHECK", true),

		// Logging and monitoring
		EnableLogging:   getEnvBool("SMTP_ENABLE_LOGGING", true),
		LogLevel:        getEnvString("SMTP_LOG_LEVEL", "info"),
		LogFile:         getEnvString("SMTP_LOG_FILE", "./logs/smtp.log"),
		EnableMetrics:   getEnvBool("SMTP_ENABLE_METRICS", true),
		MetricsInterval: getEnvDuration("SMTP_METRICS_INTERVAL", 1*time.Minute),

		// Webhook settings
		EnableWebhooks: getEnvBool("SMTP_ENABLE_WEBHOOKS", false),
		WebhookURL:     getEnvString("SMTP_WEBHOOK_URL", ""),
		WebhookSecret:  getEnvString("SMTP_WEBHOOK_SECRET", ""),
		WebhookTimeout: getEnvDuration("SMTP_WEBHOOK_TIMEOUT", 10*time.Second),
		WebhookRetries: getEnvInt("SMTP_WEBHOOK_RETRIES", 3),
		WebhookEvents:  getEnvStringSlice("SMTP_WEBHOOK_EVENTS", []string{"sent", "delivered", "bounced", "complained"}),

		// Backup SMTP settings
		EnableBackupSMTP: getEnvBool("SMTP_ENABLE_BACKUP", false),
		BackupHost:       getEnvString("SMTP_BACKUP_HOST", ""),
		BackupPort:       getEnvString("SMTP_BACKUP_PORT", "587"),
		BackupUsername:   getEnvString("SMTP_BACKUP_USERNAME", ""),
		BackupPassword:   getEnvString("SMTP_BACKUP_PASSWORD", ""),
		BackupUseTLS:     getEnvBool("SMTP_BACKUP_USE_TLS", true),
		BackupUseSSL:     getEnvBool("SMTP_BACKUP_USE_SSL", false),

		// Provider-specific settings
		Provider: getEnvString("SMTP_PROVIDER", "smtp"),

		// SendGrid settings
		SendGridAPIKey:      getEnvString("SENDGRID_API_KEY", ""),
		SendGridAPIEndpoint: getEnvString("SENDGRID_API_ENDPOINT", "https://api.sendgrid.com/v3"),

		// Mailgun settings
		MailgunAPIKey:  getEnvString("MAILGUN_API_KEY", ""),
		MailgunDomain:  getEnvString("MAILGUN_DOMAIN", ""),
		MailgunAPIBase: getEnvString("MAILGUN_API_BASE", "https://api.mailgun.net/v3"),
		MailgunRegion:  getEnvString("MAILGUN_REGION", "us"),

		// Postmark settings
		PostmarkAPIKey:      getEnvString("POSTMARK_API_KEY", ""),
		PostmarkAPIEndpoint: getEnvString("POSTMARK_API_ENDPOINT", "https://api.postmarkapp.com"),

		// Testing settings
		TestMode:           getEnvBool("SMTP_TEST_MODE", false),
		TestEmailRecipient: getEnvString("SMTP_TEST_EMAIL_RECIPIENT", ""),
		CatchAllEmail:      getEnvString("SMTP_CATCH_ALL_EMAIL", ""),

		// Delivery settings
		DeliveryMode:  getEnvString("SMTP_DELIVERY_MODE", "immediate"),
		BatchSize:     getEnvInt("SMTP_BATCH_SIZE", 100),
		BatchInterval: getEnvDuration("SMTP_BATCH_INTERVAL", 5*time.Minute),

		// Unsubscribe settings
		EnableUnsubscribe:  getEnvBool("SMTP_ENABLE_UNSUBSCRIBE", true),
		UnsubscribeURL:     getEnvString("SMTP_UNSUBSCRIBE_URL", ""),
		ListUnsubscribeURL: getEnvString("SMTP_LIST_UNSUBSCRIBE_URL", ""),

		// DKIM settings
		EnableDKIM:     getEnvBool("SMTP_ENABLE_DKIM", false),
		DKIMPrivateKey: getEnvString("SMTP_DKIM_PRIVATE_KEY", ""),
		DKIMSelector:   getEnvString("SMTP_DKIM_SELECTOR", "default"),
		DKIMDomain:     getEnvString("SMTP_DKIM_DOMAIN", ""),

		// SPF and DMARC settings
		EnableSPF:   getEnvBool("SMTP_ENABLE_SPF", false),
		SPFRecord:   getEnvString("SMTP_SPF_RECORD", ""),
		EnableDMARC: getEnvBool("SMTP_ENABLE_DMARC", false),
		DMARCPolicy: getEnvString("SMTP_DMARC_POLICY", "none"),
	}
}

// ValidateSMTPConfig validates SMTP configuration
func (c *SMTPConfig) ValidateSMTPConfig() error {
	// Basic validation
	if c.Host == "" {
		return fmt.Errorf("SMTP host is required")
	}

	if c.Port == "" {
		return fmt.Errorf("SMTP port is required")
	}

	// Validate port number
	if port, err := strconv.Atoi(c.Port); err != nil || port <= 0 || port > 65535 {
		return fmt.Errorf("SMTP port must be a valid number between 1 and 65535")
	}

	if c.FromEmail == "" {
		return fmt.Errorf("SMTP from email is required")
	}

	// Validate email format
	if !isValidEmail(c.FromEmail) {
		return fmt.Errorf("SMTP from email has invalid format")
	}

	if c.ReplyTo != "" && !isValidEmail(c.ReplyTo) {
		return fmt.Errorf("SMTP reply-to email has invalid format")
	}

	// Validate provider-specific settings
	switch c.Provider {
	case "sendgrid":
		if c.SendGridAPIKey == "" {
			return fmt.Errorf("SendGrid API key is required when using SendGrid provider")
		}
	case "mailgun":
		if c.MailgunAPIKey == "" || c.MailgunDomain == "" {
			return fmt.Errorf("Mailgun API key and domain are required when using Mailgun provider")
		}
	case "postmark":
		if c.PostmarkAPIKey == "" {
			return fmt.Errorf("Postmark API key is required when using Postmark provider")
		}
	case "smtp":
		// For SMTP, username and password are optional but recommended
		if c.Username == "" || c.Password == "" {
			// Log warning but don't fail validation
		}
	}

	// Validate rate limiting settings
	if c.RateLimitEnabled {
		if c.EmailsPerSecond <= 0 {
			return fmt.Errorf("emails per second must be greater than 0 when rate limiting is enabled")
		}
		if c.BurstSize <= 0 {
			return fmt.Errorf("burst size must be greater than 0 when rate limiting is enabled")
		}
	}

	// Validate queue settings
	if c.EnableQueue {
		if c.QueueSize <= 0 {
			return fmt.Errorf("queue size must be greater than 0 when queue is enabled")
		}
		if c.QueueWorkers <= 0 {
			return fmt.Errorf("queue workers must be greater than 0 when queue is enabled")
		}
	}

	// Validate attachment settings
	if c.EnableAttachments {
		if c.MaxAttachmentSize <= 0 {
			return fmt.Errorf("max attachment size must be greater than 0 when attachments are enabled")
		}
	}

	// Validate backup SMTP settings
	if c.EnableBackupSMTP {
		if c.BackupHost == "" {
			return fmt.Errorf("backup SMTP host is required when backup SMTP is enabled")
		}
		if c.BackupPort == "" {
			return fmt.Errorf("backup SMTP port is required when backup SMTP is enabled")
		}
	}

	// Validate DKIM settings
	if c.EnableDKIM {
		if c.DKIMPrivateKey == "" {
			return fmt.Errorf("DKIM private key is required when DKIM is enabled")
		}
		if c.DKIMDomain == "" {
			return fmt.Errorf("DKIM domain is required when DKIM is enabled")
		}
		if c.DKIMSelector == "" {
			return fmt.Errorf("DKIM selector is required when DKIM is enabled")
		}
	}

	return nil
}

// GetSMTPAddr returns SMTP server address in host:port format
func (c *SMTPConfig) GetSMTPAddr() string {
	return c.Host + ":" + c.Port
}

// GetBackupSMTPAddr returns backup SMTP server address in host:port format
func (c *SMTPConfig) GetBackupSMTPAddr() string {
	if c.EnableBackupSMTP && c.BackupHost != "" && c.BackupPort != "" {
		return c.BackupHost + ":" + c.BackupPort
	}
	return ""
}

// IsTestMode returns true if SMTP is in test mode
func (c *SMTPConfig) IsTestMode() bool {
	return c.TestMode
}

// ShouldUseTLS returns true if TLS should be used
func (c *SMTPConfig) ShouldUseTLS() bool {
	return c.UseTLS && !c.UseSSL
}

// ShouldUseSSL returns true if SSL should be used
func (c *SMTPConfig) ShouldUseSSL() bool {
	return c.UseSSL
}

// GetEffectiveFromEmail returns the effective from email
func (c *SMTPConfig) GetEffectiveFromEmail() string {
	if c.TestMode && c.CatchAllEmail != "" {
		return c.CatchAllEmail
	}
	return c.FromEmail
}

// GetEffectiveToEmail returns the effective to email for testing
func (c *SMTPConfig) GetEffectiveToEmail(originalTo string) string {
	if c.TestMode {
		if c.TestEmailRecipient != "" {
			return c.TestEmailRecipient
		}
		if c.CatchAllEmail != "" {
			return c.CatchAllEmail
		}
	}
	return originalTo
}

// GetProviderConfig returns provider-specific configuration
func (c *SMTPConfig) GetProviderConfig() map[string]interface{} {
	config := make(map[string]interface{})

	switch c.Provider {
	case "sendgrid":
		config["api_key"] = c.SendGridAPIKey
		config["api_endpoint"] = c.SendGridAPIEndpoint
	case "mailgun":
		config["api_key"] = c.MailgunAPIKey
		config["domain"] = c.MailgunDomain
		config["api_base"] = c.MailgunAPIBase
		config["region"] = c.MailgunRegion
	case "postmark":
		config["api_key"] = c.PostmarkAPIKey
		config["api_endpoint"] = c.PostmarkAPIEndpoint
	case "smtp":
		config["host"] = c.Host
		config["port"] = c.Port
		config["username"] = c.Username
		config["password"] = c.Password
		config["use_tls"] = c.UseTLS
		config["use_ssl"] = c.UseSSL
	}

	return config
}

// GetRateLimitConfig returns rate limiting configuration
func (c *SMTPConfig) GetRateLimitConfig() map[string]interface{} {
	return map[string]interface{}{
		"enabled":           c.RateLimitEnabled,
		"emails_per_second": c.EmailsPerSecond,
		"emails_per_minute": c.EmailsPerMinute,
		"emails_per_hour":   c.EmailsPerHour,
		"emails_per_day":    c.EmailsPerDay,
		"burst_size":        c.BurstSize,
		"window":            c.RateLimitWindow,
	}
}

// GetQueueConfig returns queue configuration
func (c *SMTPConfig) GetQueueConfig() map[string]interface{} {
	return map[string]interface{}{
		"enabled":         c.EnableQueue,
		"size":            c.QueueSize,
		"workers":         c.QueueWorkers,
		"retry_limit":     c.QueueRetryLimit,
		"enable_priority": c.EnablePriority,
	}
}

// GetWebhookConfig returns webhook configuration
func (c *SMTPConfig) GetWebhookConfig() map[string]interface{} {
	return map[string]interface{}{
		"enabled": c.EnableWebhooks,
		"url":     c.WebhookURL,
		"secret":  c.WebhookSecret,
		"timeout": c.WebhookTimeout,
		"retries": c.WebhookRetries,
		"events":  c.WebhookEvents,
		"headers": c.WebhookHeaders,
	}
}

// isValidEmail validates email format (basic validation)
func isValidEmail(email string) bool {
	// Basic email validation - you might want to use a more robust library
	if email == "" {
		return false
	}

	// Check for @ symbol
	if !strings.Contains(email, "@") {
		return false
	}

	// Split by @ and check parts
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return false
	}

	localPart := parts[0]
	domainPart := parts[1]

	// Basic checks
	if len(localPart) == 0 || len(domainPart) == 0 {
		return false
	}

	if len(localPart) > 64 || len(domainPart) > 253 {
		return false
	}

	// Check for valid domain
	if !strings.Contains(domainPart, ".") {
		return false
	}

	return true
}

// LoadSMTPTemplateVars loads template variables from environment
func LoadSMTPTemplateVars() map[string]string {
	vars := make(map[string]string)

	// Get all environment variables with SMTP_TEMPLATE_VAR_ prefix
	for _, env := range os.Environ() {
		if strings.HasPrefix(env, "SMTP_TEMPLATE_VAR_") {
			parts := strings.SplitN(env, "=", 2)
			if len(parts) == 2 {
				key := strings.TrimPrefix(parts[0], "SMTP_TEMPLATE_VAR_")
				key = strings.ToLower(key)
				vars[key] = parts[1]
			}
		}
	}

	return vars
}

// LoadSMTPWebhookHeaders loads webhook headers from environment
func LoadSMTPWebhookHeaders() map[string]string {
	headers := make(map[string]string)

	// Get all environment variables with SMTP_WEBHOOK_HEADER_ prefix
	for _, env := range os.Environ() {
		if strings.HasPrefix(env, "SMTP_WEBHOOK_HEADER_") {
			parts := strings.SplitN(env, "=", 2)
			if len(parts) == 2 {
				key := strings.TrimPrefix(parts[0], "SMTP_WEBHOOK_HEADER_")
				headers[key] = parts[1]
			}
		}
	}

	return headers
}

// LoadSMTPDefaultHeaders loads default headers from environment
func LoadSMTPDefaultHeaders() map[string]string {
	headers := make(map[string]string)

	// Get all environment variables with SMTP_DEFAULT_HEADER_ prefix
	for _, env := range os.Environ() {
		if strings.HasPrefix(env, "SMTP_DEFAULT_HEADER_") {
			parts := strings.SplitN(env, "=", 2)
			if len(parts) == 2 {
				key := strings.TrimPrefix(parts[0], "SMTP_DEFAULT_HEADER_")
				headers[key] = parts[1]
			}
		}
	}

	return headers
}
