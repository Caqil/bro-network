package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// Audit represents an audit log entry for tracking admin/security actions
type Audit struct {
	ID          primitive.ObjectID     `bson:"_id,omitempty" json:"id,omitempty"`
	UserID      *primitive.ObjectID    `bson:"user_id,omitempty" json:"user_id,omitempty"`
	User        *User                  `bson:"user,omitempty" json:"user,omitempty"`
	Action      AuditAction            `bson:"action" json:"action"`
	Category    AuditCategory          `bson:"category" json:"category"`
	Resource    AuditResource          `bson:"resource" json:"resource"`
	ResourceID  *primitive.ObjectID    `bson:"resource_id,omitempty" json:"resource_id,omitempty"`
	TargetID    *primitive.ObjectID    `bson:"target_id,omitempty" json:"target_id,omitempty"`
	TargetType  string                 `bson:"target_type,omitempty" json:"target_type,omitempty"`
	Description string                 `bson:"description" json:"description"`
	Details     AuditDetails           `bson:"details" json:"details"`
	Metadata    AuditMetadata          `bson:"metadata" json:"metadata"`
	Status      AuditStatus            `bson:"status" json:"status"`
	Severity    AuditSeverity          `bson:"severity" json:"severity"`
	IPAddress   string                 `bson:"ip_address" json:"ip_address"`
	UserAgent   string                 `bson:"user_agent" json:"user_agent"`
	SessionID   string                 `bson:"session_id" json:"session_id"`
	RequestID   string                 `bson:"request_id" json:"request_id"`
	Changes     []AuditChange          `bson:"changes" json:"changes"`
	Context     map[string]interface{} `bson:"context" json:"context"`
	CreatedAt   time.Time              `bson:"created_at" json:"created_at"`
}

// AuditAction represents the type of action performed
type AuditAction string

const (
	// User actions
	AuditActionUserCreate           AuditAction = "user_create"
	AuditActionUserUpdate           AuditAction = "user_update"
	AuditActionUserDelete           AuditAction = "user_delete"
	AuditActionUserLogin            AuditAction = "user_login"
	AuditActionUserLogout           AuditAction = "user_logout"
	AuditActionUserBan              AuditAction = "user_ban"
	AuditActionUserUnban            AuditAction = "user_unban"
	AuditActionUserSuspend          AuditAction = "user_suspend"
	AuditActionUserUnsuspend        AuditAction = "user_unsuspend"
	AuditActionUserRoleChange       AuditAction = "user_role_change"
	AuditActionUserPermissionChange AuditAction = "user_permission_change"

	// Content actions
	AuditActionPostCreate     AuditAction = "post_create"
	AuditActionPostUpdate     AuditAction = "post_update"
	AuditActionPostDelete     AuditAction = "post_delete"
	AuditActionPostRestore    AuditAction = "post_restore"
	AuditActionPostHide       AuditAction = "post_hide"
	AuditActionPostUnhide     AuditAction = "post_unhide"
	AuditActionCommentDelete  AuditAction = "comment_delete"
	AuditActionCommentRestore AuditAction = "comment_restore"
	AuditActionCommentHide    AuditAction = "comment_hide"

	// Moderation actions
	AuditActionReportCreate   AuditAction = "report_create"
	AuditActionReportResolve  AuditAction = "report_resolve"
	AuditActionReportEscalate AuditAction = "report_escalate"
	AuditActionContentFlag    AuditAction = "content_flag"
	AuditActionContentUnflag  AuditAction = "content_unflag"
	AuditActionWarningIssue   AuditAction = "warning_issue"

	// System actions
	AuditActionSystemStartup     AuditAction = "system_startup"
	AuditActionSystemShutdown    AuditAction = "system_shutdown"
	AuditActionConfigChange      AuditAction = "config_change"
	AuditActionDatabaseMigration AuditAction = "database_migration"
	AuditActionBackupCreate      AuditAction = "backup_create"
	AuditActionBackupRestore     AuditAction = "backup_restore"

	// Security actions
	AuditActionLoginAttempt       AuditAction = "login_attempt"
	AuditActionLoginFailure       AuditAction = "login_failure"
	AuditActionPasswordChange     AuditAction = "password_change"
	AuditActionPasswordReset      AuditAction = "password_reset"
	AuditActionTwoFactorEnable    AuditAction = "two_factor_enable"
	AuditActionTwoFactorDisable   AuditAction = "two_factor_disable"
	AuditActionSecurityAlert      AuditAction = "security_alert"
	AuditActionSuspiciousActivity AuditAction = "suspicious_activity"
	AuditActionAPIKeyCreate       AuditAction = "api_key_create"
	AuditActionAPIKeyRevoke       AuditAction = "api_key_revoke"

	// Admin actions
	AuditActionAdminAccess     AuditAction = "admin_access"
	AuditActionSettingsChange  AuditAction = "settings_change"
	AuditActionFeatureToggle   AuditAction = "feature_toggle"
	AuditActionMaintenanceMode AuditAction = "maintenance_mode"
	AuditActionDataExport      AuditAction = "data_export"
	AuditActionDataImport      AuditAction = "data_import"
	AuditActionCacheInvalidate AuditAction = "cache_invalidate"

	// File actions
	AuditActionFileUpload AuditAction = "file_upload"
	AuditActionFileDelete AuditAction = "file_delete"
	AuditActionFileAccess AuditAction = "file_access"
)

// AuditCategory represents the category of audit action
type AuditCategory string

const (
	AuditCategoryAuthentication    AuditCategory = "authentication"
	AuditCategoryAuthorization     AuditCategory = "authorization"
	AuditCategoryUserManagement    AuditCategory = "user_management"
	AuditCategoryContentManagement AuditCategory = "content_management"
	AuditCategoryModeration        AuditCategory = "moderation"
	AuditCategorySystem            AuditCategory = "system"
	AuditCategorySecurity          AuditCategory = "security"
	AuditCategoryConfiguration     AuditCategory = "configuration"
	AuditCategoryData              AuditCategory = "data"
	AuditCategoryFile              AuditCategory = "file"
	AuditCategoryAPI               AuditCategory = "api"
)

// AuditResource represents the resource being audited
type AuditResource string

const (
	AuditResourceUser         AuditResource = "user"
	AuditResourcePost         AuditResource = "post"
	AuditResourceComment      AuditResource = "comment"
	AuditResourceMessage      AuditResource = "message"
	AuditResourceReport       AuditResource = "report"
	AuditResourceNotification AuditResource = "notification"
	AuditResourceSystem       AuditResource = "system"
	AuditResourceConfig       AuditResource = "config"
	AuditResourceDatabase     AuditResource = "database"
	AuditResourceFile         AuditResource = "file"
	AuditResourceAPI          AuditResource = "api"
	AuditResourceSession      AuditResource = "session"
)

// AuditStatus represents the status of the audited action
type AuditStatus string

const (
	AuditStatusSuccess AuditStatus = "success"
	AuditStatusFailure AuditStatus = "failure"
	AuditStatusPending AuditStatus = "pending"
	AuditStatusError   AuditStatus = "error"
)

// AuditSeverity represents the severity level of the audit event
type AuditSeverity string

const (
	AuditSeverityLow      AuditSeverity = "low"
	AuditSeverityMedium   AuditSeverity = "medium"
	AuditSeverityHigh     AuditSeverity = "high"
	AuditSeverityCritical AuditSeverity = "critical"
)

// AuditDetails represents detailed information about the audit event
type AuditDetails struct {
	Method       string                 `bson:"method" json:"method"`
	URL          string                 `bson:"url" json:"url"`
	StatusCode   int                    `bson:"status_code" json:"status_code"`
	ResponseTime int64                  `bson:"response_time" json:"response_time"` // in milliseconds
	RequestSize  int64                  `bson:"request_size" json:"request_size"`
	ResponseSize int64                  `bson:"response_size" json:"response_size"`
	ErrorMessage string                 `bson:"error_message,omitempty" json:"error_message,omitempty"`
	StackTrace   string                 `bson:"stack_trace,omitempty" json:"stack_trace,omitempty"`
	RequestBody  map[string]interface{} `bson:"request_body,omitempty" json:"request_body,omitempty"`
	ResponseBody map[string]interface{} `bson:"response_body,omitempty" json:"response_body,omitempty"`
	Headers      map[string]string      `bson:"headers,omitempty" json:"headers,omitempty"`
	QueryParams  map[string]string      `bson:"query_params,omitempty" json:"query_params,omitempty"`
}

// AuditMetadata represents additional metadata for audit events
type AuditMetadata struct {
	Source       string                 `bson:"source" json:"source"` // web, mobile, api
	Version      string                 `bson:"version" json:"version"`
	Environment  string                 `bson:"environment" json:"environment"` // dev, staging, prod
	RequestID    string                 `bson:"request_id" json:"request_id"`
	TraceID      string                 `bson:"trace_id" json:"trace_id"`
	SpanID       string                 `bson:"span_id" json:"span_id"`
	GeoLocation  GeoLocation            `bson:"geo_location,omitempty" json:"geo_location,omitempty"`
	DeviceInfo   DeviceInfo             `bson:"device_info,omitempty" json:"device_info,omitempty"`
	RiskScore    float64                `bson:"risk_score,omitempty" json:"risk_score,omitempty"`
	Flags        []string               `bson:"flags,omitempty" json:"flags,omitempty"`
	Tags         []string               `bson:"tags,omitempty" json:"tags,omitempty"`
	CustomFields map[string]interface{} `bson:"custom_fields,omitempty" json:"custom_fields,omitempty"`
}

// GeoLocation represents geographical location information
type GeoLocation struct {
	Country   string  `bson:"country" json:"country"`
	Region    string  `bson:"region" json:"region"`
	City      string  `bson:"city" json:"city"`
	Latitude  float64 `bson:"latitude" json:"latitude"`
	Longitude float64 `bson:"longitude" json:"longitude"`
	Timezone  string  `bson:"timezone" json:"timezone"`
	ISP       string  `bson:"isp" json:"isp"`
}

// DeviceInfo represents device information
type DeviceInfo struct {
	DeviceType     string `bson:"device_type" json:"device_type"` // mobile, tablet, desktop
	OS             string `bson:"os" json:"os"`
	OSVersion      string `bson:"os_version" json:"os_version"`
	Browser        string `bson:"browser" json:"browser"`
	BrowserVersion string `bson:"browser_version" json:"browser_version"`
	ScreenSize     string `bson:"screen_size" json:"screen_size"`
	Language       string `bson:"language" json:"language"`
}

// AuditChange represents a change made to a field
type AuditChange struct {
	Field     string      `bson:"field" json:"field"`
	OldValue  interface{} `bson:"old_value" json:"old_value"`
	NewValue  interface{} `bson:"new_value" json:"new_value"`
	DataType  string      `bson:"data_type" json:"data_type"`
	Sensitive bool        `bson:"sensitive" json:"sensitive"`
}

// AuditCreateRequest represents audit log creation request
type AuditCreateRequest struct {
	UserID      *primitive.ObjectID    `json:"user_id,omitempty"`
	Action      AuditAction            `json:"action" binding:"required"`
	Category    AuditCategory          `json:"category" binding:"required"`
	Resource    AuditResource          `json:"resource" binding:"required"`
	ResourceID  *primitive.ObjectID    `json:"resource_id,omitempty"`
	TargetID    *primitive.ObjectID    `json:"target_id,omitempty"`
	TargetType  string                 `json:"target_type,omitempty"`
	Description string                 `json:"description" binding:"required"`
	Details     AuditDetails           `json:"details"`
	Metadata    AuditMetadata          `json:"metadata"`
	Status      AuditStatus            `json:"status"`
	Severity    AuditSeverity          `json:"severity"`
	Changes     []AuditChange          `json:"changes"`
	Context     map[string]interface{} `json:"context"`
}

// AuditResponse represents audit log response
type AuditResponse struct {
	*Audit
	CanView   bool `json:"can_view"`
	CanExport bool `json:"can_export"`
}

// AuditListResponse represents audit log list response
type AuditListResponse struct {
	Audits     []AuditResponse `json:"audits"`
	TotalCount int64           `json:"total_count"`
	Page       int             `json:"page"`
	Limit      int             `json:"limit"`
	HasMore    bool            `json:"has_more"`
}

// AuditFilter represents audit log filter options
type AuditFilter struct {
	UserID      *primitive.ObjectID `json:"user_id,omitempty"`
	Action      *AuditAction        `json:"action,omitempty"`
	Category    *AuditCategory      `json:"category,omitempty"`
	Resource    *AuditResource      `json:"resource,omitempty"`
	ResourceID  *primitive.ObjectID `json:"resource_id,omitempty"`
	Status      *AuditStatus        `json:"status,omitempty"`
	Severity    *AuditSeverity      `json:"severity,omitempty"`
	IPAddress   string              `json:"ip_address,omitempty"`
	StartDate   *time.Time          `json:"start_date,omitempty"`
	EndDate     *time.Time          `json:"end_date,omitempty"`
	SearchTerm  string              `json:"search_term,omitempty"`
	Tags        []string            `json:"tags,omitempty"`
	Environment string              `json:"environment,omitempty"`
	Source      string              `json:"source,omitempty"`
	Page        int                 `json:"page"`
	Limit       int                 `json:"limit"`
	SortBy      string              `json:"sort_by"`    // created_at, severity, status
	SortOrder   string              `json:"sort_order"` // asc, desc
}

// AuditStats represents audit statistics
type AuditStats struct {
	TotalEvents          int64                   `json:"total_events"`
	EventsByCategory     map[AuditCategory]int64 `json:"events_by_category"`
	EventsByAction       map[AuditAction]int64   `json:"events_by_action"`
	EventsByStatus       map[AuditStatus]int64   `json:"events_by_status"`
	EventsBySeverity     map[AuditSeverity]int64 `json:"events_by_severity"`
	TopUsers             []UserEventCount        `json:"top_users"`
	TopIPAddresses       []IPEventCount          `json:"top_ip_addresses"`
	FailureRate          float64                 `json:"failure_rate"`
	AvgResponseTime      float64                 `json:"avg_response_time"`
	SecurityAlerts       int64                   `json:"security_alerts"`
	SuspiciousActivities int64                   `json:"suspicious_activities"`
	Period               AnalyticsPeriod         `json:"period"`
}

// UserEventCount represents user event count for statistics
type UserEventCount struct {
	UserID     primitive.ObjectID `json:"user_id"`
	Username   string             `json:"username"`
	EventCount int64              `json:"event_count"`
}

// IPEventCount represents IP address event count for statistics
type IPEventCount struct {
	IPAddress  string `json:"ip_address"`
	EventCount int64  `json:"event_count"`
	Location   string `json:"location,omitempty"`
}

// AuditConfiguration represents audit configuration settings
type AuditConfiguration struct {
	ID                primitive.ObjectID   `bson:"_id,omitempty" json:"id,omitempty"`
	Enabled           bool                 `bson:"enabled" json:"enabled"`
	RetentionDays     int                  `bson:"retention_days" json:"retention_days"`
	LogLevel          AuditSeverity        `bson:"log_level" json:"log_level"`
	EnabledCategories []AuditCategory      `bson:"enabled_categories" json:"enabled_categories"`
	EnabledActions    []AuditAction        `bson:"enabled_actions" json:"enabled_actions"`
	SensitiveFields   []string             `bson:"sensitive_fields" json:"sensitive_fields"`
	ExcludedIPs       []string             `bson:"excluded_ips" json:"excluded_ips"`
	AlertRules        []AuditAlertRule     `bson:"alert_rules" json:"alert_rules"`
	ExportSettings    AuditExportSettings  `bson:"export_settings" json:"export_settings"`
	ArchiveSettings   AuditArchiveSettings `bson:"archive_settings" json:"archive_settings"`
	CreatedAt         time.Time            `bson:"created_at" json:"created_at"`
	UpdatedAt         time.Time            `bson:"updated_at" json:"updated_at"`
}

// AuditAlertRule represents rules for audit alerts
type AuditAlertRule struct {
	ID          primitive.ObjectID `bson:"_id,omitempty" json:"id,omitempty"`
	Name        string             `bson:"name" json:"name"`
	Description string             `bson:"description" json:"description"`
	Enabled     bool               `bson:"enabled" json:"enabled"`
	Conditions  AlertConditions    `bson:"conditions" json:"conditions"`
	Actions     AlertActions       `bson:"actions" json:"actions"`
	Cooldown    time.Duration      `bson:"cooldown" json:"cooldown"`
	CreatedAt   time.Time          `bson:"created_at" json:"created_at"`
	UpdatedAt   time.Time          `bson:"updated_at" json:"updated_at"`
}

// AlertConditions represents conditions for audit alerts
type AlertConditions struct {
	Categories    []AuditCategory `bson:"categories" json:"categories"`
	Actions       []AuditAction   `bson:"actions" json:"actions"`
	Severities    []AuditSeverity `bson:"severities" json:"severities"`
	FailureRate   float64         `bson:"failure_rate" json:"failure_rate"`
	EventCount    int64           `bson:"event_count" json:"event_count"`
	TimeWindow    time.Duration   `bson:"time_window" json:"time_window"`
	UserThreshold int64           `bson:"user_threshold" json:"user_threshold"`
	IPThreshold   int64           `bson:"ip_threshold" json:"ip_threshold"`
}

// AlertActions represents actions to take when alert conditions are met
type AlertActions struct {
	SendEmail       bool     `bson:"send_email" json:"send_email"`
	EmailRecipients []string `bson:"email_recipients" json:"email_recipients"`
	SendSlack       bool     `bson:"send_slack" json:"send_slack"`
	SlackChannel    string   `bson:"slack_channel" json:"slack_channel"`
	SendWebhook     bool     `bson:"send_webhook" json:"send_webhook"`
	WebhookURL      string   `bson:"webhook_url" json:"webhook_url"`
	CreateTicket    bool     `bson:"create_ticket" json:"create_ticket"`
	BlockIP         bool     `bson:"block_ip" json:"block_ip"`
	SuspendUser     bool     `bson:"suspend_user" json:"suspend_user"`
}

// AuditExportSettings represents settings for audit log exports
type AuditExportSettings struct {
	EnableAutoExport bool          `bson:"enable_auto_export" json:"enable_auto_export"`
	ExportInterval   time.Duration `bson:"export_interval" json:"export_interval"`
	ExportFormat     string        `bson:"export_format" json:"export_format"` // json, csv, xml
	Destination      string        `bson:"destination" json:"destination"`     // s3, ftp, email
	EncryptExports   bool          `bson:"encrypt_exports" json:"encrypt_exports"`
	CompressionType  string        `bson:"compression_type" json:"compression_type"` // gzip, zip
}

// AuditArchiveSettings represents settings for audit log archiving
type AuditArchiveSettings struct {
	EnableAutoArchive bool   `bson:"enable_auto_archive" json:"enable_auto_archive"`
	ArchiveAfterDays  int    `bson:"archive_after_days" json:"archive_after_days"`
	ArchiveLocation   string `bson:"archive_location" json:"archive_location"`
	DeleteAfterDays   int    `bson:"delete_after_days" json:"delete_after_days"`
	CompressionLevel  int    `bson:"compression_level" json:"compression_level"`
}
