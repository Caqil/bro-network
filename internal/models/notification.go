package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// Notification represents a notification for a user
type Notification struct {
	ID          primitive.ObjectID     `bson:"_id,omitempty" json:"id,omitempty"`
	UserID      primitive.ObjectID     `bson:"user_id" json:"user_id"`
	User        *User                  `bson:"user,omitempty" json:"user,omitempty"`
	ActorID     *primitive.ObjectID    `bson:"actor_id,omitempty" json:"actor_id,omitempty"`
	Actor       *User                  `bson:"actor,omitempty" json:"actor,omitempty"`
	Type        NotificationType       `bson:"type" json:"type"`
	Title       string                 `bson:"title" json:"title"`
	Message     string                 `bson:"message" json:"message"`
	Data        map[string]interface{} `bson:"data" json:"data"`
	TargetID    *primitive.ObjectID    `bson:"target_id,omitempty" json:"target_id,omitempty"`
	TargetType  NotificationTarget     `bson:"target_type,omitempty" json:"target_type,omitempty"`
	Priority    NotificationPriority   `bson:"priority" json:"priority"`
	Status      NotificationStatus     `bson:"status" json:"status"`
	Channel     []NotificationChannel  `bson:"channel" json:"channel"`
	IsRead      bool                   `bson:"is_read" json:"is_read"`
	IsArchived  bool                   `bson:"is_archived" json:"is_archived"`
	ReadAt      *time.Time             `bson:"read_at,omitempty" json:"read_at,omitempty"`
	SentAt      *time.Time             `bson:"sent_at,omitempty" json:"sent_at,omitempty"`
	ScheduledAt *time.Time             `bson:"scheduled_at,omitempty" json:"scheduled_at,omitempty"`
	ExpiresAt   *time.Time             `bson:"expires_at,omitempty" json:"expires_at,omitempty"`
	CreatedAt   time.Time              `bson:"created_at" json:"created_at"`
	UpdatedAt   time.Time              `bson:"updated_at" json:"updated_at"`
	DeletedAt   *time.Time             `bson:"deleted_at,omitempty" json:"deleted_at,omitempty"`
}

// NotificationType represents the type of notification
type NotificationType string

const (
	// Social notifications
	NotificationTypeLike           NotificationType = "like"
	NotificationTypeComment        NotificationType = "comment"
	NotificationTypeReply          NotificationType = "reply"
	NotificationTypeMention        NotificationType = "mention"
	NotificationTypeShare          NotificationType = "share"
	NotificationTypeQuote          NotificationType = "quote"
	NotificationTypeFollow         NotificationType = "follow"
	NotificationTypeFollowRequest  NotificationType = "follow_request"
	NotificationTypeFollowAccepted NotificationType = "follow_accepted"

	// Messaging notifications
	NotificationTypeMessage      NotificationType = "message"
	NotificationTypeGroupInvite  NotificationType = "group_invite"
	NotificationTypeGroupMessage NotificationType = "group_message"

	// System notifications
	NotificationTypeWelcome         NotificationType = "welcome"
	NotificationTypeAccountUpdate   NotificationType = "account_update"
	NotificationTypeSecurityAlert   NotificationType = "security_alert"
	NotificationTypePasswordChanged NotificationType = "password_changed"
	NotificationTypeEmailVerified   NotificationType = "email_verified"

	// Content notifications
	NotificationTypePostApproved   NotificationType = "post_approved"
	NotificationTypePostRejected   NotificationType = "post_rejected"
	NotificationTypeContentRemoved NotificationType = "content_removed"
	NotificationTypeContentWarning NotificationType = "content_warning"

	// Admin notifications
	NotificationTypeReportReceived  NotificationType = "report_received"
	NotificationTypeUserBanned      NotificationType = "user_banned"
	NotificationTypeUserUnbanned    NotificationType = "user_unbanned"
	NotificationTypeMaintenanceMode NotificationType = "maintenance_mode"

	// Marketing notifications
	NotificationTypePromotion  NotificationType = "promotion"
	NotificationTypeNewFeature NotificationType = "new_feature"
	NotificationTypeUpdate     NotificationType = "update"
)

// NotificationTarget represents the target type of notification
type NotificationTarget string

const (
	NotificationTargetPost         NotificationTarget = "post"
	NotificationTargetComment      NotificationTarget = "comment"
	NotificationTargetUser         NotificationTarget = "user"
	NotificationTargetMessage      NotificationTarget = "message"
	NotificationTargetConversation NotificationTarget = "conversation"
	NotificationTargetReport       NotificationTarget = "report"
)

// NotificationPriority represents notification priority
type NotificationPriority string

const (
	NotificationPriorityLow      NotificationPriority = "low"
	NotificationPriorityNormal   NotificationPriority = "normal"
	NotificationPriorityHigh     NotificationPriority = "high"
	NotificationPriorityCritical NotificationPriority = "critical"
)

// NotificationStatus represents notification status
type NotificationStatus string

const (
	NotificationStatusPending   NotificationStatus = "pending"
	NotificationStatusSent      NotificationStatus = "sent"
	NotificationStatusDelivered NotificationStatus = "delivered"
	NotificationStatusFailed    NotificationStatus = "failed"
	NotificationStatusCanceled  NotificationStatus = "canceled"
)

// NotificationChannel represents notification delivery channels
type NotificationChannel string

const (
	NotificationChannelInApp   NotificationChannel = "in_app"
	NotificationChannelPush    NotificationChannel = "push"
	NotificationChannelEmail   NotificationChannel = "email"
	NotificationChannelSMS     NotificationChannel = "sms"
	NotificationChannelSlack   NotificationChannel = "slack"
	NotificationChannelWebhook NotificationChannel = "webhook"
)

// NotificationCreateRequest represents notification creation request
type NotificationCreateRequest struct {
	UserID      primitive.ObjectID     `json:"user_id" binding:"required"`
	ActorID     *primitive.ObjectID    `json:"actor_id,omitempty"`
	Type        NotificationType       `json:"type" binding:"required"`
	Title       string                 `json:"title" binding:"required,max=100"`
	Message     string                 `json:"message" binding:"required,max=500"`
	Data        map[string]interface{} `json:"data"`
	TargetID    *primitive.ObjectID    `json:"target_id,omitempty"`
	TargetType  NotificationTarget     `json:"target_type,omitempty"`
	Priority    NotificationPriority   `json:"priority"`
	Channel     []NotificationChannel  `json:"channel"`
	ScheduledAt *time.Time             `json:"scheduled_at,omitempty"`
	ExpiresAt   *time.Time             `json:"expires_at,omitempty"`
}

// NotificationUpdateRequest represents notification update request
type NotificationUpdateRequest struct {
	IsRead     *bool `json:"is_read"`
	IsArchived *bool `json:"is_archived"`
}

// NotificationResponse represents notification response
type NotificationResponse struct {
	*Notification
	CanMarkRead bool `json:"can_mark_read"`
	CanArchive  bool `json:"can_archive"`
	CanDelete   bool `json:"can_delete"`
}

// NotificationListResponse represents notification list response
type NotificationListResponse struct {
	Notifications []NotificationResponse `json:"notifications"`
	TotalCount    int64                  `json:"total_count"`
	UnreadCount   int64                  `json:"unread_count"`
	Page          int                    `json:"page"`
	Limit         int                    `json:"limit"`
	HasMore       bool                   `json:"has_more"`
}

// NotificationFilter represents notification filter options
type NotificationFilter struct {
	UserID     *primitive.ObjectID   `json:"user_id,omitempty"`
	Type       *NotificationType     `json:"type,omitempty"`
	Priority   *NotificationPriority `json:"priority,omitempty"`
	Status     *NotificationStatus   `json:"status,omitempty"`
	IsRead     *bool                 `json:"is_read,omitempty"`
	IsArchived *bool                 `json:"is_archived,omitempty"`
	StartDate  *time.Time            `json:"start_date,omitempty"`
	EndDate    *time.Time            `json:"end_date,omitempty"`
	Page       int                   `json:"page"`
	Limit      int                   `json:"limit"`
	SortBy     string                `json:"sort_by"`    // created_at, priority
	SortOrder  string                `json:"sort_order"` // asc, desc
}

// NotificationSettings represents user notification preferences
type NotificationSettings struct {
	UserID             primitive.ObjectID                         `bson:"user_id" json:"user_id"`
	EmailNotifications bool                                       `bson:"email_notifications" json:"email_notifications"`
	PushNotifications  bool                                       `bson:"push_notifications" json:"push_notifications"`
	SMSNotifications   bool                                       `bson:"sms_notifications" json:"sms_notifications"`
	TypePreferences    map[NotificationType]bool                  `bson:"type_preferences" json:"type_preferences"`
	ChannelPreferences map[NotificationType][]NotificationChannel `bson:"channel_preferences" json:"channel_preferences"`
	QuietHours         QuietHours                                 `bson:"quiet_hours" json:"quiet_hours"`
	FrequencyLimits    FrequencyLimits                            `bson:"frequency_limits" json:"frequency_limits"`
	UpdatedAt          time.Time                                  `bson:"updated_at" json:"updated_at"`
}

// QuietHours represents notification quiet hours
type QuietHours struct {
	Enabled   bool   `bson:"enabled" json:"enabled"`
	StartTime string `bson:"start_time" json:"start_time"` // HH:MM format
	EndTime   string `bson:"end_time" json:"end_time"`     // HH:MM format
	TimeZone  string `bson:"timezone" json:"timezone"`
}

// FrequencyLimits represents notification frequency limits
type FrequencyLimits struct {
	MaxPerHour int `bson:"max_per_hour" json:"max_per_hour"`
	MaxPerDay  int `bson:"max_per_day" json:"max_per_day"`
	MaxPerWeek int `bson:"max_per_week" json:"max_per_week"`
}

// NotificationBatch represents batch notification for efficiency
type NotificationBatch struct {
	ID            primitive.ObjectID     `bson:"_id,omitempty" json:"id,omitempty"`
	Type          NotificationType       `bson:"type" json:"type"`
	UserIDs       []primitive.ObjectID   `bson:"user_ids" json:"user_ids"`
	Title         string                 `bson:"title" json:"title"`
	Message       string                 `bson:"message" json:"message"`
	Data          map[string]interface{} `bson:"data" json:"data"`
	Priority      NotificationPriority   `bson:"priority" json:"priority"`
	Channel       []NotificationChannel  `bson:"channel" json:"channel"`
	Status        NotificationStatus     `bson:"status" json:"status"`
	ScheduledAt   *time.Time             `bson:"scheduled_at,omitempty" json:"scheduled_at,omitempty"`
	SentAt        *time.Time             `bson:"sent_at,omitempty" json:"sent_at,omitempty"`
	FailedUserIDs []primitive.ObjectID   `bson:"failed_user_ids" json:"failed_user_ids"`
	CreatedAt     time.Time              `bson:"created_at" json:"created_at"`
	UpdatedAt     time.Time              `bson:"updated_at" json:"updated_at"`
}

// =============================================================================
// DEVICE AND PUSH NOTIFICATION MODELS
// =============================================================================

// Device represents a registered device for push notifications
type Device struct {
	ID          primitive.ObjectID `bson:"_id,omitempty" json:"id,omitempty"`
	UserID      primitive.ObjectID `bson:"user_id" json:"user_id"`
	DeviceToken string             `bson:"device_token" json:"device_token"`
	DeviceType  DeviceType         `bson:"device_type" json:"device_type"`
	DeviceName  string             `bson:"device_name" json:"device_name"`
	AppVersion  string             `bson:"app_version" json:"app_version"`
	Platform    PushPlatform       `bson:"platform" json:"platform"`
	Environment string             `bson:"environment" json:"environment"` // development, production
	IsActive    bool               `bson:"is_active" json:"is_active"`
	LastUsed    *time.Time         `bson:"last_used,omitempty" json:"last_used,omitempty"`
	CreatedAt   time.Time          `bson:"created_at" json:"created_at"`
	UpdatedAt   time.Time          `bson:"updated_at" json:"updated_at"`
}

// DeviceType represents device types
type DeviceType string

const (
	DeviceTypeIOS     DeviceType = "ios"
	DeviceTypeAndroid DeviceType = "android"
	DeviceTypeWeb     DeviceType = "web"
)

// PushPlatform represents push notification platforms
type PushPlatform string

const (
	PushPlatformIOS     PushPlatform = "ios"
	PushPlatformAndroid PushPlatform = "android"
	PushPlatformWeb     PushPlatform = "web"
	PushPlatformHuawei  PushPlatform = "huawei"
)

// PushToken represents a push notification token
type PushToken struct {
	ID          primitive.ObjectID `bson:"_id,omitempty" json:"id,omitempty"`
	UserID      primitive.ObjectID `bson:"user_id" json:"user_id"`
	Token       string             `bson:"token" json:"token"`
	Platform    PushPlatform       `bson:"platform" json:"platform"`
	Environment string             `bson:"environment" json:"environment"`
	IsActive    bool               `bson:"is_active" json:"is_active"`
	CreatedAt   time.Time          `bson:"created_at" json:"created_at"`
	UpdatedAt   time.Time          `bson:"updated_at" json:"updated_at"`
}

// =============================================================================
// NOTIFICATION TEMPLATES
// =============================================================================

// NotificationTemplate represents a notification template
type NotificationTemplate struct {
	ID          primitive.ObjectID            `bson:"_id,omitempty" json:"id,omitempty"`
	Name        string                        `bson:"name" json:"name"`
	Type        NotificationType              `bson:"type" json:"type"`
	Channel     NotificationChannel           `bson:"channel" json:"channel"`
	Subject     string                        `bson:"subject,omitempty" json:"subject,omitempty"`
	Content     string                        `bson:"content" json:"content"`
	Variables   []TemplateVariable            `bson:"variables" json:"variables"`
	Settings    map[string]interface{}        `bson:"settings" json:"settings"`
	Metadata    map[string]interface{}        `bson:"metadata" json:"metadata"`
	IsActive    bool                          `bson:"is_active" json:"is_active"`
	CreatedBy   primitive.ObjectID            `bson:"created_by" json:"created_by"`
	CreatedAt   time.Time                     `bson:"created_at" json:"created_at"`
	UpdatedAt   time.Time                     `bson:"updated_at" json:"updated_at"`
}

// TemplateVariable represents a template variable
type TemplateVariable struct {
	Name        string `json:"name"`
	Type        string `json:"type"`        // string, number, boolean, date
	Required    bool   `json:"required"`
	Default     string `json:"default"`
	Description string `json:"description"`
}

// =============================================================================
// WEBHOOK MODELS
// =============================================================================

// NotificationWebhook represents a notification webhook
type NotificationWebhook struct {
	ID          primitive.ObjectID   `bson:"_id,omitempty" json:"id,omitempty"`
	UserID      primitive.ObjectID   `bson:"user_id" json:"user_id"`
	URL         string               `bson:"url" json:"url"`
	Events      []WebhookEvent       `bson:"events" json:"events"`
	Secret      string               `bson:"secret" json:"secret"`
	Headers     map[string]string    `bson:"headers" json:"headers"`
	IsActive    bool                 `bson:"is_active" json:"is_active"`
	LastTriggered *time.Time         `bson:"last_triggered,omitempty" json:"last_triggered,omitempty"`
	FailureCount  int                `bson:"failure_count" json:"failure_count"`
	CreatedAt     time.Time          `bson:"created_at" json:"created_at"`
	UpdatedAt     time.Time          `bson:"updated_at" json:"updated_at"`
}

// WebhookEvent represents webhook events
type WebhookEvent string

const (
	WebhookEventNotificationCreated WebhookEvent = "notification.created"
	WebhookEventNotificationRead    WebhookEvent = "notification.read"
	WebhookEventNotificationDeleted WebhookEvent = "notification.deleted"
)

// WebhookLog represents webhook delivery log
type WebhookLog struct {
	ID         primitive.ObjectID `bson:"_id,omitempty" json:"id,omitempty"`
	WebhookID  primitive.ObjectID `bson:"webhook_id" json:"webhook_id"`
	Event      WebhookEvent       `bson:"event" json:"event"`
	Payload    map[string]interface{} `bson:"payload" json:"payload"`
	Response   string             `bson:"response" json:"response"`
	StatusCode int                `bson:"status_code" json:"status_code"`
	Success    bool               `bson:"success" json:"success"`
	Error      string             `bson:"error,omitempty" json:"error,omitempty"`
	Duration   int64              `bson:"duration" json:"duration"` // milliseconds
	CreatedAt  time.Time          `bson:"created_at" json:"created_at"`
}

// =============================================================================
// NOTIFICATION ANALYTICS MODELS
// =============================================================================

// NotificationAnalytics represents notification analytics data
type NotificationAnalytics struct {
	ID                 primitive.ObjectID `bson:"_id,omitempty" json:"id,omitempty"`
	Date               string             `bson:"date" json:"date"` // YYYY-MM-DD
	UserID             *primitive.ObjectID `bson:"user_id,omitempty" json:"user_id,omitempty"`
	Type               NotificationType    `bson:"type" json:"type"`
	Channel            NotificationChannel `bson:"channel" json:"channel"`
	TotalSent          int64              `bson:"total_sent" json:"total_sent"`
	TotalDelivered     int64              `bson:"total_delivered" json:"total_delivered"`
	TotalRead          int64              `bson:"total_read" json:"total_read"`
	TotalClicked       int64              `bson:"total_clicked" json:"total_clicked"`
	TotalFailed        int64              `bson:"total_failed" json:"total_failed"`
	DeliveryRate       float64            `bson:"delivery_rate" json:"delivery_rate"`
	OpenRate           float64            `bson:"open_rate" json:"open_rate"`
	ClickRate          float64            `bson:"click_rate" json:"click_rate"`
	EngagementRate     float64            `bson:"engagement_rate" json:"engagement_rate"`
	CreatedAt          time.Time          `bson:"created_at" json:"created_at"`
	UpdatedAt          time.Time          `bson:"updated_at" json:"updated_at"`
}

// =============================================================================
// NOTIFICATION RULES
// =============================================================================

// NotificationRule represents custom notification rules
type NotificationRule struct {
	ID          primitive.ObjectID     `bson:"_id,omitempty" json:"id,omitempty"`
	UserID      primitive.ObjectID     `bson:"user_id" json:"user_id"`
	Name        string                 `bson:"name" json:"name"`
	Conditions  []RuleCondition        `bson:"conditions" json:"conditions"`
	Actions     []RuleAction           `bson:"actions" json:"actions"`
	Priority    int                    `bson:"priority" json:"priority"`
	IsActive    bool                   `bson:"is_active" json:"is_active"`
	CreatedAt   time.Time              `bson:"created_at" json:"created_at"`
	UpdatedAt   time.Time              `bson:"updated_at" json:"updated_at"`
}

// RuleCondition represents a rule condition
type RuleCondition struct {
	Field    string      `json:"field"`    // type, priority, actor_id, etc.
	Operator string      `json:"operator"` // equals, contains, in, etc.
	Value    interface{} `json:"value"`
}

// RuleAction represents a rule action
type RuleAction struct {
	Type   string                 `json:"type"`   // mute, archive, forward, etc.
	Config map[string]interface{} `json:"config"`
}

// =============================================================================
// REALTIME CONNECTION MODELS
// =============================================================================

// RealtimeConnection represents a real-time notification connection
type RealtimeConnection struct {
	ID            primitive.ObjectID `bson:"_id,omitempty" json:"id,omitempty"`
	UserID        primitive.ObjectID `bson:"user_id" json:"user_id"`
	ConnectionID  string             `bson:"connection_id" json:"connection_id"`
	Type          ConnectionType     `bson:"type" json:"type"`
	IsActive      bool               `bson:"is_active" json:"is_active"`
	LastHeartbeat *time.Time         `bson:"last_heartbeat,omitempty" json:"last_heartbeat,omitempty"`
	UserAgent     string             `bson:"user_agent" json:"user_agent"`
	IPAddress     string             `bson:"ip_address" json:"ip_address"`
	CreatedAt     time.Time          `bson:"created_at" json:"created_at"`
	UpdatedAt     time.Time          `bson:"updated_at" json:"updated_at"`
}

// ConnectionType represents connection types
type ConnectionType string

const (
	ConnectionTypeWebSocket ConnectionType = "websocket"
	ConnectionTypeSSE       ConnectionType = "sse"
)

// RealtimePreferences represents real-time preferences
type RealtimePreferences struct {
	UserID             primitive.ObjectID `bson:"user_id" json:"user_id"`
	AutoConnect        bool               `bson:"auto_connect" json:"auto_connect"`
	ConnectionTimeout  int                `bson:"connection_timeout" json:"connection_timeout"`   // seconds
	ReconnectAttempts  int                `bson:"reconnect_attempts" json:"reconnect_attempts"`
	HeartbeatInterval  int                `bson:"heartbeat_interval" json:"heartbeat_interval"`   // seconds
	EnabledTypes       []NotificationType `bson:"enabled_types" json:"enabled_types"`
	UpdatedAt          time.Time          `bson:"updated_at" json:"updated_at"`
}

// =============================================================================
// EMAIL AND SMS MODELS
// =============================================================================

// EmailPreferences represents email notification preferences
type EmailPreferences struct {
	UserID           primitive.ObjectID `bson:"user_id" json:"user_id"`
	MarketingEmails  bool               `bson:"marketing_emails" json:"marketing_emails"`
	DigestEmails     bool               `bson:"digest_emails" json:"digest_emails"`
	SecurityAlerts   bool               `bson:"security_alerts" json:"security_alerts"`
	SocialUpdates    bool               `bson:"social_updates" json:"social_updates"`
	ProductUpdates   bool               `bson:"product_updates" json:"product_updates"`
	DigestFrequency  DigestFrequency    `bson:"digest_frequency" json:"digest_frequency"`
	DigestTime       string             `bson:"digest_time" json:"digest_time"` // HH:MM format
	IsUnsubscribed   bool               `bson:"is_unsubscribed" json:"is_unsubscribed"`
	UnsubscribeToken string             `bson:"unsubscribe_token" json:"unsubscribe_token"`
	UpdatedAt        time.Time          `bson:"updated_at" json:"updated_at"`
}

// DigestFrequency represents email digest frequency
type DigestFrequency string

const (
	DigestFrequencyNone    DigestFrequency = "none"
	DigestFrequencyDaily   DigestFrequency = "daily"
	DigestFrequencyWeekly  DigestFrequency = "weekly"
	DigestFrequencyMonthly DigestFrequency = "monthly"
)

// SMSPreferences represents SMS notification preferences  
type SMSPreferences struct {
	UserID            primitive.ObjectID `bson:"user_id" json:"user_id"`
	PhoneNumber       string             `bson:"phone_number" json:"phone_number"`
	CountryCode       string             `bson:"country_code" json:"country_code"`
	IsVerified        bool               `bson:"is_verified" json:"is_verified"`
	SecurityAlerts    bool               `bson:"security_alerts" json:"security_alerts"`
	CriticalUpdates   bool               `bson:"critical_updates" json:"critical_updates"`
	VerificationToken string             `bson:"verification_token" json:"verification_token"`
	VerifiedAt        *time.Time         `bson:"verified_at,omitempty" json:"verified_at,omitempty"`
	UpdatedAt         time.Time          `bson:"updated_at" json:"updated_at"`
}

// =============================================================================
// DELIVERY STATUS MODELS
// =============================================================================

// DeliveryStatus represents notification delivery status
type DeliveryStatus struct {
	ID             primitive.ObjectID  `bson:"_id,omitempty" json:"id,omitempty"`
	NotificationID primitive.ObjectID  `bson:"notification_id" json:"notification_id"`
	Channel        NotificationChannel `bson:"channel" json:"channel"`
	Status         DeliveryStatusType  `bson:"status" json:"status"`
	Attempts       int                 `bson:"attempts" json:"attempts"`
	LastAttempt    *time.Time          `bson:"last_attempt,omitempty" json:"last_attempt,omitempty"`
	DeliveredAt    *time.Time          `bson:"delivered_at,omitempty" json:"delivered_at,omitempty"`
	ErrorMessage   string              `bson:"error_message,omitempty" json:"error_message,omitempty"`
	ExternalID     string              `bson:"external_id,omitempty" json:"external_id,omitempty"`
	CreatedAt      time.Time           `bson:"created_at" json:"created_at"`
	UpdatedAt      time.Time           `bson:"updated_at" json:"updated_at"`
}

// DeliveryStatusType represents delivery status types
type DeliveryStatusType string

const (
	DeliveryStatusPending   DeliveryStatusType = "pending"
	DeliveryStatusSent      DeliveryStatusType = "sent"
	DeliveryStatusDelivered DeliveryStatusType = "delivered"
	DeliveryStatusFailed    DeliveryStatusType = "failed"
	DeliveryStatusBounced   DeliveryStatusType = "bounced"
)