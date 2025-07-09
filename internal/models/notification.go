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
