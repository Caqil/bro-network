package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// Message represents a direct message between users
type Message struct {
	ID               primitive.ObjectID   `bson:"_id,omitempty" json:"id,omitempty"`
	ConversationID   primitive.ObjectID   `bson:"conversation_id" json:"conversation_id"`
	SenderID         primitive.ObjectID   `bson:"sender_id" json:"sender_id"`
	RecipientID      primitive.ObjectID   `bson:"recipient_id" json:"recipient_id"`
	Sender           *User                `bson:"sender,omitempty" json:"sender,omitempty"`
	Recipient        *User                `bson:"recipient,omitempty" json:"recipient,omitempty"`
	Content          string               `bson:"content" json:"content" binding:"required,max=1000"`
	MessageType      MessageType          `bson:"message_type" json:"message_type"`
	MediaFiles       []MediaFile          `bson:"media_files" json:"media_files"`
	ReplyToID        *primitive.ObjectID  `bson:"reply_to_id,omitempty" json:"reply_to_id,omitempty"`
	ReplyTo          *Message             `bson:"reply_to,omitempty" json:"reply_to,omitempty"`
	ForwardedFromID  *primitive.ObjectID  `bson:"forwarded_from_id,omitempty" json:"forwarded_from_id,omitempty"`
	Mentions         []primitive.ObjectID `bson:"mentions" json:"mentions"`
	Status           MessageStatus        `bson:"status" json:"status"`
	IsEdited         bool                 `bson:"is_edited" json:"is_edited"`
	IsStarred        bool                 `bson:"is_starred" json:"is_starred"`
	SensitiveContent bool                 `bson:"sensitive_content" json:"sensitive_content"`
	ReadAt           *time.Time           `bson:"read_at,omitempty" json:"read_at,omitempty"`
	DeliveredAt      *time.Time           `bson:"delivered_at,omitempty" json:"delivered_at,omitempty"`
	EditedAt         *time.Time           `bson:"edited_at,omitempty" json:"edited_at,omitempty"`
	CreatedAt        time.Time            `bson:"created_at" json:"created_at"`
	UpdatedAt        time.Time            `bson:"updated_at" json:"updated_at"`
	DeletedAt        *time.Time           `bson:"deleted_at,omitempty" json:"deleted_at,omitempty"`
}

// MessageType represents the type of message
type MessageType string

const (
	MessageTypeText     MessageType = "text"
	MessageTypeImage    MessageType = "image"
	MessageTypeVideo    MessageType = "video"
	MessageTypeAudio    MessageType = "audio"
	MessageTypeFile     MessageType = "file"
	MessageTypeLocation MessageType = "location"
	MessageTypeContact  MessageType = "contact"
	MessageTypeSticker  MessageType = "sticker"
	MessageTypeGIF      MessageType = "gif"
	MessageTypeSystem   MessageType = "system"
)

// MessageStatus represents message status
type MessageStatus string

const (
	MessageStatusSent      MessageStatus = "sent"
	MessageStatusDelivered MessageStatus = "delivered"
	MessageStatusRead      MessageStatus = "read"
	MessageStatusDeleted   MessageStatus = "deleted"
	MessageStatusFailed    MessageStatus = "failed"
)

// Conversation represents a conversation between users
type Conversation struct {
	ID           primitive.ObjectID   `bson:"_id,omitempty" json:"id,omitempty"`
	Participants []primitive.ObjectID `bson:"participants" json:"participants"`
	IsGroup      bool                 `bson:"is_group" json:"is_group"`
	GroupName    string               `bson:"group_name" json:"group_name"`
	GroupImage   string               `bson:"group_image" json:"group_image"`
	AdminID      *primitive.ObjectID  `bson:"admin_id,omitempty" json:"admin_id,omitempty"`
	LastMessage  *Message             `bson:"last_message,omitempty" json:"last_message,omitempty"`
	UnreadCount  map[string]int64     `bson:"unread_count" json:"unread_count"`
	IsMuted      map[string]bool      `bson:"is_muted" json:"is_muted"`
	IsArchived   map[string]bool      `bson:"is_archived" json:"is_archived"`
	IsBlocked    bool                 `bson:"is_blocked" json:"is_blocked"`
	Settings     ConversationSettings `bson:"settings" json:"settings"`
	CreatedAt    time.Time            `bson:"created_at" json:"created_at"`
	UpdatedAt    time.Time            `bson:"updated_at" json:"updated_at"`
	DeletedAt    *time.Time           `bson:"deleted_at,omitempty" json:"deleted_at,omitempty"`
}

// ConversationSettings represents conversation settings
type ConversationSettings struct {
	AllowInvites      bool `bson:"allow_invites" json:"allow_invites"`
	AllowMediaSharing bool `bson:"allow_media_sharing" json:"allow_media_sharing"`
	AllowLinkSharing  bool `bson:"allow_link_sharing" json:"allow_link_sharing"`
	DisappearingTime  int  `bson:"disappearing_time" json:"disappearing_time"` // in hours, 0 = disabled
	OnlyAdminCanPost  bool `bson:"only_admin_can_post" json:"only_admin_can_post"`
}

// MessageCreateRequest represents message creation request
type MessageCreateRequest struct {
	ConversationID   *primitive.ObjectID  `json:"conversation_id,omitempty"`
	RecipientID      *primitive.ObjectID  `json:"recipient_id,omitempty"`
	Content          string               `json:"content" binding:"required,max=1000"`
	MessageType      MessageType          `json:"message_type"`
	MediaFiles       []MediaFile          `json:"media_files"`
	ReplyToID        *primitive.ObjectID  `json:"reply_to_id,omitempty"`
	ForwardedFromID  *primitive.ObjectID  `json:"forwarded_from_id,omitempty"`
	Mentions         []primitive.ObjectID `json:"mentions"`
	SensitiveContent bool                 `json:"sensitive_content"`
}

// MessageUpdateRequest represents message update request
type MessageUpdateRequest struct {
	Content    string      `json:"content" binding:"max=1000"`
	MediaFiles []MediaFile `json:"media_files"`
	IsStarred  *bool       `json:"is_starred"`
}

// MessageResponse represents message response with user interactions
type MessageResponse struct {
	*Message
	CanEdit    bool `json:"can_edit"`
	CanDelete  bool `json:"can_delete"`
	CanReply   bool `json:"can_reply"`
	CanForward bool `json:"can_forward"`
}

// MessageListResponse represents message list response
type MessageListResponse struct {
	Messages   []MessageResponse `json:"messages"`
	TotalCount int64             `json:"total_count"`
	Page       int               `json:"page"`
	Limit      int               `json:"limit"`
	HasMore    bool              `json:"has_more"`
}

// ConversationCreateRequest represents conversation creation request
type ConversationCreateRequest struct {
	Participants []primitive.ObjectID `json:"participants" binding:"required"`
	IsGroup      bool                 `json:"is_group"`
	GroupName    string               `json:"group_name" binding:"max=100"`
	GroupImage   string               `json:"group_image"`
}

// ConversationUpdateRequest represents conversation update request
type ConversationUpdateRequest struct {
	GroupName  string               `json:"group_name" binding:"max=100"`
	GroupImage string               `json:"group_image"`
	Settings   ConversationSettings `json:"settings"`
	IsMuted    *bool                `json:"is_muted"`
	IsArchived *bool                `json:"is_archived"`
}

// ConversationResponse represents conversation response
type ConversationResponse struct {
	*Conversation
	CanEdit       bool `json:"can_edit"`
	CanDelete     bool `json:"can_delete"`
	CanAddMembers bool `json:"can_add_members"`
	CanLeave      bool `json:"can_leave"`
}

// ConversationListResponse represents conversation list response
type ConversationListResponse struct {
	Conversations []ConversationResponse `json:"conversations"`
	TotalCount    int64                  `json:"total_count"`
	Page          int                    `json:"page"`
	Limit         int                    `json:"limit"`
	HasMore       bool                   `json:"has_more"`
}

// =============================================================================
// MESSAGE REACTIONS
// =============================================================================

// MessageReaction represents a reaction to a message
type MessageReaction struct {
	ID        primitive.ObjectID `bson:"_id,omitempty" json:"id,omitempty"`
	MessageID primitive.ObjectID `bson:"message_id" json:"message_id"`
	UserID    primitive.ObjectID `bson:"user_id" json:"user_id"`
	User      *User              `bson:"user,omitempty" json:"user,omitempty"`
	Reaction  ReactionType       `bson:"reaction" json:"reaction"`
	CreatedAt time.Time          `bson:"created_at" json:"created_at"`
}

// =============================================================================
// MESSAGE THREADS
// =============================================================================

// MessageThread represents a threaded conversation
type MessageThread struct {
	ID             primitive.ObjectID   `bson:"_id,omitempty" json:"id,omitempty"`
	RootMessageID  primitive.ObjectID   `bson:"root_message_id" json:"root_message_id"`
	ConversationID primitive.ObjectID   `bson:"conversation_id" json:"conversation_id"`
	Participants   []primitive.ObjectID `bson:"participants" json:"participants"`
	MessageCount   int64                `bson:"message_count" json:"message_count"`
	LastMessageID  *primitive.ObjectID  `bson:"last_message_id,omitempty" json:"last_message_id,omitempty"`
	LastMessage    *Message             `bson:"last_message,omitempty" json:"last_message,omitempty"`
	IsActive       bool                 `bson:"is_active" json:"is_active"`
	CreatedAt      time.Time            `bson:"created_at" json:"created_at"`
	UpdatedAt      time.Time            `bson:"updated_at" json:"updated_at"`
}

// ThreadFollower represents a user following a thread
type ThreadFollower struct {
	ID          primitive.ObjectID `bson:"_id,omitempty" json:"id,omitempty"`
	ThreadID    primitive.ObjectID `bson:"thread_id" json:"thread_id"`
	UserID      primitive.ObjectID `bson:"user_id" json:"user_id"`
	IsFollowing bool               `bson:"is_following" json:"is_following"`
	CreatedAt   time.Time          `bson:"created_at" json:"created_at"`
	UpdatedAt   time.Time          `bson:"updated_at" json:"updated_at"`
}

// =============================================================================
// MESSAGE DRAFTS
// =============================================================================

// MessageDraft represents a draft message
type MessageDraft struct {
	ID             primitive.ObjectID   `bson:"_id,omitempty" json:"id,omitempty"`
	UserID         primitive.ObjectID   `bson:"user_id" json:"user_id"`
	ConversationID *primitive.ObjectID  `bson:"conversation_id,omitempty" json:"conversation_id,omitempty"`
	RecipientID    *primitive.ObjectID  `bson:"recipient_id,omitempty" json:"recipient_id,omitempty"`
	Content        string               `bson:"content" json:"content"`
	MessageType    MessageType          `bson:"message_type" json:"message_type"`
	MediaFiles     []MediaFile          `bson:"media_files" json:"media_files"`
	ReplyToID      *primitive.ObjectID  `bson:"reply_to_id,omitempty" json:"reply_to_id,omitempty"`
	Mentions       []primitive.ObjectID `bson:"mentions" json:"mentions"`
	IsAutoSaved    bool                 `bson:"is_auto_saved" json:"is_auto_saved"`
	Version        int                  `bson:"version" json:"version"`
	CreatedAt      time.Time            `bson:"created_at" json:"created_at"`
	UpdatedAt      time.Time            `bson:"updated_at" json:"updated_at"`
}

// =============================================================================
// SCHEDULED MESSAGES
// =============================================================================

// ScheduledMessage represents a scheduled message
type ScheduledMessage struct {
	ID             primitive.ObjectID   `bson:"_id,omitempty" json:"id,omitempty"`
	UserID         primitive.ObjectID   `bson:"user_id" json:"user_id"`
	ConversationID primitive.ObjectID   `bson:"conversation_id" json:"conversation_id"`
	RecipientID    *primitive.ObjectID  `bson:"recipient_id,omitempty" json:"recipient_id,omitempty"`
	Content        string               `bson:"content" json:"content"`
	MessageType    MessageType          `bson:"message_type" json:"message_type"`
	MediaFiles     []MediaFile          `bson:"media_files" json:"media_files"`
	ReplyToID      *primitive.ObjectID  `bson:"reply_to_id,omitempty" json:"reply_to_id,omitempty"`
	Mentions       []primitive.ObjectID `bson:"mentions" json:"mentions"`
	ScheduledAt    time.Time            `bson:"scheduled_at" json:"scheduled_at"`
	Timezone       string               `bson:"timezone" json:"timezone"`
	Status         ScheduledStatus      `bson:"status" json:"status"`
	SentAt         *time.Time           `bson:"sent_at,omitempty" json:"sent_at,omitempty"`
	FailedAt       *time.Time           `bson:"failed_at,omitempty" json:"failed_at,omitempty"`
	ErrorMessage   string               `bson:"error_message,omitempty" json:"error_message,omitempty"`
	CreatedAt      time.Time            `bson:"created_at" json:"created_at"`
	UpdatedAt      time.Time            `bson:"updated_at" json:"updated_at"`
}

// ScheduledStatus represents the status of a scheduled message
type ScheduledStatus string

const (
	ScheduledStatusPending   ScheduledStatus = "pending"
	ScheduledStatusSent      ScheduledStatus = "sent"
	ScheduledStatusFailed    ScheduledStatus = "failed"
	ScheduledStatusCancelled ScheduledStatus = "cancelled"
)

// =============================================================================
// MESSAGE TEMPLATES
// =============================================================================

// MessageTemplate represents a reusable message template
type MessageTemplate struct {
	ID          primitive.ObjectID `bson:"_id,omitempty" json:"id,omitempty"`
	UserID      primitive.ObjectID `bson:"user_id" json:"user_id"`
	Name        string             `bson:"name" json:"name"`
	Content     string             `bson:"content" json:"content"`
	Category    string             `bson:"category" json:"category"`
	Variables   []TemplateVariable `bson:"variables" json:"variables"`
	IsPublic    bool               `bson:"is_public" json:"is_public"`
	UsageCount  int64              `bson:"usage_count" json:"usage_count"`
	Tags        []string           `bson:"tags" json:"tags"`
	Language    string             `bson:"language" json:"language"`
	Description string             `bson:"description" json:"description"`
	CreatedAt   time.Time          `bson:"created_at" json:"created_at"`
	UpdatedAt   time.Time          `bson:"updated_at" json:"updated_at"`
}

// =============================================================================
// MESSAGE SETTINGS AND PREFERENCES
// =============================================================================

// MessageSettings represents user message preferences
type MessageSettings struct {
	UserID                primitive.ObjectID    `bson:"user_id" json:"user_id"`
	ReadReceipts          bool                  `bson:"read_receipts" json:"read_receipts"`
	TypingIndicators      bool                  `bson:"typing_indicators" json:"typing_indicators"`
	AutoDownloadMedia     bool                  `bson:"auto_download_media" json:"auto_download_media"`
	NotificationSound     bool                  `bson:"notification_sound" json:"notification_sound"`
	Vibration             bool                  `bson:"vibration" json:"vibration"`
	MessagePreview        bool                  `bson:"message_preview" json:"message_preview"`
	OnlineStatus          bool                  `bson:"online_status" json:"online_status"`
	LastSeenVisibility    LastSeenVisibility    `bson:"last_seen_visibility" json:"last_seen_visibility"`
	GroupInvitePermission GroupInvitePermission `bson:"group_invite_permission" json:"group_invite_permission"`
	UpdatedAt             time.Time             `bson:"updated_at" json:"updated_at"`
}

// LastSeenVisibility represents who can see last seen status
type LastSeenVisibility string

const (
	LastSeenEveryone LastSeenVisibility = "everyone"
	LastSeenContacts LastSeenVisibility = "contacts"
	LastSeenNobody   LastSeenVisibility = "nobody"
)

// GroupInvitePermission represents who can add user to groups
type GroupInvitePermission string

const (
	GroupInviteEveryone GroupInvitePermission = "everyone"
	GroupInviteContacts GroupInvitePermission = "contacts"
	GroupInviteNobody   GroupInvitePermission = "nobody"
)

// MessagePrivacySettings represents message privacy settings
type MessagePrivacySettings struct {
	UserID                 primitive.ObjectID    `bson:"user_id" json:"user_id"`
	MessageRequests        bool                  `bson:"message_requests" json:"message_requests"`
	BlockUnknownSenders    bool                  `bson:"block_unknown_senders" json:"block_unknown_senders"`
	RequireContactApproval bool                  `bson:"require_contact_approval" json:"require_contact_approval"`
	AllowedSenders         AllowedSendersType    `bson:"allowed_senders" json:"allowed_senders"`
	BlockedUsers           []primitive.ObjectID  `bson:"blocked_users" json:"blocked_users"`
	BlockedKeywords        []string              `bson:"blocked_keywords" json:"blocked_keywords"`
	ContentFiltering       ContentFilteringLevel `bson:"content_filtering" json:"content_filtering"`
	UpdatedAt              time.Time             `bson:"updated_at" json:"updated_at"`
}

// AllowedSendersType represents who can send messages
type AllowedSendersType string

const (
	AllowedSendersEveryone  AllowedSendersType = "everyone"
	AllowedSendersContacts  AllowedSendersType = "contacts"
	AllowedSendersFollowers AllowedSendersType = "followers"
	AllowedSendersNobody    AllowedSendersType = "nobody"
)

// ContentFilteringLevel represents content filtering level
type ContentFilteringLevel string

const (
	ContentFilteringOff    ContentFilteringLevel = "off"
	ContentFilteringLow    ContentFilteringLevel = "low"
	ContentFilteringMedium ContentFilteringLevel = "medium"
	ContentFilteringHigh   ContentFilteringLevel = "high"
)

// MessageNotificationSettings represents message notification settings
type MessageNotificationSettings struct {
	UserID              primitive.ObjectID `bson:"user_id" json:"user_id"`
	EnableNotifications bool               `bson:"enable_notifications" json:"enable_notifications"`
	NewMessages         bool               `bson:"new_messages" json:"new_messages"`
	MessageRequests     bool               `bson:"message_requests" json:"message_requests"`
	GroupMessages       bool               `bson:"group_messages" json:"group_messages"`
	Mentions            bool               `bson:"mentions" json:"mentions"`
	Reactions           bool               `bson:"reactions" json:"reactions"`
	QuietHours          QuietHours         `bson:"quiet_hours" json:"quiet_hours"`
	PushNotifications   bool               `bson:"push_notifications" json:"push_notifications"`
	EmailNotifications  bool               `bson:"email_notifications" json:"email_notifications"`
	SMSNotifications    bool               `bson:"sms_notifications" json:"sms_notifications"`
	UpdatedAt           time.Time          `bson:"updated_at" json:"updated_at"`
}

// =============================================================================
// AUTO-REPLY SYSTEM
// =============================================================================

// AutoReplySettings represents auto-reply settings
type AutoReplySettings struct {
	UserID     primitive.ObjectID   `bson:"user_id" json:"user_id"`
	Enabled    bool                 `bson:"enabled" json:"enabled"`
	Message    string               `bson:"message" json:"message"`
	Schedule   *AutoReplySchedule   `bson:"schedule,omitempty" json:"schedule,omitempty"`
	Exceptions []primitive.ObjectID `bson:"exceptions" json:"exceptions"` // Users exempt from auto-reply
	StartDate  *time.Time           `bson:"start_date,omitempty" json:"start_date,omitempty"`
	EndDate    *time.Time           `bson:"end_date,omitempty" json:"end_date,omitempty"`
	MaxReplies int                  `bson:"max_replies" json:"max_replies"` // Max auto-replies per conversation
	ReplyCount map[string]int       `bson:"reply_count" json:"reply_count"` // Track replies per conversation
	UpdatedAt  time.Time            `bson:"updated_at" json:"updated_at"`
}

// AutoReplySchedule represents when auto-reply is active
type AutoReplySchedule struct {
	Type      ScheduleType `json:"type"`       // always, business_hours, custom
	Days      []int        `json:"days"`       // 0=Sunday, 1=Monday, etc.
	StartTime string       `json:"start_time"` // HH:MM format
	EndTime   string       `json:"end_time"`   // HH:MM format
	Timezone  string       `json:"timezone"`
}

// ScheduleType represents the type of schedule
type ScheduleType string

const (
	ScheduleTypeAlways        ScheduleType = "always"
	ScheduleTypeBusinessHours ScheduleType = "business_hours"
	ScheduleTypeCustom        ScheduleType = "custom"
)

// =============================================================================
// MESSAGE FILTERS
// =============================================================================

// MessageFilter represents a message filter rule
type MessageFilter struct {
	ID         primitive.ObjectID `bson:"_id,omitempty" json:"id,omitempty"`
	UserID     primitive.ObjectID `bson:"user_id" json:"user_id"`
	Name       string             `bson:"name" json:"name"`
	Conditions []FilterCondition  `bson:"conditions" json:"conditions"`
	Actions    []FilterAction     `bson:"actions" json:"actions"`
	Priority   int                `bson:"priority" json:"priority"`
	IsActive   bool               `bson:"is_active" json:"is_active"`
	MatchCount int64              `bson:"match_count" json:"match_count"`
	CreatedAt  time.Time          `bson:"created_at" json:"created_at"`
	UpdatedAt  time.Time          `bson:"updated_at" json:"updated_at"`
}

// FilterCondition represents a condition in a filter
type FilterCondition struct {
	Field    string                 `json:"field"`    // sender, content, type, etc.
	Operator string                 `json:"operator"` // contains, equals, starts_with, etc.
	Value    interface{}            `json:"value"`
	Options  map[string]interface{} `json:"options"` // Case sensitive, regex, etc.
}

// FilterAction represents an action in a filter
type FilterAction struct {
	Type   string                 `json:"type"`   // block, archive, label, forward, etc.
	Config map[string]interface{} `json:"config"` // Additional configuration
}

// =============================================================================
// MESSAGE REPORTS
// =============================================================================

// MessageReport represents a report on a message
type MessageReport struct {
	ID          primitive.ObjectID  `bson:"_id,omitempty" json:"id,omitempty"`
	MessageID   primitive.ObjectID  `bson:"message_id" json:"message_id"`
	ReporterID  primitive.ObjectID  `bson:"reporter_id" json:"reporter_id"`
	Reporter    *User               `bson:"reporter,omitempty" json:"reporter,omitempty"`
	ReportedID  primitive.ObjectID  `bson:"reported_id" json:"reported_id"` // Message sender
	Reported    *User               `bson:"reported,omitempty" json:"reported,omitempty"`
	Reason      ReportReason        `bson:"reason" json:"reason"`
	Description string              `bson:"description" json:"description"`
	Status      ReportStatus        `bson:"status" json:"status"`
	ReviewedBy  *primitive.ObjectID `bson:"reviewed_by,omitempty" json:"reviewed_by,omitempty"`
	ReviewedAt  *time.Time          `bson:"reviewed_at,omitempty" json:"reviewed_at,omitempty"`
	Action      *string             `bson:"action,omitempty" json:"action,omitempty"`
	CreatedAt   time.Time           `bson:"created_at" json:"created_at"`
	UpdatedAt   time.Time           `bson:"updated_at" json:"updated_at"`
}

const (
	ReportReasonSpam          ReportReason = "spam"
	ReportReasonHarassment    ReportReason = "harassment"
	ReportReasonInappropriate ReportReason = "inappropriate"
	ReportReasonViolence      ReportReason = "violence"
	ReportReasonFakeNews      ReportReason = "fake_news"
	ReportReasonOther         ReportReason = "other"
)

// =============================================================================
// MESSAGE DELIVERY AND READ RECEIPTS
// =============================================================================

// MessageDeliveryStatus represents detailed delivery status
type MessageDeliveryStatus struct {
	ID             primitive.ObjectID `bson:"_id,omitempty" json:"id,omitempty"`
	MessageID      primitive.ObjectID `bson:"message_id" json:"message_id"`
	ConversationID primitive.ObjectID `bson:"conversation_id" json:"conversation_id"`
	Participants   []DeliveryReceipt  `bson:"participants" json:"participants"`
	TotalSent      int                `bson:"total_sent" json:"total_sent"`
	TotalDelivered int                `bson:"total_delivered" json:"total_delivered"`
	TotalRead      int                `bson:"total_read" json:"total_read"`
	CreatedAt      time.Time          `bson:"created_at" json:"created_at"`
	UpdatedAt      time.Time          `bson:"updated_at" json:"updated_at"`
}

// DeliveryReceipt represents delivery receipt for a participant
type DeliveryReceipt struct {
	UserID      primitive.ObjectID `json:"user_id"`
	Status      MessageStatus      `json:"status"`
	DeliveredAt *time.Time         `json:"delivered_at,omitempty"`
	ReadAt      *time.Time         `json:"read_at,omitempty"`
}

// =============================================================================
// CONVERSATION EXPORT
// =============================================================================

// ConversationExport represents a conversation export request
type ConversationExport struct {
	ID             primitive.ObjectID `bson:"_id,omitempty" json:"id,omitempty"`
	ConversationID primitive.ObjectID `bson:"conversation_id" json:"conversation_id"`
	UserID         primitive.ObjectID `bson:"user_id" json:"user_id"`
	Format         ExportFormat       `bson:"format" json:"format"`
	Status         ExportStatus       `bson:"status" json:"status"`
	Settings       ExportSettings     `bson:"settings" json:"settings"`
	FilePath       string             `bson:"file_path" json:"file_path"`
	FileSize       int64              `bson:"file_size" json:"file_size"`
	MessageCount   int64              `bson:"message_count" json:"message_count"`
	StartDate      *time.Time         `bson:"start_date,omitempty" json:"start_date,omitempty"`
	EndDate        *time.Time         `bson:"end_date,omitempty" json:"end_date,omitempty"`
	ExpiresAt      time.Time          `bson:"expires_at" json:"expires_at"`
	DownloadCount  int                `bson:"download_count" json:"download_count"`
	CreatedAt      time.Time          `bson:"created_at" json:"created_at"`
	UpdatedAt      time.Time          `bson:"updated_at" json:"updated_at"`
}

// ExportFormat represents the export format
type ExportFormat string

const (
	ExportFormatJSON ExportFormat = "json"
	ExportFormatCSV  ExportFormat = "csv"
	ExportFormatPDF  ExportFormat = "pdf"
	ExportFormatHTML ExportFormat = "html"
)

// ExportStatus represents the export status
type ExportStatus string

const (
	ExportStatusPending    ExportStatus = "pending"
	ExportStatusProcessing ExportStatus = "processing"
	ExportStatusCompleted  ExportStatus = "completed"
	ExportStatusFailed     ExportStatus = "failed"
	ExportStatusExpired    ExportStatus = "expired"
)

// ExportSettings represents export settings
type ExportSettings struct {
	IncludeMedia     bool `json:"include_media"`
	IncludeDeleted   bool `json:"include_deleted"`
	IncludeReactions bool `json:"include_reactions"`
	IncludeThreads   bool `json:"include_threads"`
}

// =============================================================================
// MESSAGE ANALYTICS
// =============================================================================

// MessageAnalytics represents message analytics data
type MessageAnalytics struct {
	ID                   primitive.ObjectID    `bson:"_id,omitempty" json:"id,omitempty"`
	UserID               primitive.ObjectID    `bson:"user_id" json:"user_id"`
	Date                 string                `bson:"date" json:"date"` // YYYY-MM-DD
	MessagesSent         int64                 `bson:"messages_sent" json:"messages_sent"`
	MessagesReceived     int64                 `bson:"messages_received" json:"messages_received"`
	ConversationsStarted int64                 `bson:"conversations_started" json:"conversations_started"`
	ResponseTime         float64               `bson:"response_time" json:"response_time"` // Average in minutes
	MessagesByType       map[MessageType]int64 `bson:"messages_by_type" json:"messages_by_type"`
	MessagesByHour       map[int]int64         `bson:"messages_by_hour" json:"messages_by_hour"`
	TopContacts          []ContactActivity     `bson:"top_contacts" json:"top_contacts"`
	CreatedAt            time.Time             `bson:"created_at" json:"created_at"`
	UpdatedAt            time.Time             `bson:"updated_at" json:"updated_at"`
}

// ContactActivity represents activity with a specific contact
type ContactActivity struct {
	UserID           primitive.ObjectID `json:"user_id"`
	MessagesSent     int64              `json:"messages_sent"`
	MessagesReceived int64              `json:"messages_received"`
	LastMessageAt    time.Time          `json:"last_message_at"`
}

// =============================================================================
// SEARCH FUNCTIONALITY
// =============================================================================

// MessageSearchHistory represents search history
type MessageSearchHistory struct {
	ID        primitive.ObjectID     `bson:"_id,omitempty" json:"id,omitempty"`
	UserID    primitive.ObjectID     `bson:"user_id" json:"user_id"`
	Query     string                 `bson:"query" json:"query"`
	Filters   map[string]interface{} `bson:"filters" json:"filters"`
	Results   int64                  `bson:"results" json:"results"`
	CreatedAt time.Time              `bson:"created_at" json:"created_at"`
}

// MessageSearchResult represents a search result
type MessageSearchResult struct {
	Message    *Message  `json:"message"`
	Relevance  float64   `json:"relevance"`
	Highlights []string  `json:"highlights"`
	Context    []Message `json:"context"` // Surrounding messages for context
}
