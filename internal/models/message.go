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
